"""Checkov 3.2.517/3.3.0 adapter with fail-closed output-shape handling.

Candidate configuration and custom checks are deliberately absent from the request API.
The native invocation runs from private process scratch, disables downloads/uploads,
and passes only an explicit scan root plus the closed framework set.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any

from ..enums import (
    ArtifactKind,
    CheckEvaluationResult,
    CheckTargetReason,
    Severity,
    Status,
)
from ..fingerprints import (
    canonicalize_kubernetes_identity,
    canonicalize_scan_path,
    canonicalize_terraform_address,
)
from ..models import (
    CoverageCounters,
    BoundInputFile,
    CheckEvaluation,
    DomainError,
    ExpectedResource,
    Finding,
    FindingLocation,
    ResourceCoverage,
    ScannerRun,
    canonical_identifier,
    canonical_repo_path,
    canonical_resource_scope,
    require_int,
    require_trusted_scanner_run,
    safe_report_text,
)
from ..normalisation import assign_occurrence_indices
from ..process import CommandRequest, CommandResult, ProcessReason, run_command
from ..redaction import redact_detail
from .base import AdapterReason, ScannerContract


CHECKOV_CONTRACT = ScannerContract(
    name="checkov",
    supported_versions=("3.2.517", "3.3.0"),
    frameworks=("kubernetes", "terraform"),
    expected_exit_codes=(0, 1),
)


@dataclass(frozen=True, slots=True)
class _FilesystemIdentity:
    resolved: Path
    device: int
    inode: int


CheckovEligibleFileEvidence = BoundInputFile


@dataclass(frozen=True, slots=True)
class CheckovDistributionIdentity:
    """Installed environment and policy inventory derived independently of scan data."""

    scanner_environment_digest: str
    policy_inventory_digest: str
    source: str
    installed_distribution_digest: str = ""
    dependency_lock_digest: str = ""
    custom_check_digest: str = ""

    def __post_init__(self) -> None:
        for name in (
            "scanner_environment_digest", "policy_inventory_digest",
            "installed_distribution_digest", "dependency_lock_digest",
            "custom_check_digest",
        ):
            value = getattr(self, name)
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise DomainError(f"{name} must be a lowercase SHA-256")
        object.__setattr__(self, "source", canonical_identifier(self.source, "distribution source"))


@dataclass(frozen=True, slots=True)
class CheckovTargetEvidence:
    status: Status
    reason: CheckTargetReason
    evaluations: tuple
    _trusted_context: InitVar[object] = None
    _trusted_adapter_evidence: bool = field(
        init=False, default=False, repr=False, compare=False
    )

    def __post_init__(self, _trusted_context: object) -> None:
        if type(self.status) is not Status:
            raise DomainError("target evidence status must be an exact Status")
        if type(self.reason) is not CheckTargetReason:
            raise DomainError("target evidence reason must be an exact CheckTargetReason")
        if type(self.evaluations) is not tuple:
            raise DomainError("target evaluations must be an exact tuple")
        for item in self.evaluations:
            if type(item) is not CheckEvaluation:
                raise DomainError("target evaluations must contain CheckEvaluation")
        if _trusted_context is _TRUSTED_CHECKOV_TARGET_CONTEXT:
            object.__setattr__(self, "_trusted_adapter_evidence", True)


_TRUSTED_CHECKOV_TARGET_CONTEXT = object()


def _target_evidence(
    status: Status, reason: CheckTargetReason, evaluations: tuple
) -> CheckovTargetEvidence:
    return CheckovTargetEvidence(
        status,
        reason,
        evaluations,
        _trusted_context=_TRUSTED_CHECKOV_TARGET_CONTEXT,
    )


def require_trusted_checkov_target_evidence(value: object) -> CheckovTargetEvidence:
    """D5 boundary: accept only target evidence derived from a trusted run."""
    if type(value) is not CheckovTargetEvidence:
        raise DomainError("target evidence must be an exact CheckovTargetEvidence")
    if not value._trusted_adapter_evidence:
        raise DomainError("CheckovTargetEvidence is caller-authored, not trusted evidence")
    return value


def _sha256_manifest(files: list[tuple[str, Path]]) -> str:
    digest = hashlib.sha256()
    for relative, path in sorted(files):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(path.stat().st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _manifest_digest(records: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for relative, payload in sorted(records):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _inventory_regular_files(root: Path, installation_root: Path) -> list[tuple[str, Path]]:
    """Inventory one installed package without accepting mutable indirections."""
    result: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*")):
        relative_to_package = path.relative_to(root)
        if "__pycache__" in relative_to_package.parts or path.suffix == ".pyc":
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise DomainError("Checkov distribution entry could not be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise DomainError("Checkov distribution and policy trees must not contain symlinks")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise DomainError("Checkov distribution contains a non-regular entry")
        relative = path.relative_to(installation_root).as_posix()
        result.append((relative, path))
    return result


def checkov_distribution_identity(
    executable: Path, expected_version: str
) -> CheckovDistributionIdentity:
    """Hash the installed distribution tree and its policy/check inventory."""
    resolved = executable.resolve(strict=True)
    try:
        first_line = resolved.read_bytes().splitlines()[0].decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError, IndexError) as exc:
        raise DomainError("Checkov launcher cannot identify its distribution") from exc
    candidates: list[Path] = []
    if first_line.startswith("#!"):
        interpreter = Path(first_line[2:].strip().split()[0])
        if interpreter.is_absolute():
            candidates.append(interpreter.parent.parent)
    candidates.append(resolved.parent.parent)
    installation_root: Path | None = None
    checkov_roots: list[Path] = []
    for candidate in candidates:
        roots = sorted(candidate.glob("lib/python*/site-packages/checkov"))
        if roots:
            installation_root = candidate.resolve(strict=True)
            checkov_roots = [root.resolve(strict=True) for root in roots]
            break
    if installation_root is None:
        raise DomainError("Checkov installed distribution manifest cannot be established")
    package_files: list[tuple[str, Path]] = []
    policy_files: list[tuple[str, Path]] = []
    for root in checkov_roots:
        root_files = _inventory_regular_files(root, installation_root)
        package_files.extend(root_files)
        for relative, resolved_path in root_files:
            if "/checks/" in f"/{relative}" or "/policies/" in f"/{relative}":
                policy_files.append((relative, resolved_path))
    if not package_files or not policy_files:
        raise DomainError("Checkov distribution or policy inventory is empty")
    policy_paths = {relative for relative, _path in policy_files}
    package_without_policy = [
        item for item in package_files if item[0] not in policy_paths
    ]
    distribution_digest = _sha256_manifest(package_files)
    policy_digest = _sha256_manifest(policy_files)
    lock_records: list[tuple[str, bytes]] = []
    site_packages = checkov_roots[0].parent
    for metadata in sorted(site_packages.glob("*.dist-info")):
        if metadata.is_symlink():
            raise DomainError("Checkov dependency metadata must not be symlinked")
        for name in ("RECORD", "METADATA", "WHEEL", "direct_url.json"):
            path = metadata / name
            if not path.exists():
                continue
            if path.is_symlink() or not path.is_file():
                raise DomainError("Checkov dependency metadata must be regular files")
            lock_records.append((path.relative_to(site_packages).as_posix(), path.read_bytes()))
    interpreter_path = None
    if first_line.startswith("#!"):
        candidate = Path(first_line[2:].strip().split()[0])
        if candidate.is_absolute():
            interpreter_path = candidate
    if interpreter_path is not None:
        try:
            metadata = interpreter_path.lstat()
        except OSError as exc:
            raise DomainError("Checkov interpreter identity cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise DomainError("Checkov interpreter must not be a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise DomainError("Checkov interpreter must be a regular file")
        lock_records.append(("runtime/interpreter", interpreter_path.read_bytes()))
    if not lock_records:
        lock_records.append(("distribution-metadata", b"unavailable"))
    dependency_digest = _manifest_digest(lock_records)
    custom_check_digest = _manifest_digest([("custom-checks", b"disabled")])
    environment_digest = _manifest_digest([
        ("non-policy-package", bytes.fromhex(_sha256_manifest(package_without_policy))),
        ("dependency-lock", bytes.fromhex(dependency_digest)),
        ("custom-checks", bytes.fromhex(custom_check_digest)),
    ])
    return CheckovDistributionIdentity(
        environment_digest,
        policy_digest,
        f"installed-manifest-v2-{expected_version}",
        distribution_digest,
        dependency_digest,
        custom_check_digest,
    )


def _identity(path: Path, label: str, *, directory: bool) -> _FilesystemIdentity:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise DomainError(f"{label} cannot be resolved") from exc
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected:
        kind = "directory" if directory else "regular file"
        raise DomainError(f"{label} must be an existing {kind}")
    return _FilesystemIdentity(resolved, metadata.st_dev, metadata.st_ino)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise DomainError("Checkov executable cannot be hashed") from exc
    return digest.hexdigest()


def _file_type(relative: str) -> str:
    suffix = Path(relative).suffix.lower()
    if suffix == ".tf":
        return ArtifactKind.TERRAFORM_HCL.value
    if suffix in (".yaml", ".yml"):
        return ArtifactKind.KUBERNETES_YAML.value
    if suffix == ".json" and not relative.lower().endswith(".tf.json"):
        return ArtifactKind.KUBERNETES_JSON.value
    raise DomainError("eligible Checkov file has an unsupported artifact type")


def _stream_bound_file(
    path: Path,
    relative: str,
    *,
    max_bytes: int,
    destination_descriptor: int | None = None,
) -> CheckovEligibleFileEvidence:
    """Hash a no-follow descriptor and optionally copy those exact bounded bytes."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise DomainError("eligible file must be a no-follow regular file")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise DomainError(AdapterReason.INPUT_FILE_BYTES_EXCEEDED.value)
                digest.update(chunk)
                if destination_descriptor is not None:
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(destination_descriptor, chunk[offset:])
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DomainError("eligible file cannot be opened with no-follow safeguards") from exc
    return CheckovEligibleFileEvidence(
        relative,
        _file_type(relative),
        size,
        digest.hexdigest(),
        metadata.st_dev,
        metadata.st_ino,
    )


def _safe_directory(path: Path, label: str) -> Path:
    if not isinstance(path, Path):
        raise DomainError(f"{label} must be a pathlib.Path")
    return _identity(path, label, directory=True).resolved


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class CheckovKubernetesIdentity:
    """Identity supplied by the independent Kubernetes artifact detector."""

    file_path: str
    checkov_resource: str
    api_version: str
    kind: str
    namespace: str
    name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        object.__setattr__(
            self,
            "checkov_resource",
            canonical_identifier(self.checkov_resource, "Checkov Kubernetes resource"),
        )
        canonical = canonicalize_kubernetes_identity(
            self.api_version, self.kind, self.namespace, self.name
        )
        api_version, kind, namespace, name = canonical.rsplit("/", 3)
        object.__setattr__(self, "api_version", api_version)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "namespace", namespace)
        object.__setattr__(self, "name", name)

    @property
    def canonical_address(self) -> str:
        return canonicalize_kubernetes_identity(
            self.api_version, self.kind, self.namespace, self.name
        )


@dataclass(frozen=True, slots=True)
class CheckovScanRequest:
    """Trusted inputs to one Checkov execution and normalization boundary."""

    executable: Path
    scan_root: Path
    workspace_root: Path
    frameworks: tuple
    files_eligible: tuple
    expected_version: str
    expected_executable_sha256: str
    expected_scanner_environment_sha256: str
    expected_policy_inventory_sha256: str
    kubernetes_identities: tuple = ()
    expected_resources: tuple = ()
    timeout_seconds: int = 120
    max_output_bytes: int = 25 * 1024 * 1024
    max_eligible_files: int = 10_000
    max_file_bytes: int = 10 * 1024 * 1024
    max_total_eligible_bytes: int = 100 * 1024 * 1024
    _executable_identity: _FilesystemIdentity = field(init=False, repr=False, compare=False)
    _scan_root_identity: _FilesystemIdentity = field(init=False, repr=False, compare=False)
    _eligible_identities: tuple = field(init=False, repr=False, compare=False)
    _executable_sha256: str = field(init=False, repr=False, compare=False)
    _distribution_identity: CheckovDistributionIdentity = field(
        init=False, repr=False, compare=False
    )
    eligible_file_evidence: tuple = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.executable, Path):
            raise DomainError("Checkov executable must be a pathlib.Path")
        executable_identity = _identity(self.executable, "Checkov executable", directory=False)
        executable = executable_identity.resolved
        metadata = executable.stat()
        if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
            raise DomainError("Checkov executable must be an executable regular file")
        workspace = _safe_directory(self.workspace_root, "workspace_root")
        scan_root_identity = _identity(self.scan_root, "scan_root", directory=True)
        scan_root = scan_root_identity.resolved
        if not _within(scan_root, workspace):
            raise DomainError("scan_root must resolve inside workspace_root")
        if _within(executable, workspace):
            raise DomainError("Checkov executable must not resolve inside workspace_root")
        executable_sha256 = _file_sha256(executable)
        if (
            type(self.expected_executable_sha256) is not str
            or self.expected_executable_sha256 != executable_sha256
        ):
            raise DomainError("Checkov executable digest does not match trusted configuration")
        distribution_identity = checkov_distribution_identity(executable, self.expected_version)
        if self.expected_scanner_environment_sha256 != (
            distribution_identity.scanner_environment_digest
        ):
            raise DomainError("Checkov scanner environment digest does not match trusted configuration")
        if self.expected_policy_inventory_sha256 != distribution_identity.policy_inventory_digest:
            raise DomainError("Checkov policy inventory digest does not match trusted configuration")
        if type(self.frameworks) is not tuple or not self.frameworks:
            raise DomainError("frameworks must be a nonempty exact tuple")
        frameworks = tuple(
            canonical_identifier(item, "Checkov framework") for item in self.frameworks
        )
        if len(frameworks) != len(set(frameworks)):
            raise DomainError("frameworks must not contain duplicates")
        unsupported = set(frameworks) - set(CHECKOV_CONTRACT.frameworks)
        if unsupported:
            raise DomainError(f"unsupported Checkov frameworks: {sorted(unsupported)}")
        if type(self.files_eligible) is not tuple:
            raise DomainError("files_eligible must be an exact tuple")
        if require_int(self.max_eligible_files, "max_eligible_files") <= 0:
            raise DomainError("max_eligible_files must be > 0")
        if require_int(self.max_file_bytes, "max_file_bytes") <= 0:
            raise DomainError("max_file_bytes must be > 0")
        if require_int(self.max_total_eligible_bytes, "max_total_eligible_bytes") <= 0:
            raise DomainError("max_total_eligible_bytes must be > 0")
        if len(self.files_eligible) > self.max_eligible_files:
            raise DomainError(AdapterReason.INPUT_FILE_COUNT_EXCEEDED.value)
        eligible: list[str] = []
        eligible_identities: list[_FilesystemIdentity] = []
        eligible_evidence: list[CheckovEligibleFileEvidence] = []
        eligible_total = 0
        for item in self.files_eligible:
            relative = canonical_repo_path(item, "eligible file")
            identity = _identity(scan_root / relative, "eligible file", directory=False)
            if not _within(identity.resolved, scan_root):
                raise DomainError("eligible file must be a regular file inside scan_root")
            evidence = _stream_bound_file(
                scan_root / relative,
                relative,
                max_bytes=self.max_file_bytes,
            )
            if (identity.device, identity.inode) != (evidence.device, evidence.inode):
                raise DomainError("eligible file changed while binding request bytes")
            eligible_total += evidence.size
            if eligible_total > self.max_total_eligible_bytes:
                raise DomainError(AdapterReason.INPUT_TOTAL_BYTES_EXCEEDED.value)
            eligible.append(relative)
            eligible_identities.append(identity)
            eligible_evidence.append(evidence)
        if len(eligible) != len(set(eligible)):
            raise DomainError("files_eligible must not contain duplicates")
        version = canonical_identifier(self.expected_version, "expected Checkov version")
        if version not in CHECKOV_CONTRACT.supported_versions:
            raise DomainError("expected Checkov version is outside the supported contract")
        if type(self.kubernetes_identities) is not tuple:
            raise DomainError("kubernetes_identities must be an exact tuple")
        identities: list[CheckovKubernetesIdentity] = []
        for item in self.kubernetes_identities:
            if type(item) is not CheckovKubernetesIdentity:
                raise DomainError("Kubernetes identities must be exact typed records")
            rebuilt = CheckovKubernetesIdentity(
                item.file_path,
                item.checkov_resource,
                item.api_version,
                item.kind,
                item.namespace,
                item.name,
            )
            if rebuilt.file_path not in eligible:
                raise DomainError("Kubernetes identity must name an eligible file")
            identities.append(rebuilt)
        identity_keys = [(item.file_path, item.checkov_resource) for item in identities]
        if len(identity_keys) != len(set(identity_keys)):
            raise DomainError("Kubernetes identity map contains duplicate keys")
        if type(self.expected_resources) is not tuple:
            raise DomainError("expected_resources must be an exact tuple")
        expected_resources: list[ExpectedResource] = []
        kubernetes_lookup = {
            (item.file_path, item.checkov_resource): item.canonical_address
            for item in identities
        }
        for item in self.expected_resources:
            if type(item) is not ExpectedResource:
                raise DomainError("expected_resources must contain exact ExpectedResource records")
            rebuilt = ExpectedResource(
                item.file_path,
                item.resource_address,
                item.artifact_kind,
                item.scanner_native_lookup,
            )
            if rebuilt.file_path not in eligible:
                raise DomainError("expected resource must name an eligible file")
            if rebuilt.artifact_kind in {
                ArtifactKind.KUBERNETES_YAML, ArtifactKind.KUBERNETES_JSON
            }:
                key = (rebuilt.file_path, rebuilt.scanner_native_lookup)
                if kubernetes_lookup.get(key) != rebuilt.resource_address:
                    raise DomainError(
                        "Kubernetes expected resource must match independent identity mapping"
                    )
                if "kubernetes" not in frameworks:
                    raise DomainError("Kubernetes expected resource requires its framework")
            elif rebuilt.artifact_kind is ArtifactKind.TERRAFORM_HCL:
                if rebuilt.scanner_native_lookup != rebuilt.resource_address:
                    raise DomainError(
                        "Terraform expected resource native lookup must equal its address"
                    )
                if "terraform" not in frameworks:
                    raise DomainError("Terraform expected resource requires its framework")
            else:
                raise DomainError("Checkov expected resource has unsupported artifact kind")
            expected_resources.append(rebuilt)
        expected_keys = [
            (item.file_path, item.resource_address, item.artifact_kind.value)
            for item in expected_resources
        ]
        if len(expected_keys) != len(set(expected_keys)):
            raise DomainError("expected resource inventory contains duplicates")
        if require_int(self.timeout_seconds, "timeout_seconds") <= 0:
            raise DomainError("timeout_seconds must be > 0")
        if require_int(self.max_output_bytes, "max_output_bytes") <= 0:
            raise DomainError("max_output_bytes must be > 0")
        object.__setattr__(self, "executable", executable)
        object.__setattr__(self, "workspace_root", workspace)
        object.__setattr__(self, "scan_root", scan_root)
        object.__setattr__(self, "frameworks", tuple(sorted(frameworks)))
        object.__setattr__(self, "files_eligible", tuple(sorted(eligible)))
        identity_by_path = dict(zip(eligible, eligible_identities))
        object.__setattr__(self, "_executable_identity", executable_identity)
        object.__setattr__(self, "_executable_sha256", executable_sha256)
        object.__setattr__(self, "_distribution_identity", distribution_identity)
        object.__setattr__(self, "_scan_root_identity", scan_root_identity)
        object.__setattr__(
            self,
            "_eligible_identities",
            tuple(identity_by_path[path] for path in sorted(eligible)),
        )
        evidence_by_path = {item.file_path: item for item in eligible_evidence}
        object.__setattr__(
            self,
            "eligible_file_evidence",
            tuple(evidence_by_path[path] for path in sorted(eligible)),
        )
        object.__setattr__(
            self,
            "kubernetes_identities",
            tuple(sorted(identities, key=lambda item: (item.file_path, item.checkov_resource))),
        )
        object.__setattr__(
            self,
            "expected_resources",
            tuple(sorted(expected_resources, key=lambda item: item.canonical_key)),
        )


def _invocation_config_digest(request: CheckovScanRequest) -> str:
    payload = {
        "adapter": "checkov-adapter-contract-v3",
        "compact": True,
        "download_external_modules": False,
        "frameworks": list(request.frameworks),
        "output": "json",
        "quiet": False,
        "skip_download": True,
        "skip_results_upload": True,
        "max_eligible_files": request.max_eligible_files,
        "max_file_bytes": request.max_file_bytes,
        "max_total_eligible_bytes": request.max_total_eligible_bytes,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _reason_run(
    request: CheckovScanRequest,
    reason: AdapterReason,
    *,
    status: Status = Status.ERROR,
    process: CommandResult | None = None,
    version: str | None = None,
    coverage: CoverageCounters | None = None,
    resource_coverage: ResourceCoverage | None = None,
    diagnostics: tuple[str, ...] = (),
    raw_output: bytes | None = None,
    evaluations: tuple = (),
) -> ScannerRun:
    diagnostic_values = (reason.value, *diagnostics)
    ruleset_integrity = Status.PASS
    if reason in {
        AdapterReason.POLICY_INVENTORY_MISMATCH,
        AdapterReason.SCANNER_ENVIRONMENT_MISMATCH,
    }:
        ruleset_integrity = Status.FAIL
    elif reason in {
        AdapterReason.VERSION_MISMATCH,
        AdapterReason.UNSUPPORTED_VERSION,
        AdapterReason.VERSION_PROBE_FAILED,
    }:
        ruleset_integrity = Status.INCONCLUSIVE
    expected_count = len(request.expected_resources)
    return ScannerRun._from_adapter(
        scanner="checkov",
        scanner_version=version or request.expected_version,
        status=status,
        coverage=coverage or CoverageCounters(files_eligible=len(request.files_eligible)),
        resource_coverage=resource_coverage
        or ResourceCoverage(
            resources_expected=expected_count,
            expected_resources_missing=expected_count,
        ),
        exit_code=(process.exit_code if process and process.exit_code is not None else -1),
        stdout_sha256=(process.stdout_sha256 if process else ""),
        stderr_sha256=(process.stderr_sha256 if process else ""),
        raw_output_sha256=(
            hashlib.sha256(raw_output).hexdigest()
            if type(raw_output) is bytes
            else ""
        ),
        resolved_launcher_path=str(request.executable),
        launcher_digest=request._executable_sha256,
        scanner_environment_digest=(
            request._distribution_identity.scanner_environment_digest
        ),
        policy_inventory_digest=request._distribution_identity.policy_inventory_digest,
        invocation_config_digest=_invocation_config_digest(request),
        installed_distribution_digest=(
            request._distribution_identity.installed_distribution_digest
        ),
        dependency_lock_digest=request._distribution_identity.dependency_lock_digest,
        custom_check_digest=request._distribution_identity.custom_check_digest,
        ruleset_integrity=ruleset_integrity,
        evaluations=evaluations,
        input_files=request.eligible_file_evidence,
        duration_ms=(process.duration_ms if process else 0),
        diagnostics=diagnostic_values,
    )


def _process_failure(
    request: CheckovScanRequest, process: CommandResult, *, probe: bool = False
) -> ScannerRun | None:
    if process.status is Status.PASS:
        return None
    if probe:
        reason = AdapterReason.VERSION_PROBE_FAILED
    elif process.truncated:
        reason = AdapterReason.TRUNCATED_OUTPUT
    elif process.timed_out:
        reason = AdapterReason.DEADLINE_EXCEEDED
    elif process.reason_code is ProcessReason.KILLED_BY_SIGNAL:
        reason = AdapterReason.KILLED_PROCESS
    elif process.reason_code is ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT:
        reason = AdapterReason.EXIT_CODE_OUTSIDE_CONTRACT
    else:
        reason = AdapterReason.PROCESS_ERROR
    status = process.status
    if status is Status.PARTIAL and reason is AdapterReason.TRUNCATED_OUTPUT:
        status = Status.ERROR
    return _reason_run(request, reason, status=status, process=process)


def _strict_int(mapping: dict, key: str, label: str) -> int:
    value = mapping.get(key)
    if type(value) is not int or value < 0:
        raise DomainError(f"{label}.{key} must be an integer >= 0")
    return value


def _path_from_check(check: dict, scan_root: Path) -> str:
    raw = check.get("file_abs_path")
    if type(raw) is str and raw:
        return canonicalize_scan_path(raw, scan_root)
    raw = check.get("file_path")
    if type(raw) is not str or not raw:
        raise DomainError("Checkov finding has no usable file path")
    if raw.startswith("/"):
        raw = raw.lstrip("/")
    return canonicalize_scan_path(raw, scan_root)


def _line_range(check: dict) -> tuple[int, int]:
    raw = check.get("file_line_range")
    if type(raw) is not list or len(raw) != 2:
        raise DomainError("Checkov file_line_range must be a two-item JSON array")
    start, end = raw
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise DomainError("Checkov file_line_range contains invalid line evidence")
    return start, end


def _severity(raw: Any) -> Severity:
    if raw is None:
        return Severity.UNKNOWN
    if type(raw) is not str:
        raise DomainError("Checkov severity must be a string or null")
    try:
        return Severity(raw.upper())
    except ValueError as exc:
        raise DomainError("Checkov severity is outside the closed severity vocabulary") from exc


def checkov_occurrence_token(
    scanner_version: str,
    artifact_kind: ArtifactKind,
    file_path: str,
    rule_id: str,
    resource_address: str,
    evaluated_keys: tuple[str, ...],
    native_fingerprint: str = "",
) -> str:
    """Return one context-bound token shared by failed and positive evidence."""
    if type(evaluated_keys) is not tuple or any(type(item) is not str for item in evaluated_keys):
        raise DomainError("Checkov occurrence evaluated_keys must be an exact string tuple")
    payload = {
        "scanner": "checkov",
        "scanner_version": canonical_identifier(scanner_version, "Checkov version"),
        "artifact_kind": artifact_kind.value,
        "file_path": file_path,
        "rule_id": canonical_identifier(rule_id, "Checkov check_id"),
        "resource_address": resource_address,
        "evaluated_keys": sorted(set(evaluated_keys)),
        "native_fingerprint": (
            canonical_identifier(native_fingerprint, "Checkov fingerprint")
            if native_fingerprint else ""
        ),
    }
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"checkov-occurrence-v1:{digest}"


def _evaluated_keys(check: dict) -> tuple[str, ...]:
    result = check.get("check_result")
    if type(result) is not dict:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    raw = result.get("evaluated_keys", [])
    if type(raw) is not list or any(type(item) is not str for item in raw):
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    return tuple(safe_report_text(item, "Checkov evaluated key") for item in raw)


def _resource_evidence(
    check: dict,
    check_type: str,
    request: CheckovScanRequest,
    native_scan_root: Path,
) -> tuple[str, str, ArtifactKind]:
    resource = canonical_identifier(check.get("resource"), "Checkov resource")
    file_path = _path_from_check(check, native_scan_root)
    if file_path not in request.files_eligible:
        raise DomainError("Checkov reported a path outside the independently eligible set")
    if check_type == "terraform":
        return file_path, canonicalize_terraform_address(resource), ArtifactKind.TERRAFORM_HCL
    identities = {
        (item.file_path, item.checkov_resource): item.canonical_address
        for item in request.kubernetes_identities
    }
    try:
        address = identities[(file_path, resource)]
    except KeyError as exc:
        raise DomainError(AdapterReason.MISSING_RESOURCE_IDENTITY.value) from exc
    artifact = (
        ArtifactKind.KUBERNETES_JSON
        if Path(file_path).suffix.lower() == ".json"
        else ArtifactKind.KUBERNETES_YAML
    )
    return file_path, address, artifact


def _evaluation(
    check: dict,
    check_type: str,
    request: CheckovScanRequest,
    version: str,
    source_bucket: str,
    expected_result: CheckEvaluationResult,
    native_scan_root: Path,
) -> CheckEvaluation:
    if type(check) is not dict:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    check_result = check.get("check_result")
    if type(check_result) is not dict or check_result.get("result") != expected_result.value:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    file_path, resource_address, artifact_kind = _resource_evidence(
        check, check_type, request, native_scan_root
    )
    evaluated_keys = _evaluated_keys(check)
    return CheckEvaluation(
        scanner="checkov",
        scanner_version=version,
        rule_id=canonical_identifier(check.get("check_id"), "Checkov check_id"),
        resource_address=resource_address,
        file_path=file_path,
        native_result=expected_result,
        evaluated_keys=evaluated_keys,
        source_bucket=source_bucket,
        occurrence_token=checkov_occurrence_token(
            version, artifact_kind, file_path,
            canonical_identifier(check.get("check_id"), "Checkov check_id"),
            resource_address, evaluated_keys,
            check.get("fingerprint") or "",
        ),
    )


def _finding(
    check: dict,
    check_type: str,
    request: CheckovScanRequest,
    version: str,
    suppressed: bool,
    native_scan_root: Path,
) -> Finding:
    if type(check) is not dict:
        raise DomainError("Checkov findings must be JSON objects")
    rule_id = canonical_identifier(check.get("check_id"), "Checkov check_id")
    file_path, resource_address, artifact_kind = _resource_evidence(
        check, check_type, request, native_scan_root
    )
    start, end = _line_range(check)
    rule_name_raw = check.get("check_name")
    rule_name = redact_detail(rule_name_raw) if type(rule_name_raw) is str else ""
    return Finding(
        scanner="checkov",
        scanner_version=version,
        rule_id=rule_id,
        resource_address=resource_address,
        location=FindingLocation(file_path, start, end),
        severity=_severity(check.get("severity")),
        rule_name=rule_name,
        native_fingerprint=checkov_occurrence_token(
            version, artifact_kind, file_path, rule_id, resource_address,
            _evaluated_keys(check), check.get("fingerprint") or "",
        ),
        artifact_kind=artifact_kind,
        suppressed=suppressed,
    )


CHECKOV_MAX_JSON_NESTING_DEPTH = 128


def _enforce_json_nesting_depth(decoded: str) -> None:
    """Reject excessive JSON depth before CPython's parser-dependent recursion path.

    Brackets inside JSON strings are data. Escaped quotes and backslashes are tracked so
    the same byte sequence receives the same decision on every supported interpreter.
    Syntax and delimiter balance remain the strict JSON decoder's responsibility.
    """
    depth = 0
    in_string = False
    escaped = False
    for character in decoded:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > CHECKOV_MAX_JSON_NESTING_DEPTH:
                raise DomainError(AdapterReason.JSON_DEPTH_EXCEEDED.value)
        elif character in "]}":
            depth = max(0, depth - 1)


def _decode_documents(raw_output: bytes) -> list[dict]:
    if type(raw_output) is not bytes:
        raise DomainError("raw Checkov output must be bytes")
    if not raw_output:
        raise DomainError(AdapterReason.EMPTY_OUTPUT.value)
    try:
        decoded = raw_output.decode("utf-8", errors="strict")
        _enforce_json_nesting_depth(decoded)
        def strict_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
                result[key] = value
            return result

        payload = json.loads(decoded, object_pairs_hook=strict_object)
    except RecursionError as exc:
        raise DomainError(AdapterReason.MALFORMED_JSON.value) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DomainError(AdapterReason.MALFORMED_JSON.value) from exc
    if type(payload) is dict:
        return [payload]
    if type(payload) is list and payload and all(type(item) is dict for item in payload):
        return payload
    raise DomainError(AdapterReason.UNEXPECTED_TOP_LEVEL.value)


def _normalize(
    raw_output: bytes,
    request: CheckovScanRequest,
    process: CommandResult,
    probed_version: str,
    native_scan_root: Path,
) -> ScannerRun:
    documents = _decode_documents(raw_output)
    summaries: list[dict] = []
    raw_findings: list[Finding] = []
    evaluations: list[CheckEvaluation] = []
    missing_results = False
    aggregate_only = False
    unknown_buckets: set[str] = set()
    seen_frameworks: set[str] = set()
    for document in documents:
        summary = document.get("summary")
        if type(summary) is not dict:
            raise DomainError("Checkov document requires a summary object")
        summaries.append(summary)
        version = summary.get("checkov_version")
        if type(version) is not str:
            raise DomainError("Checkov summary requires checkov_version")
        if version not in CHECKOV_CONTRACT.supported_versions:
            raise DomainError(AdapterReason.UNSUPPORTED_VERSION.value)
        if version != probed_version or version != request.expected_version:
            raise DomainError(AdapterReason.VERSION_MISMATCH.value)
        results = document.get("results")
        check_type = document.get("check_type")
        if results is None:
            missing_results = True
            continue
        if type(results) is not dict:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        if type(check_type) is not str or check_type not in request.frameworks:
            raise DomainError(AdapterReason.FRAMEWORK_MISMATCH.value)
        if check_type in seen_frameworks:
            raise DomainError("Checkov returned duplicate framework documents")
        seen_frameworks.add(check_type)
        known_buckets = {
            "passed_checks": ("passed", CheckEvaluationResult.PASSED),
            "failed_checks": ("failed", CheckEvaluationResult.FAILED),
            "skipped_checks": ("skipped", CheckEvaluationResult.SKIPPED),
            "unknown_checks": (None, CheckEvaluationResult.UNKNOWN),
        }
        parsing_items = results.get("parsing_errors", [])
        if type(parsing_items) is not list:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        if "parsing_errors" in results and (
            _strict_int(summary, "parsing_errors", "summary") != len(parsing_items)
        ):
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        unknown_buckets.update(
            set(results) - set(known_buckets) - {"parsing_errors"}
        )
        for bucket, (summary_key, native_result) in known_buckets.items():
            raw_items = results.get(bucket)
            expected_count = (
                _strict_int(summary, summary_key, "summary")
                if summary_key is not None
                else None
            )
            if raw_items is None:
                if expected_count:
                    aggregate_only = True
                items: list = []
            elif type(raw_items) is list:
                items = raw_items
            else:
                raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
            if expected_count is not None and raw_items is not None and expected_count != len(items):
                raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
            for check in items:
                evaluations.append(
                    _evaluation(
                        check,
                        check_type,
                        request,
                        version,
                        bucket,
                        native_result,
                        native_scan_root,
                    )
                )
                if native_result is CheckEvaluationResult.FAILED:
                    raw_findings.append(
                        _finding(check, check_type, request, version, False, native_scan_root)
                    )
                elif native_result is CheckEvaluationResult.SKIPPED:
                    raw_findings.append(
                        _finding(check, check_type, request, version, True, native_scan_root)
                    )

    evaluation_claims: dict[tuple, set[tuple[str, str]]] = {}
    for item in evaluations:
        evaluation_claims.setdefault(item.evaluation_identity_key, set()).add(
            (item.native_result.value, item.source_bucket)
        )
    if any(len(claims) > 1 for claims in evaluation_claims.values()):
        raise DomainError(AdapterReason.CONTRADICTORY_EVALUATION_EVIDENCE.value)

    passed = sum(_strict_int(item, "passed", "summary") for item in summaries)
    failed_count = sum(_strict_int(item, "failed", "summary") for item in summaries)
    skipped_count = sum(_strict_int(item, "skipped", "summary") for item in summaries)
    parse_errors = sum(_strict_int(item, "parsing_errors", "summary") for item in summaries)
    resource_count = sum(_strict_int(item, "resource_count", "summary") for item in summaries)
    evaluations_reported = passed + failed_count + skipped_count + sum(
        item.native_result is CheckEvaluationResult.UNKNOWN for item in evaluations
    )
    eligible_count = len(request.files_eligible)
    failed_files = min(eligible_count, parse_errors)
    observed_files = {item.file_path for item in evaluations}
    missing_files = sorted(set(request.files_eligible) - observed_files)
    observed_resources = {(item.file_path, item.resource_address) for item in evaluations}
    expected_resources = {
        (item.file_path, item.resource_address) for item in request.expected_resources
    }
    missing_resources = sorted(expected_resources - observed_resources)
    unexpected_resources = sorted(observed_resources - expected_resources)
    if resource_count < len(observed_resources):
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    resource_coverage = ResourceCoverage(
        resources_expected=len(expected_resources),
        resources_observed=len(observed_resources),
        expected_resources_observed=len(expected_resources & observed_resources),
        expected_resources_missing=len(missing_resources),
        unexpected_resources_observed=len(unexpected_resources),
        summary_resources_reported=resource_count,
    )
    coverage = CoverageCounters(
        files_eligible=eligible_count,
        files_discovered=len(observed_files),
        files_parsed=len(observed_files),
        files_failed=failed_files,
        evaluations_reported=evaluations_reported,
        checks_failed_to_execute=0,
        parse_errors=parse_errors,
    )
    if missing_results and eligible_count:
        return _reason_run(
            request,
            AdapterReason.NO_RESULTS_STRUCTURE,
            process=process,
            version=probed_version,
            coverage=coverage,
            resource_coverage=resource_coverage,
            raw_output=raw_output,
            evaluations=tuple(evaluations),
        )
    if missing_results:
        return _reason_run(
            request,
            AdapterReason.EMPTY_ELIGIBLE_SCOPE,
            status=Status.SKIPPED,
            process=process,
            version=probed_version,
            coverage=coverage,
            resource_coverage=resource_coverage,
            raw_output=raw_output,
            evaluations=tuple(evaluations),
        )
    if seen_frameworks != set(request.frameworks):
        return _reason_run(
            request,
            AdapterReason.FRAMEWORK_MISMATCH,
            process=process,
            version=probed_version,
            coverage=coverage,
            resource_coverage=resource_coverage,
            raw_output=raw_output,
        )
    if eligible_count and resource_count == 0:
        return _reason_run(
            request,
            AdapterReason.ZERO_FILES_DISCOVERED,
            process=process,
            version=probed_version,
            coverage=coverage,
            resource_coverage=resource_coverage,
            raw_output=raw_output,
        )
    partial_diagnostics: list[str] = []
    if parse_errors:
        partial_diagnostics.append(AdapterReason.PARTIAL_SCAN.value)
    if aggregate_only:
        partial_diagnostics.append(AdapterReason.AGGREGATE_ONLY_EVIDENCE.value)
    if unknown_buckets:
        partial_diagnostics.append(AdapterReason.UNKNOWN_RESULT_BUCKET.value)
        partial_diagnostics.extend(f"unknown result bucket: {item}" for item in sorted(unknown_buckets))
    if eligible_count and not expected_resources:
        partial_diagnostics.append(AdapterReason.RESOURCE_INVENTORY_MISSING.value)
    if expected_resources and resource_count != len(expected_resources):
        partial_diagnostics.append(AdapterReason.RESOURCE_COUNT_MISMATCH.value)
        partial_diagnostics.append(
            f"summary resource count: {resource_count}; expected: {len(expected_resources)}"
        )
    if missing_files or missing_resources or unexpected_resources:
        partial_diagnostics.append(AdapterReason.COVERAGE_MISMATCH.value)
        partial_diagnostics.extend(f"missing evaluation file: {item}" for item in missing_files)
        partial_diagnostics.extend(
            f"missing evaluation resource: {path}@{resource}"
            for path, resource in missing_resources
        )
        partial_diagnostics.extend(
            f"unexpected evaluation resource: {path}@{resource}"
            for path, resource in unexpected_resources
        )
    status = Status.PARTIAL if partial_diagnostics else Status.PASS
    diagnostics = tuple(partial_diagnostics or [AdapterReason.COMPLETED.value])
    return ScannerRun._from_adapter(
        scanner="checkov",
        scanner_version=probed_version,
        status=status,
        findings=assign_occurrence_indices(raw_findings),
        coverage=coverage,
        resource_coverage=resource_coverage,
        exit_code=process.exit_code if process.exit_code is not None else -1,
        stdout_sha256=process.stdout_sha256,
        stderr_sha256=process.stderr_sha256,
        raw_output_sha256=hashlib.sha256(raw_output).hexdigest(),
        resolved_launcher_path=str(request.executable),
        launcher_digest=request._executable_sha256,
        scanner_environment_digest=(
            request._distribution_identity.scanner_environment_digest
        ),
        policy_inventory_digest=request._distribution_identity.policy_inventory_digest,
        invocation_config_digest=_invocation_config_digest(request),
        installed_distribution_digest=(
            request._distribution_identity.installed_distribution_digest
        ),
        dependency_lock_digest=request._distribution_identity.dependency_lock_digest,
        custom_check_digest=request._distribution_identity.custom_check_digest,
        ruleset_integrity=Status.PASS,
        evaluations=tuple(evaluations),
        input_files=request.eligible_file_evidence,
        duration_ms=process.duration_ms,
        diagnostics=diagnostics,
    )


def evaluate_checkov_target(
    run: ScannerRun,
    rule_id: str,
    resource_address: str,
    file_path: str | None = None,
) -> CheckovTargetEvidence:
    """Return only affirmative native target evidence; absence stays inconclusive."""
    if type(run) is not ScannerRun or run.scanner != "checkov":
        raise DomainError("target evaluation requires an exact Checkov ScannerRun")
    require_trusted_scanner_run(run)
    rule = canonical_identifier(rule_id, "target rule_id")
    resource = canonical_resource_scope(resource_address, "target resource_address")
    path = canonical_repo_path(file_path, "target file_path") if file_path is not None else None
    scoped = tuple(
        item
        for item in run.evaluations
        if item.rule_id == rule
        and item.resource_address == resource
        and (path is None or item.file_path == path)
    )
    results = {item.native_result for item in scoped}
    if CheckEvaluationResult.FAILED in results:
        return _target_evidence(Status.FAIL, CheckTargetReason.TARGET_FAILED, scoped)
    if CheckEvaluationResult.SKIPPED in results:
        return _target_evidence(
            Status.INCONCLUSIVE, CheckTargetReason.TARGET_SUPPRESSED, scoped
        )
    if CheckEvaluationResult.UNKNOWN in results:
        return _target_evidence(
            Status.INCONCLUSIVE,
            CheckTargetReason.TARGET_EVALUATION_UNKNOWN,
            scoped,
        )
    if CheckEvaluationResult.PASSED in results:
        if run.status is not Status.PASS or run.ruleset_integrity is not Status.PASS:
            return _target_evidence(
                Status.INCONCLUSIVE, CheckTargetReason.SCANNER_RUN_NOT_PASS, scoped
            )
        return _target_evidence(
            Status.PASS, CheckTargetReason.AFFIRMATIVE_TARGET_PASS, scoped
        )
    if run.coverage.evaluations_reported > len(run.evaluations):
        return _target_evidence(
            Status.INCONCLUSIVE, CheckTargetReason.AGGREGATE_ONLY_EVIDENCE, ()
        )
    resources = {
        (item.file_path, item.resource_address) for item in run.evaluations
    }
    if not any(
        item_resource == resource and (path is None or item_path == path)
        for item_path, item_resource in resources
    ):
        return _target_evidence(
            Status.INCONCLUSIVE, CheckTargetReason.RESOURCE_NOT_OBSERVED, ()
        )
    if not any(item.rule_id == rule for item in run.evaluations):
        return _target_evidence(
            Status.INCONCLUSIVE, CheckTargetReason.RULE_NOT_OBSERVED, ()
        )
    return _target_evidence(
        Status.INCONCLUSIVE, CheckTargetReason.TARGET_NOT_EVALUATED, ()
    )


class CheckovAdapter:
    """Pinned Checkov adapter. It classifies execution integrity, never a verdict."""

    name = "checkov"

    def contract(self) -> ScannerContract:
        return CHECKOV_CONTRACT

    def normalize(
        self,
        raw_output: bytes,
        request: CheckovScanRequest,
        process: CommandResult,
        probed_version: str,
    ) -> ScannerRun:
        if type(request) is not CheckovScanRequest:
            raise DomainError("request must be an exact CheckovScanRequest")
        if type(process) is not CommandResult:
            raise DomainError("process must be an exact CommandResult")
        failure = _process_failure(request, process)
        if failure is not None:
            return failure
        if type(raw_output) is not bytes:
            return _reason_run(
                request,
                AdapterReason.INVALID_RESULTS_STRUCTURE,
                process=process,
                version=probed_version,
                raw_output=raw_output if type(raw_output) is bytes else None,
            )
        if len(raw_output) > request.max_output_bytes:
            return _reason_run(
                request,
                AdapterReason.TRUNCATED_OUTPUT,
                process=process,
                version=probed_version,
            )
        try:
            return _normalize(
                raw_output, request, process, probed_version, request.scan_root
            )
        except DomainError as exc:
            value = str(exc)
            reason = next(
                (item for item in AdapterReason if item.value == value),
                AdapterReason.INVALID_RESULTS_STRUCTURE,
            )
            return _reason_run(
                request,
                reason,
                process=process,
                version=(
                    probed_version
                    if probed_version in CHECKOV_CONTRACT.supported_versions
                    else request.expected_version
                ),
                raw_output=raw_output,
            )

    def _probe(self, request: CheckovScanRequest) -> tuple[str | None, CommandResult]:
        result = run_command(
            CommandRequest(
                argv=(str(request.executable), "--version"),
                expected_exit_codes=(0,),
                workspace_root=request.workspace_root,
                timeout_seconds=request.timeout_seconds,
                max_output_bytes=request.max_output_bytes,
                max_stdout_bytes=request.max_output_bytes,
                max_stderr_bytes=request.max_output_bytes,
            )
        )
        if result.status is not Status.PASS:
            return None, result
        try:
            lines = result.stdout.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            return None, result
        version = lines[-1].strip() if lines else ""
        if version not in CHECKOV_CONTRACT.supported_versions:
            return version or None, result
        return version, result

    @staticmethod
    def _revalidate_inputs(request: CheckovScanRequest) -> None:
        current_executable = _identity(
            request.executable, "Checkov executable", directory=False
        )
        current_root = _identity(request.scan_root, "scan_root", directory=True)
        if current_executable != request._executable_identity:
            raise DomainError("Checkov executable changed after request validation")
        if _file_sha256(current_executable.resolved) != request._executable_sha256:
            raise DomainError("Checkov executable digest changed after request validation")
        current_distribution = checkov_distribution_identity(
            current_executable.resolved, request.expected_version
        )
        if (
            current_distribution.scanner_environment_digest
            != request._distribution_identity.scanner_environment_digest
        ):
            raise DomainError(AdapterReason.SCANNER_ENVIRONMENT_MISMATCH.value)
        if (
            current_distribution.policy_inventory_digest
            != request._distribution_identity.policy_inventory_digest
        ):
            raise DomainError(AdapterReason.POLICY_INVENTORY_MISMATCH.value)
        if current_root != request._scan_root_identity:
            raise DomainError("scan_root changed after request validation")
        if not _within(current_root.resolved, request.workspace_root):
            raise DomainError("scan_root no longer resolves inside workspace_root")
        for relative, expected, bound in zip(
            request.files_eligible,
            request._eligible_identities,
            request.eligible_file_evidence,
        ):
            current = _identity(
                request.scan_root / relative, "eligible file", directory=False
            )
            if current != expected or not _within(current.resolved, request.scan_root):
                raise DomainError(AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value)
            current_evidence = _stream_bound_file(
                request.scan_root / relative,
                relative,
                max_bytes=request.max_file_bytes,
            )
            if current_evidence != bound:
                raise DomainError(AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value)

    @staticmethod
    def _read_raw_output(path: Path, cap: int) -> bytes:
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise DomainError("Checkov raw output must be a nonsymlink regular file")
            if metadata.st_size > cap:
                raise DomainError(AdapterReason.TRUNCATED_OUTPUT.value)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    raise DomainError("Checkov raw output changed before read")
                chunks: list[bytes] = []
                remaining = cap + 1
                while remaining:
                    chunk = os.read(descriptor, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise DomainError(AdapterReason.RAW_OUTPUT_MISSING.value) from exc
        result = b"".join(chunks)
        if len(result) > cap:
            raise DomainError(AdapterReason.TRUNCATED_OUTPUT.value)
        return result

    @staticmethod
    def _build_scan_view(request: CheckovScanRequest, destination: Path) -> None:
        destination.mkdir(mode=0o700)
        governed_names = {".checkov.yml", ".checkov.yaml"}
        for relative, bound in zip(
            request.files_eligible, request.eligible_file_evidence
        ):
            if Path(relative).name in governed_names:
                raise DomainError("candidate Checkov configuration cannot be an eligible artifact")
            source = request.scan_root / relative
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(target, flags, 0o600)
                try:
                    current = _stream_bound_file(
                        source,
                        relative,
                        max_bytes=request.max_file_bytes,
                        destination_descriptor=descriptor,
                    )
                    if current != bound:
                        raise DomainError(
                            AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value
                        )
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                copied_evidence = _stream_bound_file(
                    target,
                    relative,
                    max_bytes=request.max_file_bytes,
                )
                if (
                    copied_evidence.size != bound.size
                    or copied_evidence.sha256 != bound.sha256
                ):
                    raise DomainError("private scan-view digest verification failed")
            except OSError as exc:
                raise DomainError(AdapterReason.SCAN_VIEW_PREPARATION_FAILED.value) from exc

    def scan(self, request: CheckovScanRequest) -> ScannerRun:
        if type(request) is not CheckovScanRequest:
            raise DomainError("request must be an exact CheckovScanRequest")
        if not request.files_eligible:
            return _reason_run(
                request,
                AdapterReason.EMPTY_ELIGIBLE_SCOPE,
                status=Status.SKIPPED,
            )
        try:
            self._revalidate_inputs(request)
        except (DomainError, OSError) as exc:
            value = str(exc)
            reason = next(
                (item for item in AdapterReason if item.value == value),
                AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION,
            )
            return _reason_run(request, reason)
        try:
            output_dir = Path(tempfile.mkdtemp(prefix="iacgv-checkov-output-"))
            output_identity = _identity(output_dir, "Checkov output directory", directory=True)
        except (DomainError, OSError):
            return _reason_run(request, AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED)
        raw_output: bytes | None = None
        process: CommandResult | None = None
        terminal_run: ScannerRun | None = None
        raw_reason: AdapterReason | None = None
        normalized_run: ScannerRun | None = None
        cleanup_failed = False
        probed_version: str | None = None
        preparation_complete = False
        try:
            self._revalidate_inputs(request)
            safe_config = output_dir / "iacgv-checkov.yml"
            safe_config.write_text("quiet: false\n", encoding="utf-8")
            scan_view = output_dir / "scan"
            self._build_scan_view(request, scan_view)
            preparation_complete = True
            probed_version, probe = self._probe(request)
            process = probe
            if probed_version != request.expected_version:
                reason = (
                    AdapterReason.VERSION_PROBE_FAILED
                    if probed_version is None
                    else AdapterReason.UNSUPPORTED_VERSION
                    if probed_version not in CHECKOV_CONTRACT.supported_versions
                    else AdapterReason.VERSION_MISMATCH
                )
                terminal_run = _reason_run(request, reason, process=probe)
            else:
                self._revalidate_inputs(request)
                argv = (
                    str(request.executable),
                    "-d",
                    str(scan_view),
                    "--framework",
                    *request.frameworks,
                    "--output",
                    "json",
                    "--compact",
                    "--output-file-path",
                    str(output_dir),
                    "--config-file",
                    str(safe_config),
                    "--skip-download",
                    "--download-external-modules",
                    "false",
                    "--skip-results-upload",
                )
                process = run_command(
                    CommandRequest(
                        argv=argv,
                        expected_exit_codes=CHECKOV_CONTRACT.expected_exit_codes,
                        workspace_root=request.workspace_root,
                        timeout_seconds=request.timeout_seconds,
                        max_output_bytes=request.max_output_bytes,
                        max_stdout_bytes=request.max_output_bytes,
                        max_stderr_bytes=request.max_output_bytes,
                    )
                )
                failure = _process_failure(request, process)
                if failure is not None:
                    terminal_run = failure
                else:
                    if _identity(
                        output_dir, "Checkov output directory", directory=True
                    ) != output_identity:
                        raise DomainError(
                            AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value
                        )
                    candidates = sorted(
                        item for item in output_dir.iterdir() if item.suffix == ".json"
                    )
                    if len(candidates) != 1:
                        raw_reason = AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED
                    else:
                        try:
                            raw_output = self._read_raw_output(
                                candidates[0], request.max_output_bytes
                            )
                            normalized_run = _normalize(
                                raw_output,
                                request,
                                process,
                                probed_version,
                                scan_view,
                            )
                        except DomainError as exc:
                            value = str(exc)
                            raw_reason = next(
                                (item for item in AdapterReason if item.value == value),
                                AdapterReason.INVALID_RESULTS_STRUCTURE,
                            )
        except (DomainError, OSError) as exc:
            value = str(exc)
            raw_reason = next(
                (item for item in AdapterReason if item.value == value),
                AdapterReason.SCAN_VIEW_PREPARATION_FAILED
                if not preparation_complete
                else AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED,
            )
        finally:
            try:
                shutil.rmtree(output_dir)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            return _reason_run(
                request,
                AdapterReason.OUTPUT_CLEANUP_FAILED,
                process=process,
                version=probed_version or request.expected_version,
                raw_output=raw_output,
            )
        if terminal_run is not None:
            return terminal_run
        if raw_reason is not None:
            return _reason_run(
                request,
                raw_reason,
                process=process,
                version=probed_version or request.expected_version,
                raw_output=raw_output,
            )
        if normalized_run is not None:
            return normalized_run
        if raw_output is None:
            return _reason_run(
                request,
                AdapterReason.RAW_OUTPUT_MISSING,
                process=process,
                version=probed_version,
            )
        return _reason_run(
            request,
            AdapterReason.INVALID_RESULTS_STRUCTURE,
            process=process,
            version=probed_version,
        )


__all__ = [
    "CHECKOV_CONTRACT",
    "CheckovAdapter",
    "CheckovDistributionIdentity",
    "CheckovEligibleFileEvidence",
    "CheckovKubernetesIdentity",
    "CheckovScanRequest",
    "CheckovTargetEvidence",
    "checkov_distribution_identity",
    "checkov_occurrence_token",
    "evaluate_checkov_target",
    "require_trusted_checkov_target_evidence",
]
