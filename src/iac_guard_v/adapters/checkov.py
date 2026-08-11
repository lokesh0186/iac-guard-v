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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..enums import ArtifactKind, Severity, Status
from ..fingerprints import (
    canonicalize_kubernetes_identity,
    canonicalize_scan_path,
    canonicalize_terraform_address,
)
from ..models import (
    CoverageCounters,
    DomainError,
    Finding,
    FindingLocation,
    ScannerRun,
    canonical_identifier,
    canonical_repo_path,
    require_int,
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
    expected_checks_loaded: int | None = None
    kubernetes_identities: tuple = ()
    timeout_seconds: int = 120
    max_output_bytes: int = 25 * 1024 * 1024
    _executable_identity: _FilesystemIdentity = field(init=False, repr=False, compare=False)
    _scan_root_identity: _FilesystemIdentity = field(init=False, repr=False, compare=False)
    _eligible_identities: tuple = field(init=False, repr=False, compare=False)
    _executable_sha256: str = field(init=False, repr=False, compare=False)

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
        eligible: list[str] = []
        eligible_identities: list[_FilesystemIdentity] = []
        for item in self.files_eligible:
            relative = canonical_repo_path(item, "eligible file")
            identity = _identity(scan_root / relative, "eligible file", directory=False)
            if not _within(identity.resolved, scan_root):
                raise DomainError("eligible file must be a regular file inside scan_root")
            eligible.append(relative)
            eligible_identities.append(identity)
        if len(eligible) != len(set(eligible)):
            raise DomainError("files_eligible must not contain duplicates")
        version = canonical_identifier(self.expected_version, "expected Checkov version")
        if version not in CHECKOV_CONTRACT.supported_versions:
            raise DomainError("expected Checkov version is outside the supported contract")
        if self.expected_checks_loaded is not None:
            if require_int(self.expected_checks_loaded, "expected_checks_loaded") < 0:
                raise DomainError("expected_checks_loaded must be >= 0")
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
        object.__setattr__(self, "_scan_root_identity", scan_root_identity)
        object.__setattr__(
            self,
            "_eligible_identities",
            tuple(identity_by_path[path] for path in sorted(eligible)),
        )
        object.__setattr__(
            self,
            "kubernetes_identities",
            tuple(sorted(identities, key=lambda item: (item.file_path, item.checkov_resource))),
        )


def _reason_run(
    request: CheckovScanRequest,
    reason: AdapterReason,
    *,
    status: Status = Status.ERROR,
    process: CommandResult | None = None,
    version: str | None = None,
    coverage: CoverageCounters | None = None,
    diagnostics: tuple[str, ...] = (),
    raw_output: bytes | None = None,
) -> ScannerRun:
    diagnostic_values = (reason.value, *diagnostics)
    return ScannerRun(
        scanner="checkov",
        scanner_version=version or request.expected_version,
        status=status,
        coverage=coverage or CoverageCounters(files_eligible=len(request.files_eligible)),
        exit_code=(process.exit_code if process and process.exit_code is not None else -1),
        stdout_sha256=(process.stdout_sha256 if process else ""),
        stderr_sha256=(process.stderr_sha256 if process else ""),
        raw_output_sha256=(
            hashlib.sha256(raw_output).hexdigest()
            if type(raw_output) is bytes
            else ""
        ),
        executable_or_image_digest=request._executable_sha256,
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


def _native_fingerprint(check: dict) -> str:
    native_raw = check.get("fingerprint")
    if native_raw:
        return canonical_identifier(native_raw, "Checkov fingerprint")
    check_result = check.get("check_result")
    if check_result is None:
        return ""
    if type(check_result) is not dict:
        raise DomainError("Checkov check_result must be a JSON object")
    evaluated = check_result.get("evaluated_keys")
    if evaluated is None:
        return ""
    if type(evaluated) is not list or any(type(item) is not str for item in evaluated):
        raise DomainError("Checkov evaluated_keys must be a JSON string array")
    payload = json.dumps(evaluated, ensure_ascii=False, separators=(",", ":")).encode()
    return f"checkov-eval-v1:{hashlib.sha256(payload).hexdigest()}"


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
    resource = canonical_identifier(check.get("resource"), "Checkov resource")
    file_path = _path_from_check(check, native_scan_root)
    if file_path not in request.files_eligible:
        raise DomainError("Checkov reported a path outside the independently eligible set")
    if check_type == "terraform":
        resource_address = canonicalize_terraform_address(resource)
        artifact_kind = ArtifactKind.TERRAFORM_HCL
    else:
        identities = {
            (item.file_path, item.checkov_resource): item.canonical_address
            for item in request.kubernetes_identities
        }
        try:
            resource_address = identities[(file_path, resource)]
        except KeyError as exc:
            raise DomainError(AdapterReason.MISSING_RESOURCE_IDENTITY.value) from exc
        artifact_kind = ArtifactKind.KUBERNETES_YAML
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
        native_fingerprint=_native_fingerprint(check),
        artifact_kind=artifact_kind,
        suppressed=suppressed,
    )


def _decode_documents(raw_output: bytes) -> list[dict]:
    if type(raw_output) is not bytes:
        raise DomainError("raw Checkov output must be bytes")
    if not raw_output:
        raise DomainError(AdapterReason.EMPTY_OUTPUT.value)
    try:
        decoded = raw_output.decode("utf-8", errors="strict")
        payload = json.loads(decoded)
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
    missing_results = False
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
        failed = results.get("failed_checks")
        skipped = results.get("skipped_checks", [])
        if type(failed) is not list or type(skipped) is not list:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        if _strict_int(summary, "failed", "summary") != len(failed):
            raise DomainError("Checkov summary.failed does not match failed_checks")
        if _strict_int(summary, "skipped", "summary") != len(skipped):
            raise DomainError("Checkov summary.skipped does not match skipped_checks")
        for check in failed:
            raw_findings.append(
                _finding(check, check_type, request, version, False, native_scan_root)
            )
        for check in skipped:
            raw_findings.append(
                _finding(check, check_type, request, version, True, native_scan_root)
            )

    passed = sum(_strict_int(item, "passed", "summary") for item in summaries)
    failed_count = sum(_strict_int(item, "failed", "summary") for item in summaries)
    skipped_count = sum(_strict_int(item, "skipped", "summary") for item in summaries)
    parse_errors = sum(_strict_int(item, "parsing_errors", "summary") for item in summaries)
    resource_count = sum(_strict_int(item, "resource_count", "summary") for item in summaries)
    checks_loaded = passed + failed_count + skipped_count
    eligible_count = len(request.files_eligible)
    failed_files = min(eligible_count, parse_errors)
    parsed_files = max(0, eligible_count - failed_files)
    discovered_files = eligible_count if not missing_results else 0
    coverage = CoverageCounters(
        files_eligible=eligible_count,
        files_discovered=discovered_files,
        files_parsed=parsed_files if not missing_results else 0,
        files_failed=failed_files,
        checks_loaded=checks_loaded,
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
            raw_output=raw_output,
        )
    if missing_results:
        return _reason_run(
            request,
            AdapterReason.NO_RESULTS_STRUCTURE,
            status=Status.PASS,
            process=process,
            version=probed_version,
            coverage=coverage,
            raw_output=raw_output,
        )
    if seen_frameworks != set(request.frameworks):
        return _reason_run(
            request,
            AdapterReason.FRAMEWORK_MISMATCH,
            process=process,
            version=probed_version,
            coverage=coverage,
            raw_output=raw_output,
        )
    if eligible_count and resource_count == 0:
        return _reason_run(
            request,
            AdapterReason.ZERO_FILES_DISCOVERED,
            process=process,
            version=probed_version,
            coverage=coverage,
            raw_output=raw_output,
        )
    if request.expected_checks_loaded is not None and checks_loaded != request.expected_checks_loaded:
        return _reason_run(
            request,
            AdapterReason.CHECK_INVENTORY_MISMATCH,
            process=process,
            version=probed_version,
            coverage=coverage,
            raw_output=raw_output,
        )
    status = Status.PARTIAL if parse_errors else Status.PASS
    reason = AdapterReason.PARTIAL_SCAN if parse_errors else AdapterReason.COMPLETED
    return ScannerRun(
        scanner="checkov",
        scanner_version=probed_version,
        status=status,
        findings=assign_occurrence_indices(raw_findings),
        coverage=coverage,
        exit_code=process.exit_code if process.exit_code is not None else -1,
        stdout_sha256=process.stdout_sha256,
        stderr_sha256=process.stderr_sha256,
        raw_output_sha256=hashlib.sha256(raw_output).hexdigest(),
        executable_or_image_digest=request._executable_sha256,
        duration_ms=process.duration_ms,
        diagnostics=(reason.value,),
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
        if current_root != request._scan_root_identity:
            raise DomainError("scan_root changed after request validation")
        if not _within(current_root.resolved, request.workspace_root):
            raise DomainError("scan_root no longer resolves inside workspace_root")
        for relative, expected in zip(request.files_eligible, request._eligible_identities):
            current = _identity(
                request.scan_root / relative, "eligible file", directory=False
            )
            if current != expected or not _within(current.resolved, request.scan_root):
                raise DomainError("eligible file changed after request validation")

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
        for relative, expected in zip(request.files_eligible, request._eligible_identities):
            if Path(relative).name in governed_names:
                raise DomainError("candidate Checkov configuration cannot be an eligible artifact")
            source = request.scan_root / relative
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(source, flags)
                try:
                    metadata = os.fstat(descriptor)
                    current = _FilesystemIdentity(
                        source.resolve(strict=True), metadata.st_dev, metadata.st_ino
                    )
                    if current != expected or not stat.S_ISREG(metadata.st_mode):
                        raise DomainError("eligible file changed while building scan view")
                    with os.fdopen(os.dup(descriptor), "rb") as input_stream:
                        with target.open("xb") as output_stream:
                            shutil.copyfileobj(input_stream, output_stream, 64 * 1024)
                finally:
                    os.close(descriptor)
            except OSError as exc:
                raise DomainError("eligible file could not be copied into private scan view") from exc

    def scan(self, request: CheckovScanRequest) -> ScannerRun:
        if type(request) is not CheckovScanRequest:
            raise DomainError("request must be an exact CheckovScanRequest")
        self._revalidate_inputs(request)
        probed_version, probe = self._probe(request)
        if probed_version != request.expected_version:
            reason = (
                AdapterReason.VERSION_PROBE_FAILED
                if probed_version is None
                else AdapterReason.UNSUPPORTED_VERSION
                if probed_version not in CHECKOV_CONTRACT.supported_versions
                else AdapterReason.VERSION_MISMATCH
            )
            return _reason_run(
                request,
                reason,
                status=Status.ERROR,
                process=probe,
            )

        output_dir = Path(tempfile.mkdtemp(prefix="iacgv-checkov-output-"))
        raw_output: bytes | None = None
        process: CommandResult | None = None
        process_failure: ScannerRun | None = None
        raw_reason: AdapterReason | None = None
        normalized_run: ScannerRun | None = None
        cleanup_failed = False
        try:
            self._revalidate_inputs(request)
            safe_config = output_dir / "iacgv-checkov.yml"
            # Configargparse rejects an empty YAML document. This single inert setting
            # creates a mapping while the argument array remains the authoritative
            # contract. Most importantly, it prevents discovery of candidate config.
            safe_config.write_text("quiet: true\n", encoding="utf-8")
            scan_view = output_dir / "scan"
            self._build_scan_view(request, scan_view)
            argv = (
                str(request.executable),
                "-d",
                str(scan_view),
                "--framework",
                *request.frameworks,
                "--output",
                "json",
                "--quiet",
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
                process_failure = failure
            else:
                candidates = sorted(
                    item for item in output_dir.iterdir() if item.suffix == ".json"
                )
                if len(candidates) == 1:
                    try:
                        raw_output = self._read_raw_output(
                            candidates[0], request.max_output_bytes
                        )
                    except DomainError as exc:
                        raw_reason = next(
                            (item for item in AdapterReason if item.value == str(exc)),
                            AdapterReason.RAW_OUTPUT_MISSING,
                        )
                if raw_output is not None:
                    try:
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
        finally:
            try:
                shutil.rmtree(output_dir)
            except OSError:
                cleanup_failed = True
        assert process is not None
        if cleanup_failed:
            return _reason_run(
                request,
                AdapterReason.OUTPUT_CLEANUP_FAILED,
                process=process,
                version=probed_version,
                raw_output=raw_output,
            )
        if process_failure is not None:
            return process_failure
        if raw_reason is not None:
            return _reason_run(
                request,
                raw_reason,
                process=process,
                version=probed_version,
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
    "CheckovKubernetesIdentity",
    "CheckovScanRequest",
]
