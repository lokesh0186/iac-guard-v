"""Pinned kubeconform 0.8.0 validation against the signed offline schema tree."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import InitVar, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ..adapters.base import (
    read_locked_output_directory, remove_private_tree, require_hardened_docker_argv,
)
from ..adapters.phase_e_lock import (
    LockedContainerIdentity, ProtectedKubernetesSchemaIdentity, require_locked_identity,
)
from ..adapters.phase_e_runtime import (
    TrustedContainerRuntime, require_trusted_container_runtime,
    revalidate_trusted_container_runtime,
)
from ..enums import ScanRole, Status
from ..models import BoundInputFile, DomainError, canonical_repo_path, safe_report_text
from ..process import CommandRequest, CommandResult, run_command
from .base import (
    ValidationDiagnostic, ValidationReason, ValidatorExecutionEvidence, canonical_sha256,
)
from .terraform import _strict_json


_REQUEST_CONTEXT = object()
_DOCKER_USER = "65532:65532"
_DOCKER_PIDS_LIMIT = "128"
_DOCKER_MEMORY = "512m"
_DOCKER_CPUS = "1.0"
_CONTROLS = (
    "cap-drop-all", "cpu-limit", "memory-limit", "network-none",
    "no-ignore-missing-schemas", "no-new-privileges", "non-root",
    "offline-schema-only", "output-inventory", "pid-limit", "read-only-root",
    "sealed-input",
)
_BUILTIN_GROUPS = (
    "admissionregistration.k8s.io/", "apiextensions.k8s.io/", "apps/",
    "authentication.k8s.io/", "authorization.k8s.io/", "autoscaling/", "batch/",
    "certificates.k8s.io/", "coordination.k8s.io/", "discovery.k8s.io/",
    "events.k8s.io/", "flowcontrol.apiserver.k8s.io/", "networking.k8s.io/",
    "node.k8s.io/", "policy/", "rbac.authorization.k8s.io/", "resource.k8s.io/",
    "scheduling.k8s.io/", "storage.k8s.io/",
)


def _bound_file(root: Path, relative: str, max_bytes: int) -> tuple[BoundInputFile, bytes]:
    path_text = canonical_repo_path(relative, "kubeconform input")
    if not path_text.endswith((".yaml", ".yml", ".json")):
        raise DomainError("kubeconform accepts only YAML and JSON inputs")
    path = root / path_text
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise DomainError("kubeconform input must be a nonsymlink regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                raise DomainError(ValidationReason.INPUT_CHANGED_DURING_VALIDATION.value)
            chunks = []
            size = 0
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise DomainError("kubeconform input exceeds its byte limit")
                chunks.append(chunk)
                digest.update(chunk)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DomainError(ValidationReason.INPUT_CHANGED_DURING_VALIDATION.value) from exc
    return (
        BoundInputFile(path_text, "regular_file", size, digest.hexdigest(),
                       metadata.st_dev, metadata.st_ino),
        b"".join(chunks),
    )


def _discover(relative: str, raw: bytes):
    from ..engine import _kubernetes_json_resources, _kubernetes_resources
    if relative.endswith(".json"):
        return _kubernetes_json_resources(relative, raw)
    return _kubernetes_resources(relative, raw)


@dataclass(frozen=True, slots=True)
class KubeconformValidationRequest:
    workspace_root: Path
    scan_root: Path
    role: ScanRole
    files_eligible: tuple
    input_evidence: tuple
    resource_identities: tuple
    syntax_error: str
    container_runtime: TrustedContainerRuntime
    locked_identity: LockedContainerIdentity
    schema_identity: ProtectedKubernetesSchemaIdentity
    protected_crd_schema: ProtectedKubernetesSchemaIdentity | None = None
    timeout_seconds: int = 120
    max_output_bytes: int = 8 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_input_bytes: int = 64 * 1024 * 1024
    _trusted_context: InitVar[object] = None
    _trusted_request: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if _trusted_context is not _REQUEST_CONTEXT:
            raise DomainError("kubeconform requests require the sealed factory")
        if type(self.role) is not ScanRole or self.role not in {ScanRole.BASELINE, ScanRole.CANDIDATE}:
            raise DomainError("kubeconform role must be baseline or candidate")
        identity = require_locked_identity(self.locked_identity, "kubeconform")
        if (
            type(self.schema_identity) is not ProtectedKubernetesSchemaIdentity
            or not self.schema_identity._trusted_schema_evidence
        ):
            raise DomainError("kubeconform schema must come from signed E0.3 evidence")
        if self.protected_crd_schema is not None and (
            type(self.protected_crd_schema) is not ProtectedKubernetesSchemaIdentity
            or not self.protected_crd_schema._trusted_schema_evidence
        ):
            raise DomainError("CRD schemas must be protected digest-bound evidence")
        try:
            workspace = self.workspace_root.resolve(strict=True)
            scan = self.scan_root.resolve(strict=True)
            scan.relative_to(workspace)
        except (OSError, ValueError) as exc:
            raise DomainError("kubeconform scan root must be inside its workspace") from exc
        runtime = require_trusted_container_runtime(
            self.container_runtime, workspace_root=workspace,
            protected_evidence_identity=identity.protected_evidence_identity,
        )
        paths = tuple(canonical_repo_path(item) for item in self.files_eligible)
        if type(self.files_eligible) is not tuple or paths != tuple(sorted(set(paths))):
            raise DomainError("kubeconform paths must be sorted and unique")
        if type(self.input_evidence) is not tuple or tuple(
            item.file_path for item in self.input_evidence if type(item) is BoundInputFile
        ) != paths:
            raise DomainError("kubeconform input evidence is incomplete")
        resources = tuple(self.resource_identities)
        if resources != tuple(sorted(set(resources))) or any(type(item) is not str for item in resources):
            raise DomainError("kubeconform resource identities must be sorted and unique")
        if type(self.syntax_error) is not str:
            raise DomainError("kubeconform syntax_error must be a string")
        for name in ("timeout_seconds", "max_output_bytes", "max_file_bytes", "max_total_input_bytes"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise DomainError(f"{name} must be positive")
        if sum(item.size for item in self.input_evidence) > self.max_total_input_bytes:
            raise DomainError("kubeconform inputs exceed total-byte limit")
        object.__setattr__(self, "workspace_root", workspace)
        object.__setattr__(self, "scan_root", scan)
        object.__setattr__(self, "container_runtime", runtime)
        object.__setattr__(self, "files_eligible", paths)
        object.__setattr__(self, "resource_identities", resources)
        object.__setattr__(self, "_trusted_request", True)

    @property
    def sealed_snapshot_identity(self) -> str:
        return canonical_sha256({
            "role": self.role.value,
            "files": [item.canonical_dict() for item in self.input_evidence],
            "resources": list(self.resource_identities), "syntax_error": self.syntax_error,
        })


def create_kubeconform_validation_request(
    *, workspace_root: Path, scan_root: Path, role: ScanRole, files_eligible: tuple,
    container_runtime: TrustedContainerRuntime, locked_identity: LockedContainerIdentity,
    schema_identity: ProtectedKubernetesSchemaIdentity,
    protected_crd_schema: ProtectedKubernetesSchemaIdentity | None = None,
    timeout_seconds: int = 120, max_output_bytes: int = 8 * 1024 * 1024,
    max_file_bytes: int = 8 * 1024 * 1024,
    max_total_input_bytes: int = 64 * 1024 * 1024,
) -> KubeconformValidationRequest:
    scan = scan_root.resolve(strict=True)
    paths = tuple(sorted(canonical_repo_path(item) for item in files_eligible))
    if len(paths) != len(set(paths)):
        raise DomainError("kubeconform paths contain duplicates")
    evidence = []
    identities = []
    syntax_error = ""
    for relative in paths:
        bound, raw = _bound_file(scan, relative, max_file_bytes)
        evidence.append(bound)
        try:
            _resources, detected = _discover(relative, raw)
            identities.extend(f"{item.file_path}:{item.canonical_address}" for item in detected)
        except DomainError as exc:
            syntax_error = safe_report_text(str(exc), "kubernetes syntax error", 4096)
    return KubeconformValidationRequest(
        workspace_root=workspace_root, scan_root=scan_root, role=role,
        files_eligible=paths, input_evidence=tuple(evidence),
        resource_identities=tuple(sorted(set(identities))), syntax_error=syntax_error,
        container_runtime=container_runtime, locked_identity=locked_identity,
        schema_identity=schema_identity, protected_crd_schema=protected_crd_schema,
        timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
        max_file_bytes=max_file_bytes, max_total_input_bytes=max_total_input_bytes,
        _trusted_context=_REQUEST_CONTEXT,
    )


def _custom_resources(resources: tuple[str, ...]) -> bool:
    for identity in resources:
        api_version = identity.split(":", 1)[-1].rsplit("/", 3)[0]
        if api_version != "v1" and not api_version.startswith(_BUILTIN_GROUPS):
            return True
    return False


def _native_path(value: Any, eligible: tuple[str, ...]) -> str:
    if type(value) is not str or not value:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    parts = PurePosixPath(value.replace("\\", "/")).parts
    matches = [item for item in eligible if tuple(PurePosixPath(item).parts) == parts[-len(PurePosixPath(item).parts):]]
    if len(matches) != 1:
        raise DomainError(ValidationReason.INCOMPLETE_COVERAGE.value)
    return matches[0]


def _parse_native(
    raw: bytes, request: KubeconformValidationRequest, exit_code: int | None,
) -> tuple[Status, ValidationReason, tuple, str, int]:
    payload = _strict_json(raw)
    if set(payload) != {"resources", "summary"}:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    resources = payload["resources"]
    summary = payload["summary"]
    if type(resources) is not list or type(summary) is not dict or set(summary) != {
        "valid", "invalid", "errors", "skipped",
    }:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    for value in summary.values():
        if type(value) is not int or value < 0:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    total = sum(summary.values())
    if total != len(request.resource_identities):
        raise DomainError(ValidationReason.INCOMPLETE_COVERAGE.value)
    diagnostics = []
    observed_nonvalid = 0
    for item in resources:
        if type(item) is not dict or not {"filename", "kind", "name", "version", "status", "msg"} <= set(item):
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        if set(item) - {"filename", "kind", "name", "version", "status", "msg", "validationErrors"}:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        path = _native_path(item["filename"], request.files_eligible)
        if any(type(item.get(name)) is not str for name in ("kind", "name", "version", "status", "msg")):
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        status = item["status"]
        if status not in {"statusInvalid", "statusError", "statusSkipped"}:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        severity = "error" if status != "statusSkipped" else "warning"
        diagnostics.append(ValidationDiagnostic(severity, status, item["msg"] or status, path))
        observed_nonvalid += 1
    if observed_nonvalid != summary["invalid"] + summary["errors"] + summary["skipped"]:
        raise DomainError(ValidationReason.DIAGNOSTIC_CONTRADICTION.value)
    if exit_code != (0 if summary["invalid"] == summary["errors"] == summary["skipped"] == 0 else 1):
        raise DomainError(ValidationReason.DIAGNOSTIC_CONTRADICTION.value)
    # kubeconform may emit resources in filesystem traversal order.  Preserve
    # raw bytes separately, but make the semantic identity independent of that
    # volatile ordering.
    semantic_payload = {
        "resources": sorted(
            resources,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        ),
        "summary": summary,
    }
    canonical = canonical_sha256(semantic_payload)
    if summary["errors"] or summary["skipped"]:
        missing = any("could not find schema" in item.detail.casefold() for item in diagnostics)
        reason = (
            ValidationReason.CRD_SCHEMA_UNAVAILABLE
            if missing and _custom_resources(request.resource_identities)
            and request.protected_crd_schema is None
            else ValidationReason.MISSING_SCHEMA if missing
            else ValidationReason.UNSUPPORTED_CONDITION
        )
        return Status.INCONCLUSIVE, reason, tuple(diagnostics), canonical, total
    if summary["invalid"]:
        if request.role is ScanRole.BASELINE:
            return Status.INCONCLUSIVE, ValidationReason.BASELINE_EVIDENCE_INVALID, tuple(diagnostics), canonical, total
        return Status.FAIL, ValidationReason.INVALID_CONFIGURATION, tuple(diagnostics), canonical, total
    return Status.PASS, ValidationReason.COMPLETED, tuple(diagnostics), canonical, total


def _copy_view(request: KubeconformValidationRequest, view: Path) -> None:
    view.mkdir(mode=0o700)
    for expected in request.input_evidence:
        current, raw = _bound_file(request.scan_root, expected.file_path, request.max_file_bytes)
        if current != expected:
            raise DomainError(ValidationReason.INPUT_CHANGED_DURING_VALIDATION.value)
        destination = view / expected.file_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        try:
            os.write(descriptor, raw)
        finally:
            os.close(descriptor)


def _evidence(
    request: KubeconformValidationRequest, *, status: Status, reason: ValidationReason,
    process: CommandResult | None = None, raw: bytes = b"", diagnostics: tuple = (),
    canonical: str | None = None, validated: int = 0, output_manifest: str = "",
    argv: tuple = (),
) -> ValidatorExecutionEvidence:
    empty = hashlib.sha256(b"").hexdigest()
    return ValidatorExecutionEvidence._from_execution(
        validator_id="kubeconform_schema", tool="kubeconform",
        version=request.locked_identity.version, status=status, reason=reason,
        advisory_only=False, diagnostics=diagnostics,
        resource_identities=request.resource_identities, input_files=request.input_evidence,
        files_eligible=len(request.input_evidence),
        files_validated=(len(request.input_evidence) if validated else 0),
        resources_expected=len(request.resource_identities), resources_validated=validated,
        runtime_identity=request.container_runtime.identity,
        tool_environment_identity=canonical_sha256({
            "tool": request.locked_identity.environment_digest,
            "schema": request.schema_identity.identity,
            "crd_schema": request.protected_crd_schema.identity if request.protected_crd_schema else None,
        }),
        invocation_identity=canonical_sha256({
            "argv": ["protected-container-runtime", *argv[1:]] if argv else [],
            "snapshot": request.sealed_snapshot_identity,
            "schema": request.schema_identity.identity,
        }),
        sealed_snapshot_identity=request.sealed_snapshot_identity,
        stdout_sha256=process.stdout_sha256 if process else empty,
        stderr_sha256=process.stderr_sha256 if process else empty,
        native_output_bytes_sha256=hashlib.sha256(raw).hexdigest(),
        canonical_native_output_sha256=canonical or hashlib.sha256(raw).hexdigest(),
        output_directory_manifest_sha256=output_manifest or empty,
        exit_code=process.exit_code if process else None,
        duration_ms=process.duration_ms if process else 0,
        execution_controls=_CONTROLS,
    )


class KubeconformValidator:
    def validate(self, request: KubeconformValidationRequest) -> ValidatorExecutionEvidence:
        if type(request) is not KubeconformValidationRequest or not request._trusted_request:
            raise DomainError("kubeconform validation requires a sealed request")
        if request.syntax_error:
            reason = (
                ValidationReason.INVALID_CONFIGURATION if request.role is ScanRole.CANDIDATE
                else ValidationReason.BASELINE_EVIDENCE_INVALID
            )
            status = Status.FAIL if request.role is ScanRole.CANDIDATE else Status.INCONCLUSIVE
            return _evidence(request, status=status, reason=reason,
                             diagnostics=(ValidationDiagnostic("error", reason.value, request.syntax_error),))
        if not request.resource_identities:
            return _evidence(request, status=Status.SKIPPED, reason=ValidationReason.EMPTY_SCOPE)
        work = Path(tempfile.mkdtemp(prefix="iacgv-kubeconform-"))
        process = None
        raw = b""
        output_manifest = ""
        result = None
        try:
            revalidate_trusted_container_runtime(request.container_runtime, workspace_root=request.workspace_root)
            request.schema_identity.revalidate()
            if request.protected_crd_schema:
                request.protected_crd_schema.revalidate()
            view = work / "input"
            output = work / "output"
            _copy_view(request, view)
            output.mkdir(mode=0o733)
            schema_location = "file:///schemas/{{.ResourceKind}}{{.KindSuffix}}.json"
            argv = (
                str(request.container_runtime.executable_path), "run", "--rm", "--pull", "never",
                "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", _DOCKER_PIDS_LIMIT,
                "--memory", _DOCKER_MEMORY, "--cpus", _DOCKER_CPUS, "--user", _DOCKER_USER,
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "-v", f"{view}:/iacgv-input:ro", "-v", f"{output}:/iacgv-output:rw",
                "-v", f"{request.schema_identity.schema_root}:/schemas:ro",
                "--entrypoint", "/kubeconform", request.locked_identity.execution_reference,
                "-output", "json", "-strict", "-summary", "-schema-location", schema_location,
                "/iacgv-input",
            )
            if request.protected_crd_schema:
                argv = (*argv[:-1], "-schema-location", "file:///crd-schemas/{{.ResourceKind}}.json", argv[-1])
                argv = (*argv[:argv.index("--entrypoint")], "-v", f"{request.protected_crd_schema.schema_root}:/crd-schemas:ro", *argv[argv.index("--entrypoint"):])
            require_hardened_docker_argv(argv, pids_limit=_DOCKER_PIDS_LIMIT,
                                         memory=_DOCKER_MEMORY, cpus=_DOCKER_CPUS, user=_DOCKER_USER)
            revalidate_trusted_container_runtime(request.container_runtime, workspace_root=request.workspace_root)
            process = run_command(CommandRequest(
                argv=argv, expected_exit_codes=(0, 1), workspace_root=request.workspace_root,
                timeout_seconds=request.timeout_seconds, max_output_bytes=request.max_output_bytes,
                max_stdout_bytes=request.max_output_bytes, max_stderr_bytes=request.max_output_bytes,
                env_extra={"PYTHONDONTWRITEBYTECODE": "1"},
            ))
            if process.argv != argv:
                raise DomainError(ValidationReason.RUNTIME_INTEGRITY_FAILED.value)
            for expected in request.input_evidence:
                if _bound_file(request.scan_root, expected.file_path, request.max_file_bytes)[0] != expected:
                    raise DomainError(ValidationReason.INPUT_CHANGED_DURING_VALIDATION.value)
            request.schema_identity.revalidate()
            if request.protected_crd_schema:
                request.protected_crd_schema.revalidate()
            _, output_manifest = read_locked_output_directory(
                output, allowed_files=(), max_file_bytes=request.max_output_bytes,
                max_total_bytes=request.max_output_bytes,
            )
            if process.status is not Status.PASS:
                reason = ValidationReason.TIMEOUT if process.timed_out else ValidationReason.PROCESS_ERROR
                result = _evidence(request, status=Status.INCONCLUSIVE, reason=reason,
                                   process=process, output_manifest=output_manifest, argv=argv)
            else:
                raw = process.stdout
                status, reason, diagnostics, canonical, validated = _parse_native(raw, request, process.exit_code)
                result = _evidence(request, status=status, reason=reason, process=process,
                                   raw=raw, diagnostics=diagnostics, canonical=canonical,
                                   validated=validated, output_manifest=output_manifest, argv=argv)
        except (DomainError, OSError) as exc:
            try:
                reason = ValidationReason(str(exc))
            except ValueError:
                reason = ValidationReason.PROCESS_ERROR
            result = _evidence(request, status=Status.INCONCLUSIVE, reason=reason,
                               process=process, raw=raw, output_manifest=output_manifest)
        try:
            remove_private_tree(work)
        except OSError:
            return _evidence(request, status=Status.INCONCLUSIVE,
                             reason=ValidationReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED,
                             process=process, raw=raw, output_manifest=output_manifest)
        assert result is not None
        return result


__all__ = [
    "KubeconformValidationRequest", "KubeconformValidator",
    "create_kubeconform_validation_request",
]
