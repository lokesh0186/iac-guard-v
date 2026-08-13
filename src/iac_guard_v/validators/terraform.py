"""Offline OpenTofu 1.12.5 and protected Terraform 1.15.8 validation."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import InitVar, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ..adapters.base import (
    read_locked_output_directory, remove_private_tree, require_hardened_docker_argv,
)
from ..adapters.phase_e_lock import LockedContainerIdentity, require_locked_identity
from ..adapters.phase_e_runtime import (
    TrustedContainerRuntime, require_trusted_container_runtime,
    revalidate_trusted_container_runtime,
)
from ..enums import ScanRole, Status
from ..models import BoundInputFile, DomainError, canonical_repo_path
from ..process import CommandRequest, CommandResult, ProcessReason, run_command
from .base import (
    ValidationDiagnostic, ValidationReason, ValidatorExecutionEvidence, canonical_sha256,
)
from .materialization import (
    SealedSourceFile, bind_source_file, materialize_view,
    materialized_view_manifest, prepare_writable_output_directory,
    read_sealed_source, revalidate_materialized_view,
    revalidate_readonly_file, seal_readonly_tree, verified_write,
    revalidate_writable_output_directory,
)


_REQUEST_CONTEXT = object()
_MAX_JSON_DEPTH = 128
_DOCKER_USER = "65532:65532"
_DOCKER_PIDS_LIMIT = "128"
_DOCKER_MEMORY = "512m"
_DOCKER_CPUS = "1.0"
_CONTROLS = (
    "cap-drop-all", "cpu-limit", "credentials-removed", "isolated-home",
    "isolated-tf-data-dir", "memory-limit", "network-none", "no-auto-init",
    "no-new-privileges", "non-root", "output-inventory", "pid-limit",
    "read-only-root", "sealed-input", "updates-disabled",
)
_ENTRYPOINTS = {"opentofu": "/usr/local/bin/tofu", "terraform": "/bin/terraform"}
_VALIDATOR_IDS = {"opentofu": "opentofu_validate", "terraform": "terraform_validate"}
_NEEDS_INIT = re.compile(
    r"(?:missing required provider|required plugins? (?:are|is) not installed|"
    r"module (?:is )?not installed|run [`']?(?:tofu|terraform) init|"
    r"unavailable provider|module source has changed)", re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ValidationModule:
    role: ScanRole
    module_root: str
    files: tuple
    module_snapshot_sha256: str
    tool: str

    def __post_init__(self) -> None:
        if self.role not in {ScanRole.BASELINE, ScanRole.CANDIDATE}:
            raise DomainError("validation module role is invalid")
        if self.module_root != ".":
            object.__setattr__(self, "module_root", canonical_repo_path(self.module_root))
        if (
            type(self.files) is not tuple or not self.files
            or self.files != tuple(sorted(set(self.files)))
        ):
            raise DomainError("validation module files must be nonempty, sorted, and unique")
        if any(
            (PurePosixPath(item).parent.as_posix() or ".") != self.module_root
            for item in self.files
        ):
            raise DomainError("validation module contains a file from another directory")
        if re.fullmatch(r"[0-9a-f]{64}", self.module_snapshot_sha256) is None:
            raise DomainError("validation module snapshot must be a SHA-256")
        if self.tool not in {"opentofu", "terraform", "tflint"}:
            raise DomainError("validation module tool is unsupported")

    def canonical_dict(self) -> dict:
        return {
            "role": self.role.value, "module_root": self.module_root,
            "files": list(self.files), "module_snapshot_sha256": self.module_snapshot_sha256,
            "tool": self.tool,
        }


def _module_plan(
    files: tuple[BoundInputFile, ...], role: ScanRole, tool: str,
) -> ValidationModule:
    roots = {PurePosixPath(item.file_path).parent.as_posix() or "." for item in files}
    if len(roots) != 1:
        raise DomainError(ValidationReason.MODULE_SCOPE_UNRESOLVED.value)
    return ValidationModule(
        role, next(iter(roots)), tuple(item.file_path for item in files),
        canonical_sha256([item.canonical_dict() for item in files]), tool,
    )


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _bound_file(root: Path, relative: str, max_bytes: int) -> BoundInputFile:
    return bind_source_file(
        root, relative, max_bytes, (".tf", ".tf.json"), "Terraform validator input",
    )[0].evidence


def _snapshot_identity(files: tuple[BoundInputFile, ...]) -> str:
    return canonical_sha256([item.canonical_dict() for item in files])


@dataclass(frozen=True, slots=True)
class TerraformValidationRequest:
    workspace_root: Path
    scan_root: Path
    files_eligible: tuple
    input_evidence: tuple
    container_runtime: TrustedContainerRuntime
    locked_identity: LockedContainerIdentity
    module_plan: ValidationModule | None = None
    source_bindings: tuple = ()
    timeout_seconds: int = 120
    max_output_bytes: int = 4 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_input_bytes: int = 64 * 1024 * 1024
    _trusted_context: InitVar[object] = None
    _trusted_request: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if _trusted_context is not _REQUEST_CONTEXT:
            raise DomainError("Terraform validation requests require the sealed factory")
        identity = require_locked_identity(self.locked_identity, self.locked_identity.tool)
        if identity.tool not in {"opentofu", "terraform"}:
            raise DomainError("Terraform validator requires an OpenTofu or Terraform lock")
        try:
            workspace = self.workspace_root.resolve(strict=True)
            scan = self.scan_root.resolve(strict=True)
        except OSError as exc:
            raise DomainError("Terraform validation roots are unavailable") from exc
        if not workspace.is_dir() or not scan.is_dir() or not _inside(scan, workspace):
            raise DomainError("Terraform scan root must be inside its workspace")
        if (scan / ".terraform").exists() or (scan / ".terraform").is_symlink():
            raise DomainError("candidate .terraform state is forbidden")
        runtime = require_trusted_container_runtime(
            self.container_runtime, workspace_root=workspace,
            protected_evidence_identity=identity.protected_evidence_identity,
        )
        if (
            type(self.files_eligible) is not tuple or type(self.input_evidence) is not tuple
            or type(self.source_bindings) is not tuple
        ):
            raise DomainError("Terraform validator inputs must be exact tuples")
        paths = tuple(canonical_repo_path(item) for item in self.files_eligible)
        if paths != tuple(sorted(set(paths))) or not paths:
            raise DomainError("Terraform validator paths must be nonempty, sorted, and unique")
        evidence = tuple(self.input_evidence)
        if any(type(item) is not BoundInputFile for item in evidence):
            raise DomainError("Terraform input evidence must contain BoundInputFile")
        if tuple(item.file_path for item in evidence) != paths:
            raise DomainError("Terraform evidence must exactly cover eligible files")
        if (
            any(type(item) is not SealedSourceFile for item in self.source_bindings)
            or tuple(item.evidence for item in self.source_bindings) != evidence
        ):
            raise DomainError("Terraform sealed source bindings are incomplete")
        if (
            type(self.module_plan) is not ValidationModule
            or self.module_plan.tool != identity.tool
            or self.module_plan.files != paths
            or self.module_plan.module_snapshot_sha256
            != canonical_sha256([item.canonical_dict() for item in evidence])
        ):
            raise DomainError("Terraform validation module plan is invalid")
        for name in ("timeout_seconds", "max_output_bytes", "max_file_bytes", "max_total_input_bytes"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise DomainError(f"{name} must be a positive integer")
        if sum(item.size for item in evidence) > self.max_total_input_bytes:
            raise DomainError("Terraform input exceeds total-byte limit")
        object.__setattr__(self, "workspace_root", workspace)
        object.__setattr__(self, "scan_root", scan)
        object.__setattr__(self, "container_runtime", runtime)
        object.__setattr__(self, "files_eligible", paths)
        object.__setattr__(self, "input_evidence", evidence)
        object.__setattr__(self, "_trusted_request", True)

    @property
    def sealed_snapshot_identity(self) -> str:
        return canonical_sha256({
            "module": self.module_plan.canonical_dict(),
            "files": [item.canonical_dict() for item in self.input_evidence],
        })


def create_terraform_validation_request(
    *, workspace_root: Path, scan_root: Path, files_eligible: tuple,
    container_runtime: TrustedContainerRuntime, locked_identity: LockedContainerIdentity,
    timeout_seconds: int = 120, max_output_bytes: int = 4 * 1024 * 1024,
    max_file_bytes: int = 8 * 1024 * 1024,
    max_total_input_bytes: int = 64 * 1024 * 1024,
    role: ScanRole = ScanRole.CANDIDATE,
) -> TerraformValidationRequest:
    paths = tuple(sorted(canonical_repo_path(item) for item in files_eligible))
    if any(not item.endswith((".tf", ".tf.json")) for item in paths):
        raise DomainError("Terraform validator accepts only .tf and .tf.json inputs")
    if len(paths) != len(set(paths)):
        raise DomainError("Terraform validator paths contain duplicates")
    bindings = tuple(bind_source_file(
        scan_root, item, max_file_bytes, (".tf", ".tf.json"), "Terraform validator input",
    )[0] for item in paths)
    evidence = tuple(item.evidence for item in bindings)
    module_plan = _module_plan(evidence, role, locked_identity.tool)
    return TerraformValidationRequest(
        workspace_root=workspace_root, scan_root=scan_root, files_eligible=paths,
        input_evidence=evidence, source_bindings=bindings, module_plan=module_plan,
        container_runtime=container_runtime,
        locked_identity=locked_identity, timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes, max_file_bytes=max_file_bytes,
        max_total_input_bytes=max_total_input_bytes, _trusted_context=_REQUEST_CONTEXT,
    )


def _strict_json(raw: bytes) -> dict:
    if type(raw) is not bytes or not raw:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value) from exc
    depth = 0
    in_string = escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise DomainError(ValidationReason.JSON_DEPTH_EXCEEDED.value)
        elif character in "]}":
            depth -= 1
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DomainError(ValidationReason.DUPLICATE_JSON_KEY.value)
            result[key] = value
        return result
    try:
        payload = json.loads(text, object_pairs_hook=unique)
    except RecursionError as exc:
        raise DomainError(ValidationReason.JSON_DEPTH_EXCEEDED.value) from exc
    except json.JSONDecodeError as exc:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value) from exc
    if type(payload) is not dict:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    return payload


def _diagnostic(item: Any, request: TerraformValidationRequest) -> ValidationDiagnostic:
    if type(item) is not dict or set(item) - {"severity", "summary", "detail", "range", "snippet"}:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    severity = item.get("severity")
    summary = item.get("summary")
    detail = item.get("detail", "")
    if severity not in {"error", "warning"} or type(summary) is not str or not summary:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    if type(detail) is not str:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    file_path = ""
    line = None
    range_ = item.get("range")
    if range_ is not None:
        if type(range_) is not dict or type(range_.get("filename")) is not str:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        native_path = canonical_repo_path(range_["filename"])
        module_root = request.module_plan.module_root
        file_path = native_path if module_root == "." else f"{module_root}/{native_path}"
        if file_path not in request.files_eligible:
            raise DomainError(ValidationReason.INCOMPLETE_COVERAGE.value)
        start = range_.get("start")
        if type(start) is dict and type(start.get("line")) is int and start["line"] >= 1:
            line = start["line"]
    return ValidationDiagnostic(severity, summary, detail, file_path, line)


def _parse_native(
    raw: bytes, exit_code: int | None, request: TerraformValidationRequest,
) -> tuple[Status, ValidationReason, tuple, str]:
    payload = _strict_json(raw)
    if set(payload) != {"format_version", "valid", "error_count", "warning_count", "diagnostics"}:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    if payload["format_version"] != "1.0" or type(payload["valid"]) is not bool:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    if any(type(payload[name]) is not int or payload[name] < 0 for name in ("error_count", "warning_count")):
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    if type(payload["diagnostics"]) is not list:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    diagnostics = tuple(_diagnostic(item, request) for item in payload["diagnostics"])
    errors = sum(item.severity == "error" for item in diagnostics)
    warnings = sum(item.severity == "warning" for item in diagnostics)
    if errors != payload["error_count"] or warnings != payload["warning_count"]:
        raise DomainError(ValidationReason.DIAGNOSTIC_CONTRADICTION.value)
    canonical = canonical_sha256(payload)
    if payload["valid"]:
        if errors or exit_code != 0:
            raise DomainError(ValidationReason.DIAGNOSTIC_CONTRADICTION.value)
        return Status.PASS, ValidationReason.COMPLETED, diagnostics, canonical
    if not errors or exit_code != 1:
        raise DomainError(ValidationReason.DIAGNOSTIC_CONTRADICTION.value)
    combined = "\n".join(f"{item.summary}\n{item.detail}" for item in diagnostics)
    if _NEEDS_INIT.search(combined):
        return Status.INCONCLUSIVE, ValidationReason.NEEDS_INIT, diagnostics, canonical
    return Status.FAIL, ValidationReason.INVALID_CONFIGURATION, diagnostics, canonical


def _copy_and_revalidate(request: TerraformValidationRequest, view: Path) -> str:
    return materialize_view(
        request.scan_root, request.source_bindings, view, request.max_file_bytes,
    )


def _invocation_identity(
    request: TerraformValidationRequest, argv: tuple[str, ...], materialized_view: str,
) -> str:
    redacted = list(argv)
    redacted[0] = "protected-container-runtime"
    return canonical_sha256({
        "tool": request.locked_identity.tool,
        "version": request.locked_identity.version,
        "contract": request.locked_identity.invocation_contract,
        "argv": redacted,
        "snapshot": request.sealed_snapshot_identity,
        "materialized_view": materialized_view,
        "controls": list(_CONTROLS),
    })


def _evidence(
    request: TerraformValidationRequest, *, status: Status, reason: ValidationReason,
    diagnostics: tuple = (), process: CommandResult | None = None, raw: bytes = b"",
    canonical: str | None = None, output_manifest: str | None = None,
    materialized_view: str | None = None, files_validated: int = 0,
) -> ValidatorExecutionEvidence:
    empty = hashlib.sha256(b"").hexdigest()
    return ValidatorExecutionEvidence._from_execution(
        validator_id=_VALIDATOR_IDS[request.locked_identity.tool],
        tool=request.locked_identity.tool, version=request.locked_identity.version,
        status=status, reason=reason, advisory_only=False, diagnostics=diagnostics,
        resource_identities=(),
        input_files=request.input_evidence, files_eligible=len(request.input_evidence),
        files_validated=files_validated,
        resources_expected=0, resources_validated=0,
        runtime_identity=request.container_runtime.identity,
        tool_environment_identity=request.locked_identity.environment_digest,
        invocation_identity=(
            _invocation_identity(request, process.argv, materialized_view or materialized_view_manifest(request.input_evidence)) if process else canonical_sha256({
                "tool": request.locked_identity.tool, "snapshot": request.sealed_snapshot_identity,
                "module": request.module_plan.canonical_dict(),
                "not_executed": True,
            })
        ),
        sealed_snapshot_identity=request.sealed_snapshot_identity,
        materialized_view_sha256=(
            materialized_view or materialized_view_manifest(request.input_evidence)
        ),
        stdout_sha256=process.stdout_sha256 if process else empty,
        stderr_sha256=process.stderr_sha256 if process else empty,
        native_output_bytes_sha256=hashlib.sha256(raw).hexdigest(),
        canonical_native_output_sha256=canonical or hashlib.sha256(raw).hexdigest(),
        output_directory_manifest_sha256=output_manifest or empty,
        exit_code=process.exit_code if process else None,
        duration_ms=process.duration_ms if process else 0,
        validation_scope=tuple(sorted({
            "kind": "terraform-module", "role": request.module_plan.role.value,
            "module_root": request.module_plan.module_root,
            "module_snapshot_sha256": request.module_plan.module_snapshot_sha256,
            "tool": request.module_plan.tool,
        }.items())),
        execution_controls=_CONTROLS,
    )


class TerraformValidator:
    """Execute exactly one locked validate command; never init, plan, or apply."""

    def validate(self, request: TerraformValidationRequest) -> ValidatorExecutionEvidence:
        if type(request) is not TerraformValidationRequest or not request._trusted_request:
            raise DomainError("Terraform validation requires a sealed request")
        work = Path(tempfile.mkdtemp(prefix="iacgv-terraform-validate-"))
        process: CommandResult | None = None
        raw = b""
        output_manifest = ""
        materialized_view = ""
        result: ValidatorExecutionEvidence | None = None
        try:
            revalidate_trusted_container_runtime(
                request.container_runtime, workspace_root=request.workspace_root
            )
            view = work / "input"
            output = work / "output"
            protected = work / "protected"
            materialized_view = _copy_and_revalidate(request, view)
            prepare_writable_output_directory(output)
            protected.mkdir(mode=0o755)
            cli = protected / "terraform.rc"
            verified_write(
                cli,
                b'provider_installation { filesystem_mirror { path = "/no-providers" } }\n',
            )
            seal_readonly_tree(protected)
            tool = request.locked_identity.tool
            module_dir = (
                "/iacgv-input" if request.module_plan.module_root == "."
                else f"/iacgv-input/{request.module_plan.module_root}"
            )
            argv = (
                str(request.container_runtime.executable_path), "run", "--rm", "--pull", "never",
                "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", _DOCKER_PIDS_LIMIT,
                "--memory", _DOCKER_MEMORY, "--cpus", _DOCKER_CPUS, "--user", _DOCKER_USER,
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "-e", "HOME=/tmp/iacgv-home", "-e", "TF_DATA_DIR=/tmp/iacgv-data",
                "-e", "TF_CLI_CONFIG_FILE=/iacgv-protected/terraform.rc",
                "-e", "CHECKPOINT_DISABLE=1", "-e", "TF_IN_AUTOMATION=1",
                "-v", f"{view}:/iacgv-input:ro", "-v", f"{output}:/iacgv-output:rw",
                "-v", f"{protected}:/iacgv-protected:ro", "-w", module_dir,
                "--entrypoint", _ENTRYPOINTS[tool], request.locked_identity.execution_reference,
                "validate", "-json",
            )
            require_hardened_docker_argv(
                argv, pids_limit=_DOCKER_PIDS_LIMIT, memory=_DOCKER_MEMORY,
                cpus=_DOCKER_CPUS, user=_DOCKER_USER,
            )
            revalidate_trusted_container_runtime(
                request.container_runtime, workspace_root=request.workspace_root
            )
            process = run_command(CommandRequest(
                argv=argv, expected_exit_codes=(0, 1), workspace_root=request.workspace_root,
                timeout_seconds=request.timeout_seconds,
                max_output_bytes=request.max_output_bytes,
                max_stdout_bytes=request.max_output_bytes,
                max_stderr_bytes=request.max_output_bytes,
                env_extra={"PYTHONDONTWRITEBYTECODE": "1"},
            ))
            if process.argv != argv:
                raise DomainError(ValidationReason.RUNTIME_INTEGRITY_FAILED.value)
            materialize_check = materialized_view_manifest(request.input_evidence)
            for sealed in request.source_bindings:
                read_sealed_source(request.scan_root, sealed, request.max_file_bytes)
            revalidate_materialized_view(
                view, request.input_evidence, request.max_file_bytes,
            )
            revalidate_readonly_file(
                cli,
                b'provider_installation { filesystem_mirror { path = "/no-providers" } }\n',
            )
            revalidate_writable_output_directory(output)
            if materialized_view != materialize_check:
                raise DomainError(ValidationReason.MATERIALIZED_VIEW_INTEGRITY_FAILED.value)
            revalidate_trusted_container_runtime(
                request.container_runtime, workspace_root=request.workspace_root
            )
            _, output_manifest = read_locked_output_directory(
                output, allowed_files=(), max_file_bytes=request.max_output_bytes,
                max_total_bytes=request.max_output_bytes,
            )
            revalidate_writable_output_directory(output)
            if process.status is not Status.PASS:
                reason = (
                    ValidationReason.TIMEOUT if process.timed_out
                    else ValidationReason.PROCESS_ERROR
                )
                result = _evidence(request, status=Status.INCONCLUSIVE, reason=reason,
                                   process=process, output_manifest=output_manifest,
                                   materialized_view=materialized_view)
            else:
                raw = process.stdout
                status, reason, diagnostics, canonical = _parse_native(
                    raw, process.exit_code, request,
                )
                result = _evidence(
                    request, status=status, reason=reason, diagnostics=diagnostics,
                    process=process, raw=raw, canonical=canonical,
                    output_manifest=output_manifest,
                    materialized_view=materialized_view,
                    files_validated=len(request.input_evidence),
                )
        except (DomainError, OSError) as exc:
            try:
                reason = ValidationReason(str(exc))
            except ValueError:
                reason = ValidationReason.PROCESS_ERROR
            result = _evidence(
                request, status=Status.INCONCLUSIVE, reason=reason,
                process=process, raw=raw, output_manifest=output_manifest,
                materialized_view=materialized_view,
            )
        try:
            remove_private_tree(work)
        except OSError:
            return _evidence(
                request, status=Status.INCONCLUSIVE,
                reason=ValidationReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED,
                process=process, raw=raw, output_manifest=output_manifest,
                materialized_view=materialized_view,
            )
        assert result is not None
        return result


__all__ = [
    "TerraformValidationRequest", "TerraformValidator", "ValidationModule",
    "create_terraform_validation_request",
]
