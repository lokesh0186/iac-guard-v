"""Optional, non-security TFLint 0.64.0 advisory validation."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import InitVar, dataclass, field
from pathlib import Path, PurePosixPath

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
from ..process import CommandRequest, CommandResult, run_command
from .base import (
    ValidationDiagnostic, ValidationReason, ValidatorExecutionEvidence, canonical_sha256,
)
from .terraform import ValidationModule, _module_plan, _strict_json
from .materialization import (
    SealedSourceFile, bind_source_file, materialize_view,
    materialized_view_manifest, prepare_writable_output_directory,
    read_sealed_source, revalidate_materialized_view,
    revalidate_readonly_file, seal_readonly_tree, verified_write,
    revalidate_writable_output_directory, TrustedValidationScopePlan,
    create_trusted_validation_scope_plan, revalidate_validation_scope_plan,
)


_REQUEST_CONTEXT = object()
_CONFIG_CONTEXT = object()
_PROTECTED_CONFIG = "config { disabled_by_default = false }\n"
_DOCKER_USER = "65532:65532"
_DOCKER_PIDS_LIMIT = "128"
_DOCKER_MEMORY = "512m"
_DOCKER_CPUS = "1.0"
_CONTROLS = (
    "advisory-only", "cap-drop-all", "cpu-limit", "memory-limit", "network-none",
    "no-candidate-config", "no-init", "no-new-privileges", "non-root",
    "output-inventory", "pid-limit", "protected-config", "read-only-root",
    "sealed-input",
)
_PLUGIN_NEED = re.compile(r"(?:plugin|ruleset).*(?:not found|not installed|initialize|init)", re.I)


@dataclass(frozen=True, slots=True)
class ProtectedTflintConfig:
    """Closed built-in-rules-only configuration; no candidate or plugin source."""

    content_sha256: str
    allowed_plugins: tuple
    rule_settings: tuple
    source_identity: str
    _trusted_context: InitVar[object] = None
    _trusted_config: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if self.content_sha256 != hashlib.sha256(_PROTECTED_CONFIG.encode()).hexdigest():
            raise DomainError("TFLint protected configuration digest is invalid")
        if self.allowed_plugins != () or self.rule_settings != ():
            raise DomainError("E3.3 authorizes bundled TFLint rules only")
        if self.source_identity != "iac-guard-v-protected-tflint-builtin-v1":
            raise DomainError("TFLint protected configuration source is invalid")
        if _trusted_context is _CONFIG_CONTEXT:
            object.__setattr__(self, "_trusted_config", True)

    @property
    def identity(self) -> str:
        return canonical_sha256(self.canonical_dict())

    def canonical_dict(self) -> dict:
        return {
            "content_sha256": self.content_sha256,
            "allowed_plugins": [], "rule_settings": [],
            "source_identity": self.source_identity,
        }


def load_protected_tflint_config() -> ProtectedTflintConfig:
    """Return the closed built-in-rules-only E3.3 configuration."""
    return ProtectedTflintConfig(
        hashlib.sha256(_PROTECTED_CONFIG.encode()).hexdigest(), (), (),
        "iac-guard-v-protected-tflint-builtin-v1", _trusted_context=_CONFIG_CONTEXT,
    )


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _bound_file(root: Path, relative: str, max_bytes: int) -> tuple[BoundInputFile, bytes]:
    sealed, raw = bind_source_file(
        root, relative, max_bytes, (".tf", ".tf.json"), "TFLint input",
    )
    return sealed.evidence, raw


@dataclass(frozen=True, slots=True)
class TflintValidationRequest:
    workspace_root: Path
    scan_root: Path
    files_eligible: tuple
    input_evidence: tuple
    container_runtime: TrustedContainerRuntime
    locked_identity: LockedContainerIdentity
    protected_config: ProtectedTflintConfig
    scope_plan: TrustedValidationScopePlan | None = None
    module_plan: ValidationModule | None = None
    source_bindings: tuple = ()
    timeout_seconds: int = 120
    max_output_bytes: int = 4 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    _trusted_context: InitVar[object] = None
    _trusted_request: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if _trusted_context is not _REQUEST_CONTEXT:
            raise DomainError("TFLint requests require the sealed factory")
        identity = require_locked_identity(self.locked_identity, "tflint")
        if type(self.protected_config) is not ProtectedTflintConfig or not self.protected_config._trusted_config:
            raise DomainError("TFLint requires protected configuration")
        workspace = self.workspace_root.resolve(strict=True)
        scan = self.scan_root.resolve(strict=True)
        if not _inside(scan, workspace):
            raise DomainError("TFLint scan root must be inside its workspace")
        for forbidden in (".tflint.hcl", ".terraform"):
            if (scan / forbidden).exists() or (scan / forbidden).is_symlink():
                raise DomainError(f"candidate {forbidden} is forbidden")
        runtime = require_trusted_container_runtime(
            self.container_runtime, workspace_root=workspace,
            protected_evidence_identity=identity.protected_evidence_identity,
        )
        paths = tuple(canonical_repo_path(item) for item in self.files_eligible)
        if paths != tuple(sorted(set(paths))) or not paths:
            raise DomainError("TFLint input paths must be nonempty, sorted, and unique")
        if any(type(item) is not BoundInputFile for item in self.input_evidence):
            raise DomainError("TFLint input evidence is invalid")
        if tuple(item.file_path for item in self.input_evidence) != paths:
            raise DomainError("TFLint evidence must exactly cover eligible files")
        if (
            type(self.source_bindings) is not tuple
            or any(type(item) is not SealedSourceFile for item in self.source_bindings)
            or tuple(item.evidence for item in self.source_bindings) != self.input_evidence
        ):
            raise DomainError("TFLint sealed source bindings are incomplete")
        if (
            type(self.module_plan) is not ValidationModule
            or self.module_plan.tool != "tflint"
            or self.module_plan.files != paths
            or self.module_plan.module_snapshot_sha256
            != canonical_sha256([item.canonical_dict() for item in self.input_evidence])
        ):
            raise DomainError("TFLint validation module plan is invalid")
        if (
            type(self.scope_plan) is not TrustedValidationScopePlan
            or self.scope_plan.scope_kind != "terraform-module"
            or self.scope_plan.role is not self.module_plan.role
            or self.scope_plan.files != self.input_evidence
            or self.scope_plan.module_root != self.module_plan.module_root
        ):
            raise DomainError("TFLint trusted validation scope is invalid")
        module_directory = (
            scan if self.module_plan.module_root == "."
            else scan / self.module_plan.module_root
        )
        for forbidden in (".tflint.hcl", ".terraform"):
            candidate_entry = module_directory / forbidden
            if candidate_entry.exists() or candidate_entry.is_symlink():
                raise DomainError(f"candidate module {forbidden} is forbidden")
        if type(self.timeout_seconds) is not int or self.timeout_seconds <= 0:
            raise DomainError("TFLint timeout must be positive")
        if type(self.max_output_bytes) is not int or self.max_output_bytes <= 0:
            raise DomainError("TFLint output limit must be positive")
        object.__setattr__(self, "workspace_root", workspace)
        object.__setattr__(self, "scan_root", scan)
        object.__setattr__(self, "container_runtime", runtime)
        object.__setattr__(self, "files_eligible", paths)
        object.__setattr__(self, "_trusted_request", True)

    @property
    def sealed_snapshot_identity(self) -> str:
        return self.scope_plan.manifest_sha256


def create_tflint_validation_request(
    *, workspace_root: Path, scan_root: Path, files_eligible: tuple,
    container_runtime: TrustedContainerRuntime, locked_identity: LockedContainerIdentity,
    protected_config: ProtectedTflintConfig, timeout_seconds: int = 120,
    max_output_bytes: int = 4 * 1024 * 1024, max_file_bytes: int = 8 * 1024 * 1024,
    role: ScanRole = ScanRole.CANDIDATE,
) -> TflintValidationRequest:
    scan = scan_root.resolve(strict=True)
    paths = tuple(sorted(canonical_repo_path(item) for item in files_eligible))
    if any(not item.endswith((".tf", ".tf.json")) for item in paths):
        raise DomainError("TFLint accepts only Terraform inputs")
    if len(paths) != len(set(paths)):
        raise DomainError("TFLint input paths contain duplicates")
    bindings = tuple(bind_source_file(
        scan_root, item, max_file_bytes, (".tf", ".tf.json"), "TFLint input",
    )[0] for item in paths)
    scope_plan = create_trusted_validation_scope_plan(
        scan_root=scan_root, files_eligible=paths, role=role,
        scope_kind="terraform-module", max_file_bytes=max_file_bytes,
    )
    evidence = tuple(item.evidence for item in bindings)
    module_plan = _module_plan(evidence, role, "tflint")
    return TflintValidationRequest(
        workspace_root=workspace_root, scan_root=scan_root, files_eligible=paths,
        input_evidence=evidence, container_runtime=container_runtime,
        locked_identity=locked_identity, protected_config=protected_config,
        module_plan=module_plan, source_bindings=bindings, scope_plan=scope_plan,
        timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
        max_file_bytes=max_file_bytes,
        _trusted_context=_REQUEST_CONTEXT,
    )


def _position(value: object) -> tuple[int, int]:
    if type(value) is not dict or set(value) != {"line", "column"}:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    line, column = value["line"], value["column"]
    if type(line) is not int or line < 1 or type(column) is not int or column < 1:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    return line, column


def _range(
    value: object, allowed: tuple[str, ...], module_root: str,
) -> tuple[str, int]:
    if type(value) is not dict or set(value) != {"filename", "start", "end"}:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    filename = value["filename"]
    if type(filename) is not str:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    path = PurePosixPath(filename).as_posix().removeprefix("./")
    if module_root != ".":
        path = f"{module_root}/{path}"
    if path not in allowed:
        raise DomainError(ValidationReason.INCOMPLETE_COVERAGE.value)
    start = _position(value["start"])
    end = _position(value["end"])
    if end < start:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    return path, start[0]


def _parse_native(
    raw: bytes, request: TflintValidationRequest, exit_code: int | None,
) -> tuple[Status, ValidationReason, tuple, str]:
    payload = _strict_json(raw)
    if set(payload) != {"issues", "errors"} or type(payload["issues"]) is not list or type(payload["errors"]) is not list:
        raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
    diagnostics: list[ValidationDiagnostic] = []
    semantic_issues = []
    for issue in payload["issues"]:
        required = {"rule", "message", "range", "callers", "fixable", "fixed"}
        if type(issue) is not dict or set(issue) != required:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        rule = issue["rule"]
        if type(rule) is not dict or set(rule) != {"name", "severity", "link"}:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        if any(type(rule.get(key)) is not str or not rule[key] for key in ("name", "severity", "link")):
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        if rule["severity"] not in {"error", "warning", "notice"}:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        if type(issue["message"]) is not str or not issue["message"] or type(issue["callers"]) is not list:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        if type(issue["fixable"]) is not bool or type(issue["fixed"]) is not bool:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        path, line = _range(
            issue["range"], request.files_eligible, request.module_plan.module_root,
        )
        diagnostics.append(ValidationDiagnostic(
            "info" if rule["severity"] == "notice" else rule["severity"],
            rule["name"], issue["message"], path, line,
        ))
        semantic_issues.append(issue)
    native_errors = []
    for item in payload["errors"]:
        if type(item) is not dict or not {"message", "severity"} <= set(item) or set(item) - {"summary", "message", "severity", "range"}:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        if item["severity"] not in {"error", "warning"} or type(item["message"]) is not str or not item["message"]:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        summary = item.get("summary", "TFLint execution diagnostic")
        if type(summary) is not str or not summary:
            raise DomainError(ValidationReason.MALFORMED_OUTPUT.value)
        path = ""
        line = None
        if "range" in item:
            path, line = _range(
                item["range"], request.files_eligible, request.module_plan.module_root,
            )
        diagnostics.append(ValidationDiagnostic(item["severity"], summary, item["message"], path, line))
        native_errors.append(item)
    semantic = {
        "issues": sorted(semantic_issues, key=lambda item: json.dumps(item, sort_keys=True)),
        "errors": sorted(native_errors, key=lambda item: json.dumps(item, sort_keys=True)),
    }
    canonical = canonical_sha256(semantic)
    if native_errors:
        if exit_code != 1:
            raise DomainError(ValidationReason.DIAGNOSTIC_CONTRADICTION.value)
        text = "\n".join(item["message"] for item in native_errors)
        reason = ValidationReason.PLUGIN_INITIALIZATION_REQUIRED if _PLUGIN_NEED.search(text) else ValidationReason.UNSUPPORTED_CONDITION
        return Status.INCONCLUSIVE, reason, tuple(diagnostics), canonical
    expected_exit = 2 if semantic_issues else 0
    if exit_code != expected_exit:
        raise DomainError(ValidationReason.DIAGNOSTIC_CONTRADICTION.value)
    # Advisory findings are visible but cannot turn this optional non-security
    # gate into security proof or a required failure.
    return Status.PASS, ValidationReason.COMPLETED, tuple(diagnostics), canonical


def _copy_view(request: TflintValidationRequest, view: Path) -> str:
    return materialize_view(
        request.scan_root, request.source_bindings, view, request.max_file_bytes,
    )


def _evidence(
    request: TflintValidationRequest, *, status: Status, reason: ValidationReason,
    process: CommandResult | None = None, raw: bytes = b"", diagnostics: tuple = (),
    canonical: str | None = None, output_manifest: str = "", argv: tuple = (),
    materialized_view: str = "", files_validated: int = 0,
) -> ValidatorExecutionEvidence:
    empty = hashlib.sha256(b"").hexdigest()
    return ValidatorExecutionEvidence._from_execution(
        validator_id="tflint_advisory", tool="tflint", version=request.locked_identity.version,
        status=status, reason=reason, advisory_only=True, diagnostics=diagnostics,
        resource_identities=(), input_files=request.input_evidence,
        files_eligible=len(request.input_evidence), files_validated=files_validated,
        resources_expected=0, resources_validated=0,
        runtime_identity=request.container_runtime.identity,
        tool_environment_identity=canonical_sha256({
            "tool": request.locked_identity.environment_digest,
            "protected_config": request.protected_config.identity,
        }),
        invocation_identity=canonical_sha256({
            "argv": ["protected-container-runtime", *argv[1:]] if argv else [],
            "snapshot": request.sealed_snapshot_identity,
            "materialized_view": materialized_view or materialized_view_manifest(request.input_evidence),
            "config": request.protected_config.identity,
        }), sealed_snapshot_identity=request.sealed_snapshot_identity,
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
            "module_execution_complete": "true",
            "tool": request.module_plan.tool,
        }.items())),
        execution_controls=_CONTROLS,
    )


class TflintValidator:
    def validate(self, request: TflintValidationRequest) -> ValidatorExecutionEvidence:
        if type(request) is not TflintValidationRequest or not request._trusted_request:
            raise DomainError("TFLint validation requires a sealed request")
        work = Path(tempfile.mkdtemp(prefix="iacgv-tflint-validate-"))
        process = None
        raw = b""
        output_manifest = ""
        materialized_view = ""
        argv: tuple[str, ...] = ()
        result = None
        try:
            revalidate_validation_scope_plan(
                request.scan_root, request.scope_plan, request.max_file_bytes,
            )
            revalidate_trusted_container_runtime(request.container_runtime, workspace_root=request.workspace_root)
            view, output, protected = work / "input", work / "output", work / "protected"
            materialized_view = _copy_view(request, view)
            prepare_writable_output_directory(output)
            protected.mkdir(mode=0o755)
            config = protected / "tflint.hcl"
            verified_write(config, _PROTECTED_CONFIG.encode())
            seal_readonly_tree(protected)
            module_dir = (
                "/iacgv-input" if request.module_plan.module_root == "."
                else f"/iacgv-input/{request.module_plan.module_root}"
            )
            argv = (
                str(request.container_runtime.executable_path), "run", "--rm", "--pull", "never",
                "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", _DOCKER_PIDS_LIMIT,
                "--memory", _DOCKER_MEMORY, "--cpus", _DOCKER_CPUS, "--user", _DOCKER_USER,
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "-e", "HOME=/tmp/iacgv-home",
                "-v", f"{view}:/iacgv-input:ro", "-v", f"{output}:/iacgv-output:rw",
                "-v", f"{protected}:/iacgv-protected:ro", "-w", module_dir,
                request.locked_identity.execution_reference,
                "--format", "json", "--no-color", "--chdir", module_dir,
                "--config", "/iacgv-protected/tflint.hcl",
            )
            require_hardened_docker_argv(
                argv, pids_limit=_DOCKER_PIDS_LIMIT, memory=_DOCKER_MEMORY,
                cpus=_DOCKER_CPUS, user=_DOCKER_USER,
            )
            revalidate_trusted_container_runtime(request.container_runtime, workspace_root=request.workspace_root)
            revalidate_validation_scope_plan(
                request.scan_root, request.scope_plan, request.max_file_bytes,
            )
            process = run_command(CommandRequest(
                argv=argv, expected_exit_codes=(0, 1, 2), workspace_root=request.workspace_root,
                timeout_seconds=request.timeout_seconds, max_output_bytes=request.max_output_bytes,
                max_stdout_bytes=request.max_output_bytes, max_stderr_bytes=request.max_output_bytes,
                env_extra={"PYTHONDONTWRITEBYTECODE": "1"},
            ))
            if process.argv != argv:
                raise DomainError(ValidationReason.RUNTIME_INTEGRITY_FAILED.value)
            revalidate_validation_scope_plan(
                request.scan_root, request.scope_plan, request.max_file_bytes,
            )
            for sealed in request.source_bindings:
                read_sealed_source(request.scan_root, sealed, request.max_file_bytes)
            revalidate_materialized_view(
                view, request.input_evidence, request.max_file_bytes,
            )
            revalidate_readonly_file(config, _PROTECTED_CONFIG.encode())
            revalidate_writable_output_directory(output)
            revalidate_validation_scope_plan(
                request.scan_root, request.scope_plan, request.max_file_bytes,
            )
            revalidate_trusted_container_runtime(request.container_runtime, workspace_root=request.workspace_root)
            _, output_manifest = read_locked_output_directory(
                output, allowed_files=(), max_file_bytes=request.max_output_bytes,
                max_total_bytes=request.max_output_bytes,
            )
            revalidate_writable_output_directory(output)
            if process.status is not Status.PASS:
                reason = ValidationReason.TIMEOUT if process.timed_out else ValidationReason.PROCESS_ERROR
                result = _evidence(request, status=Status.INCONCLUSIVE, reason=reason,
                                   process=process, output_manifest=output_manifest, argv=argv,
                                   materialized_view=materialized_view)
            else:
                raw = process.stdout
                status, reason, diagnostics, canonical = _parse_native(raw, request, process.exit_code)
                result = _evidence(request, status=status, reason=reason, process=process,
                                   raw=raw, diagnostics=diagnostics, canonical=canonical,
                                   output_manifest=output_manifest, argv=argv,
                                   materialized_view=materialized_view,
                                   files_validated=0)
        except (DomainError, OSError) as exc:
            try:
                reason = ValidationReason(str(exc))
            except ValueError:
                reason = ValidationReason.PROCESS_ERROR
            result = _evidence(request, status=Status.INCONCLUSIVE, reason=reason,
                               process=process, raw=raw, output_manifest=output_manifest, argv=argv,
                               materialized_view=materialized_view)
        try:
            remove_private_tree(work)
        except OSError:
            return _evidence(request, status=Status.INCONCLUSIVE,
                             reason=ValidationReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED,
                             process=process, raw=raw, output_manifest=output_manifest, argv=argv,
                             materialized_view=materialized_view)
        assert result is not None
        return result


__all__ = [
    "ProtectedTflintConfig", "TflintValidationRequest", "TflintValidator",
    "create_tflint_validation_request", "load_protected_tflint_config",
]
