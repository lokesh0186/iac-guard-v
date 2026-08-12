"""Trivy v0.73.0 adapter with independently locked external checks evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import InitVar, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ..enums import ArtifactKind, CheckEvaluationResult, Severity, Status
from ..models import (
    BoundInputFile,
    CheckEvaluation,
    CoverageCounters,
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
    safe_report_text,
)
from ..normalisation import assign_occurrence_indices
from ..process import CommandRequest, CommandResult, ProcessReason, run_command
from .base import AdapterReason, ScannerContract
from .kics import _read_bound, _strict_json
from .phase_e_lock import LockedContainerIdentity, require_locked_identity


TRIVY_CONTRACT = ScannerContract(
    name="trivy",
    supported_versions=("0.73.0",),
    frameworks=("kubernetes", "terraform"),
    expected_exit_codes=(0,),
)
TRIVY_ADAPTER_CONTRACT = "trivy-config-adapter-contract-v1"
_REQUEST_CONTEXT = object()
_RESULT_CONTEXT = object()
_SHA = re.compile(r"[0-9a-f]{64}")
_CACHE_IDENTITY = re.compile(r"trivy-checks-cache-v1:sha256:[0-9a-f]{64}")
_TOP_FIELDS = frozenset({
    "SchemaVersion", "Trivy", "ReportID", "CreatedAt", "ArtifactName",
    "ArtifactType", "Metadata", "Results",
})
_RESULT_FIELDS = frozenset({
    "Target", "Class", "Type", "MisconfSummary", "Misconfigurations",
    "Licenses", "Packages", "Vulnerabilities", "Secrets",
})
_MISCONFIG_FIELDS = frozenset({
    "Type", "ID", "AVDID", "Title", "Description", "Message", "Namespace",
    "Query", "Resolution", "Severity", "PrimaryURL", "References", "Status",
    "CauseMetadata", "IacMetadata",
})


def _cache_manifest(root: Path) -> str:
    """No-follow canonical identity over the complete external-check cache."""
    try:
        canonical = root.resolve(strict=True)
    except OSError as exc:
        raise DomainError(AdapterReason.EXTERNAL_CHECKS_MISSING.value) from exc
    if not canonical.is_dir() or root.is_symlink():
        raise DomainError(AdapterReason.EXTERNAL_CHECKS_MISSING.value)
    digest = hashlib.sha256()
    for path in sorted(canonical.rglob("*"), key=lambda item: item.relative_to(canonical).as_posix()):
        relative = path.relative_to(canonical).as_posix()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise DomainError(AdapterReason.EXTERNAL_CHECKS_CHANGED.value) from exc
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
        ):
            raise DomainError(AdapterReason.EXTERNAL_CHECKS_CHANGED.value)
        digest.update(relative.encode())
        digest.update(b"\0")
        if stat.S_ISDIR(metadata.st_mode):
            digest.update(b"directory\0")
            continue
        digest.update(b"regular_file\0")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise DomainError(AdapterReason.EXTERNAL_CHECKS_CHANGED.value)
            file_digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                file_digest.update(chunk)
        finally:
            os.close(descriptor)
        digest.update(str(size).encode())
        digest.update(b"\0")
        digest.update(file_digest.digest())
    return digest.hexdigest()


def _external_metadata(cache_root: Path, identity: LockedContainerIdentity) -> None:
    path = cache_root / "policy" / "metadata.json"
    try:
        metadata = _strict_json(path.read_bytes())
    except (OSError, DomainError) as exc:
        raise DomainError(AdapterReason.EXTERNAL_CHECKS_MISSING.value) from exc
    if metadata.get("Digest") != identity.checks_manifest_digest:
        raise DomainError(AdapterReason.EXTERNAL_CHECKS_CHANGED.value)


@dataclass(frozen=True, slots=True)
class TrivyScanRequest:
    workspace_root: Path
    scan_root: Path
    files_eligible: tuple
    eligible_file_evidence: tuple
    expected_resources: tuple
    docker_executable: Path
    external_checks_cache: Path
    locked_identity: LockedContainerIdentity
    timeout_seconds: int = 180
    max_output_bytes: int = 16 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_eligible_bytes: int = 64 * 1024 * 1024
    _trusted_context: InitVar[object] = None
    _cache_content_sha256: str = field(init=False, default="", repr=False)
    _trusted_request: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if _trusted_context is not _REQUEST_CONTEXT:
            raise DomainError("Trivy requests must come from the sealed request factory")
        identity = require_locked_identity(self.locked_identity, "trivy")
        if identity.source != "external" or identity.fallback_used:
            raise DomainError(AdapterReason.EMBEDDED_CHECKS_FALLBACK.value)
        try:
            workspace = self.workspace_root.resolve(strict=True)
            scan_root = self.scan_root.resolve(strict=True)
            docker = self.docker_executable.resolve(strict=True)
            checks = self.external_checks_cache.resolve(strict=True)
        except OSError as exc:
            raise DomainError("Trivy request path cannot be resolved") from exc
        if not workspace.is_dir() or not scan_root.is_dir():
            raise DomainError("Trivy roots must be directories")
        try:
            scan_root.relative_to(workspace)
        except ValueError as exc:
            raise DomainError("Trivy scan_root must be inside workspace_root") from exc
        if not stat.S_ISREG(docker.stat().st_mode) or not os.access(docker, os.X_OK):
            raise DomainError("Docker launcher must be executable")
        if type(self.files_eligible) is not tuple or type(self.eligible_file_evidence) is not tuple:
            raise DomainError("Trivy eligible inputs must be exact tuples")
        paths = tuple(canonical_repo_path(item, "Trivy eligible path") for item in self.files_eligible)
        if tuple(sorted(paths)) != paths or len(paths) != len(set(paths)):
            raise DomainError("Trivy eligible paths must be sorted and unique")
        evidence = []
        for item in self.eligible_file_evidence:
            if type(item) is not BoundInputFile:
                raise DomainError("Trivy input evidence must contain BoundInputFile")
            evidence.append(BoundInputFile(
                item.file_path, item.file_type, item.size, item.sha256, item.device, item.inode
            ))
        if tuple(item.file_path for item in evidence) != paths:
            raise DomainError("Trivy input evidence does not exactly cover eligible paths")
        if type(self.expected_resources) is not tuple:
            raise DomainError("Trivy expected_resources must be an exact tuple")
        resources = []
        for item in self.expected_resources:
            if type(item) is not ExpectedResource:
                raise DomainError("Trivy resources must contain ExpectedResource")
            resources.append(ExpectedResource(
                item.file_path, item.resource_address, item.artifact_kind,
                item.scanner_native_lookup,
            ))
        if len({item.canonical_key for item in resources}) != len(resources):
            raise DomainError("Trivy expected resource inventory has duplicates")
        for name in (
            "timeout_seconds", "max_output_bytes", "max_file_bytes",
            "max_total_eligible_bytes",
        ):
            if require_int(getattr(self, name), name) <= 0:
                raise DomainError(f"{name} must be > 0")
        if sum(item.size for item in evidence) > self.max_total_eligible_bytes:
            raise DomainError(AdapterReason.INPUT_TOTAL_BYTES_EXCEEDED.value)
        _external_metadata(checks, identity)
        cache_digest = _cache_manifest(checks)
        object.__setattr__(self, "workspace_root", workspace)
        object.__setattr__(self, "scan_root", scan_root)
        object.__setattr__(self, "docker_executable", docker)
        object.__setattr__(self, "external_checks_cache", checks)
        object.__setattr__(self, "eligible_file_evidence", tuple(evidence))
        object.__setattr__(self, "expected_resources", tuple(sorted(resources, key=lambda item: item.canonical_key)))
        object.__setattr__(self, "_cache_content_sha256", cache_digest)
        object.__setattr__(self, "_trusted_request", True)


def create_trivy_scan_request(**kwargs: Any) -> TrivyScanRequest:
    return TrivyScanRequest(_trusted_context=_REQUEST_CONTEXT, **kwargs)


@dataclass(frozen=True, slots=True)
class TrivyExecutionEvidence:
    """ScannerRun plus external-bundle and execution facts absent from generic models."""

    scanner_run: ScannerRun
    binary_image_identity: str
    image_index_digest: str
    checks_manifest_digest: str
    checks_layer_digest: str
    checks_cache_identity: str
    checks_cache_content_sha256: str
    invocation_identity: str
    source: str
    fallback_used: bool
    network_disabled: bool
    updates_disabled: bool
    canonical_output_sha256: str
    _trusted_context: InitVar[object] = None
    _trusted_evidence: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if type(self.scanner_run) is not ScannerRun or not self.scanner_run._trusted_adapter_evidence:
            raise DomainError("Trivy evidence requires an adapter-owned ScannerRun")
        if self.scanner_run.scanner != "trivy":
            raise DomainError("Trivy evidence cannot wrap another scanner")
        for name in (
            "binary_image_identity", "image_index_digest", "checks_manifest_digest",
            "checks_layer_digest",
        ):
            value = getattr(self, name)
            if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                raise DomainError(f"{name} must be a prefixed SHA-256")
        for name in (
            "checks_cache_content_sha256", "invocation_identity",
            "canonical_output_sha256",
        ):
            value = getattr(self, name)
            if type(value) is not str or _SHA.fullmatch(value) is None:
                raise DomainError(f"{name} must be a SHA-256")
        for name in ("fallback_used", "network_disabled", "updates_disabled"):
            if type(getattr(self, name)) is not bool:
                raise DomainError(f"{name} must be a bool")
        if (
            type(self.checks_cache_identity) is not str
            or _CACHE_IDENTITY.fullmatch(self.checks_cache_identity) is None
        ):
            raise DomainError("checks_cache_identity must be a canonical external-cache identity")
        if self.source not in {"external", "embedded_fallback"}:
            raise DomainError("Trivy checks source is invalid")
        if self.fallback_used != (self.source == "embedded_fallback"):
            raise DomainError("Trivy checks source and fallback evidence disagree")
        if _trusted_context is _RESULT_CONTEXT:
            object.__setattr__(self, "_trusted_evidence", True)

    def canonical_dict(self) -> dict:
        return {
            "scanner_run": self.scanner_run.canonical_dict(),
            "binary_image_identity": self.binary_image_identity,
            "image_index_digest": self.image_index_digest,
            "checks_manifest_digest": self.checks_manifest_digest,
            "checks_layer_digest": self.checks_layer_digest,
            "checks_cache_identity": self.checks_cache_identity,
            "checks_cache_content_sha256": self.checks_cache_content_sha256,
            "invocation_identity": self.invocation_identity,
            "source": self.source,
            "fallback_used": self.fallback_used,
            "network_disabled": self.network_disabled,
            "updates_disabled": self.updates_disabled,
            "canonical_output_sha256": self.canonical_output_sha256,
        }


def _invocation_digest(request: TrivyScanRequest) -> str:
    payload = {
        "adapter": TRIVY_ADAPTER_CONTRACT,
        "lock_contract": request.locked_identity.invocation_contract,
        "execution_reference": request.locked_identity.execution_reference,
        "format": "json", "skip_check_update": True, "network": "none",
        "include_non_failures": True, "read_only_root": True,
        "max_output_bytes": request.max_output_bytes,
        "max_file_bytes": request.max_file_bytes,
        "max_total_eligible_bytes": request.max_total_eligible_bytes,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _canonical_native_hash(raw: bytes) -> str:
    """Bind semantic JSON deterministically, or malformed bytes exactly."""
    try:
        payload = _strict_json(raw)
    except DomainError:
        return hashlib.sha256(raw).hexdigest()
    canonical = dict(payload)
    results = canonical.get("Results")
    if type(results) is list:
        rebuilt = []
        for result in results:
            if type(result) is dict:
                item = dict(result)
                misconfigurations = item.get("Misconfigurations")
                if type(misconfigurations) is list:
                    item["Misconfigurations"] = sorted(
                        misconfigurations,
                        key=lambda value: json.dumps(
                            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                        ),
                    )
                rebuilt.append(item)
            else:
                rebuilt.append(result)
        canonical["Results"] = sorted(
            rebuilt,
            key=lambda value: json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ),
        )
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _native_path(raw: Any, eligible: tuple[str, ...]) -> str | None:
    if raw == ".":
        return None
    if type(raw) is not str or not raw:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    parts = tuple(part for part in PurePosixPath(raw.replace("\\", "/")).parts if part not in {"/", ".", ".."})
    matches = [
        item for item in eligible
        if tuple(PurePosixPath(item).parts) == parts[-len(PurePosixPath(item).parts):]
    ]
    if len(matches) != 1:
        raise DomainError(AdapterReason.COVERAGE_MISMATCH.value)
    return matches[0]


def _severity(raw: Any) -> Severity:
    if type(raw) is not str:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    try:
        return Severity(raw.upper())
    except ValueError:
        return Severity.UNKNOWN


def _artifact(raw: Any, path: str) -> ArtifactKind:
    if type(raw) is not str:
        return ArtifactKind.UNKNOWN
    if raw.casefold() == "terraform":
        return ArtifactKind.TERRAFORM_HCL
    if raw.casefold() in {"kubernetes", "yaml"}:
        return ArtifactKind.KUBERNETES_JSON if path.endswith(".json") else ArtifactKind.KUBERNETES_YAML
    return ArtifactKind.UNKNOWN


def _cause(item: dict, file_path: str) -> tuple[str, int, int]:
    cause = item.get("CauseMetadata")
    if type(cause) is not dict:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    resource = cause.get("Resource")
    start = cause.get("StartLine")
    end = cause.get("EndLine")
    if type(resource) is not str or not resource.strip():
        resource = f"trivy-file-{file_path.replace('/', '-')}"
    if type(start) is not int or start < 1 or type(end) is not int or end < start:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    return canonical_resource_scope(resource, "Trivy resource"), start, end


def _reason_run(
    request: TrivyScanRequest, reason: AdapterReason, *,
    status: Status = Status.ERROR, process: CommandResult | None = None,
    raw: bytes | None = None, diagnostics: tuple[str, ...] = (),
) -> ScannerRun:
    expected = len(request.expected_resources)
    return ScannerRun._from_adapter(
        scanner="trivy", scanner_version=request.locked_identity.version,
        status=status,
        coverage=CoverageCounters(files_eligible=len(request.files_eligible)),
        resource_coverage=ResourceCoverage(
            resources_expected=expected, expected_resources_missing=expected,
        ),
        exit_code=process.exit_code if process and process.exit_code is not None else -1,
        stdout_sha256=process.stdout_sha256 if process else "",
        stderr_sha256=process.stderr_sha256 if process else "",
        raw_output_sha256=hashlib.sha256(raw).hexdigest() if raw else "",
        resolved_launcher_path="trivy-container",
        launcher_digest=request.locked_identity.launcher_digest,
        scanner_environment_digest=request.locked_identity.environment_digest,
        policy_inventory_digest=request.locked_identity.policy_inventory_digest,
        invocation_config_digest=_invocation_digest(request),
        ruleset_integrity=(
            Status.FAIL if reason in {
                AdapterReason.EXTERNAL_CHECKS_CHANGED,
                AdapterReason.EMBEDDED_CHECKS_FALLBACK,
                AdapterReason.LOCK_IDENTITY_MISMATCH,
            } else Status.INCONCLUSIVE if reason is AdapterReason.EXTERNAL_CHECKS_MISSING
            else Status.PASS
        ),
        input_files=request.eligible_file_evidence,
        duration_ms=process.duration_ms if process else 0,
        diagnostics=(reason.value, *diagnostics),
    )


def _process_failure(request: TrivyScanRequest, process: CommandResult) -> ScannerRun | None:
    if process.status is Status.PASS:
        return None
    if process.timed_out:
        reason = AdapterReason.DEADLINE_EXCEEDED
    elif process.truncated:
        reason = AdapterReason.TRUNCATED_OUTPUT
    elif process.reason_code is ProcessReason.KILLED_BY_SIGNAL:
        reason = AdapterReason.KILLED_PROCESS
    elif process.reason_code is ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT:
        reason = AdapterReason.EXIT_CODE_OUTSIDE_CONTRACT
    else:
        reason = AdapterReason.PROCESS_ERROR
    return _reason_run(request, reason, status=process.status, process=process)


def _normalize(raw: bytes, request: TrivyScanRequest, process: CommandResult) -> ScannerRun:
    payload = _strict_json(raw)
    diagnostics: list[str] = []
    if not {"SchemaVersion", "Trivy", "Results"} <= set(payload):
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    if set(payload) - _TOP_FIELDS:
        diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
    if payload.get("SchemaVersion") != 2:
        raise DomainError(AdapterReason.UNSUPPORTED_VERSION.value)
    version = payload.get("Trivy")
    if type(version) is not dict or version.get("Version") != request.locked_identity.version:
        raise DomainError(AdapterReason.VERSION_MISMATCH.value)
    results = payload.get("Results")
    if type(results) is not list:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    findings: list[Finding] = []
    evaluations: list[CheckEvaluation] = []
    observed_files: set[str] = set()
    observed_resources: set[tuple[str, str]] = set()
    summary_success = 0
    summary_failure = 0
    for result in results:
        if type(result) is not dict or not {"Target", "Class", "Type", "MisconfSummary"} <= set(result):
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        if set(result) - _RESULT_FIELDS:
            diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
        if result.get("Class") != "config":
            diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
            continue
        file_path = _native_path(result.get("Target"), request.files_eligible)
        summary = result.get("MisconfSummary")
        if type(summary) is not dict or set(summary) != {"Successes", "Failures"}:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        successes = summary.get("Successes")
        failures = summary.get("Failures")
        if type(successes) is not int or successes < 0 or type(failures) is not int or failures < 0:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        summary_success += successes
        summary_failure += failures
        items = result.get("Misconfigurations")
        if items is None:
            if failures or successes:
                raise DomainError(AdapterReason.MISSING_MISCONFIGURATIONS.value)
            if file_path is not None:
                observed_files.add(file_path)
            continue
        if type(items) is not list:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        native_failures = sum(
            type(item) is dict and item.get("Status") == "FAIL" for item in items
        )
        native_successes = sum(
            type(item) is dict and item.get("Status") == "PASS" for item in items
        )
        if native_failures != failures or native_successes != successes:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        if file_path is None:
            # Trivy emits repository-global PASS evaluations at target ".".  They
            # contribute to the native aggregate but cannot prove per-file/resource
            # coverage.  A global failure is retained as typed uncertainty because
            # it cannot be attached to an exact sealed input identity.
            if failures:
                diagnostics.append(AdapterReason.MISSING_RESOURCE_IDENTITY.value)
            continue
        if file_path is not None:
            observed_files.add(file_path)
        for item in items:
            if type(item) is not dict or not {"ID", "Title", "Severity", "Status", "CauseMetadata"} <= set(item):
                raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
            if set(item) - _MISCONFIG_FIELDS:
                diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
            status = item.get("Status")
            if status not in {"FAIL", "PASS"}:
                diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
                continue
            rule_id = canonical_identifier(item.get("ID"), "Trivy check ID")
            title = safe_report_text(item.get("Title"), "Trivy title")
            resource, start, end = _cause(item, file_path)
            severity = _severity(item.get("Severity"))
            artifact = _artifact(result.get("Type"), file_path)
            if severity is Severity.UNKNOWN or artifact is ArtifactKind.UNKNOWN:
                diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
            native_payload = {
                "rule": rule_id, "file": file_path, "resource": resource,
                "start": start, "end": end,
                "namespace": item.get("Namespace", ""), "query": item.get("Query", ""),
            }
            native = "trivy-misconf-v1:" + hashlib.sha256(
                json.dumps(native_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if status == "FAIL":
                findings.append(Finding(
                    scanner="trivy", scanner_version=request.locked_identity.version,
                    rule_id=rule_id, resource_address=resource,
                    location=FindingLocation(file_path, start, end), severity=severity,
                    rule_name=title,
                    message=safe_report_text(item.get("Message", title), "Trivy message"),
                    native_fingerprint=native, artifact_kind=artifact,
                ))
            observed_resources.add((file_path, resource))
            evaluations.append(CheckEvaluation(
                scanner="trivy", scanner_version=request.locked_identity.version,
                rule_id=rule_id, resource_address=resource, file_path=file_path,
                native_result=(
                    CheckEvaluationResult.FAILED
                    if status == "FAIL" else CheckEvaluationResult.PASSED
                ),
                evaluated_keys=(native,), source_bucket="Misconfigurations",
                occurrence_token=native,
            ))
    eligible = set(request.files_eligible)
    expected = {(item.file_path, item.resource_address) for item in request.expected_resources}
    missing_files = eligible - observed_files
    missing_resources = expected - observed_resources
    unexpected_resources = observed_resources - expected
    if missing_files or (expected and (missing_resources or unexpected_resources)):
        diagnostics.append(AdapterReason.COVERAGE_MISMATCH.value)
    coverage = CoverageCounters(
        files_eligible=len(eligible), files_discovered=len(observed_files),
        files_parsed=len(observed_files), files_failed=0,
        evaluations_reported=summary_success + summary_failure,
    )
    resource_coverage = ResourceCoverage(
        resources_expected=len(expected), resources_observed=len(observed_resources),
        expected_resources_observed=len(expected & observed_resources),
        expected_resources_missing=len(missing_resources),
        unexpected_resources_observed=len(unexpected_resources),
        summary_resources_reported=len(observed_resources),
    )
    status = Status.PARTIAL if diagnostics else Status.PASS
    return ScannerRun._from_adapter(
        scanner="trivy", scanner_version=request.locked_identity.version,
        status=status, findings=assign_occurrence_indices(findings),
        coverage=coverage, resource_coverage=resource_coverage,
        exit_code=process.exit_code if process.exit_code is not None else -1,
        stdout_sha256=process.stdout_sha256, stderr_sha256=process.stderr_sha256,
        raw_output_sha256=_canonical_native_hash(raw),
        resolved_launcher_path="trivy-container",
        launcher_digest=request.locked_identity.launcher_digest,
        scanner_environment_digest=request.locked_identity.environment_digest,
        policy_inventory_digest=request.locked_identity.policy_inventory_digest,
        invocation_config_digest=_invocation_digest(request), ruleset_integrity=Status.PASS,
        evaluations=tuple(evaluations), input_files=request.eligible_file_evidence,
        duration_ms=process.duration_ms,
        diagnostics=tuple(sorted(set(diagnostics))) if diagnostics else (AdapterReason.COMPLETED.value,),
    )


def _evidence(
    request: TrivyScanRequest, run: ScannerRun, raw: bytes | None,
    *, cache_digest: str, fallback_used: bool,
) -> TrivyExecutionEvidence:
    canonical_output = _canonical_native_hash(raw) if raw else hashlib.sha256(b"").hexdigest()
    return TrivyExecutionEvidence(
        scanner_run=run,
        binary_image_identity=request.locked_identity.image_architecture_digest,
        image_index_digest=request.locked_identity.image_index_digest,
        checks_manifest_digest=request.locked_identity.checks_manifest_digest,
        checks_layer_digest=request.locked_identity.checks_layer_digest,
        checks_cache_identity=request.locked_identity.checks_cache_identity,
        checks_cache_content_sha256=cache_digest,
        invocation_identity=_invocation_digest(request),
        source="embedded_fallback" if fallback_used else "external",
        fallback_used=fallback_used, network_disabled=True, updates_disabled=True,
        canonical_output_sha256=canonical_output, _trusted_context=_RESULT_CONTEXT,
    )


class TrivyAdapter:
    name = "trivy"

    def contract(self) -> ScannerContract:
        return TRIVY_CONTRACT

    @staticmethod
    def _revalidate(request: TrivyScanRequest) -> str:
        require_locked_identity(request.locked_identity, "trivy")
        _external_metadata(request.external_checks_cache, request.locked_identity)
        cache = _cache_manifest(request.external_checks_cache)
        if cache != request._cache_content_sha256:
            raise DomainError(AdapterReason.CACHE_CHANGED_DURING_EXECUTION.value)
        for relative, expected in zip(request.files_eligible, request.eligible_file_evidence):
            if _read_bound(request.scan_root / relative, relative, request.max_file_bytes) != expected:
                raise DomainError(AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value)
        return cache

    def normalize(
        self, raw_output: bytes, request: TrivyScanRequest, process: CommandResult,
    ) -> TrivyExecutionEvidence:
        if type(request) is not TrivyScanRequest or not request._trusted_request:
            raise DomainError("Trivy normalize requires a sealed request")
        if type(process) is not CommandResult:
            raise DomainError("Trivy process evidence must be CommandResult")
        cache_digest = self._revalidate(request)
        failure = _process_failure(request, process)
        if failure is not None:
            return _evidence(
                request, failure, None, cache_digest=cache_digest, fallback_used=False,
            )
        stderr = process.stderr.decode("utf-8", errors="replace").casefold()
        fallback = not (
            "loading from existing cache" in stderr
            and "downloading the checks bundle" not in stderr
        )
        if fallback:
            run = _reason_run(
                request, AdapterReason.EMBEDDED_CHECKS_FALLBACK,
                status=Status.INCONCLUSIVE, process=process, raw=raw_output,
            )
            return _evidence(request, run, raw_output, cache_digest=cache_digest, fallback_used=True)
        try:
            run = _normalize(raw_output, request, process)
        except DomainError as exc:
            value = str(exc)
            reason = next((item for item in AdapterReason if item.value == value), AdapterReason.INVALID_RESULTS_STRUCTURE)
            run = _reason_run(request, reason, process=process, raw=raw_output)
        return _evidence(request, run, raw_output, cache_digest=cache_digest, fallback_used=False)

    @staticmethod
    def _build_view(request: TrivyScanRequest, root: Path) -> None:
        root.mkdir(mode=0o700)
        for relative, expected in zip(request.files_eligible, request.eligible_file_evidence):
            target = root / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            try:
                if _read_bound(request.scan_root / relative, relative, request.max_file_bytes, descriptor) != expected:
                    raise DomainError(AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def scan(self, request: TrivyScanRequest) -> TrivyExecutionEvidence:
        if type(request) is not TrivyScanRequest or not request._trusted_request:
            raise DomainError("Trivy scan requires a sealed request")
        if not request.files_eligible:
            run = _reason_run(request, AdapterReason.EMPTY_ELIGIBLE_SCOPE, status=Status.SKIPPED)
            return _evidence(
                request, run, None, cache_digest=request._cache_content_sha256,
                fallback_used=False,
            )
        work = Path(tempfile.mkdtemp(prefix="iacgv-trivy-"))
        process: CommandResult | None = None
        raw: bytes | None = None
        terminal: ScannerRun | None = None
        cache_digest = request._cache_content_sha256
        try:
            cache_digest = self._revalidate(request)
            view = work / "scan"
            output = work / "output"
            self._build_view(request, view)
            output.mkdir(mode=0o700)
            argv = (
                str(request.docker_executable), "run", "--rm", "--pull", "never",
                "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", "128",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "-e", "TRIVY_CACHE_DIR=/cache",
                "-v", f"{request.external_checks_cache}:/cache:ro",
                "-v", f"{view}:/work:ro", "-v", f"{output}:/out:rw",
                "-w", "/work", request.locked_identity.execution_reference,
                "config", "--format", "json", "--output", "/out/results.json",
                "--skip-check-update", "--include-non-failures", ".",
            )
            process = run_command(CommandRequest(
                argv=argv, expected_exit_codes=TRIVY_CONTRACT.expected_exit_codes,
                workspace_root=request.workspace_root,
                timeout_seconds=request.timeout_seconds,
                max_output_bytes=request.max_output_bytes,
                max_stdout_bytes=request.max_output_bytes,
                max_stderr_bytes=request.max_output_bytes,
                env_extra={"PYTHONDONTWRITEBYTECODE": "1"},
            ))
            cache_digest = self._revalidate(request)
            failure = _process_failure(request, process)
            if failure is not None:
                terminal = failure
            else:
                result = output / "results.json"
                metadata = result.lstat()
                if not stat.S_ISREG(metadata.st_mode) or result.is_symlink() or metadata.st_size > request.max_output_bytes:
                    raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
                descriptor = os.open(result, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    raw = os.read(descriptor, request.max_output_bytes + 1)
                finally:
                    os.close(descriptor)
                if len(raw) > request.max_output_bytes:
                    raise DomainError(AdapterReason.TRUNCATED_OUTPUT.value)
        except (DomainError, OSError) as exc:
            value = str(exc)
            reason = next((item for item in AdapterReason if item.value == value), AdapterReason.SCAN_VIEW_PREPARATION_FAILED)
            terminal = _reason_run(request, reason, process=process, raw=raw)
        cleanup_failed = False
        try:
            shutil.rmtree(work)
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            terminal = _reason_run(request, AdapterReason.OUTPUT_CLEANUP_FAILED, process=process, raw=raw)
        if terminal is not None:
            return _evidence(request, terminal, raw, cache_digest=cache_digest, fallback_used=False)
        if process is None or raw is None:
            run = _reason_run(request, AdapterReason.RAW_OUTPUT_MISSING, process=process)
            return _evidence(request, run, None, cache_digest=cache_digest, fallback_used=False)
        return self.normalize(raw, request, process)


__all__ = [
    "TRIVY_ADAPTER_CONTRACT", "TRIVY_CONTRACT", "TrivyAdapter",
    "TrivyExecutionEvidence", "TrivyScanRequest", "create_trivy_scan_request",
]
