"""Fail-closed KICS v2.1.20 adapter bound to the reviewed E0.3 image lock.

The adapter emits scanner evidence only.  It does not participate in consensus and it
does not decide a policy verdict.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import InitVar, dataclass, field, fields
from datetime import datetime
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
from .base import (
    AdapterReason, ScannerContract, read_locked_output_directory,
    remove_private_tree, require_hardened_docker_argv, semantic_output_manifest,
)
from .phase_e_lock import LockedContainerIdentity, require_locked_identity
from .phase_e_runtime import (
    TrustedContainerRuntime,
    require_trusted_container_runtime,
    revalidate_trusted_container_runtime,
)


KICS_CONTRACT = ScannerContract(
    name="kics",
    supported_versions=("2.1.20",),
    frameworks=("cloudformation", "kubernetes", "terraform"),
    expected_exit_codes=(0, 20, 30, 40, 50, 60),
)
KICS_MAX_JSON_NESTING_DEPTH = 128
KICS_ADAPTER_CONTRACT = "kics-adapter-contract-v2"
_REQUEST_CONTEXT = object()
_SHA = re.compile(r"[0-9a-f]{64}")
_TOP_LEVEL_FIELDS = frozenset({
    "kics_version", "files_scanned", "lines_scanned", "files_parsed",
    "lines_parsed", "lines_ignored", "files_failed_to_scan", "queries_total",
    "queries_failed_to_execute", "queries_failed_to_compute_similarity_id",
    "scan_id", "severity_counters", "total_counter", "total_bom_resources",
    "start", "end", "paths", "queries", "bill_of_materials",
})
_TOP_LEVEL_REQUIRED_FIELDS = _TOP_LEVEL_FIELDS - {"bill_of_materials"}
_QUERY_REQUIRED_FIELDS = frozenset({
    "query_name", "query_id", "query_url", "severity", "platform", "category",
    "experimental", "description", "description_id", "files",
})
_QUERY_FIELDS = frozenset({
    "query_name", "query_id", "query_url", "severity", "platform", "cwe",
    "risk_score", "cloud_provider", "category", "experimental", "description",
    "description_id", "files", "cis_description_id", "cis_description_title",
    "cis_description_text", "cis_description_id_raw", "cis_description_text_raw",
    "cis_description_rationale", "cis_benchmark_name", "cis_benchmark_version",
})
_FILE_REQUIRED_FIELDS = frozenset({
    "file_name", "similarity_id", "line", "issue_type", "search_key",
    "search_line", "search_value", "expected_value", "actual_value",
})
_FILE_FIELDS = frozenset({
    "file_name", "similarity_id", "line", "resource_type", "resource_name",
    "issue_type", "search_key", "search_line", "search_value", "expected_value",
    "actual_value", "vuln_lines", "old_similarity_id", "value", "remediation",
    "remediation_type",
})
_SEVERITY_KEYS = frozenset({"CRITICAL", "HIGH", "INFO", "LOW", "MEDIUM", "TRACE"})
_RESULT_EXIT = {"INFO": 20, "LOW": 30, "MEDIUM": 40, "HIGH": 50, "CRITICAL": 60}
_SEVERITY_RANK = {name: index for index, name in enumerate(("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))}
_DOCKER_USER = "65532:65532"
_DOCKER_PIDS_LIMIT = "128"
_DOCKER_MEMORY = "512m"
_DOCKER_CPUS = "1.0"


def _native_time(value: Any) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value) from exc


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _read_bound(path: Path, relative: str, max_bytes: int, destination: int | None = None) -> BoundInputFile:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise DomainError("KICS input must be a nonsymlink regular file")
            if metadata.st_size > max_bytes:
                raise DomainError(AdapterReason.INPUT_FILE_BYTES_EXCEEDED.value)
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
                if destination is not None:
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination, view)
                        view = view[written:]
            return BoundInputFile(
                relative, "regular_file", size, digest.hexdigest(),
                metadata.st_dev, metadata.st_ino,
            )
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DomainError(AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value) from exc


@dataclass(frozen=True, slots=True)
class KicsScanRequest:
    """One sealed KICS input and exact E0.3 execution identity."""

    workspace_root: Path
    scan_root: Path
    files_eligible: tuple
    eligible_file_evidence: tuple
    expected_resources: tuple
    container_runtime: TrustedContainerRuntime
    locked_identity: LockedContainerIdentity
    timeout_seconds: int = 180
    max_output_bytes: int = 16 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_eligible_bytes: int = 64 * 1024 * 1024
    _trusted_context: InitVar[object] = None
    _trusted_request: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if _trusted_context is not _REQUEST_CONTEXT:
            raise DomainError("KICS requests must come from the sealed request factory")
        identity = require_locked_identity(self.locked_identity, "kics")
        try:
            workspace = self.workspace_root.resolve(strict=True)
            scan_root = self.scan_root.resolve(strict=True)
        except OSError as exc:
            raise DomainError("KICS request path cannot be resolved") from exc
        if not workspace.is_dir() or not scan_root.is_dir() or not _inside(scan_root, workspace):
            raise DomainError("KICS scan_root must be a directory inside workspace_root")
        runtime = require_trusted_container_runtime(
            self.container_runtime, workspace_root=workspace,
            protected_evidence_identity=identity.protected_evidence_identity,
        )
        if type(self.files_eligible) is not tuple or type(self.eligible_file_evidence) is not tuple:
            raise DomainError("KICS eligible files and evidence must be exact tuples")
        paths = tuple(canonical_repo_path(item, "KICS eligible path") for item in self.files_eligible)
        if len(paths) != len(set(paths)) or tuple(sorted(paths)) != paths:
            raise DomainError("KICS eligible paths must be unique and sorted")
        evidence: list[BoundInputFile] = []
        for item in self.eligible_file_evidence:
            if type(item) is not BoundInputFile:
                raise DomainError("KICS input evidence must contain BoundInputFile")
            evidence.append(BoundInputFile(
                item.file_path, item.file_type, item.size, item.sha256, item.device, item.inode
            ))
        if tuple(item.file_path for item in evidence) != paths:
            raise DomainError("KICS file evidence must exactly cover eligible paths")
        if type(self.expected_resources) is not tuple:
            raise DomainError("KICS expected resources must be an exact tuple")
        resources: list[ExpectedResource] = []
        for item in self.expected_resources:
            if type(item) is not ExpectedResource:
                raise DomainError("KICS expected resources must contain ExpectedResource")
            resources.append(ExpectedResource(
                item.file_path, item.resource_address, item.artifact_kind,
                item.scanner_native_lookup,
            ))
        if len({item.canonical_key for item in resources}) != len(resources):
            raise DomainError("KICS expected resource inventory contains duplicates")
        for name in (
            "timeout_seconds", "max_output_bytes", "max_file_bytes",
            "max_total_eligible_bytes",
        ):
            if require_int(getattr(self, name), name) <= 0:
                raise DomainError(f"{name} must be > 0")
        if sum(item.size for item in evidence) > self.max_total_eligible_bytes:
            raise DomainError(AdapterReason.INPUT_TOTAL_BYTES_EXCEEDED.value)
        object.__setattr__(self, "workspace_root", workspace)
        object.__setattr__(self, "scan_root", scan_root)
        object.__setattr__(self, "container_runtime", runtime)
        object.__setattr__(self, "eligible_file_evidence", tuple(evidence))
        object.__setattr__(self, "expected_resources", tuple(sorted(resources, key=lambda x: x.canonical_key)))
        object.__setattr__(self, "_trusted_request", True)


def create_kics_scan_request(**kwargs: Any) -> KicsScanRequest:
    """Factory kept explicit so serialized input cannot assert sealed evidence."""
    return KicsScanRequest(_trusted_context=_REQUEST_CONTEXT, **kwargs)


def _strict_json(raw: bytes) -> dict:
    if type(raw) is not bytes or not raw:
        raise DomainError(AdapterReason.EMPTY_OUTPUT.value)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DomainError(AdapterReason.MALFORMED_JSON.value) from exc
    depth = 0
    string = False
    escaped = False
    for character in text:
        if string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                string = False
            continue
        if character == '"':
            string = True
        elif character in "[{":
            depth += 1
            if depth > KICS_MAX_JSON_NESTING_DEPTH:
                raise DomainError(AdapterReason.JSON_DEPTH_EXCEEDED.value)
        elif character in "]}":
            depth = max(0, depth - 1)

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DomainError(AdapterReason.DUPLICATE_JSON_KEY.value)
            result[key] = value
        return result

    try:
        payload = json.loads(text, object_pairs_hook=no_duplicates)
    except RecursionError as exc:
        raise DomainError(AdapterReason.JSON_DEPTH_EXCEEDED.value) from exc
    except json.JSONDecodeError as exc:
        raise DomainError(AdapterReason.MALFORMED_JSON.value) from exc
    if type(payload) is not dict:
        raise DomainError(AdapterReason.UNEXPECTED_TOP_LEVEL.value)
    return payload


def _strict_nonnegative(mapping: dict, key: str) -> int:
    value = mapping.get(key)
    if type(value) is not int or value < 0:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    return value


def _native_path(raw: Any, eligible: tuple[str, ...]) -> str:
    if type(raw) is not str or not raw.strip():
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    cleaned = raw.replace("\\", "/")
    parts = tuple(part for part in PurePosixPath(cleaned).parts if part not in {"/", ".", ".."})
    matches = [
        candidate for candidate in eligible
        if len(PurePosixPath(candidate).parts) <= len(parts)
        and tuple(PurePosixPath(candidate).parts) == parts[-len(PurePosixPath(candidate).parts):]
    ]
    if len(matches) != 1:
        raise DomainError(AdapterReason.COVERAGE_MISMATCH.value)
    return matches[0]


def _artifact(platform: str, file_path: str) -> ArtifactKind:
    lowered = platform.casefold()
    if lowered == "terraform":
        return ArtifactKind.TERRAFORM_HCL
    if lowered == "kubernetes":
        return ArtifactKind.KUBERNETES_JSON if file_path.endswith(".json") else ArtifactKind.KUBERNETES_YAML
    if lowered == "cloudformation":
        return ArtifactKind.CLOUDFORMATION
    return ArtifactKind.UNKNOWN


def _severity(value: Any) -> Severity:
    if type(value) is not str:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    try:
        return Severity(value.upper())
    except ValueError:
        return Severity.UNKNOWN


def _resource(file_record: dict, query_id: str) -> str:
    kind = file_record.get("resource_type")
    name = file_record.get("resource_name")
    if kind is None and name is None:
        return canonical_resource_scope(f"kics-global-{query_id}", "KICS global resource")
    if type(kind) is not str or type(name) is not str:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    if kind.casefold() in {"n/a", "na", "none", ""} or name.casefold() in {"n/a", "na", "none", ""}:
        return canonical_resource_scope(f"kics-global-{query_id}", "KICS global resource")
    return canonical_resource_scope(f"{kind}.{name}", "KICS resource")


def _canonical_native_hash(payload: dict) -> str:
    """Bind semantic native JSON while excluding KICS-generated wall-clock fields."""
    canonical = {key: value for key, value in payload.items() if key not in {"start", "end", "scan_id"}}
    for bucket in ("queries", "bill_of_materials"):
        queries = canonical.get(bucket)
        if type(queries) is not list:
            continue
        rebuilt = []
        for query in queries:
            if type(query) is dict:
                item = dict(query)
                if type(item.get("files")) is list:
                    item["files"] = sorted(
                        item["files"],
                        key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")),
                    )
                rebuilt.append(item)
            else:
                rebuilt.append(query)
        canonical[bucket] = sorted(
            rebuilt,
            key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")),
        )
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _invocation_digest(request: KicsScanRequest) -> str:
    payload = {
        "adapter": KICS_ADAPTER_CONTRACT,
        "locked_invocation": request.locked_identity.invocation_contract,
        "execution_reference": request.locked_identity.execution_reference,
        "container_runtime_identity": request.container_runtime.identity,
        "network": "none",
        "read_only_root": True,
        "cap_drop": "ALL",
        "no_new_privileges": True,
        "pids_limit": _DOCKER_PIDS_LIMIT,
        "memory": _DOCKER_MEMORY,
        "cpus": _DOCKER_CPUS,
        "user": _DOCKER_USER,
        "report_formats": ["json"],
        "no_progress": True,
        "minimal_ui": True,
        "max_output_bytes": request.max_output_bytes,
        "max_file_bytes": request.max_file_bytes,
        "max_total_eligible_bytes": request.max_total_eligible_bytes,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _reason_run(
    request: KicsScanRequest,
    reason: AdapterReason,
    *,
    status: Status = Status.ERROR,
    process: CommandResult | None = None,
    raw_output: bytes | None = None,
    coverage: CoverageCounters | None = None,
    resource_coverage: ResourceCoverage | None = None,
    diagnostics: tuple[str, ...] = (),
) -> ScannerRun:
    expected = len(request.expected_resources)
    return ScannerRun(
        scanner="kics",
        scanner_version=request.locked_identity.version,
        status=status,
        coverage=coverage or CoverageCounters(files_eligible=len(request.files_eligible)),
        resource_coverage=resource_coverage or ResourceCoverage(
            resources_expected=expected, expected_resources_missing=expected,
        ),
        exit_code=process.exit_code if process and process.exit_code is not None else -1,
        stdout_sha256=process.stdout_sha256 if process else "",
        stderr_sha256=process.stderr_sha256 if process else "",
        raw_output_sha256=(hashlib.sha256(raw_output).hexdigest() if raw_output else ""),
        resolved_launcher_path="protected-container-runtime",
        launcher_digest=request.container_runtime.executable_sha256,
        scanner_environment_digest=request.locked_identity.environment_digest,
        policy_inventory_digest=request.locked_identity.policy_inventory_digest,
        invocation_config_digest=_invocation_digest(request),
        ruleset_integrity=(
            Status.FAIL if reason is AdapterReason.LOCK_IDENTITY_MISMATCH
            else Status.INCONCLUSIVE if reason in {
                AdapterReason.CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE,
                AdapterReason.CONTAINER_RUNTIME_CHANGED,
                AdapterReason.CONTAINER_RUNTIME_CONTEXT_CHANGED,
            } else Status.PASS
        ),
        input_files=request.eligible_file_evidence,
        duration_ms=process.duration_ms if process else 0,
        diagnostics=(reason.value, *diagnostics),
    )


def _process_failure(request: KicsScanRequest, process: CommandResult) -> ScannerRun | None:
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


def _normalize(
    raw: bytes, request: KicsScanRequest, process: CommandResult,
    output_manifest_sha256: str = "",
) -> ScannerRun:
    payload = _strict_json(raw)
    if not _TOP_LEVEL_REQUIRED_FIELDS <= set(payload):
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    diagnostics: list[str] = []
    if output_manifest_sha256:
        if _SHA.fullmatch(output_manifest_sha256) is None:
            raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
        diagnostics.append(f"output_directory_manifest_sha256:{output_manifest_sha256}")
    unknown_top = sorted(set(payload) - _TOP_LEVEL_FIELDS)
    if unknown_top:
        diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
        diagnostics.extend(f"unknown KICS field: {item}" for item in unknown_top)
    version = payload.get("kics_version")
    if version not in {request.locked_identity.version, f"v{request.locked_identity.version}"}:
        raise DomainError(AdapterReason.VERSION_MISMATCH.value)
    files_scanned = _strict_nonnegative(payload, "files_scanned")
    files_parsed = _strict_nonnegative(payload, "files_parsed")
    files_failed = _strict_nonnegative(payload, "files_failed_to_scan")
    lines_scanned = _strict_nonnegative(payload, "lines_scanned")
    lines_parsed = _strict_nonnegative(payload, "lines_parsed")
    lines_ignored = _strict_nonnegative(payload, "lines_ignored")
    queries_total = _strict_nonnegative(payload, "queries_total")
    queries_failed = _strict_nonnegative(payload, "queries_failed_to_execute")
    similarity_failed = _strict_nonnegative(payload, "queries_failed_to_compute_similarity_id")
    total_counter = _strict_nonnegative(payload, "total_counter")
    total_resources = _strict_nonnegative(payload, "total_bom_resources")
    if (
        files_parsed > files_scanned
        or files_failed > files_scanned
        or files_parsed + files_failed > files_scanned
        or lines_parsed > lines_scanned
        or lines_ignored > lines_scanned
        or lines_parsed + lines_ignored > lines_scanned
        or queries_failed > queries_total
        or similarity_failed > queries_total
        or queries_failed + similarity_failed > queries_total
    ):
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    paths = payload.get("paths")
    if type(paths) is not list or any(type(item) is not str or not item.strip() for item in paths):
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    start = _native_time(payload.get("start"))
    end = _native_time(payload.get("end"))
    if end < start:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    severity_counters = payload.get("severity_counters")
    if type(severity_counters) is not dict or set(severity_counters) != _SEVERITY_KEYS:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    for key, value in severity_counters.items():
        if type(key) is not str or type(value) is not int or value < 0:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    queries = payload.get("queries")
    if type(queries) is not list or len(queries) > queries_total:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    bill_of_materials = payload.get("bill_of_materials", [])
    if type(bill_of_materials) is not list:
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    findings: list[Finding] = []
    evaluations: list[CheckEvaluation] = []
    observed_resources: set[tuple[str, str]] = set()
    def parse_query(query: Any, *, bom: bool) -> None:
        if type(query) is not dict or not _QUERY_REQUIRED_FIELDS <= set(query):
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        if set(query) - _QUERY_FIELDS:
            diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
        query_id = canonical_identifier(query.get("query_id"), "KICS query id")
        query_name = safe_report_text(query.get("query_name"), "KICS query name")
        native_severity = query.get("severity")
        severity = Severity.UNKNOWN if bom else _severity(native_severity)
        if bom != (native_severity == "TRACE"):
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        platform = query.get("platform")
        if type(platform) is not str or not platform.strip():
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        for name in ("query_url", "category", "description", "description_id"):
            if type(query.get(name)) is not str or not query[name].strip():
                raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        if type(query.get("experimental")) is not bool:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        files = query.get("files")
        if type(files) is not list or not files:
            raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
        for native in files:
            if type(native) is not dict or not _FILE_REQUIRED_FIELDS <= set(native):
                raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
            if set(native) - _FILE_FIELDS:
                diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
            file_path = _native_path(native.get("file_name"), request.files_eligible)
            similarity = native.get("similarity_id")
            if type(similarity) is not str or _SHA.fullmatch(similarity) is None:
                raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
            for name in (
                "issue_type", "search_key", "search_value", "expected_value",
                "actual_value",
            ):
                if type(native.get(name)) is not str:
                    raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
            line = native.get("line")
            search_line = native.get("search_line")
            if (
                type(line) is not int or line < 1
                or type(search_line) is not int or search_line < -1
                or lines_scanned == 0 or line > lines_scanned
            ):
                raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
            resource = _resource(native, query_id)
            artifact = _artifact(platform, file_path)
            if artifact is ArtifactKind.UNKNOWN or (not bom and severity is Severity.UNKNOWN):
                diagnostics.append(AdapterReason.UNKNOWN_NATIVE_CATEGORY.value)
            if not bom:
                findings.append(Finding(
                    scanner="kics", scanner_version=request.locked_identity.version,
                    rule_id=query_id, resource_address=resource,
                    location=FindingLocation(file_path, line, line), severity=severity,
                    rule_name=query_name, message=query_name,
                    native_fingerprint=similarity, artifact_kind=artifact,
                ))
            if not bom and not resource.startswith("kics-global-"):
                observed_resources.add((file_path, resource))
            evaluations.append(CheckEvaluation(
                scanner="kics",
                scanner_version=request.locked_identity.version,
                rule_id=query_id,
                resource_address=resource,
                file_path=file_path,
                native_result=(
                    CheckEvaluationResult.UNKNOWN if bom
                    else CheckEvaluationResult.FAILED
                ),
                evaluated_keys=(
                    safe_report_text(
                        native.get("search_key", f"similarity:{similarity}"),
                        "KICS search key",
                    ),
                ),
                source_bucket="bill_of_materials" if bom else "queries",
                occurrence_token=f"kics-similarity-v1:{similarity}",
            ))
    for query in queries:
        parse_query(query, bom=False)
    for query in bill_of_materials:
        parse_query(query, bom=True)
    trace_count = sum(
        value for key, value in severity_counters.items() if key.upper() == "TRACE"
    )
    result_count = sum(
        value for key, value in severity_counters.items() if key.upper() != "TRACE"
    )
    if (
        len(findings) != total_counter
        or result_count != total_counter
        or trace_count != total_resources
        or sum(len(item["files"]) for item in bill_of_materials) != total_resources
    ):
        raise DomainError(AdapterReason.INVALID_RESULTS_STRUCTURE.value)
    present = [name for name in _RESULT_EXIT if severity_counters[name] > 0]
    expected_exit = 0 if not present else _RESULT_EXIT[max(present, key=_SEVERITY_RANK.get)]
    if process.exit_code != expected_exit:
        raise DomainError(AdapterReason.EXIT_RESULT_MISMATCH.value)
    eligible_count = len(request.files_eligible)
    coverage = CoverageCounters(
        files_eligible=eligible_count,
        files_discovered=files_scanned,
        files_parsed=files_parsed,
        files_failed=files_failed,
        evaluations_reported=len(evaluations),
        checks_failed_to_execute=queries_failed + similarity_failed,
        parse_errors=files_failed,
    )
    expected = {(item.file_path, item.resource_address) for item in request.expected_resources}
    missing = expected - observed_resources
    unexpected = observed_resources - expected
    resource_coverage = ResourceCoverage(
        resources_expected=len(expected),
        resources_observed=len(observed_resources),
        expected_resources_observed=len(expected & observed_resources),
        expected_resources_missing=len(missing),
        unexpected_resources_observed=len(unexpected),
        summary_resources_reported=len(observed_resources),
    )
    if files_failed:
        diagnostics.append(AdapterReason.KICS_FAILED_TO_SCAN.value)
    if queries_failed:
        diagnostics.append(AdapterReason.KICS_QUERY_EXECUTION_FAILED.value)
    if similarity_failed:
        diagnostics.append(AdapterReason.KICS_SIMILARITY_ID_FAILED.value)
    if total_resources:
        diagnostics.append(f"KICS_BILL_OF_MATERIALS_REPORTED:{total_resources}")
    if files_scanned != eligible_count or files_parsed != eligible_count:
        diagnostics.append(AdapterReason.COVERAGE_MISMATCH.value)
    if expected and (missing or unexpected):
        diagnostics.append(AdapterReason.COVERAGE_MISMATCH.value)
    adverse = [
        item for item in diagnostics
        if not item.startswith((
            "KICS_BILL_OF_MATERIALS_REPORTED:",
            "output_directory_manifest_sha256:",
        ))
    ]
    status = Status.PARTIAL if adverse else Status.PASS
    if status is Status.PASS:
        diagnostics.append(AdapterReason.COMPLETED.value)
    return ScannerRun(
        scanner="kics",
        scanner_version=request.locked_identity.version,
        status=status,
        findings=assign_occurrence_indices(findings),
        coverage=coverage,
        resource_coverage=resource_coverage,
        exit_code=process.exit_code if process.exit_code is not None else -1,
        stdout_sha256=process.stdout_sha256,
        stderr_sha256=process.stderr_sha256,
        raw_output_sha256=_canonical_native_hash(payload),
        resolved_launcher_path="protected-container-runtime",
        launcher_digest=request.container_runtime.executable_sha256,
        scanner_environment_digest=request.locked_identity.environment_digest,
        policy_inventory_digest=request.locked_identity.policy_inventory_digest,
        invocation_config_digest=_invocation_digest(request),
        ruleset_integrity=(
            Status.INCONCLUSIVE if queries_failed or similarity_failed else Status.PASS
        ),
        evaluations=tuple(evaluations),
        input_files=request.eligible_file_evidence,
        duration_ms=process.duration_ms,
        diagnostics=tuple(sorted(set(diagnostics))),
    )


class KicsAdapter:
    """KICS normalizer and locked-container execution boundary."""

    name = "kics"

    def contract(self) -> ScannerContract:
        return KICS_CONTRACT

    def normalize(self, raw_output: bytes, request: KicsScanRequest, process: CommandResult) -> ScannerRun:
        raise DomainError("KICS production normalization requires actual adapter execution")

    @staticmethod
    def _revalidate(request: KicsScanRequest) -> None:
        require_locked_identity(request.locked_identity, "kics")
        revalidate_trusted_container_runtime(
            request.container_runtime, workspace_root=request.workspace_root
        )
        for relative, expected in zip(request.files_eligible, request.eligible_file_evidence):
            current = _read_bound(request.scan_root / relative, relative, request.max_file_bytes)
            if current != expected:
                raise DomainError(AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value)

    @staticmethod
    def _build_view(request: KicsScanRequest, root: Path) -> None:
        root.mkdir(mode=0o700)
        for relative, expected in zip(request.files_eligible, request.eligible_file_evidence):
            target = root / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            try:
                current = _read_bound(
                    request.scan_root / relative, relative, request.max_file_bytes, descriptor
                )
                if current != expected:
                    raise DomainError(AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.chmod(target, 0o444)
        directories = sorted(
            (item for item in root.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts), reverse=True,
        )
        for directory in directories:
            os.chmod(directory, 0o555)
        os.chmod(root, 0o555)

    def scan(self, request: KicsScanRequest) -> ScannerRun:
        if type(request) is not KicsScanRequest or not request._trusted_request:
            raise DomainError("KICS scan requires a sealed request")
        def trusted(run: ScannerRun) -> ScannerRun:
            values = {
                item.name: getattr(run, item.name)
                for item in fields(ScannerRun) if item.init
            }
            return ScannerRun._from_adapter(**values)
        if not request.files_eligible:
            return trusted(_reason_run(
                request, AdapterReason.EMPTY_ELIGIBLE_SCOPE, status=Status.SKIPPED
            ))
        work = Path(tempfile.mkdtemp(prefix="iacgv-kics-"))
        process: CommandResult | None = None
        raw: bytes | None = None
        output_manifest_sha256 = ""
        terminal: ScannerRun | None = None
        try:
            self._revalidate(request)
            view = work / "scan"
            output = work / "output"
            self._build_view(request, view)
            output.mkdir(mode=0o733)
            argv = (
                str(request.container_runtime.executable_path), "run", "--rm", "--pull", "never",
                "--network", "none",
                "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", _DOCKER_PIDS_LIMIT,
                "--memory", _DOCKER_MEMORY, "--cpus", _DOCKER_CPUS,
                "--user", _DOCKER_USER,
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "-v", f"{view}:/iacgv-input:ro", "-v", f"{output}:/iacgv-output:rw",
                "--entrypoint", "/app/bin/kics", request.locked_identity.execution_reference,
                "scan", "--path", "/iacgv-input", "--output-path", "/iacgv-output",
                "--report-formats", "json", "--no-progress", "--minimal-ui",
            )
            require_hardened_docker_argv(
                argv, pids_limit=_DOCKER_PIDS_LIMIT, memory=_DOCKER_MEMORY,
                cpus=_DOCKER_CPUS, user=_DOCKER_USER,
            )
            revalidate_trusted_container_runtime(
                request.container_runtime, workspace_root=request.workspace_root
            )
            process = run_command(CommandRequest(
                argv=argv,
                expected_exit_codes=KICS_CONTRACT.expected_exit_codes,
                workspace_root=request.workspace_root,
                timeout_seconds=request.timeout_seconds,
                max_output_bytes=request.max_output_bytes,
                max_stdout_bytes=request.max_output_bytes,
                max_stderr_bytes=request.max_output_bytes,
                env_extra={"PYTHONDONTWRITEBYTECODE": "1"},
            ))
            if process.argv != argv:
                raise DomainError("KICS process argv differs from the locked invocation")
            self._revalidate(request)
            failure = _process_failure(request, process)
            if failure is not None:
                terminal = failure
            else:
                outputs, output_manifest_sha256 = read_locked_output_directory(
                    output, allowed_files=("results.json",),
                    max_file_bytes=request.max_output_bytes,
                    max_total_bytes=request.max_output_bytes,
                )
                raw = outputs["results.json"]
                repeated, repeated_root = read_locked_output_directory(
                    output, allowed_files=("results.json",),
                    max_file_bytes=request.max_output_bytes,
                    max_total_bytes=request.max_output_bytes,
                )
                if repeated_root != output_manifest_sha256 or repeated["results.json"] != raw:
                    raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
                output_manifest_sha256 = semantic_output_manifest(
                    "results.json", _canonical_native_hash(_strict_json(raw))
                )
        except (DomainError, OSError) as exc:
            value = str(exc)
            reason = next((item for item in AdapterReason if item.value == value), AdapterReason.SCAN_VIEW_PREPARATION_FAILED)
            terminal = _reason_run(request, reason, process=process, raw_output=raw)
        cleanup_failed = False
        try:
            remove_private_tree(work)
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            return trusted(_reason_run(
                request, AdapterReason.OUTPUT_CLEANUP_FAILED,
                process=process, raw_output=raw,
            ))
        if terminal is not None:
            return trusted(terminal)
        if process is None or raw is None:
            return trusted(_reason_run(
                request, AdapterReason.RAW_OUTPUT_MISSING, process=process
            ))
        try:
            parsed = _normalize(raw, request, process, output_manifest_sha256)
        except DomainError as exc:
            value = str(exc)
            reason = next(
                (item for item in AdapterReason if item.value == value),
                AdapterReason.INVALID_RESULTS_STRUCTURE,
            )
            parsed = _reason_run(
                request, reason, process=process, raw_output=raw,
            )
        return trusted(parsed)


__all__ = [
    "KICS_ADAPTER_CONTRACT",
    "KICS_CONTRACT",
    "KicsAdapter",
    "KicsScanRequest",
    "create_kics_scan_request",
]
