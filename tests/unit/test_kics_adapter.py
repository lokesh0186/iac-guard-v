"""E1 KICS fail-closed contract and mutation probes."""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

import iac_guard_v.adapters.kics as kics_module
from iac_guard_v.adapters.base import AdapterReason
from iac_guard_v.adapters.kics import KICS_CONTRACT, KicsAdapter, create_kics_scan_request
from iac_guard_v.adapters.phase_e_lock import (
    LockedContainerIdentity,
    load_locked_container_identity,
    load_protected_phase_e_evidence,
)
from iac_guard_v.enums import ArtifactKind, Status
from iac_guard_v.models import BoundInputFile, DomainError, ExpectedResource
from iac_guard_v.process import CommandResult, ProcessReason
from tests.phase_e_test_support import (
    make_test_container_runtime, normalize_kics_fixture,
)


LOCK = Path(__file__).parents[2] / "tools/locks/phase-e-locks.json"
ROOT = Path(__file__).parents[2]
BUNDLE = load_protected_phase_e_evidence(ROOT)


@pytest.fixture(autouse=True)
def _private_runtime_revalidation(monkeypatch):
    monkeypatch.setattr(
        kics_module, "revalidate_trusted_container_runtime",
        lambda runtime, **_: runtime.identity,
    )


def _process(
    *, status: Status = Status.PASS, exit_code: int | None = 0,
    reason: ProcessReason = ProcessReason.COMPLETED_WITHIN_CONTRACT,
    timed_out: bool = False, argv: tuple[str, ...] = ("docker",),
) -> CommandResult:
    return CommandResult(
        argv=argv, status=status, exit_code=exit_code,
        stdout=b"kics output", stderr=b"", duration_ms=3,
        truncated=False, timed_out=timed_out, killed_signal=None,
        reason_code=reason,
        resolved_executable="/usr/local/bin/docker" if status is Status.PASS else "",
        primary_execution_event=reason,
    )


def _query(
    *, query_id: str = "f861041c-8c9f-4156-acfc-5e6e524f5884",
    similarity: str = "a" * 64, severity: str = "HIGH",
    resource_type: str = "aws_s3_bucket", resource_name: str = "demo",
) -> dict:
    return {
        "query_name": "S3 Bucket Logging Disabled",
        "query_id": query_id,
        "query_url": "https://example.invalid/rule",
        "severity": severity,
        "platform": "Terraform",
        "cwe": "778",
        "risk_score": "5.1",
        "cloud_provider": "AWS",
        "category": "Observability",
        "experimental": False,
        "description": "Logging is required",
        "description_id": "fa5c7c72",
        "files": [{
            "file_name": "../../iacgv-input/main.tf",
            "similarity_id": similarity,
            "line": 1,
            "resource_type": resource_type,
            "resource_name": resource_name,
            "issue_type": "MissingAttribute",
            "search_key": "aws_s3_bucket[demo]",
            "search_line": 1,
            "search_value": "",
            "expected_value": "logging",
            "actual_value": "undefined",
        }],
    }


def _document(*, queries: list | None = None, **overrides) -> dict:
    queries = [] if queries is None else queries
    severities = {"CRITICAL": 0, "HIGH": 0, "INFO": 0, "LOW": 0, "MEDIUM": 0, "TRACE": 0}
    for item in queries:
        severities[item["severity"]] = severities.get(item["severity"], 0) + len(item["files"])
    value = {
        "kics_version": "v2.1.20",
        "files_scanned": 1,
        "lines_scanned": 1,
        "files_parsed": 1,
        "lines_parsed": 1,
        "lines_ignored": 0,
        "files_failed_to_scan": 0,
        "queries_total": 1100,
        "queries_failed_to_execute": 0,
        "queries_failed_to_compute_similarity_id": 0,
        "scan_id": "console",
        "severity_counters": severities,
        "total_counter": sum(
            len(item["files"]) for item in queries if item["severity"] != "TRACE"
        ),
        "total_bom_resources": sum(
            len(item["files"]) for item in queries if item["severity"] == "TRACE"
        ),
        "start": "2026-08-12T00:00:00Z",
        "end": "2026-08-12T00:00:01Z",
        "paths": ["/iacgv-input"],
        "queries": queries,
    }
    value.update(overrides)
    return value


def _request(tmp_path: Path, *, expected: bool = True, **overrides):
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    source = root / "main.tf"
    source.write_text('resource "aws_s3_bucket" "demo" {}\n', encoding="utf-8")
    stat_ = source.stat()
    evidence = BoundInputFile(
        "main.tf", "regular_file", stat_.st_size,
        hashlib.sha256(source.read_bytes()).hexdigest(), stat_.st_dev, stat_.st_ino,
    )
    resources = (
        ExpectedResource(
            "main.tf", "aws_s3_bucket.demo", ArtifactKind.TERRAFORM_HCL,
            "aws_s3_bucket.demo",
        ),
    ) if expected else ()
    docker = Path(shutil.which("docker") or "/usr/bin/true")
    locked = load_locked_container_identity(BUNDLE, "kics", "linux/arm64")
    values = {
        "workspace_root": root,
        "scan_root": root,
        "files_eligible": ("main.tf",),
        "eligible_file_evidence": (evidence,),
        "expected_resources": resources,
        "container_runtime": make_test_container_runtime(locked, docker),
        "locked_identity": locked,
    }
    values.update(overrides)
    return create_kics_scan_request(**values)


def _normalize(tmp_path: Path, document: dict, **request_overrides):
    counters = document.get("severity_counters", {})
    exits = {"INFO": 20, "LOW": 30, "MEDIUM": 40, "HIGH": 50, "CRITICAL": 60}
    ranks = {name: index for index, name in enumerate(exits)}
    present = [name for name in exits if type(counters) is dict and counters.get(name, 0)]
    exit_code = 0 if not present else exits[max(present, key=ranks.get)]
    return normalize_kics_fixture(
        json.dumps(document).encode(), _request(tmp_path, **request_overrides),
        _process(exit_code=exit_code),
    )


def test_contract_is_exact_e03_selection() -> None:
    assert KICS_CONTRACT.supported_versions == ("2.1.20",)
    assert KICS_CONTRACT.expected_exit_codes == (0, 20, 30, 40, 50, 60)


@pytest.mark.parametrize(
    ("severity", "exit_code"),
    [(None, 0), ("INFO", 20), ("LOW", 30), ("MEDIUM", 40), ("HIGH", 50), ("CRITICAL", 60)],
)
def test_official_result_bearing_exit_codes_are_parsed(
    tmp_path: Path, severity: str | None, exit_code: int,
) -> None:
    queries = [] if severity is None else [_query(severity=severity)]
    run = normalize_kics_fixture(
        json.dumps(_document(queries=queries)).encode(),
        _request(tmp_path, expected=severity is not None),
        _process(exit_code=exit_code),
    )
    assert run.status is Status.PASS


@pytest.mark.parametrize(
    ("document", "exit_code"),
    [(_document(queries=[_query(severity="CRITICAL")]), 20), (_document(), 60)],
)
def test_result_exit_must_match_native_highest_severity(
    tmp_path: Path, document: dict, exit_code: int,
) -> None:
    run = normalize_kics_fixture(
        json.dumps(document).encode(), _request(tmp_path), _process(exit_code=exit_code)
    )
    assert run.status is Status.ERROR
    assert AdapterReason.EXIT_RESULT_MISMATCH.value in run.diagnostics


@pytest.mark.parametrize(
    "field", ("query_url", "category", "experimental", "description", "description_id")
)
def test_required_native_query_fields_cannot_disappear(tmp_path: Path, field: str) -> None:
    document = _document(queries=[_query()])
    document["queries"][0].pop(field)
    run = _normalize(tmp_path, document)
    assert run.status is Status.ERROR
    assert AdapterReason.INVALID_RESULTS_STRUCTURE.value in run.diagnostics


@pytest.mark.parametrize(
    "field",
    ("issue_type", "search_key", "search_line", "search_value", "expected_value", "actual_value"),
)
def test_required_native_file_fields_cannot_disappear(tmp_path: Path, field: str) -> None:
    document = _document(queries=[_query()])
    document["queries"][0]["files"][0].pop(field)
    run = _normalize(tmp_path, document)
    assert run.status is Status.ERROR
    assert AdapterReason.INVALID_RESULTS_STRUCTURE.value in run.diagnostics


def test_official_bom_is_preserved_without_downgrading_run(tmp_path: Path) -> None:
    bom = _query(severity="TRACE")
    document = _document(queries=[])
    document.update(
        bill_of_materials=[bom], total_bom_resources=1,
        severity_counters={
            "CRITICAL": 0, "HIGH": 0, "INFO": 0, "LOW": 0,
            "MEDIUM": 0, "TRACE": 1,
        },
    )
    run = _normalize(tmp_path, document, expected=False)
    assert run.status is Status.PASS
    assert run.findings == ()
    assert run.evaluations[0].source_bucket == "bill_of_materials"
    assert run.evaluations[0].native_result.value == "UNKNOWN"
    assert "KICS_BILL_OF_MATERIALS_REPORTED:1" in run.diagnostics


def test_complete_standard_severity_counter_set_is_required(tmp_path: Path) -> None:
    document = _document(queries=[_query()])
    document["severity_counters"] = {"HIGH": 1}
    run = _normalize(tmp_path, document)
    assert run.status is Status.ERROR
    assert AdapterReason.INVALID_RESULTS_STRUCTURE.value in run.diagnostics


@pytest.mark.parametrize("exit_code", [1, 2, 10, 70, 126, 127])
def test_engine_error_exits_are_outside_result_contract(exit_code: int) -> None:
    assert exit_code not in KICS_CONTRACT.expected_exit_codes


def test_normal_finding_preserves_similarity_id(tmp_path: Path) -> None:
    run = _normalize(tmp_path, _document(queries=[_query()]))
    assert run.status is Status.PASS
    assert run.findings[0].native_fingerprint == "a" * 64
    assert run.findings[0].resource_address == "aws_s3_bucket.demo"
    assert run.coverage.files_parsed == 1


def test_valid_no_finding_result_can_pass(tmp_path: Path) -> None:
    run = _normalize(tmp_path, _document(), expected=False)
    assert run.status is Status.PASS
    assert run.findings == ()


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("files_failed_to_scan", AdapterReason.KICS_FAILED_TO_SCAN.value),
        ("queries_failed_to_execute", AdapterReason.KICS_QUERY_EXECUTION_FAILED.value),
        (
            "queries_failed_to_compute_similarity_id",
            AdapterReason.KICS_SIMILARITY_ID_FAILED.value,
        ),
    ],
)
def test_native_failure_counters_are_partial(
    tmp_path: Path, field: str, reason: str
) -> None:
    document = _document(queries=[_query()], **{field: 1})
    if field == "files_failed_to_scan":
        document.update(files_scanned=2, files_parsed=1)
    run = _normalize(tmp_path, document)
    assert run.status is Status.PARTIAL
    assert reason in run.diagnostics
    if field == "queries_failed_to_execute":
        assert run.ruleset_integrity is Status.INCONCLUSIVE
    elif field == "queries_failed_to_compute_similarity_id":
        assert run.ruleset_integrity is Status.INCONCLUSIVE
    else:
        assert run.ruleset_integrity is Status.PASS


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"not json", AdapterReason.MALFORMED_JSON.value),
        (b"[]", AdapterReason.UNEXPECTED_TOP_LEVEL.value),
        (b'{"kics_version":"v2.1.20","queries":[],"queries":[]}', AdapterReason.DUPLICATE_JSON_KEY.value),
        (b"", AdapterReason.EMPTY_OUTPUT.value),
    ],
)
def test_malformed_duplicate_and_wrong_shape_fail_closed(
    tmp_path: Path, raw: bytes, reason: str
) -> None:
    run = normalize_kics_fixture(raw, _request(tmp_path), _process())
    assert run.status is Status.ERROR
    assert reason in run.diagnostics


def test_timeout_is_typed(tmp_path: Path) -> None:
    process = _process(
        status=Status.TIMEOUT, exit_code=None,
        reason=ProcessReason.DEADLINE_EXCEEDED, timed_out=True,
    )
    run = normalize_kics_fixture(b"{}", _request(tmp_path), process)
    assert run.status is Status.TIMEOUT
    assert AdapterReason.DEADLINE_EXCEEDED.value in run.diagnostics


def test_unknown_native_severity_is_invalid_native_contract(tmp_path: Path) -> None:
    run = _normalize(tmp_path, _document(queries=[_query(severity="NOVEL")]))
    assert run.status is Status.ERROR
    assert AdapterReason.INVALID_RESULTS_STRUCTURE.value in run.diagnostics


def test_partial_file_coverage_cannot_pass(tmp_path: Path) -> None:
    run = _normalize(
        tmp_path,
        _document(queries=[_query()], files_scanned=1, files_parsed=0),
    )
    assert run.status is Status.PARTIAL
    assert AdapterReason.COVERAGE_MISMATCH.value in run.diagnostics


def test_partial_resource_coverage_cannot_pass(tmp_path: Path) -> None:
    run = _normalize(
        tmp_path,
        _document(queries=[_query(resource_name="other")]),
    )
    assert run.status is Status.PARTIAL
    assert run.resource_coverage.expected_resources_missing == 1


def test_version_drift_is_error(tmp_path: Path) -> None:
    run = _normalize(tmp_path, _document(kics_version="v9.9.9"))
    assert run.status is Status.ERROR
    assert AdapterReason.VERSION_MISMATCH.value in run.diagnostics


def test_lock_environment_drift_is_rejected(tmp_path: Path) -> None:
    trusted = load_locked_container_identity(BUNDLE, "kics", "linux/arm64")
    forged = LockedContainerIdentity(**trusted.canonical_dict())
    with pytest.raises(DomainError, match="reviewed Phase-E lock"):
        _request(tmp_path, locked_identity=forged)


def test_lock_graph_mutation_is_rejected(tmp_path: Path) -> None:
    payload = json.loads(LOCK.read_text())
    payload["tools"]["kics"]["version"] = "2.1.19"
    bundle_root = tmp_path / "bundle"
    shutil.copytree(ROOT / "tools", bundle_root / "tools")
    mutated = bundle_root / "tools/locks/phase-e-locks.json"
    mutated.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DomainError, match="reviewed E0.3 seal"):
        load_locked_container_identity(
            load_protected_phase_e_evidence(bundle_root), "kics", "linux/arm64"
        )


def test_native_order_reversal_has_identical_canonical_output(tmp_path: Path) -> None:
    first = _query(query_id="11111111-1111-4111-8111-111111111111", similarity="1" * 64)
    second = _query(query_id="22222222-2222-4222-8222-222222222222", similarity="2" * 64)
    run_a = _normalize(tmp_path / "a", _document(queries=[first, second]))
    run_b = _normalize(tmp_path / "b", _document(queries=[second, first]))
    assert run_a.canonical_dict() == run_b.canonical_dict()


def test_result_shape_count_contradiction_is_error(tmp_path: Path) -> None:
    run = _normalize(tmp_path, _document(queries=[_query()], total_counter=0))
    assert run.status is Status.ERROR
    assert AdapterReason.INVALID_RESULTS_STRUCTURE.value in run.diagnostics


@pytest.mark.parametrize(
    "mutation",
    [
        {"queries_total": "1100"},
        {"paths": "not-list"},
        {"lines_scanned": 1, "lines_parsed": 2},
        {"lines_scanned": 1, "lines_parsed": 1, "lines_ignored": 1},
        {"queries_total": 1, "queries_failed_to_execute": 1,
         "queries_failed_to_compute_similarity_id": 1},
        {"queries_total": 0},
    ],
)
def test_top_level_type_and_arithmetic_contradictions_are_errors(
    tmp_path: Path, mutation: dict,
) -> None:
    document = _document(queries=[_query()])
    document.update(mutation)
    run = _normalize(tmp_path, document)
    assert run.status is Status.ERROR
    assert AdapterReason.INVALID_RESULTS_STRUCTURE.value in run.diagnostics


def test_trace_is_bom_not_finding_or_resource_count(tmp_path: Path) -> None:
    document = _document(queries=[])
    document.update(
        bill_of_materials=[_query(severity="TRACE")], total_bom_resources=1,
        severity_counters={
            "CRITICAL": 0, "HIGH": 0, "INFO": 0, "LOW": 0,
            "MEDIUM": 0, "TRACE": 1,
        },
    )
    run = _normalize(tmp_path, document, expected=False)
    assert run.status is Status.PASS
    assert run.findings == ()
    assert run.resource_coverage.summary_resources_reported == 0
    assert "KICS_BILL_OF_MATERIALS_REPORTED:1" in run.diagnostics


def test_official_optional_query_and_file_fields_are_understood(tmp_path: Path) -> None:
    query = _query()
    for key in ("cwe", "risk_score", "cloud_provider"):
        query.pop(key, None)
    file_record = query["files"][0]
    for key in ("resource_type", "resource_name"):
        file_record.pop(key, None)
    run = _normalize(tmp_path, _document(queries=[query]), expected=False)
    assert run.status is Status.PASS
    assert run.findings[0].resource_address.startswith("kics-global-")

    query = _query()
    query.update({
        "cis_description_id": "1.2", "cis_description_title": "title",
        "cis_description_text": "text", "cis_description_id_raw": "1.2",
        "cis_description_text_raw": "text", "cis_description_rationale": "why",
        "cis_benchmark_name": "benchmark", "cis_benchmark_version": "1.0",
    })
    query["files"][0].update({
        "old_similarity_id": "b" * 64, "value": "x", "remediation": "fix",
        "remediation_type": "manual",
    })
    run = _normalize(tmp_path / "present", _document(queries=[query]))
    assert AdapterReason.UNKNOWN_NATIVE_CATEGORY.value not in run.diagnostics


def test_input_byte_change_is_detected_before_execution(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (request.scan_root / "main.tf").write_text("changed\n", encoding="utf-8")
    run = KicsAdapter().scan(request)
    assert run.status is Status.ERROR
    assert AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value in run.diagnostics


@pytest.mark.parametrize(
    "overrides",
    [
        {"files_eligible": ["main.tf"]},
        {"eligible_file_evidence": []},
        {"files_eligible": ("main.tf", "main.tf")},
        {"files_eligible": ("z.tf", "a.tf")},
        {"eligible_file_evidence": ("not evidence",)},
        {"expected_resources": []},
        {"expected_resources": ("not resource",)},
        {"timeout_seconds": 0},
        {"max_output_bytes": 0},
        {"max_total_eligible_bytes": 1},
    ],
)
def test_request_contract_mutations_are_rejected(tmp_path: Path, overrides: dict) -> None:
    with pytest.raises(DomainError):
        _request(tmp_path, **overrides)


def test_direct_request_construction_is_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    values = {
        name: getattr(request, name)
        for name in (
            "workspace_root", "scan_root", "files_eligible", "eligible_file_evidence",
            "expected_resources", "container_runtime", "locked_identity",
        )
    }
    with pytest.raises(DomainError, match="sealed request factory"):
        kics_module.KicsScanRequest(**values)


def test_request_rejects_scan_root_outside_workspace(tmp_path: Path) -> None:
    request = _request(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(DomainError, match="inside workspace"):
        create_kics_scan_request(
            workspace_root=request.workspace_root,
            scan_root=outside,
            files_eligible=request.files_eligible,
            eligible_file_evidence=request.eligible_file_evidence,
            expected_resources=request.expected_resources,
            container_runtime=request.container_runtime,
            locked_identity=request.locked_identity,
        )


def test_missing_request_path_and_untrusted_runtime_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    with pytest.raises(DomainError, match="cannot be resolved"):
        create_kics_scan_request(
            workspace_root=request.workspace_root,
            scan_root=tmp_path / "missing",
            files_eligible=request.files_eligible,
            eligible_file_evidence=request.eligible_file_evidence,
            expected_resources=request.expected_resources,
            container_runtime=request.container_runtime,
            locked_identity=request.locked_identity,
        )
    with pytest.raises(DomainError, match="TrustedContainerRuntime"):
        _request(tmp_path / "second", container_runtime=object())


def test_oversize_and_missing_input_are_typed(tmp_path: Path) -> None:
    source = tmp_path / "data"
    source.write_bytes(b"xx")
    with pytest.raises(DomainError, match=AdapterReason.INPUT_FILE_BYTES_EXCEEDED.value):
        kics_module._read_bound(source, "data", 1)
    with pytest.raises(DomainError, match=AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value):
        kics_module._read_bound(tmp_path / "missing", "data", 1)


def test_strict_json_depth_unicode_and_nested_duplicates_are_typed() -> None:
    with pytest.raises(DomainError, match=AdapterReason.MALFORMED_JSON.value):
        kics_module._strict_json(b"\xff")
    deep = ("[" * 129 + "]" * 129).encode()
    with pytest.raises(DomainError, match=AdapterReason.JSON_DEPTH_EXCEEDED.value):
        kics_module._strict_json(deep)
    with pytest.raises(DomainError, match=AdapterReason.DUPLICATE_JSON_KEY.value):
        kics_module._strict_json(b'{"outer":{"x":1,"x":2}}')


def test_native_path_and_resource_mutations_fail_closed() -> None:
    with pytest.raises(DomainError, match=AdapterReason.INVALID_RESULTS_STRUCTURE.value):
        kics_module._native_path(None, ("main.tf",))
    with pytest.raises(DomainError, match=AdapterReason.COVERAGE_MISMATCH.value):
        kics_module._native_path("other.tf", ("main.tf",))
    assert kics_module._resource({}, "rule") == "kics-global-rule"
    with pytest.raises(DomainError, match=AdapterReason.INVALID_RESULTS_STRUCTURE.value):
        kics_module._resource({"resource_type": "x"}, "rule")
    assert kics_module._resource(
        {"resource_type": "n/a", "resource_name": "n/a"}, "rule"
    ) == "kics-global-rule"


@pytest.mark.parametrize(
    ("platform_name", "path", "expected"),
    [
        ("Kubernetes", "pod.yaml", ArtifactKind.KUBERNETES_YAML),
        ("Kubernetes", "pod.json", ArtifactKind.KUBERNETES_JSON),
        ("CloudFormation", "stack.yaml", ArtifactKind.CLOUDFORMATION),
        ("Mystery", "main.tf", ArtifactKind.UNKNOWN),
    ],
)
def test_artifact_mapping_is_closed(platform_name: str, path: str, expected: ArtifactKind) -> None:
    assert kics_module._artifact(platform_name, path) is expected


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (lambda d: d.pop("queries"), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d.update(files_scanned=0, files_parsed=1), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d.update(severity_counters=[]), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["severity_counters"].update(HIGH=-1), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d.update(queries={}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["queries"].append({}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["queries"][0].update(platform=3), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["queries"][0].update(files=[]), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["queries"][0]["files"].append({}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["queries"][0]["files"][0].update(similarity_id="bad"), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["queries"][0]["files"][0].update(line=0), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
    ],
)
def test_result_structure_mutations_are_errors(tmp_path: Path, mutator, reason: str) -> None:
    document = _document(queries=[_query()])
    mutator(document)
    run = _normalize(tmp_path, document)
    assert run.status is Status.ERROR
    assert reason in run.diagnostics


def test_unknown_fields_and_unknown_severity_are_partial(tmp_path: Path) -> None:
    document = _document(queries=[_query()], extension=True)
    document["queries"][0]["extension"] = "x"
    document["queries"][0]["files"][0]["extension"] = "x"
    run = _normalize(tmp_path, document)
    assert run.status is Status.PARTIAL
    assert AdapterReason.UNKNOWN_NATIVE_CATEGORY.value in run.diagnostics


@pytest.mark.parametrize(
    ("status", "reason", "truncated", "expected"),
    [
        (Status.PARTIAL, ProcessReason.OUTPUT_LIMIT_EXCEEDED, True, AdapterReason.TRUNCATED_OUTPUT.value),
        (Status.ERROR, ProcessReason.KILLED_BY_SIGNAL, False, AdapterReason.KILLED_PROCESS.value),
        (Status.ERROR, ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT, False, AdapterReason.EXIT_CODE_OUTSIDE_CONTRACT.value),
        (Status.ERROR, ProcessReason.SPAWN_FAILED, False, AdapterReason.PROCESS_ERROR.value),
    ],
)
def test_process_failures_never_parse(
    tmp_path: Path, status: Status, reason: ProcessReason, truncated: bool, expected: str
) -> None:
    process = CommandResult(
        argv=("docker",), status=status,
        exit_code=-9 if reason is ProcessReason.KILLED_BY_SIGNAL else None,
        stdout=b"", stderr=b"",
        duration_ms=1, truncated=truncated, timed_out=False,
        killed_signal=9 if reason is ProcessReason.KILLED_BY_SIGNAL else None,
        reason_code=reason, resolved_executable="",
        primary_execution_event=reason,
    )
    run = normalize_kics_fixture(b"{}", _request(tmp_path), process)
    assert run.status is not Status.PASS
    assert expected in run.diagnostics


def test_empty_scope_is_skipped_without_spawn(tmp_path: Path) -> None:
    request = _request(
        tmp_path, files_eligible=(), eligible_file_evidence=(), expected_resources=()
    )
    run = KicsAdapter().scan(request)
    assert run.status is Status.SKIPPED
    assert AdapterReason.EMPTY_ELIGIBLE_SCOPE.value in run.diagnostics


def test_adapter_rejects_untrusted_request_and_process_type(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="actual adapter execution"):
        KicsAdapter().normalize(b"{}", object(), _process())
    with pytest.raises(DomainError, match="actual adapter execution"):
        KicsAdapter().normalize(b"{}", _request(tmp_path), object())
    with pytest.raises(DomainError, match="sealed request"):
        KicsAdapter().scan(object())
    assert KicsAdapter().contract() is KICS_CONTRACT


def test_locked_scan_uses_pull_never_and_all_result_exit_codes(
    tmp_path: Path, monkeypatch,
) -> None:
    request = _request(tmp_path)

    def execute(command):
        assert command.expected_exit_codes == (0, 20, 30, 40, 50, 60)
        pull = command.argv.index("--pull")
        assert command.argv[pull + 1] == "never"
        for flag, expected in (
            ("--network", "none"), ("--cap-drop", "ALL"),
            ("--security-opt", "no-new-privileges"),
            ("--pids-limit", "128"), ("--memory", "512m"),
            ("--cpus", "1.0"), ("--user", "65532:65532"),
        ):
            assert command.argv[command.argv.index(flag) + 1] == expected
        assert "--read-only" in command.argv
        output_mount = next(item for item in command.argv if item.endswith(":/iacgv-output:rw"))
        output = Path(output_mount.removesuffix(":/iacgv-output:rw"))
        (output / "results.json").write_text(
            json.dumps(_document(queries=[_query()])), encoding="utf-8"
        )
        return _process(exit_code=50, argv=command.argv)

    monkeypatch.setattr(kics_module, "run_command", execute)
    run = KicsAdapter().scan(request)
    assert run.status is Status.PASS
    assert run.exit_code == 50


def test_unexpected_output_file_fails_complete_directory_integrity(
    tmp_path: Path, monkeypatch,
) -> None:
    request = _request(tmp_path, max_output_bytes=4096)

    def execute(command):
        output_mount = next(
            item for item in command.argv if item.endswith(":/iacgv-output:rw")
        )
        output = Path(output_mount.removesuffix(":/iacgv-output:rw"))
        (output / "results.json").write_text(
            json.dumps(_document(queries=[_query()])), encoding="utf-8"
        )
        (output / "unbounded-extra.bin").write_bytes(b"x" * 8192)
        return _process(exit_code=50, argv=command.argv)

    monkeypatch.setattr(kics_module, "run_command", execute)
    run = KicsAdapter().scan(request)
    assert run.status is Status.ERROR
    assert AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value in run.diagnostics


def test_scan_rejects_command_result_for_another_argv(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(kics_module, "run_command", lambda command: _process())
    run = KicsAdapter().scan(_request(tmp_path))
    assert run.status is Status.ERROR
    assert AdapterReason.SCAN_VIEW_PREPARATION_FAILED.value in run.diagnostics
