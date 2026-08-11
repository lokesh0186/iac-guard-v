"""Review-3 D5 fail-open reproductions and permanent security properties."""
from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path

import pytest

from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.engine import (
    ChangeMetrics,
    EngineEventEvaluation,
    ScanPlanFile,
    TrustedScanPlan,
    VerificationRequest,
    attest_checkov_scan_plan,
    run_checkov_verification,
)
from iac_guard_v.enums import (
    ArtifactKind,
    CheckEvaluationResult,
    ExceptionOrigin,
    Outcome,
    Severity,
    Status,
    Verdict,
    DeltaClass,
)
from iac_guard_v.models import (
    CheckEvaluation,
    CoverageCounters,
    ExceptionPolicy,
    ExceptionRecord,
    Finding,
    FindingLocation,
    GateResult,
    RequiredGates,
    ResourceCoverage,
    ScannerRun,
    Target,
    TargetIdentity,
)
from iac_guard_v.policy import PolicyRequest, evaluate_policy

from test_engine import IDENTITY, _executable, _gate, _scan_request
from test_checkov_adapter import request as adapter_request


NOW = date(2026, 8, 11)
DIGEST = "a" * 64


def finding(
    resource: str,
    *,
    severity: Severity = Severity.HIGH,
    line: int = 1,
    suppressed: bool = False,
    native: str = "",
) -> Finding:
    return Finding(
        scanner="checkov",
        scanner_version="3.3.0",
        rule_id="CKV_X",
        resource_address=resource,
        location=FindingLocation("main.tf", line, line),
        severity=severity,
        artifact_kind=ArtifactKind.TERRAFORM_HCL,
        suppressed=suppressed,
        native_fingerprint=native,
        message=f"finding at {line}",
    )


def evaluation(
    result: CheckEvaluationResult,
    resource: str = "aws_x.r",
    *,
    evaluated_keys: tuple = (),
) -> CheckEvaluation:
    bucket = {
        CheckEvaluationResult.PASSED: "passed_checks",
        CheckEvaluationResult.FAILED: "failed_checks",
        CheckEvaluationResult.SKIPPED: "skipped_checks",
        CheckEvaluationResult.UNKNOWN: "unknown_checks",
    }[result]
    return CheckEvaluation(
        "checkov", "3.3.0", "CKV_X", resource, "main.tf", result,
        evaluated_keys, bucket,
    )


def scanner_run(
    request,
    *,
    findings: tuple,
    evaluations: tuple,
    launcher_digest: str | None = None,
    invocation_digest: str = DIGEST,
    input_files: tuple | None = None,
) -> ScannerRun:
    observed = len({(item.file_path, item.resource_address) for item in evaluations})
    expected = len(request.expected_resources)
    matched = min(observed, expected)
    return ScannerRun._from_adapter(
        scanner="checkov",
        scanner_version="3.3.0",
        status=Status.PASS,
        findings=findings,
        coverage=CoverageCounters(1, 1, 1, 0, len(evaluations), 0, 0),
        resource_coverage=ResourceCoverage(
            expected, observed, matched, expected - matched, observed - matched, observed
        ),
        exit_code=0,
        stdout_sha256=DIGEST,
        stderr_sha256=DIGEST,
        raw_output_sha256=DIGEST,
        resolved_launcher_path=str(request.executable),
        launcher_digest=launcher_digest or request.expected_executable_sha256,
        scanner_environment_digest=request.expected_scanner_environment_sha256,
        policy_inventory_digest=request.expected_policy_inventory_sha256,
        invocation_config_digest=invocation_digest,
        ruleset_integrity=Status.PASS,
        evaluations=evaluations,
        input_files=request.eligible_file_evidence if input_files is None else input_files,
        diagnostics=("COMPLETED",),
    )


def execute(monkeypatch, baseline_request, candidate_request, baseline_run, candidate_run, *, count=1):
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, request: baseline_run if request is baseline_request.request else candidate_run,
    )
    request = VerificationRequest(
        baseline_request,
        candidate_request,
        (Target(IDENTITY, count),),
        RequiredGates(("validator",)),
        "b" * 64,
        "b" * 64,
    )
    return run_checkov_verification(request, _gate_executor=_gate)


def verdict(result, exceptions=None):
    return evaluate_policy(PolicyRequest(result, NOW, exceptions=exceptions))


def requests(tmp_path: Path):
    executable = _executable(tmp_path)
    return (
        _scan_request(tmp_path / "baseline", executable),
        _scan_request(tmp_path / "candidate", executable),
    )


def test_unknown_severity_new_finding_never_verifies(monkeypatch, tmp_path: Path) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    (candidate_request.scan_root / "main.tf").write_text(
        'resource "aws_x" "r" {}\nresource "aws_x" "other" {}\n',
        encoding="utf-8",
    )
    candidate_request = attest_checkov_scan_plan(candidate_request.request)
    baseline = scanner_run(
        baseline_request, findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_request,
        findings=(finding("aws_x.other", severity=Severity.UNKNOWN),),
        evaluations=(
            evaluation(CheckEvaluationResult.PASSED),
            evaluation(CheckEvaluationResult.FAILED, "aws_x.other"),
        ),
    )
    result = execute(monkeypatch, baseline_request, candidate_request, baseline, candidate)
    assert result.regression.status is not Status.PASS
    assert verdict(result).verdict is not Verdict.VERIFIED


def test_one_generic_pass_cannot_close_two_occurrences(monkeypatch, tmp_path: Path) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    baseline = scanner_run(
        baseline_request,
        findings=(finding("aws_x.r", line=1), finding("aws_x.r", line=2)),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_request, findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),),
    )
    result = execute(
        monkeypatch, baseline_request, candidate_request, baseline, candidate, count=2
    )
    assert result.target_outcomes[0].outcome is Outcome.INCONCLUSIVE
    assert verdict(result).verdict is Verdict.INCONCLUSIVE


@pytest.mark.parametrize("identity_field", ["launcher", "invocation"])
def test_complete_execution_identity_drift_is_inconclusive(
    monkeypatch, tmp_path: Path, identity_field: str
) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    baseline = scanner_run(
        baseline_request, findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    changes = {
        "launcher_digest": "c" * 64 if identity_field == "launcher" else None,
        "invocation_digest": "d" * 64 if identity_field == "invocation" else DIGEST,
    }
    candidate = scanner_run(
        candidate_request, findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),), **changes,
    )
    result = execute(monkeypatch, baseline_request, candidate_request, baseline, candidate)
    assert result.scanner_integrity.status is Status.INCONCLUSIVE
    assert result.target_outcomes[0].outcome is Outcome.RULE_OR_SCANNER_DRIFT
    assert verdict(result).verdict is Verdict.INCONCLUSIVE


def test_real_target_suppression_does_not_create_global_policy_failure(
    monkeypatch, tmp_path: Path
) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    baseline = scanner_run(
        baseline_request, findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_request, findings=(finding("aws_x.r", suppressed=True),),
        evaluations=(evaluation(CheckEvaluationResult.SKIPPED),),
    )
    result = execute(monkeypatch, baseline_request, candidate_request, baseline, candidate)
    exception = ExceptionRecord(
        "EX-SUPPRESS", IDENTITY, "accepted suppression", "security-team",
        date(2026, 1, 1), date(2026, 12, 31), ExceptionOrigin.TRUSTED_BASE,
        frozenset({Outcome.SUPPRESSED}),
    )
    decision = verdict(result, ExceptionPolicy((exception,)))
    assert result.target_outcomes[0].outcome is Outcome.SUPPRESSED
    assert result.suppression.status is Status.PASS
    assert decision.decisions[0].policy_permitted is True
    assert decision.verdict is Verdict.VERIFIED


def test_unrelated_resource_deletion_never_verifies(monkeypatch, tmp_path: Path) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    (baseline_request.scan_root / "main.tf").write_text(
        'resource "aws_x" "r" {}\nresource "aws_x" "other" {}\n',
        encoding="utf-8",
    )
    baseline_request = attest_checkov_scan_plan(baseline_request.request)
    baseline = scanner_run(
        baseline_request,
        findings=(finding("aws_x.r"), finding("aws_x.other", line=2)),
        evaluations=(
            evaluation(CheckEvaluationResult.FAILED),
            evaluation(CheckEvaluationResult.FAILED, "aws_x.other"),
        ),
    )
    candidate = scanner_run(
        candidate_request, findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),),
    )
    result = execute(monkeypatch, baseline_request, candidate_request, baseline, candidate)
    assert any(
        item.delta_class.value == "DESTRUCTIVE_CHANGE" and item.status is Status.FAIL
        for item in result.engine_events
    )
    assert verdict(result).verdict is not Verdict.VERIFIED


def test_rule_substitution_is_typed_not_hardcoded_false(monkeypatch, tmp_path: Path) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    baseline = scanner_run(
        baseline_request, findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_request, findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),),
    )
    result = execute(monkeypatch, baseline_request, candidate_request, baseline, candidate)
    event = next(item for item in result.engine_events if item.delta_class.value == "RULE_SUBSTITUTED")
    assert event.status in {Status.PASS, Status.INCONCLUSIVE, Status.UNSUPPORTED}


def test_caller_inventory_is_ignored_and_rebuilt_from_file_bytes(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    plan = _scan_request(tmp_path / "candidate", executable)
    (plan.scan_root / "main.tf").write_text(
        'resource "aws_x" "r" {}\nresource "aws_x" "hidden" {}\n',
        encoding="utf-8",
    )
    # The stale public request still claims only aws_x.r. Attestation must rediscover
    # both resources rather than blessing the caller's precomputed inventory.
    rebuilt = attest_checkov_scan_plan(plan.request)
    assert {item.resource_address for item in rebuilt.resources} == {
        "aws_x.r", "aws_x.hidden",
    }
    with pytest.raises(Exception, match="trusted scan plan"):
        VerificationRequest(
            plan.request,
            rebuilt,
            (Target(IDENTITY, 1),),
            RequiredGates(("validator",)),
            "b" * 64,
            "b" * 64,
        )
    with pytest.raises(Exception, match="detector provenance"):
        TrustedScanPlan(
            rebuilt.request, rebuilt.files, rebuilt.resources, rebuilt.inventory_sha256
        )


def test_kubernetes_inventory_is_detected_from_bound_bytes(tmp_path: Path) -> None:
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\n",
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    assert tuple(item.resource_address for item in plan.resources) == (
        "v1/Pod/default/demo",
    )
    assert plan.files[0].sha256 == hashlib.sha256(
        (raw.scan_root / "pod.yaml").read_bytes()
    ).hexdigest()
    assert plan.files[0].sha256 != raw.eligible_file_evidence[0].sha256


def test_v4_metrics_and_preflight_are_derived_from_bound_plans(
    monkeypatch, tmp_path: Path
) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    (candidate_request.scan_root / "main.tf").write_text(
        'resource "aws_x" "r" {\n  secure = true\n}\n', encoding="utf-8"
    )
    candidate_request = attest_checkov_scan_plan(candidate_request.request)
    baseline = scanner_run(
        baseline_request, findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_request, findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),),
    )
    result = execute(monkeypatch, baseline_request, candidate_request, baseline, candidate)
    assert result.preflight.reason_code == "BOUND_SCAN_PLAN_VALIDATED"
    assert "plan_sha256=" in result.preflight.detail
    assert result.change_metrics.files_changed == 1
    assert result.change_metrics.lines_changed > 0
    assert result.change_metrics.policy_files_changed is None
    assert result.change_metrics.unavailable_metrics == ("policy_files_changed",)


def test_preflight_rejects_adapter_input_evidence_substitution(
    monkeypatch, tmp_path: Path
) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    baseline = scanner_run(
        baseline_request, findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_request, findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),), input_files=(),
    )
    result = execute(monkeypatch, baseline_request, candidate_request, baseline, candidate)
    assert result.preflight.status is Status.ERROR
    assert result.preflight.reason_code == "BOUND_INPUT_REVALIDATION_FAILED"
    assert verdict(result).verdict is Verdict.INCONCLUSIVE


def test_all_eleven_delta_classes_have_a_typed_owner(monkeypatch, tmp_path: Path) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    baseline = scanner_run(
        baseline_request, findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_request, findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),),
    )
    result = execute(monkeypatch, baseline_request, candidate_request, baseline, candidate)
    d3_classes = {
        DeltaClass.NEW_FINDING,
        DeltaClass.LOCATION_CHANGED,
        DeltaClass.SEVERITY_INCREASED,
        DeltaClass.SCOPE_EXPANDED,
        DeltaClass.SUPPRESSION_ADDED,
        DeltaClass.RESOLVED_FINDING,
    }
    d5_classes = {item.delta_class for item in result.engine_events}
    assert d3_classes | d5_classes == set(DeltaClass)
    assert all(type(item.status) is Status for item in result.engine_events)


def test_two_occurrences_can_close_with_complete_native_tokens(
    monkeypatch, tmp_path: Path
) -> None:
    baseline_request, candidate_request = requests(tmp_path)
    baseline = scanner_run(
        baseline_request,
        findings=(
            finding("aws_x.r", line=1, native="native-a"),
            finding("aws_x.r", line=2, native="native-b"),
        ),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_request,
        findings=(),
        evaluations=(evaluation(
            CheckEvaluationResult.PASSED,
            evaluated_keys=("native-a", "native-b"),
        ),),
    )
    result = execute(
        monkeypatch, baseline_request, candidate_request, baseline, candidate, count=2
    )
    assert result.target_outcomes[0].outcome is Outcome.FIXED


def test_engine_event_rejects_finding_derived_class() -> None:
    with pytest.raises(Exception, match="D5-derived"):
        EngineEventEvaluation(
            DeltaClass.NEW_FINDING, Status.FAIL, "FORGED_ENGINE_EVENT"
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"file_path": ""},
        {"file_type": ""},
        {"size": -1},
        {"size": 2},
        {"sha256": "0" * 64},
    ],
)
def test_scan_plan_file_rejects_unbound_or_malformed_bytes(changes) -> None:
    values = {
        "file_path": "main.tf",
        "file_type": "terraform_hcl",
        "size": 1,
        "sha256": hashlib.sha256(b"x").hexdigest(),
        "content": b"x",
    }
    values.update(changes)
    with pytest.raises(Exception):
        ScanPlanFile(**values)


def test_scan_plan_canonical_data_excludes_private_bytes(tmp_path: Path) -> None:
    plan = _scan_request(tmp_path / "candidate", _executable(tmp_path))
    canonical = plan.canonical_dict()
    assert "content" not in canonical["files"][0]
    assert canonical["inventory_sha256"] == plan.inventory_sha256


@pytest.mark.parametrize(
    "source, message",
    [
        (b'/* unterminated', "block comment"),
        (b'resource "unterminated', "Terraform string"),
        (b"\xff", "UTF-8"),
    ],
)
def test_terraform_detector_rejects_ambiguous_bytes(
    tmp_path: Path, source: bytes, message: str
) -> None:
    raw = _scan_request(tmp_path / "candidate", _executable(tmp_path)).request
    (raw.scan_root / "main.tf").write_bytes(source)
    with pytest.raises(Exception, match=message):
        attest_checkov_scan_plan(raw)


def test_terraform_detector_ignores_comment_and_string_lookalikes(tmp_path: Path) -> None:
    raw = _scan_request(tmp_path / "candidate", _executable(tmp_path)).request
    (raw.scan_root / "main.tf").write_text(
        '# resource "aws_x" "comment" {}\n'
        '// resource "aws_x" "slash" {}\n'
        '/* resource "aws_x" "block" {} */\n'
        'locals { value = "resource \\"aws_x\\" \\"string\\" {}" }\n'
        'resource "aws_x" "real-name" {}\n',
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    assert [item.resource_address for item in plan.resources] == ["aws_x.real-name"]


@pytest.mark.parametrize(
    "source, message",
    [
        (b"\xff", "UTF-8"),
        (b"apiVersion: v1\nkind: Pod\n", "incomplete"),
        (b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: [x]\n", "complex"),
    ],
)
def test_kubernetes_detector_rejects_ambiguous_identity(
    tmp_path: Path, source: bytes, message: str
) -> None:
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_bytes(source)
    with pytest.raises(Exception, match=message):
        attest_checkov_scan_plan(raw)


def test_scan_plan_limits_apply_to_post_construction_changes(tmp_path: Path) -> None:
    raw = adapter_request(
        tmp_path, frameworks=("terraform",), max_file_bytes=64,
        max_total_eligible_bytes=64,
    )
    (raw.scan_root / "main.tf").write_bytes(b"x" * 65)
    with pytest.raises(Exception, match="per-file limit"):
        attest_checkov_scan_plan(raw)


def test_scan_plan_rejects_post_construction_symlink_and_count_growth(
    tmp_path: Path,
) -> None:
    symlink_root = tmp_path / "symlink"
    symlink_root.mkdir()
    raw = adapter_request(symlink_root, frameworks=("terraform",))
    outside = tmp_path / "outside.tf"
    outside.write_text('resource "aws_x" "outside" {}\n', encoding="utf-8")
    (raw.scan_root / "linked.tf").symlink_to(outside)
    with pytest.raises(Exception, match="symlinked IaC"):
        attest_checkov_scan_plan(raw)

    count_root = tmp_path / "count"
    count_root.mkdir()
    raw = adapter_request(count_root, frameworks=("terraform",), max_eligible_files=1)
    (raw.scan_root / "second.tf").write_text(
        'resource "aws_x" "second" {}\n', encoding="utf-8"
    )
    with pytest.raises(Exception, match="eligible-file limit"):
        attest_checkov_scan_plan(raw)


def test_trusted_scan_plan_rejects_malformed_factory_products(tmp_path: Path) -> None:
    plan = _scan_request(tmp_path / "candidate", _executable(tmp_path))
    with pytest.raises(Exception, match="files"):
        TrustedScanPlan(plan.request, [], plan.resources, plan.inventory_sha256)
    with pytest.raises(Exception, match="resources"):
        TrustedScanPlan(plan.request, plan.files, [], plan.inventory_sha256)
    with pytest.raises(Exception, match="disagree"):
        TrustedScanPlan(plan.request, plan.files, (), plan.inventory_sha256)


@pytest.mark.parametrize(
    "changes",
    [
        {"affected_resources": ["aws_x.r"]},
        {"affected_paths": ("",)},
        {"detail": None},
    ],
)
def test_engine_event_rejects_malformed_diagnostics(changes) -> None:
    values = {
        "delta_class": DeltaClass.DESTRUCTIVE_CHANGE,
        "status": Status.FAIL,
        "reason_code": "RESOURCES_DELETED",
    }
    values.update(changes)
    with pytest.raises(Exception):
        EngineEventEvaluation(**values)


@pytest.mark.parametrize(
    "changes",
    [
        {"lines_added": -1},
        {"diff_ratio": -0.1},
        {"policy_files_changed": -1},
        {"unavailable_metrics": []},
    ],
)
def test_change_metrics_reject_malformed_values(changes) -> None:
    values = dict(
        lines_added=0, lines_removed=0, lines_changed=0, diff_ratio=0.0,
        files_changed=0, resources_changed=0, resources_added=0,
        resources_deleted=0, policy_files_changed=0,
    )
    values.update(changes)
    with pytest.raises(Exception):
        ChangeMetrics(**values)
