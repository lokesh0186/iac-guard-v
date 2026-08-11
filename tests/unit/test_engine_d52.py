"""D5.2 protected configuration and exact evidence-boundary regressions."""
from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

import pytest

import iac_guard_v.engine as ENGINE

from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.engine import (
    VerificationRequest,
    GovernedConfigEvidence,
    TrustedGateRegistry,
    TrustedVerificationConfigBundle,
    attest_checkov_scan_plan,
    production_gate_registry,
    run_checkov_verification,
)
from iac_guard_v.enums import ArtifactKind, CheckEvaluationResult, Severity, Status
from iac_guard_v.models import (
    CheckEvaluation,
    Finding,
    FindingLocation,
    RequiredGates,
    Target,
    TargetIdentity,
)

from test_engine import IDENTITY, _config, _executable, _gate, _scan_request
from test_engine_d51 import DIGEST, evaluation, finding, scanner_run


def test_verification_request_has_no_caller_policy_or_lock_fields() -> None:
    forbidden = {
        "required_gates",
        "severity_floor",
        "fail_on_location_change",
        "trusted_governed_config_sha256",
        "candidate_governed_config_sha256",
    }
    assert forbidden.isdisjoint(VerificationRequest.__dataclass_fields__)


def test_production_runner_has_no_arbitrary_gate_callback() -> None:
    assert "_gate_executor" not in inspect.signature(run_checkov_verification).parameters


def test_two_arbitrary_positive_key_sets_do_not_prove_two_occurrences(
    monkeypatch, tmp_path: Path
) -> None:
    executable = _executable(tmp_path)
    baseline_plan = _scan_request(tmp_path / "baseline", executable)
    candidate_plan = _scan_request(tmp_path / "candidate", executable)
    baseline = scanner_run(
        baseline_plan,
        findings=(
            finding("aws_x.r", line=1),
            finding("aws_x.r", line=2),
        ),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_plan,
        findings=(),
        evaluations=(
            evaluation(CheckEvaluationResult.PASSED, evaluated_keys=("unrelated-a",)),
            evaluation(CheckEvaluationResult.PASSED, evaluated_keys=("unrelated-b",)),
        ),
    )
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, request: (
            baseline if request.scan_root == baseline_plan.scan_root else candidate
        ),
    )
    gates = RequiredGates(("validator",))
    request = VerificationRequest(
        baseline_plan,
        candidate_plan,
        (Target(IDENTITY, 2),),
        _config(baseline_plan, candidate_plan, gates),
    )
    result = run_checkov_verification(request)
    assert result.target_outcomes[0].outcome.value == "INCONCLUSIVE"
    assert result.target_outcomes[0].target_reason == (
        "OCCURRENCE_PASS_COVERAGE_INCOMPLETE"
    )


def test_repeated_resource_address_requires_exact_target_selector(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    for plan in (baseline, candidate):
        (plan.scan_root / "a").mkdir()
        (plan.scan_root / "b").mkdir()
        (plan.scan_root / "a/main.tf").write_text(
            'resource "aws_x" "r" {}\n', encoding="utf-8"
        )
        (plan.scan_root / "b/main.tf").write_text(
            'resource "aws_x" "r" {}\n', encoding="utf-8"
        )
    baseline = attest_checkov_scan_plan(baseline.request)
    candidate = attest_checkov_scan_plan(candidate.request)
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    with pytest.raises(Exception, match="ambiguous"):
        VerificationRequest(
            baseline,
            candidate,
            (Target(IDENTITY, 1),),
            config,
        )


def _resource_finding(rule: str, path: str, resource: str) -> Finding:
    return Finding(
        scanner="checkov",
        scanner_version="3.3.0",
        rule_id=rule,
        resource_address=resource,
        location=FindingLocation(path, 1, 1),
        severity=Severity.HIGH,
        artifact_kind=ArtifactKind.TERRAFORM_HCL,
    )


def _resource_evaluation(rule: str, path: str, resource: str) -> CheckEvaluation:
    return CheckEvaluation(
        "checkov",
        "3.3.0",
        rule,
        resource,
        path,
        CheckEvaluationResult.FAILED,
        (),
        "failed_checks",
    )


def test_same_address_unrelated_deletion_remains_destructive(
    monkeypatch, tmp_path: Path
) -> None:
    executable = _executable(tmp_path)
    baseline_plan = _scan_request(tmp_path / "baseline", executable)
    candidate_plan = _scan_request(tmp_path / "candidate", executable)
    for relative in ("a/main.tf", "b/main.tf"):
        path = baseline_plan.scan_root / relative
        path.parent.mkdir(exist_ok=True)
        path.write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    baseline_plan = attest_checkov_scan_plan(baseline_plan.request)
    (candidate_plan.scan_root / "main.tf").write_text(
        'resource "aws_x" "keep" {}\n', encoding="utf-8"
    )
    candidate_plan = attest_checkov_scan_plan(candidate_plan.request)
    baseline = scanner_run(
        baseline_plan,
        findings=(
            _resource_finding("CKV_X", "a/main.tf", "aws_x.r"),
            _resource_finding("CKV_Y", "b/main.tf", "aws_x.r"),
        ),
        evaluations=(
            _resource_evaluation("CKV_X", "a/main.tf", "aws_x.r"),
            _resource_evaluation("CKV_Y", "b/main.tf", "aws_x.r"),
        ),
    )
    candidate = scanner_run(
        candidate_plan,
        findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED, "aws_x.keep"),),
    )
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, request: (
            baseline if request.scan_root == baseline_plan.scan_root else candidate
        ),
    )
    gates = RequiredGates(("validator",))
    request = VerificationRequest(
        baseline_plan,
        candidate_plan,
        (Target(
            TargetIdentity("checkov", "CKV_X", "aws_x.r"),
            1,
            "a/main.tf",
            ArtifactKind.TERRAFORM_HCL,
            "aws_x.r",
        ),),
        _config(baseline_plan, candidate_plan, gates),
    )
    result = run_checkov_verification(request)
    destructive = next(
        item for item in result.engine_events
        if item.delta_class.value == "DESTRUCTIVE_CHANGE"
    )
    assert destructive.status is Status.FAIL
    assert {item.file_path for item in destructive.affected_resource_records} >= {
        "a/main.tf", "b/main.tf"
    }
    assert result.regression.status is Status.FAIL


def test_candidate_checkov_config_is_mechanically_policy_drift(
    monkeypatch, tmp_path: Path
) -> None:
    executable = _executable(tmp_path)
    baseline_plan = _scan_request(tmp_path / "baseline", executable)
    candidate_plan = _scan_request(tmp_path / "candidate", executable)
    (candidate_plan.scan_root / ".checkov.yml").write_text(
        "skip-check: CKV_X\n", encoding="utf-8"
    )
    baseline = scanner_run(
        baseline_plan,
        findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_plan,
        findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),),
    )
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, request: (
            baseline if request.scan_root == baseline_plan.scan_root else candidate
        ),
    )
    gates = RequiredGates(("validator",))
    request = VerificationRequest(
        baseline_plan,
        candidate_plan,
        (Target(IDENTITY, 1),),
        _config(baseline_plan, candidate_plan, gates),
    )
    result = run_checkov_verification(request)
    policy_drift = next(
        item for item in result.engine_events if item.delta_class.value == "POLICY_DRIFT"
    )
    assert policy_drift.status is Status.FAIL
    assert ".checkov.yml" in policy_drift.affected_paths


def test_trusted_high_floor_cannot_be_replaced_by_caller_critical(
    monkeypatch, tmp_path: Path
) -> None:
    executable = _executable(tmp_path)
    baseline_plan = _scan_request(tmp_path / "baseline", executable)
    candidate_plan = _scan_request(tmp_path / "candidate", executable)
    (candidate_plan.scan_root / "main.tf").write_text(
        'resource "aws_x" "r" {}\nresource "aws_x" "new" {}\n',
        encoding="utf-8",
    )
    candidate_plan = attest_checkov_scan_plan(candidate_plan.request)
    baseline = scanner_run(
        baseline_plan,
        findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate = scanner_run(
        candidate_plan,
        findings=(finding("aws_x.new", severity=Severity.HIGH),),
        evaluations=(
            evaluation(CheckEvaluationResult.PASSED),
            evaluation(CheckEvaluationResult.FAILED, "aws_x.new"),
        ),
    )
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, request: (
            baseline if request.scan_root == baseline_plan.scan_root else candidate
        ),
    )
    gates = RequiredGates(("validator",))
    config = _config(
        baseline_plan,
        candidate_plan,
        gates,
        severity_floor=Severity.HIGH,
    )
    with pytest.raises(TypeError):
        VerificationRequest(
            baseline_plan,
            candidate_plan,
            (Target(IDENTITY, 1),),
            config,
            severity_floor=Severity.CRITICAL,
        )
    result = run_checkov_verification(
        VerificationRequest(
            baseline_plan, candidate_plan, (Target(IDENTITY, 1),), config
        )
    )
    assert result.verification_config.severity_floor is Severity.HIGH
    assert result.regression.status is Status.FAIL


def test_config_bundle_cannot_be_restamped_by_dataclass_replacement(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    with pytest.raises(Exception, match="loader provenance"):
        replace(config, severity_floor=Severity.CRITICAL)


def test_protected_framework_set_overrides_narrow_caller_scan_universe(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path)
    baseline_plan = _scan_request(tmp_path / "baseline", executable)
    candidate_plan = _scan_request(tmp_path / "candidate", executable)
    (candidate_plan.scan_root / "pod.yaml").write_text(
        '"apiVersion": v1\n"kind": Pod\n"metadata": {"name": p}\n',
        encoding="utf-8",
    )
    gates = RequiredGates(("validator",))
    # The raw requests selected Terraform only. Protected configuration expands the
    # required universe and the factory must rediscover the Kubernetes input.
    from iac_guard_v.engine import load_operator_verification_config

    config = load_operator_verification_config(
        baseline_plan.request,
        candidate_plan.request,
        required_gates=gates,
        frameworks=("terraform", "kubernetes"),
        _test_executor=_gate,
    )
    request = VerificationRequest(
        baseline_plan, candidate_plan, (Target(IDENTITY, 1),), config
    )
    assert "pod.yaml" in request.candidate_scan.files_eligible
    assert any(
        item.resource_address == "v1/Pod/default/p"
        for item in request.candidate_scan.expected_resources
    )


def test_production_gate_registry_runs_only_built_in_validators(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "main.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    (root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n", encoding="utf-8"
    )
    registry = production_gate_registry()
    assert registry.execute("validator", "terraform_hcl_parse", root).status is Status.PASS
    assert registry.execute("validator", "kubernetes_yaml_parse", root).status is Status.PASS
    assert registry.execute("oracle", "oracle", root).status is Status.UNSUPPORTED
    assert registry.execute("validator", "fake", root).status is Status.UNSUPPORTED
    (root / "main.tf").write_text(
        'resource "aws_x" "r" { invalid = }\n', encoding="utf-8"
    )
    assert registry.execute("validator", "terraform_hcl_parse", root).status is Status.FAIL


@pytest.mark.parametrize(
    "changes",
    [
        {"validator_ids": []},
        {"validator_ids": ("x", "x")},
        {"_executor": None},
    ],
)
def test_gate_registry_mutation_guards(changes) -> None:
    values = {
        "identity": "registry",
        "validator_ids": ("validator",),
        "oracle_ids": (),
        "_executor": _gate,
        "_trusted_context": ENGINE._TRUSTED_GATE_REGISTRY_CONTEXT,
    }
    values.update(changes)
    with pytest.raises(Exception):
        TrustedGateRegistry(**values)


def test_provenance_and_governed_evidence_mutations(tmp_path: Path) -> None:
    digest = "a" * 64
    with pytest.raises(Exception, match="SHA-256"):
        GovernedConfigEvidence("config.json", "bad", digest, "changed")
    with pytest.raises(Exception, match="contradicts"):
        GovernedConfigEvidence("config.json", digest, digest, "changed")
    with pytest.raises(Exception, match="factory provenance"):
        TrustedGateRegistry("registry", (), (), _gate)
    assert ENGINE._production_gate_executor(
        "oracle", "oracle", tmp_path
    ).status is Status.UNSUPPORTED


def test_governed_config_evidence_records_all_path_states(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    (baseline.scan_root / ".checkov.yml").write_text("a: 1\n", encoding="utf-8")
    (candidate.scan_root / ".checkov.yml").write_text("a: 2\n", encoding="utf-8")
    (baseline.scan_root / "severity-policy.json").write_text("{}\n", encoding="utf-8")
    (candidate.scan_root / "gate-policy.json").write_text("{}\n", encoding="utf-8")
    (baseline.scan_root / ".iac-guard").mkdir()
    (candidate.scan_root / ".iac-guard").mkdir()
    (baseline.scan_root / ".iac-guard/shared.json").write_text("{}", encoding="utf-8")
    (candidate.scan_root / ".iac-guard/shared.json").write_text("{}", encoding="utf-8")
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    assert {item.state for item in config.governed_config} == {
        "added", "removed", "changed", "stable"
    }
    assert set(config.policy_drift_paths) == {
        ".checkov.yml", "gate-policy.json", "severity-policy.json"
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"baseline_root": "not-a-path"},
        {"scanner_executable": "not-a-path"},
        {"frameworks": []},
        {"frameworks": ("terraform", "terraform")},
        {"fail_on_location_change": 1},
        {"max_file_bytes": 0},
        {"governed_config": []},
    ],
)
def test_trusted_config_bundle_mutation_table(tmp_path: Path, changes) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    values = {
        name: getattr(config, name)
        for name, field in TrustedVerificationConfigBundle.__dataclass_fields__.items()
        if field.init and name != "_trusted_context"
    }
    values.update(changes)
    with pytest.raises(Exception):
        TrustedVerificationConfigBundle(
            **values, _trusted_context=ENGINE._TRUSTED_CONFIG_CONTEXT
        )
