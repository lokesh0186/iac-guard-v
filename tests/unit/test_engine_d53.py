"""D5.3 role, registry, governed-path, and occurrence-token regressions."""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import iac_guard_v.engine as ENGINE
from iac_guard_v.adapters.checkov import CheckovAdapter, checkov_occurrence_token
from iac_guard_v.engine import (
    VerificationRequest,
    attest_checkov_scan_plan,
    load_operator_verification_config,
    run_checkov_verification,
)
from iac_guard_v.enums import (
    ArtifactKind, CheckEvaluationResult, ExecutionMode, Outcome, ScanRole, Status,
)
from iac_guard_v.models import CheckEvaluation, GateResult, RequiredGates, Target

from test_engine import IDENTITY, _config, _executable, _scan_request
from test_engine_d51 import finding, scanner_run


def test_swapped_baseline_candidate_roles_are_rejected(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    with pytest.raises(Exception, match="baseline role"):
        VerificationRequest(candidate, baseline, (Target(IDENTITY, 1),), config)


def test_same_root_is_not_a_differential_request(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    with pytest.raises(Exception, match="distinct"):
        load_operator_verification_config(
            baseline.request,
            baseline.request,
            required_gates=RequiredGates(("terraform_hcl_parse",)),
        )


def test_role_is_factory_bound_into_scan_plan(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    request = VerificationRequest(baseline, candidate, (Target(IDENTITY, 1),), config)
    assert request.baseline_scan.role is ScanRole.BASELINE
    assert request.candidate_scan.role is ScanRole.CANDIDATE
    assert request.baseline_scan.config_sha256 == config.config_sha256
    assert request.candidate_scan.config_sha256 == config.config_sha256
    assert len(request.baseline_scan.snapshot_sha256) == 64


def test_role_bound_plan_cannot_be_reused_on_other_side(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    bound = attest_checkov_scan_plan(
        candidate.request, config, ScanRole.CANDIDATE
    )
    with pytest.raises(Exception, match="baseline role"):
        VerificationRequest(bound, baseline, (Target(IDENTITY, 1),), config)


def test_production_config_loader_has_no_callback_capability(tmp_path: Path) -> None:
    assert "_test_executor" not in inspect.signature(
        load_operator_verification_config
    ).parameters
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    with pytest.raises(TypeError):
        load_operator_verification_config(
            baseline.request,
            candidate.request,
            required_gates=RequiredGates(("validator",)),
            _test_executor=lambda *_: None,
        )


def test_production_registry_binds_packaged_implementation_evidence() -> None:
    registry = ENGINE.production_gate_registry()
    assert registry.implementations
    assert {item.gate_id for item in registry.implementations} == {
        "terraform_hcl_parse", "kubernetes_yaml_parse"
    }
    assert all(len(item.code_sha256) == 64 for item in registry.implementations)
    assert all(item.canonical_dict()["version"] == "5" for item in registry.implementations)


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "fake"},
        {"code_sha256": "bad"},
        {"artifact_kinds": []},
        {"artifact_kinds": ("terraform_hcl",)},
    ],
)
def test_gate_implementation_mutation_guards(changes) -> None:
    values = dict(
        gate_id="validator", kind="validator", version="1",
        code_sha256="f" * 64, artifact_kinds=(ArtifactKind.TERRAFORM_HCL,),
    )
    values.update(changes)
    with pytest.raises(Exception):
        ENGINE.GateImplementation(**values)


def test_registry_rejects_implementation_inventory_mismatch() -> None:
    implementation = ENGINE.GateImplementation(
        "other", "validator", "1", "f" * 64, ()
    )
    with pytest.raises(Exception, match="disagrees"):
        ENGINE.TrustedGateRegistry(
            "registry", ("validator",), (), (implementation,),
            lambda *_: GateResult("validator", Status.PASS),
            _trusted_context=ENGINE._TRUSTED_GATE_REGISTRY_CONTEXT,
        )


@pytest.mark.parametrize(
    "values",
    [
        (ExecutionMode.EXPLICIT_OPERATOR, "repo", "a" * 40, "candidate", "context"),
        (ExecutionMode.PR_BASE, "", "a" * 40, "candidate", "context"),
        (ExecutionMode.PR_BASE, "repo", "", "candidate", "context"),
        (ExecutionMode.PR_BASE, "repo", "bad", "candidate", "context"),
    ],
)
def test_policy_source_authorization_mutation_guards(values) -> None:
    with pytest.raises(Exception):
        ENGINE.PolicySourceAuthorization(
            *values, _trusted_context=ENGINE._TRUSTED_POLICY_AUTHORIZATION_CONTEXT
        )
    with pytest.raises(Exception, match="protected provenance"):
        ENGINE.PolicySourceAuthorization(
            ExecutionMode.EXPLICIT_OPERATOR, "", "", "candidate", "context"
        )


def test_production_kubernetes_validator_covers_json(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    root = candidate.scan_root
    (root / "pod.json").write_text(
        '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"}}',
        encoding="utf-8",
    )
    config = _config(
        baseline, candidate, RequiredGates(("kubernetes_yaml_parse",)),
        executor=None, frameworks=("terraform", "kubernetes"),
    )
    request = VerificationRequest(
        baseline, candidate, (Target(IDENTITY, 1),), config
    )
    registry = ENGINE.production_gate_registry()
    result = registry.execute(
        "validator", "kubernetes_yaml_parse",
        request.candidate_scan.sealed_snapshot,
    )
    assert result.status is Status.PASS
    assert result.detail == "files=1"


def test_candidate_iac_guard_json_is_path_specific_policy_drift(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    (candidate.scan_root / ".iac-guard.json").write_text("{}\n", encoding="utf-8")
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    assert config.policy_drift_paths == (".iac-guard.json",)
    evidence = config.governed_config[0]
    assert evidence.state == "added"
    assert evidence.trusted_sha256 is None
    assert len(evidence.candidate_sha256) == 64


def test_failed_and_positive_evidence_share_occurrence_token_contract(
    monkeypatch, tmp_path: Path
) -> None:
    executable = _executable(tmp_path)
    baseline_plan = _scan_request(tmp_path / "baseline", executable)
    candidate_plan = _scan_request(tmp_path / "candidate", executable)
    tokens = tuple(
        checkov_occurrence_token(
            "3.3.0", ArtifactKind.TERRAFORM_HCL, "main.tf", "CKV_X",
            "aws_x.r", (key,),
        )
        for key in ("a", "b")
    )
    baseline = scanner_run(
        baseline_plan,
        findings=(finding("aws_x.r", line=1, native=tokens[0]),
                  finding("aws_x.r", line=2, native=tokens[1])),
        evaluations=(),
    )
    positive = tuple(
        CheckEvaluation(
            "checkov", "3.3.0", "CKV_X", "aws_x.r", "main.tf",
            CheckEvaluationResult.PASSED, (key,), "passed_checks", token,
        )
        for key, token in zip(("a", "b"), tokens)
    )
    candidate = scanner_run(candidate_plan, findings=(), evaluations=positive)
    monkeypatch.setattr(
        CheckovAdapter, "scan",
        lambda _self, request: (
            baseline if request.scan_root == baseline_plan.scan_root else candidate
        ),
    )
    request = VerificationRequest(
        baseline_plan, candidate_plan, (Target(IDENTITY, 2),),
        _config(baseline_plan, candidate_plan, RequiredGates(("validator",))),
    )
    result = run_checkov_verification(request)
    assert result.target_outcomes[0].outcome is Outcome.FIXED


@pytest.mark.parametrize(
    "changes",
    [
        {"role": "baseline"},
        {"snapshot_sha256": "0" * 64},
    ],
)
def test_scan_plan_role_snapshot_mutation_guards(tmp_path: Path, changes) -> None:
    executable = _executable(tmp_path)
    plan = _scan_request(tmp_path / "candidate", executable)
    values = dict(
        request=plan.request, files=plan.files, resources=plan.resources,
        inventory_sha256=plan.inventory_sha256,
        classifications=plan.classifications, role=plan.role,
        snapshot_sha256=plan.snapshot_sha256, config_sha256=plan.config_sha256,
        _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
    )
    values.update(changes)
    with pytest.raises(Exception):
        ENGINE.TrustedScanPlan(**values)


def test_role_plan_from_different_config_is_rejected(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    config = _config(baseline, candidate, RequiredGates(("validator",)))
    values = dict(
        request=baseline.request, files=baseline.files, resources=baseline.resources,
        inventory_sha256=baseline.inventory_sha256,
        classifications=baseline.classifications,
        inspected_files=baseline.inspected_files,
        governed_paths=baseline.governed_paths,
        role=ScanRole.BASELINE,
        source_state_sha256=config.baseline_source_snapshot_sha256,
        config_sha256="0" * 64,
        _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
    )
    forged = ENGINE.TrustedScanPlan(**values)
    with pytest.raises(Exception, match="different trusted config"):
        VerificationRequest(forged, candidate, (Target(IDENTITY, 1),), config)
