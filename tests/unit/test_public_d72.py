"""D7.2 semantic report state-machine and candidate-validity regressions."""
from __future__ import annotations

import copy
import json

import pytest

import iac_guard_v.cli as CLI
from iac_guard_v.engine import VerificationResult
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import DomainError
from iac_guard_v.report import (
    CandidateArtifactFailureReportV1,
    ExecutionIsolationEvidence,
    VerificationReportV1,
    _validate_test_report_payload as validate_report_payload,
)

from test_policy import _verdict, verified_engine  # noqa: F401


def _verified(verified_engine: VerificationResult) -> dict:
    return VerificationReportV1(
        verified_engine, _verdict(verified_engine)
    ).canonical_dict()


def _forge(payload: dict, kind: str) -> dict:
    value = copy.deepcopy(payload)
    if kind == "scanner_integrity":
        value["verification"]["scanner_integrity"]["status"] = "FAIL"
    elif kind == "preflight":
        value["verification"]["preflight"]["status"] = "ERROR"
    elif kind == "validator":
        value["verification"]["validators"][0]["status"] = "FAIL"
    elif kind == "target":
        value["verification"]["targets"][0]["outcome"] = "STILL_PRESENT"
    elif kind == "decision":
        value["policy"]["decisions"][0]["outcome"] = "STILL_PRESENT"
    elif kind == "regression":
        value["verification"]["regression"]["status"] = "FAIL"
    else:  # pragma: no cover - test helper is closed by parametrization
        raise AssertionError(kind)
    return value


@pytest.mark.parametrize(
    "kind", ("scanner_integrity", "preflight", "validator", "target", "decision", "regression")
)
def test_forged_verified_reports_fail_runtime_and_explain(
    verified_engine: VerificationResult, tmp_path, capsys, kind: str
) -> None:
    forged = _forge(_verified(verified_engine), kind)
    with pytest.raises(DomainError, match="semantic"):
        validate_report_payload(forged)
    path = tmp_path / f"{kind}.json"
    path.write_text(json.dumps(forged), encoding="utf-8")
    assert CLI.main(["explain", str(path)]) == 2
    assert "INVALID_REQUEST" in capsys.readouterr().err


def test_full_and_artifact_failure_branches_cannot_be_crossed(
    verified_engine: VerificationResult,
) -> None:
    full = _verified(verified_engine)
    full["verdict"] = "FAILED"
    full["exit_code"] = 1
    artifact_policy = {
        "verdict": "FAILED", "exit_code": 1, "decisions": [],
        "policy_evidence": {
            "source_origin": "operator",
            "reason_code": "CANDIDATE_ARTIFACT_INVALID",
        },
    }
    full["policy"] = artifact_policy
    with pytest.raises(DomainError):
        validate_report_payload(full)

    artifact = CandidateArtifactFailureReportV1(
        ArtifactKind.TERRAFORM_HCL,
        "terraform_hcl_parse",
        "ARTIFACT_SYNTAX_INVALID",
        "invalid HCL",
        ExecutionIsolationEvidence.reduced_verified(),
    ).canonical_dict()
    artifact["policy"] = copy.deepcopy(_verified(verified_engine)["policy"])
    artifact["policy"]["verdict"] = "FAILED"
    artifact["policy"]["exit_code"] = 1
    artifact["verdict"] = "FAILED"
    artifact["exit_code"] = 1
    with pytest.raises(DomainError):
        validate_report_payload(artifact)


def test_candidate_artifact_failure_binds_kind_gate_and_reason() -> None:
    report = CandidateArtifactFailureReportV1(
        ArtifactKind.KUBERNETES_YAML,
        "kubernetes_yaml_parse",
        "ARTIFACT_SYNTAX_INVALID",
        "duplicate Kubernetes key",
        ExecutionIsolationEvidence.reduced_verified(),
    ).canonical_dict()
    failure = report["verification"]
    assert failure["artifact_kind"] == "kubernetes_yaml"
    assert failure["validator_gate_id"] == "kubernetes_yaml_parse"
    assert failure["failure_reason"] == "ARTIFACT_SYNTAX_INVALID"
    assert failure["validators"][0]["gate_id"] == "kubernetes_yaml_parse"


def test_explain_rejects_private_test_registry_evidence(
    verified_engine: VerificationResult, tmp_path, capsys
) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_verified(verified_engine)), encoding="utf-8")
    assert CLI.main(["explain", str(path)]) == 2
    assert "private test gate registry" in capsys.readouterr().err


def test_failed_and_inconclusive_full_reports_require_their_evidence(
    verified_engine: VerificationResult,
) -> None:
    failed = _verified(verified_engine)
    failed["verdict"] = failed["policy"]["verdict"] = "FAILED"
    failed["exit_code"] = failed["policy"]["exit_code"] = 1
    failed["verification"]["targets"][0]["outcome"] = "STILL_PRESENT"
    failed["policy"]["decisions"][0]["outcome"] = "STILL_PRESENT"
    failed["policy"]["decisions"][0]["policy_permitted"] = False
    validate_report_payload(failed)

    no_failure = copy.deepcopy(failed)
    no_failure["verification"]["targets"][0]["outcome"] = "FIXED"
    no_failure["policy"]["decisions"][0]["outcome"] = "FIXED"
    with pytest.raises(DomainError, match="decisive"):
        validate_report_payload(no_failure)

    inconclusive = _verified(verified_engine)
    inconclusive["verdict"] = inconclusive["policy"]["verdict"] = "INCONCLUSIVE"
    inconclusive["exit_code"] = inconclusive["policy"]["exit_code"] = 3
    inconclusive["verification"]["scanner_integrity"]["status"] = "ERROR"
    validate_report_payload(inconclusive)

    no_uncertainty = copy.deepcopy(inconclusive)
    no_uncertainty["verification"]["scanner_integrity"]["status"] = "PASS"
    with pytest.raises(DomainError, match="typed uncertainty"):
        validate_report_payload(no_uncertainty)


def test_semantic_validator_rejects_gate_substitution_and_target_disagreement(
    verified_engine: VerificationResult,
) -> None:
    payload = _verified(verified_engine)
    payload["verification"]["validators"][0]["gate_id"] = "substituted"
    with pytest.raises(DomainError, match="required validators"):
        validate_report_payload(payload)

    payload = _verified(verified_engine)
    payload["policy"]["decisions"][0]["resolved_target"] = None
    with pytest.raises(DomainError, match="resolved targets"):
        validate_report_payload(payload)

    payload = _verified(verified_engine)
    payload["verification"]["targets"][0]["outcome"] = "SUPPRESSED"
    with pytest.raises(DomainError, match="outcome disagrees"):
        validate_report_payload(payload)


def test_artifact_failure_semantics_reject_contradictions() -> None:
    report = CandidateArtifactFailureReportV1(
        ArtifactKind.TERRAFORM_HCL,
        "terraform_hcl_parse",
        "ARTIFACT_SYNTAX_INVALID",
        "invalid HCL",
        ExecutionIsolationEvidence.reduced_verified(),
    ).canonical_dict()
    for path, value in (
        (("verification", "preflight", "status"), "ERROR"),
        (("verification", "validators", 0, "status"), "PASS"),
        (("verification", "validators", 0, "gate_id"), "other"),
        (("verification", "validators", 0, "reason_code"), "OTHER"),
    ):
        forged = copy.deepcopy(report)
        target = forged
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        with pytest.raises(DomainError):
            validate_report_payload(forged)


@pytest.mark.parametrize("field,value", [
    ("artifact_kind", ArtifactKind.UNKNOWN),
    ("validator_gate_id", ""),
    ("reason_code", "bad\nreason"),
    ("detail", ""),
    ("execution_isolation", "reduced-isolation"),
])
def test_candidate_artifact_failure_constructor_is_closed(field, value) -> None:
    values = {
        "artifact_kind": ArtifactKind.TERRAFORM_HCL,
        "validator_gate_id": "terraform_hcl_parse",
        "reason_code": "ARTIFACT_SYNTAX_INVALID",
        "detail": "invalid HCL",
        "execution_isolation": ExecutionIsolationEvidence.reduced_verified(),
    }
    values[field] = value
    with pytest.raises(DomainError):
        CandidateArtifactFailureReportV1(**values)
