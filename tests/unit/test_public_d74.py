"""D7.4 protected-config and complete evidence-graph regressions."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

import iac_guard_v.cli as CLI
import iac_guard_v.report as REPORT
from iac_guard_v.diffing import diff_findings
from iac_guard_v.engine import VerificationResult
from iac_guard_v.enums import Outcome
from iac_guard_v.models import DomainError
from iac_guard_v.report import VerificationReportV1, validate_report_payload

from test_policy import _outcome, _record, _verdict, verified_engine  # noqa: F401


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


def _rehash_config(payload: dict) -> None:
    config = payload["verification"]["verification_config"]
    identity = {name: value for name, value in config.items() if name != "config_sha256"}
    config["config_sha256"] = _digest(identity)
    for role in ("baseline", "candidate"):
        payload["verification"][f"{role}_snapshot"]["config_sha256"] = config["config_sha256"]
    payload["policy"]["policy_evidence"]["verification_config_sha256"] = config["config_sha256"]
    for event in payload["verification"]["engine_events"]:
        if event["delta_class"] == "POLICY_DRIFT":
            event["detail"] = f"config={config['config_sha256']}"


def _publicize(payload: dict) -> dict:
    """Convert private synthetic gate provenance to a public-registry graph."""
    config = payload["verification"]["verification_config"]
    config["gate_registry_identity"] = "iac_guard_v_phase_d_registry_v4"
    _rehash_config(payload)
    validate_report_payload(payload)
    return payload


def _payload(engine: VerificationResult) -> dict:
    return _publicize(
        VerificationReportV1(engine, _verdict(engine)).canonical_dict()
    )


@pytest.mark.parametrize(
    "field,value",
    (
        ("severity_floor", "CRITICAL"),
        ("frameworks", ["kubernetes"]),
        ("source_identity", "forged_source"),
        ("source_provenance", "forged_provenance"),
    ),
)
def test_protected_config_children_are_rehashed(
    verified_engine: VerificationResult, field: str, value,
) -> None:
    payload = _payload(verified_engine)
    payload["verification"]["verification_config"][field] = value
    with pytest.raises(DomainError, match="configuration identity"):
        validate_report_payload(payload)


def test_policy_source_authorization_is_rehashed(verified_engine: VerificationResult) -> None:
    payload = _payload(verified_engine)
    authorization = payload["verification"]["verification_config"][
        "policy_source_authorization"
    ]
    authorization["candidate_identity"] = "forged_candidate"
    with pytest.raises(DomainError, match="configuration identity"):
        validate_report_payload(payload)


def _new_critical(payload: dict) -> None:
    finding = copy.deepcopy(payload["verification"]["baseline_run"]["findings"][0])
    finding.update({
        "rule_id": "CKV_NEW_CRITICAL",
        "rule_name": "new critical",
        "severity": "CRITICAL",
        "native_fingerprint": "new-native-token",
        "iacgv_fingerprint": "",
    })
    payload["verification"]["candidate_run"]["findings"].append(finding)


def test_new_critical_finding_cannot_coexist_with_pass_regression(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    _new_critical(payload)
    with pytest.raises(DomainError, match="finding diff"):
        validate_report_payload(payload)


def test_new_delta_must_exist_in_candidate_findings(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    delta = payload["verification"]["finding_diff"]["deltas"][0]
    delta["delta_class"] = "NEW_FINDING"
    delta["candidate"] = delta["baseline"]
    delta["baseline"] = None
    with pytest.raises(DomainError, match="finding diff"):
        validate_report_payload(payload)


def test_candidate_finding_must_exist_in_finding_diff(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    _new_critical(payload)
    payload["verification"]["regression"] = {
        "gate_id": "regression", "status": "PASS",
        "reason_code": "NO_DECISIVE_REGRESSION", "detail": "",
    }
    with pytest.raises(DomainError, match="finding diff"):
        validate_report_payload(payload)


def test_pass_engine_event_cannot_carry_affected_evidence(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    destructive = next(
        item for item in payload["verification"]["engine_events"]
        if item["delta_class"] == "DESTRUCTIVE_CHANGE"
    )
    destructive["affected_paths"] = ["deleted/main.tf"]
    with pytest.raises(DomainError, match="DESTRUCTIVE_CHANGE"):
        validate_report_payload(payload)


def test_governed_policy_evidence_must_match_protected_config(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    payload["policy"]["policy_evidence"]["differing_governed_paths"] = [
        ".iac-guard.json"
    ]
    with pytest.raises(DomainError, match="governed paths"):
        validate_report_payload(payload)


def test_pass_scanner_cannot_carry_scanner_error_diagnostic(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    payload["verification"]["candidate_run"]["diagnostics"] = ["SCANNER_ERROR"]
    with pytest.raises(DomainError, match="adverse diagnostics"):
        validate_report_payload(payload)


def test_permitted_decision_requires_exact_applied_exception_source(
    verified_engine: VerificationResult,
) -> None:
    suppressed = _outcome(verified_engine, Outcome.SUPPRESSED)
    policy = _verdict(
        suppressed, exceptions=(_record(Outcome.SUPPRESSED),)
    )
    payload = _publicize(VerificationReportV1(suppressed, policy).canonical_dict())
    payload["policy"]["policy_evidence"]["applied_exception_sources"] = []
    with pytest.raises(DomainError, match="applied exception sources"):
        validate_report_payload(payload)


def test_repository_identity_is_bound_to_config_and_authorization(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    payload["verification"]["candidate_snapshot"]["repository_identity"] = "other_repo"
    with pytest.raises(DomainError, match="repository identity"):
        validate_report_payload(payload)


def test_resource_change_metrics_are_derived_from_snapshots(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    payload["verification"]["change_metrics"]["resources_deleted"] = 99
    with pytest.raises(DomainError, match="change metrics"):
        validate_report_payload(payload)


def test_private_test_registry_is_rejected_by_public_validator_and_explain(
    verified_engine: VerificationResult, tmp_path, capsys,
) -> None:
    payload = VerificationReportV1(verified_engine, _verdict(verified_engine)).canonical_dict()
    with pytest.raises(DomainError, match="private test gate registry"):
        validate_report_payload(payload)
    path = tmp_path / "private-report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert CLI.main(["explain", str(path)]) == 2
    assert "INVALID_REQUEST" in capsys.readouterr().err


def test_new_critical_finding_causes_explain_to_reject(
    verified_engine: VerificationResult, tmp_path, capsys,
) -> None:
    payload = _payload(verified_engine)
    _new_critical(payload)
    path = tmp_path / "forged-critical.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert CLI.main(["explain", str(path)]) == 2
    assert "INVALID_REQUEST" in capsys.readouterr().err


def test_explain_accepts_complete_public_registry_graph(
    verified_engine: VerificationResult, tmp_path, capsys,
) -> None:
    path = tmp_path / "public-report.json"
    path.write_text(json.dumps(_payload(verified_engine)), encoding="utf-8")
    assert CLI.main(["explain", str(path)]) == 0
    assert "VERIFIED" in capsys.readouterr().out


def _role_repository_mismatch(payload: dict) -> None:
    payload["verification"]["verification_config"]["role_repository_identities"] = {
        "baseline": "other_repo", "candidate": "other_repo",
    }
    _rehash_config(payload)


def _gate_overlap(payload: dict) -> None:
    required = payload["verification"]["verification_config"]["required_gates"]
    required["oracle_ids"] = [required["validator_ids"][0]]
    _rehash_config(payload)


def _gate_coverage_missing(payload: dict) -> None:
    payload["verification"]["verification_config"]["required_gates"]["oracle_ids"] = []
    payload["verification"]["oracles"] = []
    _rehash_config(payload)


def _gate_kind_wrong(payload: dict) -> None:
    config = payload["verification"]["verification_config"]
    config["gate_implementations"][0]["kind"] = "oracle"
    payload["verification"]["gate_implementations"] = copy.deepcopy(
        config["gate_implementations"]
    )
    _rehash_config(payload)


def _gate_registry_unknown(payload: dict) -> None:
    payload["verification"]["verification_config"]["gate_registry_identity"] = "unknown"
    _rehash_config(payload)


def _pass_ruleset_fail(payload: dict) -> None:
    payload["verification"]["candidate_run"]["ruleset_integrity"] = "FAIL"


def _failure_without_reason(payload: dict) -> None:
    run = payload["verification"]["candidate_run"]
    run["status"] = "ERROR"
    run["diagnostics"] = []


def _version_reason_wrong_ruleset(payload: dict) -> None:
    run = payload["verification"]["candidate_run"]
    run["status"] = "ERROR"
    run["diagnostics"] = ["VERSION_MISMATCH"]


def _parsed_failed_exceed_discovered(payload: dict) -> None:
    payload["verification"]["candidate_run"]["coverage"]["files_failed"] = 1


def _parse_errors_exceed_failed(payload: dict) -> None:
    payload["verification"]["candidate_run"]["coverage"]["parse_errors"] = 1


def _evaluation_count_mismatch(payload: dict) -> None:
    payload["verification"]["candidate_run"]["coverage"]["evaluations_reported"] = 2


def _resource_counter_inconsistent(payload: dict) -> None:
    payload["verification"]["candidate_run"]["resource_coverage"][
        "expected_resources_missing"
    ] = 1


def _eligible_count_disagrees(payload: dict) -> None:
    coverage = payload["verification"]["candidate_run"]["coverage"]
    coverage["files_eligible"] = coverage["files_discovered"] = 2


def _finding_unbound(payload: dict) -> None:
    payload["verification"]["baseline_run"]["findings"][0]["location"][
        "file_path"
    ] = "other.tf"


def _evaluation_unbound(payload: dict) -> None:
    payload["verification"]["candidate_run"]["evaluations"][0]["file_path"] = "other.tf"


def _failure_counter_on_pass(payload: dict) -> None:
    coverage = payload["verification"]["candidate_run"]["coverage"]
    coverage["checks_failed_to_execute"] = 1


def _scanner_execution_drift(payload: dict) -> None:
    payload["verification"]["candidate_run"]["installed_distribution_digest"] = "b" * 64


def _policy_config_mismatch(payload: dict) -> None:
    payload["policy"]["policy_evidence"]["verification_config_sha256"] = "b" * 64


def _policy_snapshot_mismatch(payload: dict) -> None:
    payload["policy"]["policy_evidence"]["candidate_snapshot_sha256"] = "b" * 64


def _policy_date_mismatch(payload: dict) -> None:
    payload["policy"]["policy_evidence"]["evaluation_date"] = "2026-08-11"


def _policy_context_mismatch(payload: dict) -> None:
    payload["policy"]["policy_evidence"]["execution_context_identity"] = "other"


def _reduced_hostile(payload: dict) -> None:
    payload["execution_isolation"]["hostile_input_support"] = True


def _line_metric_mismatch(payload: dict) -> None:
    payload["verification"]["change_metrics"]["lines_changed"] = 1


def _policy_metric_mismatch(payload: dict) -> None:
    payload["verification"]["change_metrics"]["policy_files_changed"] = 1


GRAPH_EDGE_MUTATIONS = (
    _role_repository_mismatch, _gate_overlap, _gate_coverage_missing,
    _gate_kind_wrong, _gate_registry_unknown, _pass_ruleset_fail,
    _failure_without_reason, _version_reason_wrong_ruleset,
    _parsed_failed_exceed_discovered, _parse_errors_exceed_failed,
    _evaluation_count_mismatch, _resource_counter_inconsistent,
    _eligible_count_disagrees, _finding_unbound, _evaluation_unbound,
    _failure_counter_on_pass, _scanner_execution_drift, _policy_config_mismatch,
    _policy_snapshot_mismatch, _policy_date_mismatch, _policy_context_mismatch,
    _reduced_hostile, _line_metric_mismatch, _policy_metric_mismatch,
)


@pytest.mark.parametrize("mutation", GRAPH_EDGE_MUTATIONS, ids=lambda item: item.__name__)
def test_mutated_authoritative_graph_edges_are_rejected(
    verified_engine: VerificationResult, mutation,
) -> None:
    payload = _payload(verified_engine)
    mutation(payload)
    with pytest.raises(DomainError):
        validate_report_payload(payload)


@pytest.mark.parametrize("severity,status,reason", (
    ("CRITICAL", "FAIL", "REGRESSION_DETECTED"),
    ("UNKNOWN", "INCONCLUSIVE", "NEW_FINDING_SEVERITY_UNKNOWN"),
    ("LOW", "PASS", "NO_DECISIVE_REGRESSION"),
))
def test_new_finding_regression_is_rederived_for_all_severity_states(
    verified_engine: VerificationResult, severity: str, status: str, reason: str,
) -> None:
    payload = _payload(verified_engine)
    _new_critical(payload)
    payload["verification"]["candidate_run"]["findings"][-1]["severity"] = severity
    before = tuple(
        REPORT._rebuild_finding(item)
        for item in payload["verification"]["baseline_run"]["findings"]
    )
    after = tuple(
        REPORT._rebuild_finding(item)
        for item in payload["verification"]["candidate_run"]["findings"]
    )
    payload["verification"]["finding_diff"] = diff_findings(before, after).canonical_dict()
    detail = (
        "NEW_FINDING" if status == "FAIL"
        else "NEW_FINDING_SEVERITY_UNKNOWN" if status == "INCONCLUSIVE" else ""
    )
    payload["verification"]["regression"] = {
        "gate_id": "regression", "status": status,
        "reason_code": reason, "detail": detail,
    }
    if status == "PASS":
        validate_report_payload(payload)
    else:
        with pytest.raises(DomainError, match="VERIFIED requires"):
            validate_report_payload(payload)


@pytest.mark.parametrize(
    "before,after,state",
    (
        ([], [{"file_path": ".iac-guard.json", "kind": "REGULAR_FILE", "sha256": "a" * 64, "size": 1}], "added"),
        ([{"file_path": ".iac-guard.json", "kind": "REGULAR_FILE", "sha256": "a" * 64, "size": 1}], [], "removed"),
        ([{"file_path": ".iac-guard.json", "kind": "REGULAR_FILE", "sha256": "a" * 64, "size": 1}], [{"file_path": ".iac-guard.json", "kind": "REAL_DIRECTORY", "sha256": "b" * 64, "size": 2}], "type_changed"),
        ([{"file_path": ".iac-guard.json", "kind": "REGULAR_FILE", "sha256": "a" * 64, "size": 1}], [{"file_path": ".iac-guard.json", "kind": "REGULAR_FILE", "sha256": "a" * 64, "size": 1}], "stable"),
        ([{"file_path": ".iac-guard.json", "kind": "SYMLINK", "sha256": "a" * 64, "size": 1}], [{"file_path": ".iac-guard.json", "kind": "SYMLINK", "sha256": "a" * 64, "size": 1}], "changed"),
    ),
)
def test_governed_comparison_states_are_closed(before, after, state: str) -> None:
    result = REPORT._governed_comparison(
        {"governed_paths": before}, {"governed_paths": after}
    )
    assert result[0]["state"] == state


def test_fixed_target_requires_actual_positive_evaluation(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    evaluation = payload["verification"]["candidate_run"]["evaluations"][0]
    evaluation["native_result"] = "FAILED"
    evaluation["source_bucket"] = "failed_checks"
    with pytest.raises(DomainError, match="affirmative exact-domain"):
        validate_report_payload(payload)


def test_unavailable_metric_names_are_unique(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    payload["verification"]["change_metrics"]["unavailable_metrics"] = [
        "diff_ratio", "diff_ratio",
    ]
    with pytest.raises(DomainError, match="unavailable change metrics"):
        validate_report_payload(payload)
