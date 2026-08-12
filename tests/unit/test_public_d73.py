"""D7.3 complete canonical report-graph validation regressions."""
from __future__ import annotations

import copy
import json

import pytest

import iac_guard_v.cli as CLI
from iac_guard_v.engine import VerificationResult
from iac_guard_v.models import DomainError
from iac_guard_v.report import VerificationReportV1, validate_report_payload

from test_policy import _verdict, verified_engine  # noqa: F401


SHA_A = "a" * 64
SHA_B = "b" * 64
ENGINE_CLASSES = {
    "RULE_SUBSTITUTED", "COVERAGE_DECREASED", "DIAGNOSTIC_ADDED",
    "DESTRUCTIVE_CHANGE", "POLICY_DRIFT",
}


def _report(engine: VerificationResult) -> dict:
    return VerificationReportV1(engine, _verdict(engine)).canonical_dict()


def _duplicate_target(payload: dict) -> None:
    bad = copy.deepcopy(payload["verification"]["targets"][0])
    bad["outcome"] = "STILL_PRESENT"
    payload["verification"]["targets"].insert(0, bad)


def _duplicate_decision(payload: dict) -> None:
    bad = copy.deepcopy(payload["policy"]["decisions"][0])
    bad["outcome"] = "STILL_PRESENT"
    bad["policy_permitted"] = True
    bad["exception_id"] = "forged"
    payload["policy"]["decisions"].insert(0, bad)


def _duplicate_required_and_observed_validator(payload: dict) -> None:
    payload["verification"]["verification_config"]["required_gates"]["validator_ids"] *= 2
    payload["verification"]["validators"] *= 2


def _duplicate_gate_implementation(payload: dict) -> None:
    payload["verification"]["gate_implementations"].append(
        copy.deepcopy(payload["verification"]["gate_implementations"][0])
    )


def _duplicate_configured_gate_implementation(payload: dict) -> None:
    item = copy.deepcopy(payload["verification"]["gate_implementations"][0])
    payload["verification"]["gate_implementations"].append(copy.deepcopy(item))
    payload["verification"]["verification_config"]["gate_implementations"].append(item)


def _duplicate_required_and_observed_oracle(payload: dict) -> None:
    payload["verification"]["verification_config"]["required_gates"]["oracle_ids"] *= 2
    payload["verification"]["oracles"] *= 2


def _no_engine_events(payload: dict) -> None:
    payload["verification"]["engine_events"] = []


def _one_engine_event_five_times(payload: dict) -> None:
    event = copy.deepcopy(payload["verification"]["engine_events"][0])
    payload["verification"]["engine_events"] = [copy.deepcopy(event) for _ in range(5)]


def _target_identity_disagrees(payload: dict) -> None:
    payload["verification"]["targets"][0]["identity"]["scope"] = "different.r"


def _decision_identity_disagrees(payload: dict) -> None:
    payload["policy"]["decisions"][0]["identity"]["scope"] = "different.r"


def _config_candidate_snapshot_changed(payload: dict) -> None:
    payload["verification"]["verification_config"]["role_snapshots"]["candidate"] = SHA_B


def _top_gate_digest_changed(payload: dict) -> None:
    payload["verification"]["gate_implementations"][0]["code_sha256"] = SHA_B


def _registry_changed(payload: dict) -> None:
    payload["verification"]["verification_config"]["gate_registry_identity"] = "other_registry"


def _candidate_role_changed(payload: dict) -> None:
    payload["verification"]["candidate_snapshot"]["role"] = "baseline"


def _candidate_snapshot_config_changed(payload: dict) -> None:
    payload["verification"]["candidate_snapshot"]["config_sha256"] = SHA_B


def _candidate_snapshot_subpath_changed(payload: dict) -> None:
    payload["verification"]["candidate_snapshot"]["repository_relative_subpath"] = "other"


def _candidate_snapshot_identity_changed(payload: dict) -> None:
    payload["verification"]["candidate_snapshot"]["snapshot_sha256"] = SHA_B


def _candidate_input_hash_changed(payload: dict) -> None:
    payload["verification"]["candidate_run"]["input_files"][0]["sha256"] = SHA_B


def _candidate_inputs_removed(payload: dict) -> None:
    payload["verification"]["candidate_run"]["input_files"] = []


def _candidate_snapshot_files_removed(payload: dict) -> None:
    payload["verification"]["candidate_snapshot"]["files"] = []


def _candidate_evaluations_removed(payload: dict) -> None:
    payload["verification"]["candidate_run"]["evaluations"] = []
    payload["verification"]["candidate_run"]["coverage"]["evaluations_reported"] = 0


def _candidate_coverage_zero(payload: dict) -> None:
    coverage = payload["verification"]["candidate_run"]["coverage"]
    for key in ("files_eligible", "files_discovered", "files_parsed", "evaluations_reported"):
        coverage[key] = 0


def _scanner_bad_exit(payload: dict) -> None:
    payload["verification"]["candidate_run"]["exit_code"] = 99


def _scanner_bad_file_counts(payload: dict) -> None:
    payload["verification"]["candidate_run"]["coverage"]["files_parsed"] = 99


def _scanner_bad_digest(payload: dict) -> None:
    payload["verification"]["candidate_run"]["launcher_digest"] = "not-a-sha"


def _scanner_domain_changed(payload: dict) -> None:
    payload["verification"]["baseline_run"]["scanner"] = "trivy"


def _scanner_resource_counts_changed(payload: dict) -> None:
    payload["verification"]["candidate_run"]["resource_coverage"]["resources_expected"] = 2


def _finding_domain_changed(payload: dict) -> None:
    payload["verification"]["baseline_run"]["findings"][0]["scanner_version"] = "other"


def _evaluation_domain_changed(payload: dict) -> None:
    payload["verification"]["candidate_run"]["evaluations"][0]["scanner_version"] = "other"


def _evaluation_bucket_changed(payload: dict) -> None:
    payload["verification"]["candidate_run"]["evaluations"][0]["source_bucket"] = "failed_checks"


def _target_counts_changed(payload: dict) -> None:
    payload["verification"]["targets"][0]["counts"]["candidate"] = 1


def _derived_target_identity_changed(payload: dict) -> None:
    payload["verification"]["targets"][0]["identity"]["opaque_id"] = "tid1:" + SHA_B


def _fixed_fabricated_exception(payload: dict) -> None:
    decision = payload["policy"]["decisions"][0]
    decision["policy_permitted"] = True
    decision["exception_id"] = "forged"


def _fixed_fabricated_rejection(payload: dict) -> None:
    payload["policy"]["decisions"][0]["rejection_reason"] = "fabricated"


def _hardened_without_isolation(payload: dict) -> None:
    isolation = payload["execution_isolation"]
    isolation["mode"] = "hardened-container"
    isolation["hostile_input_support"] = True
    isolation["network_isolation_state"] = "UNSUPPORTED"
    isolation["filesystem_isolation_state"] = "UNSUPPORTED"


def _duplicate_finding(payload: dict) -> None:
    payload["verification"]["baseline_run"]["findings"] *= 2


def _duplicate_evaluation(payload: dict) -> None:
    payload["verification"]["candidate_run"]["evaluations"] *= 2
    payload["verification"]["candidate_run"]["coverage"]["evaluations_reported"] = 2


def _duplicate_snapshot_file(payload: dict) -> None:
    payload["verification"]["candidate_snapshot"]["files"] *= 2


def _duplicate_input_file(payload: dict) -> None:
    payload["verification"]["candidate_run"]["input_files"] *= 2


def _snapshot_manifest_changed(payload: dict) -> None:
    payload["verification"]["candidate_snapshot"]["artifact_manifest_sha256"] = SHA_B


def _snapshot_inventory_changed(payload: dict) -> None:
    payload["verification"]["candidate_snapshot"]["resource_inventory_sha256"] = SHA_B


MUTATIONS = (
    _duplicate_target,
    _duplicate_decision,
    _duplicate_required_and_observed_validator,
    _duplicate_gate_implementation,
    _duplicate_configured_gate_implementation,
    _duplicate_required_and_observed_oracle,
    _no_engine_events,
    _one_engine_event_five_times,
    _target_identity_disagrees,
    _decision_identity_disagrees,
    _config_candidate_snapshot_changed,
    _top_gate_digest_changed,
    _registry_changed,
    _candidate_role_changed,
    _candidate_snapshot_config_changed,
    _candidate_snapshot_subpath_changed,
    _candidate_snapshot_identity_changed,
    _candidate_input_hash_changed,
    _candidate_inputs_removed,
    _candidate_snapshot_files_removed,
    _candidate_evaluations_removed,
    _candidate_coverage_zero,
    _scanner_bad_exit,
    _scanner_bad_file_counts,
    _scanner_bad_digest,
    _scanner_domain_changed,
    _scanner_resource_counts_changed,
    _finding_domain_changed,
    _evaluation_domain_changed,
    _evaluation_bucket_changed,
    _target_counts_changed,
    _derived_target_identity_changed,
    _fixed_fabricated_exception,
    _fixed_fabricated_rejection,
    _hardened_without_isolation,
    _duplicate_finding,
    _duplicate_evaluation,
    _duplicate_snapshot_file,
    _duplicate_input_file,
    _snapshot_manifest_changed,
    _snapshot_inventory_changed,
)


@pytest.mark.parametrize("mutation", MUTATIONS, ids=lambda item: item.__name__)
def test_verified_report_graph_mutations_are_rejected(
    verified_engine: VerificationResult, mutation,
) -> None:
    payload = copy.deepcopy(_report(verified_engine))
    mutation(payload)
    with pytest.raises(DomainError, match="semantic"):
        validate_report_payload(payload)


def test_duplicate_target_cannot_fool_explain(
    verified_engine: VerificationResult, tmp_path, capsys,
) -> None:
    payload = copy.deepcopy(_report(verified_engine))
    _duplicate_target(payload)
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert CLI.main(["explain", str(path)]) == 2
    assert "INVALID_REQUEST" in capsys.readouterr().err


def test_canonical_verified_report_contains_exact_engine_event_vocabulary(
    verified_engine: VerificationResult,
) -> None:
    events = _report(verified_engine)["verification"]["engine_events"]
    assert {item["delta_class"] for item in events} == ENGINE_CLASSES
    assert len(events) == len(ENGINE_CLASSES)


@pytest.mark.parametrize("verdict", ("FAILED", "INCONCLUSIVE"))
def test_graph_guards_apply_before_failed_or_inconclusive_verdict_logic(
    verified_engine: VerificationResult, verdict: str,
) -> None:
    payload = copy.deepcopy(_report(verified_engine))
    payload["verdict"] = payload["policy"]["verdict"] = verdict
    payload["exit_code"] = payload["policy"]["exit_code"] = (
        1 if verdict == "FAILED" else 3
    )
    if verdict == "FAILED":
        payload["verification"]["targets"][0]["outcome"] = "STILL_PRESENT"
        payload["policy"]["decisions"][0]["outcome"] = "STILL_PRESENT"
        payload["policy"]["decisions"][0]["rejection_reason"] = "not permitted"
    else:
        payload["verification"]["scanner_integrity"]["status"] = "INCONCLUSIVE"
    payload["verification"]["candidate_run"]["input_files"] *= 2
    with pytest.raises(DomainError, match="duplicate authoritative"):
        validate_report_payload(payload)
