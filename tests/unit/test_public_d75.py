"""D7.5 complete target, snapshot, artifact, and environment derivation guards."""
from __future__ import annotations

import copy

import pytest

import iac_guard_v.report as REPORT
from iac_guard_v.engine import VerificationResult
from iac_guard_v.enums import Outcome
from iac_guard_v.models import DomainError
from iac_guard_v.report import VerificationReportV1, validate_report_payload

from test_policy import _outcome, _record, _verdict, verified_engine  # noqa: F401
from test_public_d74 import _digest, _payload, _publicize, _rehash_config


@pytest.mark.parametrize(
    "outcome",
    [item for item in Outcome if item is not Outcome.FIXED],
)
def test_every_nonfixed_outcome_is_rederived_from_evidence(
    verified_engine: VerificationResult, outcome: Outcome,
) -> None:
    payload = _payload(verified_engine)
    payload["verification"]["targets"][0]["outcome"] = outcome.value
    payload["verification"]["targets"][0]["target_reason"] = "TARGET_NOT_EVALUATED"
    payload["policy"]["decisions"][0]["outcome"] = outcome.value
    with pytest.raises(DomainError, match="target outcome"):
        validate_report_payload(payload)


@pytest.mark.parametrize(
    "outcome",
    [
        Outcome.SUPPRESSED,
        Outcome.RESOURCE_DELETED,
        Outcome.FILE_DELETED_OR_RENAMED,
    ],
)
def test_exception_cannot_manufacture_an_unproven_event(
    verified_engine: VerificationResult, outcome: Outcome,
) -> None:
    forged = _outcome(verified_engine, outcome)
    payload = VerificationReportV1(
        forged, _verdict(forged, exceptions=(_record(outcome),))
    ).canonical_dict()
    with pytest.raises(DomainError, match="target outcome"):
        _publicize(payload)


def test_identical_snapshots_cannot_claim_opposite_scanner_evidence(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    verification = payload["verification"]
    baseline = verification["baseline_snapshot"]
    candidate = copy.deepcopy(baseline)
    candidate["role"] = "candidate"
    verification["candidate_snapshot"] = candidate
    verification["candidate_run"]["input_files"] = copy.deepcopy(candidate["files"])
    config = verification["verification_config"]
    config["role_snapshots"]["candidate"] = candidate["snapshot_sha256"]
    payload["policy"]["policy_evidence"]["candidate_snapshot_sha256"] = candidate[
        "snapshot_sha256"
    ]
    _rehash_config(payload)
    with pytest.raises(DomainError, match="distinct role snapshots"):
        validate_report_payload(payload)


def test_supported_fifo_cannot_disappear_from_artifact_classification(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    verification = payload["verification"]
    snapshot = verification["candidate_snapshot"]
    snapshot["filesystem_entries"].append({
        "file_path": "evil.tf", "kind": "FIFO", "size": 0, "sha256": None,
        "symlink_target_kind": None, "symlink_target_sha256": None,
        "supported": True, "governed": False,
        "rejection_reason": "UNSUPPORTED_ARTIFACT_PATH_TYPE",
    })
    snapshot["filesystem_entries"].sort(key=lambda item: item["file_path"])
    snapshot["snapshot_sha256"] = _digest(snapshot["filesystem_entries"])
    snapshot["artifact_manifest_sha256"] = _digest({
        "root_files": snapshot["classifications"],
        "eligible_files": snapshot["files"],
        "filesystem_entries": snapshot["filesystem_entries"],
    })
    verification["verification_config"]["role_snapshots"]["candidate"] = snapshot[
        "snapshot_sha256"
    ]
    payload["policy"]["policy_evidence"]["candidate_snapshot_sha256"] = snapshot[
        "snapshot_sha256"
    ]
    _rehash_config(payload)
    with pytest.raises(DomainError, match="lacks artifact classification"):
        validate_report_payload(payload)


def test_changing_only_private_registry_name_does_not_publicize_test_evidence(
    verified_engine: VerificationResult,
) -> None:
    payload = VerificationReportV1(
        verified_engine, _verdict(verified_engine)
    ).canonical_dict()
    payload["verification"]["verification_config"][
        "gate_registry_identity"
    ] = "iac_guard_v_phase_d_registry_v4"
    _rehash_config(payload)
    with pytest.raises(DomainError, match="private test"):
        validate_report_payload(payload)


def test_environment_children_cannot_change_under_unchanged_digest(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    for role in ("baseline", "candidate"):
        run = payload["verification"][f"{role}_run"]
        run["environment_components"]["installed_distribution_digest"] = "b" * 64
        run["installed_distribution_digest"] = "b" * 64
    with pytest.raises(DomainError, match="not derived from its components"):
        validate_report_payload(payload)


def test_environment_manifest_hashes_all_required_components(
    verified_engine: VerificationResult,
) -> None:
    payload = _payload(verified_engine)
    components = payload["verification"]["candidate_run"]["environment_components"]
    assert set(components) == {
        "contract", "non_policy_package_digest", "installed_distribution_digest",
        "dependency_closure_digest", "custom_check_digest",
        "policy_inventory_digest", "runtime_interpreter_digest",
    }
    assert payload["verification"]["candidate_run"][
        "scanner_environment_digest"
    ] == _digest(components)


def test_all_target_derivation_paths_are_evidence_driven(
    verified_engine: VerificationResult,
) -> None:
    original = _payload(verified_engine)["verification"]

    def derive(mutate) -> str:
        verification = copy.deepcopy(original)
        mutate(verification)
        return REPORT._derive_target_outcome(
            verification, verification["targets"][0]
        )[0]

    assert derive(lambda value: value["baseline_run"].update(findings=[])) == "INCONCLUSIVE"
    assert derive(lambda value: value["candidate_run"].update(status="ERROR")) == "SCANNER_ERROR"
    assert derive(
        lambda value: value["candidate_run"].update(ruleset_integrity="INCONCLUSIVE")
    ) == "INCONCLUSIVE"
    assert derive(
        lambda value: value["candidate_run"].update(launcher_digest="b" * 64)
    ) == "RULE_OR_SCANNER_DRIFT"
    assert derive(
        lambda value: value["baseline_snapshot"].update(resources=[])
    ) == "INCONCLUSIVE"
    assert derive(
        lambda value: value["candidate_snapshot"].update(filesystem_entries=[])
    ) == "FILE_DELETED_OR_RENAMED"

    def out_of_scope(value: dict) -> None:
        value["candidate_snapshot"]["classifications"][0][
            "classification"
        ] = "OUT_OF_SCOPE_ARTIFACT"

    assert derive(out_of_scope) == "OUT_OF_SCOPE"

    def resource_deleted(value: dict) -> None:
        value["candidate_snapshot"]["resources"] = []
        value["candidate_run"]["evaluations"] = []

    assert derive(resource_deleted) == "RESOURCE_DELETED"

    def resource_absence_with_residual_evidence(value: dict) -> None:
        value["candidate_snapshot"]["resources"] = []

    assert derive(resource_absence_with_residual_evidence) == "INCONCLUSIVE"

    def suppressed(value: dict) -> None:
        value["candidate_run"]["evaluations"][0]["native_result"] = "SKIPPED"

    assert derive(suppressed) == "SUPPRESSED"

    def contradictory_suppression(value: dict) -> None:
        skipped = copy.deepcopy(value["candidate_run"]["evaluations"][0])
        skipped["native_result"] = "SKIPPED"
        value["candidate_run"]["evaluations"].append(skipped)

    assert derive(contradictory_suppression) == "INCONCLUSIVE"

    def ambiguous(value: dict) -> None:
        value["finding_diff"]["ambiguities"] = [{"typed": "ambiguity"}]

    assert derive(ambiguous) == "INCONCLUSIVE"

    def still_present(value: dict) -> None:
        value["candidate_run"]["findings"] = copy.deepcopy(
            value["baseline_run"]["findings"]
        )

    assert derive(still_present) == "STILL_PRESENT"

    def partial(value: dict) -> None:
        second = copy.deepcopy(value["baseline_run"]["findings"][0])
        second["native_fingerprint"] = "second-occurrence"
        second["location"]["start_line"] = 2
        second["location"]["end_line"] = 2
        value["baseline_run"]["findings"].append(second)
        value["candidate_run"]["findings"] = [copy.deepcopy(second)]
        value["targets"][0]["binding"]["baseline_occurrences"] = 2

    assert derive(partial) == "PARTIALLY_FIXED"

    def incomplete_multi_pass(value: dict) -> None:
        second = copy.deepcopy(value["baseline_run"]["findings"][0])
        second["native_fingerprint"] = "second-occurrence"
        second["location"]["start_line"] = 2
        second["location"]["end_line"] = 2
        value["baseline_run"]["findings"].append(second)
        value["targets"][0]["binding"]["baseline_occurrences"] = 2

    assert derive(incomplete_multi_pass) == "INCONCLUSIVE"


def test_snapshot_reconstruction_rejects_every_unsafe_evidence_edge(
    verified_engine: VerificationResult,
) -> None:
    verification = _payload(verified_engine)["verification"]
    original = verification["candidate_snapshot"]
    config = verification["verification_config"]

    def rejects(mutate, match: str) -> None:
        snapshot = copy.deepcopy(original)
        mutate(snapshot)
        with pytest.raises(DomainError, match=match):
            REPORT._validate_snapshot(snapshot, config, "candidate")

    rejects(
        lambda value: value["filesystem_entries"][0].update(supported=False),
        "scope flags",
    )

    def missing_governed(value: dict) -> None:
        value["filesystem_entries"].append({
            "file_path": ".trivyignore", "kind": "REGULAR_FILE", "size": 0,
            "sha256": "a" * 64, "symlink_target_kind": None,
            "symlink_target_sha256": None, "supported": False,
            "governed": True, "rejection_reason": "",
        })

    rejects(missing_governed, "governed entry")

    def rejected_without_classification(value: dict) -> None:
        entry = value["filesystem_entries"][0]
        entry.update(kind="FIFO", size=0, sha256=None,
                     rejection_reason="UNSUPPORTED_ARTIFACT_PATH_TYPE")

    rejects(rejected_without_classification, "rejected artifact")
    rejects(
        lambda value: value["filesystem_entries"].clear(),
        "filesystem entry",
    )

    def unsafe_without_rejection(value: dict) -> None:
        value["filesystem_entries"][0].update(kind="FIFO", size=0, sha256=None)

    rejects(unsafe_without_rejection, "regular filesystem entry")
    rejects(
        lambda value: value["classifications"][0].update(size=99),
        "classification bytes",
    )
    rejects(
        lambda value: value["files"][0].update(size=99),
        "bound file bytes",
    )
    rejects(
        lambda value: value.update(resources=[]),
        "resource inventory",
    )
    rejects(
        lambda value: value.update(snapshot_sha256="b" * 64),
        "snapshot identity",
    )

    def valid_rejected_then_bad_manifest(value: dict) -> None:
        entry = value["filesystem_entries"][0]
        entry.update(kind="FIFO", size=0, sha256=None,
                     rejection_reason="UNSUPPORTED_ARTIFACT_PATH_TYPE")
        value["files"] = []
        classification = value["classifications"][0]
        classification.update(
            classification="REJECTED_ARTIFACT_ENTRY", size=0,
            sha256=_digest(entry), resources=[],
            reason="UNSUPPORTED_ARTIFACT_PATH_TYPE",
        )
        value["resources"] = []
        value["resource_inventory_sha256"] = _digest({
            "resources": [], "classifications": value["classifications"],
        })

    rejects(valid_rejected_then_bad_manifest, "artifact manifest")


def test_public_gate_and_environment_provenance_mutations_are_rejected(
    verified_engine: VerificationResult,
) -> None:
    def mutate_gate(payload: dict, **changes) -> None:
        implementation = payload["verification"]["verification_config"][
            "gate_implementations"
        ][0]
        implementation.update(changes)
        payload["verification"]["gate_implementations"] = copy.deepcopy(
            payload["verification"]["verification_config"]["gate_implementations"]
        )
        _rehash_config(payload)

    for mutation, match in (
        (
            lambda payload: mutate_gate(payload, version="test"),
            "private synthetic",
        ),
        (
            lambda payload: mutate_gate(payload, product_build_digest="b" * 64),
            "aliases",
        ),
        (
            lambda payload: payload["verification"]["candidate_run"].update(
                environment_components=None
            ),
            "lacks component",
        ),
        (
            lambda payload: payload["verification"]["candidate_run"][
                "environment_components"
            ].update(contract="unknown"),
            "contract",
        ),
    ):
        payload = _payload(verified_engine)
        mutation(payload)
        with pytest.raises(DomainError, match=match):
            validate_report_payload(payload)
