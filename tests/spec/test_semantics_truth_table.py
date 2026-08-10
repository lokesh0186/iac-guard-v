"""Executable truth tables for the verification semantics.

Properties proven here, each of which a draft of the specification violated:

  reachability      every target outcome is produced by at least one scenario
  disjointness      no scenario satisfies two outcome predicates
  evidence first    insufficient occurrence evidence outranks every count-based
                    outcome, in the document and in the model alike
  location change   a line-only move is observable even though line numbers are
                    excluded from the stable identity
  typed gates       validator and oracle FAIL means FAILED, while ERROR, TIMEOUT,
                    UNSUPPORTED, PARTIAL and INCONCLUSIVE mean INCONCLUSIVE
  no impossible states  oracle results are not part of target classification, so no
                    test may assert "FIXED while its own required oracle failed"

Subject under test: tests/spec/spec_reference.py, a transcription of the document.
Phase D's engine must satisfy the same tables.
"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec_reference import (  # noqa: E402
    EXIT_CODES,
    FindingLocation,
    Outcome,
    RunObservation,
    Status,
    TargetObservation,
    Verdict,
    classify,
    decide,
    location_changed,
)

# --------------------------------------------------------------------------- #
# target classification
# --------------------------------------------------------------------------- #
SCENARIOS: dict[str, tuple[TargetObservation, Outcome]] = {
    "clean single fix": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0), Outcome.FIXED),
    "all three occurrences fixed": (
        TargetObservation(baseline_occurrences=3, candidate_matches=0), Outcome.FIXED),
    "single occurrence untouched": (
        TargetObservation(baseline_occurrences=1, candidate_matches=1),
        Outcome.STILL_PRESENT),
    "all three occurrences remain": (
        TargetObservation(baseline_occurrences=3, candidate_matches=3),
        Outcome.STILL_PRESENT),
    "more occurrences than before": (
        TargetObservation(baseline_occurrences=1, candidate_matches=2),
        Outcome.STILL_PRESENT),
    "one of three fixed": (
        TargetObservation(baseline_occurrences=3, candidate_matches=2),
        Outcome.PARTIALLY_FIXED),
    "two of three fixed": (
        TargetObservation(baseline_occurrences=3, candidate_matches=1),
        Outcome.PARTIALLY_FIXED),
    "skip annotation added": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          suppression_covering_scope_added=True), Outcome.SUPPRESSED),
    "path excluded via scanner config": (
        TargetObservation(baseline_occurrences=2, candidate_matches=0,
                          suppression_covering_scope_added=True), Outcome.SUPPRESSED),
    "offending resource deleted": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          target_resource_present=False), Outcome.RESOURCE_DELETED),
    "file deleted": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          target_file_present=False),
        Outcome.FILE_DELETED_OR_RENAMED),
    "extension changed so nothing selects it": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          artifact_structurally_eligible=False), Outcome.OUT_OF_SCOPE),
    "scanner version changed between runs": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          scanner_ruleset_stable=False),
        Outcome.RULE_OR_SCANNER_DRIFT),
    "scanner produced no usable output": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          scanner_integrity_ok=False), Outcome.SCANNER_ERROR),
    "occurrence evidence insufficient": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          occurrence_evidence_sufficient=False), Outcome.INCONCLUSIVE),
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenario_maps_to_expected_outcome(name: str) -> None:
    obs, expected = SCENARIOS[name]
    assert classify(obs) is expected


def test_every_outcome_is_reachable() -> None:
    produced = {classify(obs) for obs, _ in SCENARIOS.values()}
    missing = set(Outcome) - produced
    assert not missing, f"unreachable outcomes: {sorted(o.value for o in missing)}"


def test_partially_fixed_is_reachable_specifically() -> None:
    assert classify(
        TargetObservation(baseline_occurrences=3, candidate_matches=1)
    ) is Outcome.PARTIALLY_FIXED


# --------------------------------------------------------------------------- #
# evidence sufficiency outranks every count-based outcome
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "n,m,would_be_without_the_rule",
    [
        (1, 0, Outcome.FIXED),
        (3, 0, Outcome.FIXED),
        (3, 1, Outcome.PARTIALLY_FIXED),
        (3, 2, Outcome.PARTIALLY_FIXED),
        (1, 1, Outcome.STILL_PRESENT),
        (3, 3, Outcome.STILL_PRESENT),
        (1, 4, Outcome.STILL_PRESENT),
    ],
)
def test_insufficient_evidence_outranks_count_rules(
    n: int, m: int, would_be_without_the_rule: Outcome
) -> None:
    """M == 0, 0 < M < N and M >= N must all yield INCONCLUSIVE."""
    sufficient = TargetObservation(baseline_occurrences=n, candidate_matches=m)
    assert classify(sufficient) is would_be_without_the_rule

    insufficient = TargetObservation(baseline_occurrences=n, candidate_matches=m,
                                     occurrence_evidence_sufficient=False)
    assert classify(insufficient) is Outcome.INCONCLUSIVE


def test_evidence_rule_does_not_mask_stronger_signals() -> None:
    """Operational and structural facts still take precedence over INCONCLUSIVE."""
    cases = [
        (dict(scanner_integrity_ok=False), Outcome.SCANNER_ERROR),
        (dict(scanner_ruleset_stable=False), Outcome.RULE_OR_SCANNER_DRIFT),
        (dict(artifact_structurally_eligible=False), Outcome.OUT_OF_SCOPE),
        (dict(target_file_present=False), Outcome.FILE_DELETED_OR_RENAMED),
        (dict(target_resource_present=False), Outcome.RESOURCE_DELETED),
        (dict(suppression_covering_scope_added=True), Outcome.SUPPRESSED),
    ]
    for extra, expected in cases:
        obs = TargetObservation(baseline_occurrences=1, candidate_matches=0,
                                occurrence_evidence_sufficient=False, **extra)
        assert classify(obs) is expected, extra


def test_count_predicates_are_disjoint_over_the_whole_grid() -> None:
    for n, m in itertools.product(range(1, 6), range(0, 7)):
        partial = n > 1 and 0 < m < n
        still = m >= n or (n == 1 and m == 1)
        fixed = m == 0
        assert not (partial and still), f"N={n} M={m}"
        assert not (partial and fixed), f"N={n} M={m}"
        assert not (still and fixed), f"N={n} M={m}"
        assert partial or still or fixed, f"N={n} M={m}"


def test_classification_is_total_over_the_flag_grid() -> None:
    flags = ("scanner_integrity_ok", "scanner_ruleset_stable",
             "artifact_structurally_eligible", "target_file_present",
             "target_resource_present", "suppression_covering_scope_added",
             "occurrence_evidence_sufficient")
    for combo in itertools.product([True, False], repeat=len(flags)):
        for n, m in ((1, 0), (1, 1), (3, 1), (3, 0), (3, 3)):
            obs = TargetObservation(baseline_occurrences=n, candidate_matches=m,
                                    **dict(zip(flags, combo)))
            assert isinstance(classify(obs), Outcome)


def test_suppressed_and_out_of_scope_never_collide() -> None:
    assert classify(TargetObservation(
        baseline_occurrences=1, candidate_matches=0,
        suppression_covering_scope_added=True,
        artifact_structurally_eligible=True)) is Outcome.SUPPRESSED
    assert classify(TargetObservation(
        baseline_occurrences=1, candidate_matches=0,
        suppression_covering_scope_added=False,
        artifact_structurally_eligible=False)) is Outcome.OUT_OF_SCOPE


def test_absence_of_a_finding_alone_never_yields_fixed() -> None:
    for extra in (dict(suppression_covering_scope_added=True),
                  dict(target_resource_present=False),
                  dict(artifact_structurally_eligible=False),
                  dict(scanner_integrity_ok=False),
                  dict(occurrence_evidence_sufficient=False)):
        obs = TargetObservation(baseline_occurrences=1, candidate_matches=0, **extra)
        assert classify(obs) is not Outcome.FIXED


def test_oracle_state_is_not_an_input_to_classification() -> None:
    """Oracles are gates, not classifiers (§4.3)."""
    assert not any(
        "oracle" in name for name in TargetObservation.__dataclass_fields__
    ), "target classification must not depend on oracle state"


# --------------------------------------------------------------------------- #
# location change
# --------------------------------------------------------------------------- #
def test_line_only_move_is_detected() -> None:
    """The case the previous definition could not express."""
    before = FindingLocation("main.tf", 10, 14)
    after = FindingLocation("main.tf", 25, 29)
    assert location_changed(before, after, identity_matched=True) is True


def test_file_move_is_detected() -> None:
    before = FindingLocation("main.tf", 10, 14)
    after = FindingLocation("modules/s3/main.tf", 10, 14)
    assert location_changed(before, after, identity_matched=True) is True


def test_identical_location_is_not_a_change() -> None:
    same = FindingLocation("main.tf", 10, 14)
    assert location_changed(same, same, identity_matched=True) is False


def test_unmatched_findings_are_never_location_changes() -> None:
    """A different resource is RESOLVED_FINDING plus NEW_FINDING, not a move."""
    before = FindingLocation("a.tf", 1, 2)
    after = FindingLocation("b.tf", 90, 91)
    assert location_changed(before, after, identity_matched=False) is False


# --------------------------------------------------------------------------- #
# whole-run decision table, with typed gate states
# --------------------------------------------------------------------------- #
VERDICT_TABLE = [
    ("all targets fixed", RunObservation((Outcome.FIXED, Outcome.FIXED)),
     Verdict.VERIFIED),
    ("defect remains", RunObservation((Outcome.STILL_PRESENT,)), Verdict.FAILED),
    ("partially fixed", RunObservation((Outcome.PARTIALLY_FIXED,)), Verdict.FAILED),
    ("evasion by suppression", RunObservation((Outcome.SUPPRESSED,)), Verdict.FAILED),
    ("resource deleted, not permitted", RunObservation((Outcome.RESOURCE_DELETED,)),
     Verdict.FAILED),
    ("resource deleted, permitted by trusted policy",
     RunObservation((Outcome.RESOURCE_DELETED,),
                    permitted_outcomes=frozenset({Outcome.RESOURCE_DELETED})),
     Verdict.VERIFIED),
    ("policy drift", RunObservation((Outcome.FIXED,), policy_drift=True),
     Verdict.FAILED),
    ("scanner error", RunObservation((Outcome.SCANNER_ERROR,)), Verdict.INCONCLUSIVE),
    ("ruleset drift", RunObservation((Outcome.RULE_OR_SCANNER_DRIFT,)),
     Verdict.INCONCLUSIVE),
    ("inconclusive target", RunObservation((Outcome.INCONCLUSIVE,)),
     Verdict.INCONCLUSIVE),
    ("integrity failure outranks a real defect",
     RunObservation((Outcome.STILL_PRESENT,),
                    required_scanner_integrity=Status.ERROR), Verdict.INCONCLUSIVE),
    ("preflight failure", RunObservation((Outcome.FIXED,), preflight=Status.ERROR),
     Verdict.INCONCLUSIVE),
    ("validator says the artifact is invalid",
     RunObservation((Outcome.FIXED,), required_validator_states=(Status.FAIL,)),
     Verdict.FAILED),
    ("validator could not run",
     RunObservation((Outcome.FIXED,), required_validator_states=(Status.UNSUPPORTED,)),
     Verdict.INCONCLUSIVE),
    ("validator timed out",
     RunObservation((Outcome.FIXED,), required_validator_states=(Status.TIMEOUT,)),
     Verdict.INCONCLUSIVE),
    ("oracle disproves the repair",
     RunObservation((Outcome.FIXED,), required_oracle_states=(Status.FAIL,)),
     Verdict.FAILED),
    ("oracle could not decide",
     RunObservation((Outcome.FIXED,), required_oracle_states=(Status.ERROR,)),
     Verdict.INCONCLUSIVE),
    ("oracle partial",
     RunObservation((Outcome.FIXED,), required_oracle_states=(Status.PARTIAL,)),
     Verdict.INCONCLUSIVE),
    ("oracle passes", RunObservation((Outcome.FIXED,),
                                     required_oracle_states=(Status.PASS,)),
     Verdict.VERIFIED),
    ("coverage decreased on a required scanner",
     RunObservation((Outcome.FIXED,), coverage_decreased_on_required_scanner=True),
     Verdict.INCONCLUSIVE),
    ("rule substituted on a required target",
     RunObservation((Outcome.FIXED,), rule_substituted_on_required_target=True),
     Verdict.INCONCLUSIVE),
    ("regression policy failure",
     RunObservation((Outcome.FIXED,), regression_policy=Status.FAIL), Verdict.FAILED),
    ("suppression policy failure",
     RunObservation((Outcome.FIXED,), suppression_policy=Status.FAIL), Verdict.FAILED),
]


@pytest.mark.parametrize("name,run,expected", VERDICT_TABLE,
                         ids=[row[0] for row in VERDICT_TABLE])
def test_verdict_decision_table(name: str, run: RunObservation,
                                expected: Verdict) -> None:
    assert decide(run) is expected


@pytest.mark.parametrize("undecided",
                         [Status.ERROR, Status.TIMEOUT, Status.UNSUPPORTED,
                          Status.PARTIAL, Status.INCONCLUSIVE, Status.SKIPPED])
def test_every_undecided_gate_state_yields_inconclusive(undecided: Status) -> None:
    assert decide(RunObservation((Outcome.FIXED,),
                                 required_validator_states=(undecided,))
                  ) is Verdict.INCONCLUSIVE
    assert decide(RunObservation((Outcome.FIXED,),
                                 required_oracle_states=(undecided,))
                  ) is Verdict.INCONCLUSIVE


def test_undecided_dominates_definite_failure() -> None:
    """A broken oracle plus a real defect is INCONCLUSIVE, not FAILED."""
    assert decide(RunObservation((Outcome.STILL_PRESENT,),
                                 required_oracle_states=(Status.ERROR,))
                  ) is Verdict.INCONCLUSIVE


def test_operational_failure_never_reports_verified_or_failed() -> None:
    for outcome in (Outcome.SCANNER_ERROR, Outcome.RULE_OR_SCANNER_DRIFT,
                    Outcome.INCONCLUSIVE):
        assert decide(RunObservation((outcome,))) is Verdict.INCONCLUSIVE


def test_exit_codes_match_the_specification() -> None:
    assert EXIT_CODES[Verdict.VERIFIED] == 0
    assert EXIT_CODES[Verdict.FAILED] == 1
    assert EXIT_CODES[Verdict.INCONCLUSIVE] == 3


def test_every_verdict_is_reachable() -> None:
    assert {decide(run) for _, run, _ in VERDICT_TABLE} == set(Verdict)
