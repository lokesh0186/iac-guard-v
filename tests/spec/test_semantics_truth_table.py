"""Executable truth tables and domain probes for the verification semantics.

Every probe below corresponds to a behaviour the reference model once had and should
not have. They were found by adversarial review of the model itself, not by the
existing tables, which is why they are permanent.

  zero targets              returned VERIFIED — verifying nothing is not a pass
  STILL_PRESENT permitted   returned VERIFIED — an unresolved finding was waivable
  blanket permission        one approved deletion waived every deletion
  policy ERROR/TIMEOUT      returned FAILED instead of INCONCLUSIVE
  no validators             returned VERIFIED vacuously
  N=0, N=-1, M=-1           were classified instead of rejected

Subject under test: tests/spec/spec_reference.py, a transcription of the document.
Phase D's engine must satisfy the same tables.
"""
from __future__ import annotations

import itertools
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec_reference import (  # noqa: E402
    EXIT_CODES,
    INVALID_REQUEST_EXIT_CODE,
    NEVER_PERMITTABLE_OUTCOMES,
    PERMITTABLE_EXCEPTION_OUTCOMES,
    ExceptionRecord,
    FindingLocation,
    InvalidVerificationRequest,
    Outcome,
    RunObservation,
    SpecDomainError,
    Status,
    TargetDecision,
    TargetObservation,
    Verdict,
    classify,
    decide,
    location_changed,
    permission_rejection_reason,
)

TODAY = date(2026, 8, 9)


def fixed(target_id: str = "T1") -> TargetDecision:
    return TargetDecision(target_id=target_id, outcome=Outcome.FIXED)


def run_with(*decisions: TargetDecision, **kwargs) -> RunObservation:
    return RunObservation(target_decisions=decisions or (fixed(),), **kwargs)


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
# input domain invariants
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n,m", [(0, 0), (-1, 0), (1, -1), (0, 5), (-3, -3)])
def test_invalid_counts_are_rejected_not_classified(n: int, m: int) -> None:
    with pytest.raises(SpecDomainError):
        TargetObservation(baseline_occurrences=n, candidate_matches=m)


@pytest.mark.parametrize("n,m", [(1, 0), (1, 1), (3, 0), (3, 2), (5, 9)])
def test_valid_counts_are_accepted(n: int, m: int) -> None:
    assert isinstance(
        classify(TargetObservation(baseline_occurrences=n, candidate_matches=m)), Outcome
    )


def test_boolean_counts_are_rejected() -> None:
    with pytest.raises(SpecDomainError):
        TargetObservation(baseline_occurrences=True, candidate_matches=0)


def test_zero_targets_is_an_invalid_request() -> None:
    with pytest.raises(InvalidVerificationRequest):
        RunObservation(target_decisions=())


def test_no_required_validator_is_an_invalid_request() -> None:
    with pytest.raises(InvalidVerificationRequest):
        RunObservation(target_decisions=(fixed(),), required_validator_states=())


def test_invalid_request_has_its_own_exit_code() -> None:
    assert INVALID_REQUEST_EXIT_CODE == 2
    assert INVALID_REQUEST_EXIT_CODE not in EXIT_CODES.values()


def test_duplicate_target_ids_are_rejected() -> None:
    with pytest.raises(SpecDomainError):
        RunObservation(target_decisions=(fixed("T1"), fixed("T1")))


def test_permission_without_an_exception_id_is_rejected() -> None:
    with pytest.raises(SpecDomainError):
        TargetDecision(target_id="T1", outcome=Outcome.SUPPRESSED, policy_permitted=True)


# --------------------------------------------------------------------------- #
# evidence sufficiency outranks every count-based outcome
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "n,m,would_be_without_the_rule",
    [(1, 0, Outcome.FIXED), (3, 0, Outcome.FIXED),
     (3, 1, Outcome.PARTIALLY_FIXED), (3, 2, Outcome.PARTIALLY_FIXED),
     (1, 1, Outcome.STILL_PRESENT), (3, 3, Outcome.STILL_PRESENT),
     (1, 4, Outcome.STILL_PRESENT)],
)
def test_insufficient_evidence_outranks_count_rules(
    n: int, m: int, would_be_without_the_rule: Outcome
) -> None:
    assert classify(
        TargetObservation(baseline_occurrences=n, candidate_matches=m)
    ) is would_be_without_the_rule
    assert classify(
        TargetObservation(baseline_occurrences=n, candidate_matches=m,
                          occurrence_evidence_sufficient=False)
    ) is Outcome.INCONCLUSIVE


def test_evidence_rule_does_not_mask_stronger_signals() -> None:
    for extra, expected in [
        (dict(scanner_integrity_ok=False), Outcome.SCANNER_ERROR),
        (dict(scanner_ruleset_stable=False), Outcome.RULE_OR_SCANNER_DRIFT),
        (dict(artifact_structurally_eligible=False), Outcome.OUT_OF_SCOPE),
        (dict(target_file_present=False), Outcome.FILE_DELETED_OR_RENAMED),
        (dict(target_resource_present=False), Outcome.RESOURCE_DELETED),
        (dict(suppression_covering_scope_added=True), Outcome.SUPPRESSED),
    ]:
        obs = TargetObservation(baseline_occurrences=1, candidate_matches=0,
                                occurrence_evidence_sufficient=False, **extra)
        assert classify(obs) is expected, extra


def test_count_predicates_are_disjoint_over_the_whole_grid() -> None:
    for n, m in itertools.product(range(1, 6), range(0, 7)):
        partial = n > 1 and 0 < m < n
        still = m >= n or (n == 1 and m == 1)
        is_fixed = m == 0
        assert not (partial and still), f"N={n} M={m}"
        assert not (partial and is_fixed), f"N={n} M={m}"
        assert not (still and is_fixed), f"N={n} M={m}"
        assert partial or still or is_fixed, f"N={n} M={m}"


def test_classification_is_total_over_the_flag_grid() -> None:
    """7 boolean flags x 5 (N, M) pairs = 128 x 5 = 640 classifications."""
    flags = ("scanner_integrity_ok", "scanner_ruleset_stable",
             "artifact_structurally_eligible", "target_file_present",
             "target_resource_present", "suppression_covering_scope_added",
             "occurrence_evidence_sufficient")
    pairs = ((1, 0), (1, 1), (3, 1), (3, 0), (3, 3))
    combos = list(itertools.product([True, False], repeat=len(flags)))
    assert len(combos) == 128
    checked = 0
    for combo in combos:
        for n, m in pairs:
            obs = TargetObservation(baseline_occurrences=n, candidate_matches=m,
                                    **dict(zip(flags, combo)))
            assert isinstance(classify(obs), Outcome)
            checked += 1
    assert checked == 640


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
    assert not any("oracle" in name for name in TargetObservation.__dataclass_fields__)


# --------------------------------------------------------------------------- #
# exceptions bind to one target, and only for a closed outcome set
# --------------------------------------------------------------------------- #
def approved(target_id: str, outcome: Outcome, scope: str = "s3.data",
             exception_id: str = "EX-1") -> tuple[TargetDecision, dict]:
    decision = TargetDecision(target_id=target_id, outcome=outcome, target_scope=scope,
                              policy_permitted=True, exception_id=exception_id)
    record = ExceptionRecord(exception_id=exception_id, target_id=target_id, scope=scope,
                             reason="accepted risk, tracked in TICKET-42",
                             owner="platform-team", expires=date(2026, 12, 31),
                             origin="trusted_base")
    return decision, {exception_id: record}


def test_the_permittable_and_never_permittable_sets_are_disjoint_and_complete() -> None:
    assert not (PERMITTABLE_EXCEPTION_OUTCOMES & NEVER_PERMITTABLE_OUTCOMES)
    assert (PERMITTABLE_EXCEPTION_OUTCOMES | NEVER_PERMITTABLE_OUTCOMES
            | {Outcome.FIXED}) == set(Outcome)


@pytest.mark.parametrize("outcome", sorted(PERMITTABLE_EXCEPTION_OUTCOMES,
                                           key=lambda o: o.value))
def test_eligible_outcome_with_a_valid_exception_verifies(outcome: Outcome) -> None:
    decision, exceptions = approved("T1", outcome)
    assert decide(run_with(decision, exceptions=exceptions)) is Verdict.VERIFIED


@pytest.mark.parametrize("outcome", sorted(NEVER_PERMITTABLE_OUTCOMES,
                                           key=lambda o: o.value))
def test_never_permittable_outcomes_cannot_be_waived(outcome: Outcome) -> None:
    """The headline flaw: an unresolved finding must not be approvable into a pass."""
    decision, exceptions = approved("T1", outcome)
    verdict = decide(run_with(decision, exceptions=exceptions))
    assert verdict is not Verdict.VERIFIED, f"{outcome.value} was waived into a pass"
    reason = permission_rejection_reason(decision, exceptions, TODAY)
    assert reason and "never exception-eligible" in reason


def test_still_present_cannot_be_verified_by_any_permission() -> None:
    decision, exceptions = approved("T1", Outcome.STILL_PRESENT)
    assert decide(run_with(decision, exceptions=exceptions)) is Verdict.FAILED


def test_partially_fixed_cannot_be_verified_by_any_permission() -> None:
    decision, exceptions = approved("T1", Outcome.PARTIALLY_FIXED)
    assert decide(run_with(decision, exceptions=exceptions)) is Verdict.FAILED


def test_a_permission_for_one_target_does_not_cover_another() -> None:
    approved_a, exceptions = approved("T-A", Outcome.RESOURCE_DELETED, scope="s3.a")
    unapproved_b = TargetDecision(target_id="T-B", outcome=Outcome.RESOURCE_DELETED,
                                  target_scope="s3.b")
    assert decide(run_with(approved_a, exceptions=exceptions)) is Verdict.VERIFIED
    assert decide(run_with(approved_a, unapproved_b,
                           exceptions=exceptions)) is Verdict.FAILED


def test_two_deletions_with_one_target_scoped_exception_fail() -> None:
    """The blanket-permission spillover the global set allowed."""
    approved_a, exceptions = approved("T-A", Outcome.RESOURCE_DELETED, scope="s3.a")
    claims_same_exception = TargetDecision(
        target_id="T-B", outcome=Outcome.RESOURCE_DELETED, target_scope="s3.b",
        policy_permitted=True, exception_id="EX-1",
    )
    assert decide(run_with(approved_a, claims_same_exception,
                           exceptions=exceptions)) is Verdict.FAILED
    reason = permission_rejection_reason(claims_same_exception, exceptions, TODAY)
    assert reason and "binds target" in reason


@pytest.mark.parametrize("mutation,expected_fragment", [
    ("missing", "not found"),
    ("other_target", "binds target"),
    ("scope", "scope"),
    ("head_origin", "originates in the evaluated change"),
    ("untrusted_origin", "is not trusted"),
    ("no_reason", "no reason"),
    ("no_owner", "no owner"),
    ("expired", "expired"),
])
def test_defective_exceptions_do_not_permit(mutation: str, expected_fragment: str) -> None:
    decision, exceptions = approved("T1", Outcome.SUPPRESSED)
    record = exceptions["EX-1"]
    if mutation == "missing":
        exceptions = {}
    elif mutation == "other_target":
        exceptions = {"EX-1": ExceptionRecord(**{**record.__dict__, "target_id": "T-OTHER"})}
    elif mutation == "scope":
        exceptions = {"EX-1": ExceptionRecord(**{**record.__dict__, "scope": "other.scope"})}
    elif mutation == "head_origin":
        exceptions = {"EX-1": ExceptionRecord(**{**record.__dict__,
                                                "origin": "candidate_head"})}
    elif mutation == "untrusted_origin":
        exceptions = {"EX-1": ExceptionRecord(**{**record.__dict__, "origin": "random"})}
    elif mutation == "no_reason":
        exceptions = {"EX-1": ExceptionRecord(**{**record.__dict__, "reason": "  "})}
    elif mutation == "no_owner":
        exceptions = {"EX-1": ExceptionRecord(**{**record.__dict__, "owner": ""})}
    elif mutation == "expired":
        exceptions = {"EX-1": ExceptionRecord(**{**record.__dict__,
                                                "expires": date(2026, 1, 1)})}

    reason = permission_rejection_reason(decision, exceptions, TODAY)
    assert reason is not None, mutation
    assert expected_fragment in reason, (mutation, reason)
    assert decide(run_with(decision, exceptions=exceptions)) is Verdict.FAILED


def test_permitted_event_is_still_reported() -> None:
    """Permission changes the decision, never the classification (§4.2)."""
    decision, exceptions = approved("T1", Outcome.SUPPRESSED)
    assert decision.outcome is Outcome.SUPPRESSED
    assert decide(run_with(decision, exceptions=exceptions)) is Verdict.VERIFIED


# --------------------------------------------------------------------------- #
# location change
# --------------------------------------------------------------------------- #
def test_line_only_move_is_detected() -> None:
    assert location_changed(FindingLocation("main.tf", 10, 14),
                            FindingLocation("main.tf", 25, 29), True) is True


def test_file_move_is_detected() -> None:
    assert location_changed(FindingLocation("main.tf", 10, 14),
                            FindingLocation("modules/s3/main.tf", 10, 14), True) is True


def test_identical_location_is_not_a_change() -> None:
    same = FindingLocation("main.tf", 10, 14)
    assert location_changed(same, same, True) is False


def test_unmatched_findings_are_never_location_changes() -> None:
    assert location_changed(FindingLocation("a.tf", 1, 2),
                            FindingLocation("b.tf", 90, 91), False) is False


# --------------------------------------------------------------------------- #
# whole-run decision table
# --------------------------------------------------------------------------- #
def _deleted_approved() -> RunObservation:
    decision, exceptions = approved("T1", Outcome.RESOURCE_DELETED)
    return run_with(decision, exceptions=exceptions)


VERDICT_TABLE = [
    ("all targets fixed", run_with(fixed("T1"), fixed("T2")), Verdict.VERIFIED),
    ("defect remains", run_with(TargetDecision("T1", Outcome.STILL_PRESENT)),
     Verdict.FAILED),
    ("partially fixed", run_with(TargetDecision("T1", Outcome.PARTIALLY_FIXED)),
     Verdict.FAILED),
    ("evasion by suppression", run_with(TargetDecision("T1", Outcome.SUPPRESSED)),
     Verdict.FAILED),
    ("resource deleted, not permitted",
     run_with(TargetDecision("T1", Outcome.RESOURCE_DELETED)), Verdict.FAILED),
    ("resource deleted, target-scoped exception", _deleted_approved(), Verdict.VERIFIED),
    ("policy drift", run_with(fixed(), policy_drift=True), Verdict.FAILED),
    ("scanner error", run_with(TargetDecision("T1", Outcome.SCANNER_ERROR)),
     Verdict.INCONCLUSIVE),
    ("ruleset drift", run_with(TargetDecision("T1", Outcome.RULE_OR_SCANNER_DRIFT)),
     Verdict.INCONCLUSIVE),
    ("inconclusive target", run_with(TargetDecision("T1", Outcome.INCONCLUSIVE)),
     Verdict.INCONCLUSIVE),
    ("integrity failure outranks a real defect",
     run_with(TargetDecision("T1", Outcome.STILL_PRESENT),
              required_scanner_integrity=Status.ERROR), Verdict.INCONCLUSIVE),
    ("preflight failure", run_with(fixed(), preflight=Status.ERROR),
     Verdict.INCONCLUSIVE),
    ("validator says the artifact is invalid",
     run_with(fixed(), required_validator_states=(Status.FAIL,)), Verdict.FAILED),
    ("validator could not run",
     run_with(fixed(), required_validator_states=(Status.UNSUPPORTED,)),
     Verdict.INCONCLUSIVE),
    ("oracle disproves the repair",
     run_with(fixed(), required_oracle_states=(Status.FAIL,)), Verdict.FAILED),
    ("oracle could not decide",
     run_with(fixed(), required_oracle_states=(Status.ERROR,)), Verdict.INCONCLUSIVE),
    ("oracle passes", run_with(fixed(), required_oracle_states=(Status.PASS,)),
     Verdict.VERIFIED),
    ("coverage decreased on a required scanner",
     run_with(fixed(), coverage_decreased_on_required_scanner=True),
     Verdict.INCONCLUSIVE),
    ("rule substituted on a required target",
     run_with(fixed(), rule_substituted_on_required_target=True), Verdict.INCONCLUSIVE),
    ("regression policy FAIL", run_with(fixed(), regression_policy=Status.FAIL),
     Verdict.FAILED),
    ("suppression policy FAIL", run_with(fixed(), suppression_policy=Status.FAIL),
     Verdict.FAILED),
]


@pytest.mark.parametrize("name,run,expected", VERDICT_TABLE,
                         ids=[row[0] for row in VERDICT_TABLE])
def test_verdict_decision_table(name: str, run: RunObservation,
                                expected: Verdict) -> None:
    assert decide(run) is expected


@pytest.mark.parametrize("undecided", [Status.ERROR, Status.TIMEOUT, Status.UNSUPPORTED,
                                       Status.PARTIAL, Status.INCONCLUSIVE,
                                       Status.SKIPPED])
def test_every_undecided_gate_state_yields_inconclusive(undecided: Status) -> None:
    assert decide(run_with(fixed(), required_validator_states=(undecided,))
                  ) is Verdict.INCONCLUSIVE
    assert decide(run_with(fixed(), required_oracle_states=(undecided,))
                  ) is Verdict.INCONCLUSIVE


@pytest.mark.parametrize("state,expected", [
    (Status.PASS, Verdict.VERIFIED),
    (Status.FAIL, Verdict.FAILED),
    (Status.ERROR, Verdict.INCONCLUSIVE),
    (Status.TIMEOUT, Verdict.INCONCLUSIVE),
    (Status.UNSUPPORTED, Verdict.INCONCLUSIVE),
    (Status.PARTIAL, Verdict.INCONCLUSIVE),
    (Status.INCONCLUSIVE, Verdict.INCONCLUSIVE),
    (Status.SKIPPED, Verdict.INCONCLUSIVE),
])
def test_regression_policy_states(state: Status, expected: Verdict) -> None:
    assert decide(run_with(fixed(), regression_policy=state)) is expected


@pytest.mark.parametrize("state,expected", [
    (Status.PASS, Verdict.VERIFIED),
    (Status.FAIL, Verdict.FAILED),
    (Status.ERROR, Verdict.INCONCLUSIVE),
    (Status.TIMEOUT, Verdict.INCONCLUSIVE),
    (Status.UNSUPPORTED, Verdict.INCONCLUSIVE),
    (Status.PARTIAL, Verdict.INCONCLUSIVE),
    (Status.INCONCLUSIVE, Verdict.INCONCLUSIVE),
    (Status.SKIPPED, Verdict.INCONCLUSIVE),
])
def test_suppression_policy_states(state: Status, expected: Verdict) -> None:
    assert decide(run_with(fixed(), suppression_policy=state)) is expected


def test_skipped_is_accepted_only_when_the_gate_is_explicitly_optional() -> None:
    assert decide(run_with(fixed(), regression_policy=Status.SKIPPED)
                  ) is Verdict.INCONCLUSIVE
    assert decide(run_with(fixed(), regression_policy=Status.SKIPPED,
                           optional_gates=frozenset({"regression"}))) is Verdict.VERIFIED


def test_undecided_dominates_definite_failure() -> None:
    assert decide(run_with(TargetDecision("T1", Outcome.STILL_PRESENT),
                           required_oracle_states=(Status.ERROR,))
                  ) is Verdict.INCONCLUSIVE


def test_operational_failure_never_reports_verified_or_failed() -> None:
    for outcome in (Outcome.SCANNER_ERROR, Outcome.RULE_OR_SCANNER_DRIFT,
                    Outcome.INCONCLUSIVE):
        assert decide(run_with(TargetDecision("T1", outcome))) is Verdict.INCONCLUSIVE


def test_exit_codes_match_the_specification() -> None:
    assert EXIT_CODES[Verdict.VERIFIED] == 0
    assert EXIT_CODES[Verdict.FAILED] == 1
    assert EXIT_CODES[Verdict.INCONCLUSIVE] == 3


def test_every_verdict_is_reachable() -> None:
    assert {decide(run) for _, run, _ in VERDICT_TABLE} == set(Verdict)
