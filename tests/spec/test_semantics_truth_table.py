"""Executable truth tables for the verification semantics.

Three properties are proven here, all of which an earlier draft of the specification
violated:

  reachability   every target outcome is produced by at least one scenario. The
                 previous draft evaluated STILL_PRESENT before PARTIALLY_FIXED and
                 defined it as "a finding remains", making PARTIALLY_FIXED impossible.
  disjointness   no scenario satisfies two outcome predicates, so the ordering rule is
                 an efficiency detail rather than a tie-breaker hiding ambiguity.
  verdict fit    operational failure maps to INCONCLUSIVE, candidate defects and
                 evasions map to FAILED, and only FIXED-everywhere maps to VERIFIED.

The subject under test is tests/spec/spec_reference.py, a transcription of the
specification. Phase D's engine must satisfy the same tables.
"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec_reference import (  # noqa: E402
    EXIT_CODES,
    Outcome,
    RunObservation,
    TargetObservation,
    Verdict,
    classify,
    decide,
)

# --------------------------------------------------------------------------- #
# scenario table: one row per outcome, plus the cases that used to be wrong
# --------------------------------------------------------------------------- #
SCENARIOS: dict[str, tuple[TargetObservation, Outcome]] = {
    "clean single fix": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0),
        Outcome.FIXED,
    ),
    "all three occurrences fixed": (
        TargetObservation(baseline_occurrences=3, candidate_matches=0),
        Outcome.FIXED,
    ),
    "single occurrence untouched": (
        TargetObservation(baseline_occurrences=1, candidate_matches=1),
        Outcome.STILL_PRESENT,
    ),
    "all three occurrences remain": (
        TargetObservation(baseline_occurrences=3, candidate_matches=3),
        Outcome.STILL_PRESENT,
    ),
    "more occurrences than before": (
        TargetObservation(baseline_occurrences=1, candidate_matches=2),
        Outcome.STILL_PRESENT,
    ),
    "one of three fixed": (
        TargetObservation(baseline_occurrences=3, candidate_matches=2),
        Outcome.PARTIALLY_FIXED,
    ),
    "two of three fixed": (
        TargetObservation(baseline_occurrences=3, candidate_matches=1),
        Outcome.PARTIALLY_FIXED,
    ),
    "skip annotation added": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          suppression_covering_scope_added=True),
        Outcome.SUPPRESSED,
    ),
    "path excluded via scanner config": (
        TargetObservation(baseline_occurrences=2, candidate_matches=0,
                          suppression_covering_scope_added=True),
        Outcome.SUPPRESSED,
    ),
    "offending resource deleted": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          target_resource_present=False),
        Outcome.RESOURCE_DELETED,
    ),
    "file deleted": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          target_file_present=False),
        Outcome.FILE_DELETED_OR_RENAMED,
    ),
    "extension changed so nothing selects it": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          artifact_structurally_eligible=False),
        Outcome.OUT_OF_SCOPE,
    ),
    "scanner version changed between runs": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          scanner_ruleset_stable=False),
        Outcome.RULE_OR_SCANNER_DRIFT,
    ),
    "scanner produced no usable output": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          scanner_integrity_ok=False),
        Outcome.SCANNER_ERROR,
    ),
    "evidence insufficient": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          evidence_sufficient=False),
        Outcome.INCONCLUSIVE,
    ),
    "finding absent but required oracle fails": (
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          required_oracles_pass=False),
        Outcome.INCONCLUSIVE,
    ),
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
    """The regression this table exists for."""
    assert classify(
        TargetObservation(baseline_occurrences=3, candidate_matches=1)
    ) is Outcome.PARTIALLY_FIXED


def test_count_predicates_are_disjoint_over_the_whole_grid() -> None:
    """No (N, M) pair may satisfy both the PARTIALLY_FIXED and STILL_PRESENT rules."""
    for n, m in itertools.product(range(1, 6), range(0, 7)):
        partial = n > 1 and 0 < m < n
        still = m >= n or (n == 1 and m == 1)
        fixed = m == 0
        assert not (partial and still), f"N={n} M={m} satisfies two predicates"
        assert not (partial and fixed), f"N={n} M={m} satisfies two predicates"
        assert not (still and fixed), f"N={n} M={m} satisfies two predicates"
        assert partial or still or fixed, f"N={n} M={m} satisfies no predicate"


def test_classification_is_total_over_the_flag_grid() -> None:
    """Every combination of observation flags yields exactly one outcome."""
    flags = ("scanner_integrity_ok", "scanner_ruleset_stable",
             "artifact_structurally_eligible", "target_file_present",
             "target_resource_present", "suppression_covering_scope_added",
             "required_oracles_pass", "evidence_sufficient")
    for combo in itertools.product([True, False], repeat=len(flags)):
        for n, m in ((1, 0), (1, 1), (3, 1), (3, 0), (3, 3)):
            kwargs = dict(zip(flags, combo))
            obs = TargetObservation(baseline_occurrences=n, candidate_matches=m, **kwargs)
            result = classify(obs)
            assert isinstance(result, Outcome)


def test_suppressed_and_out_of_scope_never_collide() -> None:
    """Both were previously reachable from 'path excluded'."""
    suppressed = TargetObservation(
        baseline_occurrences=1, candidate_matches=0,
        suppression_covering_scope_added=True, artifact_structurally_eligible=True,
    )
    out_of_scope = TargetObservation(
        baseline_occurrences=1, candidate_matches=0,
        suppression_covering_scope_added=False, artifact_structurally_eligible=False,
    )
    assert classify(suppressed) is Outcome.SUPPRESSED
    assert classify(out_of_scope) is Outcome.OUT_OF_SCOPE


def test_absence_of_a_finding_alone_never_yields_fixed() -> None:
    """M == 0 is shared by four outcomes; only one of them passes."""
    absent = [
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          suppression_covering_scope_added=True),
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          target_resource_present=False),
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          artifact_structurally_eligible=False),
        TargetObservation(baseline_occurrences=1, candidate_matches=0,
                          scanner_integrity_ok=False),
    ]
    for obs in absent:
        assert classify(obs) is not Outcome.FIXED


# --------------------------------------------------------------------------- #
# whole-run decision table
# --------------------------------------------------------------------------- #
VERDICT_TABLE = [
    ("all targets fixed", RunObservation((Outcome.FIXED, Outcome.FIXED)), Verdict.VERIFIED),
    ("defect remains", RunObservation((Outcome.STILL_PRESENT,)), Verdict.FAILED),
    ("partially fixed", RunObservation((Outcome.PARTIALLY_FIXED,)), Verdict.FAILED),
    ("evasion by suppression", RunObservation((Outcome.SUPPRESSED,)), Verdict.FAILED),
    ("resource deleted, not permitted", RunObservation((Outcome.RESOURCE_DELETED,)),
     Verdict.FAILED),
    ("resource deleted, permitted by trusted policy",
     RunObservation((Outcome.RESOURCE_DELETED,),
                    permitted_outcomes=frozenset({Outcome.RESOURCE_DELETED})),
     Verdict.VERIFIED),
    ("policy drift", RunObservation((Outcome.FIXED,), policy_drift=True), Verdict.FAILED),
    ("scanner error", RunObservation((Outcome.SCANNER_ERROR,)), Verdict.INCONCLUSIVE),
    ("ruleset drift", RunObservation((Outcome.RULE_OR_SCANNER_DRIFT,)),
     Verdict.INCONCLUSIVE),
    ("inconclusive target", RunObservation((Outcome.INCONCLUSIVE,)), Verdict.INCONCLUSIVE),
    ("integrity failure outranks a real defect",
     RunObservation((Outcome.STILL_PRESENT,), required_scanner_integrity_ok=False),
     Verdict.INCONCLUSIVE),
    ("validator failure", RunObservation((Outcome.FIXED,), required_validators_pass=False),
     Verdict.INCONCLUSIVE),
    ("regression policy failure",
     RunObservation((Outcome.FIXED,), regression_policy_pass=False), Verdict.FAILED),
    ("oracle failure", RunObservation((Outcome.FIXED,), required_oracles_pass=False),
     Verdict.FAILED),
]


@pytest.mark.parametrize("name,run,expected", VERDICT_TABLE,
                         ids=[row[0] for row in VERDICT_TABLE])
def test_verdict_decision_table(name: str, run: RunObservation, expected: Verdict) -> None:
    assert decide(run) is expected


def test_operational_failure_never_reports_verified_or_failed() -> None:
    """A broken run must not masquerade as either a pass or a real negative."""
    for outcome in (Outcome.SCANNER_ERROR, Outcome.RULE_OR_SCANNER_DRIFT,
                    Outcome.INCONCLUSIVE):
        assert decide(RunObservation((outcome,))) is Verdict.INCONCLUSIVE


def test_exit_codes_match_the_specification() -> None:
    assert EXIT_CODES[Verdict.VERIFIED] == 0
    assert EXIT_CODES[Verdict.FAILED] == 1
    assert EXIT_CODES[Verdict.INCONCLUSIVE] == 3


def test_every_verdict_is_reachable() -> None:
    produced = {decide(run) for _, run, _ in VERDICT_TABLE}
    assert produced == set(Verdict)
