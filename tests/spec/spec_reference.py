"""Reference model of docs/spec/VERIFICATION_SEMANTICS.md §4, §5.2, and §7.

This is **not** product code and nothing in `src/` may import it. It exists so the
specification's predicates can be executed and tested before Phase D writes the engine,
and so Phase D has an oracle to conform to. If this model and the document disagree,
the document is authoritative and this file is the defect.

Deliberately written as a flat transcription of the ordering rules rather than as
clever code: its value is that a reader can diff it against the tables in the
specification line by line.

Two corrections applied after review:

* validators and oracles carry the full `Status` vocabulary, not booleans, because
  "definitively invalid" and "could not be checked" must not produce the same verdict;
* oracle results are no longer part of the target-outcome predicate. Keeping them there
  made the whole-run rule "required oracle failed ⇒ FAILED" unreachable, because the
  classifier would never have emitted `FIXED` in the first place.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    PARTIAL = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"


#: Gate states that mean "we could not establish anything", per §7.
UNDECIDED_STATES = frozenset(
    {Status.ERROR, Status.TIMEOUT, Status.UNSUPPORTED, Status.PARTIAL,
     Status.INCONCLUSIVE, Status.SKIPPED}
)


class Outcome(str, Enum):
    FIXED = "FIXED"
    STILL_PRESENT = "STILL_PRESENT"
    PARTIALLY_FIXED = "PARTIALLY_FIXED"
    SUPPRESSED = "SUPPRESSED"
    RESOURCE_DELETED = "RESOURCE_DELETED"
    FILE_DELETED_OR_RENAMED = "FILE_DELETED_OR_RENAMED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    RULE_OR_SCANNER_DRIFT = "RULE_OR_SCANNER_DRIFT"
    SCANNER_ERROR = "SCANNER_ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


# --------------------------------------------------------------------------- #
# §4  target classification: structural and scanner evidence only
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TargetObservation:
    """Everything the classifier may look at. Note the absence of oracle state."""

    baseline_occurrences: int          # N, >= 1 by construction
    candidate_matches: int             # M, at EXACT or RELOCATED tier
    scanner_integrity_ok: bool = True
    scanner_ruleset_stable: bool = True
    artifact_structurally_eligible: bool = True
    target_file_present: bool = True
    target_resource_present: bool = True
    suppression_covering_scope_added: bool = False
    occurrence_evidence_sufficient: bool = True


def classify(obs: TargetObservation) -> Outcome:
    """Ordered evaluation exactly as specified in §4.1."""
    if not obs.scanner_integrity_ok:
        return Outcome.SCANNER_ERROR
    if not obs.scanner_ruleset_stable:
        return Outcome.RULE_OR_SCANNER_DRIFT
    if not obs.artifact_structurally_eligible:
        return Outcome.OUT_OF_SCOPE
    if not obs.target_file_present:
        return Outcome.FILE_DELETED_OR_RENAMED
    if not obs.target_resource_present:
        return Outcome.RESOURCE_DELETED
    if obs.candidate_matches == 0 and obs.suppression_covering_scope_added:
        return Outcome.SUPPRESSED

    # Evidence sufficiency gates every count-based outcome. A classification computed
    # from counts we do not trust would be a guess wearing a label.
    if not obs.occurrence_evidence_sufficient:
        return Outcome.INCONCLUSIVE

    n, m = obs.baseline_occurrences, obs.candidate_matches
    if n > 1 and 0 < m < n:
        return Outcome.PARTIALLY_FIXED
    if m >= n or (n == 1 and m == 1):
        return Outcome.STILL_PRESENT
    return Outcome.FIXED


INCONCLUSIVE_OUTCOMES = frozenset(
    {Outcome.SCANNER_ERROR, Outcome.RULE_OR_SCANNER_DRIFT, Outcome.INCONCLUSIVE}
)
PASSING_OUTCOMES = frozenset({Outcome.FIXED})


# --------------------------------------------------------------------------- #
# §5.2  location change is a metadata delta, not a tier subtraction
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FindingLocation:
    file_path: str
    start_line: int
    end_line: int


def location_changed(
    baseline: FindingLocation, candidate: FindingLocation, identity_matched: bool
) -> bool:
    """True when a matched finding moved.

    Independent of the identity tier on purpose: line numbers are excluded from the
    EXACT key, so a line-only move still matches EXACT and could never be detected by
    "RELOCATED but not EXACT".
    """
    if not identity_matched:
        return False
    return (
        baseline.file_path != candidate.file_path
        or baseline.start_line != candidate.start_line
        or baseline.end_line != candidate.end_line
    )


# --------------------------------------------------------------------------- #
# §7  whole-run verdict, with typed gate states
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RunObservation:
    target_outcomes: tuple[Outcome, ...]
    required_validator_states: tuple[Status, ...] = (Status.PASS,)
    required_oracle_states: tuple[Status, ...] = ()
    required_scanner_integrity: Status = Status.PASS
    coverage_decreased_on_required_scanner: bool = False
    rule_substituted_on_required_target: bool = False
    policy_drift: bool = False
    regression_policy: Status = Status.PASS
    suppression_policy: Status = Status.PASS
    preflight: Status = Status.PASS
    permitted_outcomes: frozenset = field(default_factory=frozenset)


def decide(run: RunObservation) -> Verdict:
    """Inconclusive dominates failure: a broken run establishes nothing either way."""
    undecided = (
        run.preflight is not Status.PASS
        or run.required_scanner_integrity is not Status.PASS
        or any(s in UNDECIDED_STATES for s in run.required_validator_states)
        or any(s in UNDECIDED_STATES for s in run.required_oracle_states)
        or any(o in INCONCLUSIVE_OUTCOMES for o in run.target_outcomes)
        or run.coverage_decreased_on_required_scanner
        or run.rule_substituted_on_required_target
    )
    if undecided:
        return Verdict.INCONCLUSIVE

    unresolved = [
        o for o in run.target_outcomes
        if o not in PASSING_OUTCOMES and o not in run.permitted_outcomes
    ]
    failed = (
        Status.FAIL in run.required_validator_states
        or Status.FAIL in run.required_oracle_states
        or run.policy_drift
        or bool(unresolved)
        or run.regression_policy is not Status.PASS
        or run.suppression_policy is not Status.PASS
    )
    return Verdict.FAILED if failed else Verdict.VERIFIED


EXIT_CODES = {Verdict.VERIFIED: 0, Verdict.FAILED: 1, Verdict.INCONCLUSIVE: 3}
