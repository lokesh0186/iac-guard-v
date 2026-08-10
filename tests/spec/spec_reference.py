"""Reference model of docs/spec/VERIFICATION_SEMANTICS.md §4 and §4.2.

This is **not** product code and nothing in `src/` may import it. It exists so the
specification's predicates can be executed and tested before Phase D writes the engine,
and so Phase D has an oracle to conform to. If this model and the document disagree,
the document is authoritative and this file is the defect.

Deliberately written as a flat, readable transcription of the ordering rule rather than
as clever code: its value is that a reader can diff it against the table in the
specification line by line.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


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


@dataclass(frozen=True)
class TargetObservation:
    """Everything the classifier is allowed to look at, per §4."""

    baseline_occurrences: int          # N, >= 1 by construction
    candidate_matches: int             # M, at EXACT or RELOCATED tier
    scanner_integrity_ok: bool = True
    scanner_ruleset_stable: bool = True
    artifact_structurally_eligible: bool = True
    target_file_present: bool = True
    target_resource_present: bool = True
    suppression_covering_scope_added: bool = False
    required_oracles_pass: bool = True
    evidence_sufficient: bool = True


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
    if not obs.evidence_sufficient:
        return Outcome.INCONCLUSIVE

    n, m = obs.baseline_occurrences, obs.candidate_matches
    if n > 1 and 0 < m < n:
        return Outcome.PARTIALLY_FIXED
    if m >= n or (n == 1 and m == 1):
        return Outcome.STILL_PRESENT
    if m == 0 and obs.required_oracles_pass:
        return Outcome.FIXED
    return Outcome.INCONCLUSIVE


# Outcomes that mean "we could not establish anything", per the §4.2 table.
INCONCLUSIVE_OUTCOMES = frozenset(
    {Outcome.SCANNER_ERROR, Outcome.RULE_OR_SCANNER_DRIFT, Outcome.INCONCLUSIVE}
)
PASSING_OUTCOMES = frozenset({Outcome.FIXED})


@dataclass(frozen=True)
class RunObservation:
    """Whole-run inputs for the §4.2 / §7 decision table."""

    target_outcomes: tuple[Outcome, ...]
    policy_drift: bool = False
    required_validators_pass: bool = True
    required_scanner_integrity_ok: bool = True
    regression_policy_pass: bool = True
    required_oracles_pass: bool = True
    permitted_outcomes: frozenset = field(default_factory=frozenset)


def decide(run: RunObservation) -> Verdict:
    """Whole-run verdict, per §7. Inconclusive dominates failure."""
    if not run.required_scanner_integrity_ok:
        return Verdict.INCONCLUSIVE
    if any(o in INCONCLUSIVE_OUTCOMES for o in run.target_outcomes):
        return Verdict.INCONCLUSIVE
    if not run.required_validators_pass:
        return Verdict.INCONCLUSIVE

    # POLICY_DRIFT is a definite negative result about the change, not missing evidence.
    if run.policy_drift:
        return Verdict.FAILED
    unresolved = [
        o for o in run.target_outcomes
        if o not in PASSING_OUTCOMES and o not in run.permitted_outcomes
    ]
    if unresolved or not run.regression_policy_pass or not run.required_oracles_pass:
        return Verdict.FAILED
    return Verdict.VERIFIED


EXIT_CODES = {Verdict.VERIFIED: 0, Verdict.FAILED: 1, Verdict.INCONCLUSIVE: 3}
