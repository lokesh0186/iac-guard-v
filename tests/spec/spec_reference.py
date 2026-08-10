"""Reference model of docs/spec/VERIFICATION_SEMANTICS.md §4, §5.2, and §7.

This is **not** product code and nothing in `src/` may import it. It exists so the
specification's rules can be executed and tested before Phase D writes the engine, and
so Phase D has a conformance oracle. If this model and the document disagree, the
document is authoritative and this file is the defect.

Corrections applied after review, each with tests:

* validators, oracles, and policy gates carry the full `Status` vocabulary, because
  "definitively wrong" and "could not be checked" must not produce the same verdict;
* oracle results are not inputs to target classification (§4.3);
* **permissions are per target, not per outcome type.** A global
  `permitted_outcomes` set allowed one approved deletion to waive every deletion, and
  allowed `STILL_PRESENT` to be waived into `VERIFIED` — turning a known unresolved
  finding into a pass, which is the exact failure this project exists to prevent;
* only a closed set of outcomes is ever exception-eligible;
* the input domain is enforced: `N >= 1`, `M >= 0`, at least one target, at least one
  required validator. Invalid input raises rather than being classified.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum


class SpecDomainError(ValueError):
    """Input outside the specified domain. Never classified, always raised."""


class InvalidVerificationRequest(SpecDomainError):
    """A request that cannot be verified at all. CLI exit code 2."""


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    PARTIAL = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"


#: Gate states meaning "we could not establish anything" (§7 step 1).
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


#: Outcomes an organisation may knowingly accept through a trusted, target-scoped,
#: unexpired exception. Deliberately closed and deliberately small.
PERMITTABLE_EXCEPTION_OUTCOMES = frozenset({
    Outcome.SUPPRESSED,
    Outcome.RESOURCE_DELETED,
    Outcome.FILE_DELETED_OR_RENAMED,
})

#: Never waivable. The first two are unresolved defects; the rest are absences of
#: evidence, which cannot be approved into evidence.
NEVER_PERMITTABLE_OUTCOMES = frozenset({
    Outcome.STILL_PRESENT,
    Outcome.PARTIALLY_FIXED,
    Outcome.SCANNER_ERROR,
    Outcome.RULE_OR_SCANNER_DRIFT,
    Outcome.INCONCLUSIVE,
    Outcome.OUT_OF_SCOPE,
})

#: Where an exception may come from (§2.1). The candidate head is never trusted.
TRUSTED_EXCEPTION_ORIGINS = frozenset({"operator", "protected_policy_repo", "trusted_base"})
UNTRUSTED_EXCEPTION_ORIGIN = "candidate_head"

INCONCLUSIVE_OUTCOMES = frozenset(
    {Outcome.SCANNER_ERROR, Outcome.RULE_OR_SCANNER_DRIFT, Outcome.INCONCLUSIVE}
)
PASSING_OUTCOMES = frozenset({Outcome.FIXED})


# --------------------------------------------------------------------------- #
# §4  target classification: structural and scanner evidence only
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TargetObservation:
    """Everything the classifier may look at. Note the absence of oracle state."""

    baseline_occurrences: int          # N
    candidate_matches: int             # M
    scanner_integrity_ok: bool = True
    scanner_ruleset_stable: bool = True
    artifact_structurally_eligible: bool = True
    target_file_present: bool = True
    target_resource_present: bool = True
    suppression_covering_scope_added: bool = False
    occurrence_evidence_sufficient: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.baseline_occurrences, int) or isinstance(
            self.baseline_occurrences, bool
        ):
            raise SpecDomainError("baseline_occurrences must be an int")
        if not isinstance(self.candidate_matches, int) or isinstance(
            self.candidate_matches, bool
        ):
            raise SpecDomainError("candidate_matches must be an int")
        if self.baseline_occurrences < 1:
            raise SpecDomainError(
                f"baseline_occurrences (N) must be >= 1, got {self.baseline_occurrences}: "
                f"a target exists because the baseline had at least one occurrence"
            )
        if self.candidate_matches < 0:
            raise SpecDomainError(
                f"candidate_matches (M) must be >= 0, got {self.candidate_matches}"
            )


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

    # Evidence sufficiency gates every count-based outcome: a classification computed
    # from counts we do not trust would be a guess wearing a label.
    if not obs.occurrence_evidence_sufficient:
        return Outcome.INCONCLUSIVE

    n, m = obs.baseline_occurrences, obs.candidate_matches
    if n > 1 and 0 < m < n:
        return Outcome.PARTIALLY_FIXED
    if m >= n or (n == 1 and m == 1):
        return Outcome.STILL_PRESENT
    return Outcome.FIXED


# --------------------------------------------------------------------------- #
# §2.4  exceptions bind to one target
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ExceptionRecord:
    exception_id: str
    target_id: str
    scope: str
    reason: str
    owner: str
    expires: date
    origin: str = "trusted_base"


@dataclass(frozen=True)
class TargetDecision:
    target_id: str
    outcome: Outcome
    target_scope: str = ""
    policy_permitted: bool = False
    exception_id: str | None = None

    def __post_init__(self) -> None:
        if not self.target_id:
            raise SpecDomainError("target_id is required")
        if self.policy_permitted and not self.exception_id:
            raise SpecDomainError(
                f"target {self.target_id}: policy_permitted requires an exception_id; "
                f"a permission with no record is not an approval"
            )


def permission_rejection_reason(
    decision: TargetDecision,
    exceptions: dict[str, ExceptionRecord],
    evaluation_date: date,
) -> str | None:
    """Why this permission does not hold, or None when it does.

    Every clause exists because its absence would let something through:
    an outcome that must never be waived, an exception belonging to another target, a
    self-granted exception authored by the change under evaluation, or an expired one.
    """
    if not decision.policy_permitted:
        return "not claimed"
    if decision.outcome in NEVER_PERMITTABLE_OUTCOMES:
        return f"{decision.outcome.value} is never exception-eligible"
    if decision.outcome not in PERMITTABLE_EXCEPTION_OUTCOMES:
        return f"{decision.outcome.value} is not in the exception-eligible set"
    record = exceptions.get(decision.exception_id or "")
    if record is None:
        return f"exception {decision.exception_id!r} not found in the trusted policy"
    if record.target_id != decision.target_id:
        return (
            f"exception {record.exception_id} binds target {record.target_id!r}, "
            f"not {decision.target_id!r}"
        )
    if record.scope != decision.target_scope:
        return (
            f"exception {record.exception_id} scope {record.scope!r} does not match "
            f"target scope {decision.target_scope!r}"
        )
    if record.origin == UNTRUSTED_EXCEPTION_ORIGIN:
        return (
            f"exception {record.exception_id} originates in the evaluated change; "
            f"a self-granted approval is not an approval"
        )
    if record.origin not in TRUSTED_EXCEPTION_ORIGINS:
        return f"exception {record.exception_id} origin {record.origin!r} is not trusted"
    if not record.reason.strip():
        return f"exception {record.exception_id} has no reason"
    if not record.owner.strip():
        return f"exception {record.exception_id} has no owner"
    if record.expires < evaluation_date:
        return f"exception {record.exception_id} expired on {record.expires.isoformat()}"
    return None


def is_permitted(
    decision: TargetDecision,
    exceptions: dict[str, ExceptionRecord],
    evaluation_date: date,
) -> bool:
    return permission_rejection_reason(decision, exceptions, evaluation_date) is None


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
# §7  whole-run verdict
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RunObservation:
    target_decisions: tuple[TargetDecision, ...]
    exceptions: dict[str, ExceptionRecord] = field(default_factory=dict)
    evaluation_date: date = date(2026, 8, 9)
    required_validator_states: tuple[Status, ...] = (Status.PASS,)
    required_oracle_states: tuple[Status, ...] = ()
    required_scanner_integrity: Status = Status.PASS
    coverage_decreased_on_required_scanner: bool = False
    rule_substituted_on_required_target: bool = False
    policy_drift: bool = False
    regression_policy: Status = Status.PASS
    suppression_policy: Status = Status.PASS
    preflight: Status = Status.PASS
    optional_gates: frozenset = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.target_decisions:
            raise InvalidVerificationRequest(
                "a verification request must name at least one target; a run with no "
                "targets verifies nothing and must not report VERIFIED. Use the "
                "scan command for target-free scanning."
            )
        if not self.required_validator_states:
            raise InvalidVerificationRequest(
                "at least one required validator is needed: validity must be "
                "established independently of the security scanner (V1), and an empty "
                "validator set would satisfy the gate vacuously"
            )
        ids = [d.target_id for d in self.target_decisions]
        if len(set(ids)) != len(ids):
            raise SpecDomainError(f"duplicate target_id in request: {ids}")


def _policy_state_is_undecided(state: Status, gate: str, optional: frozenset) -> bool:
    if state is Status.SKIPPED and gate in optional:
        return False
    return state in UNDECIDED_STATES


def decide(run: RunObservation) -> Verdict:
    """Inconclusive dominates failure: a broken run establishes nothing either way."""
    undecided = (
        run.preflight is not Status.PASS
        or run.required_scanner_integrity is not Status.PASS
        or any(s in UNDECIDED_STATES for s in run.required_validator_states)
        or any(s in UNDECIDED_STATES for s in run.required_oracle_states)
        or any(d.outcome in INCONCLUSIVE_OUTCOMES for d in run.target_decisions)
        or run.coverage_decreased_on_required_scanner
        or run.rule_substituted_on_required_target
        or _policy_state_is_undecided(run.regression_policy, "regression", run.optional_gates)
        or _policy_state_is_undecided(run.suppression_policy, "suppression", run.optional_gates)
    )
    if undecided:
        return Verdict.INCONCLUSIVE

    unresolved = [
        d for d in run.target_decisions
        if d.outcome not in PASSING_OUTCOMES
        and not is_permitted(d, run.exceptions, run.evaluation_date)
    ]
    failed = (
        Status.FAIL in run.required_validator_states
        or Status.FAIL in run.required_oracle_states
        or run.policy_drift
        or bool(unresolved)
        or run.regression_policy is Status.FAIL
        or run.suppression_policy is Status.FAIL
    )
    return Verdict.FAILED if failed else Verdict.VERIFIED


EXIT_CODES = {Verdict.VERIFIED: 0, Verdict.FAILED: 1, Verdict.INCONCLUSIVE: 3}
INVALID_REQUEST_EXIT_CODE = 2
