"""Policy layer: trusted engine evidence plus trusted exceptions to a verdict."""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from datetime import date

from .engine import VerificationResult, require_trusted_verification_result
from .enums import (
    EXIT_CODES,
    INCONCLUSIVE_OUTCOMES,
    PASSING_OUTCOMES,
    TRUSTED_EXCEPTION_ORIGINS,
    UNDECIDED_STATES,
    ExceptionOrigin,
    Outcome,
    Status,
    Verdict,
)
from .models import (
    DomainError,
    ExceptionPolicy,
    TargetDecision,
    coerce_exception_policy,
    permission_rejection_reason,
    require_date,
    require_enum,
    require_exact_type,
)


_TRUSTED_POLICY_CONTEXT = object()
_OPTIONAL_GATE_NAMES = frozenset({"regression", "suppression"})


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """Trusted engine evidence and protected policy inputs.

    Caller-authored scanner or delta evidence cannot enter this object because the
    engine result must carry the private D5 factory provenance.
    """

    verification: VerificationResult
    evaluation_date: date
    exceptions: object = None
    optional_gates: frozenset = frozenset()
    optional_gates_origin: ExceptionOrigin = ExceptionOrigin.UNKNOWN

    def __post_init__(self) -> None:
        require_trusted_verification_result(self.verification)
        require_date(self.evaluation_date, "evaluation_date")
        object.__setattr__(self, "exceptions", coerce_exception_policy(self.exceptions))
        if type(self.optional_gates) is not frozenset:
            raise DomainError("optional_gates must be an exact frozenset")
        if any(type(item) is not str for item in self.optional_gates):
            raise DomainError("optional gate names must be exact strings")
        unknown = self.optional_gates - _OPTIONAL_GATE_NAMES
        if unknown:
            raise DomainError(f"unknown optional gates: {sorted(unknown)}")
        require_enum(self.optional_gates_origin, ExceptionOrigin, "optional_gates_origin")
        if self.optional_gates and self.optional_gates_origin not in TRUSTED_EXCEPTION_ORIGINS:
            raise DomainError("optional gates must originate in protected configuration")


def _permission_for(
    identity,
    outcome: Outcome,
    policy: ExceptionPolicy,
    evaluation_date: date,
) -> TargetDecision:
    matching = tuple(
        record for record in policy.records
        if record.target.canonical_key == identity.canonical_key
        and outcome in record.permitted_outcomes
    )
    rejection = ""
    for record in matching:
        attempted = TargetDecision(identity, outcome, True, record.exception_id)
        reason = permission_rejection_reason(attempted, policy, evaluation_date)
        if reason is None:
            return attempted
        if not rejection:
            rejection = reason
    if not rejection and matching:
        rejection = "no exception record is in force"
    elif not rejection and outcome is not Outcome.FIXED:
        rejection = "no trusted target-scoped exception authorises this outcome"
    return TargetDecision(identity, outcome, False, rejection_reason=rejection)


def _gate_undecided(status: Status, name: str, optional: frozenset) -> bool:
    if status is Status.SKIPPED and name in optional:
        return False
    return status in UNDECIDED_STATES


@dataclass(frozen=True, slots=True)
class PolicyResult:
    verdict: Verdict
    exit_code: int
    decisions: tuple
    evaluation_date: date
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_enum(self.verdict, Verdict, "verdict")
        if type(self.exit_code) is not int or self.exit_code != EXIT_CODES[self.verdict]:
            raise DomainError("exit_code does not match the closed verdict mapping")
        require_date(self.evaluation_date, "evaluation_date")
        if type(self.decisions) is not tuple or not self.decisions:
            raise DomainError("policy decisions must be a nonempty exact tuple")
        if any(type(item) is not TargetDecision for item in self.decisions):
            raise DomainError("policy decisions must contain exact TargetDecision values")
        keys = [item.identity.canonical_key for item in self.decisions]
        if len(keys) != len(set(keys)):
            raise DomainError("policy decisions contain duplicate target identities")
        if _trusted_context is not _TRUSTED_POLICY_CONTEXT:
            raise DomainError("PolicyResult requires trusted policy evaluation")
        object.__setattr__(self, "decisions", tuple(sorted(self.decisions, key=lambda x: x.canonical_key)))
        object.__setattr__(self, "_trusted", True)

    def canonical_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "evaluation_date": self.evaluation_date.isoformat(),
            "decisions": [item.canonical_dict() for item in self.decisions],
        }


def evaluate_policy(request: PolicyRequest) -> PolicyResult:
    """Evaluate the section-7 table, with uncertainty dominating a real failure."""
    require_exact_type(request, PolicyRequest, "policy request")
    engine = require_trusted_verification_result(request.verification)
    decisions = tuple(
        _permission_for(
            item.identity,
            item.outcome,
            request.exceptions,
            request.evaluation_date,
        )
        for item in engine.target_outcomes
    )
    undecided = (
        engine.preflight.status is not Status.PASS
        or engine.scanner_integrity.status is not Status.PASS
        or any(item.status in UNDECIDED_STATES for item in engine.validator_results)
        or any(item.status in UNDECIDED_STATES for item in engine.oracle_results)
        or any(item.outcome in INCONCLUSIVE_OUTCOMES for item in decisions)
        or engine.coverage_decreased_on_required_scanner
        or engine.rule_substituted_on_required_target
        or _gate_undecided(engine.regression.status, "regression", request.optional_gates)
        or _gate_undecided(engine.suppression.status, "suppression", request.optional_gates)
    )
    if undecided:
        verdict = Verdict.INCONCLUSIVE
    else:
        unresolved = tuple(
            item for item in decisions
            if item.outcome not in PASSING_OUTCOMES and not item.policy_permitted
        )
        failed = (
            any(item.status is Status.FAIL for item in engine.validator_results)
            or any(item.status is Status.FAIL for item in engine.oracle_results)
            or engine.policy_drift
            or bool(unresolved)
            or engine.regression.status is Status.FAIL
            or engine.suppression.status is Status.FAIL
        )
        verdict = Verdict.FAILED if failed else Verdict.VERIFIED
    return PolicyResult(
        verdict,
        EXIT_CODES[verdict],
        decisions,
        request.evaluation_date,
        _trusted_context=_TRUSTED_POLICY_CONTEXT,
    )


def require_trusted_policy_result(value: object) -> PolicyResult:
    require_exact_type(value, PolicyResult, "policy result")
    if not value._trusted:
        raise DomainError("policy result is caller-authored, not trusted policy evidence")
    return value


__all__ = [
    "PolicyRequest", "PolicyResult", "evaluate_policy", "require_trusted_policy_result",
]
