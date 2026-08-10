"""Reference model of docs/spec/VERIFICATION_SEMANTICS.md §2.5, §4, §5.2, and §7.

This is **not** product code and nothing in `src/` may import it. It exists so the
specification's rules can be executed and tested before Phase D writes the engine, and
so Phase D has a conformance oracle. If this model and the document disagree, the
document is authoritative and this file is the defect.

`TargetObservation`'s booleans are a *specification convenience* for expressing
scenarios compactly. Product code must not collapse scanner `ERROR`, `TIMEOUT`,
`PARTIAL`, `UNSUPPORTED` and `INCONCLUSIVE` into one boolean: `ScannerRun`,
`GateResult`, validator results and integrity results carry the full `Status` value
through to report generation.

Fail-open behaviours removed after review, each with regression probes:

* required gate evidence no longer defaults to `PASS`. A caller that supplies no
  preflight, integrity, validator or policy evidence gets `InvalidVerificationRequest`,
  not `VERIFIED`.
* runtime types are enforced. Annotations are not validation: `"PASS"`, `"BOGUS"`,
  `"false"` and `0` previously flowed through to `VERIFIED` or to a misclassification,
  because an unknown string is neither in `UNDECIDED_STATES` nor equal to `Status.FAIL`.
* `evaluation_date` must be supplied by the trusted execution context. A hardcoded
  default kept exceptions valid years past their expiry.
* exception records carry `created`, their mapping key must equal their id, blank
  identities and scopes are rejected, and trusted provenance is **stamped by the
  loader** rather than believed because a record says `origin: trusted_base`.
* the exception collection is copied and frozen at construction, so mutating the
  caller's dictionary can no longer change an existing verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping


class SpecDomainError(ValueError):
    """Input outside the specified domain. Never classified, always raised."""


class InvalidVerificationRequest(SpecDomainError):
    """A request that cannot be verified at all. CLI exit code 2."""


class _Required:
    """Sentinel for evidence the caller must supply explicitly."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<REQUIRED>"


REQUIRED: Any = _Required()


# --------------------------------------------------------------------------- #
# runtime validation helpers: annotations are not checks
# --------------------------------------------------------------------------- #
def _require_bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise SpecDomainError(
            f"{name} must be a bool, got {type(value).__name__} {value!r}: "
            f"a truthy string such as 'false' would otherwise read as True"
        )
    return value


def _require_int(value: Any, name: str) -> int:
    if type(value) is not int:
        raise SpecDomainError(f"{name} must be an int, got {type(value).__name__} {value!r}")
    return value


def _require_date(value: Any, name: str) -> date:
    if isinstance(value, datetime) or type(value) is not date:
        raise SpecDomainError(
            f"{name} must be a datetime.date, got {type(value).__name__} {value!r}"
        )
    return value


def _require_enum(value: Any, enum_cls: type, name: str):
    if not isinstance(value, enum_cls):
        raise SpecDomainError(
            f"{name} must be a {enum_cls.__name__} member, got "
            f"{type(value).__name__} {value!r}. Malformed input is an invalid request, "
            f"never PASS."
        )
    return value


def _require_supplied(value: Any, name: str):
    if isinstance(value, _Required):
        raise InvalidVerificationRequest(
            f"{name} is required evidence and was not supplied. Required gate evidence "
            f"is never synthesised as PASS: absence of evidence is not evidence."
        )
    return value


def _require_nonblank(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SpecDomainError(f"{name} must be a non-blank string, got {value!r}")
    return value.strip()


def canonical_scope(raw: Any, name: str = "scope") -> str:
    """One documented canonical form, so scope comparison is not raw string luck."""
    text = _require_nonblank(raw, name)
    if "\\" in text:
        raise SpecDomainError(f"{name} must not contain a backslash: {raw!r}")
    if text.startswith("/"):
        raise SpecDomainError(f"{name} must be relative, not absolute: {raw!r}")
    parts = [p for p in text.split("/")]
    if any(p in ("", ".", "..") for p in parts):
        raise SpecDomainError(f"{name} must be normalised, got {raw!r}")
    return "/".join(parts)


# --------------------------------------------------------------------------- #
# vocabulary
# --------------------------------------------------------------------------- #
class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    PARTIAL = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"


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


class ExceptionOrigin(str, Enum):
    """Where a policy record came from. Stamped by the loader, never self-declared."""

    OPERATOR = "operator"
    PROTECTED_POLICY_REPO = "protected_policy_repo"
    TRUSTED_BASE = "trusted_base"
    CANDIDATE_HEAD = "candidate_head"
    UNKNOWN = "unknown"


TRUSTED_EXCEPTION_ORIGINS = frozenset(
    {ExceptionOrigin.OPERATOR, ExceptionOrigin.PROTECTED_POLICY_REPO,
     ExceptionOrigin.TRUSTED_BASE}
)

PERMITTABLE_EXCEPTION_OUTCOMES = frozenset({
    Outcome.SUPPRESSED, Outcome.RESOURCE_DELETED, Outcome.FILE_DELETED_OR_RENAMED,
})
NEVER_PERMITTABLE_OUTCOMES = frozenset({
    Outcome.STILL_PRESENT, Outcome.PARTIALLY_FIXED, Outcome.SCANNER_ERROR,
    Outcome.RULE_OR_SCANNER_DRIFT, Outcome.INCONCLUSIVE, Outcome.OUT_OF_SCOPE,
})
INCONCLUSIVE_OUTCOMES = frozenset(
    {Outcome.SCANNER_ERROR, Outcome.RULE_OR_SCANNER_DRIFT, Outcome.INCONCLUSIVE}
)
PASSING_OUTCOMES = frozenset({Outcome.FIXED})

#: Gates that trusted policy may declare optional. Closed on purpose.
OPTIONAL_GATE_NAMES = frozenset({"regression", "suppression"})


# --------------------------------------------------------------------------- #
# §4  target classification
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TargetObservation:
    baseline_occurrences: int
    candidate_matches: int
    scanner_integrity_ok: bool = True
    scanner_ruleset_stable: bool = True
    artifact_structurally_eligible: bool = True
    target_file_present: bool = True
    target_resource_present: bool = True
    suppression_covering_scope_added: bool = False
    occurrence_evidence_sufficient: bool = True

    def __post_init__(self) -> None:
        n = _require_int(self.baseline_occurrences, "baseline_occurrences")
        m = _require_int(self.candidate_matches, "candidate_matches")
        if n < 1:
            raise SpecDomainError(
                f"baseline_occurrences (N) must be >= 1, got {n}: a target exists "
                f"because the baseline had at least one occurrence"
            )
        if m < 0:
            raise SpecDomainError(f"candidate_matches (M) must be >= 0, got {m}")
        for name in ("scanner_integrity_ok", "scanner_ruleset_stable",
                     "artifact_structurally_eligible", "target_file_present",
                     "target_resource_present", "suppression_covering_scope_added",
                     "occurrence_evidence_sufficient"):
            _require_bool(getattr(self, name), name)


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
    if not obs.occurrence_evidence_sufficient:
        return Outcome.INCONCLUSIVE

    n, m = obs.baseline_occurrences, obs.candidate_matches
    if n > 1 and 0 < m < n:
        return Outcome.PARTIALLY_FIXED
    if m >= n or (n == 1 and m == 1):
        return Outcome.STILL_PRESENT
    return Outcome.FIXED


# --------------------------------------------------------------------------- #
# §2.5  exceptions
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ExceptionRecord:
    exception_id: str
    target_id: str
    scope: str
    reason: str
    owner: str
    created: date
    expires: date
    origin: ExceptionOrigin

    def __post_init__(self) -> None:
        object.__setattr__(self, "exception_id",
                           _require_nonblank(self.exception_id, "exception_id"))
        object.__setattr__(self, "target_id",
                           _require_nonblank(self.target_id, "target_id"))
        object.__setattr__(self, "scope", canonical_scope(self.scope, "exception scope"))
        object.__setattr__(self, "reason", _require_nonblank(self.reason, "reason"))
        object.__setattr__(self, "owner", _require_nonblank(self.owner, "owner"))
        _require_date(self.created, "created")
        _require_date(self.expires, "expires")
        _require_enum(self.origin, ExceptionOrigin, "origin")
        if self.created > self.expires:
            raise SpecDomainError(
                f"exception {self.exception_id}: created {self.created} is after "
                f"expires {self.expires}"
            )


def load_trusted_exception(record: Mapping[str, Any],
                           origin: ExceptionOrigin) -> ExceptionRecord:
    """Build a record from a trusted source, stamping the origin.

    The origin argument comes from the loader that read the bytes, not from the record.
    A serialised `origin: trusted_base` field is ignored entirely.
    """
    _require_enum(origin, ExceptionOrigin, "origin")
    if origin not in TRUSTED_EXCEPTION_ORIGINS:
        raise SpecDomainError(f"{origin} is not a trusted origin")
    return _build(record, origin)


def load_candidate_exception(record: Mapping[str, Any]) -> ExceptionRecord:
    """Build a record read from the evaluated change. Always stamped untrusted."""
    return _build(record, ExceptionOrigin.CANDIDATE_HEAD)


def _build(record: Mapping[str, Any], origin: ExceptionOrigin) -> ExceptionRecord:
    if not isinstance(record, Mapping):
        raise SpecDomainError("exception record must be a mapping")
    unknown = set(record) - {
        "exception_id", "target_id", "scope", "reason", "owner", "created", "expires",
        "origin",
    }
    if unknown:
        raise SpecDomainError(f"unknown exception fields: {sorted(unknown)}")
    return ExceptionRecord(
        exception_id=record.get("exception_id", ""),
        target_id=record.get("target_id", ""),
        scope=record.get("scope", ""),
        reason=record.get("reason", ""),
        owner=record.get("owner", ""),
        created=record.get("created"),
        expires=record.get("expires"),
        origin=origin,  # deliberately not record["origin"]
    )


class ExceptionPolicy:
    """Deeply immutable, validated set of exception records.

    A frozen dataclass holding a caller's `dict` is not immutable: clearing that dict
    changed an existing verdict from VERIFIED to FAILED. Records are copied here and
    exposed only through a read-only mapping.
    """

    __slots__ = ("_records", "_index")

    def __init__(self, records: Iterable[ExceptionRecord] | Mapping[str, ExceptionRecord] = ()):
        if isinstance(records, Mapping):
            for key, record in records.items():
                if not isinstance(record, ExceptionRecord):
                    raise SpecDomainError(
                        f"exception {key!r} must be an ExceptionRecord, got "
                        f"{type(record).__name__}"
                    )
                if key != record.exception_id:
                    raise SpecDomainError(
                        f"exception mapping key {key!r} does not match record id "
                        f"{record.exception_id!r}: an index that disagrees with its "
                        f"records is not a policy"
                    )
            items = tuple(records.values())
        else:
            items = tuple(records)
            for record in items:
                if not isinstance(record, ExceptionRecord):
                    raise SpecDomainError(
                        f"expected ExceptionRecord, got {type(record).__name__}"
                    )

        ids = [r.exception_id for r in items]
        if len(set(ids)) != len(ids):
            raise SpecDomainError(f"duplicate exception ids: {sorted(ids)}")
        self._records = items
        self._index = MappingProxyType({r.exception_id: r for r in items})

    def get(self, exception_id: str | None) -> ExceptionRecord | None:
        return self._index.get(exception_id or "")

    @property
    def records(self) -> tuple[ExceptionRecord, ...]:
        return self._records

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ExceptionPolicy({sorted(self._index)})"


@dataclass(frozen=True)
class TargetDecision:
    target_id: str
    outcome: Outcome
    target_scope: str = "unspecified/scope"
    policy_permitted: bool = False
    exception_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_id",
                           _require_nonblank(self.target_id, "target_id"))
        object.__setattr__(self, "target_scope",
                           canonical_scope(self.target_scope, "target_scope"))
        _require_enum(self.outcome, Outcome, "outcome")
        _require_bool(self.policy_permitted, "policy_permitted")
        if self.exception_id is not None:
            object.__setattr__(self, "exception_id",
                               _require_nonblank(self.exception_id, "exception_id"))
        if self.policy_permitted and not self.exception_id:
            raise SpecDomainError(
                f"target {self.target_id}: policy_permitted requires an exception_id; "
                f"a permission with no record is not an approval"
            )


def permission_rejection_reason(
    decision: TargetDecision, policy: ExceptionPolicy, evaluation_date: date
) -> str | None:
    """Why this permission does not hold, or None when it does."""
    _require_date(evaluation_date, "evaluation_date")
    if not decision.policy_permitted:
        return "not claimed"
    if decision.outcome in NEVER_PERMITTABLE_OUTCOMES:
        return f"{decision.outcome.value} is never exception-eligible"
    if decision.outcome not in PERMITTABLE_EXCEPTION_OUTCOMES:
        return f"{decision.outcome.value} is not in the exception-eligible set"
    record = policy.get(decision.exception_id)
    if record is None:
        return f"exception {decision.exception_id!r} not found in the trusted policy"
    if record.target_id != decision.target_id:
        return (f"exception {record.exception_id} binds target {record.target_id!r}, "
                f"not {decision.target_id!r}")
    if record.scope != decision.target_scope:
        return (f"exception {record.exception_id} scope {record.scope!r} does not match "
                f"target scope {decision.target_scope!r}")
    if record.origin not in TRUSTED_EXCEPTION_ORIGINS:
        return (f"exception {record.exception_id} origin {record.origin.value!r} is not "
                f"trusted; a self-granted approval is not an approval")
    if record.created > evaluation_date:
        return (f"exception {record.exception_id} is not yet in force: created "
                f"{record.created.isoformat()}")
    if record.expires < evaluation_date:
        return f"exception {record.exception_id} expired on {record.expires.isoformat()}"
    return None


def is_permitted(decision: TargetDecision, policy: ExceptionPolicy,
                 evaluation_date: date) -> bool:
    return permission_rejection_reason(decision, policy, evaluation_date) is None


# --------------------------------------------------------------------------- #
# §5.2  location change
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FindingLocation:
    file_path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_path",
                           canonical_scope(self.file_path, "file_path"))
        start = _require_int(self.start_line, "start_line")
        end = _require_int(self.end_line, "end_line")
        if start < 1:
            raise SpecDomainError(f"start_line must be >= 1, got {start}")
        if end < start:
            raise SpecDomainError(f"end_line {end} must be >= start_line {start}")


def location_changed(baseline: FindingLocation, candidate: FindingLocation,
                     identity_matched: bool) -> bool:
    """True when a matched finding moved. Independent of the identity tier."""
    _require_bool(identity_matched, "identity_matched")
    if not identity_matched:
        return False
    return (baseline.file_path != candidate.file_path
            or baseline.start_line != candidate.start_line
            or baseline.end_line != candidate.end_line)


# --------------------------------------------------------------------------- #
# §7  whole-run verdict
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RunObservation:
    target_decisions: tuple[TargetDecision, ...]
    evaluation_date: date = REQUIRED
    preflight: Status = REQUIRED
    required_scanner_integrity: Status = REQUIRED
    required_validator_states: tuple[Status, ...] = REQUIRED
    regression_policy: Status = REQUIRED
    suppression_policy: Status = REQUIRED
    required_oracle_states: tuple[Status, ...] = ()
    exceptions: Any = field(default_factory=ExceptionPolicy)
    coverage_decreased_on_required_scanner: bool = False
    rule_substituted_on_required_target: bool = False
    policy_drift: bool = False
    optional_gates: frozenset = field(default_factory=frozenset)
    optional_gates_origin: ExceptionOrigin = ExceptionOrigin.UNKNOWN

    def __post_init__(self) -> None:
        if not isinstance(self.target_decisions, tuple) or not self.target_decisions:
            raise InvalidVerificationRequest(
                "a verification request must name at least one target as a tuple; a run "
                "with no targets verifies nothing and must not report VERIFIED. Use the "
                "scan command for target-free scanning."
            )
        for decision in self.target_decisions:
            if not isinstance(decision, TargetDecision):
                raise SpecDomainError(
                    f"target_decisions must contain TargetDecision, got "
                    f"{type(decision).__name__}"
                )
        ids = [d.target_id for d in self.target_decisions]
        if len(set(ids)) != len(ids):
            raise SpecDomainError(f"duplicate target_id in request: {sorted(ids)}")

        _require_date(_require_supplied(self.evaluation_date, "evaluation_date"),
                      "evaluation_date")
        for name in ("preflight", "required_scanner_integrity", "regression_policy",
                     "suppression_policy"):
            _require_enum(_require_supplied(getattr(self, name), name), Status, name)

        validators = _require_supplied(self.required_validator_states,
                                       "required_validator_states")
        if not isinstance(validators, tuple) or not validators:
            raise InvalidVerificationRequest(
                "at least one required validator result is needed: validity must be "
                "established independently of the security scanner (V1), and an empty "
                "collection would satisfy the gate vacuously"
            )
        for state in validators:
            _require_enum(state, Status, "required_validator_states entry")
        if not isinstance(self.required_oracle_states, tuple):
            raise SpecDomainError("required_oracle_states must be a tuple")
        for state in self.required_oracle_states:
            _require_enum(state, Status, "required_oracle_states entry")

        for name in ("coverage_decreased_on_required_scanner",
                     "rule_substituted_on_required_target", "policy_drift"):
            _require_bool(getattr(self, name), name)

        # Copy and freeze the policy so a later mutation of the caller's collection
        # cannot change this run's verdict.
        policy = self.exceptions
        if not isinstance(policy, ExceptionPolicy):
            policy = ExceptionPolicy(policy)
        object.__setattr__(self, "exceptions", policy)

        gates = self.optional_gates
        if not isinstance(gates, (frozenset, set)):
            raise SpecDomainError("optional_gates must be a set of gate names")
        unknown = set(gates) - OPTIONAL_GATE_NAMES
        if unknown:
            raise SpecDomainError(
                f"unknown optional gate(s) {sorted(unknown)}; permitted: "
                f"{sorted(OPTIONAL_GATE_NAMES)}"
            )
        object.__setattr__(self, "optional_gates", frozenset(gates))
        _require_enum(self.optional_gates_origin, ExceptionOrigin,
                      "optional_gates_origin")
        if gates and self.optional_gates_origin not in TRUSTED_EXCEPTION_ORIGINS:
            raise SpecDomainError(
                "optional_gates must come from a trusted configuration source; "
                f"got origin {self.optional_gates_origin.value!r}"
            )


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
        or _policy_state_is_undecided(run.regression_policy, "regression",
                                      run.optional_gates)
        or _policy_state_is_undecided(run.suppression_policy, "suppression",
                                      run.optional_gates)
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
