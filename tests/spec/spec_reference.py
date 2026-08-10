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

import re
import unicodedata
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


#: Placeholders that must never stand in for a real identity or scope. A generic
#: default was previously accepted as an exact exception match, so an omitted scope
#: could authorise a deletion.
RESERVED_PLACEHOLDERS = frozenset({
    "unspecified", "unspecified/scope", "unknown", "unknown/scope",
    "default", "default/scope", "n/a", "na", "none", "null", "-", "todo", "tbd",
})

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def _reject_dangerous_characters(text: str, name: str) -> None:
    if "\x00" in text:
        raise SpecDomainError(f"{name} must not contain a NUL byte")
    bad = {ch for ch in text if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp")}
    if bad:
        raise SpecDomainError(
            f"{name} must not contain control characters or line breaks: "
            f"found {sorted(hex(ord(c)) for c in bad)}"
        )


def _normalise(raw: Any, name: str) -> str:
    """NFC-normalise and strip, so duplicate checks compare like with like."""
    text = _require_nonblank(raw, name)
    text = unicodedata.normalize("NFC", text)
    _reject_dangerous_characters(text, name)
    return text.strip()


def canonical_identifier(raw: Any, name: str) -> str:
    """A target id, exception id, or gate id.

    Identifiers are not paths: slashes and dots are allowed as opaque characters, but
    the value must be a single normalised token with no control characters, and must
    not be a reserved placeholder.
    """
    text = _normalise(raw, name)
    if text.lower() in RESERVED_PLACEHOLDERS:
        raise SpecDomainError(
            f"{name} must not be the placeholder {text!r}; a generic identity is not an "
            f"identity"
        )
    return text


def canonical_resource_scope(raw: Any, name: str = "scope") -> str:
    """A target or exception scope: a resource address or object identity.

    Examples: `aws_s3_bucket.data`, `module.net.aws_security_group.web[0]`,
    `apps/v1/Deployment/prod/api`. Deliberately separate from repository paths: a
    resource address is not a filename, and using one helper for both is how a
    placeholder slipped through.
    """
    text = _normalise(raw, name)
    if text.lower() in RESERVED_PLACEHOLDERS:
        raise SpecDomainError(
            f"{name} must not be the placeholder {text!r}: a deletion or suppression "
            f"must never be authorised by an unspecified scope"
        )
    if "\\" in text:
        raise SpecDomainError(f"{name} must not contain a backslash: {raw!r}")
    if text.startswith("/"):
        raise SpecDomainError(f"{name} must be relative, not absolute: {raw!r}")
    if _WINDOWS_DRIVE.match(text):
        raise SpecDomainError(f"{name} must not be a drive-absolute path: {raw!r}")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SpecDomainError(f"{name} must be normalised, got {raw!r}")
    return "/".join(parts)


def canonical_repo_path(raw: Any, name: str = "file_path") -> str:
    """A repository-relative file path."""
    text = _normalise(raw, name)
    if "\\" in text:
        raise SpecDomainError(f"{name} must use forward slashes: {raw!r}")
    if text.startswith("/"):
        raise SpecDomainError(f"{name} must be repository-relative, not absolute: {raw!r}")
    if _WINDOWS_DRIVE.match(text):
        raise SpecDomainError(f"{name} must not be a drive-absolute path: {raw!r}")
    if text.endswith("/"):
        raise SpecDomainError(f"{name} must name a file, not a directory: {raw!r}")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SpecDomainError(f"{name} must be normalised, got {raw!r}")
    return "/".join(parts)


#: Retained name for continuity in the specification text; resource scopes only.
canonical_scope = canonical_resource_scope


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
                           canonical_identifier(self.exception_id, "exception_id"))
        object.__setattr__(self, "target_id",
                           canonical_identifier(self.target_id, "target_id"))
        object.__setattr__(self, "scope",
                           canonical_resource_scope(self.scope, "exception scope"))
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


@dataclass(frozen=True, slots=True)
class ExceptionPolicy:
    """Deeply immutable, validated set of exception records.

    Two earlier attempts were not immutable enough:

    * a frozen dataclass holding the caller's `dict` — clearing that dict changed an
      existing verdict from VERIFIED to FAILED;
    * a `__slots__` class with a `MappingProxyType` index — the *object* was not
      frozen, so `policy._records = ()` still changed a stored verdict.

    This version is a frozen slotted dataclass. Normal attribute assignment raises,
    the record tuple is canonically sorted for deterministic serialisation, and the
    index is built once during construction.
    """

    records: tuple[ExceptionRecord, ...] = ()
    index: Mapping[str, ExceptionRecord] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        items = self.records
        if isinstance(items, Mapping):
            for key, record in items.items():
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
            items = tuple(items.values())
        else:
            items = tuple(items)
        for record in items:
            if type(record) is not ExceptionRecord:
                raise SpecDomainError(
                    f"expected ExceptionRecord, got {type(record).__name__}"
                )
        ids = [r.exception_id for r in items]
        if len(set(ids)) != len(ids):
            raise SpecDomainError(f"duplicate exception ids: {sorted(ids)}")

        # Canonical order, so two policies with the same records serialise identically.
        ordered = tuple(sorted(items, key=lambda r: r.exception_id))
        object.__setattr__(self, "records", ordered)
        object.__setattr__(self, "index",
                           MappingProxyType({r.exception_id: r for r in ordered}))

    def get(self, exception_id: str | None) -> ExceptionRecord | None:
        return self.index.get(exception_id or "")

    def __len__(self) -> int:
        return len(self.records)


def coerce_exception_policy(value: Any) -> ExceptionPolicy:
    """Always build a fresh policy; never retain a caller-owned object.

    A subclass or lookalike is rejected rather than trusted: `isinstance` would accept
    a subclass that overrides `get` or `index`.
    """
    if value is None:
        return ExceptionPolicy(())
    if type(value) is ExceptionPolicy:
        return ExceptionPolicy(value.records)          # defensive copy
    if isinstance(value, ExceptionPolicy):
        raise SpecDomainError(
            f"{type(value).__name__} is an ExceptionPolicy subclass; the public boundary "
            f"accepts only ExceptionPolicy itself or a collection of ExceptionRecord"
        )
    if isinstance(value, (Mapping, tuple, list, frozenset, set)):
        return ExceptionPolicy(value)
    raise SpecDomainError(
        f"exceptions must be an ExceptionPolicy or a collection of ExceptionRecord, got "
        f"{type(value).__name__}"
    )


@dataclass(frozen=True, slots=True)
class TargetDecision:
    target_id: str
    outcome: Outcome
    target_scope: str = REQUIRED          # no placeholder default, on purpose
    policy_permitted: bool = False
    exception_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_id",
                           canonical_identifier(self.target_id, "target_id"))
        _require_supplied(self.target_scope, "target_scope")
        object.__setattr__(self, "target_scope",
                           canonical_resource_scope(self.target_scope, "target_scope"))
        _require_enum(self.outcome, Outcome, "outcome")
        _require_bool(self.policy_permitted, "policy_permitted")
        if self.exception_id is not None:
            object.__setattr__(self, "exception_id",
                               canonical_identifier(self.exception_id, "exception_id"))
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
                           canonical_repo_path(self.file_path, "file_path"))
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
# gate identities: counting PASS results is not the same as covering the
# required gates
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class GateResult:
    """One named gate's typed outcome."""

    gate_id: str
    status: Status

    def __post_init__(self) -> None:
        object.__setattr__(self, "gate_id",
                           canonical_identifier(self.gate_id, "gate_id"))
        _require_enum(self.status, Status, f"status of gate {self.gate_id!r}")


@dataclass(frozen=True, slots=True)
class RequiredGates:
    """Which gates trusted configuration requires, by identity.

    Statuses alone are insufficient: one `PASS` cannot satisfy two required
    validators, and an unknown gate must not be able to stand in for a missing one.
    """

    validator_ids: tuple[str, ...] = REQUIRED
    oracle_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_supplied(self.validator_ids, "required_gates.validator_ids")
        for name in ("validator_ids", "oracle_ids"):
            raw = getattr(self, name)
            if not isinstance(raw, tuple):
                raise SpecDomainError(f"required_gates.{name} must be a tuple")
            ids = tuple(canonical_identifier(i, f"required_gates.{name} entry")
                        for i in raw)
            if len(set(ids)) != len(ids):
                raise SpecDomainError(
                    f"duplicate gate id in required_gates.{name}: {sorted(ids)}"
                )
            object.__setattr__(self, name, ids)
        if not self.validator_ids:
            raise InvalidVerificationRequest(
                "at least one required validator gate id is needed: validity must be "
                "established independently of the security scanner (V1)"
            )


def reconcile_gate_results(
    required_ids: tuple[str, ...], observed: tuple[GateResult, ...], kind: str
) -> tuple[Status, ...]:
    """Return the observed statuses in required order, or raise.

    Rejects a missing required gate, a duplicate result, and an unknown substituted
    gate. An empty observation set is valid only when nothing was required.
    """
    if not isinstance(observed, tuple):
        raise SpecDomainError(f"{kind} results must be a tuple")
    for result in observed:
        if type(result) is not GateResult:
            raise SpecDomainError(
                f"{kind} results must contain GateResult, got {type(result).__name__}"
            )
    seen = [r.gate_id for r in observed]
    duplicates = {gate for gate in seen if seen.count(gate) > 1}
    if duplicates:
        raise SpecDomainError(f"duplicate {kind} gate result(s): {sorted(duplicates)}")
    by_id = {r.gate_id: r for r in observed}
    missing = [gate for gate in required_ids if gate not in by_id]
    unknown = sorted(set(by_id) - set(required_ids))
    # Both facts are reported together: a substitution shows up as one missing gate and
    # one unrequired gate, and naming only the first hides what the caller actually did.
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"required {kind} gate(s) produced no result: {missing}")
        if unknown:
            parts.append(
                f"unrequired {kind} gate result(s) supplied: {unknown}; a substituted "
                f"gate cannot stand in for a required one"
            )
        raise InvalidVerificationRequest(
            "; ".join(parts) + ". Absence of evidence is not evidence."
        )
    return tuple(by_id[gate].status for gate in required_ids)


# --------------------------------------------------------------------------- #
# §7  whole-run verdict
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RunObservation:
    target_decisions: tuple[TargetDecision, ...]
    evaluation_date: date = REQUIRED
    preflight: Status = REQUIRED
    required_scanner_integrity: Status = REQUIRED
    required_gates: RequiredGates = REQUIRED
    validator_results: tuple[GateResult, ...] = REQUIRED
    regression_policy: Status = REQUIRED
    suppression_policy: Status = REQUIRED
    oracle_results: tuple[GateResult, ...] = ()
    exceptions: Any = field(default_factory=ExceptionPolicy)
    coverage_decreased_on_required_scanner: bool = False
    rule_substituted_on_required_target: bool = False
    policy_drift: bool = False
    optional_gates: frozenset = field(default_factory=frozenset)
    optional_gates_origin: ExceptionOrigin = ExceptionOrigin.UNKNOWN
    # derived during construction from required_gates + observed results
    _validator_states: tuple[Status, ...] = field(default=(), repr=False, compare=False)
    _oracle_states: tuple[Status, ...] = field(default=(), repr=False, compare=False)

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

        gates = _require_supplied(self.required_gates, "required_gates")
        if type(gates) is not RequiredGates:
            raise SpecDomainError(
                f"required_gates must be a RequiredGates, got {type(gates).__name__}"
            )
        observed_validators = _require_supplied(self.validator_results,
                                               "validator_results")
        validator_states = reconcile_gate_results(
            gates.validator_ids, observed_validators, "validator")
        oracle_states = reconcile_gate_results(
            gates.oracle_ids, self.oracle_results, "oracle")
        object.__setattr__(self, "_validator_states", validator_states)
        object.__setattr__(self, "_oracle_states", oracle_states)

        for name in ("coverage_decreased_on_required_scanner",
                     "rule_substituted_on_required_target", "policy_drift"):
            _require_bool(getattr(self, name), name)

        # Always rebuild: retaining a caller-owned ExceptionPolicy let a later
        # mutation of that object change this run's verdict.
        object.__setattr__(self, "exceptions", coerce_exception_policy(self.exceptions))

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


def validator_states(run: "RunObservation") -> tuple[Status, ...]:
    return getattr(run, "_validator_states")


def oracle_states(run: "RunObservation") -> tuple[Status, ...]:
    return getattr(run, "_oracle_states")


def _policy_state_is_undecided(state: Status, gate: str, optional: frozenset) -> bool:
    if state is Status.SKIPPED and gate in optional:
        return False
    return state in UNDECIDED_STATES


def decide(run: RunObservation) -> Verdict:
    """Inconclusive dominates failure: a broken run establishes nothing either way."""
    undecided = (
        run.preflight is not Status.PASS
        or run.required_scanner_integrity is not Status.PASS
        or any(s in UNDECIDED_STATES for s in validator_states(run))
        or any(s in UNDECIDED_STATES for s in oracle_states(run))
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
        Status.FAIL in validator_states(run)
        or Status.FAIL in oracle_states(run)
        or run.policy_drift
        or bool(unresolved)
        or run.regression_policy is Status.FAIL
        or run.suppression_policy is Status.FAIL
    )
    return Verdict.FAILED if failed else Verdict.VERIFIED


EXIT_CODES = {Verdict.VERIFIED: 0, Verdict.FAILED: 1, Verdict.INCONCLUSIVE: 3}
INVALID_REQUEST_EXIT_CODE = 2
