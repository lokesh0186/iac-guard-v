"""Reference model of docs/spec/VERIFICATION_SEMANTICS.md §2.5–2.7, §4, §5.2, and §7.

This is **not** product code and nothing in `src/` may import it. It exists so the
specification's rules can be executed, and so the Phase-D engine has a conformance
oracle. If this model and the document disagree, the document is authoritative and this
file is the defect.

Threat boundary: this model defends against normal attribute reassignment, `__dict__`
mutation, mutable aliases retained from callers, behaviour-overriding subclasses, and
caller-owned collection mutation. It does **not** attempt to defend against trusted code
that deliberately calls `object.__setattr__` on a frozen instance — that is indistinguishable
from the constructor itself.

Fail-open behaviours removed, each with permanent probes:

* required gate evidence is explicit, never defaulted to `PASS`;
* runtime types are enforced, because annotations are not validation;
* evaluation time comes from the trusted execution context;
* exceptions bind to one target **and to the specific event they authorise** — one
  record previously authorised `SUPPRESSED`, `RESOURCE_DELETED` and
  `FILE_DELETED_OR_RENAMED` alike, so an approved suppression silently approved deleting
  the resource;
* every persistent value is frozen **and** slotted, so there is no `__dict__` to write
  through. `RunObservation.__dict__["policy_drift"] = True` previously flipped a stored
  verdict, and `TargetObservation.__dict__["candidate_matches"] = -1` produced a `FIXED`
  classification from an impossible state;
* nested records and target decisions are defensively **reconstructed**, not aliased: the
  policy container was rebuilt while the records inside it were shared, so mutating the
  caller's record changed a stored verdict;
* exact types are required at security boundaries, because `isinstance` accepts a
  subclass whose `outcome` property reports `FIXED` while it stores `STILL_PRESENT`.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field, fields
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

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<REQUIRED>"


REQUIRED: Any = _Required()

MAX_OWNER_LENGTH = 128
MAX_REASON_LENGTH = 512
MAX_IDENTIFIER_LENGTH = 256


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
    if type(value) is not enum_cls:
        raise SpecDomainError(
            f"{name} must be a {enum_cls.__name__} member, got "
            f"{type(value).__name__} {value!r}. Malformed input is an invalid request, "
            f"never PASS."
        )
    return value


def _require_exact_type(value: Any, expected: type, name: str):
    """Exact type, not isinstance.

    `isinstance` accepts a subclass that overrides behaviour — a `TargetDecision`
    subclass whose `outcome` property returns `FIXED` while it stores `STILL_PRESENT`
    reached `VERIFIED`.
    """
    if type(value) is not expected:
        raise SpecDomainError(
            f"{name} must be exactly {expected.__name__}, got {type(value).__name__}; "
            f"subclasses are rejected at security boundaries because they can override "
            f"behaviour"
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
    if type(value) is not str or not value.strip():
        raise SpecDomainError(f"{name} must be a non-blank string, got {value!r}")
    return value.strip()


#: Placeholders that must never stand in for a real identity or scope.
RESERVED_PLACEHOLDERS = frozenset({
    "unspecified", "unspecified/scope", "unknown", "unknown/scope",
    "default", "default/scope", "n/a", "na", "none", "null", "-", "todo", "tbd",
})

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
#: Unicode categories that must never appear in machine-compared values or report text:
#: control, format (includes bidi overrides), and line/paragraph separators.
_FORBIDDEN_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")


def _reject_dangerous_characters(text: str, name: str) -> None:
    if "\x00" in text:
        raise SpecDomainError(f"{name} must not contain a NUL byte")
    bad = {ch for ch in text if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES}
    if bad:
        raise SpecDomainError(
            f"{name} must not contain control, bidirectional-format, or line-break "
            f"characters: found {sorted(hex(ord(c)) for c in bad)}"
        )


def _normalise(raw: Any, name: str) -> str:
    """NFC-normalise and strip, so duplicate checks compare like with like."""
    text = _require_nonblank(raw, name)
    text = unicodedata.normalize("NFC", text)
    _reject_dangerous_characters(text, name)
    return text.strip()


def _reject_path_hazards(text: str, name: str) -> None:
    if "\\" in text:
        raise SpecDomainError(f"{name} must not contain a backslash: {text!r}")
    if text.startswith("/"):
        raise SpecDomainError(f"{name} must not be an absolute path: {text!r}")
    if _WINDOWS_DRIVE.match(text):
        raise SpecDomainError(f"{name} must not be a drive-absolute path: {text!r}")
    if text in (".", ".."):
        raise SpecDomainError(f"{name} must not be a traversal component: {text!r}")
    if "/" in text and any(part in ("", ".", "..") for part in text.split("/")):
        raise SpecDomainError(
            f"{name} must not contain traversal or empty components: {text!r}"
        )


def canonical_identifier(raw: Any, name: str) -> str:
    """A target id, exception id, or gate id.

    Identifiers are not paths, but they must not *look* like dangerous paths either: an
    id is interpolated into messages, filenames and report keys. Structured ids such as
    `checkov:CKV_AWS_18@aws_s3_bucket.example` remain valid.
    """
    text = _normalise(raw, name)
    if len(text) > MAX_IDENTIFIER_LENGTH:
        raise SpecDomainError(
            f"{name} must be at most {MAX_IDENTIFIER_LENGTH} characters, got {len(text)}"
        )
    if text.lower() in RESERVED_PLACEHOLDERS:
        raise SpecDomainError(
            f"{name} must not be the placeholder {text!r}; a generic identity is not an "
            f"identity"
        )
    _reject_path_hazards(text, name)
    return text


def canonical_resource_scope(raw: Any, name: str = "scope") -> str:
    """A target or exception scope: a resource address or object identity.

    Deliberately separate from repository paths: a resource address is not a filename,
    and using one helper for both is how a placeholder scope reached an exact-match
    comparison.
    """
    text = _normalise(raw, name)
    if text.lower() in RESERVED_PLACEHOLDERS:
        raise SpecDomainError(
            f"{name} must not be the placeholder {text!r}: a deletion or suppression "
            f"must never be authorised by an unspecified scope"
        )
    _reject_path_hazards(text, name)
    return text


def canonical_repo_path(raw: Any, name: str = "file_path") -> str:
    """A repository-relative file path."""
    text = _normalise(raw, name)
    _reject_path_hazards(text, name)
    if text.endswith("/"):
        raise SpecDomainError(f"{name} must name a file, not a directory: {text!r}")
    return text


def canonical_principal(raw: Any, name: str = "owner") -> str:
    """A responsible person or team.

    Not a path and not an identifier: `platform-team@example.com` and
    `Security Guild (EU)` are both legitimate, so punctuation and spaces are preserved.
    Control, format and line-break characters are rejected so report serialisation stays
    deterministic and non-spoofable.
    """
    text = _normalise(raw, name)
    if len(text) > MAX_OWNER_LENGTH:
        raise SpecDomainError(
            f"{name} must be at most {MAX_OWNER_LENGTH} characters, got {len(text)}"
        )
    if text.lower() in RESERVED_PLACEHOLDERS:
        raise SpecDomainError(f"{name} must not be the placeholder {text!r}")
    return text


def safe_reason_text(raw: Any, name: str = "reason") -> str:
    """Human-readable free text for a report.

    Punctuation is preserved on purpose — a reason is meant to be read. It is *not* run
    through a path validator, which would reject ordinary prose. What is rejected is
    anything that could break or spoof report rendering: NUL, control characters,
    bidirectional overrides, line breaks, and unreasonable length.
    """
    text = _normalise(raw, name)
    if len(text) > MAX_REASON_LENGTH:
        raise SpecDomainError(
            f"{name} must be at most {MAX_REASON_LENGTH} characters, got {len(text)}"
        )
    return text


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
@dataclass(frozen=True, slots=True)
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
        for f in fields(self):
            if f.type == "bool" or isinstance(getattr(self, f.name), bool):
                if f.name not in ("baseline_occurrences", "candidate_matches"):
                    _require_bool(getattr(self, f.name), f.name)


def classify(obs: TargetObservation) -> Outcome:
    """Ordered evaluation exactly as specified in §4.1."""
    _require_exact_type(obs, TargetObservation, "observation")
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
# §2.5  exceptions bind to a target, a scope, and an event
# --------------------------------------------------------------------------- #
def _validate_permitted_outcomes(raw: Any, name: str = "permitted_outcomes") -> frozenset:
    _require_supplied(raw, name)
    if type(raw) is not frozenset:
        raise SpecDomainError(
            f"{name} must be an exact frozenset of Outcome, got {type(raw).__name__}: a "
            f"mutable or subclassed collection could change after validation"
        )
    if not raw:
        raise SpecDomainError(
            f"{name} must not be empty: an exception that authorises nothing is not an "
            f"exception"
        )
    for outcome in raw:
        _require_enum(outcome, Outcome, f"{name} entry")
        if outcome in NEVER_PERMITTABLE_OUTCOMES:
            raise SpecDomainError(
                f"{name} must not contain {outcome.value}: it is never exception-eligible"
            )
        if outcome not in PERMITTABLE_EXCEPTION_OUTCOMES:
            raise SpecDomainError(
                f"{name} must be a subset of "
                f"{sorted(o.value for o in PERMITTABLE_EXCEPTION_OUTCOMES)}, got "
                f"{outcome.value}"
            )
    return raw


@dataclass(frozen=True, slots=True)
class ExceptionRecord:
    exception_id: str
    target_id: str
    scope: str
    reason: str
    owner: str
    created: date
    expires: date
    origin: ExceptionOrigin
    permitted_outcomes: frozenset = REQUIRED   # no default: name the event

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "exception_id", canonical_identifier(self.exception_id, "exception_id"))
        set_(self, "target_id", canonical_identifier(self.target_id, "target_id"))
        set_(self, "scope", canonical_resource_scope(self.scope, "exception scope"))
        set_(self, "reason", safe_reason_text(self.reason, "reason"))
        set_(self, "owner", canonical_principal(self.owner, "owner"))
        _require_date(self.created, "created")
        _require_date(self.expires, "expires")
        _require_enum(self.origin, ExceptionOrigin, "origin")
        set_(self, "permitted_outcomes",
             _validate_permitted_outcomes(self.permitted_outcomes))
        if self.created > self.expires:
            raise SpecDomainError(
                f"exception {self.exception_id}: created {self.created} is after "
                f"expires {self.expires}"
            )

    def canonical_dict(self) -> dict:
        """Deterministic serialisation: outcomes sorted, dates as ISO strings."""
        return {
            "exception_id": self.exception_id,
            "target_id": self.target_id,
            "scope": self.scope,
            "reason": self.reason,
            "owner": self.owner,
            "created": self.created.isoformat(),
            "expires": self.expires.isoformat(),
            "origin": self.origin.value,
            "permitted_outcomes": sorted(o.value for o in self.permitted_outcomes),
        }


def rebuild_exception_record(record: Any) -> ExceptionRecord:
    """Reconstruct an exact record from copied primitive, enum and date values.

    Rebuilding only the outer container was not enough: the policy was rebuilt while the
    records inside it were shared, so mutating the caller's record changed a stored
    verdict.
    """
    _require_exact_type(record, ExceptionRecord, "exception record")
    return ExceptionRecord(
        exception_id=str(record.exception_id),
        target_id=str(record.target_id),
        scope=str(record.scope),
        reason=str(record.reason),
        owner=str(record.owner),
        created=date(record.created.year, record.created.month, record.created.day),
        expires=date(record.expires.year, record.expires.month, record.expires.day),
        origin=ExceptionOrigin(record.origin.value),
        permitted_outcomes=frozenset(Outcome(o.value) for o in record.permitted_outcomes),
    )


_EXCEPTION_FIELDS = frozenset({
    "exception_id", "target_id", "scope", "reason", "owner", "created", "expires",
    "origin", "permitted_outcomes",
})


def _parse_permitted_outcomes(raw: Any) -> frozenset:
    if raw is None:
        raise SpecDomainError(
            "permitted_outcomes is required: an exception must name the event it "
            "authorises. Approving a suppression does not approve deleting the resource."
        )
    if isinstance(raw, (str, bytes)):
        raise SpecDomainError("permitted_outcomes must be a collection, not a string")
    if not isinstance(raw, (list, tuple, set, frozenset)):
        raise SpecDomainError(
            f"permitted_outcomes must be a collection, got {type(raw).__name__}"
        )
    values = list(raw)
    names: list[str] = []
    for item in values:
        if type(item) is Outcome:
            names.append(item.value)
        elif type(item) is str:
            names.append(item)
        else:
            raise SpecDomainError(
                f"permitted_outcomes entry must be an Outcome or its name, got "
                f"{type(item).__name__}"
            )
    if len(set(names)) != len(names):
        raise SpecDomainError(f"duplicate permitted_outcomes entries: {sorted(names)}")
    parsed = set()
    for name in names:
        try:
            parsed.add(Outcome(name))
        except ValueError as exc:
            raise SpecDomainError(f"unknown outcome {name!r} in permitted_outcomes") from exc
    return _validate_permitted_outcomes(frozenset(parsed))


def _build(record: Mapping[str, Any], origin: ExceptionOrigin) -> ExceptionRecord:
    if not isinstance(record, Mapping):
        raise SpecDomainError("exception record must be a mapping")
    unknown = set(record) - _EXCEPTION_FIELDS
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
        permitted_outcomes=_parse_permitted_outcomes(record.get("permitted_outcomes")),
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


@dataclass(frozen=True, slots=True)
class ExceptionPolicy:
    """Deeply immutable, validated set of exception records.

    Three earlier attempts were not immutable enough: a frozen dataclass holding the
    caller's `dict`; a `__slots__` class whose *object* was still assignable; and a
    frozen container that rebuilt itself while aliasing the records inside it.
    """

    records: tuple = ()
    index: Mapping = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        items = self.records
        # Exact built-in containers only, and one snapshot used for both validation and
        # consumption: a custom Mapping whose items() and values() disagree could pass the
        # key check while contributing a different record.
        if type(items) is dict:
            snapshot = dict(items)
            for key, record in snapshot.items():
                _require_exact_type(record, ExceptionRecord, f"exception {key!r}")
                if key != record.exception_id:
                    raise SpecDomainError(
                        f"exception mapping key {key!r} does not match record id "
                        f"{record.exception_id!r}: an index that disagrees with its "
                        f"records is not a policy"
                    )
            items = tuple(snapshot.values())
        elif type(items) in (tuple, list, set, frozenset):
            items = tuple(items)
        elif isinstance(items, Mapping):
            raise SpecDomainError(
                f"{type(items).__name__} is not an exact dict; arbitrary Mapping "
                f"implementations are not trusted at the policy boundary because items() "
                f"and values() can disagree"
            )
        else:
            raise SpecDomainError("records must be an exact collection of ExceptionRecord")
        # Deep copy: reconstruct each record so no caller-owned object is retained.
        rebuilt = tuple(rebuild_exception_record(r) for r in items)
        ids = [r.exception_id for r in rebuilt]
        if len(set(ids)) != len(ids):
            raise SpecDomainError(f"duplicate exception ids: {sorted(ids)}")

        ordered = tuple(sorted(rebuilt, key=lambda r: r.exception_id))
        object.__setattr__(self, "records", ordered)
        object.__setattr__(self, "index",
                           MappingProxyType({r.exception_id: r for r in ordered}))

    def get(self, exception_id: str | None) -> ExceptionRecord | None:
        return self.index.get(exception_id or "")

    def __len__(self) -> int:
        return len(self.records)

    def canonical_list(self) -> list[dict]:
        return [r.canonical_dict() for r in self.records]


def coerce_exception_policy(value: Any) -> ExceptionPolicy:
    """Always build a fresh policy; never retain a caller-owned object."""
    if value is None:
        return ExceptionPolicy(())
    if type(value) is ExceptionPolicy:
        return ExceptionPolicy(value.records)          # deep defensive copy
    if isinstance(value, ExceptionPolicy):
        raise SpecDomainError(
            f"{type(value).__name__} is an ExceptionPolicy subclass; the public boundary "
            f"accepts only ExceptionPolicy itself or a collection of ExceptionRecord"
        )
    if type(value) in (tuple, list, set, frozenset, dict):
        return ExceptionPolicy(value)
    if isinstance(value, Mapping):
        raise SpecDomainError(
            f"{type(value).__name__} is not an exact dict; arbitrary Mapping "
            f"implementations are not trusted at the policy boundary"
        )
    raise SpecDomainError(
        f"exceptions must be an ExceptionPolicy or an exact collection of "
        f"ExceptionRecord, got {type(value).__name__}"
    )


@dataclass(frozen=True, slots=True)
class TargetDecision:
    target_id: str
    outcome: Outcome
    target_scope: str = REQUIRED          # no placeholder default, on purpose
    policy_permitted: bool = False
    exception_id: str | None = None

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "target_id", canonical_identifier(self.target_id, "target_id"))
        _require_supplied(self.target_scope, "target_scope")
        set_(self, "target_scope",
             canonical_resource_scope(self.target_scope, "target_scope"))
        _require_enum(self.outcome, Outcome, "outcome")
        _require_bool(self.policy_permitted, "policy_permitted")
        if self.exception_id is not None:
            set_(self, "exception_id",
                 canonical_identifier(self.exception_id, "exception_id"))
        if self.policy_permitted and not self.exception_id:
            raise SpecDomainError(
                f"target {self.target_id}: policy_permitted requires an exception_id; "
                f"a permission with no record is not an approval"
            )

    @property
    def canonical_key(self) -> tuple:
        """Documented deterministic ordering key."""
        return (self.target_id, self.target_scope, self.outcome.value,
                self.exception_id or "")

    def canonical_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "target_scope": self.target_scope,
            "outcome": self.outcome.value,
            "policy_permitted": self.policy_permitted,
            "exception_id": self.exception_id or "",
        }


def rebuild_target_decision(decision: Any) -> TargetDecision:
    """Reconstruct an exact decision from copied values."""
    _require_exact_type(decision, TargetDecision, "target decision")
    return TargetDecision(
        target_id=str(decision.target_id),
        outcome=Outcome(decision.outcome.value),
        target_scope=str(decision.target_scope),
        policy_permitted=bool(decision.policy_permitted),
        exception_id=None if decision.exception_id is None else str(decision.exception_id),
    )


def permission_rejection_reason(
    decision: TargetDecision, policy: ExceptionPolicy, evaluation_date: date
) -> str | None:
    """Why this permission does not hold, or None when it does."""
    _require_exact_type(decision, TargetDecision, "decision")
    _require_exact_type(policy, ExceptionPolicy, "policy")
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
    if decision.outcome not in record.permitted_outcomes:
        return (
            f"exception {record.exception_id} authorises "
            f"{sorted(o.value for o in record.permitted_outcomes)}, not "
            f"{decision.outcome.value}: approving one event does not approve another"
        )
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
@dataclass(frozen=True, slots=True)
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
    _require_exact_type(baseline, FindingLocation, "baseline location")
    _require_exact_type(candidate, FindingLocation, "candidate location")
    _require_bool(identity_matched, "identity_matched")
    if not identity_matched:
        return False
    return (baseline.file_path != candidate.file_path
            or baseline.start_line != candidate.start_line
            or baseline.end_line != candidate.end_line)


# --------------------------------------------------------------------------- #
# gate identities
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class GateResult:
    gate_id: str
    status: Status

    def __post_init__(self) -> None:
        object.__setattr__(self, "gate_id",
                           canonical_identifier(self.gate_id, "gate_id"))
        _require_enum(self.status, Status, f"status of gate {self.gate_id!r}")


@dataclass(frozen=True, slots=True)
class RequiredGates:
    """Which gates trusted configuration requires, by identity."""

    validator_ids: tuple = REQUIRED
    oracle_ids: tuple = ()

    def __post_init__(self) -> None:
        _require_supplied(self.validator_ids, "required_gates.validator_ids")
        for name in ("validator_ids", "oracle_ids"):
            raw = getattr(self, name)
            if type(raw) is not tuple:
                raise SpecDomainError(
                    f"required_gates.{name} must be an exact tuple, got "
                    f"{type(raw).__name__}"
                )
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
    required_ids: tuple, observed: tuple, kind: str
) -> tuple:
    """Return observed statuses in required order, or raise."""
    if type(observed) is not tuple:
        raise SpecDomainError(f"{kind} results must be an exact tuple")
    for result in observed:
        _require_exact_type(result, GateResult, f"{kind} result")
    seen = [r.gate_id for r in observed]
    duplicates = {gate for gate in seen if seen.count(gate) > 1}
    if duplicates:
        raise SpecDomainError(f"duplicate {kind} gate result(s): {sorted(duplicates)}")
    by_id = {r.gate_id: r for r in observed}
    missing = [gate for gate in required_ids if gate not in by_id]
    unknown = sorted(set(by_id) - set(required_ids))
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
@dataclass(frozen=True, slots=True)
class RunObservation:
    target_decisions: tuple
    evaluation_date: date = REQUIRED
    preflight: Status = REQUIRED
    required_scanner_integrity: Status = REQUIRED
    required_gates: Any = REQUIRED
    validator_results: tuple = REQUIRED
    regression_policy: Status = REQUIRED
    suppression_policy: Status = REQUIRED
    oracle_results: tuple = ()
    exceptions: Any = None
    coverage_decreased_on_required_scanner: bool = False
    rule_substituted_on_required_target: bool = False
    policy_drift: bool = False
    optional_gates: frozenset = frozenset()
    optional_gates_origin: ExceptionOrigin = ExceptionOrigin.UNKNOWN
    validator_states: tuple = field(default=(), repr=False, compare=False)
    oracle_states: tuple = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        raw_decisions = self.target_decisions
        if isinstance(raw_decisions, (str, bytes)) or not isinstance(
            raw_decisions, (tuple, list)
        ):
            raise InvalidVerificationRequest(
                "target_decisions must be a tuple of TargetDecision"
            )
        # Reconstruct: a tuple subclass with a mutable __iter__ previously changed a
        # stored verdict after construction.
        rebuilt = tuple(rebuild_target_decision(d) for d in tuple(raw_decisions))
        if not rebuilt:
            raise InvalidVerificationRequest(
                "a verification request must name at least one target; a run with no "
                "targets verifies nothing and must not report VERIFIED. Use the scan "
                "command for target-free scanning."
            )
        keys = [d.canonical_key for d in rebuilt]
        if len(set(keys)) != len(keys):
            raise SpecDomainError(f"duplicate canonical target identity: {sorted(keys)}")
        ids = [d.target_id for d in rebuilt]
        if len(set(ids)) != len(ids):
            raise SpecDomainError(f"duplicate target_id in request: {sorted(ids)}")
        set_(self, "target_decisions", tuple(sorted(rebuilt, key=lambda d: d.canonical_key)))

        _require_date(_require_supplied(self.evaluation_date, "evaluation_date"),
                      "evaluation_date")
        for name in ("preflight", "required_scanner_integrity", "regression_policy",
                     "suppression_policy"):
            _require_enum(_require_supplied(getattr(self, name), name), Status, name)

        gates = _require_supplied(self.required_gates, "required_gates")
        _require_exact_type(gates, RequiredGates, "required_gates")
        observed_validators = _require_supplied(self.validator_results,
                                               "validator_results")
        set_(self, "validator_states",
             reconcile_gate_results(gates.validator_ids, observed_validators, "validator"))
        set_(self, "oracle_states",
             reconcile_gate_results(gates.oracle_ids, self.oracle_results, "oracle"))

        for name in ("coverage_decreased_on_required_scanner",
                     "rule_substituted_on_required_target", "policy_drift"):
            _require_bool(getattr(self, name), name)

        set_(self, "exceptions", coerce_exception_policy(self.exceptions))

        gate_names = self.optional_gates
        if type(gate_names) not in (frozenset, set):
            raise SpecDomainError("optional_gates must be a set of gate names")
        unknown = set(gate_names) - OPTIONAL_GATE_NAMES
        if unknown:
            raise SpecDomainError(
                f"unknown optional gate(s) {sorted(unknown)}; permitted: "
                f"{sorted(OPTIONAL_GATE_NAMES)}"
            )
        set_(self, "optional_gates", frozenset(gate_names))
        _require_enum(self.optional_gates_origin, ExceptionOrigin,
                      "optional_gates_origin")
        if gate_names and self.optional_gates_origin not in TRUSTED_EXCEPTION_ORIGINS:
            raise SpecDomainError(
                "optional_gates must come from a trusted configuration source; "
                f"got origin {self.optional_gates_origin.value!r}"
            )

    def canonical_dict(self) -> dict:
        """Deterministic serialisation, independent of caller iteration order."""
        return {
            "evaluation_date": self.evaluation_date.isoformat(),
            "preflight": self.preflight.value,
            "required_scanner_integrity": self.required_scanner_integrity.value,
            "required_gates": {
                "validator_ids": list(self.required_gates.validator_ids),
                "oracle_ids": list(self.required_gates.oracle_ids),
            },
            "validator_states": [s.value for s in self.validator_states],
            "oracle_states": [s.value for s in self.oracle_states],
            "regression_policy": self.regression_policy.value,
            "suppression_policy": self.suppression_policy.value,
            "target_decisions": [d.canonical_dict() for d in self.target_decisions],
            "exceptions": self.exceptions.canonical_list(),
            "coverage_decreased_on_required_scanner":
                self.coverage_decreased_on_required_scanner,
            "rule_substituted_on_required_target":
                self.rule_substituted_on_required_target,
            "policy_drift": self.policy_drift,
            "optional_gates": sorted(self.optional_gates),
            "optional_gates_origin": self.optional_gates_origin.value,
        }


def _policy_state_is_undecided(state: Status, gate: str, optional: frozenset) -> bool:
    if state is Status.SKIPPED and gate in optional:
        return False
    return state in UNDECIDED_STATES


def decide(run: RunObservation) -> Verdict:
    """Inconclusive dominates failure: a broken run establishes nothing either way."""
    _require_exact_type(run, RunObservation, "run")
    undecided = (
        run.preflight is not Status.PASS
        or run.required_scanner_integrity is not Status.PASS
        or any(s in UNDECIDED_STATES for s in run.validator_states)
        or any(s in UNDECIDED_STATES for s in run.oracle_states)
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
        Status.FAIL in run.validator_states
        or Status.FAIL in run.oracle_states
        or run.policy_drift
        or bool(unresolved)
        or run.regression_policy is Status.FAIL
        or run.suppression_policy is Status.FAIL
    )
    return Verdict.FAILED if failed else Verdict.VERIFIED


EXIT_CODES = {Verdict.VERIFIED: 0, Verdict.FAILED: 1, Verdict.INCONCLUSIVE: 3}
INVALID_REQUEST_EXIT_CODE = 2

#: Every persistent domain value, for the immutability test matrix.
PERSISTENT_DOMAIN_CLASSES = (
    TargetObservation, ExceptionRecord, ExceptionPolicy, TargetDecision,
    FindingLocation, GateResult, RequiredGates, RunObservation,
)
