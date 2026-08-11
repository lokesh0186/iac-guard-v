"""Immutable typed domain models.

Every class here is a frozen, slotted dataclass, so instances have no `__dict__` and
normal attribute assignment raises. That is a requirement rather than a style choice:
during development, three designs that looked immutable were not, and in each case a
stored verdict could be changed after the fact —

* a frozen dataclass holding the caller's `dict`: clearing the dict flipped `VERIFIED`
  to `FAILED`;
* a `__slots__` class exposing a `MappingProxyType`: the object itself was assignable;
* a frozen container that rebuilt itself while aliasing the records inside it: mutating
  the caller's record flipped the verdict.

Three rules follow, and `tests/unit/test_models_immutability.py` enforces them for every
class in `PERSISTENT_MODELS`:

1. **Frozen and slotted.** No `__dict__`, no attribute reassignment.
2. **Reconstruct, never alias.** Collections and nested records are rebuilt from copied
   primitive, enum and date values, then canonically ordered so serialisation is
   deterministic.
3. **Exact types at security boundaries.** `isinstance` is not used for domain values,
   because a subclass can override behaviour: a `TargetDecision` subclass reporting
   `FIXED` while storing `STILL_PRESENT` reached `VERIFIED` in the reference model.

Statuses stay typed to the report. Nothing here reduces `ERROR`, `TIMEOUT`, `PARTIAL`,
`UNSUPPORTED` or `INCONCLUSIVE` to a boolean.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime
from types import MappingProxyType
from typing import Any, Mapping

from .enums import (
    NEVER_PERMITTABLE_OUTCOMES,
    PERMITTABLE_EXCEPTION_OUTCOMES,
    TRUSTED_EXCEPTION_ORIGINS,
    ArtifactKind,
    ExceptionOrigin,
    IdentityTier,
    Outcome,
    Severity,
    Status,
)


class DomainError(ValueError):
    """A value outside the specified domain. Raised, never classified."""


class InvalidRequestError(DomainError):
    """A request that cannot be verified at all. CLI exit code 2."""


MAX_IDENTIFIER_LENGTH = 256
MAX_OWNER_LENGTH = 128
MAX_REASON_LENGTH = 512
MAX_MESSAGE_LENGTH = 4096

RESERVED_PLACEHOLDERS = frozenset({
    "unspecified", "unspecified/scope", "unknown", "unknown/scope", "default",
    "default/scope", "n/a", "na", "none", "null", "-", "todo", "tbd",
})

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_FORBIDDEN_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")


# --------------------------------------------------------------------------- #
# validation primitives
# --------------------------------------------------------------------------- #
def require_bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise DomainError(
            f"{name} must be a bool, got {type(value).__name__} {value!r}: a truthy "
            f"string such as 'false' would otherwise read as True"
        )
    return value


def require_int(value: Any, name: str) -> int:
    if type(value) is not int:
        raise DomainError(f"{name} must be an int, got {type(value).__name__} {value!r}")
    return value


def require_date(value: Any, name: str) -> date:
    if isinstance(value, datetime) or type(value) is not date:
        raise DomainError(
            f"{name} must be a datetime.date, got {type(value).__name__} {value!r}"
        )
    return value


def require_enum(value: Any, enum_cls: type, name: str):
    if type(value) is not enum_cls:
        raise DomainError(
            f"{name} must be a {enum_cls.__name__} member, got {type(value).__name__} "
            f"{value!r}. Malformed input is a usage error, never PASS."
        )
    return value


def require_exact_type(value: Any, expected: type, name: str):
    """Exact type, not isinstance: a subclass can override behaviour."""
    if type(value) is not expected:
        raise DomainError(
            f"{name} must be exactly {expected.__name__}, got {type(value).__name__}; "
            f"subclasses are rejected at security boundaries"
        )
    return value


def _nonblank(value: Any, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise DomainError(f"{name} must be a non-blank string, got {value!r}")
    return value.strip()


def _reject_dangerous_characters(text: str, name: str) -> None:
    if "\x00" in text:
        raise DomainError(f"{name} must not contain a NUL byte")
    bad = {ch for ch in text if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES}
    if bad:
        raise DomainError(
            f"{name} must not contain control, bidirectional-format or line-break "
            f"characters: found {sorted(hex(ord(c)) for c in bad)}"
        )


def _normalise(raw: Any, name: str) -> str:
    text = unicodedata.normalize("NFC", _nonblank(raw, name))
    _reject_dangerous_characters(text, name)
    return text.strip()


def _reject_path_hazards(text: str, name: str) -> None:
    if "\\" in text:
        raise DomainError(f"{name} must not contain a backslash: {text!r}")
    if text.startswith("/"):
        raise DomainError(f"{name} must not be an absolute path: {text!r}")
    if _WINDOWS_DRIVE.match(text):
        raise DomainError(f"{name} must not be a drive-absolute path: {text!r}")
    if text in (".", ".."):
        raise DomainError(f"{name} must not be a traversal component: {text!r}")
    if "/" in text and any(part in ("", ".", "..") for part in text.split("/")):
        raise DomainError(f"{name} must not contain traversal or empty components: {text!r}")


def canonical_identifier(raw: Any, name: str) -> str:
    """A rule id, gate id, target id, exception id, or scanner name."""
    text = _normalise(raw, name)
    if len(text) > MAX_IDENTIFIER_LENGTH:
        raise DomainError(
            f"{name} must be at most {MAX_IDENTIFIER_LENGTH} characters, got {len(text)}"
        )
    if text.lower() in RESERVED_PLACEHOLDERS:
        raise DomainError(f"{name} must not be the placeholder {text!r}")
    _reject_path_hazards(text, name)
    return text


def canonical_resource_scope(raw: Any, name: str = "scope") -> str:
    """A resource address or object identity. Not a filename."""
    text = _normalise(raw, name)
    if text.lower() in RESERVED_PLACEHOLDERS:
        raise DomainError(
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
        raise DomainError(f"{name} must name a file, not a directory: {text!r}")
    return text


def canonical_principal(raw: Any, name: str = "owner") -> str:
    """A responsible person or team. Punctuation and spaces are preserved."""
    text = _normalise(raw, name)
    if len(text) > MAX_OWNER_LENGTH:
        raise DomainError(
            f"{name} must be at most {MAX_OWNER_LENGTH} characters, got {len(text)}"
        )
    if text.lower() in RESERVED_PLACEHOLDERS:
        raise DomainError(f"{name} must not be the placeholder {text!r}")
    return text


def safe_report_text(raw: Any, name: str, limit: int = MAX_REASON_LENGTH) -> str:
    """Human-readable free text destined for a report.

    Prose keeps its punctuation; what is rejected is anything that could break or spoof
    report rendering. A path validator must never be used here.
    """
    text = _normalise(raw, name)
    if len(text) > limit:
        raise DomainError(f"{name} must be at most {limit} characters, got {len(text)}")
    return text


# --------------------------------------------------------------------------- #
# findings and scanner runs
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class FindingLocation:
    file_path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_path",
                           canonical_repo_path(self.file_path, "file_path"))
        start = require_int(self.start_line, "start_line")
        end = require_int(self.end_line, "end_line")
        if start < 1:
            raise DomainError(f"start_line must be >= 1, got {start}")
        if end < start:
            raise DomainError(f"end_line {end} must be >= start_line {start}")

    def canonical_dict(self) -> dict:
        return {"file_path": self.file_path, "start_line": self.start_line,
                "end_line": self.end_line}


@dataclass(frozen=True, slots=True)
class Finding:
    """A normalised finding. Identity is never the rule id alone (semantics §3)."""

    scanner: str
    scanner_version: str
    rule_id: str
    resource_address: str
    location: FindingLocation
    severity: Severity = Severity.UNKNOWN
    occurrence_index: int = 0
    rule_name: str = ""
    message: str = ""
    native_fingerprint: str = ""
    iacgv_fingerprint: str = ""
    artifact_kind: ArtifactKind = ArtifactKind.UNKNOWN
    suppressed: bool = False

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "scanner", canonical_identifier(self.scanner, "scanner"))
        set_(self, "scanner_version",
             canonical_identifier(self.scanner_version, "scanner_version"))
        set_(self, "rule_id", canonical_identifier(self.rule_id, "rule_id"))
        set_(self, "resource_address",
             canonical_resource_scope(self.resource_address, "resource_address"))
        require_exact_type(self.location, FindingLocation, "location")
        require_enum(self.severity, Severity, "severity")
        require_enum(self.artifact_kind, ArtifactKind, "artifact_kind")
        require_bool(self.suppressed, "suppressed")
        if require_int(self.occurrence_index, "occurrence_index") < 0:
            raise DomainError("occurrence_index must be >= 0")
        if self.rule_name:
            set_(self, "rule_name", safe_report_text(self.rule_name, "rule_name"))
        if self.message:
            set_(self, "message",
                 safe_report_text(self.message, "message", MAX_MESSAGE_LENGTH))
        if self.native_fingerprint:
            set_(self, "native_fingerprint",
                 canonical_identifier(self.native_fingerprint, "native_fingerprint"))
        if self.iacgv_fingerprint:
            if not re.fullmatch(r"iacgv[1-9][0-9]*:[0-9a-f]{64}", self.iacgv_fingerprint):
                raise DomainError(
                    "iacgv_fingerprint must contain a visible iacgv algorithm version "
                    "and a lowercase SHA-256 digest"
                )

    @property
    def exact_key(self) -> tuple:
        """`EXACT` identity: line numbers deliberately excluded (semantics §3.3)."""
        return (self.scanner, self.rule_id, self.location.file_path,
                self.resource_address, self.occurrence_index)

    @property
    def relocated_key(self) -> tuple:
        """`RELOCATED` identity: same resource, file and lines may move."""
        return (self.scanner, self.rule_id, self.resource_address, self.occurrence_index)

    def identity_key(self, tier: IdentityTier) -> tuple:
        require_enum(tier, IdentityTier, "tier")
        if tier is IdentityTier.EXACT:
            return self.exact_key
        if tier is IdentityTier.RELOCATED:
            return self.relocated_key
        raise DomainError(f"{tier.value} identity requires a control mapping (semantics §8)")

    def canonical_dict(self) -> dict:
        return {
            "scanner": self.scanner, "scanner_version": self.scanner_version,
            "rule_id": self.rule_id, "rule_name": self.rule_name,
            "severity": self.severity.value, "resource_address": self.resource_address,
            "occurrence_index": self.occurrence_index,
            "location": self.location.canonical_dict(),
            "message": self.message, "native_fingerprint": self.native_fingerprint,
            "iacgv_fingerprint": self.iacgv_fingerprint,
            "artifact_kind": self.artifact_kind.value, "suppressed": self.suppressed,
        }


def _rebuild_finding(finding: Any) -> Finding:
    require_exact_type(finding, Finding, "finding")
    loc = finding.location
    return Finding(
        scanner=str(finding.scanner), scanner_version=str(finding.scanner_version),
        rule_id=str(finding.rule_id), resource_address=str(finding.resource_address),
        location=FindingLocation(str(loc.file_path), int(loc.start_line), int(loc.end_line)),
        severity=Severity(finding.severity.value),
        occurrence_index=int(finding.occurrence_index),
        rule_name=str(finding.rule_name), message=str(finding.message),
        native_fingerprint=str(finding.native_fingerprint),
        iacgv_fingerprint=str(finding.iacgv_fingerprint),
        artifact_kind=ArtifactKind(finding.artifact_kind.value),
        suppressed=bool(finding.suppressed),
    )


@dataclass(frozen=True, slots=True)
class CoverageCounters:
    """What the scanner says it actually covered (semantics §6 V5)."""

    files_eligible: int = 0
    files_discovered: int = 0
    files_parsed: int = 0
    files_failed: int = 0
    checks_loaded: int = 0
    checks_failed_to_execute: int = 0
    parse_errors: int = 0

    def __post_init__(self) -> None:
        for name in ("files_eligible", "files_discovered", "files_parsed", "files_failed",
                     "checks_loaded", "checks_failed_to_execute", "parse_errors"):
            if require_int(getattr(self, name), name) < 0:
                raise DomainError(f"{name} must be >= 0")

    def canonical_dict(self) -> dict:
        return {name: getattr(self, name) for name in (
            "files_eligible", "files_discovered", "files_parsed", "files_failed",
            "checks_loaded", "checks_failed_to_execute", "parse_errors")}


@dataclass(frozen=True, slots=True)
class ScannerRun:
    """One scanner execution. Carries a `Status`, never a boolean, and no verdict."""

    scanner: str
    scanner_version: str
    status: Status
    findings: tuple = ()
    coverage: CoverageCounters = field(default_factory=CoverageCounters)
    exit_code: int = 0
    stdout_sha256: str = ""
    stderr_sha256: str = ""
    duration_ms: int = 0
    diagnostics: tuple = ()

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "scanner", canonical_identifier(self.scanner, "scanner"))
        set_(self, "scanner_version",
             canonical_identifier(self.scanner_version, "scanner_version"))
        require_enum(self.status, Status, "status")
        require_exact_type(self.coverage, CoverageCounters, "coverage")
        require_int(self.exit_code, "exit_code")
        if require_int(self.duration_ms, "duration_ms") < 0:
            raise DomainError("duration_ms must be >= 0")
        if type(self.findings) not in (tuple, list):
            raise DomainError("findings must be a tuple of Finding")
        rebuilt = tuple(_rebuild_finding(f) for f in tuple(self.findings))
        # A run owns the provenance of its findings. Accepting a Trivy finding inside a
        # run claiming to be Checkov produces self-contradictory evidence, and silently
        # rewriting the finding would destroy the contradiction rather than report it.
        for finding in rebuilt:
            if finding.scanner != self.scanner:
                raise DomainError(
                    f"finding from scanner {finding.scanner!r} cannot appear in a "
                    f"{self.scanner!r} run"
                )
            if finding.scanner_version != self.scanner_version:
                raise DomainError(
                    f"finding from {finding.scanner} {finding.scanner_version!r} cannot "
                    f"appear in a run of version {self.scanner_version!r}"
                )
        # occurrence_index exists to disambiguate repeated findings, so two findings with
        # the same exact identity are a normalisation defect, not a tie to be broken by
        # caller order. Left unresolved, canonical output depended on input order.
        keys = [f.exact_key for f in rebuilt]
        duplicates = sorted({k for k in keys if keys.count(k) > 1})
        if duplicates:
            raise DomainError(
                f"duplicate exact finding identity: {duplicates}. Assign distinct "
                f"occurrence_index values; see normalisation.assign_occurrence_indices"
            )
        set_(self, "findings", tuple(sorted(rebuilt, key=lambda f: f.exact_key)))
        if type(self.diagnostics) not in (tuple, list):
            raise DomainError("diagnostics must be a tuple of strings")
        set_(self, "diagnostics",
             tuple(safe_report_text(d, "diagnostic", MAX_MESSAGE_LENGTH)
                   for d in tuple(self.diagnostics)))
        for name in ("stdout_sha256", "stderr_sha256"):
            value = getattr(self, name)
            if value and not re.fullmatch(r"[0-9a-f]{64}", value):
                raise DomainError(f"{name} must be a lowercase hex SHA-256 or empty")

    def canonical_dict(self) -> dict:
        return {
            "scanner": self.scanner, "scanner_version": self.scanner_version,
            "status": self.status.value, "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stdout_sha256": self.stdout_sha256, "stderr_sha256": self.stderr_sha256,
            "coverage": self.coverage.canonical_dict(),
            "findings": [f.canonical_dict() for f in self.findings],
            "diagnostics": list(self.diagnostics),
        }


# --------------------------------------------------------------------------- #
# gates
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class GateResult:
    gate_id: str
    status: Status
    reason_code: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "gate_id", canonical_identifier(self.gate_id, "gate_id"))
        require_enum(self.status, Status, f"status of gate {self.gate_id!r}")
        if self.reason_code:
            set_(self, "reason_code", canonical_identifier(self.reason_code, "reason_code"))
        if self.detail:
            set_(self, "detail", safe_report_text(self.detail, "detail", MAX_MESSAGE_LENGTH))

    def canonical_dict(self) -> dict:
        return {"gate_id": self.gate_id, "status": self.status.value,
                "reason_code": self.reason_code, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class RequiredGates:
    """Gate identities trusted configuration requires. Counts are not identities."""

    validator_ids: tuple
    oracle_ids: tuple = ()

    def __post_init__(self) -> None:
        for name in ("validator_ids", "oracle_ids"):
            raw = getattr(self, name)
            if type(raw) is not tuple:
                raise DomainError(f"{name} must be an exact tuple")
            ids = tuple(canonical_identifier(i, f"{name} entry") for i in raw)
            if len(set(ids)) != len(ids):
                raise DomainError(f"duplicate gate id in {name}: {sorted(ids)}")
            object.__setattr__(self, name, ids)
        if not self.validator_ids:
            raise InvalidRequestError(
                "at least one required validator gate id is needed: validity must be "
                "established independently of the security scanner"
            )

    def canonical_dict(self) -> dict:
        return {"validator_ids": list(self.validator_ids),
                "oracle_ids": list(self.oracle_ids)}


def reconcile_gate_results(required_ids: tuple, observed: tuple, kind: str) -> tuple:
    """Observed gate results must cover exactly the required identities."""
    if type(observed) not in (tuple, list):
        raise DomainError(f"{kind} results must be a tuple of GateResult")
    results = tuple(observed)
    for result in results:
        require_exact_type(result, GateResult, f"{kind} result")
    seen = [r.gate_id for r in results]
    duplicates = {g for g in seen if seen.count(g) > 1}
    if duplicates:
        raise DomainError(f"duplicate {kind} gate result(s): {sorted(duplicates)}")
    by_id = {r.gate_id: r for r in results}
    missing = [g for g in required_ids if g not in by_id]
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
        raise InvalidRequestError("; ".join(parts) + ". Absence of evidence is not evidence.")
    return tuple(by_id[g] for g in required_ids)


# --------------------------------------------------------------------------- #
# exceptions: bound to a target, a scope, and an event
# --------------------------------------------------------------------------- #
def validate_permitted_outcomes(raw: Any, name: str = "permitted_outcomes") -> frozenset:
    if type(raw) is not frozenset:
        raise DomainError(
            f"{name} must be an exact frozenset of Outcome, got {type(raw).__name__}"
        )
    if not raw:
        raise DomainError(f"{name} must not be empty: an exception must name an event")
    for outcome in raw:
        require_enum(outcome, Outcome, f"{name} entry")
        if outcome in NEVER_PERMITTABLE_OUTCOMES:
            raise DomainError(
                f"{name} must not contain {outcome.value}: it is never exception-eligible"
            )
        if outcome not in PERMITTABLE_EXCEPTION_OUTCOMES:
            raise DomainError(
                f"{name} must be a subset of "
                f"{sorted(o.value for o in PERMITTABLE_EXCEPTION_OUTCOMES)}"
            )
    return raw


@dataclass(frozen=True, slots=True)
class ExceptionRecord:
    """An approved deviation, bound to one target, one scope, and named events.

    `permitted_outcomes` has no default. Without it, one record authorised
    `SUPPRESSED`, `RESOURCE_DELETED` and `FILE_DELETED_OR_RENAMED` alike, so approving a
    suppression silently approved deleting the resource.
    """

    exception_id: str
    target: TargetIdentity
    reason: str
    owner: str
    created: date
    expires: date
    origin: ExceptionOrigin
    permitted_outcomes: frozenset

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "exception_id", canonical_identifier(self.exception_id, "exception_id"))
        require_target_identity(self.target, "exception target")
        set_(self, "reason", safe_report_text(self.reason, "reason"))
        set_(self, "owner", canonical_principal(self.owner, "owner"))
        require_date(self.created, "created")
        require_date(self.expires, "expires")
        require_enum(self.origin, ExceptionOrigin, "origin")
        set_(self, "permitted_outcomes",
             validate_permitted_outcomes(self.permitted_outcomes))
        if self.created > self.expires:
            raise DomainError(
                f"exception {self.exception_id}: created {self.created} is after expires "
                f"{self.expires}"
            )

    def canonical_dict(self) -> dict:
        return {
            "exception_id": self.exception_id,
            "target": self.target.canonical_dict(),
            "reason": self.reason, "owner": self.owner,
            "created": self.created.isoformat(), "expires": self.expires.isoformat(),
            "origin": self.origin.value,
            "permitted_outcomes": sorted(o.value for o in self.permitted_outcomes),
        }


def rebuild_exception_record(record: Any) -> ExceptionRecord:
    """Reconstruct from copied values so no caller-owned object is retained."""
    require_exact_type(record, ExceptionRecord, "exception record")
    return ExceptionRecord(
        exception_id=str(record.exception_id),
        target=TargetIdentity(str(record.target.scanner), str(record.target.rule_id),
                              str(record.target.scope)),
        reason=str(record.reason), owner=str(record.owner),
        created=date(record.created.year, record.created.month, record.created.day),
        expires=date(record.expires.year, record.expires.month, record.expires.day),
        origin=ExceptionOrigin(record.origin.value),
        permitted_outcomes=frozenset(Outcome(o.value) for o in record.permitted_outcomes),
    )


@dataclass(frozen=True, slots=True)
class ExceptionPolicy:
    """Deeply immutable, validated, canonically ordered set of exception records."""

    records: tuple = ()
    index: Mapping = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        items = self.records
        # Exact built-in containers only. A custom Mapping could return one set of
        # records from items() and a different set from values(), so validating the keys
        # proved nothing about what was consumed: a probe whose items() reported "EX-1"
        # while values() returned a record with id "DIFFERENT" built a policy containing
        # "DIFFERENT". A single snapshot of an exact dict removes the window entirely.
        if type(items) is dict:
            snapshot = dict(items)          # one snapshot, validated and consumed
            for key, rec in snapshot.items():
                require_exact_type(rec, ExceptionRecord, f"exception {key!r}")
                if key != rec.exception_id:
                    raise DomainError(
                        f"exception mapping key {key!r} does not match record id "
                        f"{rec.exception_id!r}"
                    )
            items = tuple(snapshot.values())
        elif type(items) in (tuple, list, set, frozenset):
            items = tuple(items)
        elif isinstance(items, Mapping):
            raise DomainError(
                f"{type(items).__name__} is not an exact dict; arbitrary Mapping "
                f"implementations are not trusted at the policy boundary because "
                f"items() and values() can disagree"
            )
        else:
            raise DomainError("records must be an exact collection of ExceptionRecord")
        rebuilt = tuple(rebuild_exception_record(r) for r in items)
        ids = [r.exception_id for r in rebuilt]
        if len(set(ids)) != len(ids):
            raise DomainError(f"duplicate exception ids: {sorted(ids)}")
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
        return ExceptionPolicy(value.records)
    if isinstance(value, ExceptionPolicy):
        raise DomainError(
            f"{type(value).__name__} is an ExceptionPolicy subclass; only ExceptionPolicy "
            f"itself or a collection of ExceptionRecord is accepted"
        )
    if type(value) in (tuple, list, set, frozenset, dict):
        return ExceptionPolicy(value)
    if isinstance(value, Mapping):
        raise DomainError(
            f"{type(value).__name__} is not an exact dict; arbitrary Mapping "
            f"implementations are not trusted at the policy boundary"
        )
    raise DomainError(
        f"exceptions must be an ExceptionPolicy or an exact collection of "
        f"ExceptionRecord, got {type(value).__name__}"
    )


# --------------------------------------------------------------------------- #
# targets
# --------------------------------------------------------------------------- #
_REFERENCE_ESCAPES = {"%": "%25", ";": "%3B", "=": "%3D"}
_REFERENCE_UNESCAPES = {v: k for k, v in _REFERENCE_ESCAPES.items()}
TARGET_REFERENCE_VERSION = "tid1"


def _escape_reference_value(value: str) -> str:
    out = value.replace("%", "%25")
    return out.replace(";", "%3B").replace("=", "%3D")


def _unescape_reference_value(value: str) -> str:
    out = value.replace("%3B", ";").replace("%3b", ";")
    out = out.replace("%3D", "=").replace("%3d", "=")
    return out.replace("%25", "%")


@dataclass(frozen=True, slots=True)
class TargetIdentity:
    """The authoritative identity of a target: `(scanner, rule_id, scope)`.

    Authorisation and matching bind **this structured value**, never a
    delimiter-concatenated string. A concatenated form is ambiguous, and the ambiguity is
    exploitable because exceptions bind to target identity. Both of these pairs collided
    under `f"{scanner}:{rule_id}@{scope}"`:

        ("checkov", "RULE@X", "scope")  and  ("checkov", "RULE", "X@scope")
        ("foo:bar", "baz", "scope")     and  ("foo", "bar:baz", "scope")

    so an exception intended for one target could authorise a different one.

    Three representations, with clearly different jobs:

    * `canonical_key`  — the tuple used for equality, ordering and authorisation;
    * `reference`      — a lossless, unambiguous, round-trippable encoding for CLI use;
    * `display_ref`    — `scanner:rule@scope` for humans, **non-authoritative** and never
                         parsed back;
    * `opaque_id`      — a versioned digest over a length-prefixed encoding, for use as a
                         report key. Length prefixes mean no delimiter can be forged.
    """

    scanner: str
    rule_id: str
    scope: str

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "scanner", canonical_identifier(self.scanner, "scanner"))
        set_(self, "rule_id", canonical_identifier(self.rule_id, "rule_id"))
        set_(self, "scope", canonical_resource_scope(self.scope, "scope"))

    @property
    def canonical_key(self) -> tuple:
        """The authoritative identity. Equality and ordering use this."""
        return (self.scanner, self.rule_id, self.scope)

    @property
    def display_ref(self) -> str:
        """Human-readable only.

        Deliberately ambiguous and deliberately never parsed: use `reference` for any
        value that has to survive a round trip.
        """
        return f"{self.scanner}:{self.rule_id}@{self.scope}"

    @property
    def reference(self) -> str:
        """Lossless, unambiguous encoding: `scanner=<v>;rule=<v>;scope=<v>`.

        `%`, `;` and `=` are percent-escaped inside values, so no value can introduce a
        field boundary.
        """
        return ";".join((
            f"scanner={_escape_reference_value(self.scanner)}",
            f"rule={_escape_reference_value(self.rule_id)}",
            f"scope={_escape_reference_value(self.scope)}",
        ))

    @property
    def opaque_id(self) -> str:
        """Versioned digest over a length-prefixed encoding of the structured fields."""
        payload = "|".join(
            f"{len(part.encode('utf-8'))}:{part}"
            for part in (self.scanner, self.rule_id, self.scope)
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"{TARGET_REFERENCE_VERSION}:{digest}"

    @classmethod
    def parse_reference(cls, text: Any) -> "TargetIdentity":
        """Parse the unambiguous `reference` grammar. Round-trips exactly."""
        raw = _nonblank(text, "target reference")
        fields_seen: dict[str, str] = {}
        for part in raw.split(";"):
            if "=" not in part:
                raise DomainError(
                    f"target reference field {part!r} is not `name=value`; the grammar is "
                    f"scanner=<v>;rule=<v>;scope=<v>"
                )
            name, _, value = part.partition("=")
            name = name.strip()
            if name in fields_seen:
                raise DomainError(f"duplicate field {name!r} in target reference")
            if name not in ("scanner", "rule", "scope"):
                raise DomainError(f"unknown field {name!r} in target reference")
            fields_seen[name] = _unescape_reference_value(value)
        missing = {"scanner", "rule", "scope"} - set(fields_seen)
        if missing:
            raise DomainError(f"target reference is missing {sorted(missing)}")
        return cls(scanner=fields_seen["scanner"], rule_id=fields_seen["rule"],
                   scope=fields_seen["scope"])

    def canonical_dict(self) -> dict:
        """Structured fields are retained in every report, alongside the derived forms."""
        return {"scanner": self.scanner, "rule_id": self.rule_id, "scope": self.scope,
                "reference": self.reference, "opaque_id": self.opaque_id,
                "display_ref": self.display_ref}


def require_target_identity(value: Any, name: str = "identity") -> TargetIdentity:
    require_exact_type(value, TargetIdentity, name)
    return value


@dataclass(frozen=True, slots=True)
class Target:
    """A target: an identity plus the baseline occurrence count."""

    identity: TargetIdentity
    baseline_occurrences: int = 1

    def __post_init__(self) -> None:
        require_target_identity(self.identity)
        if require_int(self.baseline_occurrences, "baseline_occurrences") < 1:
            raise DomainError(
                "baseline_occurrences must be >= 1: a target exists because the baseline "
                "had at least one occurrence"
            )

    @classmethod
    def of(cls, scanner: str, rule_id: str, scope: str,
           baseline_occurrences: int = 1) -> "Target":
        return cls(TargetIdentity(scanner, rule_id, scope), baseline_occurrences)

    @property
    def scanner(self) -> str:
        return self.identity.scanner

    @property
    def rule_id(self) -> str:
        return self.identity.rule_id

    @property
    def scope(self) -> str:
        return self.identity.scope

    def canonical_dict(self) -> dict:
        return {"identity": self.identity.canonical_dict(),
                "baseline_occurrences": self.baseline_occurrences}


@dataclass(frozen=True, slots=True)
class TargetDecision:
    """A classified target plus the policy decision about it.

    Binds `TargetIdentity`, not a string: authorisation must not depend on a
    concatenated form that two different targets can share.
    """

    identity: TargetIdentity
    outcome: Outcome
    policy_permitted: bool = False
    exception_id: str | None = None
    rejection_reason: str = ""

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        require_target_identity(self.identity)
        require_enum(self.outcome, Outcome, "outcome")
        require_bool(self.policy_permitted, "policy_permitted")
        if self.exception_id is not None:
            set_(self, "exception_id",
                 canonical_identifier(self.exception_id, "exception_id"))
        if self.policy_permitted and not self.exception_id:
            raise DomainError(
                f"target {self.identity.display_ref}: policy_permitted requires an "
                f"exception_id"
            )
        if self.rejection_reason:
            set_(self, "rejection_reason",
                 safe_report_text(self.rejection_reason, "rejection_reason"))

    @property
    def canonical_key(self) -> tuple:
        return (*self.identity.canonical_key, self.outcome.value, self.exception_id or "")

    def canonical_dict(self) -> dict:
        return {"identity": self.identity.canonical_dict(),
                "outcome": self.outcome.value,
                "policy_permitted": self.policy_permitted,
                "exception_id": self.exception_id or "",
                "rejection_reason": self.rejection_reason}


def rebuild_target_decision(decision: Any) -> TargetDecision:
    require_exact_type(decision, TargetDecision, "target decision")
    identity = decision.identity
    return TargetDecision(
        identity=TargetIdentity(str(identity.scanner), str(identity.rule_id),
                                str(identity.scope)),
        outcome=Outcome(decision.outcome.value),
        policy_permitted=bool(decision.policy_permitted),
        exception_id=None if decision.exception_id is None else str(decision.exception_id),
        rejection_reason=str(decision.rejection_reason),
    )


def permission_rejection_reason(decision: TargetDecision, policy: ExceptionPolicy,
                                evaluation_date: date) -> str | None:
    """Why a claimed permission does not hold, or None when it does."""
    require_exact_type(decision, TargetDecision, "decision")
    require_exact_type(policy, ExceptionPolicy, "policy")
    require_date(evaluation_date, "evaluation_date")
    if not decision.policy_permitted:
        return "not claimed"
    if decision.outcome in NEVER_PERMITTABLE_OUTCOMES:
        return f"{decision.outcome.value} is never exception-eligible"
    if decision.outcome not in PERMITTABLE_EXCEPTION_OUTCOMES:
        return f"{decision.outcome.value} is not in the exception-eligible set"
    record = policy.get(decision.exception_id)
    if record is None:
        return f"exception {decision.exception_id!r} not found in the trusted policy"
    if record.target.canonical_key != decision.identity.canonical_key:
        differing = [
            f"{field}: {getattr(record.target, field)!r} != "
            f"{getattr(decision.identity, field)!r}"
            for field in ("scanner", "rule_id", "scope")
            if getattr(record.target, field) != getattr(decision.identity, field)
        ]
        return (f"exception {record.exception_id} binds a different target "
                f"({'; '.join(differing)})")
    if decision.outcome not in record.permitted_outcomes:
        return (f"exception {record.exception_id} authorises "
                f"{sorted(o.value for o in record.permitted_outcomes)}, not "
                f"{decision.outcome.value}: approving one event does not approve another")
    if record.origin not in TRUSTED_EXCEPTION_ORIGINS:
        return (f"exception {record.exception_id} origin {record.origin.value!r} is not "
                f"trusted; a self-granted approval is not an approval")
    if record.created > evaluation_date:
        return (f"exception {record.exception_id} is not yet in force: created "
                f"{record.created.isoformat()}")
    if record.expires < evaluation_date:
        return f"exception {record.exception_id} expired on {record.expires.isoformat()}"
    return None


#: Every persistent model, for the immutability test matrix.
PERSISTENT_MODELS: tuple = (
    FindingLocation, Finding, CoverageCounters, ScannerRun, GateResult, RequiredGates,
    ExceptionRecord, ExceptionPolicy, TargetIdentity, Target, TargetDecision,
)
