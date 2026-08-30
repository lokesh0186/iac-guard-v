"""Bounded Helm-compatible semantic-version constraint evaluation.

The grammar and comparison behavior follow the dependency contract used by
Helm v4.2.4: github.com/Masterminds/semver/v3@v3.5.0. Resolved dependency
versions are deliberately required to be strict SemVer 2.0.0 strings; unlike
Masterminds ``NewVersion``, this verifier does not silently coerce protected
identity evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass


MAX_CONSTRAINT_BYTES = 512
MAX_CONSTRAINT_GROUPS = 32
MAX_CONSTRAINT_TERMS = 128
MAX_VERSION_BYTES = 256
MAX_UINT64 = (1 << 64) - 1

ENGINE_NAME = "github.com/Masterminds/semver/v3"
ENGINE_VERSION = "3.5.0"
IMPLEMENTATION_NAME = "iac-guard-v-internal-masterminds-compatible-v1"
HELM_CONTRACT = "helm-v4.2.4+g3900f43"

_IDENTIFIER = r"[0-9A-Za-z-]+"
_PRERELEASE = rf"{_IDENTIFIER}(?:\.{_IDENTIFIER})*"
_METADATA = _PRERELEASE
_STRICT_VERSION = re.compile(
    rf"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    rf"(?:-({_PRERELEASE}))?(?:\+({_METADATA}))?$",
    re.ASCII,
)
_PART = r"(?:[0-9]+|x|X|\*)"
_CONSTRAINT_VERSION_TEXT = (
    rf"v?{_PART}(?:\.{_PART})?(?:\.{_PART})?"
    rf"(?:-{_PRERELEASE})?(?:\+{_METADATA})?"
)
_CONSTRAINT_VERSION = re.compile(
    rf"^(v?)({_PART})(?:\.({_PART}))?(?:\.({_PART}))?"
    rf"(?:-({_PRERELEASE}))?(?:\+({_METADATA}))?$",
    re.ASCII,
)
_CONSTRAINT_AT = re.compile(_CONSTRAINT_VERSION_TEXT, re.ASCII)
_HYPHEN_RANGE = re.compile(
    rf"(?<!\S)({_CONSTRAINT_VERSION_TEXT})\s+-\s+"
    rf"({_CONSTRAINT_VERSION_TEXT})(?!\S)",
    re.ASCII,
)
_OPERATORS = ("!=", ">=", "=>", "<=", "=<", "~>", "=", ">", "<", "~", "^")


class HelmSemverError(ValueError):
    """Typed internal boundary for unsupported or contradictory version evidence."""

    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    metadata: tuple[str, ...] = ()

    def canonical(self) -> str:
        value = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            value += "-" + ".".join(self.prerelease)
        if self.metadata:
            value += "+" + ".".join(self.metadata)
        return value


@dataclass(frozen=True, slots=True)
class ConstraintTerm:
    operator: str
    original_version: str
    version: SemVer
    dirty: bool
    minor_dirty: bool
    patch_dirty: bool

    def evidence_dict(self) -> dict:
        return {
            "operator": self.operator,
            "original_version": self.original_version,
            "normalized_version": self.version.canonical(),
            "dirty": self.dirty,
            "minor_dirty": self.minor_dirty,
            "patch_dirty": self.patch_dirty,
        }


def _canonical_sha(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


_ENGINE_BODY = {
    "engine_name": ENGINE_NAME,
    "engine_version": ENGINE_VERSION,
    "implementation": IMPLEMENTATION_NAME,
    "helm_contract": HELM_CONTRACT,
    "constraint_max_bytes": MAX_CONSTRAINT_BYTES,
    "constraint_max_groups": MAX_CONSTRAINT_GROUPS,
    "constraint_max_terms": MAX_CONSTRAINT_TERMS,
    "resolved_version_parser": "STRICT_SEMVER_2_0_0",
    "prerelease_policy": "MASTERMIND_V3_5_0_AND_GROUP_OPT_IN",
}
ENGINE_IDENTITY = _canonical_sha(_ENGINE_BODY)


def _utf8_size(value: str, label: str, limit: int) -> int:
    try:
        payload = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise HelmSemverError("INVALID_ENCODING", f"{label} is not UTF-8") from exc
    if len(payload) > limit:
        raise HelmSemverError("RESOURCE_LIMIT", f"{label} exceeds {limit} bytes")
    return len(payload)


def _validated_number(value: str, label: str) -> int:
    if len(value) > 1 and value.startswith("0"):
        raise HelmSemverError(
            "UNSUPPORTED_COERCION", f"{label} has a leading zero"
        )
    parsed = int(value, 10)
    if parsed > MAX_UINT64:
        raise HelmSemverError("RESOURCE_LIMIT", f"{label} exceeds uint64")
    return parsed


def _parse_identifiers(value: str, *, prerelease: bool) -> tuple[str, ...]:
    if not value:
        return ()
    parts = tuple(value.split("."))
    for part in parts:
        if not part or re.fullmatch(_IDENTIFIER, part, re.ASCII) is None:
            raise HelmSemverError("MALFORMED_VERSION", "version identifier is invalid")
        if prerelease and part.isdigit() and len(part) > 1 and part.startswith("0"):
            raise HelmSemverError(
                "UNSUPPORTED_COERCION", "numeric prerelease identifier has a leading zero"
            )
    return parts


def parse_resolved_version(value: str) -> SemVer:
    if type(value) is not str or not value:
        raise HelmSemverError("MALFORMED_RESOLVED_VERSION", "resolved version is empty")
    _utf8_size(value, "resolved version", MAX_VERSION_BYTES)
    match = _STRICT_VERSION.fullmatch(value)
    if match is None:
        raise HelmSemverError(
            "MALFORMED_RESOLVED_VERSION",
            "resolved version is not strict SemVer 2.0.0",
        )
    return SemVer(
        _validated_number(match.group(1), "resolved major version"),
        _validated_number(match.group(2), "resolved minor version"),
        _validated_number(match.group(3), "resolved patch version"),
        _parse_identifiers(match.group(4) or "", prerelease=True),
        _parse_identifiers(match.group(5) or "", prerelease=False),
    )


def _is_wildcard(value: str | None) -> bool:
    return value in {"x", "X", "*"}


def _parse_constraint_version(value: str, operator: str) -> ConstraintTerm:
    match = _CONSTRAINT_VERSION.fullmatch(value)
    if match is None:
        raise HelmSemverError("MALFORMED_CONSTRAINT", "constraint term is malformed")
    major_raw, minor_raw, patch_raw = match.group(2), match.group(3), match.group(4)
    if _is_wildcard(major_raw) and (minor_raw is not None or patch_raw is not None):
        raise HelmSemverError(
            "UNSUPPORTED_CONSTRAINT", "components after a major wildcard are ambiguous"
        )
    if _is_wildcard(minor_raw) and patch_raw not in (None, "x", "X", "*"):
        raise HelmSemverError(
            "UNSUPPORTED_CONSTRAINT", "numeric patch after wildcard minor is ambiguous"
        )
    prerelease = _parse_identifiers(match.group(5) or "", prerelease=True)
    metadata = _parse_identifiers(match.group(6) or "", prerelease=False)
    dirty = False
    minor_dirty = False
    patch_dirty = False
    if _is_wildcard(major_raw):
        major = minor = patch = 0
        dirty = True
    else:
        major = _validated_number(major_raw, "constraint major version")
        if minor_raw is None or _is_wildcard(minor_raw):
            minor = patch = 0
            dirty = True
            minor_dirty = True
        else:
            minor = _validated_number(minor_raw, "constraint minor version")
            if patch_raw is None or _is_wildcard(patch_raw):
                patch = 0
                dirty = True
                patch_dirty = True
            else:
                patch = _validated_number(patch_raw, "constraint patch version")
    return ConstraintTerm(
        operator=operator,
        original_version=value,
        version=SemVer(major, minor, patch, prerelease, metadata),
        dirty=dirty,
        minor_dirty=minor_dirty,
        patch_dirty=patch_dirty,
    )


def _rewrite_hyphen_ranges(value: str) -> str:
    return _HYPHEN_RANGE.sub(lambda item: f">= {item.group(1)}, <= {item.group(2)}", value)


def _parse_group(value: str) -> tuple[ConstraintTerm, ...]:
    terms: list[ConstraintTerm] = []
    position = 0
    length = len(value)
    expecting_term = True
    while position < length:
        whitespace_start = position
        while position < length and value[position].isspace():
            position += 1
        if position < length and value[position] == ",":
            if expecting_term:
                raise HelmSemverError("MALFORMED_CONSTRAINT", "constraint has an empty term")
            position += 1
            expecting_term = True
            continue
        if position >= length:
            break
        if not expecting_term and position == whitespace_start:
            raise HelmSemverError("MALFORMED_CONSTRAINT", "constraint terms lack a separator")
        operator = ""
        for candidate in _OPERATORS:
            if value.startswith(candidate, position):
                operator = candidate
                position += len(candidate)
                break
        while position < length and value[position].isspace():
            position += 1
        match = _CONSTRAINT_AT.match(value, position)
        if match is None:
            raise HelmSemverError("MALFORMED_CONSTRAINT", "constraint term is malformed")
        raw_version = match.group(0)
        position = match.end()
        terms.append(_parse_constraint_version(raw_version, operator))
        if len(terms) > MAX_CONSTRAINT_TERMS:
            raise HelmSemverError("RESOURCE_LIMIT", "constraint has too many terms")
        expecting_term = False
        if position < length and not (value[position].isspace() or value[position] == ","):
            raise HelmSemverError("MALFORMED_CONSTRAINT", "constraint has trailing syntax")
        if position < length and value[position].isspace():
            expecting_term = True
    if not terms or expecting_term and value.rstrip().endswith(","):
        raise HelmSemverError("MALFORMED_CONSTRAINT", "constraint group is empty")
    return tuple(terms)


def parse_constraint(value: str) -> tuple[tuple[ConstraintTerm, ...], ...]:
    if type(value) is not str or not value:
        raise HelmSemverError("MALFORMED_CONSTRAINT", "constraint is empty")
    _utf8_size(value, "constraint", MAX_CONSTRAINT_BYTES)
    if any(
        ord(char) > 0x7F or (ord(char) < 0x20 and char not in "\t\n\f\r")
        for char in value
    ):
        raise HelmSemverError(
            "MALFORMED_CONSTRAINT",
            "constraint contains characters outside Helm's ASCII grammar",
        )
    rewritten = _rewrite_hyphen_ranges(value)
    groups_raw = rewritten.split("||")
    if len(groups_raw) > MAX_CONSTRAINT_GROUPS:
        raise HelmSemverError("RESOURCE_LIMIT", "constraint has too many OR groups")
    if any(not group.strip() for group in groups_raw):
        raise HelmSemverError("MALFORMED_CONSTRAINT", "constraint has an empty OR group")
    groups = tuple(_parse_group(group.strip()) for group in groups_raw)
    if sum(len(group) for group in groups) > MAX_CONSTRAINT_TERMS:
        raise HelmSemverError("RESOURCE_LIMIT", "constraint has too many terms")
    return groups


def _compare_prerelease(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    if not left and not right:
        return 0
    if not left:
        return 1
    if not right:
        return -1
    for first, second in zip(left, right):
        if first == second:
            continue
        first_numeric = first.isdigit()
        second_numeric = second.isdigit()
        if first_numeric and second_numeric:
            return -1 if int(first) < int(second) else 1
        if first_numeric != second_numeric:
            return -1 if first_numeric else 1
        return -1 if first < second else 1
    if len(left) == len(right):
        return 0
    return -1 if len(left) < len(right) else 1


def compare_versions(left: SemVer, right: SemVer) -> int:
    for first, second in (
        (left.major, right.major),
        (left.minor, right.minor),
        (left.patch, right.patch),
    ):
        if first != second:
            return -1 if first < second else 1
    return _compare_prerelease(left.prerelease, right.prerelease)


def _check_term(candidate: SemVer, term: ConstraintTerm) -> bool:
    constraint = term.version
    compared = compare_versions(candidate, constraint)
    operator = term.operator
    if operator in {"", "="}:
        if not term.dirty:
            return compared == 0
        operator = "~"
    if operator == "!=":
        if term.dirty:
            if constraint.major != candidate.major:
                return True
            if constraint.minor != candidate.minor and not term.minor_dirty:
                return True
            if term.minor_dirty:
                return False
            if constraint.patch != candidate.patch and not term.patch_dirty:
                return True
            if term.patch_dirty:
                if candidate.prerelease or constraint.prerelease:
                    return _compare_prerelease(
                        candidate.prerelease, constraint.prerelease
                    ) != 0
                return False
        return compared != 0
    if operator == ">":
        if not term.dirty:
            return compared > 0
        if candidate.major != constraint.major:
            return candidate.major > constraint.major
        if term.minor_dirty:
            return False
        if term.patch_dirty:
            return candidate.minor > constraint.minor
        return compared > 0
    if operator == "<":
        return compared < 0
    if operator in {">=", "=>"}:
        return compared >= 0
    if operator in {"<=", "=<"}:
        if not term.dirty:
            return compared <= 0
        if candidate.major > constraint.major:
            return False
        if (
            candidate.major == constraint.major
            and candidate.minor > constraint.minor
            and not term.minor_dirty
        ):
            return False
        return True
    if operator in {"~", "~>"}:
        if compared < 0:
            return False
        if (
            constraint.major == constraint.minor == constraint.patch == 0
            and not term.minor_dirty
            and not term.patch_dirty
        ):
            return True
        if candidate.major != constraint.major:
            return False
        if candidate.minor != constraint.minor and not term.minor_dirty:
            return False
        return True
    if operator == "^":
        if compared < 0:
            return False
        if constraint.major > 0 or term.minor_dirty:
            return candidate.major == constraint.major
        if candidate.major > 0:
            return False
        if constraint.minor > 0 or term.patch_dirty:
            return candidate.minor == constraint.minor
        if candidate.minor > 0:
            return False
        return candidate.patch == constraint.patch
    raise HelmSemverError("UNSUPPORTED_CONSTRAINT", "constraint operator is unsupported")


def constraint_satisfied(
    groups: tuple[tuple[ConstraintTerm, ...], ...], candidate: SemVer
) -> bool:
    for group in groups:
        contains_prerelease = any(term.version.prerelease for term in group)
        if candidate.prerelease and not contains_prerelease:
            continue
        if all(_check_term(candidate, term) for term in group):
            return True
    return False


def prove_constraint(declared_constraint: str, resolved_version: str) -> dict:
    groups = parse_constraint(declared_constraint)
    resolved = parse_resolved_version(resolved_version)
    ast = [[term.evidence_dict() for term in group] for group in groups]
    satisfied = constraint_satisfied(groups, resolved)
    return {
        "declared_constraint": declared_constraint,
        "declared_constraint_sha256": hashlib.sha256(
            declared_constraint.encode("utf-8")
        ).hexdigest(),
        "parsed_constraint_semantic_identity": _canonical_sha(ast),
        "constraint_ast": ast,
        "resolved_version": resolved_version,
        "resolved_version_canonical": resolved.canonical(),
        "constraint_engine": ENGINE_NAME,
        "constraint_engine_version": ENGINE_VERSION,
        "constraint_implementation": IMPLEMENTATION_NAME,
        "constraint_engine_identity": ENGINE_IDENTITY,
        "helm_constraint_contract": HELM_CONTRACT,
        "prerelease_policy": _ENGINE_BODY["prerelease_policy"],
        "satisfied": satisfied,
    }
