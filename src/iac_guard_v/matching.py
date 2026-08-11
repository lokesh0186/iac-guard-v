"""Deterministic, occurrence-preserving finding multiset matching.

Matching is exact first.  Remaining findings may relocate only when scanner, rule,
resource address, and occurrence index remain identical.  A rule moving from resource A
to resource B is therefore unmatched on both sides, never disguised as relocation.
"""
from __future__ import annotations

from dataclasses import dataclass

from .enums import IdentityTier, SEVERITY_ORDER
from .fingerprints import compute_iacgv_fingerprint
from .models import DomainError, Finding, _rebuild_finding, require_enum, require_exact_type


def _location_key(finding: Finding) -> tuple[str, int, int]:
    return (
        finding.location.file_path,
        finding.location.start_line,
        finding.location.end_line,
    )


@dataclass(frozen=True, slots=True)
class FindingMatch:
    baseline: Finding
    candidate: Finding
    tier: IdentityTier

    def __post_init__(self) -> None:
        require_exact_type(self.baseline, Finding, "baseline finding")
        require_exact_type(self.candidate, Finding, "candidate finding")
        require_enum(self.tier, IdentityTier, "matching tier")
        baseline = _rebuild_finding(self.baseline)
        candidate = _rebuild_finding(self.candidate)
        for label, finding in (("baseline", baseline), ("candidate", candidate)):
            if finding.iacgv_fingerprint and finding.iacgv_fingerprint != compute_iacgv_fingerprint(finding):
                raise DomainError(f"{label} finding carries a forged iacgv_fingerprint")
        if self.tier is IdentityTier.EXACT:
            if baseline.exact_key != candidate.exact_key:
                raise DomainError("EXACT match requires equal exact finding keys")
        elif self.tier is IdentityTier.RELOCATED:
            if baseline.relocated_key != candidate.relocated_key:
                raise DomainError("RELOCATED match requires the same resource occurrence")
            if baseline.exact_key == candidate.exact_key:
                raise DomainError("equal exact keys must be classified EXACT, not RELOCATED")
        else:
            raise DomainError("same-scanner multiset matching permits EXACT or RELOCATED only")
        object.__setattr__(self, "baseline", baseline)
        object.__setattr__(self, "candidate", candidate)

    @property
    def location_changed(self) -> bool:
        return _location_key(self.baseline) != _location_key(self.candidate)

    @property
    def severity_increased(self) -> bool:
        return SEVERITY_ORDER.index(self.candidate.severity) > SEVERITY_ORDER.index(
            self.baseline.severity
        )

    @property
    def canonical_key(self) -> tuple:
        return (self.baseline.exact_key, self.candidate.exact_key, self.tier.value)

    def canonical_dict(self) -> dict:
        return {
            "tier": self.tier.value,
            "location_changed": self.location_changed,
            "severity_increased": self.severity_increased,
            "baseline": self.baseline.canonical_dict(),
            "candidate": self.candidate.canonical_dict(),
        }


@dataclass(frozen=True, slots=True)
class FindingMultisetComparison:
    matches: tuple
    unmatched_baseline: tuple
    unmatched_candidate: tuple

    def __post_init__(self) -> None:
        for name, expected in (
            ("matches", FindingMatch),
            ("unmatched_baseline", Finding),
            ("unmatched_candidate", Finding),
        ):
            raw = getattr(self, name)
            if type(raw) is not tuple:
                raise DomainError(f"{name} must be an exact tuple")
            for value in raw:
                require_exact_type(value, expected, f"{name} entry")
        matches = tuple(
            FindingMatch(item.baseline, item.candidate, item.tier) for item in self.matches
        )
        baseline = tuple(_rebuild_finding(item) for item in self.unmatched_baseline)
        candidate = tuple(_rebuild_finding(item) for item in self.unmatched_candidate)
        object.__setattr__(self, "matches", tuple(sorted(matches, key=lambda item: item.canonical_key)))
        object.__setattr__(self, "unmatched_baseline", tuple(sorted(baseline, key=lambda item: item.exact_key)))
        object.__setattr__(self, "unmatched_candidate", tuple(sorted(candidate, key=lambda item: item.exact_key)))

    def canonical_dict(self) -> dict:
        return {
            "matches": [item.canonical_dict() for item in self.matches],
            "unmatched_baseline": [item.canonical_dict() for item in self.unmatched_baseline],
            "unmatched_candidate": [item.canonical_dict() for item in self.unmatched_candidate],
        }


def _validated_findings(raw: object, label: str) -> tuple[Finding, ...]:
    if type(raw) not in (tuple, list):
        raise DomainError(f"{label} findings must be an exact tuple or list")
    findings: list[Finding] = []
    for item in raw:
        require_exact_type(item, Finding, f"{label} finding")
        rebuilt = _rebuild_finding(item)
        if rebuilt.iacgv_fingerprint:
            expected = compute_iacgv_fingerprint(rebuilt)
            if rebuilt.iacgv_fingerprint != expected:
                raise DomainError(f"{label} finding carries a forged iacgv_fingerprint")
        findings.append(rebuilt)
    keys = [item.exact_key for item in findings]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        raise DomainError(f"duplicate exact finding identities at matching boundary: {duplicates}")
    return tuple(sorted(findings, key=lambda item: item.exact_key))


def _reject_version_drift(
    baseline: tuple[Finding, ...], candidate: tuple[Finding, ...]
) -> None:
    def versions(findings: tuple[Finding, ...]) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for finding in findings:
            result.setdefault(finding.scanner, set()).add(finding.scanner_version)
        return result

    baseline_versions = versions(baseline)
    candidate_versions = versions(candidate)
    for side, values in (("baseline", baseline_versions), ("candidate", candidate_versions)):
        for scanner, scanner_versions in values.items():
            if len(scanner_versions) != 1:
                raise DomainError(
                    f"{side} has multiple versions for scanner {scanner!r}: "
                    f"{sorted(scanner_versions)}"
                )
    for scanner in sorted(set(baseline_versions) & set(candidate_versions)):
        if baseline_versions[scanner] != candidate_versions[scanner]:
            raise DomainError(
                f"scanner version drift for {scanner!r}: "
                f"{sorted(baseline_versions[scanner])} -> {sorted(candidate_versions[scanner])}"
            )


def compare_finding_multisets(
    baseline: tuple[Finding, ...] | list[Finding],
    candidate: tuple[Finding, ...] | list[Finding],
) -> FindingMultisetComparison:
    """Match exact occurrences, then unambiguous same-resource relocations."""
    baseline_items = _validated_findings(baseline, "baseline")
    candidate_items = _validated_findings(candidate, "candidate")
    _reject_version_drift(baseline_items, candidate_items)

    candidate_by_exact = {item.exact_key: item for item in candidate_items}
    matches: list[FindingMatch] = []
    unmatched_baseline: list[Finding] = []
    matched_candidate_keys: set[tuple] = set()
    for baseline_item in baseline_items:
        candidate_item = candidate_by_exact.get(baseline_item.exact_key)
        if candidate_item is None:
            unmatched_baseline.append(baseline_item)
        else:
            matches.append(FindingMatch(baseline_item, candidate_item, IdentityTier.EXACT))
            matched_candidate_keys.add(candidate_item.exact_key)
    unmatched_candidate = [
        item for item in candidate_items if item.exact_key not in matched_candidate_keys
    ]

    def grouped_relocated(items: list[Finding]) -> dict[tuple, list[Finding]]:
        grouped: dict[tuple, list[Finding]] = {}
        for item in items:
            grouped.setdefault(item.relocated_key, []).append(item)
        return grouped

    baseline_relocated = grouped_relocated(unmatched_baseline)
    candidate_relocated = grouped_relocated(unmatched_candidate)
    common_relocated = set(baseline_relocated) & set(candidate_relocated)
    ambiguous = sorted(
        key
        for key in common_relocated
        if len(baseline_relocated[key]) != 1 or len(candidate_relocated[key]) != 1
    )
    if ambiguous:
        raise DomainError(
            f"ambiguous relocated identities: {ambiguous}; occurrence evidence "
            "is insufficient and must not be guessed"
        )
    baseline_by_relocated = {key: values[0] for key, values in baseline_relocated.items()}
    candidate_by_relocated = {key: values[0] for key, values in candidate_relocated.items()}
    relocated_keys = sorted(common_relocated)
    for key in relocated_keys:
        matches.append(
            FindingMatch(
                baseline_by_relocated[key],
                candidate_by_relocated[key],
                IdentityTier.RELOCATED,
            )
        )
    relocated_set = set(relocated_keys)
    final_baseline = tuple(
        item for item in unmatched_baseline if item.relocated_key not in relocated_set
    )
    final_candidate = tuple(
        item for item in unmatched_candidate if item.relocated_key not in relocated_set
    )
    return FindingMultisetComparison(tuple(matches), final_baseline, final_candidate)


__all__ = ["FindingMatch", "FindingMultisetComparison", "compare_finding_multisets"]
