"""Deterministic occurrence matching without trusting dense display ordinals.

Stable scanner-native occurrence evidence wins. When it is unavailable, equal locations
are paired first and only a unique remaining same-resource pairing may relocate. Equally
supported pairings become typed ``MATCHING_INCONCLUSIVE`` evidence; they are never
converted into guessed resolved/new findings.
"""
from __future__ import annotations

from collections import defaultdict
from collections import Counter
from dataclasses import dataclass

from .enums import IdentityTier, MatchingReason, SEVERITY_ORDER
from .fingerprints import compute_iacgv_fingerprint
from .models import DomainError, Finding, _rebuild_finding, require_enum, require_exact_type


def _location_key(finding: Finding) -> tuple[str, int, int]:
    return (
        finding.location.file_path,
        finding.location.start_line,
        finding.location.end_line,
    )


def _finding_order_key(finding: Finding) -> tuple:
    """Total canonical order; occurrence_index is a final display-only tiebreaker."""
    return (
        finding.match_domain_key,
        finding.rule_id,
        finding.resource_address,
        _location_key(finding),
        finding.native_fingerprint,
        finding.severity.value,
        finding.suppressed,
        finding.rule_name,
        finding.message,
        finding.occurrence_index,
        finding.iacgv_fingerprint,
    )


def _same_occurrence_relation(baseline: Finding, candidate: Finding) -> bool:
    if baseline.match_domain_key != candidate.match_domain_key:
        return False
    if (baseline.rule_id, baseline.resource_address) != (
        candidate.rule_id,
        candidate.resource_address,
    ):
        return False
    if baseline.native_fingerprint or candidate.native_fingerprint:
        return bool(
            baseline.native_fingerprint
            and baseline.native_fingerprint == candidate.native_fingerprint
        )
    return True


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
        if baseline.match_domain_key != candidate.match_domain_key:
            raise DomainError("FindingMatch requires one scanner/version/artifact match domain")
        if self.tier is IdentityTier.EXACT:
            if baseline.exact_key != candidate.exact_key:
                raise DomainError("EXACT match requires equal exact occurrence evidence")
        elif self.tier is IdentityTier.RELOCATED:
            if (baseline.rule_id, baseline.resource_address) != (
                candidate.rule_id,
                candidate.resource_address,
            ):
                raise DomainError("RELOCATED match requires the same resource occurrence")
            if baseline.exact_key == candidate.exact_key:
                raise DomainError("equal exact keys must be classified EXACT, not RELOCATED")
        else:
            raise DomainError("same-scanner multiset matching permits EXACT or RELOCATED only")
        if not _same_occurrence_relation(baseline, candidate):
            raise DomainError("FindingMatch requires compatible stable occurrence evidence")
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
        return (_finding_order_key(self.baseline), _finding_order_key(self.candidate), self.tier.value)

    def canonical_dict(self) -> dict:
        return {
            "tier": self.tier.value,
            "location_changed": self.location_changed,
            "severity_increased": self.severity_increased,
            "baseline": self.baseline.canonical_dict(),
            "candidate": self.candidate.canonical_dict(),
        }


@dataclass(frozen=True, slots=True)
class MatchingAmbiguity:
    baseline: tuple
    candidate: tuple
    reason: MatchingReason = MatchingReason.MATCHING_INCONCLUSIVE

    def __post_init__(self) -> None:
        require_enum(self.reason, MatchingReason, "matching ambiguity reason")
        for name in ("baseline", "candidate"):
            raw = getattr(self, name)
            if type(raw) is not tuple or not raw:
                raise DomainError(f"ambiguous {name} evidence must be a nonempty exact tuple")
            rebuilt = []
            for finding in raw:
                require_exact_type(finding, Finding, f"ambiguous {name} finding")
                rebuilt.append(_rebuild_finding(finding))
            object.__setattr__(self, name, tuple(sorted(rebuilt, key=_finding_order_key)))
        domains = {item.match_domain_key for item in (*self.baseline, *self.candidate)}
        if len(domains) != 1:
            raise DomainError("ambiguous findings must remain within one match domain")

    @property
    def canonical_key(self) -> tuple:
        return (
            self.reason.value,
            tuple(_finding_order_key(item) for item in self.baseline),
            tuple(_finding_order_key(item) for item in self.candidate),
        )

    def canonical_dict(self) -> dict:
        return {
            "reason": self.reason.value,
            "baseline": [item.canonical_dict() for item in self.baseline],
            "candidate": [item.canonical_dict() for item in self.candidate],
        }


@dataclass(frozen=True, slots=True)
class FindingMultisetComparison:
    matches: tuple
    unmatched_baseline: tuple
    unmatched_candidate: tuple
    ambiguities: tuple = ()

    def __post_init__(self) -> None:
        for name, expected in (
            ("matches", FindingMatch),
            ("unmatched_baseline", Finding),
            ("unmatched_candidate", Finding),
            ("ambiguities", MatchingAmbiguity),
        ):
            raw = getattr(self, name)
            if type(raw) is not tuple:
                raise DomainError(f"{name} must be an exact tuple")
            for value in raw:
                require_exact_type(value, expected, f"{name} entry")
        matches = tuple(FindingMatch(item.baseline, item.candidate, item.tier) for item in self.matches)
        baseline = tuple(_rebuild_finding(item) for item in self.unmatched_baseline)
        candidate = tuple(_rebuild_finding(item) for item in self.unmatched_candidate)
        ambiguities = tuple(
            MatchingAmbiguity(item.baseline, item.candidate, item.reason)
            for item in self.ambiguities
        )
        object.__setattr__(self, "matches", tuple(sorted(matches, key=lambda item: item.canonical_key)))
        object.__setattr__(self, "unmatched_baseline", tuple(sorted(baseline, key=_finding_order_key)))
        object.__setattr__(self, "unmatched_candidate", tuple(sorted(candidate, key=_finding_order_key)))
        object.__setattr__(self, "ambiguities", tuple(sorted(ambiguities, key=lambda item: item.canonical_key)))

    def canonical_dict(self) -> dict:
        return {
            "matches": [item.canonical_dict() for item in self.matches],
            "unmatched_baseline": [item.canonical_dict() for item in self.unmatched_baseline],
            "unmatched_candidate": [item.canonical_dict() for item in self.unmatched_candidate],
            "ambiguities": [item.canonical_dict() for item in self.ambiguities],
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
    duplicate_records = sorted(
        key for key, count in Counter(item.evidence_record_key for item in findings).items()
        if count > 1
    )
    if duplicate_records:
        raise DomainError(
            f"duplicate exact finding evidence at matching boundary: {duplicate_records}"
        )
    return tuple(sorted(findings, key=_finding_order_key))


def _validate_match_domain(
    baseline: tuple[Finding, ...], candidate: tuple[Finding, ...]
) -> None:
    baseline_domains = {item.match_domain_key for item in baseline}
    candidate_domains = {item.match_domain_key for item in candidate}
    for side, domains in (("baseline", baseline_domains), ("candidate", candidate_domains)):
        if len(domains) > 1:
            raise DomainError(
                f"{side} contains multiple versions or scanner/artifact match domains"
            )
    if baseline_domains and candidate_domains and baseline_domains != candidate_domains:
        before = next(iter(baseline_domains))
        after = next(iter(candidate_domains))
        prefix = "scanner version drift violates match domain: " if (
            before[0] == after[0] and before[1] != after[1] and before[2] == after[2]
        ) else "comparison requires one equal scanner/version/artifact match domain: "
        raise DomainError(
            prefix + f"{sorted(baseline_domains)} -> {sorted(candidate_domains)}"
        )


def _buckets(indices: list[int], items: tuple[Finding, ...], key) -> dict[tuple, list[int]]:
    grouped: dict[tuple, list[int]] = defaultdict(list)
    for index in indices:
        grouped[key(items[index])].append(index)
    return grouped


def compare_finding_multisets(
    baseline: tuple[Finding, ...] | list[Finding],
    candidate: tuple[Finding, ...] | list[Finding],
) -> FindingMultisetComparison:
    """Match stable evidence, then unique constraints, typing every unresolved tie."""
    baseline_items = _validated_findings(baseline, "baseline")
    candidate_items = _validated_findings(candidate, "candidate")
    _validate_match_domain(baseline_items, candidate_items)
    baseline_remaining = set(range(len(baseline_items)))
    candidate_remaining = set(range(len(candidate_items)))
    matches: list[FindingMatch] = []
    ambiguities: list[MatchingAmbiguity] = []

    def consume_pairs(key, tier: IdentityTier, stable_only: bool = False) -> None:
        baseline_indices = sorted(baseline_remaining)
        candidate_indices = sorted(candidate_remaining)
        if stable_only:
            baseline_indices = [i for i in baseline_indices if baseline_items[i].native_fingerprint]
            candidate_indices = [i for i in candidate_indices if candidate_items[i].native_fingerprint]
        baseline_groups = _buckets(baseline_indices, baseline_items, key)
        candidate_groups = _buckets(candidate_indices, candidate_items, key)
        for group in sorted(set(baseline_groups) & set(candidate_groups)):
            left = baseline_groups[group]
            right = candidate_groups[group]
            if len(left) == len(right) == 1:
                bi, ci = left[0], right[0]
                matches.append(FindingMatch(baseline_items[bi], candidate_items[ci], tier))
                baseline_remaining.remove(bi)
                candidate_remaining.remove(ci)
            elif tier is IdentityTier.EXACT:
                ambiguities.append(
                    MatchingAmbiguity(
                        tuple(baseline_items[i] for i in left),
                        tuple(candidate_items[i] for i in right),
                    )
                )
                baseline_remaining.difference_update(left)
                candidate_remaining.difference_update(right)

    consume_pairs(lambda item: item.exact_key, IdentityTier.EXACT)
    consume_pairs(lambda item: item.relocated_key, IdentityTier.RELOCATED, stable_only=True)

    baseline_groups = _buckets(
        sorted(baseline_remaining),
        baseline_items,
        lambda item: item.relocated_key[:-1],
    )
    candidate_groups = _buckets(
        sorted(candidate_remaining),
        candidate_items,
        lambda item: item.relocated_key[:-1],
    )
    for group in sorted(set(baseline_groups) & set(candidate_groups)):
        left = baseline_groups[group]
        right = candidate_groups[group]
        if len(left) == len(right) == 1:
            bi, ci = left[0], right[0]
            baseline_item = baseline_items[bi]
            candidate_item = candidate_items[ci]
            if baseline_item.native_fingerprint or candidate_item.native_fingerprint:
                ambiguities.append(MatchingAmbiguity((baseline_item,), (candidate_item,)))
            else:
                matches.append(FindingMatch(baseline_item, candidate_item, IdentityTier.RELOCATED))
            baseline_remaining.remove(bi)
            candidate_remaining.remove(ci)
        else:
            ambiguities.append(
                MatchingAmbiguity(
                    tuple(baseline_items[i] for i in left),
                    tuple(candidate_items[i] for i in right),
                )
            )
            baseline_remaining.difference_update(left)
            candidate_remaining.difference_update(right)

    return FindingMultisetComparison(
        tuple(matches),
        tuple(baseline_items[i] for i in sorted(baseline_remaining)),
        tuple(candidate_items[i] for i in sorted(candidate_remaining)),
        tuple(ambiguities),
    )


__all__ = [
    "FindingMatch",
    "FindingMultisetComparison",
    "MatchingAmbiguity",
    "compare_finding_multisets",
]
