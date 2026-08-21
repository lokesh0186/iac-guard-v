"""Deterministic occurrence matching without trusting dense display ordinals.

Stable scanner-native occurrence evidence wins. When it is unavailable, equal locations
are paired first and only a unique remaining same-resource pairing may relocate. Equally
supported pairings become typed ``MATCHING_INCONCLUSIVE`` evidence; they are never
converted into guessed resolved/new findings.
"""
from __future__ import annotations

from collections import defaultdict
from collections import Counter
from dataclasses import InitVar, dataclass, field

from .enums import IdentityTier, MatchingReason, SEVERITY_ORDER
from .fingerprints import compute_iacgv_fingerprint
from .models import DomainError, Finding, _rebuild_finding, require_enum, require_exact_type


_TRUSTED_MATCHING_CONTEXT = object()


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
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
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
        if _trusted_context is not _TRUSTED_MATCHING_CONTEXT:
            raise DomainError("FindingMatch requires trusted comparison context")
        object.__setattr__(self, "baseline", baseline)
        object.__setattr__(self, "candidate", candidate)
        object.__setattr__(self, "_trusted", True)

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
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
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
        if _trusted_context is not _TRUSTED_MATCHING_CONTEXT:
            raise DomainError("MatchingAmbiguity requires trusted comparison context")
        object.__setattr__(self, "_trusted", True)

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
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
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
        matches = tuple(
            FindingMatch(
                item.baseline,
                item.candidate,
                item.tier,
                _trusted_context=_TRUSTED_MATCHING_CONTEXT,
            )
            for item in self.matches
        )
        baseline = tuple(_rebuild_finding(item) for item in self.unmatched_baseline)
        candidate = tuple(_rebuild_finding(item) for item in self.unmatched_candidate)
        ambiguities = tuple(
            MatchingAmbiguity(
                item.baseline,
                item.candidate,
                item.reason,
                _trusted_context=_TRUSTED_MATCHING_CONTEXT,
            )
            for item in self.ambiguities
        )
        object.__setattr__(self, "matches", tuple(sorted(matches, key=lambda item: item.canonical_key)))
        object.__setattr__(self, "unmatched_baseline", tuple(sorted(baseline, key=_finding_order_key)))
        object.__setattr__(self, "unmatched_candidate", tuple(sorted(candidate, key=_finding_order_key)))
        object.__setattr__(self, "ambiguities", tuple(sorted(ambiguities, key=lambda item: item.canonical_key)))
        if _trusted_context is not _TRUSTED_MATCHING_CONTEXT:
            raise DomainError("FindingMultisetComparison requires trusted comparison context")
        object.__setattr__(self, "_trusted", True)

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


def _validate_run_identity(
    baseline: tuple[Finding, ...], candidate: tuple[Finding, ...]
) -> None:
    """Allow many artifact domains, but never blur scanner/version integrity."""
    baseline_runs = {(item.scanner, item.scanner_version) for item in baseline}
    candidate_runs = {(item.scanner, item.scanner_version) for item in candidate}
    for side, runs in (("baseline", baseline_runs), ("candidate", candidate_runs)):
        if len(runs) > 1:
            raise DomainError(
                f"{side} contains multiple versions or scanner identities in one run"
            )
    if baseline_runs and candidate_runs and baseline_runs != candidate_runs:
        before = next(iter(baseline_runs))
        after = next(iter(candidate_runs))
        if before[0] != after[0]:
            raise DomainError(
                f"scanner identity drift violates match domain integrity: {before} -> {after}"
            )
        raise DomainError(
            f"scanner version drift violates match domain integrity: {before} -> {after}"
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
    _validate_run_identity(baseline_items, candidate_items)
    baseline_remaining = set(range(len(baseline_items)))
    candidate_remaining = set(range(len(candidate_items)))
    matches: list[FindingMatch] = []
    ambiguities: list[MatchingAmbiguity] = []

    baseline_domains = _buckets(
        sorted(baseline_remaining), baseline_items, lambda item: item.match_domain_key
    )
    candidate_domains = _buckets(
        sorted(candidate_remaining), candidate_items, lambda item: item.match_domain_key
    )
    for domain in sorted(set(baseline_domains) & set(candidate_domains)):
        domain_baseline = set(baseline_domains[domain])
        domain_candidate = set(candidate_domains[domain])

        # Stable native occurrence evidence is authoritative despite multiplicity churn.
        native_baseline = _buckets(
            sorted(i for i in domain_baseline if baseline_items[i].native_fingerprint),
            baseline_items,
            lambda item: (item.rule_id, item.resource_address, item.native_fingerprint),
        )
        native_candidate = _buckets(
            sorted(i for i in domain_candidate if candidate_items[i].native_fingerprint),
            candidate_items,
            lambda item: (item.rule_id, item.resource_address, item.native_fingerprint),
        )
        for key in sorted(set(native_baseline) & set(native_candidate)):
            left = native_baseline[key]
            right = native_candidate[key]
            if len(left) == len(right) == 1:
                bi, ci = left[0], right[0]
                tier = (
                    IdentityTier.EXACT
                    if baseline_items[bi].exact_key == candidate_items[ci].exact_key
                    else IdentityTier.RELOCATED
                )
                matches.append(
                    FindingMatch(
                        baseline_items[bi],
                        candidate_items[ci],
                        tier,
                        _trusted_context=_TRUSTED_MATCHING_CONTEXT,
                    )
                )
                domain_baseline.remove(bi)
                domain_candidate.remove(ci)
                baseline_remaining.remove(bi)
                candidate_remaining.remove(ci)
            else:
                ambiguities.append(
                    MatchingAmbiguity(
                        tuple(baseline_items[i] for i in left),
                        tuple(candidate_items[i] for i in right),
                        _trusted_context=_TRUSTED_MATCHING_CONTEXT,
                    )
                )
                domain_baseline.difference_update(left)
                domain_candidate.difference_update(right)
                baseline_remaining.difference_update(left)
                candidate_remaining.difference_update(right)

        # No-native occurrences are judged as a complete rule/resource group. Reusing
        # one old location during cardinality churn does not establish identity.
        no_native_baseline = _buckets(
            sorted(i for i in domain_baseline if not baseline_items[i].native_fingerprint),
            baseline_items,
            lambda item: (item.rule_id, item.resource_address),
        )
        no_native_candidate = _buckets(
            sorted(i for i in domain_candidate if not candidate_items[i].native_fingerprint),
            candidate_items,
            lambda item: (item.rule_id, item.resource_address),
        )
        for key in sorted(set(no_native_baseline) & set(no_native_candidate)):
            left = no_native_baseline[key]
            right = no_native_candidate[key]
            if len(left) == len(right) == 1:
                bi, ci = left[0], right[0]
                tier = (
                    IdentityTier.EXACT
                    if baseline_items[bi].exact_key == candidate_items[ci].exact_key
                    else IdentityTier.RELOCATED
                )
                matches.append(
                    FindingMatch(
                        baseline_items[bi],
                        candidate_items[ci],
                        tier,
                        _trusted_context=_TRUSTED_MATCHING_CONTEXT,
                    )
                )
            else:
                left_locations = [_location_key(baseline_items[i]) for i in left]
                right_locations = [_location_key(candidate_items[i]) for i in right]
                location_pairing_proven = (
                    len(left) == len(right)
                    and len(set(left_locations)) == len(left_locations)
                    and len(set(right_locations)) == len(right_locations)
                    and set(left_locations) == set(right_locations)
                )
                if location_pairing_proven:
                    left_by_location = {
                        _location_key(baseline_items[i]): i for i in left
                    }
                    right_by_location = {
                        _location_key(candidate_items[i]): i for i in right
                    }
                    for location in sorted(left_by_location):
                        bi = left_by_location[location]
                        ci = right_by_location[location]
                        matches.append(
                            FindingMatch(
                                baseline_items[bi],
                                candidate_items[ci],
                                IdentityTier.EXACT,
                                _trusted_context=_TRUSTED_MATCHING_CONTEXT,
                            )
                        )
                else:
                    ambiguities.append(
                        MatchingAmbiguity(
                            tuple(baseline_items[i] for i in left),
                            tuple(candidate_items[i] for i in right),
                            _trusted_context=_TRUSTED_MATCHING_CONTEXT,
                        )
                    )
            domain_baseline.difference_update(left)
            domain_candidate.difference_update(right)
            baseline_remaining.difference_update(left)
            candidate_remaining.difference_update(right)

    return FindingMultisetComparison(
        tuple(matches),
        tuple(baseline_items[i] for i in sorted(baseline_remaining)),
        tuple(candidate_items[i] for i in sorted(candidate_remaining)),
        tuple(ambiguities),
        _trusted_context=_TRUSTED_MATCHING_CONTEXT,
    )


def require_trusted_comparison(value: object) -> FindingMultisetComparison:
    """D5 boundary: accept only output created by this module's matcher."""
    require_exact_type(value, FindingMultisetComparison, "finding comparison")
    if not value._trusted:
        raise DomainError("finding comparison is caller-authored, not trusted evidence")
    return value


__all__ = [
    "FindingMatch",
    "FindingMultisetComparison",
    "MatchingAmbiguity",
    "compare_finding_multisets",
    "require_trusted_comparison",
]
