"""Finding-derived regression deltas over deterministic multiset matches.

This D3 module emits only deltas established by finding evidence. Coverage, policy drift,
destructive plan changes, and cross-scanner rule substitution require later engine inputs
and are intentionally not guessed here.
"""
from __future__ import annotations

from dataclasses import dataclass

from .enums import DeltaClass
from .fingerprints import compute_iacgv_fingerprint
from .matching import compare_finding_multisets
from .models import (
    MAX_MESSAGE_LENGTH,
    DomainError,
    Finding,
    _rebuild_finding,
    require_enum,
    require_exact_type,
    safe_report_text,
)

_FINDING_DELTA_CLASSES = frozenset(
    {
        DeltaClass.NEW_FINDING,
        DeltaClass.LOCATION_CHANGED,
        DeltaClass.SEVERITY_INCREASED,
        DeltaClass.SCOPE_EXPANDED,
        DeltaClass.SUPPRESSION_ADDED,
        DeltaClass.RESOLVED_FINDING,
    }
)


@dataclass(frozen=True, slots=True)
class FindingDelta:
    delta_class: DeltaClass
    baseline: Finding | None = None
    candidate: Finding | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        require_enum(self.delta_class, DeltaClass, "delta_class")
        if self.delta_class not in _FINDING_DELTA_CLASSES:
            raise DomainError(
                f"{self.delta_class.value} requires later engine evidence and cannot be "
                "publicly constructed as a finding-only delta"
            )
        if self.baseline is not None:
            require_exact_type(self.baseline, Finding, "baseline finding")
            baseline = _rebuild_finding(self.baseline)
            if baseline.iacgv_fingerprint:
                if baseline.iacgv_fingerprint != compute_iacgv_fingerprint(baseline):
                    raise DomainError("baseline finding carries a forged iacgv_fingerprint")
            object.__setattr__(self, "baseline", baseline)
        if self.candidate is not None:
            require_exact_type(self.candidate, Finding, "candidate finding")
            candidate = _rebuild_finding(self.candidate)
            if candidate.iacgv_fingerprint:
                if candidate.iacgv_fingerprint != compute_iacgv_fingerprint(candidate):
                    raise DomainError("candidate finding carries a forged iacgv_fingerprint")
            object.__setattr__(self, "candidate", candidate)
        if self.detail:
            object.__setattr__(
                self, "detail", safe_report_text(self.detail, "delta detail", MAX_MESSAGE_LENGTH)
            )
        elif type(self.detail) is not str:
            raise DomainError("delta detail must be a string")
        pair_required = {
            DeltaClass.LOCATION_CHANGED,
            DeltaClass.SEVERITY_INCREASED,
            DeltaClass.SUPPRESSION_ADDED,
        }
        if self.delta_class in pair_required and (
            self.baseline is None or self.candidate is None
        ):
            raise DomainError(f"{self.delta_class.value} requires both finding sides")
        if self.delta_class is DeltaClass.NEW_FINDING and (
            self.baseline is not None or self.candidate is None
        ):
            raise DomainError("NEW_FINDING requires candidate evidence only")
        if self.delta_class is DeltaClass.RESOLVED_FINDING and (
            self.baseline is None or self.candidate is not None
        ):
            raise DomainError("RESOLVED_FINDING requires baseline evidence only")
        if self.delta_class is DeltaClass.SCOPE_EXPANDED and self.candidate is None:
            raise DomainError("SCOPE_EXPANDED requires candidate evidence")

    @property
    def canonical_key(self) -> tuple:
        baseline_key = self.baseline.exact_key if self.baseline else ()
        candidate_key = self.candidate.exact_key if self.candidate else ()
        return (self.delta_class.value, baseline_key, candidate_key, self.detail)

    def canonical_dict(self) -> dict:
        return {
            "delta_class": self.delta_class.value,
            "baseline": self.baseline.canonical_dict() if self.baseline else None,
            "candidate": self.candidate.canonical_dict() if self.candidate else None,
            "detail": self.detail,
        }


def diff_findings(
    baseline: tuple[Finding, ...] | list[Finding],
    candidate: tuple[Finding, ...] | list[Finding],
) -> tuple[FindingDelta, ...]:
    """Return canonical finding-derived deltas without collapsing occurrences."""
    if type(baseline) not in (tuple, list) or type(candidate) not in (tuple, list):
        raise DomainError("finding multisets must be exact tuple or list values")
    baseline_snapshot = tuple(baseline)
    candidate_snapshot = tuple(candidate)
    comparison = compare_finding_multisets(baseline_snapshot, candidate_snapshot)
    deltas: list[FindingDelta] = []
    for match in comparison.matches:
        if match.location_changed:
            deltas.append(
                FindingDelta(
                    DeltaClass.LOCATION_CHANGED, match.baseline, match.candidate
                )
            )
        if match.severity_increased:
            deltas.append(
                FindingDelta(
                    DeltaClass.SEVERITY_INCREASED, match.baseline, match.candidate
                )
            )
        if not match.baseline.suppressed and match.candidate.suppressed:
            deltas.append(
                FindingDelta(
                    DeltaClass.SUPPRESSION_ADDED, match.baseline, match.candidate
                )
            )
    for finding in comparison.unmatched_candidate:
        deltas.append(FindingDelta(DeltaClass.NEW_FINDING, candidate=finding))
    for finding in comparison.unmatched_baseline:
        deltas.append(FindingDelta(DeltaClass.RESOLVED_FINDING, baseline=finding))

    baseline_groups: dict[tuple[str, str], set[str]] = {}
    candidate_groups: dict[tuple[str, str], set[str]] = {}
    candidate_by_group_resource: dict[tuple[str, str, str], Finding] = {}
    for finding in baseline_snapshot:
        require_exact_type(finding, Finding, "baseline finding")
        baseline_groups.setdefault((finding.scanner, finding.rule_id), set()).add(
            finding.resource_address
        )
    for finding in candidate_snapshot:
        require_exact_type(finding, Finding, "candidate finding")
        group = (finding.scanner, finding.rule_id)
        candidate_groups.setdefault(group, set()).add(finding.resource_address)
        key = (*group, finding.resource_address)
        prior = candidate_by_group_resource.get(key)
        if prior is None or finding.exact_key < prior.exact_key:
            candidate_by_group_resource[key] = finding
    for group in sorted(set(baseline_groups) & set(candidate_groups)):
        before = baseline_groups[group]
        after = candidate_groups[group]
        if before < after:
            for resource in sorted(after - before):
                evidence = candidate_by_group_resource[(*group, resource)]
                deltas.append(
                    FindingDelta(
                        DeltaClass.SCOPE_EXPANDED,
                        candidate=evidence,
                        detail=f"{group[0]}:{group[1]} added resource {resource}",
                    )
                )
    return tuple(sorted(deltas, key=lambda item: item.canonical_key))


__all__ = ["FindingDelta", "diff_findings"]
