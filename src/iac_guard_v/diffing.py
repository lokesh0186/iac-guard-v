"""Finding-derived regression deltas backed by executable predicates."""
from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import InitVar, dataclass, field

from .enums import DeltaClass, SEVERITY_ORDER
from .fingerprints import compute_iacgv_fingerprint
from .matching import (
    MatchingAmbiguity,
    compare_finding_multisets,
    require_trusted_comparison,
)
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
_TRUSTED_DIFF_CONTEXT = object()


def _location(finding: Finding) -> tuple[str, int, int]:
    return (
        finding.location.file_path,
        finding.location.start_line,
        finding.location.end_line,
    )


def _pair_identity_is_proven(baseline: Finding, candidate: Finding) -> bool:
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
class ScopeExpansionEvidence:
    """Complete same-domain rule groups proving a strict resource-set expansion."""

    baseline_findings: tuple
    candidate_findings: tuple

    def __post_init__(self) -> None:
        for name in ("baseline_findings", "candidate_findings"):
            raw = getattr(self, name)
            if type(raw) is not tuple or not raw:
                raise DomainError(f"{name} must be a nonempty exact tuple")
            rebuilt = []
            for item in raw:
                require_exact_type(item, Finding, f"{name} entry")
                rebuilt.append(_rebuild_finding(item))
            object.__setattr__(
                self,
                name,
                tuple(sorted(rebuilt, key=lambda item: item.canonical_order_key)),
            )
        group_keys = {
            (item.match_domain_key, item.rule_id)
            for item in (*self.baseline_findings, *self.candidate_findings)
        }
        if len(group_keys) != 1:
            raise DomainError("scope expansion evidence must cover one rule match domain")
        if not self.baseline_resources < self.candidate_resources:
            raise DomainError("scope expansion requires a strict resource-set superset")

    @property
    def baseline_resources(self) -> frozenset[str]:
        return frozenset(item.resource_address for item in self.baseline_findings)

    @property
    def candidate_resources(self) -> frozenset[str]:
        return frozenset(item.resource_address for item in self.candidate_findings)

    @property
    def added_resources(self) -> frozenset[str]:
        return self.candidate_resources - self.baseline_resources

    def canonical_dict(self) -> dict:
        return {
            "baseline_resources": sorted(self.baseline_resources),
            "candidate_resources": sorted(self.candidate_resources),
            "added_resources": sorted(self.added_resources),
        }


@dataclass(frozen=True, slots=True)
class FindingDelta:
    delta_class: DeltaClass
    baseline: Finding | None = None
    candidate: Finding | None = None
    detail: str = ""
    scope_evidence: ScopeExpansionEvidence | None = None
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_enum(self.delta_class, DeltaClass, "delta_class")
        if self.delta_class not in _FINDING_DELTA_CLASSES:
            raise DomainError(
                f"{self.delta_class.value} requires later engine evidence and cannot be "
                "publicly constructed as a finding-only delta"
            )
        for name in ("baseline", "candidate"):
            finding = getattr(self, name)
            if finding is None:
                continue
            require_exact_type(finding, Finding, f"{name} finding")
            rebuilt = _rebuild_finding(finding)
            if rebuilt.iacgv_fingerprint and rebuilt.iacgv_fingerprint != compute_iacgv_fingerprint(rebuilt):
                raise DomainError(f"{name} finding carries a forged iacgv_fingerprint")
            object.__setattr__(self, name, rebuilt)
        if self.detail:
            object.__setattr__(
                self,
                "detail",
                safe_report_text(self.detail, "delta detail", MAX_MESSAGE_LENGTH),
            )
        elif type(self.detail) is not str:
            raise DomainError("delta detail must be a string")
        if self.scope_evidence is not None:
            require_exact_type(self.scope_evidence, ScopeExpansionEvidence, "scope_evidence")
            object.__setattr__(
                self,
                "scope_evidence",
                ScopeExpansionEvidence(
                    self.scope_evidence.baseline_findings,
                    self.scope_evidence.candidate_findings,
                ),
            )

        pair_required = {
            DeltaClass.LOCATION_CHANGED,
            DeltaClass.SEVERITY_INCREASED,
            DeltaClass.SUPPRESSION_ADDED,
        }
        if self.delta_class in pair_required:
            if self.baseline is None or self.candidate is None:
                raise DomainError(f"{self.delta_class.value} requires both finding sides")
            if not _pair_identity_is_proven(self.baseline, self.candidate):
                raise DomainError(f"{self.delta_class.value} requires proven occurrence identity")
        if self.delta_class is DeltaClass.LOCATION_CHANGED and _location(self.baseline) == _location(self.candidate):
            raise DomainError("LOCATION_CHANGED requires different file/start/end location")
        if self.delta_class is DeltaClass.SEVERITY_INCREASED and not (
            SEVERITY_ORDER.index(self.candidate.severity)
            > SEVERITY_ORDER.index(self.baseline.severity)
        ):
            raise DomainError("SEVERITY_INCREASED requires a strictly higher candidate severity")
        if self.delta_class is DeltaClass.SUPPRESSION_ADDED and not (
            self.baseline.suppressed is False and self.candidate.suppressed is True
        ):
            raise DomainError("SUPPRESSION_ADDED requires an unsuppressed-to-suppressed transition")
        if self.delta_class is DeltaClass.NEW_FINDING and (
            self.baseline is not None or self.candidate is None
        ):
            raise DomainError("NEW_FINDING requires candidate evidence only")
        if self.delta_class is DeltaClass.RESOLVED_FINDING and (
            self.baseline is None or self.candidate is not None
        ):
            raise DomainError("RESOLVED_FINDING requires baseline evidence only")
        if self.delta_class is DeltaClass.SCOPE_EXPANDED:
            if self.baseline is not None or self.candidate is None:
                raise DomainError("SCOPE_EXPANDED requires candidate evidence only")
            if self.scope_evidence is None:
                raise DomainError("SCOPE_EXPANDED requires complete resource-set evidence")
            if self.candidate.resource_address not in self.scope_evidence.added_resources:
                raise DomainError("SCOPE_EXPANDED candidate is not an added resource")
            if self.candidate not in self.scope_evidence.candidate_findings:
                raise DomainError("SCOPE_EXPANDED candidate is absent from its evidence set")
        elif self.scope_evidence is not None:
            raise DomainError("scope_evidence is valid only for SCOPE_EXPANDED")
        if _trusted_context is not _TRUSTED_DIFF_CONTEXT:
            raise DomainError(
                f"{self.delta_class.value} requires complete trusted comparison context"
            )
        object.__setattr__(self, "_trusted", True)

    @property
    def canonical_key(self) -> tuple:
        baseline_key = self.baseline.canonical_order_key if self.baseline else ()
        candidate_key = self.candidate.canonical_order_key if self.candidate else ()
        return (self.delta_class.value, baseline_key, candidate_key, self.detail)

    def canonical_dict(self) -> dict:
        return {
            "delta_class": self.delta_class.value,
            "baseline": self.baseline.canonical_dict() if self.baseline else None,
            "candidate": self.candidate.canonical_dict() if self.candidate else None,
            "detail": self.detail,
            "scope_evidence": self.scope_evidence.canonical_dict() if self.scope_evidence else None,
        }


@dataclass(frozen=True, slots=True)
class FindingDiffResult(Sequence[FindingDelta]):
    deltas: tuple
    ambiguities: tuple = ()
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        for name, expected in (("deltas", FindingDelta), ("ambiguities", MatchingAmbiguity)):
            raw = getattr(self, name)
            if type(raw) is not tuple:
                raise DomainError(f"{name} must be an exact tuple")
            for item in raw:
                require_exact_type(item, expected, f"{name} entry")
        object.__setattr__(self, "deltas", tuple(sorted(self.deltas, key=lambda item: item.canonical_key)))
        object.__setattr__(
            self,
            "ambiguities",
            tuple(sorted(self.ambiguities, key=lambda item: item.canonical_key)),
        )
        if _trusted_context is not _TRUSTED_DIFF_CONTEXT:
            raise DomainError("FindingDiffResult requires complete trusted comparison context")
        if any(not item._trusted for item in self.deltas):
            raise DomainError("FindingDiffResult contains caller-authored delta evidence")
        if any(not item._trusted for item in self.ambiguities):
            raise DomainError("FindingDiffResult contains caller-authored ambiguity evidence")
        object.__setattr__(self, "_trusted", True)

    def __len__(self) -> int:
        return len(self.deltas)

    def __getitem__(self, index):
        return self.deltas[index]

    def __iter__(self) -> Iterator[FindingDelta]:
        return iter(self.deltas)

    def canonical_dict(self) -> dict:
        return {
            "deltas": [item.canonical_dict() for item in self.deltas],
            "ambiguities": [item.canonical_dict() for item in self.ambiguities],
        }


def diff_findings(
    baseline: tuple[Finding, ...] | list[Finding],
    candidate: tuple[Finding, ...] | list[Finding],
) -> FindingDiffResult:
    """Return canonical finding deltas plus typed occurrence uncertainty."""
    if type(baseline) not in (tuple, list) or type(candidate) not in (tuple, list):
        raise DomainError("finding multisets must be exact tuple or list values")
    baseline_snapshot = tuple(baseline)
    candidate_snapshot = tuple(candidate)
    comparison = compare_finding_multisets(baseline_snapshot, candidate_snapshot)
    require_trusted_comparison(comparison)
    deltas: list[FindingDelta] = []
    for match in comparison.matches:
        if match.location_changed:
            deltas.append(
                FindingDelta(
                    DeltaClass.LOCATION_CHANGED,
                    match.baseline,
                    match.candidate,
                    _trusted_context=_TRUSTED_DIFF_CONTEXT,
                )
            )
        if match.severity_increased:
            deltas.append(
                FindingDelta(
                    DeltaClass.SEVERITY_INCREASED,
                    match.baseline,
                    match.candidate,
                    _trusted_context=_TRUSTED_DIFF_CONTEXT,
                )
            )
        if not match.baseline.suppressed and match.candidate.suppressed:
            deltas.append(
                FindingDelta(
                    DeltaClass.SUPPRESSION_ADDED,
                    match.baseline,
                    match.candidate,
                    _trusted_context=_TRUSTED_DIFF_CONTEXT,
                )
            )
    for finding in comparison.unmatched_candidate:
        deltas.append(
            FindingDelta(
                DeltaClass.NEW_FINDING,
                candidate=finding,
                _trusted_context=_TRUSTED_DIFF_CONTEXT,
            )
        )
    for finding in comparison.unmatched_baseline:
        deltas.append(
            FindingDelta(
                DeltaClass.RESOLVED_FINDING,
                baseline=finding,
                _trusted_context=_TRUSTED_DIFF_CONTEXT,
            )
        )

    baseline_groups: dict[tuple, list[Finding]] = {}
    candidate_groups: dict[tuple, list[Finding]] = {}
    for finding in baseline_snapshot:
        require_exact_type(finding, Finding, "baseline finding")
        baseline_groups.setdefault((finding.match_domain_key, finding.rule_id), []).append(finding)
    for finding in candidate_snapshot:
        require_exact_type(finding, Finding, "candidate finding")
        candidate_groups.setdefault((finding.match_domain_key, finding.rule_id), []).append(finding)
    for group in sorted(set(baseline_groups) & set(candidate_groups)):
        before_items = tuple(baseline_groups[group])
        after_items = tuple(candidate_groups[group])
        before_resources = {item.resource_address for item in before_items}
        after_resources = {item.resource_address for item in after_items}
        if before_resources < after_resources:
            evidence = ScopeExpansionEvidence(before_items, after_items)
            candidate_by_resource = {
                item.resource_address: item
                for item in reversed(
                    sorted(after_items, key=lambda item: item.canonical_order_key)
                )
            }
            for resource in sorted(evidence.added_resources):
                candidate_finding = candidate_by_resource[resource]
                deltas.append(
                    FindingDelta(
                        DeltaClass.SCOPE_EXPANDED,
                        candidate=candidate_finding,
                        detail=f"{group[0][0]}:{group[1]} added resource {resource}",
                        scope_evidence=evidence,
                        _trusted_context=_TRUSTED_DIFF_CONTEXT,
                    )
                )
    return FindingDiffResult(
        tuple(deltas),
        comparison.ambiguities,
        _trusted_context=_TRUSTED_DIFF_CONTEXT,
    )


def require_trusted_diff_result(value: object) -> FindingDiffResult:
    """D5 boundary: reject caller-created deltas and aggregate result objects."""
    require_exact_type(value, FindingDiffResult, "finding diff result")
    if not value._trusted:
        raise DomainError("finding diff result is caller-authored, not trusted evidence")
    return value


__all__ = [
    "FindingDelta",
    "FindingDiffResult",
    "ScopeExpansionEvidence",
    "diff_findings",
    "require_trusted_diff_result",
]
