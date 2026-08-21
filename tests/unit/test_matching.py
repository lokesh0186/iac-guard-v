"""D3 multiset matching tests: exact first, then same-resource relocation."""
from __future__ import annotations

import dataclasses

import pytest

from iac_guard_v.diffing import FindingDelta, FindingDiffResult, ScopeExpansionEvidence
from iac_guard_v.enums import ArtifactKind, IdentityTier, Severity
from iac_guard_v.matching import (
    FindingMatch,
    FindingMultisetComparison,
    MatchingAmbiguity,
    compare_finding_multisets,
)
from iac_guard_v.models import DomainError, Finding, FindingLocation
from iac_guard_v.normalisation import assign_occurrence_indices


def finding(
    resource: str,
    *,
    path: str = "main.tf",
    start: int = 1,
    end: int | None = None,
    occurrence: int = 0,
    version: str = "3.3.0",
    severity: Severity = Severity.HIGH,
    suppressed: bool = False,
    native_fingerprint: str = "",
    scanner: str = "checkov",
    artifact_kind: ArtifactKind = ArtifactKind.TERRAFORM_HCL,
) -> Finding:
    return Finding(
        scanner=scanner,
        scanner_version=version,
        rule_id="CKV_AWS_18",
        resource_address=resource,
        location=FindingLocation(path, start, start + 1 if end is None else end),
        occurrence_index=occurrence,
        severity=severity,
        artifact_kind=artifact_kind,
        suppressed=suppressed,
        native_fingerprint=native_fingerprint,
    )


def test_unique_line_move_without_native_identity_is_constrained_relocation() -> None:
    comparison = compare_finding_multisets(
        (finding("aws_s3_bucket.data", start=2, end=3),),
        (finding("aws_s3_bucket.data", start=200, end=201),),
    )
    assert len(comparison.matches) == 1
    assert comparison.matches[0].tier is IdentityTier.RELOCATED
    assert comparison.matches[0].location_changed is True
    assert comparison.unmatched_baseline == ()
    assert comparison.unmatched_candidate == ()


def test_file_move_is_relocated_only_for_same_resource() -> None:
    comparison = compare_finding_multisets(
        (finding("aws_s3_bucket.data", path="old/main.tf"),),
        (finding("aws_s3_bucket.data", path="new/main.tf"),),
    )
    assert comparison.matches[0].tier is IdentityTier.RELOCATED
    assert comparison.matches[0].location_changed is True


def test_rule_move_to_different_resource_is_not_relocation() -> None:
    baseline = finding("aws_s3_bucket.a")
    candidate = finding("aws_s3_bucket.b")
    comparison = compare_finding_multisets((baseline,), (candidate,))
    assert comparison.matches == ()
    assert comparison.unmatched_baseline[0].resource_address == "aws_s3_bucket.a"
    assert comparison.unmatched_candidate[0].resource_address == "aws_s3_bucket.b"


def test_occurrences_are_never_collapsed() -> None:
    baseline = tuple(
        finding("aws_s3_bucket.data", occurrence=i, native_fingerprint=f"native-{i}")
        for i in range(3)
    )
    candidate = tuple(
        finding("aws_s3_bucket.data", occurrence=i, native_fingerprint=f"native-{i}")
        for i in range(2)
    )
    comparison = compare_finding_multisets(baseline, candidate)
    assert len(comparison.matches) == 2
    assert [item.occurrence_index for item in comparison.unmatched_baseline] == [2]


def test_matching_is_deterministic_under_input_reordering() -> None:
    baseline = (
        finding("aws_s3_bucket.b"),
        finding("aws_s3_bucket.a", path="old.tf"),
    )
    candidate = (
        finding("aws_s3_bucket.a", path="new.tf"),
        finding("aws_s3_bucket.c"),
    )
    forward = compare_finding_multisets(baseline, candidate).canonical_dict()
    reverse = compare_finding_multisets(tuple(reversed(baseline)), tuple(reversed(candidate))).canonical_dict()
    assert forward == reverse


def test_dense_occurrence_index_compaction_cannot_mispair_retained_line() -> None:
    baseline = assign_occurrence_indices(
        (finding("aws_s3_bucket.data", start=10, end=10),
         finding("aws_s3_bucket.data", start=20, end=20))
    )
    candidate = assign_occurrence_indices(
        (finding("aws_s3_bucket.data", start=20, end=20),)
    )
    comparison = compare_finding_multisets(baseline, candidate)
    assert comparison.matches == ()
    assert comparison.unmatched_baseline == ()
    assert comparison.unmatched_candidate == ()
    assert len(comparison.ambiguities) == 1
    assert comparison.ambiguities[0].reason.value == "MATCHING_INCONCLUSIVE"


def test_equally_supported_occurrence_pairings_are_typed_inconclusive() -> None:
    comparison = compare_finding_multisets(
        (finding("aws_s3_bucket.data", start=10),
         finding("aws_s3_bucket.data", start=20)),
        (finding("aws_s3_bucket.data", start=30),),
    )
    assert comparison.matches == ()
    assert comparison.unmatched_baseline == ()
    assert comparison.unmatched_candidate == ()
    assert len(comparison.ambiguities) == 1
    assert comparison.ambiguities[0].reason.value == "MATCHING_INCONCLUSIVE"


def test_ambiguity_canonical_output_is_input_order_independent() -> None:
    baseline = (finding("aws_s3_bucket.data", start=10),
                finding("aws_s3_bucket.data", start=20))
    candidate = (finding("aws_s3_bucket.data", start=30),
                 finding("aws_s3_bucket.data", start=40))
    forward = compare_finding_multisets(baseline, candidate).canonical_dict()
    reverse = compare_finding_multisets(
        tuple(reversed(baseline)), tuple(reversed(candidate))
    ).canonical_dict()
    assert forward == reverse


def test_duplicate_exact_identity_is_rejected_at_matching_boundary() -> None:
    duplicate = finding("aws_s3_bucket.data")
    with pytest.raises(DomainError, match="duplicate exact"):
        compare_finding_multisets((duplicate, duplicate), ())


def test_ambiguous_relocated_identity_is_rejected_not_guessed() -> None:
    baseline = (
        finding("aws_s3_bucket.data", path="a.tf"),
        finding("aws_s3_bucket.data", path="b.tf"),
    )
    candidate = (finding("aws_s3_bucket.data", path="new.tf"),)
    comparison = compare_finding_multisets(baseline, candidate)
    assert comparison.matches == ()
    assert len(comparison.ambiguities) == 1


def test_multiple_unmatched_occurrences_need_no_relocation_guess() -> None:
    baseline = (
        finding("aws_s3_bucket.data", path="a.tf"),
        finding("aws_s3_bucket.data", path="b.tf"),
    )
    comparison = compare_finding_multisets(baseline, ())
    assert len(comparison.unmatched_baseline) == 2


def test_scanner_version_drift_is_rejected_before_matching() -> None:
    with pytest.raises(DomainError, match="version drift"):
        compare_finding_multisets(
            (finding("aws_s3_bucket.data", version="3.2.517"),),
            (finding("aws_s3_bucket.data", version="3.3.0"),),
        )


def test_multiple_versions_within_one_side_are_rejected() -> None:
    with pytest.raises(DomainError, match="multiple versions"):
        compare_finding_multisets(
            (
                finding("aws_s3_bucket.a", version="3.2.517"),
                finding("aws_s3_bucket.b", version="3.3.0"),
            ),
            (),
        )


def test_severity_increase_is_typed_match_evidence() -> None:
    comparison = compare_finding_multisets(
        (finding("aws_s3_bucket.data", severity=Severity.MEDIUM),),
        (finding("aws_s3_bucket.data", severity=Severity.HIGH),),
    )
    assert comparison.matches[0].severity_increased is True


def test_public_match_collections_reject_finding_subclasses() -> None:
    class SneakyFinding(Finding):
        __slots__ = ()

    sneaky = SneakyFinding(
        scanner="checkov",
        scanner_version="3.3.0",
        rule_id="CKV_AWS_18",
        resource_address="aws_s3_bucket.data",
        location=FindingLocation("main.tf", 1, 1),
    )
    with pytest.raises(DomainError, match="exactly Finding"):
        compare_finding_multisets((sneaky,), ())


def test_tuple_subclass_is_rejected_at_matching_boundary() -> None:
    class SneakyTuple(tuple):
        pass

    with pytest.raises(DomainError, match="exact tuple or list"):
        compare_finding_multisets(SneakyTuple((finding("aws_s3_bucket.data"),)), ())


def test_public_match_rejects_invalid_tier_and_keys() -> None:
    baseline = finding("aws_s3_bucket.a")
    candidate = finding("aws_s3_bucket.b")
    with pytest.raises(DomainError, match="EXACT match"):
        FindingMatch(baseline, candidate, IdentityTier.EXACT)
    with pytest.raises(DomainError, match="RELOCATED match"):
        FindingMatch(baseline, candidate, IdentityTier.RELOCATED)
    with pytest.raises(DomainError, match="classified EXACT"):
        FindingMatch(baseline, baseline, IdentityTier.RELOCATED)
    with pytest.raises(DomainError, match="EXACT or RELOCATED"):
        FindingMatch(baseline, candidate, IdentityTier.SEMANTIC)


@pytest.mark.parametrize(
    "candidate",
    [
        finding("aws_s3_bucket.a", version="3.2.517"),
        finding("aws_s3_bucket.a", artifact_kind=ArtifactKind.CLOUDFORMATION),
        finding("aws_s3_bucket.a", scanner="trivy"),
    ],
)
def test_public_exact_match_rejects_incompatible_domains(candidate: Finding) -> None:
    with pytest.raises(DomainError, match="match domain"):
        FindingMatch(finding("aws_s3_bucket.a"), candidate, IdentityTier.EXACT)


@pytest.mark.parametrize(
    "candidate",
    [
        finding("aws_s3_bucket.a", scanner="trivy"),
    ],
)
def test_comparison_rejects_cross_scanner_domains(candidate: Finding) -> None:
    with pytest.raises(DomainError, match="match domain"):
        compare_finding_multisets((finding("aws_s3_bucket.a"),), (candidate,))


def test_one_sided_artifact_domain_is_unmatched_not_cross_matched() -> None:
    baseline = finding("aws_s3_bucket.a")
    candidate = finding("aws_s3_bucket.a", artifact_kind=ArtifactKind.CLOUDFORMATION)
    comparison = compare_finding_multisets((baseline,), (candidate,))
    assert comparison.matches == ()
    assert comparison.unmatched_baseline == (baseline,)
    assert comparison.unmatched_candidate == (candidate,)


def test_public_comparison_requires_exact_tuple_fields() -> None:
    with pytest.raises(DomainError, match="matches must be an exact tuple"):
        FindingMultisetComparison([], (), ())


def test_forged_stored_fingerprint_is_rejected_by_matching() -> None:
    forged = Finding(
        scanner="checkov",
        scanner_version="3.3.0",
        rule_id="CKV_AWS_18",
        resource_address="aws_s3_bucket.data",
        location=FindingLocation("main.tf", 1, 1),
        iacgv_fingerprint="iacgv1:" + "0" * 64,
    )
    with pytest.raises(DomainError, match="forged"):
        compare_finding_multisets((forged,), ())


@pytest.mark.parametrize(
    "cls",
    [
        FindingMatch,
        FindingMultisetComparison,
        MatchingAmbiguity,
        FindingDelta,
        FindingDiffResult,
        ScopeExpansionEvidence,
    ],
)
def test_d3_evidence_models_are_frozen_and_slotted(cls: type) -> None:
    assert dataclasses.is_dataclass(cls)
    assert cls.__dataclass_params__.frozen is True
    assert "__slots__" in cls.__dict__
    assert "__dict__" not in cls.__dict__
