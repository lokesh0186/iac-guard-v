"""D3.2 regressions for conservative occurrence and multi-domain matching."""
from __future__ import annotations

import pytest

from iac_guard_v.adapters.checkov import (
    CheckovTargetEvidence,
    require_trusted_checkov_target_evidence,
)
from iac_guard_v.diffing import (
    FindingDelta,
    FindingDiffResult,
    diff_findings,
    require_trusted_diff_result,
)
from iac_guard_v.enums import (
    ArtifactKind,
    CheckTargetReason,
    DeltaClass,
    IdentityTier,
    Severity,
    Status,
)
from iac_guard_v.matching import (
    FindingMatch,
    FindingMultisetComparison,
    MatchingAmbiguity,
    compare_finding_multisets,
    require_trusted_comparison,
)
from iac_guard_v.models import (
    DomainError,
    Finding,
    FindingLocation,
    ScannerRun,
    require_trusted_scanner_run,
)


def finding(
    *,
    start: int,
    message: str,
    artifact: ArtifactKind = ArtifactKind.TERRAFORM_HCL,
    resource: str = "aws_x.r",
    path: str = "main.tf",
    severity: Severity = Severity.LOW,
    suppressed: bool = False,
    native: str = "",
    scanner: str = "checkov",
    version: str = "3.3.0",
) -> Finding:
    return Finding(
        scanner=scanner,
        scanner_version=version,
        rule_id="CKV_X",
        resource_address=resource,
        location=FindingLocation(path, start, start),
        severity=severity,
        artifact_kind=artifact,
        suppressed=suppressed,
        native_fingerprint=native,
        message=message,
    )


def churn_case(*, native: bool = False) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
    baseline = (
        finding(start=10, message="occ-A", native="native-A" if native else ""),
        finding(
            start=20,
            message="occ-B",
            severity=Severity.HIGH,
            suppressed=True,
            native="native-B" if native else "",
        ),
    )
    candidate = (
        finding(
            start=20,
            message="occ-A",
            severity=Severity.HIGH,
            suppressed=True,
            native="native-A" if native else "",
        ),
    )
    return baseline, candidate


def test_reused_location_during_no_native_multiplicity_churn_is_inconclusive() -> None:
    baseline, candidate = churn_case()
    comparison = compare_finding_multisets(baseline, candidate)
    assert comparison.matches == ()
    assert comparison.unmatched_baseline == ()
    assert comparison.unmatched_candidate == ()
    assert len(comparison.ambiguities) == 1
    assert comparison.ambiguities[0].reason.value == "MATCHING_INCONCLUSIVE"
    result = diff_findings(baseline, candidate)
    assert result.deltas == ()
    assert len(result.ambiguities) == 1


def test_native_identity_proves_churned_occurrence_and_all_changes() -> None:
    baseline, candidate = churn_case(native=True)
    comparison = compare_finding_multisets(baseline, candidate)
    assert [(match.baseline.message, match.candidate.message, match.tier) for match in comparison.matches] == [
        ("occ-A", "occ-A", IdentityTier.EXACT)
    ]
    assert [item.message for item in comparison.unmatched_baseline] == ["occ-B"]
    result = diff_findings(baseline, candidate)
    assert [delta.delta_class for delta in result.deltas] == [
        DeltaClass.LOCATION_CHANGED,
        DeltaClass.RESOLVED_FINDING,
        DeltaClass.SEVERITY_INCREASED,
        DeltaClass.SUPPRESSION_ADDED,
    ]


def test_unique_no_native_relocation_remains_supported() -> None:
    comparison = compare_finding_multisets(
        (finding(start=10, message="one"),),
        (finding(start=20, message="one"),),
    )
    assert len(comparison.matches) == 1
    assert comparison.matches[0].tier is IdentityTier.RELOCATED


def test_equal_multi_occurrence_location_sets_match_exactly() -> None:
    baseline = (finding(start=10, message="A"), finding(start=20, message="B"))
    candidate = (finding(start=20, message="changed-B"), finding(start=10, message="changed-A"))
    comparison = compare_finding_multisets(baseline, candidate)
    assert [(m.baseline.location.start_line, m.candidate.location.start_line, m.tier)
            for m in comparison.matches] == [
        (10, 10, IdentityTier.EXACT),
        (20, 20, IdentityTier.EXACT),
    ]
    assert comparison.ambiguities == ()


def test_churn_ambiguity_is_input_order_independent() -> None:
    baseline, candidate = churn_case()
    forward = compare_finding_multisets(baseline, candidate).canonical_dict()
    reverse = compare_finding_multisets(
        tuple(reversed(baseline)), tuple(reversed(candidate))
    ).canonical_dict()
    assert forward == reverse


def mixed_domains() -> tuple[Finding, Finding]:
    terraform = finding(start=1, message="tf")
    kubernetes = finding(
        start=2,
        message="k8s",
        artifact=ArtifactKind.KUBERNETES_YAML,
        resource="Pod/default/demo",
        path="pod.yaml",
    )
    return terraform, kubernetes


def test_multiple_artifact_domains_compare_independently_and_deterministically() -> None:
    terraform, kubernetes = mixed_domains()
    forward = compare_finding_multisets((terraform, kubernetes), (kubernetes, terraform))
    reverse = compare_finding_multisets((kubernetes, terraform), (terraform, kubernetes))
    assert len(forward.matches) == 2
    assert {match.baseline.artifact_kind for match in forward.matches} == {
        ArtifactKind.TERRAFORM_HCL,
        ArtifactKind.KUBERNETES_YAML,
    }
    assert forward.canonical_dict() == reverse.canonical_dict()


def test_artifact_domains_never_cross_match_and_one_sided_domain_is_unmatched() -> None:
    terraform, kubernetes = mixed_domains()
    comparison = compare_finding_multisets((terraform, kubernetes), (terraform,))
    assert len(comparison.matches) == 1
    assert comparison.matches[0].baseline.artifact_kind is ArtifactKind.TERRAFORM_HCL
    assert comparison.unmatched_baseline == (kubernetes,)
    assert comparison.unmatched_candidate == ()


@pytest.mark.parametrize(
    "candidate",
    [
        finding(start=1, message="drift", scanner="trivy"),
        finding(start=1, message="drift", version="3.2.517"),
    ],
)
def test_scanner_or_version_drift_is_not_ordinary_unmatched_evidence(candidate: Finding) -> None:
    with pytest.raises(DomainError, match="scanner|version"):
        compare_finding_multisets((finding(start=1, message="base"),), (candidate,))


def test_caller_cannot_construct_set_derived_delta_as_trusted_evidence() -> None:
    with pytest.raises(DomainError, match="trusted comparison"):
        FindingDelta(
            DeltaClass.NEW_FINDING,
            candidate=finding(start=1, message="injected"),
        )


def test_production_boundary_rejects_all_caller_authored_derived_evidence() -> None:
    base = finding(start=1, message="base")
    moved = finding(start=2, message="moved")
    with pytest.raises(DomainError, match="trusted comparison"):
        FindingMatch(base, base, IdentityTier.EXACT)
    with pytest.raises(DomainError, match="trusted comparison"):
        MatchingAmbiguity((base,), (moved,))
    with pytest.raises(DomainError, match="trusted comparison"):
        FindingMultisetComparison((), (), ())
    with pytest.raises(DomainError, match="trusted comparison"):
        FindingDiffResult((), ())

    caller_run = ScannerRun("checkov", "3.3.0", Status.PASS)
    with pytest.raises(DomainError, match="caller-authored"):
        require_trusted_scanner_run(caller_run)
    caller_target = CheckovTargetEvidence(
        Status.INCONCLUSIVE, CheckTargetReason.TARGET_NOT_EVALUATED, ()
    )
    with pytest.raises(DomainError, match="caller-authored"):
        require_trusted_checkov_target_evidence(caller_target)

    comparison = compare_finding_multisets((base,), (moved,))
    result = diff_findings((base,), (moved,))
    assert require_trusted_comparison(comparison) is comparison
    assert require_trusted_diff_result(result) is result
