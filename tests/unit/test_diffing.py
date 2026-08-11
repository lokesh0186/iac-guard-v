"""D3 finding-derived delta tests over occurrence-preserving comparisons."""
from __future__ import annotations

import pytest

from iac_guard_v.diffing import FindingDelta, diff_findings
from iac_guard_v.enums import ArtifactKind, DeltaClass, Severity
from iac_guard_v.models import DomainError, Finding, FindingLocation


def finding(
    resource: str,
    *,
    path: str = "main.tf",
    start: int = 1,
    occurrence: int = 0,
    severity: Severity = Severity.MEDIUM,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        scanner="checkov",
        scanner_version="3.3.0",
        rule_id="CKV_AWS_18",
        resource_address=resource,
        location=FindingLocation(path, start, start + 1),
        occurrence_index=occurrence,
        severity=severity,
        artifact_kind=ArtifactKind.TERRAFORM_HCL,
        suppressed=suppressed,
    )


def classes(result) -> list[DeltaClass]:
    return [delta.delta_class for delta in result]


def test_resource_move_is_resolved_plus_new_not_location_changed() -> None:
    deltas = diff_findings(
        (finding("aws_s3_bucket.a"),),
        (finding("aws_s3_bucket.b"),),
    )
    assert classes(deltas) == [DeltaClass.NEW_FINDING, DeltaClass.RESOLVED_FINDING]
    assert DeltaClass.LOCATION_CHANGED not in classes(deltas)
    assert DeltaClass.SCOPE_EXPANDED not in classes(deltas)


def test_line_shift_is_location_changed_even_with_exact_identity() -> None:
    deltas = diff_findings(
        (finding("aws_s3_bucket.data", start=1),),
        (finding("aws_s3_bucket.data", start=20),),
    )
    assert classes(deltas) == [DeltaClass.LOCATION_CHANGED]


def test_file_move_is_location_changed() -> None:
    deltas = diff_findings(
        (finding("aws_s3_bucket.data", path="old.tf"),),
        (finding("aws_s3_bucket.data", path="new.tf"),),
    )
    assert classes(deltas) == [DeltaClass.LOCATION_CHANGED]


def test_severity_increase_is_reported() -> None:
    deltas = diff_findings(
        (finding("aws_s3_bucket.data", severity=Severity.LOW),),
        (finding("aws_s3_bucket.data", severity=Severity.HIGH),),
    )
    assert classes(deltas) == [DeltaClass.SEVERITY_INCREASED]


def test_new_resource_stacks_new_finding_and_scope_expanded_when_old_scope_remains() -> None:
    deltas = diff_findings(
        (finding("aws_s3_bucket.a"),),
        (finding("aws_s3_bucket.a"), finding("aws_s3_bucket.b")),
    )
    assert classes(deltas) == [DeltaClass.NEW_FINDING, DeltaClass.SCOPE_EXPANDED]


def test_suppression_transition_is_reported_without_erasing_identity() -> None:
    deltas = diff_findings(
        (finding("aws_s3_bucket.data", suppressed=False),),
        (finding("aws_s3_bucket.data", suppressed=True),),
    )
    assert classes(deltas) == [DeltaClass.SUPPRESSION_ADDED]


def test_duplicate_occurrence_removal_is_one_resolved_finding() -> None:
    baseline = tuple(finding("aws_s3_bucket.data", occurrence=i) for i in range(3))
    candidate = tuple(finding("aws_s3_bucket.data", occurrence=i) for i in range(2))
    deltas = diff_findings(baseline, candidate)
    assert classes(deltas) == [DeltaClass.RESOLVED_FINDING]
    assert deltas[0].baseline.occurrence_index == 2


def test_delta_output_is_deterministic_and_structured() -> None:
    baseline = (finding("aws_s3_bucket.b"), finding("aws_s3_bucket.a"))
    candidate = (finding("aws_s3_bucket.a", start=10), finding("aws_s3_bucket.c"))
    forward = [item.canonical_dict() for item in diff_findings(baseline, candidate)]
    reverse = [
        item.canonical_dict()
        for item in diff_findings(tuple(reversed(baseline)), tuple(reversed(candidate)))
    ]
    assert forward == reverse


def test_tuple_subclass_is_rejected_before_diffing() -> None:
    class SneakyTuple(tuple):
        pass

    with pytest.raises(DomainError, match="exact tuple or list"):
        diff_findings(SneakyTuple((finding("aws_s3_bucket.a"),)), ())


def test_engine_only_delta_cannot_be_forged_from_finding_evidence() -> None:
    with pytest.raises(DomainError, match="later engine evidence"):
        FindingDelta(DeltaClass.POLICY_DRIFT)


@pytest.mark.parametrize(
    "delta",
    [
        lambda: FindingDelta(DeltaClass.LOCATION_CHANGED),
        lambda: FindingDelta(DeltaClass.NEW_FINDING, baseline=finding("aws_s3_bucket.a")),
        lambda: FindingDelta(DeltaClass.RESOLVED_FINDING, candidate=finding("aws_s3_bucket.a")),
        lambda: FindingDelta(DeltaClass.SCOPE_EXPANDED),
    ],
)
def test_public_delta_shape_invariants(delta) -> None:
    with pytest.raises(DomainError):
        delta()


def test_delta_detail_rejects_report_spoofing_controls() -> None:
    with pytest.raises(DomainError, match="control"):
        FindingDelta(
            DeltaClass.SCOPE_EXPANDED,
            candidate=finding("aws_s3_bucket.a"),
            detail="bad\nline",
        )


def test_forged_stored_fingerprint_is_rejected_by_delta() -> None:
    forged = Finding(
        scanner="checkov",
        scanner_version="3.3.0",
        rule_id="CKV_AWS_18",
        resource_address="aws_s3_bucket.data",
        location=FindingLocation("main.tf", 1, 1),
        iacgv_fingerprint="iacgv1:" + "0" * 64,
    )
    with pytest.raises(DomainError, match="forged"):
        FindingDelta(DeltaClass.NEW_FINDING, candidate=forged)
