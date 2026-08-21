"""D3 golden and adversarial tests for versioned IaC-Guard-V fingerprints."""
from __future__ import annotations

from pathlib import Path

import pytest

from iac_guard_v.enums import ArtifactKind, Severity
from iac_guard_v.fingerprints import (
    FINGERPRINT_ALGORITHM,
    attach_iacgv_fingerprint,
    canonicalize_kubernetes_identity,
    canonicalize_scan_path,
    canonicalize_terraform_address,
    compute_iacgv_fingerprint,
)
from iac_guard_v.models import DomainError, Finding, FindingLocation
from iac_guard_v.normalisation import assign_occurrence_indices


def finding(**overrides) -> Finding:
    values = dict(
        scanner="checkov",
        scanner_version="3.3.0",
        rule_id="CKV_AWS_18",
        resource_address="aws_s3_bucket.data",
        location=FindingLocation("modules/s3/main.tf", 10, 12),
        severity=Severity.HIGH,
        occurrence_index=0,
        rule_name="S3 logging",
        message="logging is absent",
        native_fingerprint="native-123",
        artifact_kind=ArtifactKind.TERRAFORM_HCL,
    )
    values.update(overrides)
    return Finding(**values)


def test_fingerprint_has_visible_algorithm_and_golden_value() -> None:
    value = compute_iacgv_fingerprint(finding())
    assert value.startswith(f"{FINGERPRINT_ALGORITHM}:")
    assert value == "iacgv2:fe6442319649d2827b7334576a8eee3222bc466fe3d5fcad2546d96402b41b02"


def test_line_and_message_drift_do_not_change_primary_fingerprint() -> None:
    original = finding()
    moved = finding(
        location=FindingLocation("modules/s3/main.tf", 200, 205),
        message="different scanner prose",
        rule_name="renamed display label",
        severity=Severity.CRITICAL,
        scanner_version="3.3.1",
    )
    assert compute_iacgv_fingerprint(original) == compute_iacgv_fingerprint(moved)


def test_suppression_state_does_not_erase_finding_identity() -> None:
    assert compute_iacgv_fingerprint(finding(suppressed=False)) == (
        compute_iacgv_fingerprint(finding(suppressed=True))
    )


def test_dense_display_ordinal_does_not_define_primary_identity() -> None:
    """A regenerated position in the current set is not stable occurrence evidence."""
    assert compute_iacgv_fingerprint(finding(occurrence_index=0)) == (
        compute_iacgv_fingerprint(finding(occurrence_index=99))
    )


def test_native_occurrence_evidence_is_bound_when_available() -> None:
    assert compute_iacgv_fingerprint(finding(native_fingerprint="native-123")) != (
        compute_iacgv_fingerprint(finding(native_fingerprint="native-456"))
    )


@pytest.mark.parametrize(
    "override",
    [
        {"rule_id": "CKV_AWS_19"},
        {"resource_address": "aws_s3_bucket.logs"},
        {"location": FindingLocation("other/main.tf", 10, 12)},
        {"artifact_kind": ArtifactKind.CLOUDFORMATION},
        {"scanner": "trivy"},
    ],
)
def test_identity_changes_change_fingerprint(override: dict) -> None:
    assert compute_iacgv_fingerprint(finding()) != compute_iacgv_fingerprint(
        finding(**override)
    )


def test_native_and_iacgv_fingerprints_are_both_preserved() -> None:
    attached = attach_iacgv_fingerprint(finding())
    assert attached.native_fingerprint == "native-123"
    assert attached.iacgv_fingerprint == compute_iacgv_fingerprint(attached)
    assert attached.canonical_dict()["native_fingerprint"] == "native-123"
    assert attached.canonical_dict()["iacgv_fingerprint"].startswith("iacgv2:")


def test_occurrence_normalisation_attaches_fingerprint_after_indexing() -> None:
    normalized = assign_occurrence_indices(
        (finding(message="second"), finding(message="first"))
    )
    assert [item.occurrence_index for item in normalized] == [0, 1]
    assert all(item.iacgv_fingerprint == compute_iacgv_fingerprint(item) for item in normalized)


def test_forged_existing_iacgv_fingerprint_is_rejected() -> None:
    forged = finding(iacgv_fingerprint="iacgv1:" + "0" * 64)
    with pytest.raises(DomainError, match="does not match"):
        attach_iacgv_fingerprint(forged)


def test_scan_root_rename_does_not_change_canonical_path(tmp_path: Path) -> None:
    root_a = tmp_path / "iac-guard-v-a"
    root_b = tmp_path / "iac-guard-v-b"
    for root in (root_a, root_b):
        (root / "modules" / "s3").mkdir(parents=True)
        (root / "modules" / "s3" / "main.tf").write_text("x", encoding="utf-8")
    assert canonicalize_scan_path(root_a / "modules/s3/main.tf", root_a) == (
        canonicalize_scan_path(root_b / "modules/s3/main.tf", root_b)
    ) == "modules/s3/main.tf"


def test_scan_path_escape_and_symlink_escape_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    outside_file = outside / "main.tf"
    outside_file.write_text("x", encoding="utf-8")
    with pytest.raises(DomainError, match="outside scan_root"):
        canonicalize_scan_path(outside_file, root)
    link = root / "escape.tf"
    link.symlink_to(outside_file)
    with pytest.raises(DomainError, match="outside scan_root"):
        canonicalize_scan_path(link, root)


def test_relative_scan_path_is_canonicalized(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "modules").mkdir(parents=True)
    assert canonicalize_scan_path("modules/main.tf", root) == "modules/main.tf"


def test_scan_path_boundary_rejects_bad_root_and_path_types(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="scan_root must be"):
        canonicalize_scan_path("main.tf", str(tmp_path))  # type: ignore[arg-type]
    missing = tmp_path / "missing"
    with pytest.raises(DomainError, match="cannot be resolved"):
        canonicalize_scan_path("main.tf", missing)
    regular = tmp_path / "file"
    regular.write_text("x", encoding="utf-8")
    with pytest.raises(DomainError, match="existing directory"):
        canonicalize_scan_path("main.tf", regular)
    with pytest.raises(DomainError, match="nonblank"):
        canonicalize_scan_path("", tmp_path)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("aws_s3_bucket.data", "aws_s3_bucket.data"),
        ('module.net.aws_security_group.web["blue"]', 'module.net.aws_security_group.web["blue"]'),
        ("aws_instance.web[0]", "aws_instance.web[0]"),
    ],
)
def test_terraform_addresses_have_one_canonical_form(raw: str, expected: str) -> None:
    assert canonicalize_terraform_address(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [" aws_s3_bucket.data ", "aws_s3_bucket .data", "../x", "aws..bucket", "single"],
)
def test_malformed_terraform_addresses_are_rejected(raw: str) -> None:
    with pytest.raises(DomainError):
        canonicalize_terraform_address(raw)


def test_kubernetes_identity_is_structured_and_canonical() -> None:
    assert canonicalize_kubernetes_identity("apps/v1", "Deployment", "prod", "api") == (
        "apps/v1/Deployment/prod/api"
    )


@pytest.mark.parametrize("parts", [("", "Pod", "default", "x"), ("v1", "Pod", "", "x")])
def test_kubernetes_identity_rejects_missing_components(parts: tuple) -> None:
    with pytest.raises(DomainError):
        canonicalize_kubernetes_identity(*parts)


@pytest.mark.parametrize(
    "parts",
    [("apps//v1", "Deployment", "prod", "api"), ("v1", "Bad/Kind", "prod", "api")],
)
def test_kubernetes_identity_rejects_malformed_components(parts: tuple) -> None:
    with pytest.raises(DomainError):
        canonicalize_kubernetes_identity(*parts)
