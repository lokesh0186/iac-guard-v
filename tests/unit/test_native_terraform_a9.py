from __future__ import annotations

from pathlib import Path

import pytest

from iac_guard_v.models import DomainError
from iac_guard_v.native_properties import (
    NativeArtifactClass,
    NativePropertyRequest,
    NativePropertyResult,
    evaluate_native_request,
    load_protected_native_universe,
)


def _universe(tmp_path: Path, text: str):
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    return load_protected_native_universe(tmp_path, NativeArtifactClass.TERRAFORM_SOURCE)


def _request(universe, source, target, path, **extra):
    if extra.get("complete_expected_domain") is True:
        extra.setdefault("reference_contract_digest", "f" * 64)
    return NativePropertyRequest.build(
        request_id="tf-ref",
        property_id="IACGV_TF_REFERENCE_RESOLVES_V1",
        property_version="1",
        artifact_class=NativeArtifactClass.TERRAFORM_SOURCE,
        subject_identity=source,
        parameters={
            "attribute_path": path,
            "expected_target": target,
            **extra,
        },
        protected_universe_identity=universe.identity,
    )


TF = """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

resource "aws_lb" "app" {
  access_logs {
    bucket  = aws_s3_bucket.logs.id
    enabled = true
  }
}
"""


def test_exact_direct_source_local_reference_has_span(tmp_path: Path) -> None:
    universe = _universe(tmp_path, TF)
    observation = evaluate_native_request(
        universe,
        _request(
            universe, "aws_lb.app", "aws_s3_bucket.logs",
            ["access_logs", 0, "bucket"], complete_expected_domain=True,
        ),
    )
    assert observation.result is NativePropertyResult.SATISFIED
    span = observation.witness.contents["reference_span"]
    assert span["start_line"] == 8
    assert span["end_byte"] > span["start_byte"]


def test_reference_negative_requires_complete_domain(tmp_path: Path) -> None:
    universe = _universe(tmp_path, TF.replace("aws_s3_bucket.logs.id", '"other"'))
    incomplete = evaluate_native_request(
        universe,
        _request(
            universe, "aws_lb.app", "aws_s3_bucket.logs",
            ["access_logs", 0, "bucket"], complete_expected_domain=False,
        ),
    )
    complete = evaluate_native_request(
        universe,
        _request(
            universe, "aws_lb.app", "aws_s3_bucket.logs",
            ["access_logs", 0, "bucket"], complete_expected_domain=True,
        ),
    )
    assert incomplete.result is NativePropertyResult.NOT_EVALUATED
    assert complete.result is NativePropertyResult.VIOLATED


def test_complete_reference_domain_requires_reviewed_contract_identity(tmp_path: Path) -> None:
    universe = _universe(tmp_path, TF)
    request = NativePropertyRequest.build(
        request_id="missing-contract",
        property_id="IACGV_TF_REFERENCE_RESOLVES_V1",
        property_version="1",
        artifact_class=NativeArtifactClass.TERRAFORM_SOURCE,
        subject_identity="aws_lb.app",
        parameters={
            "attribute_path": ["access_logs", 0, "bucket"],
            "expected_target": "aws_s3_bucket.logs",
            "complete_expected_domain": True,
        },
        protected_universe_identity=universe.identity,
    )
    with pytest.raises(DomainError, match="packaged schema"):
        evaluate_native_request(universe, request)


def test_reference_dynamic_module_and_transitive_fail_closed(tmp_path: Path) -> None:
    dynamic = TF.replace("aws_s3_bucket.logs.id", "var.log_bucket")
    universe = _universe(tmp_path, dynamic)
    observation = evaluate_native_request(
        universe,
        _request(
            universe, "aws_lb.app", "aws_s3_bucket.logs",
            ["access_logs", 0, "bucket"], complete_expected_domain=True,
        ),
    )
    assert observation.result is NativePropertyResult.NOT_EVALUATED
    assert observation.reason_code == "TERRAFORM_REFERENCE_EXPRESSION_UNSUPPORTED"
    transitive = evaluate_native_request(
        universe,
        _request(
            universe, "aws_lb.app", "aws_s3_bucket.logs",
            ["access_logs", 0, "bucket"], mode="TRANSITIVE",
        ),
    )
    assert transitive.result is NativePropertyResult.UNSUPPORTED


def test_for_each_and_missing_target_fail_closed(tmp_path: Path) -> None:
    universe = _universe(
        tmp_path,
        TF.replace('resource "aws_lb" "app" {', 'resource "aws_lb" "app" {\n  for_each = var.items'),
    )
    observation = evaluate_native_request(
        universe,
        _request(
            universe, "aws_lb.app", "aws_s3_bucket.logs",
            ["access_logs", 0, "bucket"], complete_expected_domain=True,
        ),
    )
    assert observation.result is NativePropertyResult.NOT_EVALUATED
    assert observation.reason_code == "TERRAFORM_INSTANCE_IDENTITY_UNRESOLVED"
    missing = evaluate_native_request(
        universe,
        _request(
            universe, "aws_lb.app", "aws_s3_bucket.missing",
            ["access_logs", 0, "bucket"], complete_expected_domain=True,
        ),
    )
    assert missing.result is NativePropertyResult.NOT_EVALUATED


def test_duplicate_terraform_identity_rejected(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text('resource "null_resource" "same" {}', encoding="utf-8")
    (tmp_path / "b.tf").write_text('resource "null_resource" "same" {}', encoding="utf-8")
    with pytest.raises(DomainError, match="duplicate Terraform"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.TERRAFORM_SOURCE)
