"""D4.5 complete Kubernetes JSON/YAML artifact-classification properties."""
from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

import iac_guard_v.engine as ENGINE
from iac_guard_v.engine import (
    ArtifactClassification,
    TrustedScanPlan,
    attest_checkov_scan_plan,
)
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import ExpectedResource

from test_checkov_adapter import request as adapter_request


def _request(tmp_path: Path):
    raw = adapter_request(tmp_path, frameworks=("kubernetes", "terraform"))
    (raw.scan_root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: yaml-pod}\n",
        encoding="utf-8",
    )
    return raw


def _classification(plan, path: str):
    return next(item for item in plan.classifications if item.file_path == path)


def test_kubernetes_json_pod_is_bound_and_eligible(tmp_path: Path) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "pod.json").write_text(
        '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"}}',
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    assert "pod.json" in plan.files_eligible
    resource = next(item for item in plan.resources if item.file_path == "pod.json")
    assert resource.resource_address == "v1/Pod/default/p"
    assert resource.artifact_kind is ArtifactKind.KUBERNETES_JSON
    record = _classification(plan, "pod.json")
    assert record.classification == "KUBERNETES_RESOURCES"
    assert record.syntax_kind == "json"
    assert record.sha256 == next(
        item.sha256 for item in plan.files if item.file_path == "pod.json"
    )


def test_kubernetes_json_list_expands_items(tmp_path: Path) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "list.json").write_text(
        '{"apiVersion":"v1","kind":"List","items":['
        '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a"}},'
        '{"apiVersion":"apps/v1","kind":"Deployment",'
        '"metadata":{"name":"b","namespace":"prod"}}]}',
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    assert {
        item.resource_address for item in plan.resources
        if item.file_path == "list.json"
    } == {"v1/Pod/default/a", "apps/v1/Deployment/prod/b"}


def test_ordinary_json_is_classified_not_scanned(tmp_path: Path) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "package.json").write_text(
        '{"name":"ordinary","scripts":{"test":"pytest"}}', encoding="utf-8"
    )
    plan = attest_checkov_scan_plan(raw)
    assert "package.json" not in plan.files_eligible
    assert _classification(plan, "package.json").classification == (
        "NON_KUBERNETES_JSON"
    )


def test_duplicate_key_json_fails_closed(tmp_path: Path) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "pod.json").write_text(
        '{"apiVersion":"v1","kind":"Pod","kind":"Service",'
        '"metadata":{"name":"p"}}',
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="duplicate Kubernetes JSON key"):
        attest_checkov_scan_plan(raw)


def test_github_actions_yaml_is_non_kubernetes(tmp_path: Path) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "workflow.yaml").write_text(
        "name: CI\non:\n  push:\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    assert "workflow.yaml" not in plan.files_eligible
    assert _classification(plan, "workflow.yaml").classification == (
        "NON_KUBERNETES_YAML"
    )


def test_non_kubernetes_cloudformation_custom_tag_is_classified(tmp_path: Path) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "cloudformation.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"
        "    Properties:\n      BucketName: !Ref BucketName\n",
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    assert _classification(plan, "cloudformation.yaml").classification == (
        "NON_KUBERNETES_YAML"
    )


@pytest.mark.parametrize(
    "source",
    [
        "apiVersion: !unsafe v1\nkind: Pod\nmetadata: {name: p}\n",
        "items:\n  - apiVersion: v1\n    kind: Pod\n    metadata: {name: p}\n",
    ],
)
def test_kubernetes_looking_unsupported_yaml_fails_closed(
    tmp_path: Path, source: str
) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "unsupported.yaml").write_text(source, encoding="utf-8")
    with pytest.raises(Exception, match="Kubernetes YAML"):
        attest_checkov_scan_plan(raw)


def test_mixed_repository_retains_every_relevant_classification(
    tmp_path: Path,
) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "pod.json").write_text(
        '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"json-pod"}}',
        encoding="utf-8",
    )
    (raw.scan_root / "workflow.yml").write_text(
        "name: CI\non: [push]\njobs: {}\n", encoding="utf-8"
    )
    (raw.scan_root / "ordinary.json").write_text(
        '{"project":"not-kubernetes"}', encoding="utf-8"
    )
    plan = attest_checkov_scan_plan(raw)
    by_path = {item.file_path: item.classification for item in plan.classifications}
    assert by_path == {
        "main.tf": "TERRAFORM_RESOURCES",
        "ordinary.json": "NON_KUBERNETES_JSON",
        "pod.json": "KUBERNETES_RESOURCES",
        "pod.yaml": "KUBERNETES_RESOURCES",
        "workflow.yml": "NON_KUBERNETES_YAML",
    }
    assert set(plan.files_eligible) == {"main.tf", "pod.json", "pod.yaml"}


@pytest.mark.parametrize(
    "changes",
    [
        {"size": -1},
        {"syntax_kind": "unknown"},
        {"classification": "UNKNOWN"},
        {"reason": 1},
    ],
)
def test_artifact_classification_shape_mutations_are_rejected(changes) -> None:
    value = ArtifactClassification(
        "ordinary.json",
        hashlib.sha256(b"{}").hexdigest(),
        2,
        "json",
        "NON_KUBERNETES_JSON",
    )
    with pytest.raises(Exception):
        replace(value, **changes)


def test_artifact_classification_resource_predicates_are_closed() -> None:
    resource = ExpectedResource(
        "pod.json", "v1/Pod/default/p", ArtifactKind.KUBERNETES_JSON,
        "Pod.default.p",
    )
    terraform_resource = ExpectedResource(
        "main.tf", "aws_s3_bucket.example", ArtifactKind.TERRAFORM_HCL,
        "aws_s3_bucket.example",
    )
    digest = hashlib.sha256(b"{}").hexdigest()
    with pytest.raises(Exception, match="requires resources"):
        ArtifactClassification(
            "pod.json", digest, 2, "json", "KUBERNETES_RESOURCES"
        )
    with pytest.raises(Exception, match="cannot claim resources"):
        ArtifactClassification(
            "pod.json", digest, 2, "json", "NON_KUBERNETES_JSON", (resource,)
        )
    with pytest.raises(Exception, match="structural-only"):
        ArtifactClassification(
            "pod.json", digest, 2, "json", "NON_KUBERNETES_JSON",
            coverage_kind="STRUCTURAL_ONLY",
        )
    with pytest.raises(Exception, match="cannot claim resources"):
        ArtifactClassification(
            "main.tf", digest, 2, "terraform_hcl", "TERRAFORM_STRUCTURE",
            (resource,), coverage_kind="STRUCTURAL_ONLY",
        )
    with pytest.raises(Exception, match="ambiguous file coverage"):
        ArtifactClassification(
            "main.tf", digest, 2, "terraform_hcl", "TERRAFORM_STRUCTURE",
            coverage_kind="AMBIGUOUS",
        )
    with pytest.raises(Exception, match="must bear scanner evidence"):
        ArtifactClassification(
            "main.tf", digest, 2, "terraform_hcl", "TERRAFORM_RESOURCES",
            (terraform_resource,),
            coverage_kind="UNSUPPORTED",
        )
    with pytest.raises(Exception, match="scanner-evidence coverage"):
        ArtifactClassification(
            "ordinary.json", digest, 2, "json", "NON_KUBERNETES_JSON",
            coverage_kind="SCAN_EVIDENCE_BEARING",
        )


def test_scan_plan_classification_invariants_are_enforced(tmp_path: Path) -> None:
    plan = attest_checkov_scan_plan(_request(tmp_path))
    context = ENGINE._TRUSTED_SCAN_PLAN_CONTEXT
    with pytest.raises(Exception, match="duplicate paths"):
        TrustedScanPlan(
            plan.request, plan.files, plan.resources, plan.inventory_sha256,
            plan.classifications + (plan.classifications[0],),
            _trusted_context=context,
        )
    with pytest.raises(Exception, match="disagree with classifications"):
        TrustedScanPlan(
            plan.request, plan.files, plan.resources, plan.inventory_sha256,
            tuple(
                item for item in plan.classifications
                if item.file_path != plan.files[0].file_path
            ),
            _trusted_context=context,
        )
    mutated = tuple(
        replace(item, sha256="0" * 64)
        if item.file_path == plan.files[0].file_path else item
        for item in plan.classifications
    )
    with pytest.raises(Exception, match="bytes disagree"):
        TrustedScanPlan(
            plan.request, plan.files, plan.resources, plan.inventory_sha256, mutated,
            _trusted_context=context,
        )
    with pytest.raises(Exception, match="not canonical"):
        TrustedScanPlan(
            plan.request, plan.files, plan.resources, "0" * 64,
            plan.classifications, _trusted_context=context,
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"\xff", "UTF-8"),
        (b'{"a":', "malformed"),
        (b'}', "unbalanced"),
        (
            ("[" * 70 + "]" * 70).encode("utf-8"),
            "depth limit",
        ),
        (
            b'[{"apiVersion":"v1","kind":"Pod",'
            b'"metadata":{"name":"p"}}]',
            "document shape",
        ),
        (b'{"apiVersion":"v1","kind":"Pod"}', "metadata"),
    ],
)
def test_kubernetes_json_failure_modes_are_typed(
    tmp_path: Path, payload: bytes, message: str
) -> None:
    raw = _request(tmp_path)
    (raw.scan_root / "probe.json").write_bytes(payload)
    with pytest.raises(Exception, match=message):
        attest_checkov_scan_plan(raw)
