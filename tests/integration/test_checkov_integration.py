"""Pinned local Checkov 3.3.0 adapter integration; no benchmark inputs are scanned."""
from __future__ import annotations

import shutil
import hashlib
from pathlib import Path

from iac_guard_v.adapters.checkov import (
    CheckovAdapter,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
    checkov_distribution_identity,
    evaluate_checkov_target,
)
from iac_guard_v.enums import ArtifactKind, CheckEvaluationResult, CheckTargetReason, Status
from iac_guard_v.models import ExpectedResource


def _checkov() -> Path:
    value = shutil.which("checkov")
    assert value is not None, "BLOCKED: pinned Checkov 3.3.0 executable is not installed"
    return Path(value)


def test_pinned_checkov_330_terraform_contract(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "main.tf").write_text(
        'resource "aws_security_group" "bad" {\n'
        '  name = "iacgv-d4-test"\n'
        "  ingress {\n"
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )
    # Candidate-governed Checkov configuration must remain inert. If Checkov discovers
    # this file from the scan root, the known world-open SSH finding disappears.
    (root / ".checkov.yml").write_text("skip-check: CKV_AWS_23\n")
    executable = _checkov()
    distribution = checkov_distribution_identity(executable, "3.3.0")
    run = CheckovAdapter().scan(
        CheckovScanRequest(
            executable=executable,
            scan_root=root,
            workspace_root=root,
            frameworks=("terraform",),
            files_eligible=("main.tf",),
            expected_version="3.3.0",
            expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            expected_scanner_environment_sha256=distribution.scanner_environment_digest,
            expected_policy_inventory_sha256=distribution.policy_inventory_digest,
            expected_resources=(
                ExpectedResource(
                    "main.tf",
                    "aws_security_group.bad",
                    ArtifactKind.TERRAFORM_HCL,
                    "aws_security_group.bad",
                ),
            ),
        )
    )
    assert run.status is Status.PASS
    assert run.scanner_version == "3.3.0"
    assert run.coverage.files_parsed == 1
    assert run.findings
    assert {"CKV_AWS_23", "CKV_AWS_24"} <= {item.rule_id for item in run.findings}
    assert all(item.artifact_kind is ArtifactKind.TERRAFORM_HCL for item in run.findings)
    passed = next(
        item for item in run.evaluations
        if item.native_result is CheckEvaluationResult.PASSED
    )
    target = evaluate_checkov_target(
        run, passed.rule_id, passed.resource_address, passed.file_path
    )
    assert target.status is Status.PASS
    assert target.reason is CheckTargetReason.AFFIRMATIVE_TARGET_PASS
    absent_resource = evaluate_checkov_target(
        run, passed.rule_id, "aws_security_group.absent", passed.file_path
    )
    assert absent_resource.status is Status.INCONCLUSIVE
    assert absent_resource.reason is CheckTargetReason.RESOURCE_NOT_OBSERVED
    absent_rule = evaluate_checkov_target(
        run, "CKV_DOES_NOT_EXIST", passed.resource_address, passed.file_path
    )
    assert absent_rule.status is Status.INCONCLUSIVE
    assert absent_rule.reason is CheckTargetReason.RULE_NOT_OBSERVED


def test_pinned_checkov_330_kubernetes_contract(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\n  namespace: default\n"
        "spec:\n  containers:\n    - name: app\n      image: nginx:latest\n"
    )
    executable = _checkov()
    distribution = checkov_distribution_identity(executable, "3.3.0")
    run = CheckovAdapter().scan(
        CheckovScanRequest(
            executable=executable,
            scan_root=root,
            workspace_root=root,
            frameworks=("kubernetes",),
            files_eligible=("pod.yaml",),
            expected_version="3.3.0",
            expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            expected_scanner_environment_sha256=distribution.scanner_environment_digest,
            expected_policy_inventory_sha256=distribution.policy_inventory_digest,
            kubernetes_identities=(
                CheckovKubernetesIdentity(
                    "pod.yaml", "Pod.default.demo", "v1", "Pod", "default", "demo"
                ),
            ),
            expected_resources=(
                ExpectedResource(
                    "pod.yaml",
                    "v1/Pod/default/demo",
                    ArtifactKind.KUBERNETES_YAML,
                    "Pod.default.demo",
                ),
            ),
        )
    )
    assert run.status is Status.PASS
    assert run.coverage.files_parsed == 1
    assert run.findings
    assert all(item.artifact_kind is ArtifactKind.KUBERNETES_YAML for item in run.findings)
    assert {item.resource_address for item in run.findings} == {"v1/Pod/default/demo"}
    passed = next(
        item for item in run.evaluations
        if item.native_result is CheckEvaluationResult.PASSED
    )
    assert evaluate_checkov_target(
        run, passed.rule_id, passed.resource_address, passed.file_path
    ).status is Status.PASS


def test_pinned_checkov_330_inline_skip_is_retained(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "main.tf").write_text(
        'resource "aws_security_group" "bad" {\n'
        '  #checkov:skip=CKV_AWS_23:accepted only as suppression evidence\n'
        '  ingress {\n'
        '    from_port = 22\n'
        '    to_port = 22\n'
        '    protocol = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n'
    )
    executable = _checkov()
    distribution = checkov_distribution_identity(executable, "3.3.0")
    run = CheckovAdapter().scan(
        CheckovScanRequest(
            executable=executable,
            scan_root=root,
            workspace_root=root,
            frameworks=("terraform",),
            files_eligible=("main.tf",),
            expected_version="3.3.0",
            expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            expected_scanner_environment_sha256=distribution.scanner_environment_digest,
            expected_policy_inventory_sha256=distribution.policy_inventory_digest,
            expected_resources=(
                ExpectedResource(
                    "main.tf",
                    "aws_security_group.bad",
                    ArtifactKind.TERRAFORM_HCL,
                    "aws_security_group.bad",
                ),
            ),
        )
    )
    skipped = [
        item for item in run.evaluations
        if item.native_result is CheckEvaluationResult.SKIPPED
    ]
    assert skipped, run.canonical_dict()
    assert any(item.suppressed for item in run.findings)
    evidence = evaluate_checkov_target(
        run, skipped[0].rule_id, skipped[0].resource_address, skipped[0].file_path
    )
    assert evidence.status is Status.INCONCLUSIVE
    assert evidence.reason is CheckTargetReason.TARGET_SUPPRESSED


def test_pinned_checkov_330_missing_file_evaluation_is_partial(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "main.tf").write_text('resource "aws_s3_bucket" "data" {}\n')
    (root / "empty.tf").write_text("# independently eligible but no resource\n")
    executable = _checkov()
    distribution = checkov_distribution_identity(executable, "3.3.0")
    run = CheckovAdapter().scan(
        CheckovScanRequest(
            executable=executable,
            scan_root=root,
            workspace_root=root,
            frameworks=("terraform",),
            files_eligible=("empty.tf", "main.tf"),
            expected_version="3.3.0",
            expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            expected_scanner_environment_sha256=distribution.scanner_environment_digest,
            expected_policy_inventory_sha256=distribution.policy_inventory_digest,
            expected_resources=(
                ExpectedResource(
                    "main.tf",
                    "aws_s3_bucket.data",
                    ArtifactKind.TERRAFORM_HCL,
                    "aws_s3_bucket.data",
                ),
            ),
        )
    )
    assert run.status is Status.PARTIAL
    assert run.coverage.files_parsed == 1
    assert any("empty.tf" in item for item in run.diagnostics)


def test_pinned_checkov_330_in_place_rewrite_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    source = root / "main.tf"
    source.write_text('resource "aws_s3_bucket" "data" {}\n')
    executable = _checkov()
    distribution = checkov_distribution_identity(executable, "3.3.0")
    request = CheckovScanRequest(
        executable=executable,
        scan_root=root,
        workspace_root=root,
        frameworks=("terraform",),
        files_eligible=("main.tf",),
        expected_version="3.3.0",
        expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        expected_scanner_environment_sha256=distribution.scanner_environment_digest,
        expected_policy_inventory_sha256=distribution.policy_inventory_digest,
        expected_resources=(
            ExpectedResource(
                "main.tf",
                "aws_s3_bucket.data",
                ArtifactKind.TERRAFORM_HCL,
                "aws_s3_bucket.data",
            ),
        ),
    )
    inode = source.stat().st_ino
    source.write_text('resource "aws_s3_bucket" "changed" {}\n')
    assert source.stat().st_ino == inode
    run = CheckovAdapter().scan(request)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("INPUT_CHANGED_DURING_SCAN_PREPARATION",)
