"""Pinned local Checkov 3.3.0 adapter integration; no benchmark inputs are scanned."""
from __future__ import annotations

import shutil
import hashlib
from pathlib import Path

from iac_guard_v.adapters.checkov import (
    CheckovAdapter,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
)
from iac_guard_v.enums import ArtifactKind, Status


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
    run = CheckovAdapter().scan(
        CheckovScanRequest(
            executable=_checkov(),
            scan_root=root,
            workspace_root=tmp_path,
            frameworks=("terraform",),
            files_eligible=("main.tf",),
            expected_version="3.3.0",
            expected_executable_sha256=hashlib.sha256(_checkov().read_bytes()).hexdigest(),
        )
    )
    assert run.status is Status.PASS
    assert run.scanner_version == "3.3.0"
    assert run.coverage.files_parsed == 1
    assert run.findings
    assert {"CKV_AWS_23", "CKV_AWS_24"} <= {item.rule_id for item in run.findings}
    assert all(item.artifact_kind is ArtifactKind.TERRAFORM_HCL for item in run.findings)


def test_pinned_checkov_330_kubernetes_contract(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\n  namespace: default\n"
        "spec:\n  containers:\n    - name: app\n      image: nginx:latest\n"
    )
    run = CheckovAdapter().scan(
        CheckovScanRequest(
            executable=_checkov(),
            scan_root=root,
            workspace_root=tmp_path,
            frameworks=("kubernetes",),
            files_eligible=("pod.yaml",),
            expected_version="3.3.0",
            expected_executable_sha256=hashlib.sha256(_checkov().read_bytes()).hexdigest(),
            kubernetes_identities=(
                CheckovKubernetesIdentity(
                    "pod.yaml", "Pod.default.demo", "v1", "Pod", "default", "demo"
                ),
            ),
        )
    )
    assert run.status is Status.PASS
    assert run.coverage.files_parsed == 1
    assert run.findings
    assert all(item.artifact_kind is ArtifactKind.KUBERNETES_YAML for item in run.findings)
    assert {item.resource_address for item in run.findings} == {"v1/Pod/default/demo"}
