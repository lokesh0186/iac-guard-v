"""Offline KICS v2.1.20 execution against the exact E0.3 image lock."""
from __future__ import annotations

import hashlib
import platform
import shutil
from pathlib import Path

from iac_guard_v.adapters.kics import KicsAdapter, create_kics_scan_request
from iac_guard_v.adapters.phase_e_lock import (
    load_locked_container_identity, load_protected_phase_e_evidence,
)
from iac_guard_v.adapters.phase_e_runtime import attest_container_runtime
from iac_guard_v.enums import ArtifactKind, Status
from iac_guard_v.models import BoundInputFile, ExpectedResource


def test_locked_kics_finding_and_offline_execution(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    source = root / "main.tf"
    source.write_text('resource "aws_s3_bucket" "demo" {}\n', encoding="utf-8")
    metadata = source.stat()
    evidence = BoundInputFile(
        "main.tf", "regular_file", metadata.st_size,
        hashlib.sha256(source.read_bytes()).hexdigest(), metadata.st_dev, metadata.st_ino,
    )
    architecture = "linux/arm64" if platform.machine() in {"arm64", "aarch64"} else "linux/amd64"
    repo_root = Path(__file__).parents[2]
    bundle = load_protected_phase_e_evidence(repo_root)
    locked = load_locked_container_identity(bundle, "kics", architecture)
    request = create_kics_scan_request(
        workspace_root=root,
        scan_root=root,
        files_eligible=("main.tf",),
        eligible_file_evidence=(evidence,),
        expected_resources=(ExpectedResource(
            "main.tf", "aws_s3_bucket.demo", ArtifactKind.TERRAFORM_HCL,
            "aws_s3_bucket.demo",
        ),),
        container_runtime=attest_container_runtime(
            Path(shutil.which("docker") or "docker").resolve(strict=True),
            protected_execution_context_identity=hashlib.sha256(
                b"phase-e-locked-integration"
            ).hexdigest(),
            protected_evidence=bundle,
            evaluated_workspaces=(root,),
        ),
        locked_identity=locked,
    )
    run = KicsAdapter().scan(request)
    assert run.status is Status.PASS
    assert run.findings
    assert all(item.native_fingerprint for item in run.findings)
    assert run.scanner_environment_digest == request.locked_identity.environment_digest
    assert run.policy_inventory_digest == request.locked_identity.policy_inventory_digest
    assert "COMPLETED" in run.diagnostics
