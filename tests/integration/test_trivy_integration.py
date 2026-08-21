"""Offline Trivy v0.73.0 execution using the exact E0.3 external checks lock."""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
from pathlib import Path

from iac_guard_v.adapters.phase_e_lock import (
    load_locked_container_identity,
    load_protected_checks_cache_identity,
    load_protected_phase_e_evidence,
)
from iac_guard_v.adapters.phase_e_runtime import attest_container_runtime
from iac_guard_v.adapters.trivy import TrivyAdapter, create_trivy_scan_request
from iac_guard_v.enums import ArtifactKind, Status
from iac_guard_v.models import BoundInputFile, ExpectedResource


def test_locked_trivy_finding_external_bundle_and_offline_execution(tmp_path: Path) -> None:
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
    cache_setting = os.environ.get("IACGV_PHASE_E_CACHE")
    assert cache_setting, "IACGV_PHASE_E_CACHE must name the E0.3 protected cache root"
    protected_cache = load_protected_checks_cache_identity(
        bundle, Path(cache_setting)
    )
    request = create_trivy_scan_request(
        workspace_root=root, scan_root=root,
        files_eligible=("main.tf",), eligible_file_evidence=(evidence,),
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
        protected_checks_cache=protected_cache,
        locked_identity=load_locked_container_identity(bundle, "trivy", architecture),
    )
    result = TrivyAdapter().scan(request)
    assert result.scanner_run.status is Status.PASS
    assert result.scanner_run.findings
    assert result.source == "external"
    assert result.fallback_used is False
    assert result.network_disabled and result.updates_disabled
    assert result.checks_manifest_digest == request.locked_identity.checks_manifest_digest
    assert result.checks_cache_content_sha256 == request._cache_content_sha256
    assert result.container_runtime_identity == request.container_runtime.identity
    assert result.scanner_run.launcher_digest == request.container_runtime.executable_sha256
    assert result.raw_stdout_sha256 == (
        result.scanner_run.stdout_sha256 or hashlib.sha256(b"").hexdigest()
    )
    assert result.raw_stderr_sha256 == (
        result.scanner_run.stderr_sha256 or hashlib.sha256(b"").hexdigest()
    )
    assert result.raw_results_file_sha256 == result.native_output_bytes_sha256
    assert len(result.canonical_output_sha256) == 64
    assert len(result.output_directory_physical_manifest_sha256) == 64
    assert len(result.fallback_determination_sha256) == 64
    assert result.cache_attestation_public_key_sha256 == (
        request.protected_checks_cache.cache_attestation_public_key_sha256
    )


def test_locked_trivy_valid_empty_result(tmp_path: Path) -> None:
    root = tmp_path / "empty-candidate"
    root.mkdir()
    source = root / "main.tf"
    source.write_text(
        'resource "aws_s3_bucket_public_access_block" "demo" {\n'
        '  bucket = "example"\n'
        '  block_public_acls = true\n'
        '  block_public_policy = true\n'
        '  ignore_public_acls = true\n'
        '  restrict_public_buckets = true\n'
        '}\n',
        encoding="utf-8",
    )
    metadata = source.stat()
    bound = BoundInputFile(
        "main.tf", "regular_file", metadata.st_size,
        hashlib.sha256(source.read_bytes()).hexdigest(), metadata.st_dev, metadata.st_ino,
    )
    architecture = "linux/arm64" if platform.machine() in {"arm64", "aarch64"} else "linux/amd64"
    repo_root = Path(__file__).parents[2]
    bundle = load_protected_phase_e_evidence(repo_root)
    cache_setting = os.environ.get("IACGV_PHASE_E_CACHE")
    assert cache_setting, "IACGV_PHASE_E_CACHE must name the E0.3 protected cache root"
    request = create_trivy_scan_request(
        workspace_root=root, scan_root=root,
        files_eligible=("main.tf",), eligible_file_evidence=(bound,),
        expected_resources=(ExpectedResource(
            "main.tf", "aws_s3_bucket_public_access_block.demo",
            ArtifactKind.TERRAFORM_HCL, "aws_s3_bucket_public_access_block.demo",
        ),),
        container_runtime=attest_container_runtime(
            Path(shutil.which("docker") or "docker").resolve(strict=True),
            protected_execution_context_identity=hashlib.sha256(
                b"phase-e-locked-integration"
            ).hexdigest(),
            protected_evidence=bundle,
            evaluated_workspaces=(root,),
        ),
        protected_checks_cache=load_protected_checks_cache_identity(
            bundle, Path(cache_setting)
        ),
        locked_identity=load_locked_container_identity(
            bundle, "trivy", architecture,
        ),
    )
    result = TrivyAdapter().scan(request)
    assert result.scanner_run.status is Status.PARTIAL
    assert result.scanner_run.findings == ()
    assert result.source == "external" and result.fallback_used is False
    assert "COVERAGE_MISMATCH" in result.scanner_run.diagnostics
