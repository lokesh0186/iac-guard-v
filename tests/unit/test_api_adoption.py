"""Branch-complete tests for the direct and Git adoption API boundaries."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import iac_guard_v.api as API
from iac_guard_v.enums import ArtifactKind, Severity, Status
from iac_guard_v.models import (
    CoverageCounters,
    DomainError,
    ExpectedResource,
    Finding,
    FindingLocation,
    ResourceCoverage,
    ScannerRun,
)


def _finding(file_path: str = "main.tf", resource: str = "aws_x.r") -> Finding:
    return Finding(
        "checkov", "3.3.0", "CKV_X", resource,
        FindingLocation(file_path, 1, 1), Severity.HIGH,
        artifact_kind=ArtifactKind.TERRAFORM_HCL,
    )


def _run(*findings: Finding, status: Status = Status.PASS) -> ScannerRun:
    digest = "a" * 64
    return ScannerRun._from_adapter(
        scanner="checkov", scanner_version="3.3.0", status=status,
        findings=findings,
        coverage=CoverageCounters(1, 1, 1, 0, 0, 0, 0),
        resource_coverage=ResourceCoverage(1, 1, 1, 0, 0, 1),
        exit_code=0, stdout_sha256=digest, stderr_sha256=digest,
        raw_output_sha256=digest, resolved_launcher_path="/protected/checkov",
        launcher_digest=digest, scanner_environment_digest=digest,
        policy_inventory_digest=digest, invocation_config_digest=digest,
        ruleset_integrity=Status.PASS, diagnostics=("COMPLETED",),
    )


def _install_discovery(
    monkeypatch: pytest.MonkeyPatch,
    run: ScannerRun,
    resources: tuple[ExpectedResource, ...],
) -> None:
    plan = SimpleNamespace(request=object(), expected_resources=resources)
    monkeypatch.setattr(API, "_untrusted_scan_request", lambda *_: object())
    monkeypatch.setattr(API, "attest_checkov_scan_plan", lambda _request: plan)

    class Adapter:
        def scan(self, request):
            assert request is plan.request
            return run

    monkeypatch.setattr(API, "CheckovAdapter", Adapter)


def test_discovery_resolves_all_and_exact_targets(monkeypatch, tmp_path: Path) -> None:
    finding = _finding()
    resource = ExpectedResource(
        "main.tf", "aws_x.r", ArtifactKind.TERRAFORM_HCL, "aws_x.r",
    )
    _install_discovery(monkeypatch, _run(finding), (resource,))
    all_targets = API.discover_baseline_targets(
        tmp_path, tmp_path / "checkov", ("terraform",), all_findings=True,
    )
    exact_targets = API.discover_baseline_targets(
        tmp_path, tmp_path / "checkov", ("terraform",),
        (("CKV_X", "aws_x.r", "main.tf"),),
    )
    assert all_targets == exact_targets
    assert all_targets[0].scanner_native_lookup == "aws_x.r"


def test_discovery_ambiguity_missing_duplicate_and_filtering(
    monkeypatch, tmp_path: Path,
) -> None:
    findings = (_finding("a.tf"), _finding("b.tf"))
    resources = tuple(
        ExpectedResource(path, "aws_x.r", ArtifactKind.TERRAFORM_HCL, "aws_x.r")
        for path in ("a.tf", "b.tf")
    )
    _install_discovery(monkeypatch, _run(*findings), resources)
    with pytest.raises(DomainError, match="ambiguous"):
        API.discover_baseline_targets(
            tmp_path, tmp_path / "checkov", ("terraform",),
            (("CKV_X", "aws_x.r", ""),),
        )
    with pytest.raises(DomainError, match="no failed finding"):
        API.discover_baseline_targets(
            tmp_path, tmp_path / "checkov", ("terraform",),
            (("CKV_OTHER", "aws_x.r", ""),),
        )
    with pytest.raises(DomainError, match="duplicate exact targets"):
        API.discover_baseline_targets(
            tmp_path, tmp_path / "checkov", ("terraform",),
            (("CKV_X", "aws_x.r", "a.tf"), ("CKV_X", "aws_x.r", "a.tf")),
        )
    filtered = API.discover_baseline_targets(
        tmp_path, tmp_path / "checkov", ("terraform",), all_findings=True,
        eligible_paths=("a.tf",),
    )
    assert tuple(item.file_path for item in filtered) == ("a.tf",)


def test_discovery_rejects_bad_inputs_and_incomplete_evidence(
    monkeypatch, tmp_path: Path,
) -> None:
    arguments = [
        (str(tmp_path), tmp_path / "checkov", ("terraform",), (), True, None),
        (tmp_path, tmp_path / "checkov", (), (), True, None),
        (tmp_path, tmp_path / "checkov", ("terraform",), [], False, None),
        (tmp_path, tmp_path / "checkov", ("terraform",), (), "yes", None),
        (tmp_path, tmp_path / "checkov", ("terraform",), (), False, None),
        (tmp_path, tmp_path / "checkov", ("terraform",), (), True, ["main.tf"]),
    ]
    for root, executable, frameworks, selectors, all_findings, eligible in arguments:
        with pytest.raises(DomainError):
            API.discover_baseline_targets(
                root, executable, frameworks, selectors,
                all_findings=all_findings, eligible_paths=eligible,
            )

    _install_discovery(monkeypatch, _run(status=Status.PARTIAL), ())
    with pytest.raises(API.BaselineDiscoveryUnavailable, match="not complete"):
        API.discover_baseline_targets(
            tmp_path, tmp_path / "checkov", ("terraform",), all_findings=True,
        )
    monkeypatch.setattr(
        API, "_untrusted_scan_request",
        lambda *_: (_ for _ in ()).throw(OSError("unavailable")),
    )
    with pytest.raises(API.BaselineDiscoveryUnavailable, match="unavailable"):
        API.discover_baseline_targets(
            tmp_path, tmp_path / "checkov", ("terraform",), all_findings=True,
        )


def test_discovery_requires_independent_resource_binding(monkeypatch, tmp_path: Path) -> None:
    _install_discovery(monkeypatch, _run(_finding()), ())
    with pytest.raises(DomainError, match="independent resource binding"):
        API.discover_baseline_targets(
            tmp_path, tmp_path / "checkov", ("terraform",), all_findings=True,
        )


def test_git_api_requires_trusted_exact_materialization(monkeypatch, tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()

    class Materialization:
        def __init__(self, trusted=True):
            self._trusted = trusted
            self.baseline_root = before
            self.candidate_root = after

    monkeypatch.setattr(API, "GitVerificationMaterialization", Materialization)
    request = SimpleNamespace(baseline_root=before, candidate_root=after)
    expected = object()
    monkeypatch.setattr(API, "_verify_request", lambda req, materialized: expected)
    assert API._verify_git(request, Materialization()) is expected
    with pytest.raises(DomainError, match="protected materialization"):
        API._verify_git(request, Materialization(False))
    wrong = SimpleNamespace(baseline_root=after, candidate_root=before)
    with pytest.raises(DomainError, match="disagree"):
        API._verify_git(wrong, Materialization())
