"""Discoverability and failure remediation branches for the adoption CLI."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import iac_guard_v.cli as CLI
from iac_guard_v.api import BaselineDiscoveryUnavailable
from iac_guard_v.models import DomainError
from iac_guard_v.report import OperationalReportV1


def _direct(tmp_path: Path, **changes):
    values = {
        "before": tmp_path,
        "after": tmp_path,
        "target": ["CKV_X=aws_x.r"],
        "all_baseline_findings": False,
        "framework": ["terraform"],
        "local_trusted": True,
        "checkov_executable": tmp_path / "checkov",
    }
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.mark.parametrize("value", ["bad", "=resource", "RULE=", "RULE=resource@"])
def test_target_selector_rejections(value: str) -> None:
    with pytest.raises(DomainError, match="target selector"):
        CLI._parse_target_selector(value)


def test_direct_request_remediation_branches(monkeypatch, tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="--after"):
        CLI._direct_request(_direct(tmp_path, after=None))
    with pytest.raises(DomainError, match="--target"):
        CLI._direct_request(_direct(tmp_path, target=[]))
    with pytest.raises(DomainError, match="requires --local-trusted"):
        CLI._direct_request(_direct(tmp_path, local_trusted=False))

    monkeypatch.setattr(CLI.shutil, "which", lambda _name: None)
    unavailable = CLI._direct_request(_direct(tmp_path, checkov_executable=None))
    assert isinstance(unavailable, OperationalReportV1)
    assert unavailable.reason_code == "CHECKOV_NOT_FOUND"

    monkeypatch.setattr(
        CLI, "discover_baseline_targets",
        lambda *_a, **_k: (_ for _ in ()).throw(
            BaselineDiscoveryUnavailable("locked scanner unavailable")
        ),
    )
    unavailable = CLI._direct_request(_direct(tmp_path))
    assert unavailable.reason_code == "BASELINE_TARGET_DISCOVERY_UNAVAILABLE"


def test_pr_request_remediation_branches(monkeypatch, tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="--local-trusted"):
        CLI._pr_executable(_direct(tmp_path, local_trusted=False))
    unavailable = CLI._pr_executable(
        _direct(tmp_path, local_trusted=False, checkov_executable=None)
    )
    assert unavailable.reason_code == "HARDENED_CONTAINER_UNAVAILABLE"
    monkeypatch.setattr(CLI.shutil, "which", lambda _name: None)
    unavailable = CLI._pr_executable(_direct(tmp_path, checkov_executable=None))
    assert unavailable.reason_code == "CHECKOV_NOT_FOUND"

    args = SimpleNamespace(
        head_ref=None, target=["CKV_X=aws_x.r"], all_baseline_findings=False,
    )
    with pytest.raises(DomainError, match="--head-ref"):
        CLI._git_pr_report(args)
    args.head_ref = "HEAD"
    args.target = []
    with pytest.raises(DomainError, match="--target"):
        CLI._git_pr_report(args)


def test_doctor_and_reporter_closed_vocabularies() -> None:
    with pytest.raises(DomainError, match="doctor mode"):
        CLI.doctor("unknown")
    with pytest.raises(DomainError, match="output format"):
        CLI._project_report({}, "console")


def test_real_demo_requires_explicit_local_mode() -> None:
    with pytest.raises(DomainError, match="explicit --local-trusted"):
        CLI._real_demo(SimpleNamespace(local_trusted=False))
