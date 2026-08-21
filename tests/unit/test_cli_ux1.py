"""UX.1 direct-request adoption boundary."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import iac_guard_v.cli as CLI
from iac_guard_v.config import PublicTarget
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import DomainError
from iac_guard_v.report import OperationalReportV1


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    (before / "main.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    (after / "main.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    return before, after


def _exact_target() -> PublicTarget:
    return PublicTarget(
        "CKV_X",
        "aws_x.r",
        "main.tf",
        ArtifactKind.TERRAFORM_HCL,
        "aws_x.r",
    )


def test_direct_and_config_build_equivalent_public_request_and_report(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    before, after = _roots(tmp_path)
    checkov = tmp_path / "checkov"
    checkov.write_bytes(b"launcher")
    checkov.chmod(0o700)
    monkeypatch.setattr(CLI, "discover_baseline_targets", lambda *_args, **_kwargs: (_exact_target(),))
    seen = []
    expected = OperationalReportV1("EXPECTED", "detail", "remediation")
    monkeypatch.setattr(CLI, "verify", lambda request: seen.append(request) or expected)

    direct_output = tmp_path / "direct.json"
    assert CLI.main([
        "verify", "--before", str(before), "--after", str(after),
        "--target", "CKV_X=aws_x.r", "--framework", "terraform",
        "--local-trusted", "--checkov-executable", str(checkov),
        "--format", "json", "--output", str(direct_output),
    ]) == 3
    direct_stdout = capsys.readouterr().out

    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "schema_version": "config-v1",
        "execution_mode": "reduced-isolation",
        "baseline": str(before),
        "candidate": str(after),
        "checkov_executable": str(checkov),
        "frameworks": ["terraform"],
        "targets": [{
            "rule_id": "CKV_X",
            "resource_address": "aws_x.r",
            "file_path": "main.tf",
            "artifact_kind": "terraform_hcl",
            "scanner_native_lookup": "aws_x.r",
        }],
    }), encoding="utf-8")
    config_output = tmp_path / "config-report.json"
    assert CLI.main([
        "verify", "--config", str(config), "--format", "json",
        "--output", str(config_output),
    ]) == 3
    config_stdout = capsys.readouterr().out

    assert seen[0] == seen[1]
    assert direct_stdout == config_stdout == expected.canonical_json()
    assert direct_output.read_bytes() == config_output.read_bytes()


def test_direct_ambiguous_target_prints_exact_candidate_selectors(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    before, after = _roots(tmp_path)
    checkov = tmp_path / "checkov"
    checkov.write_bytes(b"launcher")
    checkov.chmod(0o700)
    monkeypatch.setattr(
        CLI,
        "discover_baseline_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(DomainError(
            "target selector is ambiguous; choose one exact selector: "
            "CKV_X=aws_x.r@a.tf, CKV_X=aws_x.r@b.tf"
        )),
    )
    assert CLI.main([
        "verify", "--before", str(before), "--after", str(after),
        "--target", "CKV_X=aws_x.r", "--local-trusted",
        "--checkov-executable", str(checkov),
    ]) == 2
    error = json.loads(capsys.readouterr().err)
    assert "CKV_X=aws_x.r@a.tf" in error["detail"]
    assert "CKV_X=aws_x.r@b.tf" in error["detail"]


def test_zero_baseline_targets_is_inconclusive_never_verified(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    before, after = _roots(tmp_path)
    checkov = tmp_path / "checkov"
    checkov.write_bytes(b"launcher")
    checkov.chmod(0o700)
    monkeypatch.setattr(CLI, "discover_baseline_targets", lambda *_args, **_kwargs: ())
    assert CLI.main([
        "verify", "--before", str(before), "--after", str(after),
        "--all-baseline-findings", "--local-trusted",
        "--checkov-executable", str(checkov), "--format", "json",
    ]) == 3
    value = json.loads(capsys.readouterr().out)
    assert value["verdict"] == "INCONCLUSIVE"
    assert value["diagnostic"]["reason_code"] == "NO_BASELINE_TARGETS"


def test_report_output_is_new_no_follow_and_quiet_is_supported(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    before, after = _roots(tmp_path)
    checkov = tmp_path / "checkov"
    checkov.write_bytes(b"launcher")
    checkov.chmod(0o700)
    monkeypatch.setattr(CLI, "discover_baseline_targets", lambda *_args, **_kwargs: (_exact_target(),))
    monkeypatch.setattr(
        CLI, "verify", lambda _request: OperationalReportV1("EXPECTED", "detail", "fix")
    )
    base = [
        "verify", "--before", str(before), "--after", str(after),
        "--target", "CKV_X=aws_x.r", "--local-trusted",
        "--checkov-executable", str(checkov), "--quiet",
    ]
    output = tmp_path / "report.json"
    assert CLI.main([*base, "--output", str(output)]) == 3
    assert capsys.readouterr().out == ""
    original = output.read_bytes()
    assert CLI.main([*base, "--output", str(output)]) == 2
    assert output.read_bytes() == original
    capsys.readouterr()

    symlink = tmp_path / "linked-report.json"
    target = tmp_path / "outside.json"
    target.write_text("unchanged", encoding="utf-8")
    symlink.symlink_to(target)
    assert CLI.main([*base, "--output", str(symlink)]) == 2
    assert target.read_text(encoding="utf-8") == "unchanged"


def test_hardened_direct_mode_never_falls_back_to_local(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    before, after = _roots(tmp_path)
    monkeypatch.setattr(
        CLI,
        "discover_baseline_targets",
        lambda *_args, **_kwargs: pytest.fail("hardened mode must not execute local Checkov"),
    )
    assert CLI.main([
        "verify", "--before", str(before), "--after", str(after),
        "--target", "CKV_X=aws_x.r", "--format", "json",
    ]) == 3
    value = json.loads(capsys.readouterr().out)
    assert value["diagnostic"]["reason_code"] == "HARDENED_CONTAINER_UNAVAILABLE"
    assert "--local-trusted" in value["diagnostic"]["remediation"]


def test_config_and_direct_arguments_are_mutually_exclusive(
    tmp_path: Path, capsys,
) -> None:
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")
    assert CLI.main([
        "verify", "--config", str(config), "--after", str(tmp_path),
    ]) == 2
    assert "cannot be combined" in json.loads(capsys.readouterr().err)["detail"]
