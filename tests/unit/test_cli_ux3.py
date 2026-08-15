"""UX.3 mode diagnosis, demo, output, and discoverability tests."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import iac_guard_v.cli as CLI
from iac_guard_v.models import DomainError
from iac_guard_v.report import OperationalReportV1


def _doctor(checkov: str, hardened: str, registry: str) -> CLI.DoctorReportV1:
    return CLI.DoctorReportV1(
        {"status": checkov, "reason_code": "CHECKOV", "remediation": "install checkov"},
        {"status": hardened, "reason_code": "CONTAINER", "remediation": "install image"},
        {"status": registry, "reason_code": "REGISTRY", "remediation": "reinstall wheel"},
    )


def test_doctor_exit_status_tracks_only_requested_mode(monkeypatch, capsys) -> None:
    report = _doctor("PASS", "INCONCLUSIVE", "PASS")
    seen = []
    monkeypatch.setattr(
        CLI, "doctor",
        lambda mode="all", checkov_executable=None: seen.append(
            (mode, checkov_executable)
        ) or report,
    )
    assert CLI.main(["doctor", "--mode", "local-trusted", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["checkov"]["status"] == "PASS"
    assert CLI.main(["doctor", "--mode", "hardened-container"]) == 3
    capsys.readouterr()
    assert CLI.main(["doctor", "--mode", "all"]) == 3
    capsys.readouterr()
    assert seen == [
        ("local-trusted", None), ("hardened-container", None), ("all", None),
    ]


def test_doctor_uses_explicit_checkov_without_path_discovery(
    tmp_path: Path, monkeypatch,
) -> None:
    executable = tmp_path / "checkov"
    executable.write_bytes(b"launcher")
    executable.chmod(0o700)
    path_lookups: list[str] = []
    monkeypatch.setattr(
        CLI.shutil, "which",
        lambda name: path_lookups.append(name) or None,
    )
    monkeypatch.setattr(CLI, "_version", lambda path: "3.3.0" if path == executable else "bad")
    monkeypatch.setattr(
        CLI, "checkov_distribution_identity",
        lambda path, version: SimpleNamespace(
            scanner_environment_digest="a" * 64,
            policy_inventory_digest="b" * 64,
            installed_distribution_digest="c" * 64,
            dependency_lock_digest="d" * 64,
        ),
    )
    report = CLI.doctor("local-trusted", executable).canonical_dict()
    assert report["checkov"]["status"] == "PASS"
    assert "checkov" not in path_lookups
    assert report["checkov"]["launcher_sha256"]
    with pytest.raises(DomainError, match="valid only"):
        CLI.doctor("hardened-container", executable)

    missing = CLI.doctor("local-trusted", tmp_path / "missing").canonical_dict()
    assert missing["checkov"]["status"] == "INCONCLUSIVE"
    assert missing["checkov"]["reason_code"] == "CHECKOV_ENVIRONMENT_INCOMPLETE"


def test_offline_demo_shows_four_distinct_outcomes(capsys) -> None:
    assert CLI.main(["demo"]) == 0
    output = capsys.readouterr().out
    for value in ("VERIFIED", "FAILED", "SUPPRESSED", "INCONCLUSIVE"):
        assert value in output
    assert "not verification evidence" in output


def test_real_demo_uses_public_direct_request_and_writes_report(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    checkov = tmp_path / "checkov"
    checkov.write_bytes(b"launcher")
    checkov.chmod(0o700)
    seen = {}

    def direct(args):
        seen["before"] = args.before
        seen["after"] = args.after
        seen["target"] = args.target
        assert (args.before / "main.tf").exists()
        assert (args.after / "main.tf").exists()
        return object()

    monkeypatch.setattr(CLI, "_direct_request", direct)
    monkeypatch.setattr(
        CLI, "verify", lambda request: OperationalReportV1("REAL", "detail", "fix")
    )
    output = tmp_path / "real.json"
    assert CLI.main([
        "demo", "--real", "--local-trusted", "--checkov-executable", str(checkov),
        "--format", "json", "--output", str(output),
    ]) == 3
    assert json.loads(capsys.readouterr().out)["diagnostic"]["reason_code"] == "REAL"
    assert json.loads(output.read_text())["diagnostic"]["reason_code"] == "REAL"
    assert seen["target"] == [
        "CKV_AWS_53=aws_s3_bucket_public_access_block.example"
    ]
    assert not seen["before"].exists()
    assert not seen["after"].exists()


def test_help_explains_canonical_command_modes_target_and_exits(capsys) -> None:
    try:
        CLI.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    top = capsys.readouterr().out
    assert "iac-guard verify --before BEFORE --after AFTER" in top
    assert "Exit codes: 0 VERIFIED" in top
    assert "reduced isolation" in top
    assert "canonical alpha command" in top

    try:
        CLI.main(["verify", "--help"])
    except SystemExit as exc:
        assert exc.code == 0
    verify_help = capsys.readouterr().out
    assert "RULE_ID=RESOURCE_ADDRESS@FILE" in verify_help
    assert "--all-baseline-findings" in verify_help


def test_alias_and_explain_outputs_are_create_only_artifacts(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    report = OperationalReportV1("EXPECTED", "detail", "fix")
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(CLI, "load_public_config", lambda _path: object())
    monkeypatch.setattr(CLI, "verify", lambda _request: report)
    for command in ("scan", "differential"):
        output = tmp_path / f"{command}.json"
        assert CLI.main([
            command, "--config", str(config), "--format", "console",
            "--output", str(output), "--quiet",
        ]) == 3
        assert json.loads(output.read_text())["diagnostic"]["reason_code"] == "EXPECTED"
        assert capsys.readouterr().out == ""

    report_path = tmp_path / "input.json"
    report_path.write_text(report.canonical_json(), encoding="utf-8")
    explanation = tmp_path / "explanation.md"
    assert CLI.main([
        "explain", str(report_path), "--format", "markdown",
        "--output", str(explanation), "--quiet",
    ]) == 0
    assert explanation.read_text().startswith("# IaC-Guard-V report")
    assert capsys.readouterr().out == ""
    original = explanation.read_bytes()
    assert CLI.main([
        "explain", str(report_path), "--format", "markdown",
        "--output", str(explanation), "--quiet",
    ]) == 2
    assert explanation.read_bytes() == original
