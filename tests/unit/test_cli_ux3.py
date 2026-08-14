"""UX.3 mode diagnosis, demo, output, and discoverability tests."""
from __future__ import annotations

import json
from pathlib import Path

import iac_guard_v.cli as CLI
from iac_guard_v.report import OperationalReportV1


def _doctor(checkov: str, hardened: str, registry: str) -> CLI.DoctorReportV1:
    return CLI.DoctorReportV1(
        {"status": checkov, "reason_code": "CHECKOV", "remediation": "install checkov"},
        {"status": hardened, "reason_code": "CONTAINER", "remediation": "install image"},
        {"status": registry, "reason_code": "REGISTRY", "remediation": "reinstall wheel"},
    )


def test_doctor_exit_status_tracks_only_requested_mode(monkeypatch, capsys) -> None:
    report = _doctor("PASS", "INCONCLUSIVE", "PASS")
    monkeypatch.setattr(CLI, "doctor", lambda mode="all": report)
    assert CLI.main(["doctor", "--mode", "local-trusted", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["checkov"]["status"] == "PASS"
    assert CLI.main(["doctor", "--mode", "hardened-container"]) == 3
    capsys.readouterr()
    assert CLI.main(["doctor", "--mode", "all"]) == 3
    capsys.readouterr()


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
