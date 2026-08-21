"""E6.2 closed workflow commands and non-evidentiary lock records."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import iac_guard_v.cli as CLI
import iac_guard_v.workflow as WORKFLOW
from iac_guard_v.config import load_public_config
from iac_guard_v.models import DomainError
from iac_guard_v.report import OperationalReportV1


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir(parents=True)
    candidate.mkdir()
    return baseline, candidate


def _config(
    tmp_path: Path, *, file_path: str = "main.tf", changed: bool = True,
    mode: str = "hardened-container", executable: Path | None = None,
) -> Path:
    baseline, candidate = _roots(tmp_path)
    (baseline / "main.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    candidate_text = (
        'resource "aws_x" "r" {}\n# changed\n'
        if changed else 'resource "aws_x" "r" {}\n'
    )
    (candidate / "main.tf").write_text(candidate_text, encoding="utf-8")
    value = {
        "schema_version": "config-v1",
        "execution_mode": mode,
        "baseline": str(baseline),
        "candidate": str(candidate),
        "frameworks": ["terraform"],
        "targets": [{
            "rule_id": "CKV_X",
            "resource_address": "aws_x.r",
            "file_path": file_path,
            "artifact_kind": "terraform_hcl",
            "scanner_native_lookup": "aws_x.r",
        }],
    }
    if executable is not None:
        value["checkov_executable"] = str(executable)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_scan_and_differential_use_exact_public_request_and_report(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    config = _config(tmp_path)
    seen = []

    def fake_verify(request):
        seen.append(request)
        return OperationalReportV1("EXPECTED_UNCERTAINTY", "detail", "remediation")

    monkeypatch.setattr(CLI, "verify", fake_verify)
    outputs = []
    for command in ("scan", "differential"):
        assert CLI.main([command, "--config", str(config), "--format", "json"]) == 3
        outputs.append(capsys.readouterr().out)
    assert outputs[0] == outputs[1]
    assert len(seen) == 2
    assert seen[0] == seen[1] == load_public_config(config)


@pytest.mark.parametrize("output_format,marker", [
    ("sarif", '"version":"2.1.0"'),
    ("markdown", "# IaC-Guard-V report"),
    ("junit", '<testsuite name="IaC-Guard-V report-v1"'),
])
def test_report_commands_project_only_validated_report_v1(
    tmp_path: Path, monkeypatch, capsys, output_format: str, marker: str,
) -> None:
    config = _config(tmp_path)
    report = OperationalReportV1("EXPECTED_UNCERTAINTY", "detail", "remediation")
    monkeypatch.setattr(CLI, "verify", lambda _request: report)
    assert CLI.main([
        "scan", "--config", str(config), "--format", output_format,
    ]) == 3
    assert marker in capsys.readouterr().out

    report_path = tmp_path / "report.json"
    report_path.write_text(report.canonical_json(), encoding="utf-8")
    assert CLI.main([
        "explain", str(report_path), "--format", output_format,
    ]) == 0
    assert marker in capsys.readouterr().out


def test_init_creates_deterministic_closed_config_without_overwrite(
    tmp_path: Path, capsys,
) -> None:
    baseline, candidate = _roots(tmp_path)
    arguments = [
        "init", "--baseline", str(baseline), "--candidate", str(candidate),
        "--target", "CKV_X=aws_x.r", "--framework", "terraform",
        "--format", "json",
    ]
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    assert CLI.main([*arguments, "--output", str(first)]) == 0
    first_receipt = json.loads(capsys.readouterr().out)
    assert CLI.main([*arguments, "--output", str(second)]) == 0
    second_receipt = json.loads(capsys.readouterr().out)
    assert first.read_bytes() == second.read_bytes()
    assert first_receipt == second_receipt
    assert load_public_config(first) == load_public_config(second)
    assert set(json.loads(first.read_text())) == {
        "baseline", "candidate", "execution_mode", "frameworks",
        "schema_version", "targets",
    }
    assert CLI.main([*arguments, "--output", str(first)]) == 2
    assert json.loads(capsys.readouterr().err)["reason_code"] == "INVALID_REQUEST"


def test_init_rejects_malformed_selector_and_isolation_downgrade(
    tmp_path: Path, capsys,
) -> None:
    baseline, candidate = _roots(tmp_path)
    base = [
        "init", "--baseline", str(baseline), "--candidate", str(candidate),
        "--output", str(tmp_path / "config.json"),
    ]
    assert CLI.main([*base, "--target", "not-a-selector"]) == 2
    assert "target selector" in json.loads(capsys.readouterr().err)["detail"]
    assert CLI.main([
        *base, "--target", "CKV_X=aws_x.r", "--execution-mode", "reduced-isolation",
    ]) == 2
    assert "explicit Checkov executable" in json.loads(capsys.readouterr().err)["detail"]


def test_lock_hardened_mode_is_typed_uncertainty_and_writes_nothing(
    tmp_path: Path, capsys,
) -> None:
    config = _config(tmp_path)
    output = tmp_path / "guard.lock.json"
    assert CLI.main([
        "lock", "--config", str(config), "--output", str(output), "--format", "json",
    ]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["diagnostic"]["reason_code"] == "HARDENED_CONTAINER_LOCK_UNAVAILABLE"
    assert not output.exists()


def test_reduced_lock_binds_inspected_environment_without_private_paths(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    executable = tmp_path / "checkov"
    executable.write_bytes(b"locked launcher")
    executable.chmod(0o700)
    config = _config(
        tmp_path / "request", mode="reduced-isolation", executable=executable,
    )
    digest = hashlib.sha256(b"locked launcher").hexdigest()
    identity = SimpleNamespace(
        dependency_lock_digest="1" * 64,
        installed_distribution_digest="2" * 64,
        policy_inventory_digest="3" * 64,
        scanner_environment_digest="4" * 64,
    )
    monkeypatch.setattr(CLI, "_version", lambda _path: "3.3.0")
    monkeypatch.setattr(WORKFLOW, "checkov_distribution_identity", lambda *_: identity)
    # cli imported this function directly; the function still reads its module global.
    output = tmp_path / "iac-guard.lock.json"
    assert CLI.main([
        "lock", "--config", str(config), "--output", str(output), "--format", "json",
    ]) == 0
    receipt = json.loads(capsys.readouterr().out)
    lock = json.loads(output.read_text())
    assert lock["authority"] == "LOCK_RECORD_NOT_VERIFICATION_EVIDENCE"
    assert lock["scanner"]["launcher_sha256"] == digest
    assert lock["scanner"]["scanner_environment_digest"] == "4" * 64
    assert str(tmp_path) not in output.read_text()
    assert receipt["artifact_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()


def test_lock_rejects_symlink_launcher_before_distribution_identity(
    tmp_path: Path, monkeypatch,
) -> None:
    executable = tmp_path / "checkov-real"
    executable.write_bytes(b"launcher")
    link = tmp_path / "checkov"
    link.symlink_to(executable)
    request_path = _config(
        tmp_path / "request", mode="reduced-isolation", executable=link,
    )
    request = load_public_config(request_path)
    monkeypatch.setattr(
        WORKFLOW, "checkov_distribution_identity",
        lambda *_: pytest.fail("symlink must fail before distribution inspection"),
    )
    with pytest.raises(DomainError, match="no-follow regular"):
        WORKFLOW.create_reduced_isolation_lock(request, scanner_version="3.3.0")


def test_pr_changed_only_accepts_only_changed_exact_target_paths(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    changed = _config(tmp_path / "changed")
    calls = []
    monkeypatch.setattr(
        CLI, "verify",
        lambda request: calls.append(request) or OperationalReportV1("X", "x", "x"),
    )
    assert CLI.main([
        "pr", "--changed-only", "--config", str(changed), "--format", "json",
    ]) == 3
    capsys.readouterr()
    assert len(calls) == 1

    unchanged = _config(tmp_path / "unchanged", changed=False)
    assert CLI.main([
        "pr", "--changed-only", "--config", str(unchanged), "--format", "json",
    ]) == 2
    assert "unchanged" in json.loads(capsys.readouterr().err)["detail"]
    assert len(calls) == 1


def test_pr_changed_only_rejects_target_without_file_binding(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    config = _config(tmp_path, file_path="")
    monkeypatch.setattr(CLI, "verify", lambda _request: pytest.fail("must not execute"))
    assert CLI.main(["pr", "--changed-only", "--config", str(config)]) == 2
    assert "exact file_path" in json.loads(capsys.readouterr().err)["detail"]


def test_changed_only_rejects_duplicate_file_selectors(tmp_path: Path) -> None:
    config = _config(tmp_path)
    payload = json.loads(config.read_text())
    payload["targets"].append({
        "rule_id": "CKV_Y", "resource_address": "aws_x.r",
        "file_path": "main.tf", "artifact_kind": "terraform_hcl",
    })
    config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DomainError, match="must be unique"):
        WORKFLOW.changed_only_targets_are_bound(load_public_config(config))


def test_lock_factory_closes_mode_version_and_launcher_inspection(
    tmp_path: Path, monkeypatch,
) -> None:
    hardened = load_public_config(_config(tmp_path / "hardened"))
    with pytest.raises(DomainError, match="reduced-isolation"):
        WORKFLOW.create_reduced_isolation_lock(hardened, scanner_version="3.3.0")

    executable = tmp_path / "checkov"
    executable.write_bytes(b"launcher")
    executable.chmod(0o700)
    reduced = load_public_config(_config(
        tmp_path / "reduced", mode="reduced-isolation", executable=executable,
    ))
    with pytest.raises(DomainError, match="outside the locked contract"):
        WORKFLOW.create_reduced_isolation_lock(reduced, scanner_version="99.0.0")

    missing = tmp_path / "missing-checkov"
    missing_request = load_public_config(_config(
        tmp_path / "missing", mode="reduced-isolation", executable=missing,
    ))
    with pytest.raises(DomainError, match="cannot be inspected"):
        WORKFLOW.create_reduced_isolation_lock(
            missing_request, scanner_version="3.3.0"
        )
    with pytest.raises(DomainError, match="exact PublicVerificationRequest"):
        WORKFLOW.request_identity(object())
    assert "checkov_executable" in WORKFLOW.public_config_payload(reduced)


def test_workflow_output_validates_type_size_parent_and_write_progress(
    tmp_path: Path, monkeypatch,
) -> None:
    with pytest.raises(DomainError, match="pathlib.Path"):
        WORKFLOW.write_new_regular_file(str(tmp_path / "x"), b"x")
    for payload in (b"", "not-bytes", b"x" * (1024 * 1024 + 1)):
        with pytest.raises(DomainError, match="no larger"):
            WORKFLOW.write_new_regular_file(tmp_path / "x", payload)
    with pytest.raises(DomainError, match="parent does not exist"):
        WORKFLOW.write_new_regular_file(tmp_path / "missing" / "x", b"x")
    parent_file = tmp_path / "parent-file"
    parent_file.write_bytes(b"x")
    with pytest.raises(DomainError, match="parent must be a directory"):
        WORKFLOW.write_new_regular_file(parent_file / "child", b"x")

    monkeypatch.setattr(WORKFLOW.os, "write", lambda *_: 0)
    with pytest.raises(DomainError, match="new no-follow"):
        WORKFLOW.write_new_regular_file(tmp_path / "zero-write", b"x")


@pytest.mark.parametrize("flag", [
    "--scanner-run", "--oracle-result", "--validation-universe-result",
    "--policy-decision", "--callback", "--trusted-runtime",
])
def test_workflow_commands_do_not_accept_precomputed_evidence_flags(
    tmp_path: Path, flag: str,
) -> None:
    config = _config(tmp_path)
    with pytest.raises(SystemExit) as result:
        CLI.main(["scan", "--config", str(config), flag, "forged.json"])
    assert result.value.code == 2


def test_workflow_output_rejects_existing_and_symlink_entries(tmp_path: Path) -> None:
    existing = tmp_path / "existing.json"
    existing.write_text("owned", encoding="utf-8")
    with pytest.raises(DomainError, match="new no-follow"):
        WORKFLOW.write_new_regular_file(existing, b"{}\n")
    target = tmp_path / "target.json"
    target.write_text("owned", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(DomainError, match="new no-follow"):
        WORKFLOW.write_new_regular_file(link, b"{}\n")
    assert target.read_text() == "owned"
