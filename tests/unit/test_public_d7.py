"""D7 public boundary, fail-closed isolation, and report-v1 contracts."""
from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import pytest

import iac_guard_v.cli as CLI
from iac_guard_v.api import verify
from iac_guard_v.config import (
    ExecutionIsolation,
    PublicTarget,
    PublicVerificationRequest,
    load_public_config,
)
from iac_guard_v.engine import VerificationResult
from iac_guard_v.enums import ArtifactKind, Verdict
from iac_guard_v.models import DomainError, RequiredGates
from iac_guard_v.engine import load_operator_verification_config
from iac_guard_v.policy import PolicyResult
from iac_guard_v.report import OperationalReportV1, VerificationReportV1, render_console

from iac_guard_v.adapters.checkov import CheckovAdapter
from test_engine import IDENTITY, _executable, _run, _scan_request
from test_policy import _verdict, verified_engine  # noqa: F401


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    return baseline, candidate


def _hostile_request(tmp_path: Path) -> PublicVerificationRequest:
    baseline, candidate = _roots(tmp_path)
    return PublicVerificationRequest(
        baseline,
        candidate,
        (PublicTarget("CKV_X", "aws_x.r"),),
    )


def test_default_hostile_mode_never_downgrades_to_native(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "iac_guard_v.api.checkov_distribution_identity",
        lambda *_: pytest.fail("native scanner must not be inspected"),
    )
    report = verify(_hostile_request(tmp_path))
    assert type(report) is OperationalReportV1
    assert report.exit_code == 3
    assert report.verdict is Verdict.INCONCLUSIVE
    assert report.reason_code == "HARDENED_CONTAINER_UNAVAILABLE"


def test_reduced_isolation_requires_an_explicit_native_executable(tmp_path) -> None:
    baseline, candidate = _roots(tmp_path)
    with pytest.raises(DomainError, match="explicit Checkov executable"):
        PublicVerificationRequest(
            baseline, candidate, (PublicTarget("CKV_X", "aws_x.r"),),
            ExecutionIsolation.REDUCED_ISOLATION,
        )


def test_explicit_reduced_isolation_runs_only_internal_evidence_pipeline(
    monkeypatch, tmp_path,
) -> None:
    baseline, candidate = _roots(tmp_path)
    (baseline / "main.tf").write_text(
        'resource "aws_x" "r" {}\n', encoding="utf-8"
    )
    (candidate / "main.tf").write_text(
        'resource "aws_x" "r" {}\n# candidate snapshot\n', encoding="utf-8"
    )
    executable = _executable(tmp_path)
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, scan: _run(scan, baseline=scan.scan_root == baseline),
    )
    report = verify(PublicVerificationRequest(
        baseline,
        candidate,
        (PublicTarget(
            "CKV_X", "aws_x.r", "main.tf", ArtifactKind.TERRAFORM_HCL,
            "aws_x.r",
        ),),
        ExecutionIsolation.REDUCED_ISOLATION,
        executable,
        ("terraform",),
    ))
    assert type(report) is VerificationReportV1
    assert report.verdict is Verdict.VERIFIED
    assert report.exit_code == 0


def test_public_operator_config_binds_only_required_gate_implementations(tmp_path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    config = load_operator_verification_config(
        baseline.request,
        candidate.request,
        required_gates=RequiredGates(("terraform_hcl_parse",)),
        frameworks=("terraform",),
    )
    assert config.gate_registry.validator_ids == ("terraform_hcl_parse",)
    assert tuple(
        item.gate_id for item in config.gate_registry.implementations
    ) == ("terraform_hcl_parse",)


def test_public_request_has_no_precomputed_or_trust_assertion_fields() -> None:
    names = {item.name for item in fields(PublicVerificationRequest)}
    forbidden = {
        "scanner_run", "finding_diff", "policy", "exception_records",
        "trusted_origin", "expected_resources", "gate_executor", "evaluation_date",
        "scanner_environment_digest", "policy_inventory_digest",
    }
    assert names.isdisjoint(forbidden)


def test_config_rejects_unknown_precomputed_and_callback_fields(tmp_path) -> None:
    baseline, candidate = _roots(tmp_path)
    for field_name in ("scanner_run", "policy", "gate_callback", "trusted_origin"):
        path = tmp_path / f"{field_name}.json"
        path.write_text(json.dumps({
            "schema_version": "config-v1",
            "baseline": str(baseline),
            "candidate": str(candidate),
            "targets": [{"rule_id": "CKV_X", "resource_address": "aws_x.r"}],
            field_name: {},
        }), encoding="utf-8")
        with pytest.raises(DomainError, match="unknown fields"):
            load_public_config(path)


def test_config_rejects_duplicate_keys_and_symlink(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"schema_version":"config-v1","schema_version":"config-v1"}', encoding="utf-8")
    with pytest.raises(DomainError, match="duplicate"):
        load_public_config(path)
    link = tmp_path / "linked.json"
    link.symlink_to(path)
    with pytest.raises(DomainError, match="no-follow regular"):
        load_public_config(link)


def test_cli_hostile_mode_returns_typed_operational_exit_3(tmp_path, capsys) -> None:
    baseline, candidate = _roots(tmp_path)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "schema_version": "config-v1",
        "baseline": str(baseline),
        "candidate": str(candidate),
        "targets": [{"rule_id": "CKV_X", "resource_address": "aws_x.r"}],
    }), encoding="utf-8")
    assert CLI.main(["verify", "--config", str(path), "--format", "json"]) == 3
    output = json.loads(capsys.readouterr().out)
    assert output["verdict"] == "INCONCLUSIVE"
    assert output["diagnostic"]["reason_code"] == "HARDENED_CONTAINER_UNAVAILABLE"


def test_cli_invalid_request_is_exit_2(tmp_path, capsys) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"schema_version":"wrong"}', encoding="utf-8")
    assert CLI.main(["verify", "--config", str(path)]) == 2
    output = json.loads(capsys.readouterr().err)
    assert output["exit_code"] == 2
    assert output["reason_code"] == "INVALID_REQUEST"


def test_doctor_reports_absent_scanner_and_container_with_remediation(monkeypatch) -> None:
    monkeypatch.setattr(CLI.shutil, "which", lambda _name: None)
    report = CLI.doctor().canonical_dict()
    assert report["checkov"]["status"] == "UNAVAILABLE"
    assert report["hardened_container"]["status"] == "INCONCLUSIVE"
    assert report["checkov"]["remediation"]
    assert report["hardened_container"]["remediation"]


def test_report_v1_retains_complete_gate_snapshot_and_policy_evidence(
    verified_engine: VerificationResult,
) -> None:
    policy: PolicyResult = _verdict(verified_engine)
    report = VerificationReportV1(verified_engine, policy)
    canonical = report.canonical_dict()
    assert canonical["schema_version"] == "report-v1"
    assert canonical["exit_code"] == 0
    assert canonical["verification"]["gate_implementations"]
    for role in ("baseline_snapshot", "candidate_snapshot"):
        snapshot = canonical["verification"][role]
        assert "filesystem_entries" in snapshot
        assert snapshot["snapshot_sha256"]
    assert canonical["policy"]["policy_evidence"]["source_origin"] == "operator"
    assert "report_sha256" in render_console(report)


def test_report_rejects_policy_from_another_verification(
    verified_engine: VerificationResult,
) -> None:
    # A trusted policy result can only be combined with its bound verification snapshot.
    values = {
        name: getattr(verified_engine, name)
        for name in verified_engine.__dataclass_fields__
        if name not in {"_trusted_context", "_trusted"}
    }
    values["candidate_snapshot"] = verified_engine.baseline_snapshot
    with pytest.raises(DomainError):
        VerificationReportV1(
            VerificationResult(**values), _verdict(verified_engine)
        )


def test_public_schemas_and_console_entrypoint_are_packaged_contracts() -> None:
    root = Path(__file__).parents[2]
    for name in ("config-v1.schema.json", "report-v1.schema.json"):
        payload = json.loads(
            (root / "src/iac_guard_v/schemas" / name).read_text(encoding="utf-8")
        )
        assert payload["$schema"].endswith("2020-12/schema")
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'iac-guard = "iac_guard_v.cli:main"' in project
