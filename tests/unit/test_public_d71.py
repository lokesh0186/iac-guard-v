"""D7.1 closed public API, CLI, config, and report contracts."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

import iac_guard_v.cli as CLI
from iac_guard_v.api import verify
from iac_guard_v.config import ExecutionIsolation, PublicTarget, PublicVerificationRequest
from iac_guard_v.engine import VerificationResult
from iac_guard_v.enums import ArtifactKind, Verdict
from iac_guard_v.models import DomainError
from iac_guard_v.report import CandidateArtifactFailureReportV1, VerificationReportV1, validate_report_payload

from test_engine import _executable
from test_policy import _verdict, verified_engine  # noqa: F401


ROOT = Path(__file__).parents[2]
REPORT_SCHEMA = json.loads((ROOT / "src/iac_guard_v/schemas/report-v1.schema.json").read_text())
CONFIG_SCHEMA = json.loads((ROOT / "src/iac_guard_v/schemas/config-v1.schema.json").read_text())


@pytest.mark.parametrize("payload", [
    {"schema_version": "report-v1", "result_kind": "operational_uncertainty", "verdict": "VERIFIED", "exit_code": 0, "diagnostic": {"reason_code": "X", "detail": "x", "remediation": "x"}},
    {"schema_version": "report-v1", "result_kind": "operational_uncertainty", "verdict": "INCONCLUSIVE", "exit_code": 3, "diagnostic": {"reason_code": "X", "detail": "x", "remediation": "x"}, "policy": {}},
])
def test_contradictory_operational_reports_are_rejected(payload) -> None:
    with pytest.raises((jsonschema.ValidationError, DomainError)):
        validate_report_payload(payload)


def test_policy_and_top_level_must_agree(verified_engine: VerificationResult) -> None:
    report = VerificationReportV1(verified_engine, _verdict(verified_engine)).canonical_dict()
    report["policy"]["verdict"] = "FAILED"
    report["policy"]["exit_code"] = 1
    with pytest.raises(DomainError):
        validate_report_payload(report)


@pytest.mark.parametrize("mode,executable", [
    ("reduced-isolation", None),
    ("hardened-container", "/usr/bin/checkov"),
])
def test_config_schema_closes_isolation_conditions(mode, executable) -> None:
    payload = {"schema_version": "config-v1", "execution_mode": mode, "baseline": "b", "candidate": "c", "targets": [{"rule_id": "CKV_X", "resource_address": "aws_x.r"}]}
    if executable is not None:
        payload["checkov_executable"] = executable
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, CONFIG_SCHEMA)


@pytest.mark.parametrize("direction", ["baseline_parent", "candidate_parent"])
def test_nested_roots_are_rejected(tmp_path: Path, direction: str) -> None:
    parent = tmp_path / "parent"; child = parent / "child"; child.mkdir(parents=True)
    baseline, candidate = (parent, child) if direction == "baseline_parent" else (child, parent)
    with pytest.raises(DomainError, match="must not contain"):
        PublicVerificationRequest(baseline, candidate, (PublicTarget("CKV_X", "aws_x.r"),))


def test_invalid_candidate_hcl_is_verification_failure_not_request_error(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"; candidate = tmp_path / "candidate"
    baseline.mkdir(); candidate.mkdir()
    (baseline / "main.tf").write_text('resource "aws_x" "r" {}\n')
    (candidate / "main.tf").write_text('resource "aws_x" "r" {\n')
    report = verify(PublicVerificationRequest(
        baseline, candidate,
        (PublicTarget("CKV_X", "aws_x.r", "main.tf", ArtifactKind.TERRAFORM_HCL, "aws_x.r"),),
        ExecutionIsolation.REDUCED_ISOLATION, _executable(tmp_path), ("terraform",),
    ))
    assert type(report) is CandidateArtifactFailureReportV1
    assert report.verdict is Verdict.FAILED
    assert report.exit_code == 1
    jsonschema.validate(report.canonical_dict(), REPORT_SCHEMA)


def test_reduced_verified_report_names_isolation(verified_engine: VerificationResult) -> None:
    report = VerificationReportV1(verified_engine, _verdict(verified_engine)).canonical_dict()
    assert report["execution_isolation"]["mode"] == "reduced-isolation"
    assert report["execution_isolation"]["hostile_input_support"] is False


def test_version_demo_and_explain_are_real_commands(tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit) as result:
        CLI.main(["--version"])
    assert result.value.code == 0
    assert "iac-guard" in capsys.readouterr().out
    assert CLI.main(["demo", "--format", "json"]) == 0
    demo = capsys.readouterr().out
    report_path = tmp_path / "report.json"; report_path.write_text(demo)
    assert CLI.main(["explain", str(report_path)]) == 0
    assert "report explanation" in capsys.readouterr().out


def test_doctor_report_deeply_copies_source_mappings() -> None:
    source = {"status": "PASS", "nested": {"values": ["a", "b"]}}
    report = CLI.DoctorReportV1(source, {"status": "PASS"})
    before = report.canonical_json()
    source["status"] = "FAIL"; source["nested"]["values"].append("c")
    assert report.canonical_json() == before


def test_real_reports_validate_and_unknown_nested_fields_fail(verified_engine: VerificationResult) -> None:
    report = VerificationReportV1(verified_engine, _verdict(verified_engine)).canonical_dict()
    jsonschema.validate(report, REPORT_SCHEMA)
    report["execution_isolation"]["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(report, REPORT_SCHEMA)
