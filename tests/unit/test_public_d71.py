"""D7.1 closed public API, CLI, config, and report contracts."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import jsonschema
import pytest

import iac_guard_v.cli as CLI
import iac_guard_v.api as API
from iac_guard_v.api import verify
from iac_guard_v.config import (
    ExecutionIsolation, PublicTarget, PublicVerificationRequest, load_public_config,
)
from iac_guard_v.engine import VerificationResult
from iac_guard_v.enums import ArtifactKind, Verdict
from iac_guard_v.models import DomainError
from iac_guard_v.report import (
    CandidateArtifactFailureReportV1, ExecutionIsolationEvidence, OperationalReportV1,
    VerificationReportV1, render_console, validate_report_payload,
)

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


@pytest.mark.parametrize("artifact,occurrences", [
    ("terraform_hcl", 1),
    (ArtifactKind.TERRAFORM_HCL, True),
    (ArtifactKind.TERRAFORM_HCL, 0),
])
def test_public_target_rejects_untyped_or_invalid_values(artifact, occurrences) -> None:
    with pytest.raises(DomainError):
        PublicTarget("CKV_X", "aws_x.r", artifact_kind=artifact, baseline_occurrences=occurrences)


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir(); candidate.mkdir()
    return baseline, candidate


@pytest.mark.parametrize("field,value", [
    ("execution_isolation", "reduced-isolation"),
    ("targets", []),
    ("targets", ("not-a-target",)),
    ("frameworks", ["terraform"]),
    ("frameworks", ("terraform", "terraform")),
    ("frameworks", ("trivy",)),
])
def test_public_request_rejects_untyped_closed_fields(tmp_path: Path, field, value) -> None:
    baseline, candidate = _roots(tmp_path)
    values = {
        "baseline_root": baseline,
        "candidate_root": candidate,
        "targets": (PublicTarget("CKV_X", "aws_x.r"),),
        "execution_isolation": ExecutionIsolation.HARDENED_CONTAINER,
        "frameworks": ("terraform",),
    }
    values[field] = value
    with pytest.raises(DomainError):
        PublicVerificationRequest(**values)


def test_public_request_rejects_bad_roots_and_isolation_executable(tmp_path: Path) -> None:
    baseline, candidate = _roots(tmp_path)
    target = (PublicTarget("CKV_X", "aws_x.r"),)
    with pytest.raises(DomainError, match="pathlib"):
        PublicVerificationRequest(str(baseline), candidate, target)
    with pytest.raises(DomainError, match="does not exist"):
        PublicVerificationRequest(tmp_path / "missing", candidate, target)
    file_root = tmp_path / "file"; file_root.write_text("x")
    with pytest.raises(DomainError, match="directory"):
        PublicVerificationRequest(file_root, candidate, target)
    with pytest.raises(DomainError, match="distinct"):
        PublicVerificationRequest(baseline, baseline, target)
    with pytest.raises(DomainError, match="cannot provide"):
        PublicVerificationRequest(
            baseline, candidate, target, checkov_executable=tmp_path / "checkov",
            frameworks=("terraform",),
        )


def _write_config(tmp_path: Path, payload, *, raw: bytes | None = None) -> Path:
    path = tmp_path / "config.json"
    path.write_bytes(raw if raw is not None else json.dumps(payload).encode())
    return path


@pytest.mark.parametrize("mutation", [
    {"unknown": True},
    {"schema_version": "wrong"},
    {"baseline": None},
    {"targets": []},
    {"targets": ["bad"]},
    {"targets": [{"rule_id": "CKV_X"}]},
    {"targets": [{"rule_id": 1, "resource_address": "aws_x.r"}]},
    {"targets": [{"rule_id": "CKV_X", "resource_address": "aws_x.r", "artifact_kind": "bad"}]},
    {"execution_mode": "bad"},
    {"checkov_executable": ""},
    {"frameworks": [1]},
])
def test_config_loader_rejects_malformed_fields(tmp_path: Path, mutation) -> None:
    baseline, candidate = _roots(tmp_path)
    payload = {
        "schema_version": "config-v1", "baseline": str(baseline),
        "candidate": str(candidate),
        "targets": [{"rule_id": "CKV_X", "resource_address": "aws_x.r"}],
    }
    payload.update(mutation)
    with pytest.raises(DomainError):
        load_public_config(_write_config(tmp_path, payload))


def test_config_reader_rejects_path_and_json_failures(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="pathlib"):
        load_public_config("config.json")
    with pytest.raises(DomainError, match="inspected"):
        load_public_config(tmp_path / "missing")
    directory = tmp_path / "directory"; directory.mkdir()
    with pytest.raises(DomainError, match="regular file"):
        load_public_config(directory)
    with pytest.raises(DomainError, match="UTF-8 JSON"):
        load_public_config(_write_config(tmp_path, {}, raw=b"\xff"))
    with pytest.raises(DomainError, match="top level"):
        load_public_config(_write_config(tmp_path, []))
    with pytest.raises(DomainError, match="duplicate"):
        load_public_config(_write_config(tmp_path, {}, raw=b'{"schema_version":"config-v1","schema_version":"x"}'))


@pytest.mark.parametrize("args", [
    ("bad", False, "PASS", "PASS", "PASS"),
    ("reduced-isolation", 1, "PASS", "PASS", "PASS"),
    ("reduced-isolation", False, "bad", "PASS", "PASS"),
    ("reduced-isolation", False, "PASS", "PASS", "PASS",),
])
def test_execution_isolation_evidence_is_closed(args) -> None:
    values = list(args)
    if args[0] == "reduced-isolation" and args[1] is False and args[2:] == ("PASS", "PASS", "PASS"):
        values[1] = True
    with pytest.raises(DomainError):
        ExecutionIsolationEvidence(*values)


def test_operational_report_guards_and_rendering() -> None:
    with pytest.raises(DomainError):
        OperationalReportV1(" ", "detail", "fix")
    report = OperationalReportV1("X", "detail", "fix")
    assert "reason: X" in render_console(report)
    assert json.loads(report.canonical_json())["exit_code"] == 3


def test_candidate_failure_json_and_verification_isolation_guard(
    verified_engine: VerificationResult,
) -> None:
    isolation = ExecutionIsolationEvidence.reduced_verified()
    report = CandidateArtifactFailureReportV1("BAD", "invalid", isolation)
    assert json.loads(report.canonical_json())["exit_code"] == 1
    with pytest.raises(DomainError, match="typed execution"):
        VerificationReportV1(verified_engine, _verdict(verified_engine), "bad")


def test_version_probe_success_and_failures(tmp_path: Path, monkeypatch) -> None:
    executable = tmp_path / "checkov"; executable.write_text("x")
    monkeypatch.setattr(CLI.subprocess, "run", lambda *a, **k: SimpleNamespace(
        stdout="Checkov 3.3.0\n", stderr="", returncode=0,
    ))
    assert CLI._version(executable) == "3.3.0"
    monkeypatch.setattr(CLI.subprocess, "run", lambda *a, **k: SimpleNamespace(
        stdout="", stderr="", returncode=1,
    ))
    with pytest.raises(DomainError):
        CLI._version(executable)
    monkeypatch.setattr(CLI.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(
        subprocess.TimeoutExpired("checkov", 10)
    ))
    with pytest.raises(DomainError):
        CLI._version(executable)


@pytest.mark.parametrize("version,status", [("3.3.0", "PASS"), ("9.9.9", "UNSUPPORTED")])
def test_doctor_verified_and_unsupported_environments(tmp_path: Path, monkeypatch, version, status) -> None:
    executable = tmp_path / "checkov"; executable.write_bytes(b"launcher")
    monkeypatch.setattr(CLI.shutil, "which", lambda name: str(executable) if name == "checkov" else None)
    monkeypatch.setattr(CLI, "_version", lambda _path: version)
    identity = SimpleNamespace(
        scanner_environment_digest="a" * 64, policy_inventory_digest="b" * 64,
        installed_distribution_digest="c" * 64, dependency_lock_digest="d" * 64,
    )
    monkeypatch.setattr(CLI, "checkov_distribution_identity", lambda *_args: identity)
    assert CLI.doctor().canonical_dict()["checkov"]["status"] == status


@pytest.mark.parametrize("detail,reason", [
    ("unsafe bytecode/cache content", "CHECKOV_ENVIRONMENT_UNSAFE_BYTECODE"),
    ("missing RECORD", "CHECKOV_ENVIRONMENT_UNVERIFIABLE"),
    ("other incomplete state", "CHECKOV_ENVIRONMENT_INCOMPLETE"),
])
def test_doctor_types_environment_failures(tmp_path: Path, monkeypatch, detail, reason) -> None:
    executable = tmp_path / "checkov"; executable.write_bytes(b"launcher")
    monkeypatch.setattr(CLI.shutil, "which", lambda name: str(executable) if name == "checkov" else None)
    monkeypatch.setattr(CLI, "_version", lambda _path: "3.3.0")
    monkeypatch.setattr(CLI, "checkov_distribution_identity", lambda *_args: (_ for _ in ()).throw(DomainError(detail)))
    assert CLI.doctor().canonical_dict()["checkov"]["reason_code"] == reason


def test_cli_doctor_explain_json_and_internal_error(tmp_path: Path, capsys, monkeypatch) -> None:
    doctor_report = CLI.DoctorReportV1(
        {"status": "PASS", "reason_code": "OK"},
        {"status": "PASS", "reason_code": "OK"},
    )
    monkeypatch.setattr(CLI, "doctor", lambda: doctor_report)
    assert CLI.main(["doctor", "--format", "json"]) == 0
    capsys.readouterr()
    demo = OperationalReportV1("X", "detail", "fix").canonical_json()
    path = tmp_path / "report.json"; path.write_text(demo)
    assert CLI.main(["explain", str(path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["result_kind"] == "operational_uncertainty"
    monkeypatch.setattr(CLI, "load_public_config", lambda _path: (_ for _ in ()).throw(RuntimeError("boom")))
    assert CLI.main(["verify", "--config", str(path)]) == 4
    assert "UNEXPECTED_INTERNAL_ERROR" in capsys.readouterr().err


def test_report_reader_rejects_duplicate_nonobject_and_oversize(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text('{"schema_version":"report-v1","schema_version":"x"}')
    with pytest.raises(DomainError, match="duplicate"):
        CLI._read_report(path)
    path.write_text("[]")
    with pytest.raises(DomainError, match="JSON object"):
        CLI._read_report(path)
    path.write_bytes(b" " * (25 * 1024 * 1024 + 1))
    with pytest.raises(DomainError, match="25 MiB"):
        CLI._read_report(path)


def test_api_rejects_wrong_type_and_types_attestation_failures(tmp_path: Path, monkeypatch) -> None:
    with pytest.raises(TypeError):
        verify(object())
    baseline, candidate = _roots(tmp_path)
    request = PublicVerificationRequest(
        baseline, candidate, (PublicTarget("CKV_X", "aws_x.r"),),
        ExecutionIsolation.REDUCED_ISOLATION, _executable(tmp_path), ("terraform",),
    )
    monkeypatch.setattr(API, "_untrusted_scan_request", lambda *args: object())
    monkeypatch.setattr(API, "attest_checkov_scan_plan", lambda _request: (_ for _ in ()).throw(DomainError("baseline bad")))
    assert API.verify(request).reason_code == "TRUSTED_BASELINE_EVIDENCE_UNAVAILABLE"

    calls = iter([SimpleNamespace(request=object()), DomainError("unsupported candidate")])
    def attest(_request):
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value
    monkeypatch.setattr(API, "attest_checkov_scan_plan", attest)
    assert API.verify(request).reason_code == "CANDIDATE_ARTIFACT_INDETERMINATE"
