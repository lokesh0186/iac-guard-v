"""E6.1 deterministic, validated report-v1 projections."""
from __future__ import annotations

import copy
import json
from xml.etree import ElementTree as ET

import pytest

from iac_guard_v.engine import VerificationResult
from iac_guard_v.engine import VerificationRequest, run_checkov_verification
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import DomainError, RequiredGates, Target
from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.report import (
    CandidateArtifactFailureReportV1, ExecutionIsolationEvidence,
    OperationalReportV1, VerificationReportV1,
)
from iac_guard_v.reporters import render_junit, render_markdown, render_sarif
from iac_guard_v.reporters import _shared as REPORTER_SHARED
from iac_guard_v.reporters import sarif as SARIF

from test_policy import _verdict, verified_engine  # noqa: F401
from test_public_d74 import _publicize
from test_engine import IDENTITY, _config, _executable, _run, _scan_request


def _report(engine: VerificationResult) -> dict:
    return _publicize(
        VerificationReportV1(engine, _verdict(engine)).canonical_dict()
    )


def _artifact_failure() -> dict:
    return CandidateArtifactFailureReportV1(
        ArtifactKind.TERRAFORM_HCL,
        "terraform_hcl_parse",
        "ARTIFACT_SYNTAX_INVALID",
        "candidate syntax is invalid",
        ExecutionIsolationEvidence.reduced_verified(),
    ).canonical_dict()


def _still_present_report(monkeypatch, tmp_path) -> dict:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    monkeypatch.setattr(
        CheckovAdapter, "scan", lambda _self, request: _run(request, baseline=True),
    )
    gates = RequiredGates(("validator",), ("oracle",))
    engine = run_checkov_verification(VerificationRequest(
        baseline, candidate, (Target(IDENTITY, 1),),
        _config(baseline, candidate, gates),
    ))
    return _report(engine)


def _xml(value: str) -> ET.Element:
    return ET.fromstring(value.removeprefix('<?xml version="1.0" encoding="UTF-8"?>\n'))


@pytest.mark.parametrize("renderer", (render_sarif, render_markdown, render_junit))
def test_reporters_are_byte_deterministic_and_do_not_retain_input(
    verified_engine: VerificationResult, renderer,
) -> None:
    payload = _report(verified_engine)
    expected = renderer(payload)
    assert renderer(copy.deepcopy(payload)) == expected
    payload["verdict"] = "FAILED"
    assert expected != ""


@pytest.mark.parametrize("renderer", (render_sarif, render_markdown, render_junit))
def test_every_reporter_invokes_public_graph_validation(
    verified_engine: VerificationResult, renderer,
) -> None:
    payload = _report(verified_engine)
    payload["verification"]["scanner_integrity"]["status"] = "FAIL"
    with pytest.raises(DomainError, match="semantic violation"):
        renderer(payload)


@pytest.mark.parametrize("renderer", (render_sarif, render_markdown, render_junit))
def test_private_test_registry_is_not_a_reporter_input(
    verified_engine: VerificationResult, renderer,
) -> None:
    private = VerificationReportV1(
        verified_engine, _verdict(verified_engine)
    ).canonical_dict()
    with pytest.raises(DomainError, match="private test gate registry"):
        renderer(private)


@pytest.mark.parametrize("value", (None, [], "report"))
@pytest.mark.parametrize("renderer", (render_sarif, render_markdown, render_junit))
def test_reporters_require_exact_dictionary(value, renderer) -> None:
    with pytest.raises(DomainError, match="exact report-v1 dictionary"):
        renderer(value)


def test_sarif_preserves_target_policy_delta_gate_and_isolation_evidence(
    verified_engine: VerificationResult,
) -> None:
    payload = _report(verified_engine)
    sarif = json.loads(render_sarif(payload))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "IaC-Guard-V"
    assert run["invocations"][0]["exitCode"] == 0
    assert run["invocations"][0]["properties"]["finalVerdict"] == "VERIFIED"
    assert run["invocations"][0]["properties"]["executionIsolation"]["mode"] == (
        "reduced-isolation"
    )
    assert {item["gateId"] for item in run["invocations"][0]["properties"]["gates"]} >= {
        "preflight", "scanner_integrity", "validator", "oracle", "regression",
        "suppression",
    }
    result = run["results"][0]
    target = payload["verification"]["targets"][0]
    assert result["properties"]["targetIdentity"] == target["identity"]["opaque_id"]
    assert result["properties"]["targetOutcome"] == "FIXED"
    assert result["properties"]["policyPermitted"] is False
    assert result["properties"]["engineEvents"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        target["binding"]["file_path"]
    )


def test_markdown_explains_full_evidence_without_new_policy(
    verified_engine: VerificationResult,
) -> None:
    output = render_markdown(_report(verified_engine))
    for heading in (
        "## Evaluation scope", "## Targets and policy",
        "## Scanner and gate evidence",
        "## Regression, destructive, drift, and suppression evidence",
        "## Policy exceptions", "## Remediation",
    ):
        assert heading in output
    assert "FIXED" in output
    assert "No remediation is recorded in report-v1." in output


def test_inconclusive_verification_remains_nonpassing_in_all_formats(
    verified_engine: VerificationResult,
) -> None:
    report = _report(verified_engine)
    report["verdict"] = report["policy"]["verdict"] = "INCONCLUSIVE"
    report["exit_code"] = report["policy"]["exit_code"] = 3
    report["verification"]["scanner_integrity"]["status"] = "ERROR"
    sarif = json.loads(render_sarif(report))
    assert sarif["runs"][0]["results"][0]["kind"] == "review"
    assert "INCONCLUSIVE" in render_markdown(report)
    junit = _xml(render_junit(report))
    final = junit.find("./testcase[@name='final-verdict']")
    assert final is not None and final.find("skipped") is not None
    assert int(junit.attrib["skipped"]) > 0


def test_artifact_failure_is_a_failed_result_in_every_projection() -> None:
    report = _artifact_failure()
    sarif = json.loads(render_sarif(report))["runs"][0]["results"][0]
    assert sarif["kind"] == "fail"
    assert sarif["properties"]["artifactKind"] == "terraform_hcl"
    assert "Candidate artifact failure" in render_markdown(report)
    assert _xml(render_junit(report)).find("./testcase/failure") is not None


def test_junit_failed_target_is_a_failure_not_a_success(monkeypatch, tmp_path) -> None:
    report = _still_present_report(monkeypatch, tmp_path)
    assert report["verdict"] == "FAILED"
    junit = _xml(render_junit(report))
    target = junit.findall("./testcase")[1]
    failure = target.find("failure")
    assert failure is not None
    assert failure.attrib["message"] == "STILL_PRESENT"
    assert int(junit.attrib["failures"]) == 2


def test_operational_uncertainty_is_junit_error_and_is_redacted() -> None:
    secret = "ghp_" + "A" * 40
    report = OperationalReportV1(
        "CONTAINER_UNAVAILABLE",
        f"runtime failed at /Users/alice/private/cache token={secret}",
        f"remove token={secret} from /private/tmp/iacgv-cache",
    ).canonical_dict()
    outputs = (render_sarif(report), render_markdown(report), render_junit(report))
    for output in outputs:
        assert secret not in output
        assert "/Users/alice" not in output
        assert "/private/tmp" not in output
        assert "[REDACTED]" in output
        assert "[PATH]" in output
    junit = _xml(outputs[2])
    assert junit.attrib["errors"] == "1"
    assert junit.attrib["skipped"] == "0"
    assert junit.find("./testcase/error") is not None


def test_junit_verified_result_is_success_and_counters_are_exact(
    verified_engine: VerificationResult,
) -> None:
    junit = _xml(render_junit(_report(verified_engine)))
    assert junit.attrib == {
        "name": "IaC-Guard-V report-v1",
        "tests": "2", "failures": "0", "errors": "0", "skipped": "0",
    }
    assert junit.find("./testcase[@name='final-verdict']/*") is None


def test_structured_digest_identities_are_preserved(
    verified_engine: VerificationResult,
) -> None:
    report = _report(verified_engine)
    baseline_sha = report["verification"]["baseline_snapshot"]["snapshot_sha256"]
    assert baseline_sha in render_markdown(report)
    sarif = json.loads(render_sarif(report))
    automation_id = sarif["runs"][0]["automationDetails"]["id"]
    assert len(automation_id.removeprefix("iac-guard-v/")) == 64
    junit = _xml(render_junit(report))
    report_hash = next(
        item.attrib["value"]
        for item in junit.findall("./properties/property")
        if item.attrib["name"] == "report.sha256"
    )
    assert len(report_hash) == 64 and report_hash != "[REDACTED]"


def test_output_free_text_escapes_markdown_and_xml() -> None:
    report = OperationalReportV1(
        "RUNTIME_ERROR", "bad | detail <xml>", "retry | safely <now>",
    ).canonical_dict()
    assert "bad \\| detail <xml>" in render_markdown(report)
    junit = render_junit(report)
    assert "&lt;xml&gt;" in junit
    ET.fromstring(junit.removeprefix('<?xml version="1.0" encoding="UTF-8"?>\n'))


def test_shared_projection_helpers_fail_closed_and_do_not_invent_evidence(
    verified_engine: VerificationResult,
) -> None:
    with pytest.raises(DomainError, match="canonical JSON"):
        REPORTER_SHARED.validated_snapshot({"not_json": object()})
    report = _report(verified_engine)
    target = report["verification"]["targets"][0]
    no_finding = copy.deepcopy(report)
    no_finding["verification"]["baseline_run"]["findings"] = []
    no_finding["verification"]["candidate_run"]["findings"] = []
    assert REPORTER_SHARED.target_location(no_finding, target) == (0, 0)
    missing_decision = copy.deepcopy(report)
    missing_decision["policy"]["decisions"] = []
    with pytest.raises(DomainError, match="lacks its policy decision"):
        REPORTER_SHARED.decision_for(missing_decision, target)
    artifact = _artifact_failure()
    assert REPORTER_SHARED.target_delta_classes(artifact, {}) == []
    assert REPORTER_SHARED.engine_events(artifact) == []
    assert REPORTER_SHARED.remediation_for(artifact) == ""
    assert REPORTER_SHARED.safe_text(3) == "3"


def test_sarif_closed_level_and_kind_projection_branches() -> None:
    exception_target = {"outcome": "SUPPRESSED"}
    verified = {"result_kind": "verification", "verdict": "VERIFIED"}
    assert SARIF._level(verified, exception_target) == "warning"
    assert SARIF._kind(verified, exception_target) == "review"
