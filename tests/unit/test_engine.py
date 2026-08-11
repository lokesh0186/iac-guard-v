"""D5 executable target and engine-boundary semantics."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from iac_guard_v.adapters.checkov import (
    CheckovAdapter,
    CheckovScanRequest,
    checkov_distribution_identity,
)
from iac_guard_v.engine import (
    TargetObservation,
    VerificationRequest,
    classify_target,
    require_trusted_verification_result,
    run_checkov_verification,
)
from iac_guard_v.enums import (
    ArtifactKind,
    CheckEvaluationResult,
    Outcome,
    Severity,
    Status,
)
from iac_guard_v.models import (
    CheckEvaluation,
    CoverageCounters,
    ExpectedResource,
    Finding,
    FindingLocation,
    GateResult,
    RequiredGates,
    ResourceCoverage,
    ScannerRun,
    Target,
    TargetIdentity,
    DomainError,
)


IDENTITY = TargetIdentity("checkov", "CKV_X", "aws_x.r")


def observation(**overrides) -> TargetObservation:
    values = dict(
        identity=IDENTITY,
        baseline_occurrences=1,
        candidate_matches=0,
        scanner_integrity=Status.PASS,
        ruleset_integrity=Status.PASS,
        artifact_eligibility=Status.PASS,
        target_file_presence=Status.PASS,
        target_resource_presence=Status.PASS,
        suppression_absence=Status.PASS,
        occurrence_evidence=Status.PASS,
        affirmative_target_pass=Status.PASS,
    )
    values.update(overrides)
    return TargetObservation(**values)


@pytest.mark.parametrize(("changes", "expected"), [
    ({}, Outcome.FIXED),
    ({"candidate_matches": 1}, Outcome.STILL_PRESENT),
    ({"baseline_occurrences": 3, "candidate_matches": 1}, Outcome.PARTIALLY_FIXED),
    ({"suppression_absence": Status.FAIL}, Outcome.SUPPRESSED),
    ({"target_resource_presence": Status.FAIL}, Outcome.RESOURCE_DELETED),
    ({"target_file_presence": Status.FAIL}, Outcome.FILE_DELETED_OR_RENAMED),
    ({"artifact_eligibility": Status.FAIL}, Outcome.OUT_OF_SCOPE),
    ({"ruleset_integrity": Status.FAIL}, Outcome.RULE_OR_SCANNER_DRIFT),
    ({"scanner_integrity": Status.ERROR}, Outcome.SCANNER_ERROR),
    ({"occurrence_evidence": Status.INCONCLUSIVE}, Outcome.INCONCLUSIVE),
])
def test_all_ten_target_outcomes_are_executable(changes, expected) -> None:
    assert classify_target(observation(**changes)) is expected


@pytest.mark.parametrize("state", [
    Status.FAIL, Status.ERROR, Status.TIMEOUT, Status.UNSUPPORTED,
    Status.SKIPPED, Status.PARTIAL, Status.INCONCLUSIVE,
])
def test_absence_without_affirmative_target_pass_is_inconclusive(state: Status) -> None:
    assert classify_target(observation(affirmative_target_pass=state)) is Outcome.INCONCLUSIVE


@pytest.mark.parametrize("changes", [
    {"ruleset_integrity": Status.INCONCLUSIVE},
    {"artifact_eligibility": Status.INCONCLUSIVE},
    {"target_file_presence": Status.INCONCLUSIVE},
    {"target_resource_presence": Status.INCONCLUSIVE},
    {"suppression_absence": Status.INCONCLUSIVE},
])
def test_unknown_structural_predicate_is_inconclusive(changes) -> None:
    assert classify_target(observation(**changes)) is Outcome.INCONCLUSIVE


@pytest.mark.parametrize("changes", [
    {"baseline_occurrences": 0},
    {"candidate_matches": -1},
    {"candidate_matches": True},
    {"scanner_integrity": "PASS"},
])
def test_target_observation_rejects_malformed_evidence(changes) -> None:
    with pytest.raises(DomainError):
        observation(**changes)


def _scan_request(root: Path, executable: Path) -> CheckovScanRequest:
    root.mkdir()
    (root / "main.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    distribution = checkov_distribution_identity(executable, "3.3.0")
    return CheckovScanRequest(
        executable=executable,
        scan_root=root,
        workspace_root=root,
        frameworks=("terraform",),
        files_eligible=("main.tf",),
        expected_version="3.3.0",
        expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        expected_scanner_environment_sha256=distribution.scanner_environment_digest,
        expected_policy_inventory_sha256=distribution.policy_inventory_digest,
        expected_resources=(ExpectedResource(
            "main.tf", "aws_x.r", ArtifactKind.TERRAFORM_HCL, "aws_x.r"
        ),),
    )


def _executable(tmp_path: Path) -> Path:
    trusted = tmp_path / "trusted"
    executable = trusted / "bin" / "checkov"
    interpreter = trusted / "libexec" / "bin" / "python"
    policy = trusted / "libexec/lib/python3.11/site-packages/checkov/checks/rule.py"
    executable.parent.mkdir(parents=True)
    interpreter.parent.mkdir(parents=True)
    policy.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    interpreter.chmod(0o755)
    executable.write_text(f"#!{interpreter}\n", encoding="utf-8")
    executable.chmod(0o755)
    policy.write_text("RULE = 'CKV_X'\n", encoding="utf-8")
    return executable


def _finding() -> Finding:
    return Finding(
        scanner="checkov", scanner_version="3.3.0", rule_id="CKV_X",
        resource_address="aws_x.r", location=FindingLocation("main.tf", 1, 1),
        severity=Severity.HIGH, artifact_kind=ArtifactKind.TERRAFORM_HCL,
    )


def _run(request: CheckovScanRequest, *, baseline: bool) -> ScannerRun:
    findings = (_finding(),) if baseline else ()
    evaluations = () if baseline else (
        CheckEvaluation(
            "checkov", "3.3.0", "CKV_X", "aws_x.r", "main.tf",
            CheckEvaluationResult.PASSED, (), "passed_checks",
        ),
    )
    digest = "a" * 64
    return ScannerRun._from_adapter(
        scanner="checkov", scanner_version="3.3.0", status=Status.PASS,
        findings=findings,
        coverage=CoverageCounters(1, 1, 1, 0, len(evaluations), 0, 0),
        resource_coverage=ResourceCoverage(1, 1, 1, 0, 0, 1),
        exit_code=0, stdout_sha256=digest, stderr_sha256=digest,
        raw_output_sha256=digest, resolved_launcher_path=str(request.executable),
        launcher_digest=request.expected_executable_sha256,
        scanner_environment_digest=request.expected_scanner_environment_sha256,
        policy_inventory_digest=request.expected_policy_inventory_sha256,
        invocation_config_digest=digest, ruleset_integrity=Status.PASS,
        evaluations=evaluations, input_files=request.eligible_file_evidence,
        diagnostics=("COMPLETED",),
    )


def _gate(kind: str, gate_id: str, root: Path) -> GateResult:
    assert kind in {"validator", "oracle"}
    assert root.name == "candidate"
    return GateResult(gate_id, Status.PASS, "AFFIRMATIVE_GATE_EVIDENCE")


def test_engine_invokes_adapter_and_factories_internally(monkeypatch, tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    called = []

    def scan(_self, request):
        called.append(request.scan_root.name)
        return _run(request, baseline=request is baseline)

    monkeypatch.setattr(CheckovAdapter, "scan", scan)
    request = VerificationRequest(
        baseline, candidate, (Target(IDENTITY, 1),),
        RequiredGates(("terraform_hcl_parse",), ("target_oracle",)),
        "b" * 64, "b" * 64,
    )
    result = run_checkov_verification(request, _gate_executor=_gate)
    assert called == ["baseline", "candidate"]
    assert result.target_outcomes[0].outcome is Outcome.FIXED
    assert result.finding_diff.deltas[0].delta_class.value == "RESOLVED_FINDING"
    assert result.validator_results[0].status is Status.PASS
    assert result.oracle_results[0].status is Status.PASS
    assert require_trusted_verification_result(result) is result
    canonical = result.canonical_dict()
    assert canonical["targets"][0]["outcome"] == "FIXED"
    assert canonical["baseline_run"]["scanner"] == "checkov"


def test_missing_gate_executor_is_explicitly_unsupported(monkeypatch, tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    monkeypatch.setattr(
        CheckovAdapter, "scan",
        lambda _self, req: _run(req, baseline=req is baseline),
    )
    request = VerificationRequest(
        baseline, candidate, (Target(IDENTITY, 1),),
        RequiredGates(("validator",), ("oracle",)), "d" * 64, "e" * 64,
    )
    result = run_checkov_verification(request)
    assert result.validator_results[0].status is Status.UNSUPPORTED
    assert result.oracle_results[0].status is Status.UNSUPPORTED
    assert result.policy_drift is True


def test_production_request_has_no_caller_evidence_fields() -> None:
    forbidden = {
        "scanner_run", "baseline_run", "candidate_run", "finding_match",
        "finding_diff", "ambiguity", "delta", "target_evidence", "target_outcome",
    }
    assert forbidden.isdisjoint(VerificationRequest.__dataclass_fields__)


def test_verification_request_mutation_guards(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    gates = RequiredGates(("validator",))
    target = Target(IDENTITY, 1)
    base = (baseline, candidate, (target,), gates, "f" * 64, "f" * 64)
    with pytest.raises(DomainError, match="nonempty"):
        VerificationRequest(baseline, candidate, (), gates, "f" * 64, "f" * 64)
    with pytest.raises(DomainError, match="duplicate"):
        VerificationRequest(baseline, candidate, (target, target), gates, "f" * 64, "f" * 64)
    with pytest.raises(DomainError, match="lowercase SHA"):
        VerificationRequest(*base[:-2], "BAD", "f" * 64)
    with pytest.raises(DomainError, match="bool"):
        VerificationRequest(*base, fail_on_location_change=1)
    with pytest.raises(DomainError, match="Severity"):
        VerificationRequest(*base, severity_floor="HIGH")
    with pytest.raises(DomainError, match="Checkov targets"):
        VerificationRequest(
            baseline, candidate,
            (Target(TargetIdentity("trivy", "AVD_X", "aws_x.r"), 1),),
            gates, "f" * 64, "f" * 64,
        )


def test_gate_substitution_is_rejected(monkeypatch, tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    monkeypatch.setattr(
        CheckovAdapter, "scan",
        lambda _self, req: _run(req, baseline=req is baseline),
    )
    request = VerificationRequest(
        baseline, candidate, (Target(IDENTITY, 1),),
        RequiredGates(("required",)), "c" * 64, "c" * 64,
    )
    with pytest.raises(Exception, match="substituted"):
        run_checkov_verification(
            request,
            _gate_executor=lambda _kind, _id, _root: GateResult("other", Status.PASS),
        )
