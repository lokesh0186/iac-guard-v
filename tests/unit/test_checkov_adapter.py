"""D4 Checkov contract fixtures and trust-boundary mutation probes."""
from __future__ import annotations

import json
import hashlib
import base64
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from iac_guard_v.adapters.base import AdapterReason, ScannerContract
from iac_guard_v.adapters.checkov import (
    CHECKOV_CONTRACT,
    CheckovAdapter,
    CheckovDistributionIdentity,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
    checkov_distribution_identity,
    evaluate_checkov_target,
)
from iac_guard_v.enums import ArtifactKind, Status
from iac_guard_v.models import (
    DomainError,
    ExpectedResource,
    GraphCheckEvidence,
    GraphParticipant,
)
from iac_guard_v.process import CommandResult, ProcessReason


def request(tmp_path: Path, *, frameworks: tuple = ("terraform",), **overrides) -> CheckovScanRequest:
    scan_root = tmp_path / "repo"
    scan_root.mkdir(exist_ok=True)
    eligible = []
    if "terraform" in frameworks:
        (scan_root / "main.tf").write_text("resource \"aws_s3_bucket\" \"bad\" {}\n")
        eligible.append("main.tf")
    identities = []
    if "kubernetes" in frameworks:
        (scan_root / "pod.yaml").write_text("kind: Pod\nmetadata:\n  name: demo\n")
        eligible.append("pod.yaml")
        identities.append(
            CheckovKubernetesIdentity(
                "pod.yaml", "Pod.default.demo", "v1", "Pod", "default", "demo"
            )
        )
    trusted_root = tmp_path / "trusted-checkov"
    executable = trusted_root / "bin" / "checkov"
    interpreter = trusted_root / "libexec" / "bin" / "python"
    policy = (
        trusted_root
        / "libexec/lib/python3.11/site-packages/checkov/terraform/checks/resource/test.py"
    )
    interpreter.parent.mkdir(parents=True, exist_ok=True)
    executable.parent.mkdir(parents=True, exist_ok=True)
    policy.parent.mkdir(parents=True, exist_ok=True)
    interpreter.write_text("#!/bin/sh\nexit 0\n")
    interpreter.chmod(0o755)
    executable.write_text(f"#!{interpreter}\n")
    executable.chmod(0o755)
    policy.write_text("RULES = (\"CKV_AWS_18\",)\n")
    metadata = policy.parents[4] / "checkov-3.3.0.dist-info"
    metadata.mkdir(exist_ok=True)
    payload = policy.read_bytes()
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    relative_policy = policy.relative_to(metadata.parent).as_posix()
    (metadata / "RECORD").write_text(
        f"{relative_policy},sha256={encoded},{len(payload)}\n"
        "checkov-3.3.0.dist-info/RECORD,,\n"
    )
    distribution = checkov_distribution_identity(executable, "3.3.0")
    final_eligible = tuple(overrides.get("files_eligible", tuple(eligible)))
    expected_resources = []
    if "main.tf" in final_eligible:
        expected_resources.append(
            ExpectedResource(
                "main.tf",
                "aws_s3_bucket.bad",
                ArtifactKind.TERRAFORM_HCL,
                "aws_s3_bucket.bad",
            )
        )
    if "pod.yaml" in final_eligible:
        expected_resources.append(
            ExpectedResource(
                "pod.yaml",
                "v1/Pod/default/demo",
                ArtifactKind.KUBERNETES_YAML,
                "Pod.default.demo",
            )
        )
    values = {
        "executable": executable,
        "scan_root": scan_root,
        "workspace_root": scan_root,
        "frameworks": frameworks,
        "files_eligible": final_eligible,
        "expected_version": "3.3.0",
        "expected_executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "expected_scanner_environment_sha256": distribution.scanner_environment_digest,
        "expected_policy_inventory_sha256": distribution.policy_inventory_digest,
        "source_snapshot_sha256": "b" * 64,
        "kubernetes_identities": tuple(identities),
        "expected_resources": tuple(expected_resources),
    }
    values.update(overrides)
    return CheckovScanRequest(**values)


def process(
    *,
    status: Status = Status.PASS,
    exit_code: int | None = 0,
    reason: ProcessReason = ProcessReason.COMPLETED_WITHIN_CONTRACT,
    truncated: bool = False,
    timed_out: bool = False,
    killed_signal: int | None = None,
) -> CommandResult:
    primary = reason
    return CommandResult(
        argv=("/opt/checkov",),
        status=status,
        exit_code=exit_code,
        stdout=b"process stdout",
        stderr=b"",
        duration_ms=1,
        truncated=truncated,
        timed_out=timed_out,
        killed_signal=killed_signal,
        reason_code=reason,
        resolved_executable="/opt/checkov" if status is Status.PASS else "",
        primary_execution_event=primary,
    )


def check(
    *,
    framework: str = "terraform",
    path: str = "main.tf",
    resource: str = "aws_s3_bucket.bad",
    check_id: str = "CKV_AWS_18",
    severity=None,
    evaluated_keys: list | None = None,
) -> dict:
    return {
        "check_id": check_id,
        "check_name": "Ensure secure configuration",
        "severity": severity,
        "resource": resource,
        "file_abs_path": path,
        "file_path": "/" + path,
        "file_line_range": [1, 1],
        "check_result": {
            "result": "FAILED",
            "evaluated_keys": [] if evaluated_keys is None else evaluated_keys,
        },
    }


def document(
    *,
    framework: str = "terraform",
    failed: list | None = None,
    skipped: list | None = None,
    passed: int = 1,
    parsing_errors: int = 0,
    resource_count: int = 1,
    version: str = "3.3.0",
    include_results: bool = True,
) -> dict:
    failed = [] if failed is None else failed
    skipped = [] if skipped is None else skipped
    failed = [dict(item, check_result=dict(item["check_result"], result="FAILED")) for item in failed]
    skipped = [dict(item, check_result=dict(item["check_result"], result="SKIPPED")) for item in skipped]
    default_path = "pod.yaml" if framework == "kubernetes" else "main.tf"
    default_resource = "Pod.default.demo" if framework == "kubernetes" else "aws_s3_bucket.bad"
    passed_checks = []
    for index in range(passed):
        item = check(
            path=default_path,
            resource=default_resource,
            check_id=f"CKV_PASS_{index}",
        )
        item["check_result"]["result"] = "PASSED"
        item["check_result"]["evaluated_keys"] = [f"pass/{index}"]
        passed_checks.append(item)
    value = {
        "check_type": framework,
        "summary": {
            "passed": passed,
            "failed": len(failed),
            "skipped": len(skipped),
            "parsing_errors": parsing_errors,
            "resource_count": resource_count,
            "checkov_version": version,
        },
    }
    if include_results:
        value["results"] = {
            "passed_checks": passed_checks,
            "failed_checks": failed,
            "skipped_checks": skipped,
        }
    return value


def normalize(req: CheckovScanRequest, payload, proc: CommandResult | None = None):
    raw = payload if type(payload) is bytes else json.dumps(payload).encode()
    return CheckovAdapter().normalize(raw, req, proc or process(), "3.3.0")


def test_contract_is_closed_and_checkov_only() -> None:
    assert CHECKOV_CONTRACT.canonical_dict() == {
        "name": "checkov",
        "supported_versions": ["3.2.517", "3.3.0"],
        "frameworks": ["kubernetes", "terraform"],
        "expected_exit_codes": [0, 1],
    }
    assert "trivy" not in repr(CHECKOV_CONTRACT).lower()
    assert CheckovAdapter().contract() is CHECKOV_CONTRACT


def test_adapter_evidence_is_frozen_slotted_and_caller_independent(tmp_path: Path) -> None:
    req = request(tmp_path)
    identity = CheckovKubernetesIdentity(
        "pod.yaml", "Pod.default.demo", "v1", "Pod", "default", "demo"
    )
    for value in (CHECKOV_CONTRACT, req, identity):
        assert not hasattr(value, "__dict__")
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            value.name = "mutated"


def test_research_32517_contract_fixture_is_normalized(tmp_path: Path) -> None:
    req = request(tmp_path, expected_version="3.2.517")
    raw = json.dumps(document(version="3.2.517", failed=[check()])).encode()
    run = CheckovAdapter().normalize(raw, req, process(exit_code=1), "3.2.517")
    assert run.status is Status.PASS
    assert run.scanner_version == "3.2.517"
    assert run.findings[0].rule_id == "CKV_AWS_18"


def test_normal_object_with_findings_is_normalized_and_fingerprinted(tmp_path: Path) -> None:
    req = request(tmp_path)
    run = normalize(req, document(failed=[check()], passed=2))
    assert run.status is Status.PASS
    assert run.diagnostics == (AdapterReason.COMPLETED.value,)
    assert len(run.findings) == 1
    finding = run.findings[0]
    assert finding.resource_address == "aws_s3_bucket.bad"
    assert finding.location.file_path == "main.tf"
    assert finding.iacgv_fingerprint.startswith("iacgv2:")
    assert run.coverage.evaluations_reported == 3
    assert run.exit_code == 0
    assert run.stdout_sha256 == process().stdout_sha256
    assert run.raw_output_sha256 != run.stdout_sha256
    assert run.launcher_digest == req.expected_executable_sha256


def test_valid_zero_findings_with_affirmative_results_is_pass(tmp_path: Path) -> None:
    run = normalize(request(tmp_path), document(passed=4))
    assert run.status is Status.PASS
    assert run.findings == ()
    assert run.coverage.files_parsed == 1


def test_summary_only_is_error_when_independent_detector_found_eligible_file(tmp_path: Path) -> None:
    run = normalize(request(tmp_path), document(include_results=False))
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.NO_RESULTS_STRUCTURE.value,)
    assert run.coverage.files_discovered == 0


def test_summary_only_is_non_error_only_for_an_independently_empty_scope(tmp_path: Path) -> None:
    template = request(tmp_path)
    scan_root = template.scan_root
    (scan_root / "main.tf").unlink()
    req = CheckovScanRequest(
        executable=template.executable,
        scan_root=scan_root,
        workspace_root=scan_root,
        frameworks=("terraform",),
        files_eligible=(),
        expected_version="3.3.0",
        expected_executable_sha256=template.expected_executable_sha256,
        expected_scanner_environment_sha256=template.expected_scanner_environment_sha256,
        expected_policy_inventory_sha256=template.expected_policy_inventory_sha256,
    )
    run = normalize(req, document(include_results=False, resource_count=0, passed=0))
    assert run.status is Status.SKIPPED
    assert run.diagnostics == (AdapterReason.EMPTY_ELIGIBLE_SCOPE.value,)


def test_multiple_framework_documents_are_all_parsed(tmp_path: Path) -> None:
    req = request(tmp_path, frameworks=("terraform", "kubernetes"))
    payload = [
        document(failed=[check()]),
        document(
            framework="kubernetes",
            failed=[
                check(
                    framework="kubernetes",
                    path="pod.yaml",
                    resource="Pod.default.demo",
                    check_id="CKV_K8S_20",
                )
            ],
        ),
    ]
    run = normalize(req, payload)
    assert run.status is Status.PASS
    assert {item.artifact_kind.value for item in run.findings} == {
        "terraform_hcl",
        "kubernetes_yaml",
    }
    assert any(item.resource_address == "v1/Pod/default/demo" for item in run.findings)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"", AdapterReason.EMPTY_OUTPUT),
        (b"not json", AdapterReason.MALFORMED_JSON),
        (b'{"summary":', AdapterReason.MALFORMED_JSON),
        (b"[]", AdapterReason.UNEXPECTED_TOP_LEVEL),
        (b'"wrong"', AdapterReason.UNEXPECTED_TOP_LEVEL),
        (b'{"summary":{}}suffix', AdapterReason.MALFORMED_JSON),
    ],
)
def test_empty_malformed_truncated_and_wrong_top_level_fail_closed(
    tmp_path: Path, raw: bytes, reason: AdapterReason
) -> None:
    run = normalize(request(tmp_path), raw)
    assert run.status is Status.ERROR
    assert run.diagnostics == (reason.value,)
    if raw:
        assert run.raw_output_sha256 == hashlib.sha256(raw).hexdigest()


def test_nonzero_exit_one_with_valid_findings_is_inside_contract(tmp_path: Path) -> None:
    run = normalize(
        request(tmp_path),
        document(failed=[check()]),
        process(exit_code=1),
    )
    assert run.status is Status.PASS
    assert run.exit_code == 1


@pytest.mark.parametrize(
    "proc",
    [
        process(
            status=Status.ERROR,
            exit_code=2,
            reason=ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT,
        ),
        process(
            status=Status.TIMEOUT,
            exit_code=-15,
            reason=ProcessReason.DEADLINE_EXCEEDED,
            timed_out=True,
            killed_signal=15,
        ),
        process(
            status=Status.ERROR,
            exit_code=-9,
            reason=ProcessReason.KILLED_BY_SIGNAL,
            killed_signal=9,
        ),
        process(
            status=Status.PARTIAL,
            exit_code=-15,
            reason=ProcessReason.OUTPUT_LIMIT_EXCEEDED,
            truncated=True,
            killed_signal=15,
        ),
    ],
)
def test_process_failure_shapes_never_parse_into_pass(
    tmp_path: Path, proc: CommandResult
) -> None:
    run = normalize(request(tmp_path), document(), proc)
    assert run.status is not Status.PASS


def test_partial_scan_indicators_are_typed_partial(tmp_path: Path) -> None:
    run = normalize(request(tmp_path), document(parsing_errors=1))
    assert run.status is Status.PARTIAL
    assert run.diagnostics == (AdapterReason.PARTIAL_SCAN.value,)
    assert run.coverage.parse_errors == 1
    assert run.coverage.files_failed == 1


def test_zero_resource_summary_with_eligible_input_fails_closed(tmp_path: Path) -> None:
    run = normalize(request(tmp_path), document(resource_count=0, passed=0))
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.ZERO_FILES_DISCOVERED.value,)


@pytest.mark.parametrize("version", ["3.2.516", "3.3.1", "latest"])
def test_version_outside_closed_contract_is_error(tmp_path: Path, version: str) -> None:
    run = normalize(request(tmp_path), document(version=version))
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.UNSUPPORTED_VERSION.value,)


def test_summary_version_must_match_probe_and_trusted_expectation(tmp_path: Path) -> None:
    run = CheckovAdapter().normalize(
        json.dumps(document(version="3.2.517")).encode(),
        request(tmp_path),
        process(),
        "3.2.517",
    )
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.VERSION_MISMATCH.value,)


def test_evaluation_count_is_not_a_check_inventory_lock(tmp_path: Path) -> None:
    req = request(tmp_path)
    one = normalize(req, document(passed=1))
    two = normalize(req, document(passed=2))
    assert one.policy_inventory_digest == two.policy_inventory_digest
    assert one.coverage.evaluations_reported == 1
    assert two.coverage.evaluations_reported == 2


def test_skipped_checks_become_suppression_evidence(tmp_path: Path) -> None:
    run = normalize(request(tmp_path), document(skipped=[check()], passed=0))
    assert run.status is Status.PASS
    assert len(run.findings) == 1
    assert run.findings[0].suppressed is True
    assert run.coverage.evaluations_reported == 1


def test_repeated_native_occurrences_are_preserved_by_evaluated_key_evidence(
    tmp_path: Path,
) -> None:
    first = check(evaluated_keys=["ingress/[0]/cidr_blocks/[0]"])
    second = check(evaluated_keys=["ingress/[1]/cidr_blocks/[0]"])
    run = normalize(request(tmp_path), document(failed=[first, second], passed=0))
    assert run.status is Status.PASS
    assert len(run.findings) == 2
    assert [item.occurrence_index for item in run.findings] == [0, 1]
    assert len({item.native_fingerprint for item in run.findings}) == 2


def test_kubernetes_result_requires_independent_canonical_identity(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="independent identity mapping"):
        request(tmp_path, frameworks=("kubernetes",), kubernetes_identities=())


def test_finding_path_outside_eligible_set_is_not_accepted(tmp_path: Path) -> None:
    req = request(tmp_path)
    (req.scan_root / "other.tf").write_text("resource \"aws_s3_bucket\" \"x\" {}")
    run = normalize(req, document(failed=[check(path="other.tf")]))
    assert run.status is Status.ERROR
    assert run.findings == ()


def test_request_rejects_candidate_executable_and_untrusted_framework(tmp_path: Path) -> None:
    template = request(tmp_path)
    fake = template.scan_root / "checkov"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    with pytest.raises(DomainError, match="must not resolve inside"):
        request(
            tmp_path,
            executable=fake,
            expected_executable_sha256=hashlib.sha256(fake.read_bytes()).hexdigest(),
        )
    with pytest.raises(DomainError, match="unsupported Checkov frameworks"):
        request(tmp_path, frameworks=("trivy",))
    with pytest.raises(DomainError, match="digest does not match"):
        request(tmp_path, expected_executable_sha256="0" * 64)


def test_request_has_no_candidate_config_or_custom_check_input() -> None:
    names = set(CheckovScanRequest.__dataclass_fields__)
    assert not names & {
        "config_file",
        "external_checks_dir",
        "external_checks_git",
        "custom_checks",
        "download_external_modules",
    }


def test_scan_builds_locked_offline_argument_array_from_private_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    calls = []

    def fake_run(command):
        calls.append(command)
        if command.argv[1:] == ("--version",):
            return CommandResult(
                argv=command.argv,
                status=Status.PASS,
                exit_code=0,
                stdout=b"3.3.0\n",
                stderr=b"",
                duration_ms=1,
                truncated=False,
                timed_out=False,
                killed_signal=None,
                reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
                resolved_executable=str(req.executable),
            )
        output_dir = Path(command.argv[command.argv.index("--output-file-path") + 1])
        (output_dir / "results_json.json").write_text(json.dumps(document()))
        return CommandResult(
            argv=command.argv,
            status=Status.PASS,
            exit_code=0,
            stdout=b"",
            stderr=b"",
            duration_ms=2,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
            resolved_executable=str(req.executable),
        )

    monkeypatch.setattr("iac_guard_v.adapters.checkov.run_command", fake_run)
    run = CheckovAdapter().scan(req)
    assert run.status is Status.PASS
    scan_request = calls[1]
    assert scan_request.cwd is None
    assert scan_request.argv[0] == str(req.executable)
    for required in (
        "--skip-download",
        "--download-external-modules",
        "false",
        "--skip-results-upload",
        "--output-file-path",
        "--config-file",
    ):
        assert required in scan_request.argv
    assert not set(scan_request.argv) & {
        "--external-checks-dir",
        "--external-checks-git",
        "--run-all-external-checks",
    }


def test_raw_output_cleanup_failure_is_stronger_than_scan_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)

    def fake_run(command):
        stdout = b"3.3.0\n" if command.argv[1:] == ("--version",) else b""
        if "--output-file-path" in command.argv:
            output_dir = Path(command.argv[command.argv.index("--output-file-path") + 1])
            (output_dir / "results_json.json").write_text(json.dumps(document()))
        return CommandResult(
            argv=command.argv,
            status=Status.PASS,
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            duration_ms=1,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
            resolved_executable=str(req.executable),
        )

    monkeypatch.setattr("iac_guard_v.adapters.checkov.run_command", fake_run)
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.shutil.rmtree",
        lambda _path: (_ for _ in ()).throw(OSError("private/output/path")),
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.OUTPUT_CLEANUP_FAILED.value,)
    assert "private/output/path" not in repr(run.canonical_dict())


def test_cleanup_failure_is_stronger_than_a_process_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    calls = 0

    def fake_run(command):
        nonlocal calls
        calls += 1
        if calls == 1:
            return CommandResult(
                argv=command.argv,
                status=Status.PASS,
                exit_code=0,
                stdout=b"3.3.0\n",
                stderr=b"",
                duration_ms=1,
                truncated=False,
                timed_out=False,
                killed_signal=None,
                reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
                resolved_executable=str(req.executable),
            )
        return CommandResult(
            argv=command.argv,
            status=Status.ERROR,
            exit_code=2,
            stdout=b"",
            stderr=b"",
            duration_ms=1,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code=ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT,
        )

    monkeypatch.setattr("iac_guard_v.adapters.checkov.run_command", fake_run)
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.shutil.rmtree",
        lambda _path: (_ for _ in ()).throw(OSError("private/output/path")),
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.OUTPUT_CLEANUP_FAILED.value,)


def test_public_normalize_enforces_raw_output_cap(tmp_path: Path) -> None:
    req = request(tmp_path, max_output_bytes=8)
    run = CheckovAdapter().normalize(b"{" + b"x" * 8, req, process(), "3.3.0")
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.TRUNCATED_OUTPUT.value,)


def test_scan_root_symlink_replacement_is_rejected_before_any_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    original = tmp_path / "original"
    req.scan_root.rename(original)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    req.scan_root.symlink_to(outside, target_is_directory=True)
    calls = []
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.run_command", lambda command: calls.append(command)
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value,)
    assert calls == []


def test_eligible_file_replacement_is_rejected_before_any_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    target = req.scan_root / "main.tf"
    target.unlink()
    outside = tmp_path / "outside.tf"
    outside.write_text("resource \"aws_s3_bucket\" \"outside\" {}")
    target.symlink_to(outside)
    calls = []
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.run_command", lambda command: calls.append(command)
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value,)
    assert calls == []


def test_contradictory_absolute_native_path_is_not_fallback_accepted(tmp_path: Path) -> None:
    payload = document(failed=[check()])
    payload["results"]["failed_checks"][0]["file_abs_path"] = "/etc/passwd"
    run = normalize(request(tmp_path), payload)
    assert run.status is Status.ERROR
    assert run.findings == ()


def test_contract_inputs_reject_subclass_and_boolean_integer_mutations(tmp_path: Path) -> None:
    class SneakyTuple(tuple):
        pass

    with pytest.raises(DomainError, match="exact tuple"):
        request(tmp_path, files_eligible=SneakyTuple(("main.tf",)))
    with pytest.raises(DomainError, match="environment digest"):
        request(tmp_path, expected_scanner_environment_sha256="0" * 64)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ScannerContract("checkov", [], ("terraform",), (0,)),
        lambda: ScannerContract("checkov", (), ("terraform",), (0,)),
        lambda: ScannerContract("checkov", ("3.3.0", "3.3.0"), ("terraform",), (0,)),
    ],
)
def test_scanner_contract_rejects_mutable_empty_and_duplicate_evidence(factory) -> None:
    with pytest.raises(DomainError):
        factory()


def test_request_validation_mutations(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="pathlib.Path"):
        request(tmp_path, executable="/bin/sh")
    with pytest.raises(DomainError, match="nonempty exact tuple"):
        request(tmp_path, frameworks=[])
    with pytest.raises(DomainError, match="duplicates"):
        request(tmp_path, frameworks=("terraform", "terraform"))
    with pytest.raises(DomainError, match="duplicates"):
        request(tmp_path, files_eligible=("main.tf", "main.tf"))
    with pytest.raises(DomainError, match="outside the supported"):
        request(tmp_path, expected_version="3.3.1")
    with pytest.raises(DomainError, match="exact tuple"):
        request(tmp_path, kubernetes_identities=[])
    with pytest.raises(DomainError, match="must be > 0"):
        request(tmp_path, timeout_seconds=0)
    with pytest.raises(DomainError, match="must be > 0"):
        request(tmp_path, max_output_bytes=0)


def test_kubernetes_identity_map_validation_mutations(tmp_path: Path) -> None:
    identity = CheckovKubernetesIdentity(
        "pod.yaml", "Pod.default.demo", "v1", "Pod", "default", "demo"
    )
    with pytest.raises(DomainError, match="exact typed"):
        request(tmp_path, frameworks=("kubernetes",), kubernetes_identities=(object(),))
    with pytest.raises(DomainError, match="duplicate keys"):
        request(
            tmp_path,
            frameworks=("kubernetes",),
            kubernetes_identities=(identity, identity),
        )
    foreign = CheckovKubernetesIdentity(
        "other.yaml", "Pod.default.demo", "v1", "Pod", "default", "demo"
    )
    with pytest.raises(DomainError, match="eligible file"):
        request(tmp_path, frameworks=("kubernetes",), kubernetes_identities=(foreign,))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("summary"),
        lambda value: value["summary"].__setitem__("checkov_version", 330),
        lambda value: value.__setitem__("results", []),
        lambda value: value.__setitem__("check_type", "kubernetes"),
        lambda value: value["results"].__setitem__("failed_checks", {}),
        lambda value: value["summary"].__setitem__("failed", 1),
        lambda value: value["summary"].__setitem__("skipped", 1),
        lambda value: value["summary"].__setitem__("passed", True),
    ],
)
def test_malformed_document_fields_never_escape_as_pass(
    tmp_path: Path, mutate
) -> None:
    payload = document()
    mutate(payload)
    run = normalize(request(tmp_path), payload)
    assert run.status is Status.ERROR
    assert run.findings == ()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.__setitem__("file_abs_path", ""),
        lambda value: value.__setitem__("file_line_range", [1]),
        lambda value: value.__setitem__("file_line_range", [0, 1]),
        lambda value: value.__setitem__("severity", 4),
        lambda value: value.__setitem__("severity", "EXTREME"),
    ],
)
def test_malformed_finding_fields_never_escape_as_pass(tmp_path: Path, mutate) -> None:
    item = check()
    mutate(item)
    if item.get("file_abs_path") == "":
        item["file_path"] = ""
    run = normalize(request(tmp_path), document(failed=[item]))
    assert run.status is Status.ERROR
    assert run.findings == ()


def test_duplicate_framework_document_is_rejected(tmp_path: Path) -> None:
    run = normalize(request(tmp_path), [document(), document()])
    assert run.status is Status.ERROR


def test_normalize_rejects_nonexact_boundary_values(tmp_path: Path) -> None:
    req = request(tmp_path)
    with pytest.raises(DomainError, match="exact CheckovScanRequest"):
        CheckovAdapter().normalize(b"{}", object(), process(), "3.3.0")
    with pytest.raises(DomainError, match="exact CommandResult"):
        CheckovAdapter().normalize(b"{}", req, object(), "3.3.0")
    run = CheckovAdapter().normalize("{}", req, process(), "3.3.0")
    assert run.status is Status.ERROR


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (b"", AdapterReason.VERSION_PROBE_FAILED),
        (b"3.3.1\n", AdapterReason.UNSUPPORTED_VERSION),
        (b"3.2.517\n", AdapterReason.VERSION_MISMATCH),
        (b"\xff", AdapterReason.VERSION_PROBE_FAILED),
    ],
)
def test_probe_version_failures_are_typed_before_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    expected: AdapterReason,
) -> None:
    req = request(tmp_path)

    def fake_run(command):
        return CommandResult(
            argv=command.argv,
            status=Status.PASS,
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            duration_ms=1,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
            resolved_executable=str(req.executable),
        )

    monkeypatch.setattr("iac_guard_v.adapters.checkov.run_command", fake_run)
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == (expected.value,)


def test_raw_output_reader_rejects_symlink_oversize_and_missing(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(DomainError, match="nonsymlink"):
        CheckovAdapter._read_raw_output(link, 10)
    with pytest.raises(DomainError, match="TRUNCATED_OUTPUT"):
        CheckovAdapter._read_raw_output(target, 1)
    with pytest.raises(DomainError, match="RAW_OUTPUT_MISSING"):
        CheckovAdapter._read_raw_output(tmp_path / "missing.json", 10)


def test_ckv2_without_bound_policy_class_or_query_cannot_authorize_target(
    tmp_path: Path,
) -> None:
    req = request(tmp_path)
    item = check(check_id="CKV2_AWS_6")

    run = normalize(req, document(failed=[item], passed=0), process(exit_code=1))

    assert run.status is Status.PASS
    assert len(run.evaluations) == 1
    evidence = run.evaluations[0].graph_evidence
    assert evidence is not None
    assert evidence.status is Status.INCONCLUSIVE
    assert evidence.reason_code == "GRAPH_POLICY_OR_CLASS_UNSUPPORTED"
    target = evaluate_checkov_target(
        run, "CKV2_AWS_6", "aws_s3_bucket.bad", "main.tf"
    )
    assert target.status is Status.INCONCLUSIVE


def test_graph_scan_may_bind_exact_terraform_summary_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    resources = (
        ExpectedResource(
            "main.tf", "aws_s3_bucket.bad", ArtifactKind.TERRAFORM_HCL,
            "aws_s3_bucket.bad",
        ),
        ExpectedResource(
            "main.tf", "aws_s3_bucket.not_evaluated", ArtifactKind.TERRAFORM_HCL,
            "aws_s3_bucket.not_evaluated",
        ),
    )
    req = request(tmp_path, expected_resources=resources)
    participant = GraphParticipant(
        "main.tf", "aws_s3_bucket.bad", ArtifactKind.TERRAFORM_HCL,
        "aws_s3_bucket",
    )

    class Context:
        auxiliary_identities = ()

        @staticmethod
        def evidence_for(**_kwargs):
            return GraphCheckEvidence(
                Status.PASS, "GRAPH_EVIDENCE_COMPLETE", participant,
                (participant,), (), "1" * 64, "b" * 64, "2" * 64,
                "3" * 64, "4" * 64,
            )

    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.build_graph_evidence_context",
        lambda **_kwargs: Context(),
    )
    item = check(check_id="CKV2_AWS_6")
    item["check_class"] = "checkov.common.graph.checks_infra.base_check"
    item["check_result"]["result"] = "PASSED"
    payload = document(passed=0, resource_count=2)
    payload["summary"]["passed"] = 1
    payload["results"]["passed_checks"] = [item]

    run = normalize(req, payload)

    assert run.status is Status.PASS
    assert run.resource_coverage.inventory_completion_basis == (
        "terraform_summary_exact",
    )
    assert run.resource_coverage.expected_resources_missing == 0


def test_kubernetes_graph_primary_alias_is_bound_in_summary_coverage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resource = ExpectedResource(
        "pod.yaml",
        "apps/v1/Deployment/default/demo",
        ArtifactKind.KUBERNETES_YAML,
        "Deployment.default.demo",
    )
    identity = CheckovKubernetesIdentity(
        "pod.yaml", "Deployment.default.demo", "apps/v1", "Deployment",
        "default", "demo",
    )
    req = request(
        tmp_path,
        frameworks=("kubernetes",),
        expected_resources=(resource,),
        kubernetes_identities=(identity,),
    )
    participant = GraphParticipant(
        "pod.yaml", resource.resource_address, ArtifactKind.KUBERNETES_YAML,
        "Deployment",
    )

    class Context:
        auxiliary_identities = ()

        @staticmethod
        def evidence_for(**_kwargs):
            return GraphCheckEvidence(
                Status.PASS, "GRAPH_EVIDENCE_COMPLETE", participant,
                (participant,), (), "1" * 64, "b" * 64, "2" * 64,
                "3" * 64, "4" * 64,
            )

    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.build_graph_evidence_context",
        lambda **_kwargs: Context(),
    )
    item = check(
        framework="kubernetes",
        path="pod.yaml",
        resource="Pod.default.demo.app-demo",
        check_id="CKV2_K8S_6",
    )
    item["check_class"] = "checkov.common.graph.checks_infra.base_check"
    item["check_result"]["result"] = "FAILED"
    payload = document(framework="kubernetes", passed=0, resource_count=2)
    payload["summary"]["failed"] = 1
    payload["results"]["failed_checks"] = [item]

    run = normalize(req, payload)

    assert run.status is Status.PASS
    assert run.resource_coverage.inventory_completion_basis == (
        "kubernetes_graph_primary_aliases",
    )
    assert run.resource_coverage.summary_resources_reported == 2
    assert run.resource_coverage.resources_observed == 1
