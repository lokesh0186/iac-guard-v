"""D4 Checkov contract fixtures and trust-boundary mutation probes."""
from __future__ import annotations

import json
import hashlib
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from iac_guard_v.adapters.base import AdapterReason, ScannerContract
from iac_guard_v.adapters.checkov import (
    CHECKOV_CONTRACT,
    CheckovAdapter,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
)
from iac_guard_v.enums import Status
from iac_guard_v.models import DomainError
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
    values = {
        "executable": Path("/bin/sh"),
        "scan_root": scan_root,
        "workspace_root": tmp_path,
        "frameworks": frameworks,
        "files_eligible": tuple(eligible),
        "expected_version": "3.3.0",
        "expected_executable_sha256": hashlib.sha256(Path("/bin/sh").read_bytes()).hexdigest(),
        "kubernetes_identities": tuple(identities),
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
        value["results"] = {"failed_checks": failed, "skipped_checks": skipped}
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
    assert finding.iacgv_fingerprint.startswith("iacgv1:")
    assert run.coverage.checks_loaded == 3
    assert run.exit_code == 0
    assert run.stdout_sha256 == process().stdout_sha256
    assert run.raw_output_sha256 != run.stdout_sha256
    assert run.executable_or_image_digest == req.expected_executable_sha256


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
    scan_root = tmp_path / "repo"
    scan_root.mkdir()
    req = CheckovScanRequest(
        executable=Path("/bin/sh"),
        scan_root=scan_root,
        workspace_root=tmp_path,
        frameworks=("terraform",),
        files_eligible=(),
        expected_version="3.3.0",
        expected_executable_sha256=hashlib.sha256(Path("/bin/sh").read_bytes()).hexdigest(),
    )
    run = normalize(req, document(include_results=False, resource_count=0, passed=0))
    assert run.status is Status.PASS
    assert run.diagnostics == (AdapterReason.NO_RESULTS_STRUCTURE.value,)


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


def test_check_inventory_mismatch_is_error(tmp_path: Path) -> None:
    req = request(tmp_path, expected_checks_loaded=999)
    run = normalize(req, document(passed=2))
    assert run.status is Status.ERROR
    assert run.diagnostics == (AdapterReason.CHECK_INVENTORY_MISMATCH.value,)


def test_skipped_checks_become_suppression_evidence(tmp_path: Path) -> None:
    run = normalize(request(tmp_path), document(skipped=[check()], passed=0))
    assert run.status is Status.PASS
    assert len(run.findings) == 1
    assert run.findings[0].suppressed is True
    assert run.coverage.checks_loaded == 1


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
    req = request(tmp_path, frameworks=("kubernetes",), kubernetes_identities=())
    payload = document(
        framework="kubernetes",
        failed=[
            check(
                path="pod.yaml",
                resource="Pod.default.demo",
                check_id="CKV_K8S_20",
            )
        ],
    )
    run = normalize(req, payload)
    assert run.status is Status.ERROR
    assert run.findings == ()
    assert run.diagnostics == (AdapterReason.MISSING_RESOURCE_IDENTITY.value,)


def test_finding_path_outside_eligible_set_is_not_accepted(tmp_path: Path) -> None:
    req = request(tmp_path)
    (req.scan_root / "other.tf").write_text("resource \"aws_s3_bucket\" \"x\" {}")
    run = normalize(req, document(failed=[check(path="other.tf")]))
    assert run.status is Status.ERROR
    assert run.findings == ()


def test_request_rejects_candidate_executable_and_untrusted_framework(tmp_path: Path) -> None:
    fake = tmp_path / "checkov"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    with pytest.raises(DomainError, match="must not resolve inside"):
        request(tmp_path, executable=fake)
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
    with pytest.raises(DomainError, match="scan_root changed"):
        CheckovAdapter().scan(req)
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
    with pytest.raises(DomainError, match="eligible file changed"):
        CheckovAdapter().scan(req)
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
    with pytest.raises(DomainError, match="must be an int"):
        request(tmp_path, expected_checks_loaded=True)


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
    with pytest.raises(DomainError, match=">= 0"):
        request(tmp_path, expected_checks_loaded=-1)
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
