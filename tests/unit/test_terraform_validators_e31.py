"""E3.1 OpenTofu/Terraform fail-closed validation contract."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from dataclasses import fields, replace
from unittest.mock import patch

import iac_guard_v.validators.terraform as terraform_module
from iac_guard_v.adapters.phase_e_lock import (
    load_locked_container_identity, load_protected_phase_e_evidence,
)
from iac_guard_v.enums import Status
from iac_guard_v.models import DomainError
from iac_guard_v.process import CommandResult, ProcessReason
from iac_guard_v.validators import (
    TerraformValidationRequest, ValidationDiagnostic, ValidationReason,
    ValidatorExecutionEvidence, TerraformValidator,
    create_terraform_validation_request, require_trusted_validator_evidence,
)
from tests.phase_e_test_support import (
    execute_terraform_validator_fixture, make_test_container_runtime,
)


ROOT = Path(__file__).parents[2]
BUNDLE = load_protected_phase_e_evidence(ROOT)


def _process(raw: bytes, *, exit_code: int = 0, status: Status = Status.PASS,
             timed_out: bool = False) -> CommandResult:
    reason = (
        ProcessReason.COMPLETED_WITHIN_CONTRACT if status is Status.PASS
        else ProcessReason.DEADLINE_EXCEEDED if timed_out
        else ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT
    )
    return CommandResult(
        argv=("docker",), status=status, exit_code=exit_code,
        stdout=raw, stderr=b"", duration_ms=4, truncated=False,
        timed_out=timed_out, killed_signal=None, reason_code=reason,
        resolved_executable="/usr/local/bin/docker" if status is Status.PASS else "",
        primary_execution_event=reason,
    )


def _native(*, valid: bool = True, diagnostics: list | None = None) -> bytes:
    diagnostics = diagnostics or []
    return json.dumps({
        "format_version": "1.0", "valid": valid,
        "error_count": sum(item["severity"] == "error" for item in diagnostics),
        "warning_count": sum(item["severity"] == "warning" for item in diagnostics),
        "diagnostics": diagnostics,
    }).encode()


def _request(tmp_path: Path, tool: str = "opentofu", content: str = "locals { x = 1 }\n"):
    root = tmp_path / tool
    root.mkdir()
    (root / "main.tf").write_text(content, encoding="utf-8")
    locked = load_locked_container_identity(BUNDLE, tool, "linux/arm64")
    docker = Path(shutil.which("docker") or "/usr/bin/true")
    return create_terraform_validation_request(
        workspace_root=root, scan_root=root, files_eligible=("main.tf",),
        container_runtime=make_test_container_runtime(locked, docker),
        locked_identity=locked,
    )


@pytest.mark.parametrize("tool", ["opentofu", "terraform"])
def test_valid_self_contained_configuration_is_separate_trusted_pass(
    tmp_path: Path, tool: str,
) -> None:
    run = execute_terraform_validator_fixture(_request(tmp_path, tool), _process(_native()))
    assert run.status is Status.PASS
    assert run.reason is ValidationReason.COMPLETED
    assert run.validator_id == f"{tool}_validate"
    assert run.tool == tool
    assert require_trusted_validator_evidence(run) is run
    assert "no-auto-init" in run.execution_controls
    assert "network-none" in run.execution_controls


def test_definitive_invalid_candidate_is_fail(tmp_path: Path) -> None:
    diagnostic = {"severity": "error", "summary": "Invalid expression", "detail": "Expected expression"}
    run = execute_terraform_validator_fixture(
        _request(tmp_path), _process(_native(valid=False, diagnostics=[diagnostic]), exit_code=1),
    )
    assert run.status is Status.FAIL
    assert run.reason is ValidationReason.INVALID_CONFIGURATION


@pytest.mark.parametrize("summary", ["Missing required provider", "Module not installed"])
def test_provider_or_module_initialization_is_inconclusive(tmp_path: Path, summary: str) -> None:
    diagnostic = {"severity": "error", "summary": summary, "detail": "Run `tofu init`"}
    run = execute_terraform_validator_fixture(
        _request(tmp_path), _process(_native(valid=False, diagnostics=[diagnostic]), exit_code=1),
    )
    assert run.status is Status.INCONCLUSIVE
    assert run.reason is ValidationReason.NEEDS_INIT


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"not-json", ValidationReason.MALFORMED_OUTPUT),
        (b'{"format_version":"1.0","format_version":"1.0"}', ValidationReason.DUPLICATE_JSON_KEY),
    ],
)
def test_malformed_and_duplicate_validate_json_fail_closed(
    tmp_path: Path, raw: bytes, reason: ValidationReason,
) -> None:
    run = execute_terraform_validator_fixture(_request(tmp_path), _process(raw))
    assert run.status is Status.INCONCLUSIVE
    assert run.reason is reason


def test_timeout_and_unexpected_exit_are_operational_uncertainty(tmp_path: Path) -> None:
    timeout = _process(b"", exit_code=None, status=Status.TIMEOUT, timed_out=True)
    run = execute_terraform_validator_fixture(_request(tmp_path), timeout)
    assert (run.status, run.reason) == (Status.INCONCLUSIVE, ValidationReason.TIMEOUT)


def test_candidate_dot_terraform_and_cli_config_never_apply(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (request.scan_root / ".terraform").mkdir()
    with pytest.raises(DomainError, match="candidate .terraform"):
        create_terraform_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity,
        )
    (request.scan_root / ".terraform").rmdir()
    (request.scan_root / ".terraformrc").write_text("credentials {}", encoding="utf-8")
    run = execute_terraform_validator_fixture(request, _process(_native()))
    assert run.status is Status.PASS
    assert all(item.file_path != ".terraformrc" for item in run.input_files)


def test_direct_request_and_caller_evidence_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    with pytest.raises(DomainError, match="sealed factory"):
        TerraformValidationRequest(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=request.files_eligible, input_evidence=request.input_evidence,
            container_runtime=request.container_runtime, locked_identity=request.locked_identity,
        )
    with pytest.raises(DomainError, match="actual trusted execution"):
        require_trusted_validator_evidence(object())


def test_diagnostic_counts_and_exit_must_be_consistent(tmp_path: Path) -> None:
    contradictory = json.dumps({
        "format_version": "1.0", "valid": True, "error_count": 1,
        "warning_count": 0, "diagnostics": [],
    }).encode()
    run = execute_terraform_validator_fixture(_request(tmp_path), _process(contradictory))
    assert run.reason is ValidationReason.DIAGNOSTIC_CONTRADICTION

    cases = (
        ({"format_version": "1.0", "valid": True, "error_count": 0,
          "warning_count": 0, "diagnostics": [], "extra": True}, 0,
         ValidationReason.MALFORMED_OUTPUT),
        ({"format_version": "1.0", "valid": True, "error_count": 0,
          "warning_count": 0, "diagnostics": []}, 1,
         ValidationReason.DIAGNOSTIC_CONTRADICTION),
        ({"format_version": "1.0", "valid": False, "error_count": 0,
          "warning_count": 0, "diagnostics": []}, 1,
         ValidationReason.DIAGNOSTIC_CONTRADICTION),
    )
    for index, (payload, exit_code, expected) in enumerate(cases):
        case = tmp_path / f"contradiction-{index}"
        case.mkdir()
        run = execute_terraform_validator_fixture(
            _request(case), _process(json.dumps(payload).encode(), exit_code=exit_code),
        )
        assert run.reason is expected


def test_input_byte_change_after_sealing_is_detected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (request.scan_root / "main.tf").write_text("locals { changed = true }\n", encoding="utf-8")
    run = execute_terraform_validator_fixture(request, _process(_native()))
    assert run.status is Status.INCONCLUSIVE
    assert run.reason is ValidationReason.INPUT_CHANGED_DURING_VALIDATION


@pytest.mark.parametrize("path", ["main.yaml", "main.txt", "main"])
def test_only_terraform_extensions_enter_sealed_request(tmp_path: Path, path: str) -> None:
    request = _request(tmp_path)
    (request.scan_root / path).write_text("x", encoding="utf-8")
    with pytest.raises(DomainError, match="only .tf"):
        create_terraform_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=(path,), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity,
        )


def test_symlink_missing_oversize_and_duplicate_inputs_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    source = request.scan_root / "main.tf"
    source.unlink()
    source.symlink_to("missing.tf")
    with pytest.raises(DomainError, match="nonsymlink"):
        create_terraform_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity,
        )
    source.unlink()
    source.write_text("12345", encoding="utf-8")
    with pytest.raises(DomainError, match="byte limit"):
        create_terraform_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity, max_file_bytes=4,
        )
    with pytest.raises(DomainError, match="duplicates"):
        create_terraform_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf", "main.tf"),
            container_runtime=request.container_runtime, locked_identity=request.locked_identity,
        )


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"format_version": "2.0", "valid": True, "error_count": 0,
         "warning_count": 0, "diagnostics": []},
        {"format_version": "1.0", "valid": "yes", "error_count": 0,
         "warning_count": 0, "diagnostics": []},
        {"format_version": "1.0", "valid": True, "error_count": -1,
         "warning_count": 0, "diagnostics": []},
        {"format_version": "1.0", "valid": True, "error_count": 0,
         "warning_count": 0, "diagnostics": {}},
    ],
)
def test_validate_json_shape_mutations_are_inconclusive(tmp_path: Path, payload) -> None:
    raw = json.dumps(payload).encode()
    run = execute_terraform_validator_fixture(_request(tmp_path), _process(raw))
    assert run.reason is ValidationReason.MALFORMED_OUTPUT


@pytest.mark.parametrize(
    "diagnostic",
    [
        {"severity": "fatal", "summary": "x"},
        {"severity": "error", "summary": ""},
        {"severity": "error", "summary": "x", "detail": 1},
        {"severity": "error", "summary": "x", "unknown": True},
        {"severity": "error", "summary": "x", "range": "bad"},
    ],
)
def test_diagnostic_shape_mutations_are_inconclusive(tmp_path: Path, diagnostic: dict) -> None:
    raw = json.dumps({
        "format_version": "1.0", "valid": False, "error_count": 1,
        "warning_count": 0, "diagnostics": [diagnostic],
    }).encode()
    run = execute_terraform_validator_fixture(_request(tmp_path), _process(raw, exit_code=1))
    assert run.reason is ValidationReason.MALFORMED_OUTPUT


def test_diagnostic_range_and_warning_are_preserved(tmp_path: Path) -> None:
    warning = {
        "severity": "warning", "summary": "Deprecated", "detail": "detail",
        "range": {"filename": "main.tf", "start": {"line": 2, "column": 1},
                  "end": {"line": 2, "column": 2}},
    }
    run = execute_terraform_validator_fixture(
        _request(tmp_path), _process(_native(diagnostics=[warning])),
    )
    assert run.status is Status.PASS
    assert run.diagnostics[0].file_path == "main.tf"
    assert run.diagnostics[0].line == 2


def test_json_depth_utf8_and_top_level_fail_closed(tmp_path: Path) -> None:
    for index, (raw, reason) in enumerate((
        (b'{' + b'"x":[' * 130 + b'0' + b']' * 130 + b'}', ValidationReason.JSON_DEPTH_EXCEEDED),
        (b'\xff', ValidationReason.MALFORMED_OUTPUT),
        (b'', ValidationReason.MALFORMED_OUTPUT),
    )):
        case = tmp_path / str(index)
        case.mkdir()
        run = execute_terraform_validator_fixture(_request(case), _process(raw))
        assert run.reason is reason


def test_locked_argv_and_output_directory_are_enforced(tmp_path: Path) -> None:
    request = _request(tmp_path)
    process = _process(_native())

    def wrong_argv(command):
        return replace(process, argv=("different",))

    with patch("iac_guard_v.validators.terraform.run_command", wrong_argv), patch(
        "iac_guard_v.validators.terraform.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        run = TerraformValidator().validate(request)
    assert run.reason is ValidationReason.RUNTIME_INTEGRITY_FAILED

    def extra_output(command):
        mount = next(item for item in command.argv if item.endswith(":/iacgv-output:rw"))
        Path(mount.removesuffix(":/iacgv-output:rw"), "extra").write_bytes(b"x")
        return replace(process, argv=command.argv)

    with patch("iac_guard_v.validators.terraform.run_command", extra_output), patch(
        "iac_guard_v.validators.terraform.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        run = TerraformValidator().validate(request)
    assert run.reason is ValidationReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED


def test_unsealed_validator_invocation_is_rejected() -> None:
    with pytest.raises(DomainError, match="sealed request"):
        TerraformValidator().validate(object())


def test_evidence_model_rejects_contradictory_and_malformed_fields(tmp_path: Path) -> None:
    valid = execute_terraform_validator_fixture(_request(tmp_path), _process(_native()))
    values = {item.name: getattr(valid, item.name) for item in fields(valid) if item.init}
    mutations = (
        {"status": "PASS"}, {"reason": "COMPLETED"}, {"advisory_only": 1},
        {"diagnostics": []}, {"input_files": []}, {"files_eligible": -1},
        {"files_validated": 2}, {"runtime_identity": "bad"}, {"exit_code": "0"},
        {"execution_controls": ("x", "x")},
        {"status": Status.PASS, "reason": ValidationReason.NEEDS_INIT},
    )
    for mutation in mutations:
        with pytest.raises(DomainError):
            ValidatorExecutionEvidence(**(values | mutation))
    assert valid.identity == valid.identity
    assert valid.canonical_dict()["validator_id"] == "opentofu_validate"


def test_validation_diagnostic_model_is_closed() -> None:
    for args in (("fatal", "x"), ("error", "x", "", 1), ("error", "x", "", "", 0)):
        with pytest.raises(DomainError):
            ValidationDiagnostic(*args)
