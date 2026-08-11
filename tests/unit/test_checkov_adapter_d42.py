"""D4.2 resource-coverage and evidence-consistency security properties."""
from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from iac_guard_v.adapters.checkov import (
    CHECKOV_MAX_JSON_NESTING_DEPTH,
    CheckovAdapter,
    _enforce_json_nesting_depth,
)
from iac_guard_v.enums import ArtifactKind, Status
from iac_guard_v.models import DomainError, ExpectedResource, ScannerRun

from test_checkov_adapter import document, normalize, request
from test_checkov_adapter_d41 import command_result, evaluation, evidence_document


def test_summary_two_resources_with_only_one_observed_cannot_pass(tmp_path: Path) -> None:
    payload = evidence_document(passed=(evaluation("PASSED"),))
    payload["summary"]["resource_count"] = 2
    run = normalize(request(tmp_path), payload)
    assert run.status is not Status.PASS
    assert "RESOURCE_COUNT_MISMATCH" in run.diagnostics or "COVERAGE_MISMATCH" in run.diagnostics


def test_summary_resource_count_below_observed_is_invalid(tmp_path: Path) -> None:
    payload = evidence_document(
        passed=(
            evaluation("PASSED", resource="aws_s3_bucket.one"),
            evaluation("PASSED", resource="aws_s3_bucket.two"),
        )
    )
    payload["summary"]["resource_count"] = 1
    run = normalize(request(tmp_path), payload)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("INVALID_RESULTS_STRUCTURE",)


def test_same_evaluation_cannot_be_both_passed_and_failed(tmp_path: Path) -> None:
    payload = evidence_document(
        passed=(evaluation("PASSED"),), failed=(evaluation("FAILED"),)
    )
    run = normalize(request(tmp_path), payload)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("CONTRADICTORY_EVALUATION_EVIDENCE",)


def test_policy_inventory_mismatch_cannot_report_integrity_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    policy = next(
        (tmp_path / "trusted-checkov/libexec").glob(
            "lib/python*/site-packages/checkov/terraform/checks/resource/test.py"
        )
    )
    policy.write_text('RULES = ("CKV_AWS_999",)\n')
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.run_command",
        lambda _command: pytest.fail("mismatch must be typed before spawn"),
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("POLICY_INVENTORY_MISMATCH",)
    assert run.ruleset_integrity is Status.FAIL


def test_portable_input_evidence_excludes_device_and_inode(tmp_path: Path) -> None:
    first = request(tmp_path).eligible_file_evidence[0]
    canonical = first.canonical_dict()
    assert canonical == {
        "file_path": first.file_path,
        "file_type": first.file_type,
        "size": first.size,
        "sha256": first.sha256,
    }
    assert "device" not in json.dumps(canonical)
    assert "inode" not in json.dumps(canonical)


def test_empty_eligible_scope_is_skipped_not_pass(tmp_path: Path) -> None:
    req = request(tmp_path, files_eligible=())
    run = normalize(
        req,
        document(passed=0, resource_count=0, include_results=False),
    )
    assert run.status is Status.SKIPPED
    assert run.diagnostics == ("EMPTY_ELIGIBLE_SCOPE",)


def test_deep_json_failure_is_typed_not_raised(tmp_path: Path) -> None:
    raw = ("[" * 2000 + "{}" + "]" * 2000).encode()
    run = CheckovAdapter().normalize(
        raw, request(tmp_path), command_result(("/bin/sh",)), "3.3.0"
    )
    assert run.status is Status.ERROR
    assert run.diagnostics == ("JSON_DEPTH_EXCEEDED",)


def test_deep_json_has_interpreter_independent_depth_diagnostic(tmp_path: Path) -> None:
    raw = ("[" * 2000 + "{}" + "]" * 2000).encode()
    run = CheckovAdapter().normalize(
        raw, request(tmp_path), command_result(("/bin/sh",)), "3.3.0"
    )
    assert run.status is Status.ERROR
    assert run.diagnostics == ("JSON_DEPTH_EXCEEDED",)


def test_json_depth_limit_has_exact_boundary_and_ignores_string_brackets() -> None:
    _enforce_json_nesting_depth("[" * CHECKOV_MAX_JSON_NESTING_DEPTH + "]" * CHECKOV_MAX_JSON_NESTING_DEPTH)
    _enforce_json_nesting_depth(r'{"value":"[[[\\\"{{{]]]"}')
    with pytest.raises(DomainError, match="JSON_DEPTH_EXCEEDED"):
        _enforce_json_nesting_depth(
            "[" * (CHECKOV_MAX_JSON_NESTING_DEPTH + 1)
            + "]" * (CHECKOV_MAX_JSON_NESTING_DEPTH + 1)
        )


def test_nonempty_scan_without_independent_resource_inventory_is_partial(
    tmp_path: Path,
) -> None:
    req = request(tmp_path, expected_resources=())
    run = normalize(req, evidence_document(passed=(evaluation("PASSED"),)))
    assert run.status is Status.PARTIAL
    assert "RESOURCE_INVENTORY_MISSING" in run.diagnostics
    assert run.resource_coverage.resources_expected == 0
    assert run.resource_coverage.unexpected_resources_observed == 1


def test_every_expected_resource_needs_native_evaluation(tmp_path: Path) -> None:
    req = request(
        tmp_path,
        expected_resources=(
            ExpectedResource(
                "main.tf", "aws_s3_bucket.bad", ArtifactKind.TERRAFORM_HCL,
                "aws_s3_bucket.bad",
            ),
            ExpectedResource(
                "main.tf", "aws_s3_bucket.other", ArtifactKind.TERRAFORM_HCL,
                "aws_s3_bucket.other",
            ),
        ),
    )
    payload = evidence_document(passed=(evaluation("PASSED"),))
    payload["summary"]["resource_count"] = 2
    run = normalize(req, payload)
    assert run.status is Status.PARTIAL
    assert run.resource_coverage.expected_resources_missing == 1
    assert any("aws_s3_bucket.other" in item for item in run.diagnostics)


def test_unexpected_observed_resource_cannot_silently_pass(tmp_path: Path) -> None:
    run = normalize(
        request(tmp_path),
        evidence_document(
            passed=(evaluation("PASSED", resource="aws_s3_bucket.unexpected"),)
        ),
    )
    assert run.status is Status.PARTIAL
    assert run.resource_coverage.unexpected_resources_observed == 1
    assert "COVERAGE_MISMATCH" in run.diagnostics


def test_device_and_inode_are_runtime_only_not_portable_identity(tmp_path: Path) -> None:
    bound = request(tmp_path).eligible_file_evidence[0]
    moved_runtime = replace(bound, device=bound.device + 1, inode=bound.inode + 1)
    assert bound.canonical_dict() == moved_runtime.canonical_dict()
    assert bound.canonical_key == moved_runtime.canonical_key


def test_runtime_inode_replacement_is_still_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    source = req.scan_root / "main.tf"
    replacement = req.scan_root / "replacement.tf"
    replacement.write_bytes(source.read_bytes())
    os.replace(replacement, source)
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.run_command",
        lambda _command: pytest.fail("inode replacement must be rejected before spawn"),
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("INPUT_CHANGED_DURING_SCAN_PREPARATION",)


def test_empty_scope_short_circuits_before_process_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path, files_eligible=())
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.run_command",
        lambda _command: pytest.fail("empty scope must not spawn Checkov"),
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.SKIPPED
    assert run.diagnostics == ("EMPTY_ELIGIBLE_SCOPE",)


def test_input_file_count_cap_is_enforced_before_spawn(tmp_path: Path) -> None:
    initial = request(tmp_path)
    (initial.scan_root / "other.tf").write_text('resource "null_resource" "other" {}\n')
    with pytest.raises(DomainError, match="INPUT_FILE_COUNT_EXCEEDED"):
        request(
            tmp_path,
            files_eligible=("main.tf", "other.tf"),
            max_eligible_files=1,
        )


def test_per_file_and_total_input_byte_caps_are_enforced(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="INPUT_FILE_BYTES_EXCEEDED"):
        request(tmp_path, max_file_bytes=1)

    initial = request(tmp_path)
    (initial.scan_root / "other.tf").write_text('resource "null_resource" "other" {}\n')
    with pytest.raises(DomainError, match="INPUT_TOTAL_BYTES_EXCEEDED"):
        request(
            tmp_path,
            files_eligible=("main.tf", "other.tf"),
            max_file_bytes=1024,
            max_total_eligible_bytes=40,
        )


def test_input_limits_are_bound_into_invocation_identity(tmp_path: Path) -> None:
    payload = evidence_document(passed=(evaluation("PASSED"),))
    standard = normalize(request(tmp_path), payload)
    changed = normalize(request(tmp_path, max_file_bytes=20 * 1024 * 1024), payload)
    assert standard.invocation_config_digest != changed.invocation_config_digest


def test_caller_scanner_run_cannot_mint_trusted_target_evidence() -> None:
    from iac_guard_v.adapters.checkov import evaluate_checkov_target

    caller_run = ScannerRun("checkov", "3.3.0", Status.PASS)
    with pytest.raises(DomainError, match="caller-authored"):
        evaluate_checkov_target(caller_run, "CKV_X", "aws_x.r", "main.tf")


def test_version_mismatch_makes_ruleset_integrity_inconclusive(tmp_path: Path) -> None:
    run = normalize(request(tmp_path), document(version="3.2.517"))
    assert run.status is Status.ERROR
    assert run.diagnostics == ("VERSION_MISMATCH",)
    assert run.ruleset_integrity is Status.INCONCLUSIVE


def test_scanner_environment_mismatch_fails_ruleset_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    interpreter = tmp_path / "trusted-checkov/libexec/bin/python"
    interpreter.write_text("#!/bin/sh\nexit 7\n")
    interpreter.chmod(0o755)
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.run_command",
        lambda _command: pytest.fail("environment mismatch must stop before spawn"),
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("SCANNER_ENVIRONMENT_MISMATCH",)
    assert run.ruleset_integrity is Status.FAIL
