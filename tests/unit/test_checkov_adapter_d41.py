"""D4.1 affirmative-evidence and byte-bound scan-view security properties."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.enums import Status
from iac_guard_v.models import DomainError
from iac_guard_v.process import CommandResult, ProcessReason

from test_checkov_adapter import check, document, normalize, request


def evaluation(
    result: str,
    *,
    path: str = "main.tf",
    resource: str = "aws_s3_bucket.bad",
    rule_id: str = "CKV_AWS_18",
) -> dict:
    value = check(path=path, resource=resource, check_id=rule_id)
    value["check_result"]["result"] = result
    return value


def evidence_document(
    *,
    passed: tuple[dict, ...] = (),
    failed: tuple[dict, ...] = (),
    skipped: tuple[dict, ...] = (),
    unknown: tuple[dict, ...] = (),
    extra_results: dict | None = None,
) -> dict:
    results = {
        "passed_checks": list(passed),
        "failed_checks": list(failed),
        "skipped_checks": list(skipped),
    }
    if unknown:
        results["unknown_checks"] = list(unknown)
    if extra_results:
        results.update(extra_results)
    return {
        "check_type": "terraform",
        "summary": {
            "passed": len(passed),
            "failed": len(failed),
            "skipped": len(skipped),
            "parsing_errors": 0,
            "resource_count": 1,
            "checkov_version": "3.3.0",
        },
        "results": results,
    }


def command_result(argv: tuple, stdout: bytes = b"") -> CommandResult:
    return CommandResult(
        argv=argv,
        status=Status.PASS,
        exit_code=0,
        stdout=stdout,
        stderr=b"",
        duration_ms=1,
        truncated=False,
        timed_out=False,
        killed_signal=None,
        reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
        resolved_executable=argv[0],
    )


def test_in_place_rewrite_is_typed_before_checkov_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    source = req.scan_root / "main.tf"
    original_inode = source.stat().st_ino
    source.write_text("resource \"aws_s3_bucket\" \"changed\" {}\n")
    assert source.stat().st_ino == original_inode
    calls = []

    def fake_run(command):
        calls.append(command)
        if command.argv[1:] == ("--version",):
            return command_result(command.argv, b"3.3.0\n")
        output_dir = Path(command.argv[command.argv.index("--output-file-path") + 1])
        (output_dir / "results_json.json").write_text(
            json.dumps(evidence_document(passed=(evaluation("PASSED"),)))
        )
        return command_result(command.argv)

    monkeypatch.setattr("iac_guard_v.adapters.checkov.run_command", fake_run)
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("INPUT_CHANGED_DURING_SCAN_PREPARATION",)
    assert calls == []


def test_scan_view_contains_exactly_request_bound_bytes(tmp_path: Path) -> None:
    req = request(tmp_path)
    bound = req.eligible_file_evidence[0]
    destination = tmp_path / "view"
    CheckovAdapter._build_scan_view(req, destination)
    copied = (destination / bound.file_path).read_bytes()
    assert len(copied) == bound.size
    assert hashlib.sha256(copied).hexdigest() == bound.sha256
    assert bound.file_type == "terraform_hcl"


def test_two_eligible_files_with_one_observed_is_partial(tmp_path: Path) -> None:
    initial = request(tmp_path)
    (initial.scan_root / "other.tf").write_text(
        'resource "aws_s3_bucket" "other" {}\n'
    )
    req = request(tmp_path, files_eligible=("main.tf", "other.tf"))
    run = normalize(
        req,
        evidence_document(passed=(evaluation("PASSED", path="main.tf"),)),
    )
    assert run.status is Status.PARTIAL
    assert run.coverage.files_eligible == 2
    assert run.coverage.files_parsed == 1
    assert any("other.tf" in item for item in run.diagnostics)
    evaluator = getattr(__import__(
        "iac_guard_v.adapters.checkov", fromlist=["evaluate_checkov_target"]
    ), "evaluate_checkov_target")
    target = evaluator(run, "CKV_AWS_18", "aws_s3_bucket.bad", "main.tf")
    assert target.status is Status.INCONCLUSIVE
    assert target.reason.value == "SCANNER_RUN_NOT_PASS"


def test_affirmative_native_pass_is_retained_and_target_is_proven(tmp_path: Path) -> None:
    req = request(tmp_path)
    run = normalize(req, evidence_document(passed=(evaluation("PASSED"),)))
    assert run.status is Status.PASS
    assert len(run.evaluations) == 1
    assert run.evaluations[0].native_result.value == "PASSED"
    evaluator = getattr(__import__(
        "iac_guard_v.adapters.checkov", fromlist=["evaluate_checkov_target"]
    ), "evaluate_checkov_target")
    target = evaluator(run, "CKV_AWS_18", "aws_s3_bucket.bad", "main.tf")
    assert target.status is Status.PASS
    assert target.reason.value == "AFFIRMATIVE_TARGET_PASS"


def test_aggregate_count_without_per_target_evidence_is_inconclusive(
    tmp_path: Path,
) -> None:
    payload = document(passed=7)
    payload["results"].pop("passed_checks")
    run = normalize(request(tmp_path), payload)
    assert run.status in (Status.PARTIAL, Status.INCONCLUSIVE)
    assert run.coverage.evaluations_reported == 7
    assert run.evaluations == ()
    evaluator = getattr(__import__(
        "iac_guard_v.adapters.checkov", fromlist=["evaluate_checkov_target"]
    ), "evaluate_checkov_target")
    target = evaluator(run, "CKV_AWS_18", "aws_s3_bucket.bad", "main.tf")
    assert target.status is Status.INCONCLUSIVE
    assert target.reason.value == "AGGREGATE_ONLY_EVIDENCE"


@pytest.mark.parametrize(
    ("payload", "expected_reason"),
    [
        (evidence_document(), "RESOURCE_NOT_OBSERVED"),
        (
            evidence_document(
                passed=(evaluation("PASSED", rule_id="CKV_AWS_999"),)
            ),
            "RULE_NOT_OBSERVED",
        ),
        (
            evidence_document(
                unknown=(evaluation("UNKNOWN"),)
            ),
            "TARGET_EVALUATION_UNKNOWN",
        ),
    ],
)
def test_absent_or_unknown_target_evidence_is_inconclusive(
    tmp_path: Path, payload: dict, expected_reason: str
) -> None:
    run = normalize(request(tmp_path), payload)
    evaluator = getattr(__import__(
        "iac_guard_v.adapters.checkov", fromlist=["evaluate_checkov_target"]
    ), "evaluate_checkov_target")
    target = evaluator(run, "CKV_AWS_18", "aws_s3_bucket.bad", "main.tf")
    assert target.status is Status.INCONCLUSIVE
    assert target.reason.value == expected_reason


def test_inline_skip_is_typed_evaluation_and_never_affirmative_pass(
    tmp_path: Path,
) -> None:
    run = normalize(
        request(tmp_path),
        evidence_document(skipped=(evaluation("SKIPPED"),)),
    )
    assert run.evaluations[0].native_result.value == "SKIPPED"
    assert run.findings[0].suppressed is True
    evaluator = getattr(__import__(
        "iac_guard_v.adapters.checkov", fromlist=["evaluate_checkov_target"]
    ), "evaluate_checkov_target")
    target = evaluator(run, "CKV_AWS_18", "aws_s3_bucket.bad", "main.tf")
    assert target.status is Status.INCONCLUSIVE


def test_rule_and_resource_seen_separately_do_not_prove_target_evaluation(
    tmp_path: Path,
) -> None:
    run = normalize(
        request(tmp_path),
        evidence_document(
            passed=(
                evaluation("PASSED", rule_id="CKV_AWS_18", resource="aws_s3_bucket.other"),
                evaluation("PASSED", rule_id="CKV_AWS_19", resource="aws_s3_bucket.bad"),
            )
        ),
    )
    evaluator = getattr(__import__(
        "iac_guard_v.adapters.checkov", fromlist=["evaluate_checkov_target"]
    ), "evaluate_checkov_target")
    target = evaluator(run, "CKV_AWS_18", "aws_s3_bucket.bad", "main.tf")
    assert target.status is Status.INCONCLUSIVE
    assert target.reason.value == "TARGET_NOT_EVALUATED"


def test_bucket_native_result_contradiction_is_invalid(tmp_path: Path) -> None:
    run = normalize(
        request(tmp_path),
        evidence_document(failed=(evaluation("PASSED"),)),
    )
    assert run.status is Status.ERROR
    assert run.diagnostics == ("INVALID_RESULTS_STRUCTURE",)


def test_duplicate_json_key_at_any_depth_is_invalid(tmp_path: Path) -> None:
    summary = json.dumps(document(passed=1)["summary"])
    malicious = json.dumps({
        "failed_checks": [evaluation("FAILED")],
        "passed_checks": [],
        "skipped_checks": [],
    })
    benign = json.dumps({
        "failed_checks": [],
        "passed_checks": [evaluation("PASSED")],
        "skipped_checks": [],
    })
    raw = (
        '{"check_type":"terraform","summary":' + summary
        + ',"results":' + malicious + ',"results":' + benign + "}"
    ).encode()
    run = CheckovAdapter().normalize(raw, request(tmp_path), command_result(("/bin/sh",)), "3.3.0")
    assert run.status is Status.ERROR
    assert run.diagnostics == ("INVALID_RESULTS_STRUCTURE",)

    nested = (
        b'{"check_type":"terraform","summary":{"passed":1,"passed":0,'
        b'"failed":0,"skipped":0,"parsing_errors":0,"resource_count":1,'
        b'"checkov_version":"3.3.0"},"results":{"passed_checks":[],'
        b'"failed_checks":[],"skipped_checks":[]}}'
    )
    nested_run = CheckovAdapter().normalize(
        nested, request(tmp_path), command_result(("/bin/sh",)), "3.3.0"
    )
    assert nested_run.status is Status.ERROR
    assert nested_run.diagnostics == ("INVALID_RESULTS_STRUCTURE",)


def test_unknown_result_bucket_is_not_silently_ignored(tmp_path: Path) -> None:
    run = normalize(
        request(tmp_path),
        evidence_document(
            passed=(evaluation("PASSED"),),
            extra_results={"future_checks": [evaluation("UNKNOWN")]},
        ),
    )
    assert run.status in (Status.PARTIAL, Status.INCONCLUSIVE)
    assert "UNKNOWN_RESULT_BUCKET" in run.diagnostics


def test_evaluation_count_is_not_ruleset_identity(tmp_path: Path) -> None:
    req = request(tmp_path)
    one = normalize(req, evidence_document(passed=(evaluation("PASSED"),)))
    two = normalize(
        req,
        evidence_document(
            passed=(
                evaluation("PASSED", rule_id="CKV_AWS_18"),
                evaluation("PASSED", rule_id="CKV_AWS_19"),
            )
        ),
    )
    assert one.policy_inventory_digest == two.policy_inventory_digest
    assert one.coverage.evaluations_reported == 1
    assert two.coverage.evaluations_reported == 2
    assert one.status is Status.PASS
    assert two.status is Status.PASS


def test_launcher_environment_policy_and_invocation_identities_are_distinct(
    tmp_path: Path,
) -> None:
    run = normalize(
        request(tmp_path), evidence_document(passed=(evaluation("PASSED"),))
    )
    canonical = run.canonical_dict()
    assert canonical["resolved_launcher_path"]
    assert canonical["launcher_digest"]
    assert canonical["scanner_environment_digest"]
    assert canonical["policy_inventory_digest"]
    assert canonical["invocation_config_digest"]
    assert canonical["launcher_digest"] != canonical["scanner_environment_digest"]
    with pytest.raises(DomainError, match="ruleset integrity"):
        replace(run, ruleset_integrity=Status.INCONCLUSIVE)


def test_machine_scan_removes_quiet_to_retain_positive_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    calls = []

    def fake_run(command):
        calls.append(command)
        if command.argv[1:] == ("--version",):
            return command_result(command.argv, b"3.3.0\n")
        output_dir = Path(command.argv[command.argv.index("--output-file-path") + 1])
        (output_dir / "results_json.json").write_text(
            json.dumps(evidence_document(passed=(evaluation("PASSED"),)))
        )
        return command_result(command.argv)

    monkeypatch.setattr("iac_guard_v.adapters.checkov.run_command", fake_run)
    run = CheckovAdapter().scan(req)
    assert run.status is Status.PASS
    assert "--quiet" not in calls[1].argv


def test_scan_view_copy_failure_is_typed_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    monkeypatch.setattr(
        CheckovAdapter,
        "_build_scan_view",
        lambda *_args: (_ for _ in ()).throw(OSError("copy failed")),
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("SCAN_VIEW_PREPARATION_FAILED",)


def test_multiple_json_outputs_are_typed_directory_integrity_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)

    def fake_run(command):
        if command.argv[1:] == ("--version",):
            return command_result(command.argv, b"3.3.0\n")
        output_dir = Path(command.argv[command.argv.index("--output-file-path") + 1])
        (output_dir / "one.json").write_text("{}")
        (output_dir / "two.json").write_text("{}")
        return command_result(command.argv)

    monkeypatch.setattr("iac_guard_v.adapters.checkov.run_command", fake_run)
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("OUTPUT_DIRECTORY_INTEGRITY_FAILED",)


def test_policy_inventory_replacement_is_typed_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    req = request(tmp_path)
    policy = next(
        (tmp_path / "trusted-checkov/libexec").glob(
            "lib/python*/site-packages/checkov/terraform/checks/resource/test.py"
        )
    )
    policy.write_text('RULES = ("CKV_AWS_999",)\n')
    calls = []
    monkeypatch.setattr(
        "iac_guard_v.adapters.checkov.run_command", lambda command: calls.append(command)
    )
    run = CheckovAdapter().scan(req)
    assert run.status is Status.ERROR
    assert run.diagnostics == ("POLICY_INVENTORY_MISMATCH",)
    assert calls == []
