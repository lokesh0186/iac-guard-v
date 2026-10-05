"""Safety checks for the public external-repair input boundary."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "adoption/repairer-eval/evaluate.py"
SPEC = importlib.util.spec_from_file_location("repairer_evaluate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


@pytest.mark.parametrize(
    "header",
    [
        "diff --git a/../outside.tf b/../outside.tf",
        "diff --git a/.git/config b/.git/config",
    ],
)
def test_patch_cannot_escape_case_tree(tmp_path: Path, header: str) -> None:
    patch = tmp_path / "candidate.patch"
    patch.write_text(header + "\n--- a/main.tf\n+++ b/main.tf\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe patch path"):
        RUNNER.validate_patch(patch)


def test_symlink_baseline_is_rejected_before_verification(tmp_path: Path) -> None:
    before = tmp_path / "cases" / "case-1" / "before"
    before.mkdir(parents=True)
    (before / "main.tf").symlink_to(tmp_path / "outside.tf")
    repairs = tmp_path / "repairs"
    repairs.mkdir()
    (repairs / "case-1.patch").write_text("diff --git a/main.tf b/main.tf\n", encoding="utf-8")
    with pytest.raises(ValueError, match="symlink in case tree"):
        RUNNER.safe_case(tmp_path, {"id": "case-1", "target": "CKV_AWS_3=aws_ebs_volume.target"})


def test_example_patch_is_a_valid_text_diff() -> None:
    example = ROOT / "adoption/repairer-eval/example"
    case = {"id": "ebs-encryption", "target": "CKV_AWS_3=aws_ebs_volume.target"}
    _, before, patch, _ = RUNNER.safe_case(example, case)
    RUNNER.validate_patch(patch)
    assert before.is_dir()


def test_inconclusive_report_stays_inconclusive() -> None:
    report = {"schema_version": "report-v1", "result_kind": "operational_uncertainty",
              "verdict": "INCONCLUSIVE", "exit_code": 3}
    assert RUNNER.consistent_report(report, 3, "CKV_AWS_3=aws_ebs_volume.target")


def test_verified_report_requires_exact_fixed_target() -> None:
    report = {"schema_version": "report-v1", "result_kind": "verification",
              "verdict": "VERIFIED", "exit_code": 0,
              "verification": {"targets": [{"outcome": "FIXED", "identity": {
                  "scanner": "checkov", "rule_id": "CKV_AWS_3", "scope": "aws_ebs_volume.other"}}]}}
    assert not RUNNER.consistent_report(report, 0, "CKV_AWS_3=aws_ebs_volume.target")
