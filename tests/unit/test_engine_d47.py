"""D4.7 complete no-follow artifact and scanner-environment inventory."""
from __future__ import annotations

import os
import shutil
import socket
import tempfile
from pathlib import Path

import pytest

import iac_guard_v.adapters.checkov as CHECKOV
from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.engine import VerificationRequest, run_checkov_verification
from iac_guard_v.enums import CheckEvaluationResult, Status, Verdict
from iac_guard_v.models import RequiredGates, Target

from test_engine import IDENTITY, _config, _executable, _scan_request
from test_engine_d51 import evaluation, finding, scanner_run, verdict


def _request_with_entry(tmp_path: Path, make_entry):
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    make_entry(candidate.scan_root)
    gates = RequiredGates(("kubernetes_yaml_parse", "terraform_hcl_parse"))
    config = _config(
        baseline, candidate, gates, executor=None,
        frameworks=("terraform", "kubernetes"),
    )
    request = VerificationRequest(
        baseline, candidate, (Target(IDENTITY, 1),), config
    )
    baseline_run = scanner_run(
        request.baseline_scan,
        findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate_run = scanner_run(
        request.candidate_scan,
        findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),),
    )
    return request, baseline_run, candidate_run


def _execute(monkeypatch, request, baseline_run, candidate_run):
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, value: (
            baseline_run
            if value.scan_root == request.baseline_scan.scan_root
            else candidate_run
        ),
    )
    return run_checkov_verification(request)


@pytest.mark.parametrize("target", ["outside", "internal", "missing", "cycle"])
def test_directory_symlink_is_recorded_and_never_verifies(
    monkeypatch, tmp_path: Path, target: str
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: hidden}\n",
        encoding="utf-8",
    )

    def make(root: Path) -> None:
        if target == "internal":
            real = root / "real"
            real.mkdir()
            (real / "pod.yaml").write_text(
                "apiVersion: v1\nkind: Pod\nmetadata: {name: internal}\n",
                encoding="utf-8",
            )
            destination = real
        elif target == "missing":
            destination = root / "does-not-exist"
        elif target == "cycle":
            destination = root / "linked"
        else:
            destination = outside
        (root / "linked").symlink_to(destination, target_is_directory=True)

    request, baseline_run, candidate_run = _request_with_entry(tmp_path, make)
    result = _execute(monkeypatch, request, baseline_run, candidate_run)
    entries = {
        item.file_path: item for item in result.candidate_snapshot.filesystem_entries
    }
    assert entries["linked"].kind == "SYMLINK"
    assert entries["linked"].symlink_target
    assert entries["linked"].rejection_reason == "UNSAFE_SYMLINK_ENTRY"
    assert result.preflight.status is Status.ERROR
    assert result.preflight.reason_code == "ARTIFACT_UNIVERSE_UNRESOLVED"
    assert verdict(result).verdict is not Verdict.VERIFIED


@pytest.mark.parametrize("entry_type", ["fifo", "socket", "directory", "symlink", "broken_symlink"])
def test_supported_nonregular_entry_is_bound_and_never_verifies(
    monkeypatch, tmp_path: Path, entry_type: str
) -> None:
    sockets: list[socket.socket] = []
    short_root: Path | None = None
    if entry_type == "socket":
        short_root = Path(tempfile.mkdtemp(prefix="iag-d47-", dir="/tmp"))
        tmp_path = short_root

    def make(root: Path) -> None:
        path = root / {
            "fifo": "evil.tf",
            "socket": "manifest.yaml",
            "directory": "config.json",
            "symlink": "main-link.tf",
            "broken_symlink": "pod.yaml",
        }[entry_type]
        if entry_type == "fifo":
            os.mkfifo(path)
        elif entry_type == "socket":
            value = socket.socket(socket.AF_UNIX)
            value.bind(str(path))
            sockets.append(value)
        elif entry_type == "directory":
            path.mkdir()
        elif entry_type == "symlink":
            path.symlink_to(root / "main.tf")
        else:
            path.symlink_to(root / "missing.yaml")

    try:
        request, baseline_run, candidate_run = _request_with_entry(tmp_path, make)
        result = _execute(monkeypatch, request, baseline_run, candidate_run)
        unsafe = [
            item for item in result.candidate_snapshot.filesystem_entries
            if item.rejection_reason
        ]
        assert unsafe
        assert result.preflight.status is Status.ERROR
        assert result.preflight.reason_code == "ARTIFACT_UNIVERSE_UNRESOLVED"
        assert verdict(result).verdict is not Verdict.VERIFIED
    finally:
        for value in sockets:
            value.close()
        if short_root is not None:
            shutil.rmtree(short_root)


def test_dependency_code_bytes_are_bound_not_only_dist_info(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    dependency = (
        tmp_path
        / "trusted/libexec/lib/python3.11/site-packages/dependency_pkg/dependency.py"
    )
    dependency.parent.mkdir()
    dependency.write_text("VALUE = 1\n", encoding="utf-8")
    before = CHECKOV.checkov_distribution_identity(executable, "3.3.0")
    dependency.write_text("VALUE = 2\n", encoding="utf-8")
    after = CHECKOV.checkov_distribution_identity(executable, "3.3.0")
    assert before.dependency_lock_digest != after.dependency_lock_digest
    assert before.scanner_environment_digest != after.scanner_environment_digest
