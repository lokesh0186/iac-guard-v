"""D2.3 process-boundary closure regression tests.

These probes assert security properties reproduced against ``eba9b73``.  They are
deliberately phrased in terms of observable evidence and spawn prevention, so deleting
or bypassing a guard makes the corresponding test fail.
"""
from __future__ import annotations

import errno
import io
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from iac_guard_v.enums import Status  # noqa: E402
import iac_guard_v.process as process_module  # noqa: E402
from iac_guard_v.process import (  # noqa: E402
    CommandRequest,
    CommandResult,
    ProcessGroupState,
    ProcessPolicyError,
    ProcessReason,
    run_command,
)
from iac_guard_v.redaction import REDACTED_MARKER, redact_paths  # noqa: E402

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX process semantics")


def _canonical_text(result: CommandResult) -> str:
    return json.dumps(result.canonical_dict(), sort_keys=True)


def _result(**overrides) -> CommandResult:
    values = dict(
        argv=("tool",),
        status=Status.ERROR,
        exit_code=1,
        stdout=b"",
        stderr=b"",
        duration_ms=0,
        truncated=False,
        timed_out=False,
        killed_signal=None,
        reason_code=ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT,
        detail="",
        resolved_executable="/usr/bin/tool",
    )
    values.update(overrides)
    return CommandResult(**values)


def test_clean_bytecode_warning_error_import() -> None:
    """A stale pyc must not hide invalid escapes from a warnings-as-errors import."""
    for cache in (REPO / "src").rglob("__pycache__"):
        shutil.rmtree(cache)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src")
    completed = subprocess.run(
        [sys.executable, "-W", "error", "-c", "import iac_guard_v"],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("metadata", "value"),
    [
        ("sensitive_option_names", ("--custom-secret",)),
        ("sensitive_argument_indices", (4,)),
    ],
)
def test_adapter_sensitive_metadata_redacts_every_report_surface(
    metadata: str, value: tuple,
) -> None:
    secret = "plain-secret-xyz"
    request = CommandRequest(
        argv=(sys.executable, "-c", "pass", "--custom-secret", secret),
        **{metadata: value},
    )
    result = run_command(request)
    assert secret not in request.display_command
    assert secret not in _canonical_text(result)
    assert REDACTED_MARKER in request.display_command
    assert REDACTED_MARKER in _canonical_text(result)


@pytest.mark.parametrize(
    "indices",
    [("2",), (True,), (-1,), (3,), (1, 1)],
)
def test_sensitive_argument_indices_reject_malformed_values(indices: tuple) -> None:
    with pytest.raises(ProcessPolicyError):
        CommandRequest(argv=("tool", "a", "b"), sensitive_argument_indices=indices)


def test_sensitive_argument_indices_are_canonical() -> None:
    request = CommandRequest(
        argv=("tool", "a", "b", "c"), sensitive_argument_indices=[3, 1]
    )
    assert request.sensitive_argument_indices == (1, 3)
    assert type(request.sensitive_argument_indices) is tuple


@pytest.mark.parametrize(
    "option_names",
    [
        ("",),
        ("   ",),
        ("token",),
        ("--bad=value",),
        ("--bad\x00name",),
        ("--bad\nname",),
        ("--bad\u0001name",),
        ("--bad\u202ename",),
        ("--same", "--same"),
    ],
)
def test_sensitive_option_names_reject_malformed_values(option_names: tuple) -> None:
    with pytest.raises(ProcessPolicyError):
        CommandRequest(argv=("tool",), sensitive_option_names=option_names)


def test_sensitive_option_names_are_canonical() -> None:
    request = CommandRequest(
        argv=("tool",), sensitive_option_names=["--z-secret", "--a-secret"]
    )
    assert request.sensitive_option_names == ("--a-secret", "--z-secret")
    assert type(request.sensitive_option_names) is tuple


@pytest.mark.parametrize(
    "local_path",
    [
        "/Users/Alice/secret.tf",
        "/home/alice/secret.tf",
        "/mnt/private/secret.tf",
        "/private/repo/secret.tf",
        "/tmp/secret.tf",
        "/var/private/secret.tf",
        "/opt/company/secret/file.tf",
        "/root/.aws/credentials",
        "/workspace/repo/main.tf",
        "C:/Users/Alice/secret.tf",
        r"C:\Users\Alice\secret.tf",
    ],
)
def test_complete_local_paths_are_redacted(local_path: str) -> None:
    redacted = redact_paths(f"failed at {local_path}")
    assert local_path not in redacted
    assert redacted == "failed at [PATH]"


def test_path_redaction_does_not_corrupt_urls() -> None:
    urls = (
        "https://registry.terraform.io/modules/foo/bar",
        "http://example.test/root/.aws/credentials",
    )
    text = " ".join(urls)
    assert redact_paths(text) == text


def test_absolute_executable_identity_is_basename_only_in_reports() -> None:
    executable = "/Users/person/private-venv/bin/checkov"
    result = _result(argv=(executable, "--version"), resolved_executable=executable)
    canonical = _canonical_text(result)
    assert executable not in canonical
    assert result.canonical_dict()["argv"][0] == "checkov"
    assert result.canonical_dict()["resolved_executable"] == "checkov"


def test_windows_absolute_executable_identity_is_basename_only_in_reports() -> None:
    executable = r"C:\Users\Alice\private-venv\scanner.exe"
    result = _result(argv=(executable, "--version"), resolved_executable=executable)
    canonical = _canonical_text(result)
    assert executable not in canonical
    assert result.canonical_dict()["argv"][0] == "scanner.exe"
    assert result.canonical_dict()["resolved_executable"] == "scanner.exe"


def test_spawn_and_scratch_cleanup_failures_are_both_final_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    process_module.logger.addHandler(handler)
    process_module.logger.setLevel(logging.WARNING)
    created: list[Path] = []
    real_mkdtemp = process_module.tempfile.mkdtemp
    real_rmtree = shutil.rmtree

    def tracked_mkdtemp(*args, **kwargs) -> str:
        path = Path(real_mkdtemp(*args, **kwargs))
        created.append(path)
        return str(path)

    monkeypatch.setattr(process_module.tempfile, "mkdtemp", tracked_mkdtemp)
    monkeypatch.setattr(
        process_module.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(OSError("spawn denied"))
    )
    monkeypatch.setattr(
        process_module.shutil, "rmtree", lambda *a, **k: (_ for _ in ()).throw(OSError("cleanup denied"))
    )
    try:
        result = run_command(CommandRequest(argv=(sys.executable, "-c", "pass")))
    finally:
        process_module.logger.removeHandler(handler)
        for path in created:
            real_rmtree(path, ignore_errors=True)

    canonical = _canonical_text(result)
    logs = log_stream.getvalue()
    assert result.status is not Status.PASS
    assert result.reason_code is ProcessReason.SPAWN_FAILED
    assert result.scratch_cleanup_success is False
    assert ProcessReason.SCRATCH_CLEANUP_FAILED in result.cleanup_diagnostics
    assert "SPAWN_FAILED" in canonical
    assert "SCRATCH_CLEANUP_FAILED" in canonical
    assert "spawn denied" in canonical
    assert "cleanup" in canonical.lower()
    for path in created:
        assert str(path) not in canonical
        assert str(path) not in logs


@pytest.mark.parametrize(
    "overrides",
    [
        dict(status=Status.PARTIAL, reason_code=ProcessReason.OUTPUT_LIMIT_EXCEEDED),
        dict(status=Status.ERROR, reason_code=ProcessReason.OUTPUT_LIMIT_EXCEEDED),
        dict(status=Status.TIMEOUT, timed_out=True, reason_code=ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT),
        dict(reason_code=""),
        dict(reason_code="   "),
        dict(reason_code="BAD\x00REASON"),
        dict(reason_code="BAD\nREASON"),
        dict(reason_code="BAD\u0001REASON"),
        dict(reason_code="BAD\u202eREASON"),
        dict(killed_signal=0),
        dict(killed_signal=-9),
        dict(killed_signal=999999),
        dict(killed_signal=int(signal.SIGTERM), exit_code=1),
        dict(exit_code=-int(signal.SIGTERM), killed_signal=None),
        dict(
            status=Status.PASS,
            exit_code=0,
            reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
            resolved_executable="",
        ),
        dict(status=Status.ERROR, timed_out=True, reason_code=ProcessReason.DEADLINE_EXCEEDED),
        dict(status=Status.ERROR, reason_code=ProcessReason.PROCESS_GROUP_CLEANUP_FAILED),
        dict(primary_execution_event=ProcessReason.DEADLINE_EXCEEDED),
        dict(cleanup_diagnostics=(ProcessReason.SCRATCH_CLEANUP_FAILED,)),
    ],
)
def test_command_result_rejects_contradictory_evidence(overrides: dict) -> None:
    with pytest.raises(ProcessPolicyError):
        _result(**overrides)


def test_output_limit_requires_truncation() -> None:
    result = _result(
        status=Status.PARTIAL,
        reason_code=ProcessReason.OUTPUT_LIMIT_EXCEEDED,
        truncated=True,
        exit_code=-int(signal.SIGTERM),
        killed_signal=int(signal.SIGTERM),
    )
    assert result.truncated is True


def test_group_cleanup_failure_requires_typed_failed_cleanup() -> None:
    result = _result(
        status=Status.ERROR,
        reason_code=ProcessReason.PROCESS_GROUP_CLEANUP_FAILED,
        process_group_cleanup_attempted=True,
        process_group_cleanup_success=False,
        primary_execution_event=ProcessReason.DEADLINE_EXCEEDED,
        cleanup_diagnostics=(ProcessReason.PROCESS_GROUP_CLEANUP_FAILED,),
        timed_out=True,
        exit_code=-int(signal.SIGKILL),
        killed_signal=int(signal.SIGKILL),
    )
    assert result.status is Status.ERROR


@POSIX_ONLY
@pytest.mark.parametrize(
    "error",
    [PermissionError(errno.EPERM, "denied"), OSError(errno.EIO, "inspection failed")],
)
def test_group_inspection_uncertainty_is_not_absence(error: OSError) -> None:
    with patch.object(process_module.os, "killpg", side_effect=error):
        assert process_module._process_group_alive(424242) is ProcessGroupState.UNKNOWN


@POSIX_ONLY
def test_esrch_confirms_group_absence() -> None:
    with patch.object(
        process_module.os, "killpg", side_effect=ProcessLookupError(errno.ESRCH, "gone")
    ):
        assert process_module._process_group_alive(424242) is ProcessGroupState.ABSENT


@pytest.mark.parametrize(
    ("execution_event", "expected_old_status"),
    [
        (ProcessReason.DEADLINE_EXCEEDED, Status.TIMEOUT),
        (ProcessReason.OUTPUT_LIMIT_EXCEEDED, Status.PARTIAL),
    ],
)
def test_group_cleanup_uncertainty_overrides_timeout_or_partial(
    execution_event: ProcessReason,
    expected_old_status: Status,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del expected_old_status  # documents the vulnerable old classification
    real_terminate = process_module._terminate_process_group

    def uncertain_cleanup(proc, pgid):
        outcome = real_terminate(proc, pgid)
        return process_module.ProcessGroupCleanup(
            attempted=True,
            success=False,
            killed_signal=outcome.killed_signal,
            diagnostic="process-group cleanup could not be confirmed",
        )

    monkeypatch.setattr(process_module, "_terminate_process_group", uncertain_cleanup)
    if execution_event is ProcessReason.DEADLINE_EXCEEDED:
        request = CommandRequest(
            argv=(sys.executable, "-c", "import time; time.sleep(30)"),
            timeout_seconds=1,
        )
    else:
        request = CommandRequest(
            argv=(
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x'*1000000); sys.stdout.flush()",
            ),
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_output_bytes=1024,
            timeout_seconds=10,
        )
    result = run_command(request)
    assert result.status is Status.ERROR
    assert result.reason_code is ProcessReason.PROCESS_GROUP_CLEANUP_FAILED
    assert result.primary_execution_event is execution_event
    assert result.process_group_cleanup_attempted is True
    assert result.process_group_cleanup_success is False
    assert ProcessReason.PROCESS_GROUP_CLEANUP_FAILED in result.cleanup_diagnostics
    canonical = result.canonical_dict()
    assert canonical["primary_execution_event"] == execution_event.value
    assert canonical["process_group_cleanup_success"] is False


@POSIX_ONLY
def test_workspace_absolute_executable_is_rejected_before_spawn(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = tmp_path / "executed"
    fake = workspace / "fakecheckov"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    fake.chmod(0o755)
    request = CommandRequest(argv=(str(fake),), cwd=workspace, workspace_root=workspace)
    with patch.object(process_module.subprocess, "Popen") as popen:
        with pytest.raises(ProcessPolicyError, match="workspace"):
            run_command(request)
        popen.assert_not_called()
    assert not marker.exists()


@POSIX_ONLY
def test_executable_symlink_resolving_into_workspace_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    helper = tmp_path / "helper"
    workspace.mkdir()
    helper.mkdir()
    target = workspace / "fakecheckov"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    link = helper / "fakecheckov"
    link.symlink_to(target)
    request = CommandRequest(
        argv=(str(link),),
        cwd=workspace,
        workspace_root=workspace,
        trusted_helper_dirs=(helper,),
    )
    with patch.object(process_module.subprocess, "Popen") as popen:
        with pytest.raises(ProcessPolicyError, match="workspace"):
            run_command(request)
        popen.assert_not_called()


@POSIX_ONLY
def test_cwd_symlink_swap_is_rejected_immediately_before_spawn(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    work = workspace / "work"
    workspace.mkdir()
    outside.mkdir()
    work.mkdir()
    request = CommandRequest(
        argv=(sys.executable, "-c", "import pathlib; pathlib.Path('ran').touch()"),
        cwd=work,
        workspace_root=workspace,
    )
    work.rmdir()
    work.symlink_to(outside, target_is_directory=True)
    with patch.object(process_module.subprocess, "Popen") as popen:
        with pytest.raises(ProcessPolicyError, match="cwd"):
            run_command(request)
        popen.assert_not_called()
    assert not (outside / "ran").exists()


@POSIX_ONLY
def test_trusted_helper_replacement_into_workspace_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    helper = tmp_path / "helper"
    original = tmp_path / "helper-original"
    candidate_helper = workspace / "candidate-helper"
    workspace.mkdir()
    helper.mkdir()
    candidate_helper.mkdir()
    request = CommandRequest(
        argv=(sys.executable, "-c", "pass"),
        cwd=workspace,
        workspace_root=workspace,
        trusted_helper_dirs=(helper,),
    )
    helper.rename(original)
    helper.symlink_to(candidate_helper, target_is_directory=True)
    with patch.object(process_module.subprocess, "Popen") as popen:
        with pytest.raises(ProcessPolicyError, match="trusted_helper_dirs"):
            run_command(request)
        popen.assert_not_called()


def test_trusted_helper_must_exist_and_be_a_directory(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(ProcessPolicyError, match="trusted_helper_dirs"):
        CommandRequest(argv=(sys.executable, "-c", "pass"), trusted_helper_dirs=(missing,))
    regular_file = tmp_path / "file"
    regular_file.write_text("x", encoding="utf-8")
    with pytest.raises(ProcessPolicyError, match="trusted_helper_dirs"):
        CommandRequest(
            argv=(sys.executable, "-c", "pass"), trusted_helper_dirs=(regular_file,)
        )


def test_observed_and_retained_byte_counts_are_separate_and_bounded() -> None:
    request = CommandRequest(
        argv=(
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'o'*5000); "
            "sys.stderr.buffer.write(b'e'*4000); sys.stdout.flush(); sys.stderr.flush()",
        ),
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
        max_output_bytes=1536,
    )
    result = run_command(request)
    canonical = result.canonical_dict()
    assert result.stdout_retained_bytes == len(result.stdout) <= request.max_stdout_bytes
    assert result.stderr_retained_bytes == len(result.stderr) <= request.max_stderr_bytes
    assert result.stdout_retained_bytes + result.stderr_retained_bytes <= request.max_output_bytes
    assert result.stdout_observed_bytes >= result.stdout_retained_bytes
    assert result.stderr_observed_bytes >= result.stderr_retained_bytes
    assert result.stdout_observed_bytes + result.stderr_observed_bytes > (
        result.stdout_retained_bytes + result.stderr_retained_bytes
    )
    assert canonical["stdout_observed_bytes"] == result.stdout_observed_bytes
    assert canonical["stderr_observed_bytes"] == result.stderr_observed_bytes
    assert canonical["stdout_retained_bytes"] == len(result.stdout)
    assert canonical["stderr_retained_bytes"] == len(result.stderr)
    assert canonical["output_hashes_cover"] == "retained_bytes_only"


def test_public_byte_count_contradictions_are_rejected() -> None:
    with pytest.raises(ProcessPolicyError):
        _result(stdout=b"abc", stdout_retained_bytes=2)
    with pytest.raises(ProcessPolicyError):
        _result(stdout=b"abc", stdout_observed_bytes=2)
