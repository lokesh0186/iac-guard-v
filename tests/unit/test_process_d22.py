"""D2.2 acceptance probes for process.py and redaction.py security hardening.

Each test demonstrates a DEFECT that was independently reproduced and asserts
the CORRECTED behavior after the D2.2 fixes.

Defects covered:
A. Process group termination — lingering descendants are killed
B. Combined output cap — stdout + stderr never exceeds max_output_bytes
C. Redaction in canonical_dict — secrets and paths never leak
D. Cleanup as a typed gate — scratch failure cannot return PASS
E. CommandResult consistency — contradictory states are rejected
F. Stop inheriting parent PATH — child never sees parent PATH entries
G. Mandatory workspace boundary — cwd without workspace_root rejected
H. Record resolved executable — canonical_dict includes binary name
"""
from __future__ import annotations

import os
import shutil
import signal
import sys
import textwrap
import time
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from iac_guard_v.enums import Status  # noqa: E402
from iac_guard_v.process import (  # noqa: E402
    MINIMAL_SYSTEM_PATH,
    CommandRequest,
    CommandResult,
    ProcessPolicyError,
    python_command,
    run_command,
)
from iac_guard_v.redaction import (  # noqa: E402
    REDACTED_MARKER,
    REDACTED_PATH_MARKER,
    display_command,
    redact_argv,
    redact_detail,
    redact_option_values,
    redact_paths,
)

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX process semantics")


def script(body: str) -> tuple:
    return python_command("-c", textwrap.dedent(body))


# =========================================================================== #
# A. Process group termination
# =========================================================================== #
class TestDefectA_ProcessGroupTermination:
    """D2.2 Defect A: After the command completes, ALWAYS check if the process
    group still exists. If leader exits cleanly but descendants remain, status
    must NOT be PASS.
    """

    @POSIX_ONLY
    def test_leader_exits_cleanly_but_background_child_trapped(self, tmp_path: Path) -> None:
        """Leader starts background child that traps TERM, redirects pipes, leader
        exits 0. Result must NOT be PASS, marker never appears."""
        marker = tmp_path / "child-survived"
        result = run_command(CommandRequest(
            argv=script(f"""
                import subprocess, sys, os
                # Background child that traps SIGTERM and tries to write marker
                child = subprocess.Popen([
                    sys.executable, "-c",
                    "import signal, time, os\\n"
                    "signal.signal(signal.SIGTERM, lambda *a: None)\\n"
                    "time.sleep(5)\\n"
                    "open({str(marker)!r}, 'w').write('survived')\\n"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Leader exits immediately with 0
                sys.exit(0)
            """),
            timeout_seconds=10,
            cwd=tmp_path,
            workspace_root=tmp_path,
        ))
        # Leader exited 0 but descendants were found — must NOT be PASS
        assert result.status is not Status.PASS, (
            "lingering descendants must prevent PASS status"
        )
        # Wait and verify marker never appears
        time.sleep(6)
        assert not marker.exists(), "background child must be terminated"

    @POSIX_ONLY
    def test_leader_sleeps_until_timeout_child_ignores_term(self, tmp_path: Path) -> None:
        """Leader sleeps until timeout, child ignores TERM. Status is TIMEOUT,
        marker never appears."""
        marker = tmp_path / "child-survived-timeout"
        result = run_command(CommandRequest(
            argv=script(f"""
                import subprocess, sys, os, time
                child = subprocess.Popen([
                    sys.executable, "-c",
                    "import signal, time\\n"
                    "signal.signal(signal.SIGTERM, lambda *a: None)\\n"
                    "time.sleep(10)\\n"
                    "open({str(marker)!r}, 'w').write('survived')\\n"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(30)
            """),
            timeout_seconds=2,
            cwd=tmp_path,
            workspace_root=tmp_path,
        ))
        assert result.status is Status.TIMEOUT
        time.sleep(6)
        assert not marker.exists(), "child ignoring TERM must still be killed"

    @POSIX_ONLY
    def test_both_leader_and_child_ignore_term_sigkill_reaches_all(self, tmp_path: Path) -> None:
        """Both leader and child ignore TERM. SIGKILL must reach all, no survivor."""
        marker = tmp_path / "unkillable-survived"
        result = run_command(CommandRequest(
            argv=script(f"""
                import subprocess, sys, os, signal, time
                signal.signal(signal.SIGTERM, lambda *a: None)
                child = subprocess.Popen([
                    sys.executable, "-c",
                    "import signal, time\\n"
                    "signal.signal(signal.SIGTERM, lambda *a: None)\\n"
                    "time.sleep(10)\\n"
                    "open({str(marker)!r}, 'w').write('survived')\\n"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(30)
            """),
            timeout_seconds=2,
            cwd=tmp_path,
            workspace_root=tmp_path,
        ))
        assert result.status is Status.TIMEOUT
        time.sleep(6)
        assert not marker.exists(), "SIGKILL must reach all processes in group"


# =========================================================================== #
# B. Combined output cap
# =========================================================================== #
class TestDefectB_CombinedOutputCap:
    """D2.2 Defect B: Track combined bytes. With max_output_bytes=65536 and
    50k on each stream, retained total must be <= 65536.
    """

    def test_combined_cap_enforced(self) -> None:
        """50k stdout + 50k stderr under 65536 combined cap -> total <= 65536."""
        result = run_command(CommandRequest(
            argv=script("""
                import sys
                # Write 50k to stdout
                sys.stdout.buffer.write(b'O' * 51200)
                sys.stdout.flush()
                # Write 50k to stderr
                sys.stderr.buffer.write(b'E' * 51200)
                sys.stderr.flush()
                sys.exit(0)
            """),
            max_output_bytes=65536,
            max_stdout_bytes=65536,
            max_stderr_bytes=65536,
            timeout_seconds=30,
        ))
        total_retained = len(result.stdout) + len(result.stderr)
        assert total_retained <= 65536, (
            f"combined output must not exceed max_output_bytes; got {total_retained}"
        )
        assert result.status is Status.PARTIAL
        assert result.truncated is True


# =========================================================================== #
# C. Redaction in canonical_dict
# =========================================================================== #
class TestDefectC_RedactionInCanonicalDict:
    """D2.2 Defect C: canonical_dict must redact secrets and paths."""

    def test_token_after_sensitive_flag_absent_from_canonical_dict(self) -> None:
        """Token value after --token must be redacted in canonical_dict."""
        r = CommandResult(
            argv=("/usr/bin/scanner", "--token", "super-secret-token-value123"),
            status=Status.ERROR,
            exit_code=1,
            stdout=b"",
            stderr=b"",
            duration_ms=100,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code="EXIT_CODE_OUTSIDE_CONTRACT",
            detail="failed at /Users/dev/project/main.tf",
            resolved_executable="/usr/bin/scanner",
        )
        cd = r.canonical_dict()
        argv_str = " ".join(cd["argv"])
        assert "super-secret-token-value123" not in argv_str
        assert REDACTED_MARKER in argv_str

    def test_path_absent_from_canonical_dict(self) -> None:
        """Local paths like /Users/... must be redacted in canonical_dict detail."""
        r = CommandResult(
            argv=("/usr/bin/scanner", "/Users/dev/project/main.tf"),
            status=Status.ERROR,
            exit_code=1,
            stdout=b"",
            stderr=b"",
            duration_ms=100,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code="EXIT_CODE_OUTSIDE_CONTRACT",
            detail="error processing /Users/dev/project/secrets.yaml",
            resolved_executable="/usr/bin/scanner",
        )
        cd = r.canonical_dict()
        assert "/Users/dev" not in str(cd["argv"])
        assert "/Users/dev" not in cd["detail"]

    def test_detail_redacted_in_canonical_dict(self) -> None:
        """Detail field must have credentials and paths stripped."""
        r = CommandResult(
            argv=("scanner",),
            status=Status.ERROR,
            exit_code=1,
            stdout=b"",
            stderr=b"",
            duration_ms=50,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code="EXIT_CODE_OUTSIDE_CONTRACT",
            detail="token=mysecrettoken1234567890 at /home/user/.config/app",
            resolved_executable="/usr/bin/scanner",
        )
        cd = r.canonical_dict()
        assert "mysecrettoken1234567890" not in cd["detail"]
        assert "/home/user" not in cd["detail"]

    def test_display_command_is_redacted(self) -> None:
        """CommandRequest.display_command must be redacted."""
        req = CommandRequest(
            argv=("scanner", "--token", "my-secret-value", "/Users/dev/file.tf"),
        )
        dc = req.display_command
        assert "my-secret-value" not in dc
        assert "/Users/dev" not in dc

    def test_urls_not_redacted_in_paths(self) -> None:
        """URLs must NOT be redacted by path redaction."""
        text = "downloading from https://registry.terraform.io/modules/foo"
        result = redact_paths(text)
        assert "https://registry.terraform.io" in result


# =========================================================================== #
# D. Cleanup as a typed gate
# =========================================================================== #
class TestDefectD_CleanupTypedGate:
    """D2.2 Defect D: If scratch cleanup fails and command otherwise succeeded,
    status must be ERROR with reason SCRATCH_CLEANUP_FAILED.
    """

    def test_cleanup_failure_cannot_return_pass(self, monkeypatch) -> None:
        """Monkeypatched rmtree failure must produce ERROR, not PASS."""
        original_rmtree = shutil.rmtree
        call_count = [0]

        def failing_rmtree(path, *args, **kwargs):
            call_count[0] += 1
            raise OSError("permission denied (simulated)")

        monkeypatch.setattr(shutil, "rmtree", failing_rmtree)
        result = run_command(CommandRequest(
            argv=script("print('hello')"),
        ))
        assert result.status is not Status.PASS, (
            "cleanup failure must not allow PASS status"
        )
        assert result.status is Status.ERROR
        assert result.reason_code == "SCRATCH_CLEANUP_FAILED"
        assert result.scratch_cleanup_success is False

    def test_cleanup_failure_in_canonical_output(self, monkeypatch) -> None:
        """scratch_cleanup_success must appear in canonical_dict."""
        def failing_rmtree(path, *args, **kwargs):
            raise OSError("simulated failure")

        monkeypatch.setattr(shutil, "rmtree", failing_rmtree)
        result = run_command(CommandRequest(
            argv=script("print('ok')"),
        ))
        cd = result.canonical_dict()
        assert "scratch_cleanup_success" in cd
        assert cd["scratch_cleanup_success"] is False


# =========================================================================== #
# E. CommandResult consistency
# =========================================================================== #
class TestDefectE_CommandResultConsistency:
    """D2.2 Defect E: Reject contradictory states in __post_init__."""

    def _make(self, **overrides):
        defaults = dict(
            argv=("test",),
            status=Status.PASS,
            exit_code=0,
            stdout=b"",
            stderr=b"",
            duration_ms=100,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code="COMPLETED_WITHIN_CONTRACT",
            detail="",
        )
        defaults.update(overrides)
        return CommandResult(**defaults)

    def test_pass_with_timed_out_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="contradictory"):
            self._make(timed_out=True)

    def test_pass_with_truncated_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="contradictory"):
            self._make(truncated=True)

    def test_pass_with_killed_signal_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="contradictory"):
            self._make(killed_signal=9)

    def test_pass_with_scratch_cleanup_false_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="contradictory"):
            self._make(scratch_cleanup_success=False)

    def test_timeout_with_timed_out_false_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="contradictory"):
            self._make(
                status=Status.TIMEOUT,
                timed_out=False,
                reason_code="DEADLINE_EXCEEDED",
            )

    def test_completed_within_contract_with_non_pass_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="contradictory"):
            self._make(
                status=Status.ERROR,
                reason_code="COMPLETED_WITHIN_CONTRACT",
            )

    def test_deadline_exceeded_with_timed_out_false_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="contradictory"):
            self._make(
                status=Status.ERROR,
                reason_code="DEADLINE_EXCEEDED",
                timed_out=False,
            )


# =========================================================================== #
# F. Stop inheriting parent PATH
# =========================================================================== #
class TestDefectF_NoParentPath:
    """D2.2 Defect F: Child PATH must ONLY be minimal system + trusted_helper_dirs.
    Never entries from parent PATH."""

    @POSIX_ONLY
    def test_attacker_dir_in_parent_path_not_in_child(self, tmp_path: Path) -> None:
        """An absolute dir in parent PATH cannot reach child helpers."""
        attacker_dir = tmp_path / "attacker_bin"
        attacker_dir.mkdir()
        fake_bin = attacker_dir / "fake_tool"
        fake_bin.write_text("#!/bin/sh\necho pwned\n")
        fake_bin.chmod(0o755)

        # Even if parent PATH has attacker_dir, child should not find it
        with patch.dict(os.environ, {"PATH": f"{attacker_dir}:/usr/bin:/bin"}):
            result = run_command(CommandRequest(
                argv=("fake_tool",),
            ))
        assert result.status is Status.UNSUPPORTED
        assert result.reason_code == "EXECUTABLE_NOT_FOUND"

    @POSIX_ONLY
    def test_child_path_is_only_minimal_system(self) -> None:
        """Child sees only the minimal system PATH."""
        result = run_command(CommandRequest(
            argv=script("import os; print(os.environ.get('PATH', ''))"),
        ))
        assert result.status is Status.PASS
        child_path = result.stdout.decode().strip()
        assert child_path == MINIMAL_SYSTEM_PATH

    @POSIX_ONLY
    def test_trusted_helper_dirs_added_to_path(self, tmp_path: Path) -> None:
        """trusted_helper_dirs are appended to child PATH."""
        helper_dir = tmp_path / "helpers"
        helper_dir.mkdir()
        # Use workspace in a sibling dir so helper_dir is not inside it
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        result = run_command(CommandRequest(
            argv=script("import os; print(os.environ.get('PATH', ''))"),
            cwd=workspace,
            workspace_root=workspace,
            trusted_helper_dirs=(helper_dir,),
        ))
        assert result.status is Status.PASS
        child_path = result.stdout.decode().strip()
        assert str(helper_dir.resolve()) in child_path

    def test_blocked_env_vars_not_in_child(self) -> None:
        """LD_PRELOAD, PYTHONPATH, etc. are blocked."""
        result = run_command(CommandRequest(
            argv=script("""
                import os
                blocked = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH',
                           'PYTHONHOME', 'BASH_ENV', 'NODE_OPTIONS',
                           'RUBYOPT', 'PERL5LIB']
                found = [v for v in blocked if v in os.environ]
                print(','.join(found) if found else 'NONE')
            """),
            env_allowlist=("LD_PRELOAD", "PYTHONPATH", "BASH_ENV",
                           "NODE_OPTIONS", "RUBYOPT", "PERL5LIB"),
        ))
        assert result.status is Status.PASS
        assert result.stdout.decode().strip() == "NONE"


# =========================================================================== #
# G. Mandatory workspace boundary
# =========================================================================== #
class TestDefectG_MandatoryWorkspaceBoundary:
    """D2.2 Defect G: If cwd is supplied, workspace_root is REQUIRED."""

    def test_cwd_without_workspace_root_rejected(self, tmp_path: Path) -> None:
        """cwd=<dir>, workspace_root=None must be rejected."""
        with pytest.raises(ProcessPolicyError, match="workspace_root is required"):
            CommandRequest(
                argv=python_command("-c", "pass"),
                cwd=tmp_path,
            )

    def test_neither_cwd_nor_workspace_accepted(self) -> None:
        """If neither is supplied, use private scratch as cwd."""
        result = run_command(CommandRequest(
            argv=script("import os; print(os.getcwd())"),
        ))
        assert result.status is Status.PASS
        # The cwd should be in scratch (contains 'iac-guard-v')
        cwd_output = result.stdout.decode().strip()
        assert "iac-guard-v" in cwd_output


# =========================================================================== #
# H. Record resolved executable
# =========================================================================== #
class TestDefectH_ResolvedExecutable:
    """D2.2 Defect H: CommandResult includes resolved_executable in canonical_dict."""

    def test_resolved_executable_in_result(self) -> None:
        """resolved_executable is populated after execution."""
        result = run_command(CommandRequest(
            argv=script("print('hi')"),
        ))
        assert result.status is Status.PASS
        assert result.resolved_executable != ""
        assert "python" in result.resolved_executable.lower() or "Python" in result.resolved_executable

    def test_resolved_executable_in_canonical_dict(self) -> None:
        """canonical_dict includes resolved_executable with binary name."""
        result = run_command(CommandRequest(
            argv=script("print('hi')"),
        ))
        cd = result.canonical_dict()
        assert "resolved_executable" in cd
        assert cd["resolved_executable"] != ""
        # Should contain the binary name (python3 or similar)
        assert "python" in cd["resolved_executable"].lower() or "Python" in cd["resolved_executable"]

    def test_resolved_executable_machine_path_redacted(self) -> None:
        """Machine-specific path parts should be redacted in canonical_dict."""
        r = CommandResult(
            argv=("scanner",),
            status=Status.ERROR,
            exit_code=1,
            stdout=b"",
            stderr=b"",
            duration_ms=50,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code="EXIT_CODE_OUTSIDE_CONTRACT",
            detail="",
            resolved_executable="/Users/developer/tools/bin/scanner",
        )
        cd = r.canonical_dict()
        # Machine path should be redacted but binary name preserved
        assert "/Users/developer" not in cd["resolved_executable"]
        assert "scanner" in cd["resolved_executable"]
