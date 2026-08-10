"""D2.1 acceptance probes for process.py security hardening.

Each test demonstrates an OLD vulnerable behavior (stated in the docstring) and
asserts the CORRECTED behavior after the D2.1 rewrite.

Twelve probes covering the nine independently reproduced defects plus additional
requirements.
"""
from __future__ import annotations

import os
import signal
import sys
import textwrap
import time
from pathlib import Path
from types import MappingProxyType

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from iac_guard_v.enums import Status  # noqa: E402
from iac_guard_v.process import (  # noqa: E402
    PROTECTED_ENV_NAMES,
    CommandRequest,
    CommandResult,
    ProcessPolicyError,
    build_child_environment,
    python_command,
    run_command,
)
from iac_guard_v.redaction import (  # noqa: E402
    REDACTED_MARKER,
    redact_argv,
    redact_credentials,
    redact_detail,
    redact_paths,
)

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX process semantics")


def script(body: str) -> tuple:
    return python_command("-c", textwrap.dedent(body))


# --------------------------------------------------------------------------- #
# Probe 1: Child no longer inherits real HOME (Defect 1)
# --------------------------------------------------------------------------- #
class TestProbe01PrivateHome:
    """OLD: Child inherited the real HOME and could read ~/.aws/credentials.
    NEW: Child gets a private HOME under per-command scratch; real HOME is not passed.
    """

    def test_child_does_not_see_real_home(self) -> None:
        real_home = os.environ.get("HOME", "/nonexistent")
        result = run_command(CommandRequest(
            argv=script("""
                import os
                print(os.environ.get('HOME', 'NONE'))
            """),
        ))
        assert result.status is Status.PASS
        child_home = result.stdout.decode().strip()
        assert child_home != real_home, "child must not see the real HOME"
        assert child_home != "NONE", "child must have a HOME set"
        assert "iac-guard-v" in child_home, "HOME should be in scratch"


# --------------------------------------------------------------------------- #
# Probe 2: PATH='.' with untrusted cwd no longer executes fake binary (Defect 2)
# --------------------------------------------------------------------------- #
class TestProbe02PathInjection:
    """OLD: PATH='.' + untrusted cwd could execute a fake 'checkov' placed in cwd.
    NEW: Executables are resolved to absolute paths from trusted config; relative
    paths and unsafe PATH entries (empty, '.', relative) are rejected.
    """

    def test_relative_executable_rejected(self) -> None:
        """A relative path with directory separator is refused."""
        with pytest.raises(ProcessPolicyError, match="relative executable paths"):
            run_command(CommandRequest(argv=("./malicious",)))

    def test_dot_in_path_does_not_resolve_binary(self, tmp_path: Path) -> None:
        """Even if cwd has a 'checkov', it won't be found via '.' in PATH."""
        fake_bin = tmp_path / "fake_scanner"
        fake_bin.write_text("#!/bin/sh\necho pwned\n")
        fake_bin.chmod(0o755)
        # The binary name alone should not resolve from cwd
        result = run_command(CommandRequest(
            argv=("fake_scanner", "--version"),
            cwd=tmp_path,
            workspace_root=tmp_path,
        ))
        assert result.status is Status.UNSUPPORTED
        assert result.reason_code == "EXECUTABLE_NOT_FOUND"


# --------------------------------------------------------------------------- #
# Probe 3: stderr is now bounded (Defect 3)
# --------------------------------------------------------------------------- #
class TestProbe03StderrBounded:
    """OLD: 1MiB stderr under 64KiB cap returned PASS because only stdout was checked.
    NEW: Both stdout AND stderr are independently capped plus a combined cap.
    Exceeding stderr cap triggers PARTIAL.
    """

    def test_large_stderr_triggers_partial(self) -> None:
        result = run_command(CommandRequest(
            argv=script("""
                import sys
                # Write 1MiB to stderr
                block = b'E' * 65536
                for _ in range(20):
                    sys.stderr.buffer.write(block)
                sys.stderr.flush()
                sys.exit(0)
            """),
            max_stderr_bytes=64 * 1024,
            max_stdout_bytes=64 * 1024,
            max_output_bytes=128 * 1024,
            timeout_seconds=30,
        ))
        assert result.status is Status.PARTIAL, (
            "large stderr must trigger PARTIAL, not PASS"
        )
        assert result.truncated is True


# --------------------------------------------------------------------------- #
# Probe 4: Wall-clock deadline after stream close (Defect 4)
# --------------------------------------------------------------------------- #
class TestProbe04WallClockDeadline:
    """OLD: Process closes stdout/stderr then sleeps; timeout_seconds=1 returned
    after ~3.9s as ERROR not TIMEOUT because deadline was only checked during I/O.
    NEW: Wall-clock deadline enforced via process.wait(remaining) after streams close.
    """

    @POSIX_ONLY
    def test_process_that_closes_streams_then_sleeps_is_timed_out(self) -> None:
        result = run_command(CommandRequest(
            argv=script("""
                import os, sys, time
                sys.stdout.close()
                sys.stderr.close()
                os.close(1)
                os.close(2)
                time.sleep(30)
            """),
            timeout_seconds=2,
        ))
        assert result.status is Status.TIMEOUT, (
            "must be TIMEOUT even when streams close before deadline"
        )
        assert result.timed_out is True
        assert result.duration_ms < 10_000, "should not wait much beyond the deadline"


# --------------------------------------------------------------------------- #
# Probe 5: Grandchild killed with process group (Defect 5)
# --------------------------------------------------------------------------- #
class TestProbe05ProcessGroupKill:
    """OLD: Leader os._exit(0) + grandchild survives; grandchild wrote its marker.
    NEW: After deadline or completion, always signal the process GROUP using saved
    pgid (child pid when start_new_session=True), then wait, then kill.
    """

    @POSIX_ONLY
    def test_grandchild_does_not_survive_group_kill(self, tmp_path: Path) -> None:
        marker = tmp_path / "grandchild-survived"
        result = run_command(CommandRequest(
            argv=script(f"""
                import subprocess, sys, os, time
                subprocess.Popen([sys.executable, "-c",
                    "import time; time.sleep(4); open({str(marker)!r},'w').write('x')"])
                time.sleep(30)
            """),
            timeout_seconds=1,
            cwd=tmp_path,
            workspace_root=tmp_path,
        ))
        assert result.status is Status.TIMEOUT
        time.sleep(6)
        assert not marker.exists(), (
            "grandchild must not survive process-group termination"
        )


# --------------------------------------------------------------------------- #
# Probe 6: env_extra is immutable (Defect 6)
# --------------------------------------------------------------------------- #
class TestProbe06EnvExtraImmutable:
    """OLD: CommandRequest.env_extra was a mutable dict retained by reference.
    Mutating the caller's dict after construction changed the request's env.
    NEW: CommandRequest is frozen+slotted, env_extra deep-copied into
    MappingProxyType at construction.
    """

    def test_env_extra_is_frozen_mapping_proxy(self) -> None:
        original = {"MY_VAR": "original_value"}
        req = CommandRequest(argv=python_command("-c", "pass"), env_extra=original)
        # Mutate the original dict
        original["MY_VAR"] = "MUTATED"
        original["INJECTED"] = "evil"
        # The request must not be affected
        assert req.env_extra["MY_VAR"] == "original_value"
        assert "INJECTED" not in req.env_extra
        assert isinstance(req.env_extra, MappingProxyType)

    def test_env_extra_cannot_be_mutated_directly(self) -> None:
        req = CommandRequest(
            argv=python_command("-c", "pass"),
            env_extra={"SAFE": "value"},
        )
        with pytest.raises(TypeError):
            req.env_extra["NEW_KEY"] = "x"  # type: ignore[index]


# --------------------------------------------------------------------------- #
# Probe 7: Invalid env var names raise ProcessPolicyError (Defect 7)
# --------------------------------------------------------------------------- #
class TestProbe07EnvVarValidation:
    """OLD: 'BAD=KEY' in env_extra raised raw ValueError from Popen.
    NEW: env names validated (no '=', no NUL, no empty) in __post_init__,
    raises ProcessPolicyError.
    """

    def test_env_key_with_equals_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="must not contain '='"):
            CommandRequest(
                argv=python_command("-c", "pass"),
                env_extra={"BAD=KEY": "value"},
            )

    def test_env_key_with_nul_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="must not contain NUL"):
            CommandRequest(
                argv=python_command("-c", "pass"),
                env_extra={"BAD\x00KEY": "value"},
            )

    def test_env_value_with_nul_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="must not contain NUL"):
            CommandRequest(
                argv=python_command("-c", "pass"),
                env_extra={"GOOD_KEY": "bad\x00value"},
            )

    def test_empty_env_key_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="must not be empty"):
            CommandRequest(
                argv=python_command("-c", "pass"),
                env_extra={"": "value"},
            )


# --------------------------------------------------------------------------- #
# Probe 8: CommandResult validates its fields (Defect 8)
# --------------------------------------------------------------------------- #
class TestProbe08CommandResultValidation:
    """OLD: CommandResult accepted malformed values without validation.
    NEW: Frozen+slotted with __post_init__ validation:
    status must be Status enum, argv must be tuple of str,
    stdout/stderr must be bytes, duration >= 0, booleans must be bool.
    """

    def test_status_must_be_enum(self) -> None:
        with pytest.raises(ProcessPolicyError, match="Status enum"):
            CommandResult(
                argv=("test",), status="PASS",  # type: ignore
                exit_code=0, stdout=b"", stderr=b"",
                duration_ms=0, truncated=False, timed_out=False,
                killed_signal=None, reason_code="TEST", detail="",
            )

    def test_stdout_must_be_bytes(self) -> None:
        with pytest.raises(ProcessPolicyError, match="stdout must be bytes"):
            CommandResult(
                argv=("test",), status=Status.PASS,
                exit_code=0, stdout="not bytes",  # type: ignore
                stderr=b"", duration_ms=0, truncated=False,
                timed_out=False, killed_signal=None,
                reason_code="TEST", detail="",
            )

    def test_negative_duration_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="duration_ms must be >= 0"):
            CommandResult(
                argv=("test",), status=Status.PASS,
                exit_code=0, stdout=b"", stderr=b"",
                duration_ms=-1, truncated=False,
                timed_out=False, killed_signal=None,
                reason_code="TEST", detail="",
            )

    def test_truncated_must_be_bool(self) -> None:
        with pytest.raises(ProcessPolicyError, match="truncated must be bool"):
            CommandResult(
                argv=("test",), status=Status.PASS,
                exit_code=0, stdout=b"", stderr=b"",
                duration_ms=0, truncated=1,  # type: ignore
                timed_out=False, killed_signal=None,
                reason_code="TEST", detail="",
            )


# --------------------------------------------------------------------------- #
# Probe 9: redaction.py exists and works (Defect 9)
# --------------------------------------------------------------------------- #
class TestProbe09Redaction:
    """OLD: No redaction.py existed. Credentials could leak into logs.
    NEW: redaction.py with functions to redact credential-shaped values, tokens,
    and local paths from argv and detail strings.
    """

    def test_aws_key_redacted(self) -> None:
        text = "key=AKIAIOSFODNN7EXAMPLE is active"
        result = redact_credentials(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert REDACTED_MARKER in result

    def test_github_token_redacted(self) -> None:
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
        result = redact_credentials(text)
        assert "ghp_" not in result
        assert REDACTED_MARKER in result

    def test_paths_redacted(self) -> None:
        text = "failed at /Users/dev/project/secrets.yaml line 5"
        result = redact_paths(text)
        assert "/Users/dev" not in result
        assert "[PATH]" in result

    def test_redact_argv_preserves_executable(self) -> None:
        argv = ("/usr/bin/checkov", "--token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl")
        result = redact_argv(argv)
        assert result[0] == "/usr/bin/checkov"
        assert "ghp_" not in result[2]


# --------------------------------------------------------------------------- #
# Probe 10: Protected env vars cannot be overridden (Additional requirement)
# --------------------------------------------------------------------------- #
class TestProbe10ProtectedEnvVars:
    """OLD: env_extra could override HOME, PATH, TMPDIR, XDG vars.
    NEW: Protected environment variable names cannot be overridden via env_extra.
    """

    @pytest.mark.parametrize("var", sorted(PROTECTED_ENV_NAMES))
    def test_protected_var_in_env_extra_rejected(self, var: str) -> None:
        with pytest.raises(ProcessPolicyError, match="protected variable"):
            CommandRequest(
                argv=python_command("-c", "pass"),
                env_extra={var: "/evil/path"},
            )


# --------------------------------------------------------------------------- #
# Probe 11: workspace_root confines cwd (Additional requirement)
# --------------------------------------------------------------------------- #
class TestProbe11WorkspaceRootConfinement:
    """OLD: No workspace_root; cwd could point anywhere on disk.
    NEW: workspace_root parameter confines cwd; traversal and symlink escapes rejected.
    """

    def test_cwd_outside_workspace_root_rejected(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        with pytest.raises(ProcessPolicyError, match="outside workspace_root"):
            CommandRequest(
                argv=python_command("-c", "pass"),
                cwd=outside,
                workspace_root=workspace,
            )

    @POSIX_ONLY
    def test_symlink_escape_rejected(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        # Create a symlink inside workspace pointing outside
        link = workspace / "escape"
        link.symlink_to(outside)
        with pytest.raises(ProcessPolicyError, match="outside workspace_root"):
            CommandRequest(
                argv=python_command("-c", "pass"),
                cwd=link,
                workspace_root=workspace,
            )


# --------------------------------------------------------------------------- #
# Probe 12: Scratch cleanup recorded (Additional requirement)
# --------------------------------------------------------------------------- #
class TestProbe12ScratchCleanupRecorded:
    """OLD: shutil.rmtree(ignore_errors=True) silently swallowed cleanup failures.
    NEW: Scratch cleanup success/failure is recorded in CommandResult.
    """

    def test_scratch_cleanup_success_recorded(self) -> None:
        result = run_command(CommandRequest(
            argv=script("print('hello')"),
        ))
        assert result.status is Status.PASS
        assert result.scratch_cleanup_success is True

    def test_scratch_cleanup_field_exists_on_result(self) -> None:
        """CommandResult has the scratch_cleanup_success field."""
        r = CommandResult(
            argv=("test",), status=Status.PASS,
            exit_code=0, stdout=b"", stderr=b"",
            duration_ms=0, truncated=False, timed_out=False,
            killed_signal=None, reason_code="TEST", detail="",
            scratch_cleanup_success=False,
        )
        assert r.scratch_cleanup_success is False
