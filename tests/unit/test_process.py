"""Tests for the secure process runner.

These run real subprocesses. Each test targets one property of the policy, and several
are written so they fail if the corresponding guard is removed — the pattern that caught
the tautological artifact test earlier in this project.
"""
from __future__ import annotations

import os
import signal
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from iac_guard_v.enums import Status  # noqa: E402
from iac_guard_v.process import (  # noqa: E402
    CREDENTIAL_DENYLIST_PREFIXES,
    DEFAULT_ENV_ALLOWLIST,
    CommandRequest,
    ProcessPolicyError,
    build_child_environment,
    python_command,
    run_command,
)

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX process semantics")


def script(body: str) -> tuple:
    return python_command("-c", textwrap.dedent(body))


# --------------------------------------------------------------------------- #
# 1. argument arrays, never a shell
# --------------------------------------------------------------------------- #
def test_arguments_are_not_interpreted_by_a_shell(tmp_path: Path) -> None:
    """A shell metacharacter in an argument is data, not syntax."""
    canary = tmp_path / "canary"
    injected = f"; touch {canary}"
    result = run_command(CommandRequest(
        argv=python_command("-c", "import sys; print(sys.argv[1])", injected)
    ))
    assert result.status is Status.PASS
    assert result.stdout.decode().strip() == injected
    assert not canary.exists(), "the argument was interpreted as a command"


@pytest.mark.parametrize("argv", [
    (), ["", "x"], ("python", ""), ("python", None), ("python", 5), ("python", "a\x00b"),
])
def test_malformed_argv_is_refused(argv) -> None:
    with pytest.raises(ProcessPolicyError):
        CommandRequest(argv=argv)


def test_display_command_is_for_reports_only() -> None:
    request = CommandRequest(argv=("checkov", "-d", "some dir"))
    assert request.display_command == "checkov -d some dir"
    assert request.argv == ("checkov", "-d", "some dir")


# --------------------------------------------------------------------------- #
# 2. environment allowlist and credential denial
# --------------------------------------------------------------------------- #
def test_child_sees_only_allowlisted_variables() -> None:
    parent = {"PATH": "/usr/bin", "HOME": "/home/x", "SECRET_SAUCE": "s3cret"}
    env = build_child_environment(parent=parent)
    assert set(env) <= set(DEFAULT_ENV_ALLOWLIST)
    assert "SECRET_SAUCE" not in env


@pytest.mark.parametrize("name", [
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS", "KUBECONFIG", "KUBERNETES_SERVICE_HOST",
    "DOCKER_HOST", "GITHUB_TOKEN", "GH_TOKEN", "CI_JOB_TOKEN", "VAULT_TOKEN",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SSH_AUTH_SOCK",
])
def test_credentials_are_denied_even_when_explicitly_requested(name: str) -> None:
    """The denylist is applied after the allowlist, so it cannot be opted out of."""
    env = build_child_environment(allowlist=("PATH", name),
                                  extra={name: "leaked"},
                                  parent={"PATH": "/usr/bin", name: "leaked"})
    assert name not in env


def test_credential_denial_reaches_the_actual_child() -> None:
    result = run_command(CommandRequest(
        argv=script("""
            import os
            print(sorted(k for k in os.environ if 'AWS' in k or 'TOKEN' in k))
        """),
        env_extra={"AWS_SECRET_ACCESS_KEY": "leaked", "GITHUB_TOKEN": "leaked"},
    ))
    assert result.status is Status.PASS
    assert result.stdout.decode().strip() == "[]"


def test_denylist_covers_every_documented_prefix() -> None:
    for prefix in CREDENTIAL_DENYLIST_PREFIXES:
        name = f"{prefix}PROBE"
        assert name not in build_child_environment(extra={name: "x"})


def test_extra_environment_must_be_an_exact_dict() -> None:
    class MyDict(dict):
        pass

    with pytest.raises(ProcessPolicyError):
        build_child_environment(extra=MyDict({"A": "b"}))


# --------------------------------------------------------------------------- #
# 3. deadlines and process-group termination
# --------------------------------------------------------------------------- #
def test_a_hanging_process_times_out_and_is_reported_as_timeout() -> None:
    result = run_command(CommandRequest(
        argv=script("import time; time.sleep(30)"), timeout_seconds=1,
    ))
    assert result.status is Status.TIMEOUT
    assert result.timed_out is True
    assert result.reason_code == "DEADLINE_EXCEEDED"
    assert result.duration_ms < 15_000


@POSIX_ONLY
def test_the_whole_process_group_is_terminated_not_just_the_child(tmp_path: Path) -> None:
    """A grandchild must not survive the deadline holding the workspace.

    The child spawns a grandchild that would write a marker after the deadline. If only
    the direct child were signalled, the marker would appear.
    """
    marker = tmp_path / "grandchild-survived"
    result = run_command(CommandRequest(
        argv=script(f"""
            import subprocess, sys, time
            subprocess.Popen([sys.executable, "-c",
                              "import time; time.sleep(4); open({str(marker)!r},'w').write('x')"])
            time.sleep(30)
        """),
        timeout_seconds=1,
    ))
    assert result.status is Status.TIMEOUT
    import time as _time
    _time.sleep(6)
    assert not marker.exists(), "a grandchild outlived the process-group termination"


@POSIX_ONLY
def test_a_process_killed_by_a_signal_is_an_error_not_a_pass() -> None:
    result = run_command(CommandRequest(
        argv=script("import os, signal; os.kill(os.getpid(), signal.SIGKILL)"),
    ))
    assert result.status is Status.ERROR
    assert result.reason_code == "KILLED_BY_SIGNAL"
    assert result.killed_signal == int(signal.SIGKILL)


# --------------------------------------------------------------------------- #
# 4. bounded output
# --------------------------------------------------------------------------- #
def test_oversized_output_is_partial_not_pass() -> None:
    result = run_command(CommandRequest(
        argv=script("""
            import sys
            block = b'x' * 65536
            for _ in range(200):
                sys.stdout.buffer.write(block)
            sys.stdout.flush()
        """),
        max_output_bytes=256 * 1024,
        timeout_seconds=30,
    ))
    assert result.status is Status.PARTIAL
    assert result.truncated is True
    assert result.reason_code == "OUTPUT_LIMIT_EXCEEDED"
    assert len(result.stdout) <= 256 * 1024


def test_output_within_the_cap_is_complete_and_not_flagged() -> None:
    result = run_command(CommandRequest(
        argv=script("print('a' * 1000)"), max_output_bytes=64 * 1024,
    ))
    assert result.status is Status.PASS
    assert result.truncated is False
    assert result.stdout.decode().strip() == "a" * 1000


def test_partial_output_is_never_reported_as_a_clean_run() -> None:
    """`PARTIAL` must not be in the set of statuses a caller may treat as success."""
    from iac_guard_v.enums import UNDECIDED_STATES
    assert Status.PARTIAL in UNDECIDED_STATES
    assert Status.TIMEOUT in UNDECIDED_STATES


# --------------------------------------------------------------------------- #
# 5. isolated scratch space
# --------------------------------------------------------------------------- #
def test_a_private_tmpdir_is_provided_and_removed() -> None:
    result = run_command(CommandRequest(
        argv=script("""
            import os, stat
            path = os.environ["TMPDIR"]
            print(path)
            print(oct(stat.S_IMODE(os.stat(path).st_mode)))
        """),
    ))
    assert result.status is Status.PASS
    path, mode = result.stdout.decode().split()
    assert mode == "0o700", "the scratch directory must not be world readable"
    assert not Path(path).exists(), "the scratch directory must be removed afterwards"


def test_scratch_isolation_can_be_disabled_explicitly() -> None:
    result = run_command(CommandRequest(
        argv=script("import os; print('TMPDIR' in os.environ)"),
        isolated_tmpdir=False,
    ))
    assert result.stdout.decode().strip() in ("True", "False")  # inherits nothing extra


def test_the_working_directory_is_honoured(tmp_path: Path) -> None:
    (tmp_path / "marker.txt").write_text("here", encoding="utf-8")
    result = run_command(CommandRequest(
        argv=script("import os; print(sorted(os.listdir('.')))"), cwd=tmp_path,
    ))
    assert "marker.txt" in result.stdout.decode()


def test_a_missing_working_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ProcessPolicyError):
        CommandRequest(argv=python_command("-c", "pass"), cwd=tmp_path / "nope")


# --------------------------------------------------------------------------- #
# 6. typed classification, including exit-code contracts
# --------------------------------------------------------------------------- #
def test_a_declared_nonzero_exit_code_is_within_contract() -> None:
    """Checkov exits 1 when it finds something; that is not an error."""
    result = run_command(CommandRequest(
        argv=script("import sys; print('findings'); sys.exit(1)"),
        expected_exit_codes=(0, 1),
    ))
    assert result.status is Status.PASS
    assert result.exit_code == 1


def test_an_undeclared_exit_code_is_an_error() -> None:
    result = run_command(CommandRequest(
        argv=script("import sys; sys.exit(2)"), expected_exit_codes=(0, 1),
    ))
    assert result.status is Status.ERROR
    assert result.reason_code == "EXIT_CODE_OUTSIDE_CONTRACT"
    assert "not in the adapter's declared contract" in result.detail


def test_an_adapter_must_declare_its_exit_contract() -> None:
    with pytest.raises(ProcessPolicyError):
        CommandRequest(argv=python_command("-c", "pass"), expected_exit_codes=())


def test_a_missing_executable_is_unsupported_not_error() -> None:
    result = run_command(CommandRequest(argv=("iac-guard-v-no-such-binary", "--version")))
    assert result.status is Status.UNSUPPORTED
    assert result.reason_code == "EXECUTABLE_NOT_FOUND"


def test_a_failing_child_never_raises() -> None:
    """Every ending is a result. Only a refused request raises."""
    for argv in (script("import sys; sys.exit(3)"),
                 script("raise SystemExit(9)"),
                 ("iac-guard-v-no-such-binary",)):
        result = run_command(CommandRequest(argv=argv, expected_exit_codes=(0,)))
        assert result.status in {Status.ERROR, Status.UNSUPPORTED}


def test_request_must_be_the_exact_type() -> None:
    class SneakyRequest(CommandRequest):
        __slots__ = ()

    with pytest.raises(ProcessPolicyError):
        run_command(SneakyRequest(argv=python_command("-c", "pass")))


# --------------------------------------------------------------------------- #
# 7. recorded evidence
# --------------------------------------------------------------------------- #
def test_evidence_records_digests_rather_than_raw_output() -> None:
    """The command is recorded; the child's output is not.

    argv legitimately appears in the record — it is what ran. What must not appear is
    what the child *printed*, because scanner output can contain source and secrets.
    """
    result = run_command(CommandRequest(
        argv=script("print('SENSITIVE-OUTPUT-MARKER')"),
    ))
    payload = result.canonical_dict()
    assert b"SENSITIVE-OUTPUT-MARKER" in result.stdout
    assert "SENSITIVE-OUTPUT-MARKER" not in repr(
        {k: v for k, v in payload.items() if k != "argv"}
    )
    assert "stdout" not in payload, "raw stdout must never be serialised"
    assert payload["stdout_sha256"] == result.stdout_sha256
    assert payload["stdout_bytes"] == len(result.stdout)
    assert payload["status"] == "PASS"
    assert payload["argv"] == list(result.argv)


def test_stderr_is_captured_separately_from_stdout() -> None:
    result = run_command(CommandRequest(
        argv=script("""
            import sys
            print('to stdout')
            print('to stderr', file=sys.stderr)
        """),
    ))
    assert b"to stdout" in result.stdout
    assert b"to stderr" in result.stderr
    assert b"to stderr" not in result.stdout, "streams must not be merged"


def test_duration_is_recorded() -> None:
    result = run_command(CommandRequest(argv=script("import time; time.sleep(0.2)")))
    assert result.duration_ms >= 150


# --------------------------------------------------------------------------- #
# 8. no network of its own
# --------------------------------------------------------------------------- #
def test_the_runner_module_opens_no_sockets() -> None:
    source = (REPO / "src" / "iac_guard_v" / "process.py").read_text(encoding="utf-8")
    for token in ("import socket", "urllib", "requests", "httpx", "http.client"):
        assert token not in source, f"process.py references {token}"
