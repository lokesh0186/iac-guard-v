"""Secure subprocess execution.

Everything this module runs is a scanner or validator invoked against **untrusted**
infrastructure code, usually on a machine that holds credentials. The frozen research
harness shelled out with a timeout and nothing else (audit finding F11): no process-group
termination, no output bound, no environment allowlist, no working-directory isolation.

Eight properties, each of which exists because its absence is exploitable:

1. **Argument arrays only.** Never `shell=True`, never string interpolation. A path, rule
   id, or config value cannot become a command.
2. **Environment allowlist.** The child sees `PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ` and
   explicitly permitted additions. Cloud, Kubernetes, and CI credentials are stripped,
   so a scanner or policy cannot read them and a leak cannot echo them.
3. **Process-group termination.** On timeout the whole group is signalled, then verified
   dead, then killed. Terminating only the direct child leaves orphans holding the
   workspace.
4. **Bounded output.** Reading is capped; exceeding the cap terminates the process and
   reports `PARTIAL` rather than parsing a truncated document as if it were complete.
5. **Isolated scratch.** A private temporary directory per call, `0o700`, removed
   afterwards, exported as `TMPDIR` so the child does not write into the workspace.
6. **Typed classification.** Every ending maps to a `Status`: `PASS`, `FAIL`, `TIMEOUT`,
   `ERROR`, `PARTIAL`, `UNSUPPORTED`. Nothing collapses into a boolean.
7. **Recorded evidence.** Command, exit code, duration, and SHA-256 of stdout and stderr,
   so a report can show what ran without embedding the output itself.
8. **No network of its own.** This module never opens a socket. Network denial for
   children is enforced by the container layer, which is where it is enforceable.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from .enums import Status
from .models import DomainError, canonical_identifier, require_bool, require_int

#: Environment variables a child may always see.
DEFAULT_ENV_ALLOWLIST: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TZ")

#: Prefixes and names that must never reach a child, even if explicitly allowlisted.
#: Credential exposure is not a preference to be overridden by configuration.
CREDENTIAL_DENYLIST_PREFIXES: tuple[str, ...] = (
    "AWS_", "AZURE_", "ARM_", "GOOGLE_", "GCP_", "GCLOUD_", "KUBE", "K8S_",
    "DOCKER_", "GITHUB_", "GITLAB_", "CI_", "BUILDKITE_", "CIRCLE_", "TF_TOKEN_",
    "VAULT_", "OP_", "NPM_TOKEN", "PYPI_", "TWINE_", "SSH_", "GPG_", "GNUPG",
    "ANTHROPIC_", "OPENAI_", "BEDROCK_",
)
CREDENTIAL_DENYLIST_NAMES: frozenset[str] = frozenset({
    "AWS_PROFILE", "KUBECONFIG", "DOCKER_HOST", "GITHUB_TOKEN", "GH_TOKEN",
    "TF_VAR_password", "TF_LOG_PATH", "NETRC", "CURLOPT_PROXY",
})

DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_OUTPUT_BYTES = 25 * 1024 * 1024      # 25 MiB, per the configuration schema
_READ_CHUNK = 64 * 1024
_GRACE_SECONDS = 3.0


class ProcessPolicyError(DomainError):
    """A request this module refuses to execute at all."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_child_environment(
    allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
    extra: Mapping[str, str] | None = None,
    parent: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the child environment: an allowlist, minus anything credential-shaped.

    The denylist is applied **after** the allowlist and after `extra`, so a caller cannot
    re-admit a credential by naming it explicitly. That ordering is the point: an adapter
    that needs `AWS_PROFILE` is asking for something this layer does not grant.
    """
    if parent is None:
        parent = os.environ
    if type(extra) not in (dict, type(None)):
        raise ProcessPolicyError("extra environment must be an exact dict or None")

    env: dict[str, str] = {}
    for name in allowlist:
        key = canonical_identifier(name, "environment variable name")
        if key in parent:
            env[key] = str(parent[key])
    for key, value in (extra or {}).items():
        env[canonical_identifier(key, "environment variable name")] = str(value)

    denied = sorted(
        key for key in env
        if key in CREDENTIAL_DENYLIST_NAMES
        or key.startswith(CREDENTIAL_DENYLIST_PREFIXES)
    )
    for key in denied:
        del env[key]
    return env


@dataclass(frozen=True, slots=True)
class CommandRequest:
    """What to run. Immutable, validated, and never a shell string."""

    argv: tuple
    cwd: Path | None = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    env_allowlist: tuple = DEFAULT_ENV_ALLOWLIST
    env_extra: dict = field(default_factory=dict)
    expected_exit_codes: tuple = (0,)
    isolated_tmpdir: bool = True

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        if type(self.argv) not in (tuple, list) or not self.argv:
            raise ProcessPolicyError("argv must be a non-empty tuple of strings")
        argv = tuple(self.argv)
        for index, part in enumerate(argv):
            if type(part) is not str or not part:
                raise ProcessPolicyError(
                    f"argv[{index}] must be a non-empty string, got {part!r}: arguments "
                    f"are passed as an array, never interpolated into a shell string"
                )
            if "\x00" in part:
                raise ProcessPolicyError(f"argv[{index}] must not contain a NUL byte")
        set_(self, "argv", argv)

        if self.cwd is not None:
            # Filesystem paths are the one deliberate exception to the exact-type rule:
            # `Path("x")` returns `PosixPath` or `WindowsPath`, so `type(x) is Path` is
            # never true. `isinstance` is correct here, and the value is resolved and
            # checked below rather than trusted.
            if not isinstance(self.cwd, Path):
                raise ProcessPolicyError(
                    f"cwd must be a pathlib.Path or None, got {type(self.cwd).__name__}"
                )
            resolved = self.cwd.resolve()
            if not resolved.is_dir():
                raise ProcessPolicyError(
                    f"cwd does not exist or is not a directory: {self.cwd}"
                )
            set_(self, "cwd", resolved)

        if require_int(self.timeout_seconds, "timeout_seconds") <= 0:
            raise ProcessPolicyError("timeout_seconds must be > 0")
        if require_int(self.max_output_bytes, "max_output_bytes") <= 0:
            raise ProcessPolicyError("max_output_bytes must be > 0")
        require_bool(self.isolated_tmpdir, "isolated_tmpdir")

        if type(self.env_allowlist) not in (tuple, list):
            raise ProcessPolicyError("env_allowlist must be a tuple of names")
        set_(self, "env_allowlist", tuple(self.env_allowlist))
        if type(self.env_extra) is not dict:
            raise ProcessPolicyError("env_extra must be an exact dict")
        set_(self, "env_extra", dict(self.env_extra))

        if type(self.expected_exit_codes) not in (tuple, list):
            raise ProcessPolicyError("expected_exit_codes must be a tuple of ints")
        codes = tuple(require_int(c, "expected exit code") for c in self.expected_exit_codes)
        if not codes:
            raise ProcessPolicyError(
                "expected_exit_codes must not be empty: an adapter has to declare its "
                "contract, because success is never inferred from an exit code alone"
            )
        set_(self, "expected_exit_codes", codes)

    @property
    def display_command(self) -> str:
        """For reports and logs. Never parsed, never executed."""
        return " ".join(self.argv)


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Evidence about one execution. Carries a `Status`, never a boolean."""

    argv: tuple
    status: Status
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_ms: int
    truncated: bool
    timed_out: bool
    killed_signal: int | None
    reason_code: str
    detail: str = ""

    @property
    def stdout_sha256(self) -> str:
        return _sha256(self.stdout)

    @property
    def stderr_sha256(self) -> str:
        return _sha256(self.stderr)

    def canonical_dict(self) -> dict:
        """Digests, never the output itself: reports must not carry raw scanner text."""
        return {
            "argv": list(self.argv),
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "timed_out": self.timed_out,
            "killed_signal": self.killed_signal,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
        }


def _terminate_process_group(process: subprocess.Popen) -> int | None:
    """Signal the whole group, wait briefly, then kill. Returns the signal used.

    Terminating only the direct child leaves grandchildren running — a scanner that
    spawns helpers would keep the workspace open after the deadline passed.
    """
    if process.poll() is not None:
        return None
    used = signal.SIGTERM
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        else:  # pragma: no cover - Windows has no process groups in this sense
            process.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        return None

    deadline = time.monotonic() + _GRACE_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return int(used)
        time.sleep(0.05)

    used = signal.SIGKILL
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:  # pragma: no cover
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        process.wait(timeout=_GRACE_SECONDS)
    except subprocess.TimeoutExpired:  # pragma: no cover - unkillable process
        pass
    return int(used)


def run_command(request: CommandRequest) -> CommandResult:
    """Execute one command under the policy above, returning typed evidence.

    Never raises for a failing child: a non-zero exit, a timeout, an oversized output and
    a missing binary are all *results*, classified with a `Status`. Only a request this
    module refuses to run raises `ProcessPolicyError`.
    """
    if type(request) is not CommandRequest:
        raise ProcessPolicyError(
            f"request must be exactly CommandRequest, got {type(request).__name__}"
        )

    if request.cwd is None and shutil.which(request.argv[0]) is None \
            and not Path(request.argv[0]).exists():
        return CommandResult(
            argv=request.argv, status=Status.UNSUPPORTED, exit_code=None,
            stdout=b"", stderr=b"", duration_ms=0, truncated=False, timed_out=False,
            killed_signal=None, reason_code="EXECUTABLE_NOT_FOUND",
            detail=f"{request.argv[0]!r} is not on PATH",
        )

    scratch: str | None = None
    env = build_child_environment(request.env_allowlist, request.env_extra)
    if request.isolated_tmpdir:
        scratch = tempfile.mkdtemp(prefix="iac-guard-v-")
        os.chmod(scratch, 0o700)
        env["TMPDIR"] = scratch

    started = time.monotonic()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_bytes = 0
    truncated = False
    timed_out = False
    killed_signal: int | None = None
    process: subprocess.Popen | None = None

    try:
        popen_kwargs: dict = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "stdin": subprocess.DEVNULL,
            "cwd": str(request.cwd) if request.cwd else None,
            "env": env,
            "close_fds": True,
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True   # its own process group
        try:
            process = subprocess.Popen(request.argv, **popen_kwargs)  # noqa: S603
        except FileNotFoundError as exc:
            return CommandResult(
                argv=request.argv, status=Status.UNSUPPORTED, exit_code=None,
                stdout=b"", stderr=b"", duration_ms=0, truncated=False, timed_out=False,
                killed_signal=None, reason_code="EXECUTABLE_NOT_FOUND", detail=str(exc),
            )
        except (PermissionError, OSError) as exc:
            return CommandResult(
                argv=request.argv, status=Status.ERROR, exit_code=None,
                stdout=b"", stderr=b"", duration_ms=0, truncated=False, timed_out=False,
                killed_signal=None, reason_code="SPAWN_FAILED", detail=str(exc),
            )

        deadline = started + request.timeout_seconds
        assert process.stdout is not None and process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)

        import selectors

        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        open_streams = 2

        while open_streams and not truncated:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(timeout=min(remaining, 0.25)):
                chunk = key.fileobj.read(_READ_CHUNK)  # type: ignore[union-attr]
                if chunk is None:
                    continue
                if chunk == b"":
                    selector.unregister(key.fileobj)
                    open_streams -= 1
                    continue
                if key.data == "stdout":
                    stdout_chunks.append(chunk)
                    stdout_bytes += len(chunk)
                    if stdout_bytes > request.max_output_bytes:
                        truncated = True
                        break
                else:
                    stderr_chunks.append(chunk)
            if process.poll() is not None and open_streams == 0:
                break
        selector.close()

        if timed_out or truncated:
            killed_signal = _terminate_process_group(process)
        exit_code = process.poll()
        if exit_code is None:
            try:
                exit_code = process.wait(timeout=_GRACE_SECONDS)
            except subprocess.TimeoutExpired:  # pragma: no cover
                killed_signal = _terminate_process_group(process)
                exit_code = process.poll()
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:  # pragma: no cover
                        pass
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout = b"".join(stdout_chunks)[: request.max_output_bytes]
    stderr = b"".join(stderr_chunks)

    if timed_out:
        status, reason = Status.TIMEOUT, "DEADLINE_EXCEEDED"
        detail = f"exceeded {request.timeout_seconds}s and the process group was signalled"
    elif truncated:
        status, reason = Status.PARTIAL, "OUTPUT_LIMIT_EXCEEDED"
        detail = (f"stdout exceeded {request.max_output_bytes} bytes; the process group "
                  f"was signalled and the output must not be parsed as complete")
    elif exit_code is None:
        status, reason = Status.ERROR, "NO_EXIT_STATUS"
        detail = "the child produced no exit status"
    elif exit_code < 0:
        status, reason = Status.ERROR, "KILLED_BY_SIGNAL"
        killed_signal = -exit_code
        detail = f"terminated by signal {killed_signal}"
    elif exit_code in request.expected_exit_codes:
        status, reason = Status.PASS, "COMPLETED_WITHIN_CONTRACT"
        detail = ""
    else:
        status, reason = Status.ERROR, "EXIT_CODE_OUTSIDE_CONTRACT"
        detail = (f"exit code {exit_code} is not in the adapter's declared contract "
                  f"{list(request.expected_exit_codes)}")

    return CommandResult(
        argv=request.argv, status=status, exit_code=exit_code, stdout=stdout,
        stderr=stderr, duration_ms=duration_ms, truncated=truncated,
        timed_out=timed_out, killed_signal=killed_signal, reason_code=reason,
        detail=detail,
    )


def python_command(*args: str) -> tuple:
    """The current interpreter plus arguments, for tests and internal helpers."""
    return (sys.executable, *args)
