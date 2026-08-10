"""Secure subprocess execution with reduced isolation.

.. warning::

    Host-native execution is NOT a sandbox. This module provides *reduced isolation*:
    environment stripping, output bounding, process-group termination, private scratch
    directories, and workspace-root confinement. It does **not** prevent a determined
    child from accessing host resources outside the workspace. True containment requires
    a container or VM layer above this module.

Eight properties, each of which exists because its absence is exploitable:

1. **Argument arrays only.** Never `shell=True`, never string interpolation.
2. **Environment allowlist.** The child sees only explicitly permitted variables.
   Cloud, Kubernetes, and CI credentials are stripped. HOME, TMPDIR, PATH and XDG
   directories are set to private scratch locations; env_extra cannot override them.
3. **Process-group termination.** On timeout the whole group is signalled (via saved
   pgid), then verified dead, then killed — regardless of stream state.
4. **Bounded output.** Both stdout AND stderr are independently capped, plus a
   combined cap. Exceeding any cap terminates the process and reports PARTIAL.
5. **Isolated scratch.** A private temporary directory per call with private HOME,
   TMPDIR, and XDG directories. Cleanup failures are recorded, never silently ignored.
6. **Typed classification.** Every ending maps to a `Status`.
7. **Recorded evidence.** Command, exit code, duration, SHA-256 of outputs.
8. **No network of its own.** This module never opens a socket.

Additionally:
- Executables are resolved to absolute paths before spawn; relative paths rejected.
- workspace_root confines cwd via symlink-aware resolution.
- Wall-clock deadline enforced after stream close via process.wait(remaining).
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence

from .enums import Status
from .models import DomainError, canonical_identifier, require_bool, require_int

logger = logging.getLogger(__name__)

#: Environment variables a child may always see (values come from scratch dirs).
DEFAULT_ENV_ALLOWLIST: tuple[str, ...] = ("LANG", "LC_ALL", "TZ")

#: Protected env var names that env_extra cannot override.
PROTECTED_ENV_NAMES: frozenset[str] = frozenset({
    "HOME", "TMPDIR", "PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
})

#: Prefixes and names that must never reach a child.
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
DEFAULT_MAX_OUTPUT_BYTES = 25 * 1024 * 1024      # 25 MiB combined cap
DEFAULT_MAX_STDOUT_BYTES = 25 * 1024 * 1024      # 25 MiB per-stream
DEFAULT_MAX_STDERR_BYTES = 25 * 1024 * 1024      # 25 MiB per-stream
_READ_CHUNK = 64 * 1024
_GRACE_SECONDS = 3.0


class ProcessPolicyError(DomainError):
    """A request this module refuses to execute at all."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_safe_path_entry(entry: str) -> bool:
    """Return True if a PATH entry is safe (absolute, not empty, not relative)."""
    if not entry:
        return False
    if entry == ".":
        return False
    if not os.path.isabs(entry):
        return False
    return True


def _resolve_executable(argv0: str, trusted_path: str | None = None) -> str:
    """Resolve argv[0] to an absolute path. Reject relative paths."""
    if not argv0:
        raise ProcessPolicyError("argv[0] must not be empty")

    # If already absolute, verify it exists
    if os.path.isabs(argv0):
        if os.path.isfile(argv0) and os.access(argv0, os.X_OK):
            return argv0
        raise ProcessPolicyError(
            f"executable {argv0!r} does not exist or is not executable"
        )

    # Relative paths with directory separators are rejected
    if os.sep in argv0 or (os.altsep and os.altsep in argv0):
        raise ProcessPolicyError(
            f"relative executable paths are not allowed: {argv0!r}. "
            f"Use an absolute path or ensure the binary is on a trusted PATH."
        )

    # Resolve from trusted PATH only
    if trusted_path is None:
        trusted_path = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    for entry in trusted_path.split(os.pathsep):
        if not _is_safe_path_entry(entry):
            continue
        candidate = os.path.join(entry, argv0)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return ""  # Not found - caller handles this



def build_child_environment(
    allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
    extra: Mapping[str, str] | None = None,
    parent: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the child environment: an allowlist, minus anything credential-shaped.

    Protected names (HOME, TMPDIR, PATH, XDG_*) cannot be set via extra.
    The denylist is applied **after** the allowlist and after `extra`, so a caller cannot
    re-admit a credential by naming it explicitly.
    """
    if parent is None:
        parent = os.environ
    if type(extra) not in (dict, type(None)):
        raise ProcessPolicyError("extra environment must be an exact dict or None")

    # Validate env_extra keys cannot override protected names
    if extra:
        for key in extra:
            if key in PROTECTED_ENV_NAMES:
                raise ProcessPolicyError(
                    f"env_extra cannot override protected variable {key!r}. "
                    f"Protected names: {sorted(PROTECTED_ENV_NAMES)}"
                )

    env: dict[str, str] = {}
    for name in allowlist:
        key = canonical_identifier(name, "environment variable name")
        if key in PROTECTED_ENV_NAMES:
            continue  # Protected names are set by the runner, not inherited
        if key in parent:
            env[key] = str(parent[key])
    for key, value in (extra or {}).items():
        ckey = canonical_identifier(key, "environment variable name")
        if ckey in PROTECTED_ENV_NAMES:
            raise ProcessPolicyError(
                f"env_extra cannot override protected variable {ckey!r}"
            )
        env[ckey] = str(value)

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
    """What to run. Immutable, validated, and never a shell string.

    Fixes applied (D2.1):
    - frozen+slotted: no mutable aliasing
    - env_extra deep-copied into MappingProxyType at construction
    - env var names/values validated (no '=', no NUL, no empty)
    - workspace_root confines cwd
    - Protected env names cannot be overridden
    """

    argv: tuple
    cwd: Path | None = None
    workspace_root: Path | None = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES
    env_allowlist: tuple = DEFAULT_ENV_ALLOWLIST
    env_extra: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))
    expected_exit_codes: tuple = (0,)
    isolated_tmpdir: bool = True
    trusted_path: str | None = None

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

        # Validate and freeze env_extra (Defect 6 & 7)
        raw_extra = self.env_extra
        if isinstance(raw_extra, MappingProxyType):
            extra_dict = dict(raw_extra)
        elif type(raw_extra) is dict:
            extra_dict = dict(raw_extra)  # deep copy
        else:
            raise ProcessPolicyError("env_extra must be a dict or MappingProxyType")

        for key, value in extra_dict.items():
            if type(key) is not str:
                raise ProcessPolicyError(
                    f"env_extra key must be a string, got {type(key).__name__}"
                )
            if not key:
                raise ProcessPolicyError("env_extra key must not be empty")
            if "=" in key:
                raise ProcessPolicyError(
                    f"env_extra key must not contain '=': {key!r}"
                )
            if "\x00" in key:
                raise ProcessPolicyError(
                    f"env_extra key must not contain NUL: {key!r}"
                )
            if key in PROTECTED_ENV_NAMES:
                raise ProcessPolicyError(
                    f"env_extra cannot override protected variable {key!r}"
                )
            if type(value) is not str:
                raise ProcessPolicyError(
                    f"env_extra value for {key!r} must be a string"
                )
            if "\x00" in value:
                raise ProcessPolicyError(
                    f"env_extra value for {key!r} must not contain NUL"
                )
        set_(self, "env_extra", MappingProxyType(extra_dict))

        # workspace_root validation
        if self.workspace_root is not None:
            if not isinstance(self.workspace_root, Path):
                raise ProcessPolicyError(
                    f"workspace_root must be a Path or None, got {type(self.workspace_root).__name__}"
                )
            resolved_root = self.workspace_root.resolve()
            if not resolved_root.is_dir():
                raise ProcessPolicyError(
                    f"workspace_root does not exist or is not a directory: {self.workspace_root}"
                )
            set_(self, "workspace_root", resolved_root)

        if self.cwd is not None:
            if not isinstance(self.cwd, Path):
                raise ProcessPolicyError(
                    f"cwd must be a pathlib.Path or None, got {type(self.cwd).__name__}"
                )
            resolved = self.cwd.resolve()
            if not resolved.is_dir():
                raise ProcessPolicyError(
                    f"cwd does not exist or is not a directory: {self.cwd}"
                )
            # If workspace_root is set, cwd must be inside it
            if self.workspace_root is not None:
                ws_root = self.workspace_root  # already resolved above
                try:
                    resolved.relative_to(ws_root)
                except ValueError:
                    raise ProcessPolicyError(
                        f"cwd {resolved} is outside workspace_root {ws_root}. "
                        f"Directory traversal is not permitted."
                    )
            set_(self, "cwd", resolved)

        if require_int(self.timeout_seconds, "timeout_seconds") <= 0:
            raise ProcessPolicyError("timeout_seconds must be > 0")
        if require_int(self.max_output_bytes, "max_output_bytes") <= 0:
            raise ProcessPolicyError("max_output_bytes must be > 0")
        if require_int(self.max_stdout_bytes, "max_stdout_bytes") <= 0:
            raise ProcessPolicyError("max_stdout_bytes must be > 0")
        if require_int(self.max_stderr_bytes, "max_stderr_bytes") <= 0:
            raise ProcessPolicyError("max_stderr_bytes must be > 0")
        require_bool(self.isolated_tmpdir, "isolated_tmpdir")

        if type(self.env_allowlist) not in (tuple, list):
            raise ProcessPolicyError("env_allowlist must be a tuple of names")
        set_(self, "env_allowlist", tuple(self.env_allowlist))

        if type(self.expected_exit_codes) not in (tuple, list):
            raise ProcessPolicyError("expected_exit_codes must be a tuple of ints")
        codes = tuple(require_int(c, "expected exit code") for c in self.expected_exit_codes)
        if not codes:
            raise ProcessPolicyError(
                "expected_exit_codes must not be empty: an adapter has to declare its "
                "contract, because success is never inferred from an exit code alone"
            )
        set_(self, "expected_exit_codes", codes)

        if self.trusted_path is not None and type(self.trusted_path) is not str:
            raise ProcessPolicyError("trusted_path must be a string or None")

    @property
    def display_command(self) -> str:
        """For reports and logs. Never parsed, never executed."""
        return " ".join(self.argv)


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Evidence about one execution. Carries a `Status`, never a boolean.

    Frozen+slotted with __post_init__ validation (Defect 8):
    - status must be Status enum
    - argv must be tuple of str
    - stdout/stderr must be bytes
    - duration_ms >= 0
    - booleans must be bool
    """

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
    scratch_cleanup_success: bool | None = None

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        # Validate status is Status enum
        if type(self.status) is not Status:
            raise ProcessPolicyError(
                f"status must be a Status enum member, got {type(self.status).__name__}"
            )
        # Validate argv is tuple of str
        if type(self.argv) not in (tuple, list):
            raise ProcessPolicyError("argv must be a tuple of strings")
        argv = tuple(self.argv)
        for i, part in enumerate(argv):
            if type(part) is not str:
                raise ProcessPolicyError(
                    f"argv[{i}] must be a string, got {type(part).__name__}"
                )
        set_(self, "argv", argv)
        # Validate stdout/stderr are bytes
        if type(self.stdout) is not bytes:
            raise ProcessPolicyError(
                f"stdout must be bytes, got {type(self.stdout).__name__}"
            )
        if type(self.stderr) is not bytes:
            raise ProcessPolicyError(
                f"stderr must be bytes, got {type(self.stderr).__name__}"
            )
        # Validate duration_ms >= 0
        if type(self.duration_ms) is not int:
            raise ProcessPolicyError(
                f"duration_ms must be int, got {type(self.duration_ms).__name__}"
            )
        if self.duration_ms < 0:
            raise ProcessPolicyError("duration_ms must be >= 0")
        # Validate booleans
        if type(self.truncated) is not bool:
            raise ProcessPolicyError(
                f"truncated must be bool, got {type(self.truncated).__name__}"
            )
        if type(self.timed_out) is not bool:
            raise ProcessPolicyError(
                f"timed_out must be bool, got {type(self.timed_out).__name__}"
            )
        # Validate exit_code
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ProcessPolicyError(
                f"exit_code must be int or None, got {type(self.exit_code).__name__}"
            )
        # Validate killed_signal
        if self.killed_signal is not None and type(self.killed_signal) is not int:
            raise ProcessPolicyError(
                f"killed_signal must be int or None, got {type(self.killed_signal).__name__}"
            )
        # Validate reason_code
        if type(self.reason_code) is not str:
            raise ProcessPolicyError(
                f"reason_code must be str, got {type(self.reason_code).__name__}"
            )
        # Validate detail
        if type(self.detail) is not str:
            raise ProcessPolicyError(
                f"detail must be str, got {type(self.detail).__name__}"
            )
        # Validate scratch_cleanup_success
        if self.scratch_cleanup_success is not None and type(self.scratch_cleanup_success) is not bool:
            raise ProcessPolicyError(
                f"scratch_cleanup_success must be bool or None, got {type(self.scratch_cleanup_success).__name__}"
            )

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


def _terminate_process_group(process: subprocess.Popen, pgid: int) -> int | None:
    """Signal the whole group using saved pgid, wait, then kill.

    Uses the saved pgid (= child pid when start_new_session=True) rather than
    querying getpgid which can race if the child has already exited (Defect 5).
    """
    if process.poll() is not None:
        return None
    used = signal.SIGTERM
    try:
        if os.name == "posix":
            os.killpg(pgid, signal.SIGTERM)
        else:  # pragma: no cover
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
            os.killpg(pgid, signal.SIGKILL)
        else:  # pragma: no cover
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        process.wait(timeout=_GRACE_SECONDS)
    except subprocess.TimeoutExpired:  # pragma: no cover
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

    # Resolve executable to absolute path (Defect 2)
    resolved_exe = _resolve_executable(request.argv[0], request.trusted_path)
    if not resolved_exe:
        return CommandResult(
            argv=request.argv, status=Status.UNSUPPORTED, exit_code=None,
            stdout=b"", stderr=b"", duration_ms=0, truncated=False, timed_out=False,
            killed_signal=None, reason_code="EXECUTABLE_NOT_FOUND",
            detail=f"{request.argv[0]!r} is not on a trusted PATH",
        )

    # Build the actual argv with resolved executable
    actual_argv = (resolved_exe,) + request.argv[1:]

    # Create per-command scratch with private HOME/TMPDIR/XDG (Defect 1)
    scratch: str | None = None
    scratch_cleanup_success: bool | None = None
    env = build_child_environment(request.env_allowlist, dict(request.env_extra))

    if request.isolated_tmpdir:
        scratch = tempfile.mkdtemp(prefix="iac-guard-v-")
        os.chmod(scratch, 0o700)
        # Create private subdirectories
        home_dir = os.path.join(scratch, "home")
        tmp_dir = os.path.join(scratch, "tmp")
        xdg_config = os.path.join(scratch, "xdg_config")
        xdg_cache = os.path.join(scratch, "xdg_cache")
        xdg_data = os.path.join(scratch, "xdg_data")
        for d in (home_dir, tmp_dir, xdg_config, xdg_cache, xdg_data):
            os.makedirs(d, mode=0o700, exist_ok=True)
        # Set protected env vars to scratch locations
        env["HOME"] = home_dir
        env["TMPDIR"] = tmp_dir
        env["XDG_CONFIG_HOME"] = xdg_config
        env["XDG_CACHE_HOME"] = xdg_cache
        env["XDG_DATA_HOME"] = xdg_data
    else:
        # Even without isolated tmpdir, don't pass real HOME
        scratch = tempfile.mkdtemp(prefix="iac-guard-v-")
        os.chmod(scratch, 0o700)
        home_dir = os.path.join(scratch, "home")
        os.makedirs(home_dir, mode=0o700, exist_ok=True)
        env["HOME"] = home_dir

    # Build safe PATH from trusted sources only (Defect 2)
    trusted_path = request.trusted_path
    if trusted_path is None:
        # Use system default safe PATH entries
        safe_entries = []
        for entry in os.environ.get("PATH", "").split(os.pathsep):
            if _is_safe_path_entry(entry):
                safe_entries.append(entry)
        if not safe_entries:
            safe_entries = ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        trusted_path = os.pathsep.join(safe_entries)
    else:
        # Validate trusted_path entries
        safe_entries = []
        for entry in trusted_path.split(os.pathsep):
            if _is_safe_path_entry(entry):
                safe_entries.append(entry)
        trusted_path = os.pathsep.join(safe_entries)
    env["PATH"] = trusted_path

    started = time.monotonic()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_bytes = 0
    stderr_bytes = 0
    truncated = False
    timed_out = False
    killed_signal: int | None = None
    process: subprocess.Popen | None = None
    pgid: int = 0

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
            popen_kwargs["start_new_session"] = True
        try:
            process = subprocess.Popen(actual_argv, **popen_kwargs)  # noqa: S603
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

        # Save pgid = child pid (since start_new_session=True, child IS the group leader)
        pgid = process.pid

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
                    # Check stdout cap (Defect 3)
                    if stdout_bytes > request.max_stdout_bytes:
                        truncated = True
                        break
                else:
                    stderr_chunks.append(chunk)
                    stderr_bytes += len(chunk)
                    # Check stderr cap (Defect 3)
                    if stderr_bytes > request.max_stderr_bytes:
                        truncated = True
                        break
                # Check combined cap (Defect 3)
                if (stdout_bytes + stderr_bytes) > request.max_output_bytes:
                    truncated = True
                    break
            if process.poll() is not None and open_streams == 0:
                break
        selector.close()

        # Wall-clock deadline enforcement AFTER streams close (Defect 4)
        if not timed_out and not truncated:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
            elif process.poll() is None:
                try:
                    process.wait(timeout=max(0, remaining))
                except subprocess.TimeoutExpired:
                    timed_out = True

        # Always signal process group after completion or deadline (Defect 5)
        if timed_out or truncated:
            killed_signal = _terminate_process_group(process, pgid)
        elif process.poll() is None:
            killed_signal = _terminate_process_group(process, pgid)

        # Final cleanup: signal group even on normal completion to kill grandchildren
        if process.poll() is not None and pgid:
            try:
                if os.name == "posix":
                    os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass  # Group already gone

        exit_code = process.poll()
        if exit_code is None:
            try:
                exit_code = process.wait(timeout=_GRACE_SECONDS)
            except subprocess.TimeoutExpired:  # pragma: no cover
                killed_signal = _terminate_process_group(process, pgid)
                exit_code = process.poll()
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:  # pragma: no cover
                        pass
        # Record scratch cleanup success/failure (never ignore_errors silently)
        if scratch:
            try:
                shutil.rmtree(scratch)
                scratch_cleanup_success = True
            except OSError as cleanup_err:
                scratch_cleanup_success = False
                logger.warning(
                    "scratch cleanup failed for %s: %s", scratch, cleanup_err
                )

    duration_ms = int((time.monotonic() - started) * 1000)
    # Cap each stream at its own limit AND the combined limit
    stdout_cap = min(request.max_stdout_bytes, request.max_output_bytes)
    stderr_cap = min(request.max_stderr_bytes, request.max_output_bytes)
    stdout = b"".join(stdout_chunks)[: stdout_cap]
    stderr = b"".join(stderr_chunks)[: stderr_cap]

    if timed_out:
        status, reason = Status.TIMEOUT, "DEADLINE_EXCEEDED"
        detail = f"exceeded {request.timeout_seconds}s and the process group was signalled"
    elif truncated:
        status, reason = Status.PARTIAL, "OUTPUT_LIMIT_EXCEEDED"
        detail = (f"output exceeded cap (stdout={request.max_stdout_bytes}, "
                  f"stderr={request.max_stderr_bytes}, combined={request.max_output_bytes}); "
                  f"the process group was signalled and output must not be parsed as complete")
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
        detail=detail, scratch_cleanup_success=scratch_cleanup_success,
    )


def python_command(*args: str) -> tuple:
    """The current interpreter plus arguments, for tests and internal helpers."""
    return (sys.executable, *args)
