"""Fail-closed native subprocess execution with explicitly reduced isolation.

This runner supplies argument-array execution, a stripped environment, bounded retained
output, private scratch state, process-group cleanup, and spawn-time path revalidation.
It is not a filesystem, network, or resource sandbox.  Host-native execution is suitable
only where the operator trusts the scanner executable and accepts reduced isolation;
hostile pull-request content requires the separately hardened container path.
"""
from __future__ import annotations

import errno
import hashlib
import logging
import ntpath
import os
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence

from .enums import Status
from .models import DomainError, canonical_identifier, require_bool, require_int
from .redaction import display_command, redact_argv, redact_detail

logger = logging.getLogger(__name__)

DEFAULT_ENV_ALLOWLIST: tuple[str, ...] = ("LANG", "LC_ALL", "TZ")
PROTECTED_ENV_NAMES: frozenset[str] = frozenset(
    {"HOME", "TMPDIR", "PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"}
)
CREDENTIAL_DENYLIST_PREFIXES: tuple[str, ...] = (
    "AWS_", "AZURE_", "ARM_", "GOOGLE_", "GCP_", "GCLOUD_", "KUBE", "K8S_",
    "DOCKER_", "GITHUB_", "GITLAB_", "CI_", "BUILDKITE_", "CIRCLE_", "TF_TOKEN_",
    "VAULT_", "OP_", "NPM_TOKEN", "PYPI_", "TWINE_", "SSH_", "GPG_", "GNUPG",
    "ANTHROPIC_", "OPENAI_", "BEDROCK_",
)
CREDENTIAL_DENYLIST_NAMES: frozenset[str] = frozenset(
    {
        "AWS_PROFILE", "KUBECONFIG", "DOCKER_HOST", "GITHUB_TOKEN", "GH_TOKEN",
        "TF_VAR_password", "TF_LOG_PATH", "NETRC", "CURLOPT_PROXY", "LD_PRELOAD",
        "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "BASH_ENV", "ENV",
        "NODE_OPTIONS", "RUBYOPT", "PERL5LIB",
    }
)
ENV_DENYLIST_PREFIXES_EXTENDED: tuple[str, ...] = ("DYLD_",)
MINIMAL_SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_OUTPUT_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_STDOUT_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_STDERR_BYTES = 25 * 1024 * 1024
_READ_CHUNK = 64 * 1024
_GRACE_SECONDS = 3.0
_OPTION_NAME = re.compile(r"-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*\Z")


class ProcessPolicyError(DomainError):
    """A request or evidence object refused at the process trust boundary."""


class ProcessReason(str, Enum):
    """Closed reason vocabulary for process execution evidence."""

    COMPLETED_WITHIN_CONTRACT = "COMPLETED_WITHIN_CONTRACT"
    EXECUTABLE_NOT_FOUND = "EXECUTABLE_NOT_FOUND"
    SPAWN_FAILED = "SPAWN_FAILED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    PROCESS_GROUP_CLEANUP_FAILED = "PROCESS_GROUP_CLEANUP_FAILED"
    LINGERING_DESCENDANTS_TERMINATED = "LINGERING_DESCENDANTS_TERMINATED"
    NO_EXIT_STATUS = "NO_EXIT_STATUS"
    KILLED_BY_SIGNAL = "KILLED_BY_SIGNAL"
    EXIT_CODE_OUTSIDE_CONTRACT = "EXIT_CODE_OUTSIDE_CONTRACT"
    SCRATCH_CLEANUP_FAILED = "SCRATCH_CLEANUP_FAILED"


class ProcessGroupState(str, Enum):
    """Result of a process-group existence inspection."""

    ABSENT = "ABSENT"
    ALIVE = "ALIVE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ProcessGroupCleanup:
    """Typed outcome of attempting to terminate and confirm a process group."""

    attempted: bool
    success: bool
    killed_signal: int | None = None
    diagnostic: str = ""

    def __post_init__(self) -> None:
        if type(self.attempted) is not bool or type(self.success) is not bool:
            raise ProcessPolicyError("process-group cleanup flags must be booleans")
        if self.killed_signal is not None and type(self.killed_signal) is not int:
            raise ProcessPolicyError("process-group killed_signal must be int or None")
        if type(self.diagnostic) is not str:
            raise ProcessPolicyError("process-group diagnostic must be a string")


@dataclass(frozen=True, slots=True)
class _PathIdentity:
    resolved: Path
    device: int
    inode: int


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _contains_forbidden_text(text: str) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cf"} for character in text)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _snapshot_directory(path: Path, label: str) -> _PathIdentity:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise ProcessPolicyError(
            f"{label} does not exist or cannot be resolved: {redact_detail(str(exc))}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ProcessPolicyError(f"{label} must be an existing directory")
    return _PathIdentity(resolved, metadata.st_dev, metadata.st_ino)


def _revalidate_directory(path: Path, identity: _PathIdentity, label: str) -> Path:
    current = _snapshot_directory(path, label)
    if current != identity:
        raise ProcessPolicyError(
            f"{label} changed after request validation; refusing spawn to reduce TOCTOU exposure"
        )
    return current.resolved


def _validate_sensitive_indices(raw: object, argv_length: int) -> tuple[int, ...]:
    if type(raw) not in (tuple, list):
        raise ProcessPolicyError("sensitive_argument_indices must be a tuple or list of ints")
    values: list[int] = []
    for value in raw:
        if type(value) is not int:
            raise ProcessPolicyError("sensitive_argument_indices values must be exact integers")
        if value < 0 or value >= argv_length:
            raise ProcessPolicyError("sensitive_argument_indices value is outside argv bounds")
        values.append(value)
    if len(values) != len(set(values)):
        raise ProcessPolicyError("sensitive_argument_indices must not contain duplicates")
    return tuple(sorted(values))


def _validate_sensitive_options(raw: object) -> tuple[str, ...]:
    if type(raw) not in (tuple, list):
        raise ProcessPolicyError("sensitive_option_names must be a tuple or list of strings")
    values: list[str] = []
    for value in raw:
        if type(value) is not str or not value.strip():
            raise ProcessPolicyError("sensitive_option_names values must be exact nonblank strings")
        if _contains_forbidden_text(value):
            raise ProcessPolicyError("sensitive_option_names values must not contain control or bidi characters")
        if not _OPTION_NAME.fullmatch(value):
            raise ProcessPolicyError(f"invalid sensitive option syntax: {value!r}")
        values.append(value)
    if len(values) != len(set(values)):
        raise ProcessPolicyError("sensitive_option_names must not contain duplicates")
    return tuple(sorted(values))


def _is_safe_path_entry(entry: str) -> bool:
    return bool(entry) and entry != "." and os.path.isabs(entry)


def _snapshot_executable(candidate: Path, workspace_root: Path | None) -> _PathIdentity:
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise ProcessPolicyError(
            "executable does not exist or cannot be strictly resolved: "
            f"{redact_detail(str(exc))}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise ProcessPolicyError("executable must be an executable regular file")
    if workspace_root is not None and _is_within(resolved, workspace_root):
        raise ProcessPolicyError("executable resolves inside workspace_root and is untrusted")
    return _PathIdentity(resolved, metadata.st_dev, metadata.st_ino)


def _resolve_executable(
    argv0: str,
    lookup_dirs: Sequence[Path],
    workspace_root: Path | None,
) -> _PathIdentity | None:
    if not argv0:
        raise ProcessPolicyError("argv[0] must not be empty")
    if os.path.isabs(argv0):
        return _snapshot_executable(Path(argv0), workspace_root)
    if os.sep in argv0 or (os.altsep and os.altsep in argv0):
        raise ProcessPolicyError(
            f"relative executable paths are not allowed: {argv0!r}. Use a trusted absolute path."
        )
    for directory in lookup_dirs:
        candidate = directory / argv0
        if candidate.exists():
            return _snapshot_executable(candidate, workspace_root)
    return None


def _revalidate_executable(
    identity: _PathIdentity, workspace_root: Path | None
) -> Path:
    current = _snapshot_executable(identity.resolved, workspace_root)
    if current != identity:
        raise ProcessPolicyError(
            "executable changed after resolution; refusing spawn to reduce TOCTOU exposure"
        )
    return current.resolved


def build_child_environment(
    allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
    extra: Mapping[str, str] | None = None,
    parent: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the child environment from an allowlist, then apply the denylist."""
    if parent is None:
        parent = os.environ
    if type(extra) not in (dict, type(None)):
        raise ProcessPolicyError("extra environment must be an exact dict or None")
    if extra:
        for key in extra:
            if key in PROTECTED_ENV_NAMES:
                raise ProcessPolicyError(f"env_extra cannot override protected variable {key!r}")

    env: dict[str, str] = {}
    for name in allowlist:
        key = canonical_identifier(name, "environment variable name")
        if key not in PROTECTED_ENV_NAMES and key in parent:
            env[key] = str(parent[key])
    for key, value in (extra or {}).items():
        canonical_key = canonical_identifier(key, "environment variable name")
        if canonical_key in PROTECTED_ENV_NAMES:
            raise ProcessPolicyError(
                f"env_extra cannot override protected variable {canonical_key!r}"
            )
        env[canonical_key] = str(value)
    denied = sorted(
        key
        for key in env
        if key in CREDENTIAL_DENYLIST_NAMES
        or key.startswith(CREDENTIAL_DENYLIST_PREFIXES)
        or key.startswith(ENV_DENYLIST_PREFIXES_EXTENDED)
    )
    for key in denied:
        del env[key]
    return env


@dataclass(frozen=True, slots=True)
class CommandRequest:
    """Immutable process request assembled only from trusted adapter/operator config."""

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
    trusted_helper_dirs: tuple = ()
    sensitive_argument_indices: tuple = ()
    sensitive_option_names: tuple = ()
    _workspace_identity: _PathIdentity | None = field(init=False, repr=False, compare=False)
    _cwd_identity: _PathIdentity | None = field(init=False, repr=False, compare=False)
    _helper_identities: tuple[_PathIdentity, ...] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        if type(self.argv) not in (tuple, list) or not self.argv:
            raise ProcessPolicyError("argv must be a non-empty tuple or list of strings")
        argv = tuple(self.argv)
        for index, part in enumerate(argv):
            if type(part) is not str or not part:
                raise ProcessPolicyError(f"argv[{index}] must be a non-empty exact string")
            if "\x00" in part:
                raise ProcessPolicyError(f"argv[{index}] must not contain a NUL byte")
        set_(self, "argv", argv)

        raw_extra = self.env_extra
        if isinstance(raw_extra, MappingProxyType):
            extra = dict(raw_extra)
        elif type(raw_extra) is dict:
            extra = dict(raw_extra)
        else:
            raise ProcessPolicyError("env_extra must be a dict or MappingProxyType")
        for key, value in extra.items():
            if type(key) is not str:
                raise ProcessPolicyError("env_extra key must be a string")
            if not key:
                raise ProcessPolicyError("env_extra key must not be empty")
            if "=" in key:
                raise ProcessPolicyError(f"env_extra key must not contain '=': {key!r}")
            if "\x00" in key:
                raise ProcessPolicyError(f"env_extra key must not contain NUL: {key!r}")
            if key in PROTECTED_ENV_NAMES:
                raise ProcessPolicyError(f"env_extra cannot override protected variable {key!r}")
            if type(value) is not str:
                raise ProcessPolicyError(f"env_extra value for {key!r} must be a string")
            if "\x00" in value:
                raise ProcessPolicyError(f"env_extra value for {key!r} must not contain NUL")
        set_(self, "env_extra", MappingProxyType(extra))

        if self.cwd is not None and self.workspace_root is None:
            raise ProcessPolicyError(
                "workspace_root is required when cwd is supplied; arbitrary cwd is refused"
            )
        workspace_identity: _PathIdentity | None = None
        if self.workspace_root is not None:
            if not isinstance(self.workspace_root, Path):
                raise ProcessPolicyError("workspace_root must be a pathlib.Path or None")
            workspace_identity = _snapshot_directory(self.workspace_root, "workspace_root")
            set_(self, "workspace_root", workspace_identity.resolved)
        set_(self, "_workspace_identity", workspace_identity)

        cwd_identity: _PathIdentity | None = None
        if self.cwd is not None:
            if not isinstance(self.cwd, Path):
                raise ProcessPolicyError("cwd must be a pathlib.Path or None")
            cwd_identity = _snapshot_directory(self.cwd, "cwd")
            assert workspace_identity is not None
            if not _is_within(cwd_identity.resolved, workspace_identity.resolved):
                raise ProcessPolicyError("cwd is outside workspace_root; traversal is refused")
            set_(self, "cwd", cwd_identity.resolved)
        set_(self, "_cwd_identity", cwd_identity)

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
            raise ProcessPolicyError("env_allowlist must be a tuple or list")
        set_(self, "env_allowlist", tuple(self.env_allowlist))
        if type(self.expected_exit_codes) not in (tuple, list):
            raise ProcessPolicyError("expected_exit_codes must be a tuple or list of ints")
        codes = tuple(require_int(code, "expected exit code") for code in self.expected_exit_codes)
        if not codes:
            raise ProcessPolicyError("expected_exit_codes must not be empty")
        set_(self, "expected_exit_codes", codes)

        if type(self.trusted_helper_dirs) not in (tuple, list):
            raise ProcessPolicyError("trusted_helper_dirs must be a tuple or list of Paths")
        helper_identities: list[_PathIdentity] = []
        for index, helper in enumerate(self.trusted_helper_dirs):
            if not isinstance(helper, Path):
                raise ProcessPolicyError(f"trusted_helper_dirs[{index}] must be a Path")
            identity = _snapshot_directory(helper, f"trusted_helper_dirs[{index}]")
            if workspace_identity is not None and _is_within(
                identity.resolved, workspace_identity.resolved
            ):
                raise ProcessPolicyError(
                    f"trusted_helper_dirs[{index}] must not be inside workspace_root"
                )
            helper_identities.append(identity)
        set_(self, "trusted_helper_dirs", tuple(item.resolved for item in helper_identities))
        set_(self, "_helper_identities", tuple(helper_identities))

        set_(
            self,
            "sensitive_argument_indices",
            _validate_sensitive_indices(self.sensitive_argument_indices, len(argv)),
        )
        set_(self, "sensitive_option_names", _validate_sensitive_options(self.sensitive_option_names))

    @property
    def display_command(self) -> str:
        """Redacted, quoted report text; never parsed and never executed."""
        return display_command(
            self.argv,
            sensitive_option_names=self.sensitive_option_names,
            sensitive_argument_indices=self.sensitive_argument_indices,
        )


_ALLOWED_REASON_BY_STATUS: Mapping[Status, frozenset[ProcessReason]] = MappingProxyType(
    {
        Status.PASS: frozenset({ProcessReason.COMPLETED_WITHIN_CONTRACT}),
        Status.UNSUPPORTED: frozenset({ProcessReason.EXECUTABLE_NOT_FOUND}),
        Status.TIMEOUT: frozenset({ProcessReason.DEADLINE_EXCEEDED}),
        Status.PARTIAL: frozenset({ProcessReason.OUTPUT_LIMIT_EXCEEDED}),
        Status.ERROR: frozenset(
            {
                ProcessReason.SPAWN_FAILED,
                ProcessReason.PROCESS_GROUP_CLEANUP_FAILED,
                ProcessReason.LINGERING_DESCENDANTS_TERMINATED,
                ProcessReason.NO_EXIT_STATUS,
                ProcessReason.KILLED_BY_SIGNAL,
                ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT,
                ProcessReason.SCRATCH_CLEANUP_FAILED,
            }
        ),
    }
)


def _canonical_reason(value: object, label: str) -> ProcessReason:
    if type(value) is ProcessReason:
        return value
    if type(value) is not str or not value.strip() or _contains_forbidden_text(value):
        raise ProcessPolicyError(f"{label} must be a nonblank ProcessReason without controls")
    try:
        return ProcessReason(value)
    except ValueError as exc:
        raise ProcessPolicyError(f"{label} is not a supported ProcessReason: {value!r}") from exc


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Immutable, internally consistent execution evidence."""

    argv: tuple
    status: Status
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_ms: int
    truncated: bool
    timed_out: bool
    killed_signal: int | None
    reason_code: ProcessReason | str
    detail: str = ""
    scratch_cleanup_success: bool | None = None
    resolved_executable: str = ""
    sensitive_argument_indices: tuple = ()
    sensitive_option_names: tuple = ()
    process_group_cleanup_attempted: bool = False
    process_group_cleanup_success: bool | None = None
    primary_execution_event: ProcessReason | str | None = None
    cleanup_diagnostics: tuple = ()
    stdout_observed_bytes: int | None = None
    stderr_observed_bytes: int | None = None
    stdout_retained_bytes: int | None = None
    stderr_retained_bytes: int | None = None

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        if type(self.status) is not Status:
            raise ProcessPolicyError("status must be a Status enum member")
        if type(self.argv) not in (tuple, list):
            raise ProcessPolicyError("argv must be a tuple or list of strings")
        argv = tuple(self.argv)
        if not argv:
            raise ProcessPolicyError("argv must not be empty")
        for index, part in enumerate(argv):
            if type(part) is not str:
                raise ProcessPolicyError(f"argv[{index}] must be a string")
        set_(self, "argv", argv)
        if type(self.stdout) is not bytes:
            raise ProcessPolicyError("stdout must be bytes")
        if type(self.stderr) is not bytes:
            raise ProcessPolicyError("stderr must be bytes")
        if type(self.duration_ms) is not int:
            raise ProcessPolicyError("duration_ms must be int")
        if self.duration_ms < 0:
            raise ProcessPolicyError("duration_ms must be >= 0")
        for label in ("truncated", "timed_out", "process_group_cleanup_attempted"):
            if type(getattr(self, label)) is not bool:
                raise ProcessPolicyError(f"{label} must be bool")
        if self.process_group_cleanup_success is not None and type(
            self.process_group_cleanup_success
        ) is not bool:
            raise ProcessPolicyError("process_group_cleanup_success must be bool or None")
        if self.scratch_cleanup_success is not None and type(self.scratch_cleanup_success) is not bool:
            raise ProcessPolicyError("scratch_cleanup_success must be bool or None")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ProcessPolicyError("exit_code must be int or None")
        if self.killed_signal is not None and type(self.killed_signal) is not int:
            raise ProcessPolicyError("killed_signal must be int or None")
        if type(self.detail) is not str or type(self.resolved_executable) is not str:
            raise ProcessPolicyError("detail and resolved_executable must be strings")

        reason = _canonical_reason(self.reason_code, "reason_code")
        set_(self, "reason_code", reason)
        if reason not in _ALLOWED_REASON_BY_STATUS.get(self.status, frozenset()):
            raise ProcessPolicyError(
                "contradictory status/reason combination: "
                f"{self.status.value}/{reason.value}"
            )

        primary = self.primary_execution_event
        if primary is None:
            primary_reason = (
                ProcessReason.COMPLETED_WITHIN_CONTRACT
                if reason is ProcessReason.SCRATCH_CLEANUP_FAILED
                else reason
            )
        else:
            primary_reason = _canonical_reason(primary, "primary_execution_event")
        set_(self, "primary_execution_event", primary_reason)

        if type(self.cleanup_diagnostics) not in (tuple, list):
            raise ProcessPolicyError("cleanup_diagnostics must be a tuple or list")
        diagnostics = [_canonical_reason(item, "cleanup diagnostic") for item in self.cleanup_diagnostics]
        if self.scratch_cleanup_success is False and ProcessReason.SCRATCH_CLEANUP_FAILED not in diagnostics:
            diagnostics.append(ProcessReason.SCRATCH_CLEANUP_FAILED)
        if self.process_group_cleanup_success is False and ProcessReason.PROCESS_GROUP_CLEANUP_FAILED not in diagnostics:
            diagnostics.append(ProcessReason.PROCESS_GROUP_CLEANUP_FAILED)
        if len(diagnostics) != len(set(diagnostics)):
            raise ProcessPolicyError("cleanup_diagnostics must not contain duplicates")
        set_(self, "cleanup_diagnostics", tuple(sorted(diagnostics, key=lambda item: item.value)))
        if (
            ProcessReason.PROCESS_GROUP_CLEANUP_FAILED in diagnostics
        ) is not (self.process_group_cleanup_success is False):
            raise ProcessPolicyError(
                "process-group cleanup diagnostic must exactly match failed cleanup evidence"
            )
        if (ProcessReason.SCRATCH_CLEANUP_FAILED in diagnostics) is not (
            self.scratch_cleanup_success is False
        ):
            raise ProcessPolicyError(
                "scratch cleanup diagnostic must exactly match failed cleanup evidence"
            )

        indices = _validate_sensitive_indices(self.sensitive_argument_indices, len(argv))
        options = _validate_sensitive_options(self.sensitive_option_names)
        set_(self, "sensitive_argument_indices", indices)
        set_(self, "sensitive_option_names", options)

        retained_stdout = len(self.stdout)
        retained_stderr = len(self.stderr)
        stdout_retained = retained_stdout if self.stdout_retained_bytes is None else self.stdout_retained_bytes
        stderr_retained = retained_stderr if self.stderr_retained_bytes is None else self.stderr_retained_bytes
        stdout_observed = retained_stdout if self.stdout_observed_bytes is None else self.stdout_observed_bytes
        stderr_observed = retained_stderr if self.stderr_observed_bytes is None else self.stderr_observed_bytes
        for label, value in (
            ("stdout_retained_bytes", stdout_retained),
            ("stderr_retained_bytes", stderr_retained),
            ("stdout_observed_bytes", stdout_observed),
            ("stderr_observed_bytes", stderr_observed),
        ):
            if type(value) is not int or value < 0:
                raise ProcessPolicyError(f"{label} must be an integer >= 0")
        if stdout_retained != retained_stdout or stderr_retained != retained_stderr:
            raise ProcessPolicyError("retained byte counts must equal the retained output lengths")
        if stdout_observed < stdout_retained or stderr_observed < stderr_retained:
            raise ProcessPolicyError("observed byte counts must be >= retained byte counts")
        set_(self, "stdout_retained_bytes", stdout_retained)
        set_(self, "stderr_retained_bytes", stderr_retained)
        set_(self, "stdout_observed_bytes", stdout_observed)
        set_(self, "stderr_observed_bytes", stderr_observed)

        if self.status is Status.PASS:
            if self.timed_out or self.truncated or self.killed_signal is not None:
                raise ProcessPolicyError(
                    "contradictory state: PASS cannot carry timeout, truncation, or signal evidence"
                )
            if self.scratch_cleanup_success is False:
                raise ProcessPolicyError(
                    "contradictory state: PASS cannot carry failed scratch cleanup"
                )
            if not self.resolved_executable:
                raise ProcessPolicyError("PASS requires a resolved executable identity")
            if self.exit_code is None or self.exit_code < 0:
                raise ProcessPolicyError("PASS requires a non-negative exit code")
        if self.status is Status.TIMEOUT and not self.timed_out:
            raise ProcessPolicyError(
                "contradictory state: DEADLINE_EXCEEDED requires TIMEOUT and timed_out=True"
            )
        if reason is ProcessReason.OUTPUT_LIMIT_EXCEEDED and not self.truncated:
            raise ProcessPolicyError("OUTPUT_LIMIT_EXCEEDED requires truncated=True")
        if self.status is Status.PARTIAL and not self.truncated:
            raise ProcessPolicyError("PARTIAL process output requires truncated=True")
        if reason is ProcessReason.DEADLINE_EXCEEDED and (
            self.status is not Status.TIMEOUT or not self.timed_out
        ):
            raise ProcessPolicyError(
                "contradictory state: DEADLINE_EXCEEDED requires TIMEOUT and timed_out=True"
            )
        if reason is ProcessReason.PROCESS_GROUP_CLEANUP_FAILED:
            if not self.process_group_cleanup_attempted or self.process_group_cleanup_success is not False:
                raise ProcessPolicyError(
                    "PROCESS_GROUP_CLEANUP_FAILED requires attempted=True and success=False"
                )
            if ProcessReason.PROCESS_GROUP_CLEANUP_FAILED not in self.cleanup_diagnostics:
                raise ProcessPolicyError("failed process-group cleanup requires a typed diagnostic")
        if self.process_group_cleanup_success is False and reason is not ProcessReason.PROCESS_GROUP_CLEANUP_FAILED:
            raise ProcessPolicyError("failed process-group cleanup must be the stronger primary reason")
        if reason is ProcessReason.SCRATCH_CLEANUP_FAILED and self.scratch_cleanup_success is not False:
            raise ProcessPolicyError("SCRATCH_CLEANUP_FAILED requires scratch_cleanup_success=False")

        if reason is ProcessReason.PROCESS_GROUP_CLEANUP_FAILED:
            if primary_reason in {
                ProcessReason.PROCESS_GROUP_CLEANUP_FAILED,
                ProcessReason.SCRATCH_CLEANUP_FAILED,
            }:
                raise ProcessPolicyError(
                    "process-group cleanup failure must preserve a non-cleanup primary event"
                )
        elif reason is ProcessReason.SCRATCH_CLEANUP_FAILED:
            if primary_reason is not ProcessReason.COMPLETED_WITHIN_CONTRACT:
                raise ProcessPolicyError(
                    "scratch cleanup override must preserve completed execution as primary"
                )
        elif primary_reason is not reason:
            raise ProcessPolicyError(
                "primary_execution_event may differ only when a cleanup failure overrides it"
            )
        if self.timed_out:
            if not (
                (reason is ProcessReason.DEADLINE_EXCEEDED)
                or (
                    reason is ProcessReason.PROCESS_GROUP_CLEANUP_FAILED
                    and primary_reason is ProcessReason.DEADLINE_EXCEEDED
                )
            ):
                raise ProcessPolicyError("timed_out evidence requires a deadline primary event")
        if self.truncated:
            if not (
                reason is ProcessReason.OUTPUT_LIMIT_EXCEEDED
                or (
                    reason is ProcessReason.PROCESS_GROUP_CLEANUP_FAILED
                    and primary_reason is ProcessReason.OUTPUT_LIMIT_EXCEEDED
                )
            ):
                raise ProcessPolicyError("truncated evidence requires an output-limit primary event")
        if primary_reason is ProcessReason.DEADLINE_EXCEEDED and not self.timed_out:
            raise ProcessPolicyError("deadline primary event requires timed_out=True")
        if primary_reason is ProcessReason.OUTPUT_LIMIT_EXCEEDED and not self.truncated:
            raise ProcessPolicyError("output-limit primary event requires truncated=True")

        valid_signals = {int(item) for item in signal.valid_signals()}
        if self.killed_signal is not None:
            if self.killed_signal <= 0 or self.killed_signal not in valid_signals:
                raise ProcessPolicyError("killed_signal must be a supported positive platform signal")
            if self.exit_code != -self.killed_signal:
                raise ProcessPolicyError("killed_signal requires matching negative exit_code evidence")
        if self.exit_code is not None and self.exit_code < 0:
            if self.killed_signal != -self.exit_code:
                raise ProcessPolicyError("negative exit_code requires matching killed_signal semantics")
        if reason is ProcessReason.KILLED_BY_SIGNAL and self.killed_signal is None:
            raise ProcessPolicyError("KILLED_BY_SIGNAL requires signal termination evidence")

    @property
    def stdout_sha256(self) -> str:
        return _sha256(self.stdout)

    @property
    def stderr_sha256(self) -> str:
        return _sha256(self.stderr)

    def canonical_dict(self) -> dict:
        """Return redacted evidence; output hashes cover retained bytes only."""
        safe_argv = list(
            redact_argv(
                self.argv,
                sensitive_option_names=self.sensitive_option_names,
                sensitive_argument_indices=self.sensitive_argument_indices,
            )
        )
        safe_resolved = ""
        if self.resolved_executable:
            safe_resolved = ntpath.basename(self.resolved_executable.replace("/", "\\"))
        result = {
            "argv": safe_argv,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "timed_out": self.timed_out,
            "killed_signal": self.killed_signal,
            "reason_code": self.reason_code.value,
            "primary_execution_event": self.primary_execution_event.value,
            "detail": redact_detail(self.detail) if self.detail else "",
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_bytes": self.stdout_retained_bytes,
            "stderr_bytes": self.stderr_retained_bytes,
            "stdout_observed_bytes": self.stdout_observed_bytes,
            "stderr_observed_bytes": self.stderr_observed_bytes,
            "stdout_retained_bytes": self.stdout_retained_bytes,
            "stderr_retained_bytes": self.stderr_retained_bytes,
            "output_hashes_cover": "retained_bytes_only",
            "resolved_executable": safe_resolved,
            "process_group_cleanup_attempted": self.process_group_cleanup_attempted,
            "process_group_cleanup_success": self.process_group_cleanup_success,
            "cleanup_diagnostics": [item.value for item in self.cleanup_diagnostics],
        }
        if self.scratch_cleanup_success is not None:
            result["scratch_cleanup_success"] = self.scratch_cleanup_success
        return result


def _process_group_alive(pgid: int) -> ProcessGroupState:
    """Inspect a process group without treating permission or I/O errors as absence."""
    if os.name != "posix":
        return ProcessGroupState.UNKNOWN
    try:
        os.killpg(pgid, 0)
        return ProcessGroupState.ALIVE
    except ProcessLookupError:
        return ProcessGroupState.ABSENT
    except PermissionError:
        return ProcessGroupState.UNKNOWN
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return ProcessGroupState.ABSENT
        return ProcessGroupState.UNKNOWN


def _signal_group(process: subprocess.Popen, pgid: int, sig: signal.Signals) -> str | None:
    try:
        if os.name == "posix":
            os.killpg(pgid, sig)
        elif sig is signal.SIGTERM:  # pragma: no cover - Windows path
            process.terminate()
        else:  # pragma: no cover - Windows path
            process.kill()
        return None
    except ProcessLookupError:
        return None
    except PermissionError as exc:
        return f"permission denied while signalling process group: {redact_detail(str(exc))}"
    except OSError as exc:
        return f"process-group signalling failed: {redact_detail(str(exc))}"


def _terminate_process_group(process: subprocess.Popen, pgid: int) -> ProcessGroupCleanup:
    """Terminate a group and succeed only after absence is positively confirmed."""
    diagnostics: list[str] = []
    first_error = _signal_group(process, pgid, signal.SIGTERM)
    if first_error:
        diagnostics.append(first_error)
    deadline = time.monotonic() + _GRACE_SECONDS
    process.poll()  # reap an exited leader before using killpg(0) as group evidence
    state = _process_group_alive(pgid)
    while state is not ProcessGroupState.ABSENT and time.monotonic() < deadline:
        time.sleep(0.05)
        process.poll()
        state = _process_group_alive(pgid)
    if state is not ProcessGroupState.ABSENT:
        kill_error = _signal_group(process, pgid, signal.SIGKILL)
        if kill_error:
            diagnostics.append(kill_error)
        deadline = time.monotonic() + _GRACE_SECONDS
        process.poll()
        state = _process_group_alive(pgid)
        while state is not ProcessGroupState.ABSENT and time.monotonic() < deadline:
            time.sleep(0.05)
            process.poll()
            state = _process_group_alive(pgid)

    try:
        process.wait(timeout=_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        diagnostics.append("process leader could not be reaped after group termination")
    except OSError as exc:
        diagnostics.append(f"process leader reap failed: {redact_detail(str(exc))}")
    exit_code = process.poll()
    killed_signal = -exit_code if exit_code is not None and exit_code < 0 else None
    success = state is ProcessGroupState.ABSENT
    if not success:
        diagnostics.append(f"process-group final state is {state.value}; absence is unconfirmed")
    return ProcessGroupCleanup(
        attempted=True,
        success=success,
        killed_signal=killed_signal,
        diagnostic="; ".join(diagnostics),
    )


def _revalidate_spawn_paths(
    request: CommandRequest, executable: _PathIdentity
) -> tuple[Path, Path | None, tuple[Path, ...]]:
    workspace: Path | None = None
    if request._workspace_identity is not None:
        assert request.workspace_root is not None
        workspace = _revalidate_directory(
            request.workspace_root, request._workspace_identity, "workspace_root"
        )
    cwd: Path | None = None
    if request._cwd_identity is not None:
        assert request.cwd is not None and workspace is not None
        cwd = _revalidate_directory(request.cwd, request._cwd_identity, "cwd")
        if not _is_within(cwd, workspace):
            raise ProcessPolicyError("cwd no longer resolves inside workspace_root")
    helpers: list[Path] = []
    for index, identity in enumerate(request._helper_identities):
        helper = _revalidate_directory(
            request.trusted_helper_dirs[index], identity, f"trusted_helper_dirs[{index}]"
        )
        if workspace is not None and _is_within(helper, workspace):
            raise ProcessPolicyError(
                f"trusted_helper_dirs[{index}] moved into evaluated workspace"
            )
        helpers.append(helper)
    resolved_executable = _revalidate_executable(executable, workspace)
    return resolved_executable, cwd, tuple(helpers)


def run_command(request: CommandRequest) -> CommandResult:
    """Run one trusted executable and finalize one evidence result after cleanup."""
    if type(request) is not CommandRequest:
        raise ProcessPolicyError(f"request must be exactly CommandRequest, got {type(request).__name__}")

    workspace = request._workspace_identity.resolved if request._workspace_identity else None
    lookup_dirs = tuple(Path(entry) for entry in MINIMAL_SYSTEM_PATH.split(os.pathsep)) + tuple(
        item.resolved for item in request._helper_identities
    )
    executable = _resolve_executable(request.argv[0], lookup_dirs, workspace)
    if executable is None:
        return CommandResult(
            argv=request.argv,
            status=Status.UNSUPPORTED,
            exit_code=None,
            stdout=b"",
            stderr=b"",
            duration_ms=0,
            truncated=False,
            timed_out=False,
            killed_signal=None,
            reason_code=ProcessReason.EXECUTABLE_NOT_FOUND,
            detail=f"{request.argv[0]!r} is not on the trusted executable path",
            sensitive_argument_indices=request.sensitive_argument_indices,
            sensitive_option_names=request.sensitive_option_names,
            primary_execution_event=ProcessReason.EXECUTABLE_NOT_FOUND,
        )

    scratch: str | None = None
    scratch_cleanup_success: bool | None = None
    scratch_cleanup_detail = ""
    process: subprocess.Popen | None = None
    process_group = ProcessGroupCleanup(attempted=False, success=True)
    started = time.monotonic()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_observed = 0
    stderr_observed = 0
    stdout_retained = 0
    stderr_retained = 0
    truncated = False
    timed_out = False
    lingering_descendants = False
    exit_code: int | None = None
    primary_event = ProcessReason.SPAWN_FAILED
    status = Status.ERROR
    detail = ""

    env = build_child_environment(request.env_allowlist, dict(request.env_extra))
    try:
        scratch = tempfile.mkdtemp(prefix="iac-guard-v-")
        os.chmod(scratch, 0o700)
        home_dir = os.path.join(scratch, "home")
        os.makedirs(home_dir, mode=0o700, exist_ok=True)
        env["HOME"] = home_dir
        if request.isolated_tmpdir:
            tmp_dir = os.path.join(scratch, "tmp")
            xdg_config = os.path.join(scratch, "xdg_config")
            xdg_cache = os.path.join(scratch, "xdg_cache")
            xdg_data = os.path.join(scratch, "xdg_data")
            for directory in (tmp_dir, xdg_config, xdg_cache, xdg_data):
                os.makedirs(directory, mode=0o700, exist_ok=True)
            env.update(
                {
                    "TMPDIR": tmp_dir,
                    "XDG_CONFIG_HOME": xdg_config,
                    "XDG_CACHE_HOME": xdg_cache,
                    "XDG_DATA_HOME": xdg_data,
                }
            )

        resolved_executable, spawn_cwd, helper_dirs = _revalidate_spawn_paths(request, executable)
        path_entries = MINIMAL_SYSTEM_PATH.split(os.pathsep)
        for helper in helper_dirs:
            entry = str(helper)
            if entry not in path_entries:
                path_entries.append(entry)
        env["PATH"] = os.pathsep.join(path_entries)
        actual_argv = (str(resolved_executable),) + request.argv[1:]
        popen_kwargs: dict = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "stdin": subprocess.DEVNULL,
            "cwd": str(spawn_cwd) if spawn_cwd is not None else scratch,
            "env": env,
            "close_fds": True,
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        try:
            process = subprocess.Popen(actual_argv, **popen_kwargs)  # noqa: S603
        except (FileNotFoundError, PermissionError, OSError) as exc:
            primary_event = ProcessReason.SPAWN_FAILED
            detail = f"spawn failed: {redact_detail(str(exc))}"

        if process is not None:
            pgid = process.pid
            deadline = started + request.timeout_seconds
            assert process.stdout is not None and process.stderr is not None
            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stderr.fileno(), False)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            open_streams = 2
            try:
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
                        combined_retained = stdout_retained + stderr_retained
                        combined_remaining = max(0, request.max_output_bytes - combined_retained)
                        if key.data == "stdout":
                            stdout_observed += len(chunk)
                            stream_remaining = max(0, request.max_stdout_bytes - stdout_retained)
                            keep = min(len(chunk), stream_remaining, combined_remaining)
                            if keep:
                                stdout_chunks.append(chunk[:keep])
                                stdout_retained += keep
                        else:
                            stderr_observed += len(chunk)
                            stream_remaining = max(0, request.max_stderr_bytes - stderr_retained)
                            keep = min(len(chunk), stream_remaining, combined_remaining)
                            if keep:
                                stderr_chunks.append(chunk[:keep])
                                stderr_retained += keep
                        if keep < len(chunk):
                            truncated = True
                            break
                    if process.poll() is not None and open_streams == 0:
                        break
            finally:
                selector.close()

            if not timed_out and not truncated:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                elif process.poll() is None:
                    try:
                        process.wait(timeout=max(0, remaining))
                    except subprocess.TimeoutExpired:
                        timed_out = True

            if timed_out:
                primary_event = ProcessReason.DEADLINE_EXCEEDED
                process_group = _terminate_process_group(process, pgid)
            elif truncated:
                primary_event = ProcessReason.OUTPUT_LIMIT_EXCEEDED
                process_group = _terminate_process_group(process, pgid)
            elif process.poll() is None:
                primary_event = ProcessReason.NO_EXIT_STATUS
                process_group = _terminate_process_group(process, pgid)
            else:
                leader_exit = process.poll()
                if leader_exit is not None and leader_exit < 0:
                    primary_event = ProcessReason.KILLED_BY_SIGNAL
                elif leader_exit in request.expected_exit_codes:
                    primary_event = ProcessReason.COMPLETED_WITHIN_CONTRACT
                else:
                    primary_event = ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT
                group_state = _process_group_alive(pgid)
                if group_state is ProcessGroupState.ABSENT:
                    process_group = ProcessGroupCleanup(attempted=False, success=True)
                else:
                    lingering_descendants = group_state is ProcessGroupState.ALIVE
                    process_group = _terminate_process_group(process, pgid)

            exit_code = process.poll()
            if exit_code is None:
                try:
                    exit_code = process.wait(timeout=_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
            killed_signal = -exit_code if exit_code is not None and exit_code < 0 else None

            if not process_group.success:
                status = Status.ERROR
                reason = ProcessReason.PROCESS_GROUP_CLEANUP_FAILED
                detail = process_group.diagnostic or "process-group cleanup could not be confirmed"
            elif timed_out:
                status = Status.TIMEOUT
                reason = ProcessReason.DEADLINE_EXCEEDED
                detail = f"exceeded {request.timeout_seconds}s; process-group absence was confirmed"
            elif truncated:
                status = Status.PARTIAL
                reason = ProcessReason.OUTPUT_LIMIT_EXCEEDED
                detail = (
                    "output exceeded a retained-byte cap; process-group absence was confirmed; "
                    "output hashes cover retained bytes only"
                )
            elif lingering_descendants:
                status = Status.ERROR
                reason = ProcessReason.LINGERING_DESCENDANTS_TERMINATED
                primary_event = reason
                detail = "leader exited but descendants were found and terminated"
            elif exit_code is None:
                status = Status.ERROR
                reason = ProcessReason.NO_EXIT_STATUS
                primary_event = reason
                detail = "the child produced no exit status"
            elif exit_code < 0:
                status = Status.ERROR
                reason = ProcessReason.KILLED_BY_SIGNAL
                primary_event = reason
                detail = f"terminated by signal {-exit_code}"
            elif exit_code in request.expected_exit_codes:
                status = Status.PASS
                reason = ProcessReason.COMPLETED_WITHIN_CONTRACT
                primary_event = reason
                detail = ""
            else:
                status = Status.ERROR
                reason = ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT
                primary_event = reason
                detail = (
                    f"exit code {exit_code} is not in the adapter's declared contract "
                    f"{list(request.expected_exit_codes)}"
                )
        else:
            reason = ProcessReason.SPAWN_FAILED
            killed_signal = None
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        if scratch:
            try:
                shutil.rmtree(scratch)
                scratch_cleanup_success = True
            except OSError as cleanup_error:
                scratch_cleanup_success = False
                scratch_cleanup_detail = redact_detail(str(cleanup_error))
                logger.warning(
                    "%s", redact_detail(f"scratch cleanup failed: {cleanup_error}")
                )

    cleanup_diagnostics: list[ProcessReason] = []
    if not process_group.success:
        cleanup_diagnostics.append(ProcessReason.PROCESS_GROUP_CLEANUP_FAILED)
    if scratch_cleanup_success is False:
        cleanup_diagnostics.append(ProcessReason.SCRATCH_CLEANUP_FAILED)
        suffix = "scratch cleanup failed"
        if scratch_cleanup_detail:
            suffix += f": {scratch_cleanup_detail}"
        detail = f"{detail}; additionally: {suffix}" if detail else suffix
        if status is Status.PASS:
            status = Status.ERROR
            reason = ProcessReason.SCRATCH_CLEANUP_FAILED

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout = b"".join(stdout_chunks)
    stderr = b"".join(stderr_chunks)
    resolved_executable_text = str(executable.resolved)
    return CommandResult(
        argv=request.argv,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        truncated=truncated,
        timed_out=timed_out,
        killed_signal=killed_signal,
        reason_code=reason,
        detail=detail,
        scratch_cleanup_success=scratch_cleanup_success,
        resolved_executable=resolved_executable_text,
        sensitive_argument_indices=request.sensitive_argument_indices,
        sensitive_option_names=request.sensitive_option_names,
        process_group_cleanup_attempted=process_group.attempted,
        process_group_cleanup_success=process_group.success,
        primary_execution_event=primary_event,
        cleanup_diagnostics=tuple(cleanup_diagnostics),
        stdout_observed_bytes=stdout_observed,
        stderr_observed_bytes=stderr_observed,
        stdout_retained_bytes=len(stdout),
        stderr_retained_bytes=len(stderr),
    )


def python_command(*args: str) -> tuple:
    """Return the current trusted interpreter plus arguments."""
    return (sys.executable, *args)
