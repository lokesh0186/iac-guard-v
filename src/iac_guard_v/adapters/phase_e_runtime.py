"""Protected container-runtime authority for Phase-E scanner execution.

Adapter requests carry this immutable capability rather than an executable selected by
candidate or serialized input.  The capability binds the exact Docker client bytes to
the live client/server/context identity observed by protected operator plumbing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..models import DomainError, canonical_identifier


_RUNTIME_CONTEXT = object()
_SHA = re.compile(r"[0-9a-f]{64}")
RUNTIME_CONTRACT = "trusted-container-runtime-v1"
REQUIRED_ISOLATION_CONTROLS = (
    "cap_drop", "cpu_limit", "memory_limit", "network_none",
    "no_new_privileges", "non_root_user", "pid_limit", "read_only_root",
)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
    ).hexdigest()


def _file_sha256(path: Path) -> tuple[str, int, int]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DomainError("CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DomainError("container runtime must be a nonsymlink regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            raise DomainError("CONTAINER_RUNTIME_CHANGED")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), metadata.st_dev, metadata.st_ino


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _strict_json(raw: bytes, label: str) -> dict:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DomainError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=no_duplicates
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DomainError(f"{label} is not valid JSON") from exc
    if type(value) is not dict:
        raise DomainError(f"{label} must be an object")
    return value


def _run_probe(executable: Path) -> dict:
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    commands = (
        ("version", (str(executable), "version", "--format", "{{json .}}")),
        ("context", (str(executable), "context", "show")),
        ("info", (str(executable), "info", "--format", "{{json .}}")),
    )
    outputs: dict[str, bytes] = {}
    for name, argv in commands:
        try:
            completed = subprocess.run(
                argv, check=False, capture_output=True, timeout=15, env=environment,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DomainError("CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE") from exc
        if completed.returncode != 0 or not completed.stdout:
            raise DomainError("CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE")
        outputs[name] = completed.stdout.strip()

    version = _strict_json(outputs["version"], "Docker version evidence")
    info = _strict_json(outputs["info"], "Docker daemon evidence")
    context = outputs["context"].decode("utf-8", errors="strict").strip()
    client = version.get("Client")
    server = version.get("Server")
    if type(client) is not dict or type(server) is not dict or not context:
        raise DomainError("CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE")
    for key in ("Version", "ApiVersion", "GitCommit", "Os", "Arch"):
        if type(client.get(key)) is not str or not client[key]:
            raise DomainError("CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE")
    for key in ("Version", "ApiVersion", "GitCommit", "Os", "Arch"):
        if type(server.get(key)) is not str or not server[key]:
            raise DomainError("CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE")
    if server.get("Os") != "linux" or info.get("OSType") != "linux":
        raise DomainError("container runtime server must execute Linux containers")
    if not all(info.get(key) is True for key in ("MemoryLimit", "CpuCfsQuota", "PidsLimit")):
        raise DomainError("container runtime lacks required resource controls")
    daemon = {
        "id": info.get("ID"),
        "name": info.get("Name"),
        "operating_system": info.get("OperatingSystem"),
        "architecture": info.get("Architecture"),
        "server_version": info.get("ServerVersion"),
        "docker_root_dir_digest": hashlib.sha256(
            str(info.get("DockerRootDir", "")).encode("utf-8")
        ).hexdigest(),
    }
    if any(value in (None, "") for value in daemon.values()):
        raise DomainError("CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE")
    return {
        "client_version": client["Version"],
        "client_identity": _canonical_sha256(client),
        "server_version": server["Version"],
        "daemon_identity": _canonical_sha256(daemon),
        "context_identity": _canonical_sha256({"context": context}),
        "platform": server["Os"],
        "architecture": server["Arch"],
    }


@dataclass(frozen=True, slots=True)
class TrustedContainerRuntime:
    """Opaque, live-attested Docker capability; the local path is noncanonical."""

    executable_sha256: str
    runtime_kind: str
    runtime_contract: str
    client_version: str
    client_identity: str
    server_version: str
    daemon_identity: str
    context_identity: str
    platform: str
    architecture: str
    supported_isolation_controls: tuple
    protected_execution_context_identity: str
    protected_evidence_identity: str
    _executable_path: Path = field(repr=False, compare=False)
    _device: int = field(repr=False, compare=False)
    _inode: int = field(repr=False, compare=False)
    _trusted_context: InitVar[object] = None
    _trusted_runtime: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        for name in (
            "executable_sha256", "client_identity", "daemon_identity",
            "context_identity", "protected_execution_context_identity",
            "protected_evidence_identity",
        ):
            value = getattr(self, name)
            if type(value) is not str or _SHA.fullmatch(value) is None:
                raise DomainError(f"{name} must be a canonical SHA-256")
        if self.runtime_kind != "docker" or self.runtime_contract != RUNTIME_CONTRACT:
            raise DomainError("container runtime contract is unsupported")
        for name in ("client_version", "server_version", "platform", "architecture"):
            canonical_identifier(getattr(self, name), name)
        controls = tuple(sorted(self.supported_isolation_controls))
        if controls != REQUIRED_ISOLATION_CONTROLS:
            raise DomainError("container runtime isolation controls are incomplete")
        if not isinstance(self._executable_path, Path):
            raise DomainError("container runtime private path is invalid")
        if type(self._device) is not int or type(self._inode) is not int:
            raise DomainError("container runtime private file identity is invalid")
        object.__setattr__(self, "supported_isolation_controls", controls)
        if _trusted_context is _RUNTIME_CONTEXT:
            object.__setattr__(self, "_trusted_runtime", True)

    @property
    def executable_path(self) -> Path:
        return self._executable_path

    @property
    def identity(self) -> str:
        return _canonical_sha256(self.canonical_dict())

    def canonical_dict(self) -> dict:
        return {
            "executable_sha256": self.executable_sha256,
            "runtime_kind": self.runtime_kind,
            "runtime_contract": self.runtime_contract,
            "client_version": self.client_version,
            "client_identity": self.client_identity,
            "server_version": self.server_version,
            "daemon_identity": self.daemon_identity,
            "context_identity": self.context_identity,
            "platform": self.platform,
            "architecture": self.architecture,
            "supported_isolation_controls": list(self.supported_isolation_controls),
            "protected_execution_context_identity": self.protected_execution_context_identity,
            "protected_evidence_identity": self.protected_evidence_identity,
        }


def attest_container_runtime(
    executable: Path,
    *,
    protected_execution_context_identity: str,
    protected_evidence: object,
    evaluated_workspaces: Iterable[Path] = (),
) -> TrustedContainerRuntime:
    """Protected operator/workflow factory; never populated from adapter JSON/config."""
    from .phase_e_lock import require_protected_phase_e_evidence

    bundle = require_protected_phase_e_evidence(protected_evidence)
    if not isinstance(executable, Path):
        raise DomainError("container runtime executable must be pathlib.Path")
    try:
        resolved = executable.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DomainError("CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE") from exc
    if executable.is_symlink():
        raise DomainError("container runtime executable must not be a symlink")
    for workspace in evaluated_workspaces:
        try:
            root = workspace.resolve(strict=True)
        except OSError as exc:
            raise DomainError("evaluated workspace cannot be resolved") from exc
        if _inside(resolved, root):
            raise DomainError("container runtime executable is inside evaluated workspace")
    digest, device, inode = _file_sha256(resolved)
    probe = _run_probe(resolved)
    observed_engine = f"{probe['server_version']} {probe['platform']}/{probe['architecture']}"
    if observed_engine != bundle.container_engine_contract:
        raise DomainError("container runtime differs from protected Phase-E evidence")
    return TrustedContainerRuntime(
        executable_sha256=digest,
        runtime_kind="docker",
        runtime_contract=RUNTIME_CONTRACT,
        client_version=probe["client_version"],
        client_identity=probe["client_identity"],
        server_version=probe["server_version"],
        daemon_identity=probe["daemon_identity"],
        context_identity=probe["context_identity"],
        platform=probe["platform"],
        architecture=probe["architecture"],
        supported_isolation_controls=REQUIRED_ISOLATION_CONTROLS,
        protected_execution_context_identity=protected_execution_context_identity,
        protected_evidence_identity=bundle.identity,
        _executable_path=resolved,
        _device=device,
        _inode=inode,
        _trusted_context=_RUNTIME_CONTEXT,
    )


def require_trusted_container_runtime(
    value: object, *, workspace_root: Path | None = None,
    protected_evidence_identity: str | None = None,
) -> TrustedContainerRuntime:
    if type(value) is not TrustedContainerRuntime or not value._trusted_runtime:
        raise DomainError("adapter requires a protected TrustedContainerRuntime")
    if protected_evidence_identity is not None and (
        value.protected_evidence_identity != protected_evidence_identity
    ):
        raise DomainError("container runtime and Phase-E evidence bundle differ")
    if workspace_root is not None and _inside(value.executable_path, workspace_root):
        raise DomainError("container runtime executable is inside evaluated workspace")
    return value


def revalidate_trusted_container_runtime(
    value: TrustedContainerRuntime, *, workspace_root: Path,
) -> str:
    runtime = require_trusted_container_runtime(value, workspace_root=workspace_root)
    digest, device, inode = _file_sha256(runtime.executable_path)
    if (
        digest != runtime.executable_sha256
        or device != runtime._device
        or inode != runtime._inode
    ):
        raise DomainError("CONTAINER_RUNTIME_CHANGED")
    probe = _run_probe(runtime.executable_path)
    expected = {
        "client_version": runtime.client_version,
        "client_identity": runtime.client_identity,
        "server_version": runtime.server_version,
        "daemon_identity": runtime.daemon_identity,
        "context_identity": runtime.context_identity,
        "platform": runtime.platform,
        "architecture": runtime.architecture,
    }
    if probe != expected:
        raise DomainError("CONTAINER_RUNTIME_CONTEXT_CHANGED")
    return runtime.identity


__all__ = [
    "RUNTIME_CONTRACT", "TrustedContainerRuntime", "attest_container_runtime",
    "require_trusted_container_runtime", "revalidate_trusted_container_runtime",
]
