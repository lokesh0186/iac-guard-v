"""Closed workflow-command helpers; request data never becomes trusted evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .adapters.checkov import CHECKOV_CONTRACT, checkov_distribution_identity
from .config import PublicTarget, PublicVerificationRequest
from .engine import (
    _filesystem_inventory,
    _kubernetes_json_resources,
    _kubernetes_resources,
    _terraform_resources,
)
from .enums import ArtifactKind
from .models import DomainError


WORKFLOW_LOCK_CONTRACT = "iac-guard-v-workflow-lock-v1"
WORKFLOW_RECEIPT_CONTRACT = "iac-guard-v-workflow-command-v1"
_MAX_INVENTORY_FILES = 10_000
_MAX_FILE_BYTES = 10 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_GIT_CONTEXT = object()


@dataclass(frozen=True, slots=True)
class GitVerificationMaterialization:
    repository_identity: str
    base_commit: str
    base_tree: str
    head_commit: str
    head_tree: str
    changed_paths: tuple[str, ...]
    baseline_root: Path
    candidate_root: Path
    context_identity: str
    _trusted_context: object = field(repr=False, compare=False)
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        for name in ("base_commit", "base_tree", "head_commit", "head_tree"):
            if not re.fullmatch(r"[0-9a-f]{40,64}", getattr(self, name)):
                raise DomainError(f"Git materialization {name} must be a full object ID")
        for name in ("repository_identity", "context_identity"):
            value = getattr(self, name)
            if not re.fullmatch(r"[a-z0-9_]+", value):
                raise DomainError(f"Git materialization {name} is not canonical")
        if type(self.changed_paths) is not tuple or any(
            type(item) is not str or not item for item in self.changed_paths
        ):
            raise DomainError("Git changed paths must be an exact nonblank tuple")
        if len(self.changed_paths) != len(set(self.changed_paths)):
            raise DomainError("Git changed paths contain duplicates")
        for name in ("baseline_root", "candidate_root"):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_dir():
                raise DomainError(f"Git materialization {name} must be a directory")
        if self._trusted_context is not _GIT_CONTEXT:
            raise DomainError("Git materialization requires protected workflow provenance")
        object.__setattr__(self, "_trusted", True)


def _git_executable() -> Path:
    discovered = shutil.which("git")
    if discovered is None:
        raise DomainError("Git executable is unavailable")
    path = Path(discovered)
    try:
        metadata = path.stat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DomainError("Git executable cannot be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise DomainError("Git executable must be an executable regular file")
    return resolved


def _git(
    executable: Path,
    repository: Path,
    arguments: tuple[str, ...],
    *,
    max_output_bytes: int = 2 * 1024 * 1024,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> bytes:
    if type(arguments) is not tuple or any(type(item) is not str for item in arguments):
        raise DomainError("Git arguments must be an exact string tuple")
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "",
    }
    try:
        completed = subprocess.run(
            [str(executable), *arguments],
            cwd=repository,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DomainError("Git object command failed") from exc
    if len(completed.stdout) > max_output_bytes or len(completed.stderr) > 256 * 1024:
        raise DomainError("Git object command exceeded its output limit")
    if (
        type(accepted_returncodes) is not tuple
        or not accepted_returncodes
        or any(type(item) is not int or item < 0 for item in accepted_returncodes)
    ):
        raise DomainError("Git accepted return codes must be a nonempty integer tuple")
    if completed.returncode not in accepted_returncodes:
        raise DomainError("Git object command rejected the repository or ref")
    return completed.stdout


def _repository_identity(executable: Path, repository: Path) -> str:
    roots_raw = _git(
        executable,
        repository,
        ("rev-list", "--max-parents=0", "--all"),
        max_output_bytes=1024 * 1024,
    )
    roots = tuple(sorted(roots_raw.decode("ascii", errors="strict").split()))
    if not roots or any(not re.fullmatch(r"[0-9a-f]{40,64}", item) for item in roots):
        raise DomainError("Git repository identity roots are unavailable")
    remote_raw = _git(
        executable,
        repository,
        ("config", "--get", "remote.origin.url"),
        max_output_bytes=4096,
        accepted_returncodes=(0, 1),
    )
    remote = remote_raw.decode("utf-8", errors="strict").strip()
    payload = json.dumps(
        {"root_commits": list(roots), "protected_remote": remote},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "git_repository_v1_" + hashlib.sha256(payload).hexdigest()


def _safe_ref(value: str, name: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise DomainError(f"{name} must be a nonblank bounded Git ref")
    if value.startswith("-") or any(ord(character) < 32 for character in value):
        raise DomainError(f"{name} is not a safe Git ref")
    return value


def _object_id(
    executable: Path, repository: Path, expression: str, object_kind: str,
) -> str:
    raw = _git(
        executable,
        repository,
        ("rev-parse", "--verify", f"{expression}^{{{object_kind}}}"),
        max_output_bytes=1024,
    ).decode("ascii", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", raw):
        raise DomainError("Git returned a noncanonical object ID")
    return raw


def _git_tree_entries(
    executable: Path, repository: Path, commit: str,
) -> tuple[tuple[str, str, str, int], ...]:
    raw = _git(
        executable,
        repository,
        ("ls-tree", "-r", "-z", "-l", "--full-tree", commit),
        max_output_bytes=8 * 1024 * 1024,
    )
    entries: list[tuple[str, str, str, int]] = []
    total = 0
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, path_raw = record.split(b"\t", 1)
            mode_raw, kind_raw, object_raw, size_raw = header.split(b" ", 3)
            mode = mode_raw.decode("ascii")
            kind = kind_raw.decode("ascii")
            object_id = object_raw.decode("ascii")
            relative = path_raw.decode("utf-8", errors="strict")
            size = int(size_raw)
        except (UnicodeError, ValueError) as exc:
            raise DomainError("Git tree entry is malformed") from exc
        from .models import canonical_repo_path
        relative = canonical_repo_path(relative, "Git tree path")
        if mode not in {"100644", "100755", "120000"} or kind != "blob":
            raise DomainError("Git tree contains an unsupported entry type")
        if not re.fullmatch(r"[0-9a-f]{40,64}", object_id) or size < 0:
            raise DomainError("Git tree entry identity is malformed")
        if size > _MAX_FILE_BYTES:
            raise DomainError("Git tree file exceeds the protected per-file limit")
        total += size
        if total > 100 * 1024 * 1024:
            raise DomainError("Git tree exceeds the protected total-byte limit")
        entries.append((relative, mode, object_id, size))
    if len(entries) > _MAX_INVENTORY_FILES:
        raise DomainError("Git tree exceeds the protected file-count limit")
    paths = [item[0] for item in entries]
    if len(paths) != len(set(paths)):
        raise DomainError("Git tree contains duplicate canonical paths")
    return tuple(sorted(entries))


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise DomainError("Git materialization encountered a zero-byte write")
        offset += written


def _materialize_git_tree(
    executable: Path, repository: Path, commit: str, destination: Path,
) -> None:
    destination.mkdir(mode=0o700)
    entries = _git_tree_entries(executable, repository, commit)
    for relative, mode, object_id, expected_size in entries:
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = _git(
            executable,
            repository,
            ("cat-file", "blob", object_id),
            max_output_bytes=_MAX_FILE_BYTES,
        )
        if len(payload) != expected_size:
            raise DomainError("Git blob size changed during materialization")
        if mode == "120000":
            try:
                link_target = payload.decode("utf-8", errors="strict")
                os.symlink(link_target, target)
            except (OSError, UnicodeError) as exc:
                raise DomainError("Git symlink could not be materialized safely") from exc
            continue
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags, 0o600)
            try:
                _write_all(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise DomainError("Git blob could not be materialized safely") from exc
        if hashlib.sha256(target.read_bytes()).hexdigest() != hashlib.sha256(payload).hexdigest():
            raise DomainError("Git materialized bytes failed digest verification")


@contextmanager
def materialize_git_comparison(
    repository: Path, base_ref: str, head_ref: str,
):
    """Yield exact private Git trees without reading or changing the working tree."""
    if not isinstance(repository, Path):
        raise DomainError("Git repository must be pathlib.Path")
    executable = _git_executable()
    requested = repository.resolve(strict=True)
    root_raw = _git(
        executable, requested, ("rev-parse", "--show-toplevel"), max_output_bytes=4096
    )
    try:
        root = Path(root_raw.decode("utf-8", errors="strict").strip()).resolve(strict=True)
    except (OSError, UnicodeError) as exc:
        raise DomainError("Git repository root cannot be resolved") from exc
    base = _object_id(executable, root, _safe_ref(base_ref, "base_ref"), "commit")
    head = _object_id(executable, root, _safe_ref(head_ref, "head_ref"), "commit")
    base_tree = _object_id(executable, root, base, "tree")
    head_tree = _object_id(executable, root, head, "tree")
    changed_raw = _git(
        executable,
        root,
        ("diff", "--no-renames", "--name-only", "-z", base, head, "--"),
        max_output_bytes=8 * 1024 * 1024,
    )
    from .models import canonical_repo_path
    changed = tuple(sorted(
        canonical_repo_path(item.decode("utf-8", errors="strict"), "changed Git path")
        for item in changed_raw.split(b"\0") if item
    ))
    repository_identity = _repository_identity(executable, root)
    context_payload = json.dumps({
        "repository_identity": repository_identity,
        "base_commit": base,
        "base_tree": base_tree,
        "head_commit": head,
        "head_tree": head_tree,
        "changed_paths": list(changed),
    }, sort_keys=True, separators=(",", ":")).encode()
    context_identity = "git_pr_v1_" + hashlib.sha256(context_payload).hexdigest()
    temporary = Path(tempfile.mkdtemp(prefix="iacgv-git-comparison-"))
    baseline = temporary / "baseline"
    candidate = temporary / "candidate"
    try:
        _materialize_git_tree(executable, root, base, baseline)
        _git(
            executable,
            root,
            (
                "clone", "--quiet", "--no-checkout", "--no-tags", "--local",
                "--no-hardlinks",
                "--", str(root), str(candidate),
            ),
            max_output_bytes=1024 * 1024,
        )
        original_remote = _git(
            executable,
            root,
            ("config", "--get", "remote.origin.url"),
            max_output_bytes=4096,
            accepted_returncodes=(0, 1),
        ).decode("utf-8", errors="strict").strip()
        if original_remote:
            _git(executable, candidate, ("remote", "set-url", "origin", original_remote))
        else:
            _git(executable, candidate, ("remote", "remove", "origin"))
        _git(executable, candidate, ("checkout", "--quiet", "--detach", "--force", head))
        if _repository_identity(executable, candidate) != repository_identity:
            raise DomainError("private Git materialization changed repository identity")
        yield GitVerificationMaterialization(
            repository_identity,
            base,
            base_tree,
            head,
            head_tree,
            changed,
            baseline,
            candidate,
            context_identity,
            _GIT_CONTEXT,
        )
    finally:
        try:
            shutil.rmtree(temporary)
        except OSError as exc:
            raise DomainError("Git verification temporary-tree cleanup failed") from exc


def bind_inventory_targets(
    baseline_root: Path,
    targets: tuple[PublicTarget, ...],
    frameworks: tuple[str, ...],
) -> tuple[PublicTarget, ...]:
    """Resolve init selectors against the complete independent baseline inventory."""
    entries = _filesystem_inventory(
        baseline_root,
        max_files=_MAX_INVENTORY_FILES,
        max_file_bytes=_MAX_FILE_BYTES,
        max_total_bytes=_MAX_TOTAL_BYTES,
    )
    resources = []
    for entry in entries:
        if entry.kind != "REGULAR_FILE" or entry.content is None:
            continue
        path = entry.file_path
        suffix = Path(path).suffix.lower()
        if suffix == ".tf" and "terraform" in frameworks:
            resources.extend(_terraform_resources(path, entry.content))
        elif suffix in {".yaml", ".yml"} and "kubernetes" in frameworks:
            detected, _identities = _kubernetes_resources(path, entry.content)
            resources.extend(detected)
        elif suffix == ".json" and not path.lower().endswith(".tf.json") and "kubernetes" in frameworks:
            detected, _identities = _kubernetes_json_resources(path, entry.content)
            resources.extend(detected)
    # Preserve config-v1 authoring for an intentionally empty scope. Such a config
    # remains non-authoritative and verification will fail closed because its selector
    # cannot resolve. Real documented init inputs with IaC resources are bound below.
    if not resources:
        return targets
    bound: list[PublicTarget] = []
    for target in targets:
        matches = [
            item for item in resources
            if item.resource_address == target.resource_address
            and (not target.file_path or item.file_path == target.file_path)
        ]
        if not matches:
            raise DomainError(
                f"init target does not resolve in baseline inventory: "
                f"{target.rule_id}={target.resource_address}"
            )
        if len(matches) != 1:
            candidates = ", ".join(sorted(
                f"{target.rule_id}={target.resource_address}@{item.file_path}"
                for item in matches
            ))
            raise DomainError(f"init target is ambiguous; choose one exact selector: {candidates}")
        resource = matches[0]
        bound.append(PublicTarget(
            target.rule_id,
            target.resource_address,
            resource.file_path,
            resource.artifact_kind,
            resource.scanner_native_lookup,
            target.baseline_occurrences,
        ))
    return tuple(bound)


def _canonical_request(request: PublicVerificationRequest) -> dict:
    """Return the complete public request contract without adding authority."""
    if type(request) is not PublicVerificationRequest:
        raise DomainError("workflow requires an exact PublicVerificationRequest")
    return {
        "baseline": str(request.baseline_root),
        "candidate": str(request.candidate_root),
        "checkov_executable": (
            None if request.checkov_executable is None else str(request.checkov_executable)
        ),
        "execution_mode": request.execution_isolation.value,
        "frameworks": list(request.frameworks),
        "targets": [
            {
                "artifact_kind": target.artifact_kind.value,
                "baseline_occurrences": target.baseline_occurrences,
                "file_path": target.file_path,
                "resource_address": target.resource_address,
                "rule_id": target.rule_id,
                "scanner_native_lookup": target.scanner_native_lookup,
            }
            for target in request.targets
        ],
    }


def request_identity(request: PublicVerificationRequest) -> str:
    raw = json.dumps(
        _canonical_request(request), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def public_config_payload(request: PublicVerificationRequest) -> dict:
    """Serialize only fields admitted by config-v1."""
    canonical = _canonical_request(request)
    payload = {
        "schema_version": "config-v1",
        "baseline": canonical["baseline"],
        "candidate": canonical["candidate"],
        "execution_mode": canonical["execution_mode"],
        "frameworks": canonical["frameworks"],
        "targets": canonical["targets"],
    }
    if canonical["checkov_executable"] is not None:
        payload["checkov_executable"] = canonical["checkov_executable"]
    return payload


def changed_only_targets_are_bound(request: PublicVerificationRequest) -> tuple[str, ...]:
    """Require every selected PR target to name a physically changed artifact.

    This is selection validation only. The verification engine subsequently rebuilds
    and seals both complete inventories, so this helper cannot supply scan evidence.
    """
    selected = tuple(target.file_path for target in request.targets)
    if any(not item for item in selected):
        raise DomainError("pr --changed-only requires an exact file_path for every target")
    if len(selected) != len(set(selected)):
        raise DomainError("pr --changed-only target file paths must be unique")

    def inventory(root: Path) -> dict[str, tuple]:
        entries = _filesystem_inventory(
            root,
            max_files=_MAX_INVENTORY_FILES,
            max_file_bytes=_MAX_FILE_BYTES,
            max_total_bytes=_MAX_TOTAL_BYTES,
        )
        return {
            item.file_path: (
                item.kind, item.size, item.sha256, item.symlink_target,
                item.supported, item.governed, item.rejection_reason,
            )
            for item in entries
        }

    baseline = inventory(request.baseline_root)
    candidate = inventory(request.candidate_root)
    unchanged = tuple(sorted(
        item for item in selected if baseline.get(item) == candidate.get(item)
    ))
    if unchanged:
        raise DomainError(
            "pr --changed-only targets include unchanged or unclassified paths: "
            f"{list(unchanged)}"
        )
    return tuple(sorted(selected))


def create_reduced_isolation_lock(
    request: PublicVerificationRequest, *, scanner_version: str,
) -> dict:
    """Inspect the configured native scanner and create a non-evidentiary lock record."""
    from .config import ExecutionIsolation

    if request.execution_isolation is not ExecutionIsolation.REDUCED_ISOLATION:
        raise DomainError(
            "workflow lock creation requires an explicit reduced-isolation scanner; "
            "the hardened Phase-E execution image is not released"
        )
    if scanner_version not in CHECKOV_CONTRACT.supported_versions:
        raise DomainError("configured Checkov version is outside the locked contract")
    configured = request.checkov_executable
    assert configured is not None
    try:
        metadata = configured.lstat()
    except OSError as exc:
        raise DomainError("configured Checkov launcher cannot be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DomainError("configured Checkov launcher must be a no-follow regular file")
    executable = configured.resolve(strict=True)
    launcher_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    identity = checkov_distribution_identity(executable, scanner_version)
    return {
        "authority": "LOCK_RECORD_NOT_VERIFICATION_EVIDENCE",
        "config_identity": request_identity(request),
        "contract": WORKFLOW_LOCK_CONTRACT,
        "execution_mode": "reduced-isolation",
        "product_version": __version__,
        "scanner": {
            "dependency_lock_digest": identity.dependency_lock_digest,
            "installed_distribution_digest": identity.installed_distribution_digest,
            "launcher_sha256": launcher_sha256,
            "name": "checkov",
            "policy_inventory_digest": identity.policy_inventory_digest,
            "scanner_environment_digest": identity.scanner_environment_digest,
            "version": scanner_version,
        },
    }


def canonical_json(value: dict) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def write_new_regular_file(
    path: Path, payload: bytes, *, max_bytes: int = 1024 * 1024,
) -> str:
    """Create one bounded artifact without following or replacing an existing entry."""
    if not isinstance(path, Path):
        raise DomainError("workflow output path must be pathlib.Path")
    if type(max_bytes) is not int or max_bytes <= 0 or max_bytes > 25 * 1024 * 1024:
        raise DomainError("workflow output limit is outside the protected range")
    if type(payload) is not bytes or not payload or len(payload) > max_bytes:
        raise DomainError(
            "workflow output must be nonempty bytes and no larger than its protected limit"
        )
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise DomainError("workflow output parent does not exist") from exc
    if not parent.is_dir():
        raise DomainError("workflow output parent must be a directory")
    target = parent / path.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("zero-byte workflow output write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DomainError("workflow output must be a new no-follow regular file") from exc
    return hashlib.sha256(payload).hexdigest()


def command_receipt(command: str, artifact_contract: str, sha256: str) -> dict:
    return {
        "artifact_contract": artifact_contract,
        "artifact_sha256": sha256,
        "command": command,
        "contract": WORKFLOW_RECEIPT_CONTRACT,
        "status": "CREATED",
    }


__all__ = [
    "GitVerificationMaterialization", "WORKFLOW_LOCK_CONTRACT",
    "WORKFLOW_RECEIPT_CONTRACT", "bind_inventory_targets", "canonical_json",
    "changed_only_targets_are_bound", "command_receipt",
    "create_reduced_isolation_lock", "request_identity", "write_new_regular_file",
    "materialize_git_comparison", "public_config_payload",
]
