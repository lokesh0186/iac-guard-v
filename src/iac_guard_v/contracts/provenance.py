"""Contract source confinement and verifier-derived provenance."""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

from ..models import DomainError
from .model import ContractProvenance, ContractSourceIdentity


CANONICAL_PROJECT_CONTRACT = ".iac-guard-v/contracts.yaml"
_COMMIT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def _regular_bytes(path: Path) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise DomainError("contract source must be a regular non-symlink file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise DomainError("contract source changed before reading")
        content = bytearray()
        while chunk := os.read(descriptor, 64 * 1024):
            content.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(content) > 1024 * 1024:
        raise DomainError("contract source exceeds the 1 MiB limit")
    if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        raise DomainError("contract source changed while reading")
    return bytes(content)


def _prove_project_authorship(root: Path, source_commit: str, content: bytes) -> None:
    """Require the canonical bytes to exist in the declared local Git commit.

    A caller-provided revision string and a canonical-looking path are not proof
    that project authors committed a contract.  This check is deliberately
    offline and reads only the already protected local repository.
    """
    if _COMMIT_ID.fullmatch(source_commit) is None:
        raise DomainError(
            "project-authored provenance requires an exact lowercase Git commit identity"
        )
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def run(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                ("git", "-C", str(root), *arguments),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DomainError("project-authored provenance could not be verified locally") from exc

    top = run("rev-parse", "--show-toplevel")
    if top.returncode != 0:
        raise DomainError("project-authored provenance requires a protected local Git repository")
    try:
        top_level = Path(top.stdout.decode("utf-8").strip()).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as exc:
        raise DomainError("project-authored Git root identity is invalid") from exc
    if top_level != root:
        raise DomainError("project-authored contract root must be the protected Git repository root")

    resolved = run("rev-parse", "--verify", f"{source_commit}^{{commit}}")
    if resolved.returncode != 0:
        raise DomainError("project-authored source commit is unavailable in the protected repository")
    try:
        exact_commit = resolved.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise DomainError("project-authored source commit identity is invalid") from exc
    if exact_commit != source_commit:
        raise DomainError("project-authored source commit identity is not exact")

    committed = run("show", f"{source_commit}:{CANONICAL_PROJECT_CONTRACT}")
    if committed.returncode != 0:
        raise DomainError("project-authored contract is absent from the declared source commit")
    if committed.stdout != content:
        raise DomainError("project-authored contract bytes differ from the declared source commit")


def derive_contract_source(
    path: Path,
    project_root: Path,
    requested: ContractProvenance | None,
    *,
    source_commit: str = "WORKTREE",
) -> tuple[ContractSourceIdentity, bytes]:
    if not isinstance(path, Path) or not isinstance(project_root, Path):
        raise DomainError("contract source paths must use pathlib.Path")
    root = project_root.resolve(strict=True)
    if not root.is_dir() or project_root.is_symlink():
        raise DomainError("protected project root must be a regular directory")
    if path.is_symlink():
        raise DomainError("contract source must be a regular non-symlink file")
    source = path.resolve(strict=True)
    try:
        relative = source.relative_to(root).as_posix()
    except ValueError as exc:
        if requested is ContractProvenance.PROJECT_AUTHORED:
            raise DomainError("external contract cannot be project-authored") from exc
        relative = f"external/{source.name}"
    canonical = relative == CANONICAL_PROJECT_CONTRACT and source == root / CANONICAL_PROJECT_CONTRACT
    content = _regular_bytes(source)
    if canonical:
        if requested not in (None, ContractProvenance.PROJECT_AUTHORED):
            provenance = requested
        else:
            _prove_project_authorship(root, source_commit, content)
            provenance = ContractProvenance.PROJECT_AUTHORED
    else:
        if requested is None or requested is ContractProvenance.PROJECT_AUTHORED:
            raise DomainError("noncanonical contract requires explicit non-project provenance")
        provenance = requested
    # Never bind evidence to a machine-local absolute checkout path.  The source
    # revision, contract bytes, and canonical project-relative path identify the
    # protected project root without leaking or varying with its local location.
    root_identity = hashlib.sha256(
        (
            "iac-guard-v:protected-project-root-v2:"
            f"{source_commit}:{relative}:{hashlib.sha256(content).hexdigest()}"
        ).encode("utf-8")
    ).hexdigest()
    return ContractSourceIdentity(
        relative,
        hashlib.sha256(content).hexdigest(),
        source_commit,
        root_identity,
        provenance,
    ), content


__all__ = ["CANONICAL_PROJECT_CONTRACT", "derive_contract_source"]
