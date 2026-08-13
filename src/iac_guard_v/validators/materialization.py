"""No-follow source binding and verified private-view materialization."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from ..models import BoundInputFile, DomainError, canonical_repo_path


MATERIALIZATION_CONTRACT = "sealed-validator-materialization-v1"
MATERIALIZATION_FAILURE = "MATERIALIZED_VIEW_INTEGRITY_FAILED"
UNSAFE_PARENT = "UNSAFE_SYMLINK_PATH_COMPONENT"


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    relative_path: str
    device: int
    inode: int

    def canonical_dict(self) -> dict:
        return {
            "relative_path": self.relative_path,
            "device": self.device,
            "inode": self.inode,
        }


@dataclass(frozen=True, slots=True)
class SealedSourceFile:
    evidence: BoundInputFile
    parent_directories: tuple[DirectoryIdentity, ...]

    def canonical_dict(self) -> dict:
        return {
            "evidence": self.evidence.canonical_dict(),
            "parent_directories": [item.canonical_dict() for item in self.parent_directories],
        }


def _root_fd(root: Path) -> tuple[int, os.stat_result]:
    try:
        metadata = root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise DomainError("validator scan root must be a nonsymlink directory")
        descriptor = os.open(
            root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            os.close(descriptor)
            raise DomainError("validator scan root changed during binding")
        return descriptor, opened
    except OSError as exc:
        raise DomainError(f"validator input must be nonsymlink ({UNSAFE_PARENT})") from exc


def _open_source_safe(root: Path, relative: str) -> tuple[int, tuple[DirectoryIdentity, ...]]:
    """Implementation with explicit descriptor ownership for all components."""
    canonical = canonical_repo_path(relative, "validator input")
    parts = canonical.split("/")
    root_descriptor, root_stat = _root_fd(root)
    current = root_descriptor
    opened_parents: list[int] = []
    parents = [DirectoryIdentity(".", root_stat.st_dev, root_stat.st_ino)]
    try:
        prefix: list[str] = []
        for component in parts[:-1]:
            prefix.append(component)
            try:
                descriptor = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
            except OSError as exc:
                raise DomainError(f"validator input must be nonsymlink ({UNSAFE_PARENT})") from exc
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(descriptor)
                raise DomainError(f"validator input must be nonsymlink ({UNSAFE_PARENT})")
            opened_parents.append(descriptor)
            current = descriptor
            parents.append(DirectoryIdentity("/".join(prefix), metadata.st_dev, metadata.st_ino))
        try:
            descriptor = os.open(
                parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current,
            )
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise DomainError("INPUT_CHANGED_DURING_VALIDATION") from exc
            raise DomainError(f"validator input must be nonsymlink ({UNSAFE_PARENT})") from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise DomainError("validator input must be a nonsymlink regular file")
        return descriptor, tuple(parents)
    finally:
        for parent in reversed(opened_parents):
            os.close(parent)
        os.close(root_descriptor)


def _read_all(descriptor: int, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        try:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - size))
        except InterruptedError:
            continue
        if not chunk:
            break
        size += len(chunk)
        if size > max_bytes:
            raise DomainError("validator input exceeds its byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


def bind_source_file(
    root: Path, relative: str, max_bytes: int, extensions: tuple[str, ...], label: str,
) -> tuple[SealedSourceFile, bytes]:
    canonical = canonical_repo_path(relative, label)
    if not canonical.endswith(extensions):
        raise DomainError(f"{label} accepts only supported extensions")
    descriptor, parents = _open_source_safe(root, canonical)
    try:
        metadata = os.fstat(descriptor)
        raw = _read_all(descriptor, max_bytes)
    finally:
        os.close(descriptor)
    evidence = BoundInputFile(
        canonical, "regular_file", len(raw), hashlib.sha256(raw).hexdigest(),
        metadata.st_dev, metadata.st_ino,
    )
    return SealedSourceFile(evidence, parents), raw


def read_sealed_source(root: Path, sealed: SealedSourceFile, max_bytes: int) -> bytes:
    descriptor, parents = _open_source_safe(root, sealed.evidence.file_path)
    try:
        metadata = os.fstat(descriptor)
        raw = _read_all(descriptor, max_bytes)
    finally:
        os.close(descriptor)
    observed = BoundInputFile(
        sealed.evidence.file_path, "regular_file", len(raw), hashlib.sha256(raw).hexdigest(),
        metadata.st_dev, metadata.st_ino,
    )
    if observed != sealed.evidence or parents != sealed.parent_directories:
        raise DomainError("INPUT_CHANGED_DURING_VALIDATION")
    return raw


def write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(descriptor, view[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise DomainError(MATERIALIZATION_FAILURE)
        offset += written


def verified_write(path: Path, raw: bytes, mode: int = 0o400) -> BoundInputFile:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise DomainError(MATERIALIZATION_FAILURE)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            observed = _read_all(descriptor, max(len(raw), 1))
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, DomainError) as exc:
        if isinstance(exc, DomainError) and str(exc) == MATERIALIZATION_FAILURE:
            raise
        raise DomainError(MATERIALIZATION_FAILURE) from exc
    if observed != raw:
        raise DomainError(MATERIALIZATION_FAILURE)
    return BoundInputFile(
        path.name, "regular_file", len(observed), hashlib.sha256(observed).hexdigest(),
        opened.st_dev, opened.st_ino,
    )


def materialized_view_manifest(files: tuple[BoundInputFile, ...]) -> str:
    return _sha({
        "contract": MATERIALIZATION_CONTRACT,
        "files": [item.canonical_dict() for item in sorted(files, key=lambda item: item.canonical_key)],
    })


def materialize_view(
    root: Path, sealed_files: tuple[SealedSourceFile, ...], destination: Path,
    max_file_bytes: int,
) -> str:
    destination.mkdir(mode=0o700)
    materialized: list[BoundInputFile] = []
    for sealed in sealed_files:
        raw = read_sealed_source(root, sealed, max_file_bytes)
        target = destination / sealed.evidence.file_path
        target.parent.mkdir(parents=True, exist_ok=True)
        written = verified_write(target, raw)
        materialized.append(BoundInputFile(
            sealed.evidence.file_path, written.file_type, written.size, written.sha256,
            written.device, written.inode,
        ))
    expected = materialized_view_manifest(tuple(item.evidence for item in sealed_files))
    observed = materialized_view_manifest(tuple(materialized))
    if observed != expected:
        raise DomainError(MATERIALIZATION_FAILURE)
    return observed


__all__ = [
    "MATERIALIZATION_CONTRACT", "MATERIALIZATION_FAILURE", "DirectoryIdentity",
    "SealedSourceFile", "bind_source_file", "materialize_view",
    "materialized_view_manifest", "read_sealed_source", "verified_write", "write_all",
]
