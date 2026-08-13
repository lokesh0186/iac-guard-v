"""No-follow source binding and verified private-view materialization."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath

from ..enums import ScanRole
from ..models import BoundInputFile, DomainError, canonical_repo_path


MATERIALIZATION_CONTRACT = "sealed-validator-materialization-v2"
MATERIALIZATION_FAILURE = "MATERIALIZED_VIEW_INTEGRITY_FAILED"
UNSAFE_PARENT = "UNSAFE_SYMLINK_PATH_COMPONENT"
READ_ONLY_DIRECTORY_MODE = 0o555
READ_ONLY_FILE_MODE = 0o444
WRITABLE_OUTPUT_DIRECTORY_MODE = 0o733
VALIDATION_SCOPE_CONTRACT = "trusted-validation-scope-v1"
SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED_DURING_VALIDATION"
_SCOPE_CONTEXT = object()


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


@dataclass(frozen=True, slots=True)
class TrustedValidationScopePlan:
    """Factory-attested complete module or Kubernetes artifact universe."""

    role: ScanRole
    scope_kind: str
    module_root: str
    files: tuple[BoundInputFile, ...]
    resource_identities: tuple[str, ...]
    manifest_sha256: str
    contract: str = VALIDATION_SCOPE_CONTRACT
    _trusted_context: object = None

    def __post_init__(self) -> None:
        if self._trusted_context is not _SCOPE_CONTEXT:
            raise DomainError("validation scope plan requires the trusted factory")
        if self.role not in {ScanRole.BASELINE, ScanRole.CANDIDATE}:
            raise DomainError("validation scope role is invalid")
        if self.scope_kind not in {"terraform-module", "kubernetes-artifact-universe"}:
            raise DomainError("validation scope kind is unsupported")
        if self.module_root != ".":
            object.__setattr__(self, "module_root", canonical_repo_path(self.module_root))
        if type(self.files) is not tuple or any(type(item) is not BoundInputFile for item in self.files):
            raise DomainError("validation scope files must be exact bound inputs")
        paths = tuple(item.file_path for item in self.files)
        if paths != tuple(sorted(set(paths))):
            raise DomainError("validation scope paths must be sorted and unique")
        if (
            type(self.resource_identities) is not tuple
            or self.resource_identities != tuple(sorted(set(self.resource_identities)))
        ):
            raise DomainError("validation scope resources must be sorted and unique")
        if self.manifest_sha256 != _scope_manifest(
            self.role, self.scope_kind, self.module_root, self.files,
            self.resource_identities,
        ):
            raise DomainError("validation scope manifest is not canonical")

    def canonical_dict(self) -> dict:
        return {
            "contract": self.contract,
            "role": self.role.value,
            "scope_kind": self.scope_kind,
            "module_root": self.module_root,
            "files": [item.canonical_dict() for item in self.files],
            "resource_identities": list(self.resource_identities),
            "manifest_sha256": self.manifest_sha256,
        }


def _scope_manifest(
    role: ScanRole, scope_kind: str, module_root: str,
    files: tuple[BoundInputFile, ...], resources: tuple[str, ...],
) -> str:
    return _sha({
        "contract": VALIDATION_SCOPE_CONTRACT,
        "role": role.value,
        "scope_kind": scope_kind,
        "module_root": module_root,
        "files": [item.canonical_dict() for item in files],
        "resource_identities": list(resources),
    })


def _terraform_scope(
    root: Path, selected: tuple[str, ...], role: ScanRole, max_file_bytes: int,
) -> TrustedValidationScopePlan:
    roots = {PurePath(item).parent.as_posix() or "." for item in selected}
    if len(roots) != 1:
        raise DomainError("MODULE_SCOPE_UNRESOLVED")
    module_root = next(iter(roots))
    module_path = root if module_root == "." else root / module_root
    # Prove the directory chain itself contains no symlink before enumerating it.
    marker = f"{module_root}/.__iacgv_scope_marker__" if module_root != "." else ".__iacgv_scope_marker__"
    try:
        parent = marker.rsplit("/", 1)[0] if "/" in marker else "."
        if parent != ".":
            descriptor, _parents = _open_source_safe(root, f"{parent}/.__missing__")
            os.close(descriptor)
    except DomainError as exc:
        # A missing final marker is expected; unsafe parents are not.
        if UNSAFE_PARENT in str(exc):
            raise
    try:
        children = sorted(os.scandir(module_path), key=lambda item: item.name)
    except OSError as exc:
        raise DomainError(SNAPSHOT_CHANGED) from exc
    paths: list[str] = []
    for child in children:
        relative = child.name if module_root == "." else f"{module_root}/{child.name}"
        metadata = child.stat(follow_symlinks=False)
        if child.name == ".terraform":
            raise DomainError("candidate .terraform state is forbidden")
        if child.name == ".tflint.hcl":
            raise DomainError("candidate module .tflint.hcl is forbidden")
        if not child.name.endswith((".tf", ".tf.json")):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise DomainError("supported Terraform module entry is not a regular file")
        paths.append(relative)
    observed = tuple(sorted(paths))
    if observed != selected:
        raise DomainError("INCOMPLETE_MODULE_SCOPE")
    bindings = tuple(
        bind_source_file(root, item, max_file_bytes, (".tf", ".tf.json"), "validation scope")[0]
        for item in observed
    )
    files = tuple(item.evidence for item in bindings)
    manifest = _scope_manifest(role, "terraform-module", module_root, files, ())
    return TrustedValidationScopePlan(
        role, "terraform-module", module_root, files, (), manifest,
        _trusted_context=_SCOPE_CONTEXT,
    )


def _kubernetes_scope(
    root: Path, selected: tuple[str, ...], role: ScanRole, max_file_bytes: int,
) -> TrustedValidationScopePlan:
    # Reuse the engine's single no-follow physical inventory and independent
    # bounded Kubernetes classifiers. Imports are lazy to avoid a module cycle.
    from ..engine import (
        _filesystem_inventory, _kubernetes_json_resources, _kubernetes_resources,
    )
    entries = _filesystem_inventory(
        root, max_files=10_000, max_file_bytes=max_file_bytes,
        max_total_bytes=64 * 1024 * 1024,
    )
    paths: list[str] = list(selected)
    resources: list[str] = []
    for entry in entries:
        if not entry.file_path.endswith((".yaml", ".yml", ".json")):
            continue
        if entry.kind != "REGULAR_FILE":
            if entry.supported:
                raise DomainError("supported Kubernetes artifact is not a regular file")
            continue
        assert entry.content is not None
        try:
            if entry.file_path.endswith(".json"):
                _documents, detected = _kubernetes_json_resources(entry.file_path, entry.content)
            else:
                _documents, detected = _kubernetes_resources(entry.file_path, entry.content)
        except DomainError:
            # Kubernetes-like malformed input is still in the required universe.
            if entry.file_path not in paths:
                paths.append(entry.file_path)
            continue
        if detected:
            if entry.file_path not in paths:
                paths.append(entry.file_path)
            resources.extend(
                f"{item.file_path}:{item.canonical_address}" for item in detected
            )
    observed = tuple(sorted(set(paths)))
    if observed != selected:
        raise DomainError("INCOMPLETE_KUBERNETES_SCOPE")
    bindings = tuple(
        bind_source_file(root, item, max_file_bytes, (".yaml", ".yml", ".json"), "validation scope")[0]
        for item in observed
    )
    files = tuple(item.evidence for item in bindings)
    identities = tuple(sorted(set(resources)))
    manifest = _scope_manifest(
        role, "kubernetes-artifact-universe", ".", files, identities,
    )
    return TrustedValidationScopePlan(
        role, "kubernetes-artifact-universe", ".", files, identities, manifest,
        _trusted_context=_SCOPE_CONTEXT,
    )


def create_trusted_validation_scope_plan(
    *, scan_root: Path, files_eligible: tuple, role: ScanRole,
    scope_kind: str, max_file_bytes: int,
) -> TrustedValidationScopePlan:
    root = scan_root.resolve(strict=True)
    selected = tuple(sorted(canonical_repo_path(item) for item in files_eligible))
    if not selected or len(selected) != len(set(selected)):
        raise DomainError("validation scope paths must be nonempty and unique")
    if scope_kind == "terraform-module":
        return _terraform_scope(root, selected, role, max_file_bytes)
    if scope_kind == "kubernetes-artifact-universe":
        return _kubernetes_scope(root, selected, role, max_file_bytes)
    raise DomainError("validation scope kind is unsupported")


def revalidate_validation_scope_plan(
    root: Path, plan: TrustedValidationScopePlan, max_file_bytes: int,
) -> None:
    if type(plan) is not TrustedValidationScopePlan or plan._trusted_context is not _SCOPE_CONTEXT:
        raise DomainError("validation scope plan is not trusted")
    try:
        observed = create_trusted_validation_scope_plan(
            scan_root=root, files_eligible=tuple(item.file_path for item in plan.files),
            role=plan.role, scope_kind=plan.scope_kind, max_file_bytes=max_file_bytes,
        )
    except DomainError as exc:
        if str(exc) in {"INCOMPLETE_MODULE_SCOPE", "INCOMPLETE_KUBERNETES_SCOPE"}:
            raise DomainError(SNAPSHOT_CHANGED) from exc
        raise
    if observed.canonical_dict() != plan.canonical_dict():
        if tuple(item.file_path for item in observed.files) == tuple(
            item.file_path for item in plan.files
        ):
            raise DomainError("INPUT_CHANGED_DURING_VALIDATION")
        raise DomainError(SNAPSHOT_CHANGED)


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


def verified_write(
    path: Path, raw: bytes, mode: int = READ_ONLY_FILE_MODE,
) -> BoundInputFile:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            write_all(descriptor, raw)
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
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
    if stat.S_IMODE(opened.st_mode) != mode:
        raise DomainError(MATERIALIZATION_FAILURE)
    return BoundInputFile(
        path.name, "regular_file", len(observed), hashlib.sha256(observed).hexdigest(),
        opened.st_dev, opened.st_ino,
    )


def materialized_view_manifest(files: tuple[BoundInputFile, ...]) -> str:
    return _sha({
        "contract": MATERIALIZATION_CONTRACT,
        "directory_mode": format(READ_ONLY_DIRECTORY_MODE, "04o"),
        "file_mode": format(READ_ONLY_FILE_MODE, "04o"),
        "files": [item.canonical_dict() for item in sorted(files, key=lambda item: item.canonical_key)],
    })


def seal_readonly_tree(destination: Path) -> None:
    directories = [destination, *(path for path in destination.rglob("*") if path.is_dir())]
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        metadata = directory.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise DomainError(MATERIALIZATION_FAILURE)
        os.chmod(directory, READ_ONLY_DIRECTORY_MODE, follow_symlinks=False)


def revalidate_materialized_view(
    destination: Path, expected_files: tuple[BoundInputFile, ...], max_file_bytes: int,
) -> str:
    expected = {item.file_path: item for item in expected_files}
    observed: list[BoundInputFile] = []
    seen_directories = set()
    for path in sorted(destination.rglob("*")):
        relative = path.relative_to(destination).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise DomainError(MATERIALIZATION_FAILURE)
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != READ_ONLY_DIRECTORY_MODE:
                raise DomainError(MATERIALIZATION_FAILURE)
            seen_directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or relative not in expected:
            raise DomainError(MATERIALIZATION_FAILURE)
        if stat.S_IMODE(metadata.st_mode) != READ_ONLY_FILE_MODE:
            raise DomainError(MATERIALIZATION_FAILURE)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            raw = _read_all(descriptor, max_file_bytes)
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        item = expected[relative]
        if len(raw) != item.size or hashlib.sha256(raw).hexdigest() != item.sha256:
            raise DomainError(MATERIALIZATION_FAILURE)
        observed.append(BoundInputFile(
            relative, "regular_file", len(raw), hashlib.sha256(raw).hexdigest(),
            opened.st_dev, opened.st_ino,
        ))
    if stat.S_IMODE(destination.lstat().st_mode) != READ_ONLY_DIRECTORY_MODE:
        raise DomainError(MATERIALIZATION_FAILURE)
    if set(item.file_path for item in observed) != set(expected):
        raise DomainError(MATERIALIZATION_FAILURE)
    required_directories = {
        parent.as_posix()
        for item in expected
        for parent in PurePath(item).parents
        if parent.as_posix() != "."
    }
    if not required_directories.issubset(seen_directories):
        raise DomainError(MATERIALIZATION_FAILURE)
    return materialized_view_manifest(tuple(observed))


def revalidate_readonly_file(path: Path, raw: bytes) -> BoundInputFile:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != READ_ONLY_FILE_MODE
    ):
        raise DomainError(MATERIALIZATION_FAILURE)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        observed = _read_all(descriptor, max(len(raw), 1))
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if observed != raw:
        raise DomainError(MATERIALIZATION_FAILURE)
    return BoundInputFile(
        path.name, "regular_file", len(raw), hashlib.sha256(raw).hexdigest(),
        opened.st_dev, opened.st_ino,
    )


def prepare_writable_output_directory(path: Path) -> None:
    path.mkdir(mode=WRITABLE_OUTPUT_DIRECTORY_MODE)
    os.chmod(path, WRITABLE_OUTPUT_DIRECTORY_MODE, follow_symlinks=False)
    revalidate_writable_output_directory(path)


def revalidate_writable_output_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != WRITABLE_OUTPUT_DIRECTORY_MODE
    ):
        raise DomainError(MATERIALIZATION_FAILURE)


def materialize_view(
    root: Path, sealed_files: tuple[SealedSourceFile, ...], destination: Path,
    max_file_bytes: int,
) -> str:
    destination.mkdir(mode=0o755)
    materialized: list[BoundInputFile] = []
    for sealed in sealed_files:
        raw = read_sealed_source(root, sealed, max_file_bytes)
        target = destination / sealed.evidence.file_path
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        written = verified_write(target, raw)
        materialized.append(BoundInputFile(
            sealed.evidence.file_path, written.file_type, written.size, written.sha256,
            written.device, written.inode,
        ))
    seal_readonly_tree(destination)
    expected = materialized_view_manifest(tuple(item.evidence for item in sealed_files))
    observed = revalidate_materialized_view(
        destination, tuple(item.evidence for item in sealed_files), max_file_bytes,
    )
    if observed != expected:
        raise DomainError(MATERIALIZATION_FAILURE)
    return observed


__all__ = [
    "MATERIALIZATION_CONTRACT", "MATERIALIZATION_FAILURE", "DirectoryIdentity",
    "READ_ONLY_DIRECTORY_MODE", "READ_ONLY_FILE_MODE", "WRITABLE_OUTPUT_DIRECTORY_MODE",
    "SealedSourceFile", "TrustedValidationScopePlan", "bind_source_file",
    "create_trusted_validation_scope_plan", "materialize_view",
    "prepare_writable_output_directory",
    "materialized_view_manifest", "read_sealed_source", "revalidate_materialized_view",
    "revalidate_readonly_file", "revalidate_validation_scope_plan",
    "revalidate_writable_output_directory",
    "seal_readonly_tree", "verified_write", "write_all",
]
