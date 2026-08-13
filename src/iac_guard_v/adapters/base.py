"""Scanner-neutral adapter contract evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..models import DomainError, canonical_identifier, require_int


class AdapterReason(str, Enum):
    """Closed reasons emitted by scanner adapters before the integrity engine."""

    COMPLETED = "COMPLETED"
    PROCESS_ERROR = "PROCESS_ERROR"
    EMPTY_OUTPUT = "EMPTY_OUTPUT"
    MALFORMED_JSON = "MALFORMED_JSON"
    TRUNCATED_OUTPUT = "TRUNCATED_OUTPUT"
    UNEXPECTED_TOP_LEVEL = "UNEXPECTED_TOP_LEVEL"
    EXIT_CODE_OUTSIDE_CONTRACT = "EXIT_CODE_OUTSIDE_CONTRACT"
    EXIT_RESULT_MISMATCH = "EXIT_RESULT_MISMATCH"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    KILLED_PROCESS = "KILLED_PROCESS"
    PARTIAL_SCAN = "PARTIAL_SCAN"
    ZERO_FILES_DISCOVERED = "ZERO_FILES_DISCOVERED"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    VERSION_PROBE_FAILED = "VERSION_PROBE_FAILED"
    NO_RESULTS_STRUCTURE = "NO_RESULTS_STRUCTURE"
    INVALID_RESULTS_STRUCTURE = "INVALID_RESULTS_STRUCTURE"
    COVERAGE_MISMATCH = "COVERAGE_MISMATCH"
    FRAMEWORK_MISMATCH = "FRAMEWORK_MISMATCH"
    MISSING_RESOURCE_IDENTITY = "MISSING_RESOURCE_IDENTITY"
    RAW_OUTPUT_MISSING = "RAW_OUTPUT_MISSING"
    OUTPUT_CLEANUP_FAILED = "OUTPUT_CLEANUP_FAILED"
    INPUT_CHANGED_DURING_SCAN_PREPARATION = "INPUT_CHANGED_DURING_SCAN_PREPARATION"
    SCAN_VIEW_PREPARATION_FAILED = "SCAN_VIEW_PREPARATION_FAILED"
    OUTPUT_DIRECTORY_INTEGRITY_FAILED = "OUTPUT_DIRECTORY_INTEGRITY_FAILED"
    UNKNOWN_RESULT_BUCKET = "UNKNOWN_RESULT_BUCKET"
    AGGREGATE_ONLY_EVIDENCE = "AGGREGATE_ONLY_EVIDENCE"
    SCANNER_ENVIRONMENT_MISMATCH = "SCANNER_ENVIRONMENT_MISMATCH"
    POLICY_INVENTORY_MISMATCH = "POLICY_INVENTORY_MISMATCH"
    RESOURCE_INVENTORY_MISSING = "RESOURCE_INVENTORY_MISSING"
    RESOURCE_COUNT_MISMATCH = "RESOURCE_COUNT_MISMATCH"
    CONTRADICTORY_EVALUATION_EVIDENCE = "CONTRADICTORY_EVALUATION_EVIDENCE"
    EMPTY_ELIGIBLE_SCOPE = "EMPTY_ELIGIBLE_SCOPE"
    INPUT_FILE_COUNT_EXCEEDED = "INPUT_FILE_COUNT_EXCEEDED"
    INPUT_FILE_BYTES_EXCEEDED = "INPUT_FILE_BYTES_EXCEEDED"
    INPUT_TOTAL_BYTES_EXCEEDED = "INPUT_TOTAL_BYTES_EXCEEDED"
    JSON_DEPTH_EXCEEDED = "JSON_DEPTH_EXCEEDED"
    LOCK_IDENTITY_MISMATCH = "LOCK_IDENTITY_MISMATCH"
    DUPLICATE_JSON_KEY = "DUPLICATE_JSON_KEY"
    KICS_FAILED_TO_SCAN = "KICS_FAILED_TO_SCAN"
    KICS_QUERY_EXECUTION_FAILED = "KICS_QUERY_EXECUTION_FAILED"
    KICS_SIMILARITY_ID_FAILED = "KICS_SIMILARITY_ID_FAILED"
    UNKNOWN_NATIVE_CATEGORY = "UNKNOWN_NATIVE_CATEGORY"
    EXTERNAL_CHECKS_MISSING = "EXTERNAL_CHECKS_MISSING"
    EXTERNAL_CHECKS_CHANGED = "EXTERNAL_CHECKS_CHANGED"
    EMBEDDED_CHECKS_FALLBACK = "EMBEDDED_CHECKS_FALLBACK"
    CACHE_CHANGED_DURING_EXECUTION = "CACHE_CHANGED_DURING_EXECUTION"
    MISSING_MISCONFIGURATIONS = "MISSING_MISCONFIGURATIONS"
    EXPERIMENTAL_MODIFIED_FINDINGS = "EXPERIMENTAL_MODIFIED_FINDINGS"


@dataclass(frozen=True, slots=True)
class ScannerContract:
    """Pinned executable contract; tuples are copied and canonically ordered."""

    name: str
    supported_versions: tuple
    frameworks: tuple
    expected_exit_codes: tuple

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", canonical_identifier(self.name, "adapter name"))
        for field_name in ("supported_versions", "frameworks", "expected_exit_codes"):
            if type(getattr(self, field_name)) is not tuple:
                raise DomainError(f"{field_name} must be an exact tuple")
        versions = tuple(
            canonical_identifier(item, "supported scanner version")
            for item in self.supported_versions
        )
        frameworks = tuple(
            canonical_identifier(item, "scanner framework") for item in self.frameworks
        )
        exit_codes = tuple(
            require_int(item, "expected scanner exit code")
            for item in self.expected_exit_codes
        )
        if not versions or not frameworks or not exit_codes:
            raise DomainError("scanner contract tuples must not be empty")
        if any(len(values) != len(set(values)) for values in (versions, frameworks, exit_codes)):
            raise DomainError("scanner contract tuples must not contain duplicates")
        object.__setattr__(self, "supported_versions", tuple(sorted(versions)))
        object.__setattr__(self, "frameworks", tuple(sorted(frameworks)))
        object.__setattr__(self, "expected_exit_codes", tuple(sorted(exit_codes)))

    def canonical_dict(self) -> dict:
        return {
            "name": self.name,
            "supported_versions": list(self.supported_versions),
            "frameworks": list(self.frameworks),
            "expected_exit_codes": list(self.expected_exit_codes),
        }


def read_locked_output_directory(
    root: Path,
    *,
    allowed_files: tuple[str, ...],
    max_file_bytes: int,
    max_total_bytes: int,
) -> tuple[dict[str, bytes], str]:
    """Read one flat scanner output directory through an exact no-follow contract."""
    if type(allowed_files) is not tuple or not allowed_files:
        raise DomainError("scanner output allowlist must be a nonempty tuple")
    if len(set(allowed_files)) != len(allowed_files) or tuple(sorted(allowed_files)) != allowed_files:
        raise DomainError("scanner output allowlist must be unique and sorted")
    if max_file_bytes <= 0 or max_total_bytes <= 0:
        raise DomainError("scanner output limits must be positive")
    try:
        root_metadata = root.lstat()
        entries = sorted(os.scandir(root), key=lambda item: item.name)
    except OSError as exc:
        raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value) from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
    if tuple(item.name for item in entries) != allowed_files:
        raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
    result: dict[str, bytes] = {}
    manifest: list[dict] = []
    total = 0
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value) from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
        if metadata.st_size > max_file_bytes:
            raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
        total += metadata.st_size
        if total > max_total_bytes:
            raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
        path = root / entry.name
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or opened.st_size != metadata.st_size:
                    raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
                chunks: list[bytes] = []
                size = 0
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(descriptor, min(64 * 1024, max_file_bytes + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_file_bytes:
                        raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value)
                    chunks.append(chunk)
                    digest.update(chunk)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise DomainError(AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value) from exc
        result[entry.name] = b"".join(chunks)
        manifest.append({
            "path": entry.name,
            "kind": "REGULAR_FILE",
            "size": size,
            "sha256": digest.hexdigest(),
        })
    manifest_root = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return result, manifest_root


def remove_private_tree(root: Path) -> None:
    """Restore owner permissions without following links, then remove a private tree."""
    def restore(directory: Path) -> None:
        for entry in os.scandir(directory):
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                restore(path)
                os.chmod(path, 0o700, follow_symlinks=False)
            elif stat.S_ISREG(metadata.st_mode):
                os.chmod(path, 0o600, follow_symlinks=False)
        os.chmod(directory, 0o700, follow_symlinks=False)

    restore(root)
    shutil.rmtree(root)


def require_hardened_docker_argv(
    argv: tuple[str, ...], *, pids_limit: str, memory: str, cpus: str, user: str,
) -> None:
    """Reject any locked invocation missing one material container guard."""
    required = (
        ("--pull", "never"), ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--pids-limit", pids_limit), ("--memory", memory),
        ("--cpus", cpus), ("--user", user),
    )
    if "--read-only" not in argv:
        raise DomainError("locked Docker invocation omits read-only root")
    for flag, value in required:
        if argv.count(flag) != 1:
            raise DomainError(f"locked Docker invocation omits {flag}")
        index = argv.index(flag)
        if index + 1 >= len(argv) or argv[index + 1] != value:
            raise DomainError(f"locked Docker invocation changes {flag}")
    try:
        uid = int(user.split(":", 1)[0])
    except (ValueError, IndexError) as exc:
        raise DomainError("locked Docker user is malformed") from exc
    if uid == 0:
        raise DomainError("locked Docker execution must be non-root")


def semantic_output_manifest(path: str, semantic_sha256: str) -> str:
    """Portable manifest identity over an already verified output and its semantics."""
    if not re.fullmatch(r"[0-9a-f]{64}", semantic_sha256):
        raise DomainError("semantic output digest must be a SHA-256")
    return hashlib.sha256(json.dumps(
        [{"path": path, "kind": "REGULAR_FILE", "semantic_sha256": semantic_sha256}],
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


__all__ = ["AdapterReason", "ScannerContract"]
