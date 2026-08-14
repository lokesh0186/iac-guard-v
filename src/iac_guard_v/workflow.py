"""Closed workflow-command helpers; request data never becomes trusted evidence."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from . import __version__
from .adapters.checkov import CHECKOV_CONTRACT, checkov_distribution_identity
from .config import PublicVerificationRequest
from .engine import _filesystem_inventory
from .models import DomainError


WORKFLOW_LOCK_CONTRACT = "iac-guard-v-workflow-lock-v1"
WORKFLOW_RECEIPT_CONTRACT = "iac-guard-v-workflow-command-v1"
_MAX_INVENTORY_FILES = 10_000
_MAX_FILE_BYTES = 10 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024


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


def write_new_regular_file(path: Path, payload: bytes) -> str:
    """Create one bounded artifact without following or replacing an existing entry."""
    if not isinstance(path, Path):
        raise DomainError("workflow output path must be pathlib.Path")
    if type(payload) is not bytes or not payload or len(payload) > 1024 * 1024:
        raise DomainError("workflow output must be nonempty and no larger than 1 MiB")
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
    "WORKFLOW_LOCK_CONTRACT", "WORKFLOW_RECEIPT_CONTRACT", "canonical_json",
    "changed_only_targets_are_bound", "command_receipt",
    "create_reduced_isolation_lock", "request_identity", "write_new_regular_file",
    "public_config_payload",
]
