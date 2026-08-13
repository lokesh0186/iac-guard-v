"""Private test-only Phase-E capabilities; excluded from product wheels and sdists."""
from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from iac_guard_v.adapters.kics import KicsAdapter
from iac_guard_v.adapters.phase_e_lock import (
    LockedContainerIdentity,
    ProtectedChecksCacheIdentity,
    _TRIVY_CACHE_PREFIX,
    _canonical_sha256,
    _physical_inventory,
)
from iac_guard_v.adapters.trivy import TrivyAdapter
from iac_guard_v.adapters.phase_e_runtime import (
    REQUIRED_ISOLATION_CONTROLS,
    RUNTIME_CONTRACT,
    TrustedContainerRuntime,
)
from iac_guard_v.process import CommandResult


def make_test_container_runtime(
    locked: LockedContainerIdentity, executable: Path,
) -> TrustedContainerRuntime:
    """Create nonshipped runtime evidence for isolated parser/adapter unit tests."""
    resolved = executable.resolve(strict=True)
    metadata = resolved.stat()
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    value = object.__new__(TrustedContainerRuntime)
    fields = {
        "executable_sha256": digest,
        "runtime_kind": "docker",
        "runtime_contract": RUNTIME_CONTRACT,
        "client_version": "private-test-client",
        "client_identity": "1" * 64,
        "server_version": "private-test-server",
        "daemon_identity": "2" * 64,
        "context_identity": "3" * 64,
        "platform": "linux",
        "architecture": "arm64",
        "supported_isolation_controls": REQUIRED_ISOLATION_CONTROLS,
        "protected_execution_context_identity": "4" * 64,
        "protected_evidence_identity": locked.protected_evidence_identity,
        "_executable_path": resolved,
        "_device": metadata.st_dev,
        "_inode": metadata.st_ino,
        "_trusted_runtime": True,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


def test_protected_checks_cache_identity(
    cache_root: Path, locked: LockedContainerIdentity,
) -> ProtectedChecksCacheIdentity:
    """Construct unit-fixture cache evidence only inside the non-shipped tests tree."""
    container = cache_root.parent.parent
    subtree = _physical_inventory(cache_root, prefix=_TRIVY_CACHE_PREFIX)
    metadata = cache_root / "policy/metadata.json"
    value = object.__new__(ProtectedChecksCacheIdentity)
    fields = {
        "protected_manifest_root": "0" * 64,
        "trivy_subtree_root": _canonical_sha256(list(subtree)),
        "external_manifest_digest": locked.checks_manifest_digest,
        "external_layer_digest": locked.checks_layer_digest,
        "cache_metadata_sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
        "cache_attestation_identity": "private-test-cache-attestation",
        "cache_attestation_record_sha256": "0" * 64,
        "cache_attestation_signature_sha256": "0" * 64,
        "_cache_root": container,
        "_expected_subtree_entries": subtree,
        "_trusted_cache_evidence": True,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


def normalize_kics_fixture(
    raw: bytes, request, process: CommandResult,
):
    def execute(command):
        output_mount = next(
            item for item in command.argv if item.endswith(":/iacgv-output:rw")
        )
        output = Path(output_mount.removesuffix(":/iacgv-output:rw"))
        if process.status.value == "PASS":
            (output / "results.json").write_bytes(raw)
        return replace(process, argv=command.argv)

    with patch("iac_guard_v.adapters.kics.run_command", execute), patch(
        "iac_guard_v.adapters.kics.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        return KicsAdapter().scan(request)


def normalize_trivy_fixture(
    raw: bytes, request, process: CommandResult,
):
    def execute(command):
        output_mount = next(item for item in command.argv if item.endswith(":/out:rw"))
        output = Path(output_mount.removesuffix(":/out:rw"))
        if process.status.value == "PASS":
            (output / "results.json").write_bytes(raw)
        return replace(process, argv=command.argv)

    with patch("iac_guard_v.adapters.trivy.run_command", execute), patch(
        "iac_guard_v.adapters.trivy.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        return TrivyAdapter().scan(request)
