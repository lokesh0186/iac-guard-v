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
    ProtectedKubernetesSchemaIdentity,
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
    full = _physical_inventory(container)
    subtree = _physical_inventory(cache_root, prefix=_TRIVY_CACHE_PREFIX)
    metadata = cache_root / "policy/metadata.json"
    value = object.__new__(ProtectedChecksCacheIdentity)
    fields = {
        "protected_manifest_root": _canonical_sha256(list(full)),
        "trivy_subtree_root": _canonical_sha256(list(subtree)),
        "external_manifest_digest": locked.checks_manifest_digest,
        "external_layer_digest": locked.checks_layer_digest,
        "cache_metadata_sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
        "cache_attestation_identity": "private-test-cache-attestation",
        "cache_attestation_public_key_sha256": "5" * 64,
        "cache_attestation_record_sha256": "0" * 64,
        "cache_attestation_signature_sha256": "0" * 64,
        "_cache_root": container,
        "_expected_full_entries": full,
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


def execute_terraform_validator_fixture(request, process: CommandResult):
    """Drive the product validator through its private execution path in unit tests."""
    from iac_guard_v.validators.terraform import TerraformValidator

    def execute(command):
        return replace(process, argv=command.argv)

    with patch("iac_guard_v.validators.terraform.run_command", execute), patch(
        "iac_guard_v.validators.terraform.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        return TerraformValidator().validate(request)


def make_test_kubernetes_schema_identity(root: Path) -> ProtectedKubernetesSchemaIdentity:
    """Nonshipped digest-shaped schema capability for validator unit tests."""
    root.mkdir(parents=True, exist_ok=True)
    value = object.__new__(ProtectedKubernetesSchemaIdentity)
    fields = {
        "repository": "https://github.com/yannh/kubernetes-json-schema",
        "commit": "c8f4e61c63bc529749125ac566bccc6986e08d45",
        "kubernetes_version": "1.34.0", "strict": True,
        "tree_manifest_root": "1" * 64, "file_count": 1, "total_bytes": 1,
        "bundle_content_digest": "2" * 64, "license_id": "NOASSERTION",
        "protected_cache_manifest_root": "3" * 64,
        "cache_attestation_identity": "private-test-cache",
        "_schema_root": root, "_protected_cache": object(),
        "_trusted_schema_evidence": True,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


def execute_kubeconform_fixture(request, process: CommandResult):
    from iac_guard_v.validators.kubeconform import KubeconformValidator

    def execute(command):
        return replace(process, argv=command.argv)

    with patch("iac_guard_v.validators.kubeconform.run_command", execute), patch(
        "iac_guard_v.validators.kubeconform.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ), patch.object(ProtectedKubernetesSchemaIdentity, "revalidate", return_value="1" * 64):
        return KubeconformValidator().validate(request)


def execute_tflint_fixture(request, process: CommandResult):
    from iac_guard_v.validators.tflint import TflintValidator

    def execute(command):
        return replace(process, argv=command.argv)

    with patch("iac_guard_v.validators.tflint.run_command", execute), patch(
        "iac_guard_v.validators.tflint.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        return TflintValidator().validate(request)
