from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from tools.validate_phase_e_locks import (
    LockValidationError,
    _verify_tag_relation,
    lock_payload_sha256,
    runtime_execution_digest,
    trivy_offline_execution_digest,
    validate_lock,
)


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "tools" / "locks" / "phase-e-locks.json"


def _payload() -> dict[str, object]:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def _reseal(payload: dict[str, object]) -> None:
    payload["lock_payload_sha256"] = lock_payload_sha256(payload)


def test_static_lock_requires_independent_source_and_runtime_verification() -> None:
    assert _payload()["verification_claims"] == {
        "schema": "REQUIRES_SCHEMA_VALIDATION",
        "source": "REQUIRES_PROTECTED_CACHE_VERIFICATION",
        "runtime": "REQUIRES_REEXECUTION_OR_SIGNED_ATTESTATION",
    }


def test_tag_relation_uses_exact_ref_map_not_unrelated_lines() -> None:
    commit = "a" * 40
    raw = (
        f"{commit}\trefs/tags/unrelated\n"
        f"{'b' * 40}\trefs/tags/v1.2.3\n"
    )
    with pytest.raises(LockValidationError, match="lightweight tag"):
        _verify_tag_relation(raw, "v1.2.3", commit, "release")


def test_annotated_tag_must_peel_to_the_locked_commit() -> None:
    commit = "a" * 40
    raw = (
        f"{'b' * 40}\trefs/tags/v1.2.3\n"
        f"{commit}\trefs/tags/v1.2.3^{{}}\n"
    )
    _verify_tag_relation(raw, "v1.2.3", commit, "release")
    with pytest.raises(LockValidationError, match="peel"):
        _verify_tag_relation(raw, "v1.2.3", "c" * 40, "release")


def test_official_repository_identity_is_closed_even_after_resealing() -> None:
    payload = copy.deepcopy(_payload())
    payload["tools"]["kics"]["release"]["repository"] = (
        "https://github.com/example/kics"
    )
    _reseal(payload)
    with pytest.raises(LockValidationError, match="official source"):
        validate_lock(payload)


def test_source_verification_rejects_structurally_valid_commit_replacement() -> None:
    payload = copy.deepcopy(_payload())
    release = payload["tools"]["kics"]["release"]
    original = release["commit"]
    replacement = "a" * 40 if original != "a" * 40 else "b" * 40
    release["commit"] = replacement
    _reseal(payload)
    validate_lock(payload)
    protected_ref_bytes = f"{original}\trefs/tags/{release['tag']}\n"
    with pytest.raises(LockValidationError, match="lightweight tag"):
        _verify_tag_relation(
            protected_ref_bytes, release["tag"], replacement, "kics.release"
        )


def test_runtime_records_bind_both_architectures_and_execution_digest() -> None:
    for tool in _payload()["tools"].values():
        assert set(tool["runtime_records"]) == {"linux/amd64", "linux/arm64"}
        for architecture, record in tool["runtime_records"].items():
            assert record["architecture"] == architecture
            assert record["execution_digest"] == runtime_execution_digest(record)
            assert record["output_schema_result"] == (
                "VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION"
            )


def test_runtime_record_mutation_fails_after_outer_lock_is_resealed() -> None:
    payload = copy.deepcopy(_payload())
    payload["tools"]["trivy"]["runtime_records"]["linux/arm64"][
        "version_output"
    ] = "Version: 999.0.0"
    _reseal(payload)
    with pytest.raises(LockValidationError, match="version_output"):
        validate_lock(payload)


def test_trivy_external_checks_runtime_is_bound_for_both_architectures() -> None:
    checks = _payload()["tools"]["trivy"]["checks"]
    records = checks["offline_verification"]["runtime_records"]
    assert set(records) == {"linux/amd64", "linux/arm64"}
    for architecture, record in records.items():
        assert record["architecture"] == architecture
        assert record["fallback_used"] is False
        assert record["network_mode"] == "none"
        assert record["checks_manifest_digest"] == checks["external_manifest_digest"]
        assert record["execution_digest"] == trivy_offline_execution_digest(record)


def test_committed_protected_cache_attestation_is_signed_and_canonical() -> None:
    payload = _payload()
    record = payload["protected_cache_attestation"]
    paths = {
        name: ROOT / record[name]
        for name in (
            "attestation_path", "manifest_path", "signature_path", "public_key_path",
        )
    }
    for name, path in paths.items():
        digest_name = name.replace("_path", "_sha256")
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record[digest_name]
    manifest = json.loads(paths["manifest_path"].read_text(encoding="utf-8"))
    encoded = json.dumps(
        manifest["files"], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == record["manifest_root"]
    verified = subprocess.run(
        [
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(paths["public_key_path"]),
            "-sigfile", str(paths["signature_path"]),
            "-in", str(paths["attestation_path"]),
        ],
        check=False,
        capture_output=True,
    )
    assert verified.returncode == 0


def test_schema_source_git_tree_and_trivy_checks_sources_are_exact() -> None:
    payload = _payload()
    schema = payload["tools"]["kubeconform"]["schema_bundle"]
    assert schema["repository"] == "https://github.com/yannh/kubernetes-json-schema"
    assert schema["source_evidence"]["extracted_file_count"] == 2608
    assert schema["source_evidence"]["commit_object_cache_path"].endswith(
        "source-commit-object.txt"
    )
    checks = payload["tools"]["trivy"]["checks"]
    assert checks["source_repository"] == "https://github.com/aquasecurity/trivy-checks"
