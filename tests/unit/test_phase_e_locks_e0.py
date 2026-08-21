from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.render_phase_e_lock_review import render
from tools.validate_phase_e_locks import (
    LockValidationError,
    lock_payload_sha256,
    validate_lock,
)


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "tools" / "locks" / "phase-e-locks.json"


def _payload() -> dict[str, object]:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def test_reviewed_phase_e_lock_is_complete_and_immutable() -> None:
    validate_lock(_payload())


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda p: p["tools"]["kics"].pop("license"), "kics is incomplete"),
        (lambda p: p["tools"]["trivy"]["container"].update(
            index_digest="sha256:not-a-digest"), "manifest digest"),
        (lambda p: p["tools"]["trivy"]["checks"].update(
            external_repository="ghcr.io/aquasecurity/trivy-checks:2"),
         "moving checks tag"),
        (lambda p: p["tools"]["terraform"].update(
            distribution_mode="BUNDLED"), "Terraform bundling"),
        (lambda p: p["tools"]["trivy"]["checks"].update(
            fallback_used=True), "Trivy fallback"),
        (lambda p: p["hardened_container_base"].update(
            image="docker.io/library/debian:latest"), "floating base image"),
    ],
)
def test_material_lock_mutations_fail_closed(mutation, message: str) -> None:
    payload = copy.deepcopy(_payload())
    mutation(payload)
    with pytest.raises(LockValidationError):
        validate_lock(payload)


def test_candidate_kics_release_without_runtime_assets_is_not_selected() -> None:
    payload = _payload()
    decision = payload["selection_decisions"]["kics"]
    assert decision["proposed"] == "2.1.21"
    assert decision["accepted"] == "2.1.20"
    assert "no official archives" in decision["reason"]


def test_trivy_binary_and_check_sources_are_independently_bound() -> None:
    trivy = _payload()["tools"]["trivy"]
    assert trivy["version"] == "0.73.0"
    assert trivy["container"]["index_digest"].startswith("sha256:")
    assert trivy["checks"]["external_manifest_digest"].startswith("sha256:")
    assert trivy["checks"]["selected_source"] == "external"
    assert trivy["checks"]["fallback_used"] is False
    assert trivy["checks"]["external_repository"].endswith(":2.2.0")


def test_canonical_lock_seal_binds_every_source_claim() -> None:
    payload = _payload()
    assert payload["lock_payload_sha256"] == lock_payload_sha256(payload)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["tools"]["kics"]["release"].update(commit="a" * 40),
        lambda p: p["tools"]["kics"]["archives"]["linux/amd64"].update(
            sha256="a" * 64),
        lambda p: p["tools"]["kics"]["container"].update(
            index_digest="sha256:" + "a" * 64),
        lambda p: p["tools"]["kics"]["archives"]["linux/amd64"][
            "acquisition"
        ].update(signature="CRYPTOGRAPHICALLY_VERIFIED"),
        lambda p: p["tools"]["kics"]["compatibility_test"].update(
            result="RUNTIME_PASS"),
        lambda p: p["tools"]["kics"]["container"][
            "architecture_digests"
        ].pop("linux/arm64"),
        lambda p: p["tools"]["kubeconform"].pop("schema_bundle"),
        lambda p: p["tools"]["trivy"]["checks"].update(fallback_used=True),
    ],
    ids=[
        "random-release-commit",
        "random-archive-sha",
        "random-oci-digest",
        "prose-crypto-claim",
        "prose-runtime-claim",
        "missing-arm64-child",
        "missing-kubeconform-schema",
        "trivy-embedded-fallback",
    ],
)
def test_e01_unverified_source_claims_fail_closed(mutation) -> None:
    payload = copy.deepcopy(_payload())
    mutation(payload)
    with pytest.raises(LockValidationError):
        validate_lock(payload)


def test_signature_evidence_is_structured_and_claims_are_narrow() -> None:
    statuses = {
        name: tool["archives"]["linux/amd64"]["acquisition"]["signature"][
            "status"
        ]
        for name, tool in _payload()["tools"].items()
    }
    assert statuses == {
        "kics": "VERIFIED",
        "kubeconform": "UNAVAILABLE",
        "opentofu": "VERIFIED",
        "terraform": "VERIFIED",
        "tflint": "AVAILABLE_NOT_VERIFIED",
        "trivy": "AVAILABLE_NOT_VERIFIED",
    }


def test_every_execution_reference_is_digest_qualified_per_architecture() -> None:
    for tool in _payload()["tools"].values():
        container = tool["container"]
        for architecture in ("linux/amd64", "linux/arm64"):
            assert container["execution_references"][architecture] == (
                f"{container['image']}@{container['architecture_digests'][architecture]}"
            )


def test_kubeconform_schema_and_trivy_external_runtime_are_bound() -> None:
    payload = _payload()
    schema = payload["tools"]["kubeconform"]["schema_bundle"]
    assert schema["supported_kubernetes_versions"] == ["1.34.0"]
    assert schema["strict_tree"]["file_count"] == 1304
    checks = payload["tools"]["trivy"]["checks"]
    assert checks["offline_verification"]["status"] == "RUNTIME_PASS"
    assert checks["offline_verification"]["fallback_used"] is False


def test_human_lock_review_is_generated_from_canonical_json() -> None:
    expected = (ROOT / "docs" / "spec" / "PHASE_E_LOCK_REVIEW.md").read_text(
        encoding="utf-8"
    )
    assert expected == render(_payload())
