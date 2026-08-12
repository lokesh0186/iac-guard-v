from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.validate_phase_e_locks import LockValidationError, validate_lock


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
            manifest_digest="sha256:not-a-digest"), "manifest digest"),
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
    assert trivy["container"]["manifest_digest"].startswith("sha256:")
    assert trivy["checks"]["external_manifest_digest"].startswith("sha256:")
    assert trivy["checks"]["selected_source"] == "external"
    assert trivy["checks"]["fallback_used"] is False
    assert trivy["checks"]["external_repository"].endswith(":2.2.0")
