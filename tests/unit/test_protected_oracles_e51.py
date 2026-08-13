from __future__ import annotations

from pathlib import Path

import pytest

from iac_guard_v.engine import attest_checkov_scan_plan
from iac_guard_v.enums import ArtifactKind, ScanRole, Status
from iac_guard_v.models import DomainError
from iac_guard_v.oracles import (
    OracleResult,
    ProtectedOracleRegistry,
    create_protected_oracle_request,
    require_trusted_oracle_evidence,
)

from test_checkov_adapter import request as adapter_request


def _snapshot(tmp_path: Path, security_context: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec:\n"
        "  containers:\n    - name: app\n      image: example.invalid/app\n"
        f"      securityContext: {security_context}\n",
        encoding="utf-8",
    )
    discovery = attest_checkov_scan_plan(raw)
    # A normal role-bound snapshot is created by protected verification configuration.
    # Tests use the scan-plan factory context already carried by a role-bound clone.
    import iac_guard_v.engine as engine
    return engine.SealedVerificationSnapshot(
        ScanRole.CANDIDATE, "repository_v1", ".", discovery.snapshot_sha256 or "a" * 64,
        discovery.artifact_manifest_sha256 or "b" * 64, discovery.inventory_sha256,
        "c" * 64, discovery.files, discovery.classifications, discovery.resources,
        discovery.governed_paths, discovery.filesystem_entries,
        _trusted_context=engine._TRUSTED_SCAN_PLAN_CONTEXT,
    )


def _execute(tmp_path: Path, oracle_id: str, context: str):
    snapshot = _snapshot(tmp_path, context)
    request = create_protected_oracle_request(
        oracle_id=oracle_id,
        snapshot=snapshot,
        file_path="pod.yaml",
        artifact_kind=ArtifactKind.KUBERNETES_YAML,
        resource_identity="v1/Pod/default/demo",
    )
    return ProtectedOracleRegistry().execute(request)


def test_no_privileged_container_oracle_passes_and_fails(tmp_path: Path) -> None:
    passed = _execute(tmp_path / "pass", "kubernetes_no_privileged_containers_v1", "{privileged: false}")
    failed = _execute(tmp_path / "fail", "kubernetes_no_privileged_containers_v1", "{privileged: true}")
    assert passed.status is Status.PASS
    assert failed.status is Status.FAIL
    assert require_trusted_oracle_evidence(passed) is passed
    assert passed.sealed_snapshot_identity
    assert passed.protected_policy_sha256 == failed.protected_policy_sha256


def test_privilege_escalation_requires_explicit_false(tmp_path: Path) -> None:
    passed = _execute(
        tmp_path / "pass", "kubernetes_allow_privilege_escalation_false_v1",
        "{allowPrivilegeEscalation: false}",
    )
    failed = _execute(
        tmp_path / "fail", "kubernetes_allow_privilege_escalation_false_v1", "{}",
    )
    assert passed.status is Status.PASS
    assert failed.status is Status.FAIL
    assert failed.observations[0].result == "VIOLATED"


def test_unknown_oracle_and_unbound_resource_are_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, "{privileged: false}")
    with pytest.raises(DomainError, match="protected registry"):
        create_protected_oracle_request(
            oracle_id="candidate_callback", snapshot=snapshot, file_path="pod.yaml",
            artifact_kind=ArtifactKind.KUBERNETES_YAML,
            resource_identity="v1/Pod/default/demo",
        )
    with pytest.raises(DomainError, match="exact sealed resource"):
        create_protected_oracle_request(
            oracle_id="kubernetes_no_privileged_containers_v1", snapshot=snapshot,
            file_path="pod.yaml", artifact_kind=ArtifactKind.KUBERNETES_YAML,
            resource_identity="v1/Pod/default/other",
        )


def test_caller_cannot_construct_trusted_oracle_evidence() -> None:
    with pytest.raises((TypeError, DomainError)):
        OracleResult(  # type: ignore[call-arg]
            oracle_id="forged", contract_version="v1",
            implementation_build_identity="a" * 64, protected_policy_sha256="b" * 64,
            sealed_snapshot_identity="c" * 64, role=ScanRole.CANDIDATE,
            file_path="pod.yaml", artifact_kind=ArtifactKind.KUBERNETES_YAML,
            resource_identity="v1/Pod/default/demo", status=Status.PASS,
            reason="ASSERTION_SATISFIED", observations=(), raw_output_sha256="d" * 64,
            canonical_output_sha256="d" * 64, execution_controls=(),
            authoritative_reference="https://example.invalid",
        )


def test_oracle_evidence_is_deterministic(tmp_path: Path) -> None:
    first = _execute(tmp_path / "a", "kubernetes_no_privileged_containers_v1", "{privileged: false}")
    second = _execute(tmp_path / "b", "kubernetes_no_privileged_containers_v1", "{privileged: false}")
    assert first.canonical_dict() == second.canonical_dict()
    assert first.identity == second.identity
