from __future__ import annotations

from pathlib import Path
from dataclasses import replace
from unittest.mock import patch

import pytest

from iac_guard_v.engine import attest_checkov_scan_plan
from iac_guard_v.enums import ArtifactKind, ScanRole, Status
from iac_guard_v.models import DomainError
from iac_guard_v.oracles import (
    OracleObservation,
    OracleResult,
    ProtectedOracleRegistry,
    create_protected_oracle_request,
    require_trusted_oracle_evidence,
)
import iac_guard_v.oracles.base as oracle_base
import iac_guard_v.oracles.structural as structural

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


def _execute_document(tmp_path: Path, oracle_id: str, document: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(document, encoding="utf-8")
    snapshot = _role_snapshot_for_test(attest_checkov_scan_plan(raw))
    resource = snapshot.resources[0]
    request = create_protected_oracle_request(
        oracle_id=oracle_id, snapshot=snapshot, file_path="pod.yaml",
        artifact_kind=resource.artifact_kind,
        resource_identity=resource.resource_address,
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
    assert not hasattr(oracle_base, "create_oracle_result")


def test_oracle_evidence_is_deterministic(tmp_path: Path) -> None:
    first = _execute(tmp_path / "a", "kubernetes_no_privileged_containers_v1", "{privileged: false}")
    second = _execute(tmp_path / "b", "kubernetes_no_privileged_containers_v1", "{privileged: false}")
    assert first.canonical_dict() == second.canonical_dict()
    assert first.identity == second.identity


def test_json_and_workload_controller_shapes_are_supported(tmp_path: Path) -> None:
    for name, document in (
        ("pod.json", '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"demo"},"spec":{"containers":[{"name":"app","securityContext":{"privileged":false}}]}}'),
        ("deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo}\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          securityContext: {privileged: false}\n"),
        ("cron.yaml", "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: demo}\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n            - name: app\n              securityContext: {privileged: false}\n"),
    ):
        case = tmp_path / name.replace(".", "-")
        case.mkdir()
        raw = adapter_request(case, frameworks=("kubernetes",))
        (raw.scan_root / "pod.yaml").unlink()
        (raw.scan_root / name).write_text(document)
        snapshot = _role_snapshot_for_test(attest_checkov_scan_plan(raw))
        resource = snapshot.resources[0]
        result = ProtectedOracleRegistry().execute(create_protected_oracle_request(
            oracle_id="kubernetes_no_privileged_containers_v1", snapshot=snapshot,
            file_path=name, artifact_kind=resource.artifact_kind,
            resource_identity=resource.resource_address,
        ))
        assert result.status is Status.PASS


def _role_snapshot_for_test(discovery):
    import iac_guard_v.engine as engine
    return engine.SealedVerificationSnapshot(
        ScanRole.CANDIDATE, "repository_v1", ".", discovery.snapshot_sha256 or "a" * 64,
        discovery.artifact_manifest_sha256 or "b" * 64, discovery.inventory_sha256,
        "c" * 64, discovery.files, discovery.classifications, discovery.resources,
        discovery.governed_paths, discovery.filesystem_entries,
        _trusted_context=engine._TRUSTED_SCAN_PLAN_CONTEXT,
    )


def test_unsupported_kind_and_unresolved_container_scope_are_typed(tmp_path: Path) -> None:
    for name, source, expected in (
        ("service", "apiVersion: v1\nkind: Service\nmetadata: {name: demo}\n", Status.UNSUPPORTED),
        ("empty", "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec: {}\n", Status.INCONCLUSIVE),
    ):
        case = tmp_path / name
        case.mkdir()
        raw = adapter_request(case, frameworks=("kubernetes",))
        (raw.scan_root / "pod.yaml").write_text(source)
        snapshot = _role_snapshot_for_test(attest_checkov_scan_plan(raw))
        resource = snapshot.resources[0]
        result = ProtectedOracleRegistry().execute(create_protected_oracle_request(
            oracle_id="kubernetes_no_privileged_containers_v1", snapshot=snapshot,
            file_path="pod.yaml", artifact_kind=resource.artifact_kind,
            resource_identity=resource.resource_address,
        ))
        assert result.status is expected


def test_kubernetes_list_expands_to_exact_target(tmp_path: Path) -> None:
    case = tmp_path / "list"
    case.mkdir()
    raw = adapter_request(case, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: List\nitems:\n"
        "  - apiVersion: v1\n    kind: Pod\n    metadata: {name: demo}\n"
        "    spec:\n      containers: [{name: app, securityContext: {privileged: false}}]\n"
    )
    snapshot = _role_snapshot_for_test(attest_checkov_scan_plan(raw))
    result = ProtectedOracleRegistry().execute(create_protected_oracle_request(
        oracle_id="kubernetes_no_privileged_containers_v1", snapshot=snapshot,
        file_path="pod.yaml", artifact_kind=ArtifactKind.KUBERNETES_YAML,
        resource_identity="v1/Pod/default/demo",
    ))
    assert result.status is Status.PASS


def test_protected_policy_loader_rejects_malformed_or_duplicate_policy() -> None:
    for raw, message in (
        (b"not-json", "malformed"),
        (b'{"contract":"x","policies":[]}', "contract"),
        (b'{"contract":"iac-guard-v-bundled-oracle-policy-v1","policies":{}}', "records"),
        (b'{"contract":"iac-guard-v-bundled-oracle-policy-v1","contract":"x","policies":[]}', "duplicate"),
    ):
        with patch.object(structural, "_policy_bytes", return_value=raw):
            with pytest.raises(DomainError, match=message):
                structural._policies()
    malformed_record = (
        b'{"contract":"iac-guard-v-bundled-oracle-policy-v1","policies":[{}]}'
    )
    duplicate_ids = (
        b'{"contract":"iac-guard-v-bundled-oracle-policy-v1","policies":['
        b'{"oracle_id":"x","predicate":"p","authoritative_reference":"https://x","supported_kinds":[]},'
        b'{"oracle_id":"x","predicate":"p","authoritative_reference":"https://x","supported_kinds":[]}]}'
    )
    for raw, message in ((malformed_record, "record"), (duplicate_ids, "duplicated")):
        with patch.object(structural, "_policy_bytes", return_value=raw):
            with pytest.raises(DomainError, match=message):
                structural._policies()


def test_oracle_result_model_rejects_contradictions(tmp_path: Path) -> None:
    valid = _execute(
        tmp_path, "kubernetes_no_privileged_containers_v1", "{privileged: false}",
    )
    mutations = (
        ({"implementation_build_identity": "bad"}, "canonical SHA"),
        ({"role": ScanRole.DISCOVERY}, "role-bound"),
        ({"execution_controls": ("x", "x")}, "controls"),
        ({"authoritative_reference": "http://unsafe"}, "HTTPS"),
        ({"status": Status.FAIL}, "requires a violation"),
        ({"observations": (OracleObservation("x", "VIOLATED", "bad"),)}, "passing oracle"),
    )
    for values, message in mutations:
        with pytest.raises(DomainError, match=message):
            replace(valid, _trusted_context=oracle_base._EVIDENCE_CONTEXT, **values)
    with pytest.raises(DomainError, match="unsupported"):
        OracleObservation("x", "BOGUS", "bad")
    with pytest.raises(DomainError, match="detail"):
        OracleObservation("x", "SATISFIED", object())
    with pytest.raises(DomainError, match="observations"):
        replace(
            valid, _trusted_context=oracle_base._EVIDENCE_CONTEXT,
            observations=("not-typed",),
        )
    with pytest.raises(DomainError, match="duplicate paths"):
        replace(
            valid, _trusted_context=oracle_base._EVIDENCE_CONTEXT,
            observations=(valid.observations[0], valid.observations[0]),
        )


def test_internal_evaluator_fails_closed_on_unknown_policy_or_container_shape() -> None:
    policy = {"predicate": "unknown", "supported_kinds": ["Pod"]}
    document = {"kind": "Pod", "spec": {"containers": [{"name": "app"}]}}
    assert structural._evaluate(policy, document)[0] is Status.ERROR
    broken = {"kind": "Pod", "spec": {"containers": "not-list"}}
    known = {"predicate": "no_container_is_privileged", "supported_kinds": ["Pod"]}
    assert structural._evaluate(known, broken)[0] is Status.INCONCLUSIVE
    assert structural._identity({"metadata": None}) == ""
    assert structural._identity({"metadata": {"name": 1}}) == ""
    assert structural._containers({"kind": "Deployment", "spec": {}}) is None
    assert structural._containers({"kind": "Pod", "spec": "bad"}) is None
    assert structural._containers({"kind": "Pod", "spec": {"containers": ["bad"]}}) is None


def test_request_and_registry_private_boundaries_fail_closed(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, "{privileged: false}")
    resource = snapshot.resources[0]
    with pytest.raises(DomainError, match="protected factory"):
        structural.ProtectedOracleRequest(
            "kubernetes_no_privileged_containers_v1", snapshot, "pod.yaml",
            resource.artifact_kind, resource.resource_address,
        )
    with pytest.raises(DomainError, match="trusted sealed snapshot"):
        structural.ProtectedOracleRequest(
            "kubernetes_no_privileged_containers_v1", object(), "pod.yaml",
            resource.artifact_kind, resource.resource_address,
            _trusted_context=structural._REQUEST_CONTEXT,
        )
    request = create_protected_oracle_request(
        oracle_id="kubernetes_no_privileged_containers_v1", snapshot=snapshot,
        file_path="pod.yaml", artifact_kind=resource.artifact_kind,
        resource_identity=resource.resource_address,
    )
    with pytest.raises(DomainError, match="caller-authored"):
        ProtectedOracleRegistry().execute(object())
    assert ProtectedOracleRegistry().oracle_ids
    with patch.object(structural, "_documents", return_value=()):
        assert ProtectedOracleRegistry().execute(request).status is Status.INCONCLUSIVE
    with patch.object(structural, "_documents", side_effect=DomainError("bad")):
        assert ProtectedOracleRegistry().execute(request).status is Status.ERROR
    object.__setattr__(request, "artifact_kind", ArtifactKind.TERRAFORM_HCL)
    with pytest.raises(DomainError, match="does not support"):
        structural._documents(request)
    with pytest.raises(DomainError, match="not protected"):
        require_trusted_oracle_evidence(object())


@pytest.mark.parametrize(
    ("oracle_id", "field"),
    (
        ("kubernetes_no_privileged_containers_v1", "privileged: true"),
        (
            "kubernetes_allow_privilege_escalation_false_v1",
            "allowPrivilegeEscalation: true",
        ),
    ),
)
def test_ephemeral_containers_are_policy_covered(
    tmp_path: Path, oracle_id: str, field: str,
) -> None:
    result = _execute_document(
        tmp_path, oracle_id,
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec:\n"
        "  containers:\n    - name: app\n      securityContext:\n"
        "        privileged: false\n        allowPrivilegeEscalation: false\n"
        "  ephemeralContainers:\n    - name: debug\n      securityContext:\n"
        f"        {field}\n",
    )
    assert result.status is Status.FAIL
    assert any(item.path.startswith("ephemeralContainers/debug/") for item in result.observations)


@pytest.mark.parametrize(
    ("oracle_id", "context", "reason"),
    (
        (
            "kubernetes_no_privileged_containers_v1",
            '{privileged: "yes"}',
            "PRIVILEGED_FIELD_TYPE_INVALID",
        ),
        (
            "kubernetes_allow_privilege_escalation_false_v1",
            '{allowPrivilegeEscalation: "false"}',
            "PRIVILEGE_ESCALATION_FIELD_TYPE_INVALID",
        ),
        (
            "kubernetes_no_privileged_containers_v1",
            '"not-a-map"',
            "SECURITY_CONTEXT_TYPE_INVALID",
        ),
    ),
)
def test_malformed_security_context_never_passes(
    tmp_path: Path, oracle_id: str, context: str, reason: str,
) -> None:
    result = _execute(tmp_path, oracle_id, context)
    assert result.status is Status.ERROR
    assert result.reason == reason


def test_windows_privilege_escalation_is_not_applicable(tmp_path: Path) -> None:
    result = _execute_document(
        tmp_path, "kubernetes_allow_privilege_escalation_false_v1",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec:\n"
        "  os: {name: windows}\n  containers:\n    - name: app\n",
    )
    assert result.status is Status.UNSUPPORTED
    assert result.reason == "WINDOWS_POLICY_NOT_APPLICABLE"


def test_duplicate_container_names_are_typed_error(tmp_path: Path) -> None:
    result = _execute_document(
        tmp_path, "kubernetes_no_privileged_containers_v1",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec:\n"
        "  containers:\n"
        "    - name: duplicate\n      securityContext: {privileged: false}\n"
        "  initContainers:\n"
        "    - name: duplicate\n      securityContext: {privileged: false}\n",
    )
    assert result.status is Status.ERROR
    assert result.reason == "DUPLICATE_CONTAINER_IDENTITY"


def test_empty_observation_pass_is_rejected_even_with_internal_token() -> None:
    with pytest.raises(DomainError, match="affirmative satisfied observations"):
        OracleResult(
            oracle_id="forged", contract_version="v1",
            implementation_build_identity="a" * 64,
            protected_policy_sha256="b" * 64,
            sealed_snapshot_identity="c" * 64, role=ScanRole.CANDIDATE,
            file_path="pod.yaml", artifact_kind=ArtifactKind.KUBERNETES_YAML,
            resource_identity="v1/Pod/default/demo", status=Status.PASS,
            reason="ASSERTION_SATISFIED", observations=(),
            raw_output_sha256="d" * 64, canonical_output_sha256="d" * 64,
            execution_controls=(), authoritative_reference="https://example.invalid",
            _trusted_context=oracle_base._EVIDENCE_CONTEXT,
        )


def test_behavioral_helper_change_alters_implementation_identity() -> None:
    registry = ProtectedOracleRegistry()
    before = registry.implementation_build_identity

    def changed_containers(document):
        return ()

    with patch.object(structural, "_containers", changed_containers):
        after = registry.implementation_build_identity
    assert after != before
