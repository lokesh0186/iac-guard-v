from __future__ import annotations

from pathlib import Path

import pytest

from iac_guard_v.models import DomainError
from iac_guard_v.native_properties import (
    NativeArtifactClass,
    NativePropertyRequest,
    NativePropertyResult,
    evaluate_native_request,
    load_protected_native_universe,
)


def _universe(tmp_path: Path, body: str):
    (tmp_path / "objects.yaml").write_text(body, encoding="utf-8")
    return load_protected_native_universe(
        tmp_path, NativeArtifactClass.KUBERNETES_RENDERED
    )


def _request(universe, property_id: str, subject: str, *, complete: bool = False):
    parameters = {"complete_expected_domain": True} if complete else {}
    return NativePropertyRequest.build(
        request_id=f"rbac-{property_id}",
        property_id=property_id,
        property_version="1",
        artifact_class=NativeArtifactClass.KUBERNETES_RENDERED,
        subject_identity=subject,
        parameters=parameters,
        protected_universe_identity=universe.identity,
    )


def _evaluate(universe, property_id: str, subject: str, *, complete: bool = False):
    return evaluate_native_request(
        universe, _request(universe, property_id, subject, complete=complete)
    )


BASE = """
apiVersion: v1
kind: ServiceAccount
metadata: {name: local, namespace: target}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: remote, namespace: source}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: local-role, namespace: target}
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: other-role, namespace: source}
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: global-role}
rules: []
"""


def test_rolebinding_serviceaccount_namespace_semantics(tmp_path: Path) -> None:
    universe = _universe(tmp_path, BASE + """
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: subjects, namespace: target}
subjects:
  - {kind: ServiceAccount, name: local, namespace: target}
  - {kind: ServiceAccount, name: remote, namespace: source}
  - {kind: ServiceAccount, name: local}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local-role}
""")
    binding = "rbac.authorization.k8s.io/v1/RoleBinding/target/subjects"
    scope = _evaluate(universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", binding)
    subjects = _evaluate(
        universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", binding,
        complete=True,
    )
    role = _evaluate(
        universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", binding, complete=True
    )
    assert (scope.result, subjects.result, role.result) == (
        NativePropertyResult.SATISFIED,
        NativePropertyResult.SATISFIED,
        NativePropertyResult.SATISFIED,
    )
    evaluations = scope.witness.contents["service_account_subjects"]
    assert evaluations[1]["cross_namespace"] is True
    assert evaluations[2]["namespace_source"] == "DEFAULTED_FROM_ROLEBINDING_NAMESPACE"
    assert evaluations[2]["effective_namespace"] == "target"
    assert scope.witness.contents["permission_scope"] == "target"
    assert scope.witness.contents["role_ref_target_identity"].endswith(
        "/Role/target/local-role"
    )


def test_rolebinding_clusterrole_and_multiple_remote_subjects(tmp_path: Path) -> None:
    universe = _universe(tmp_path, BASE + """
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: global, namespace: target}
subjects:
  - {kind: ServiceAccount, name: local, namespace: target}
  - {kind: ServiceAccount, name: remote, namespace: source}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: global-role}
""")
    binding = "rbac.authorization.k8s.io/v1/RoleBinding/target/global"
    assert _evaluate(
        universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", binding
    ).result is NativePropertyResult.SATISFIED
    assert _evaluate(
        universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", binding, complete=True
    ).result is NativePropertyResult.SATISFIED


@pytest.mark.parametrize("kind", ["User", "Group"])
def test_clusterrolebinding_non_namespaced_subjects(tmp_path: Path, kind: str) -> None:
    universe = _universe(tmp_path, BASE + f"""
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {{name: principal}}
subjects:
  - {{kind: {kind}, apiGroup: rbac.authorization.k8s.io, name: example, namespace: ignored}}
roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: global-role}}
""")
    binding = "rbac.authorization.k8s.io/v1/ClusterRoleBinding/_cluster/principal"
    scope = _evaluate(universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", binding)
    assert scope.result is NativePropertyResult.SATISFIED
    assert scope.witness.contents["non_service_account_subjects"][0][
        "namespace_semantics"
    ] == "NON_NAMESPACED_SUBJECT_NAMESPACE_IGNORED"


def test_clusterrolebinding_serviceaccount_requires_namespace(tmp_path: Path) -> None:
    universe = _universe(tmp_path, BASE + """
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: missing-namespace}
subjects: [{kind: ServiceAccount, name: local}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: global-role}
""")
    binding = "rbac.authorization.k8s.io/v1/ClusterRoleBinding/_cluster/missing-namespace"
    scope = _evaluate(universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", binding)
    subjects = _evaluate(
        universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", binding,
        complete=True,
    )
    assert scope.result is NativePropertyResult.VIOLATED
    assert subjects.result is NativePropertyResult.NOT_EVALUATED
    assert scope.witness.contents["service_account_subjects"][0][
        "namespace_source"
    ] == "REQUIRED_FOR_CLUSTERROLEBINDING"


@pytest.mark.parametrize(
    ("name", "role_ref", "expected"),
    [
        ("wrong-namespace", "{apiGroup: rbac.authorization.k8s.io, kind: Role, name: other-role}", NativePropertyResult.VIOLATED),
        ("missing-role", "{apiGroup: rbac.authorization.k8s.io, kind: Role, name: absent}", NativePropertyResult.VIOLATED),
        ("missing-clusterrole", "{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: absent}", NativePropertyResult.VIOLATED),
    ],
)
def test_rolebinding_role_ref_resolution_failures(
    tmp_path: Path, name: str, role_ref: str, expected: NativePropertyResult
) -> None:
    universe = _universe(tmp_path, BASE + f"""
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {{name: {name}, namespace: target}}
subjects: [{{kind: ServiceAccount, name: local}}]
roleRef: {role_ref}
""")
    binding = f"rbac.authorization.k8s.io/v1/RoleBinding/target/{name}"
    assert _evaluate(
        universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", binding, complete=True
    ).result is expected


def test_unresolved_serviceaccount_in_complete_domain(tmp_path: Path) -> None:
    universe = _universe(tmp_path, BASE + """
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: absent-subject, namespace: target}
subjects: [{kind: ServiceAccount, name: absent, namespace: source}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local-role}
""")
    binding = "rbac.authorization.k8s.io/v1/RoleBinding/target/absent-subject"
    assert _evaluate(
        universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", binding,
        complete=True,
    ).result is NativePropertyResult.VIOLATED


def test_clusterrolebinding_role_kind_is_scope_inconsistent(tmp_path: Path) -> None:
    universe = _universe(tmp_path, BASE + """
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: wrong-kind}
subjects: [{kind: ServiceAccount, name: local, namespace: target}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local-role}
""")
    binding = "rbac.authorization.k8s.io/v1/ClusterRoleBinding/_cluster/wrong-kind"
    assert _evaluate(
        universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", binding
    ).result is NativePropertyResult.VIOLATED


def test_malformed_subject_kind_fails_closed(tmp_path: Path) -> None:
    universe = _universe(tmp_path, BASE + """
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: malformed, namespace: target}
subjects: [{kind: Robot, name: example}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local-role}
""")
    binding = "rbac.authorization.k8s.io/v1/RoleBinding/target/malformed"
    assert _evaluate(
        universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", binding
    ).result is NativePropertyResult.ERROR


def test_duplicate_serviceaccount_identity_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="duplicate"):
        _universe(tmp_path, """
apiVersion: v1
kind: ServiceAccount
metadata: {name: duplicate, namespace: target}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: duplicate, namespace: target}
""")


def test_cluster_scoped_binding_namespace_contradiction_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="cluster-scoped"):
        _universe(tmp_path, """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: contradictory, namespace: target}
subjects: [{kind: User, apiGroup: rbac.authorization.k8s.io, name: example}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: view}
""")
