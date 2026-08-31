"""Kubernetes RBAC binding identity and scope relationships (not authorization)."""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError
from .model import NativePropertyRequest, NativePropertyResult, thaw_json
from .outcome import EvaluationOutcome
from .universe import KubernetesResource, ProtectedNativeUniverse


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if type(value) not in (dict, MappingProxyType):
        raise DomainError(f"{label} must be a mapping")
    return value


def _binding(universe: ProtectedNativeUniverse, identity: str) -> KubernetesResource:
    resource = universe.kubernetes_resource(identity)
    if resource.api_version != "rbac.authorization.k8s.io/v1" or resource.kind not in {
        "RoleBinding", "ClusterRoleBinding"
    }:
        raise DomainError("native RBAC subject must be a v1 binding")
    return resource


def _complete_domain(params: Mapping[str, Any]) -> bool:
    value = params.get("complete_expected_domain", False)
    if type(value) is not bool:
        raise DomainError("complete_expected_domain must be an exact bool")
    return value


def _role_ref(binding: KubernetesResource) -> Mapping[str, Any]:
    role_ref = _mapping(binding.data.get("roleRef"), "RBAC roleRef")
    if set(role_ref) - {"apiGroup", "kind", "name"}:
        raise DomainError("RBAC roleRef contains unsupported fields")
    if (
        role_ref.get("apiGroup") != "rbac.authorization.k8s.io"
        or type(role_ref.get("kind")) is not str
        or type(role_ref.get("name")) is not str
        or not role_ref.get("name")
    ):
        raise DomainError("RBAC roleRef is malformed")
    return role_ref


def _role_target_identity(binding: KubernetesResource, role_ref: Mapping[str, Any]) -> tuple[str | None, str]:
    kind = role_ref["kind"]
    name = role_ref["name"]
    if binding.kind == "RoleBinding" and kind == "Role":
        return f"rbac.authorization.k8s.io/v1/Role/{binding.namespace}/{name}", "NAMESPACED_ROLE"
    if kind == "ClusterRole":
        return f"rbac.authorization.k8s.io/v1/ClusterRole/_cluster/{name}", "CLUSTER_ROLE"
    return None, "SCOPE_INCONSISTENT"


def evaluate_role_ref_resolves(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    binding = _binding(universe, request.subject_identity)
    params = thaw_json(request.parameters)
    role_ref = _role_ref(binding)
    target_identity, scope_state = _role_target_identity(binding, role_ref)
    target = None
    if target_identity is not None:
        matches = tuple(
            item for item in universe.kubernetes_resources if item.identity == target_identity
        )
        if len(matches) > 1:
            raise DomainError("RBAC roleRef target identity is ambiguous")
        target = matches[0] if matches else None
    if scope_state == "SCOPE_INCONSISTENT":
        result = NativePropertyResult.VIOLATED
        reason = "RBAC_ROLE_REF_SCOPE_INCONSISTENT"
    elif target is not None:
        result = NativePropertyResult.SATISFIED
        reason = "RBAC_ROLE_REF_RESOLVED"
    elif _complete_domain(params):
        result = NativePropertyResult.VIOLATED
        reason = "RBAC_ROLE_REF_UNRESOLVED_IN_COMPLETE_PROTECTED_SET"
    else:
        result = NativePropertyResult.NOT_EVALUATED
        reason = "EXTERNAL_IDENTITY_NOT_PROTECTED"
    return EvaluationOutcome(
        result,
        reason,
        {
            "binding": binding.provenance_dict(),
            "binding_kind": binding.kind,
            "binding_namespace": binding.namespace,
            "role_ref": dict(role_ref),
            "scope_state": scope_state,
            "expected_target_identity": target_identity,
            "resolved_target": target.provenance_dict() if target is not None else None,
            "resolution_domain": "COMPLETE_PROTECTED_SET" if _complete_domain(params) else "PROTECTED_RENDERED_SET",
            "authorization_simulated": False,
        },
        binding.provenance_dict(),
    )


def _subjects(binding: KubernetesResource) -> tuple[tuple[int, Mapping[str, Any]], ...]:
    subjects = binding.data.get("subjects", ())
    if subjects is None:
        subjects = ()
    if type(subjects) not in (list, tuple):
        raise DomainError("RBAC subjects must be a list")
    result = []
    for index, raw in enumerate(subjects):
        subject = _mapping(raw, "RBAC subject")
        if set(subject) - {"apiGroup", "kind", "name", "namespace"}:
            raise DomainError("RBAC subject contains unsupported fields")
        kind = subject.get("kind")
        if kind not in {"ServiceAccount", "User", "Group"}:
            raise DomainError("RBAC subject kind is unsupported")
        if type(subject.get("name")) is not str or not subject.get("name"):
            raise DomainError("RBAC subject name is malformed")
        namespace = subject.get("namespace")
        if namespace is not None and type(namespace) is not str:
            raise DomainError("RBAC subject namespace is malformed")
        if kind == "ServiceAccount":
            if subject.get("apiGroup") not in (None, ""):
                raise DomainError("ServiceAccount subject apiGroup must be empty")
        elif subject.get("apiGroup") != "rbac.authorization.k8s.io":
            raise DomainError("User/Group subject apiGroup must be rbac.authorization.k8s.io")
        result.append((index, subject))
    return tuple(result)


def _service_account_subjects(binding: KubernetesResource) -> tuple[tuple[int, Mapping[str, Any]], ...]:
    return tuple(
        (index, subject)
        for index, subject in _subjects(binding)
        if subject.get("kind") == "ServiceAccount"
    )


def _service_account_namespace(
    binding: KubernetesResource, subject: Mapping[str, Any]
) -> tuple[str | None, str, bool]:
    declared = subject.get("namespace")
    if type(declared) is str and declared:
        return declared, "EXPLICIT_SUBJECT_NAMESPACE", True
    if binding.kind == "RoleBinding":
        return binding.namespace, "DEFAULTED_FROM_ROLEBINDING_NAMESPACE", True
    return None, "REQUIRED_FOR_CLUSTERROLEBINDING", False


def evaluate_service_account_subjects(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    binding = _binding(universe, request.subject_identity)
    params = thaw_json(request.parameters)
    subjects = _service_account_subjects(binding)
    evaluations = []
    unresolved = False
    indeterminate = False
    for index, subject in subjects:
        name = subject.get("name")
        declared_namespace = subject.get("namespace")
        namespace, namespace_source, namespace_valid = _service_account_namespace(
            binding, subject
        )
        if type(name) is not str or not name:
            raise DomainError("ServiceAccount subject name is malformed")
        if not namespace_valid or namespace is None:
            indeterminate = True
            evaluations.append({
                "subject_index": index,
                "name": name,
                "declared_namespace": declared_namespace,
                "effective_namespace": None,
                "namespace_source": namespace_source,
                "expected_identity": None,
                "resolved_target": None,
                "reason": "SERVICEACCOUNT_NAMESPACE_NOT_EXPLICIT",
            })
            continue
        identity = f"v1/ServiceAccount/{namespace}/{name}"
        matches = tuple(
            item for item in universe.kubernetes_resources if item.identity == identity
        )
        if len(matches) > 1:
            raise DomainError("ServiceAccount subject identity is ambiguous")
        target = matches[0] if matches else None
        if target is None:
            if _complete_domain(params):
                unresolved = True
                reason = "SERVICEACCOUNT_UNRESOLVED_IN_COMPLETE_PROTECTED_SET"
            else:
                indeterminate = True
                reason = "EXTERNAL_IDENTITY_NOT_PROTECTED"
        else:
            reason = "SERVICEACCOUNT_SUBJECT_RESOLVED"
        evaluations.append({
            "subject_index": index,
            "name": name,
            "declared_namespace": declared_namespace,
            "effective_namespace": namespace,
            "namespace_source": namespace_source,
            "expected_identity": identity,
            "resolved_target": target.provenance_dict() if target is not None else None,
            "reason": reason,
        })
    if not subjects:
        result = NativePropertyResult.NOT_EVALUATED
        reason = "NO_SERVICEACCOUNT_SUBJECTS"
    elif unresolved:
        result = NativePropertyResult.VIOLATED
        reason = "RBAC_SERVICEACCOUNT_SUBJECT_UNRESOLVED"
    elif indeterminate:
        result = NativePropertyResult.NOT_EVALUATED
        reason = "RBAC_SERVICEACCOUNT_SUBJECT_NOT_FULLY_PROTECTED"
    else:
        result = NativePropertyResult.SATISFIED
        reason = "RBAC_SERVICEACCOUNT_SUBJECTS_RESOLVED"
    return EvaluationOutcome(
        result,
        reason,
        {
            "binding": binding.provenance_dict(),
            "binding_kind": binding.kind,
            "binding_namespace": binding.namespace,
            "resolution_domain": "COMPLETE_PROTECTED_SET" if _complete_domain(params) else "PROTECTED_RENDERED_SET",
            "service_account_subjects": evaluations,
            "non_service_account_subjects": len(_subjects(binding)) - len(subjects),
            "authorization_simulated": False,
        },
        binding.provenance_dict(),
    )


def evaluate_binding_scope(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    binding = _binding(universe, request.subject_identity)
    role_ref = _role_ref(binding)
    role_target_identity, role_scope = _role_target_identity(binding, role_ref)
    subject_evaluations = []
    valid = role_scope != "SCOPE_INCONSISTENT"
    for index, subject in _service_account_subjects(binding):
        declared_namespace = subject.get("namespace")
        effective_namespace, namespace_source, namespace_valid = _service_account_namespace(
            binding, subject
        )
        subject_evaluations.append({
            "subject_index": index,
            "name": subject.get("name"),
            "declared_namespace": declared_namespace,
            "effective_namespace": effective_namespace,
            "namespace_source": namespace_source,
            "namespace_valid": namespace_valid,
            "cross_namespace": (
                binding.kind == "RoleBinding"
                and effective_namespace is not None
                and effective_namespace != binding.namespace
            ),
        })
        valid = valid and namespace_valid
    non_service_account_subjects = [
        {
            "subject_index": index,
            "kind": subject.get("kind"),
            "name": subject.get("name"),
            "namespace": subject.get("namespace"),
            "namespace_semantics": "NON_NAMESPACED_SUBJECT_NAMESPACE_IGNORED",
        }
        for index, subject in _subjects(binding)
        if subject.get("kind") in {"User", "Group"}
    ]
    return EvaluationOutcome(
        NativePropertyResult.SATISFIED if valid else NativePropertyResult.VIOLATED,
        "RBAC_BINDING_SCOPE_CONSISTENT" if valid else "RBAC_BINDING_SCOPE_INCONSISTENT",
        {
            "binding": binding.provenance_dict(),
            "binding_kind": binding.kind,
            "binding_namespace": binding.namespace,
            "permission_scope": binding.namespace if binding.kind == "RoleBinding" else "_cluster",
            "role_ref": dict(role_ref),
            "role_ref_scope": role_scope,
            "role_ref_target_identity": role_target_identity,
            "service_account_subjects": subject_evaluations,
            "non_service_account_subjects": non_service_account_subjects,
            "authorization_simulated": False,
        },
        binding.provenance_dict(),
    )


__all__ = [
    "evaluate_binding_scope",
    "evaluate_role_ref_resolves",
    "evaluate_service_account_subjects",
]
