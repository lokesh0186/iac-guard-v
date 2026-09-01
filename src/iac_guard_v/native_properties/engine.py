"""Definition-bound dispatch for native property requests."""
from __future__ import annotations

from typing import Callable

import jsonschema

from ..models import DomainError
from .evidence import validate_native_observation
from .model import (
    NativePropertyObservation,
    NativePropertyRequest,
    NativePropertyResult,
    NativePropertyWitness,
    thaw_json,
)
from .network_policy import (
    evaluate_component_closure,
    evaluate_denied_by_rendered_set,
    evaluate_egress_path,
    evaluate_ingress_path,
    evaluate_pod_network_path,
    evaluate_workload_isolated,
    evaluate_workload_selected,
)
from .opentofu_reference import evaluate_opentofu_reference_resolves
from .prometheus_operator import (
    evaluate_monitoring_ingress,
    evaluate_pod_monitor,
    evaluate_service_monitor,
)
from .rbac import (
    evaluate_binding_scope,
    evaluate_role_ref_resolves,
    evaluate_service_account_subjects,
)
from .registry import NATIVE_PROPERTY_REGISTRY
from .services import evaluate_service_port_resolution, evaluate_service_selects_workload
from .terraform import evaluate_reference_resolves
from .universe import ProtectedNativeUniverse


Evaluator = Callable[[ProtectedNativeUniverse, NativePropertyRequest], object]


_EVALUATORS: dict[str, Evaluator] = {
    "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1": evaluate_workload_selected,
    "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1": lambda universe, request: evaluate_workload_isolated(universe, request, "Ingress"),
    "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1": lambda universe, request: evaluate_workload_isolated(universe, request, "Egress"),
    "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1": evaluate_component_closure,
    "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1": evaluate_service_selects_workload,
    "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1": evaluate_service_port_resolution,
    "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1": evaluate_ingress_path,
    "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1": evaluate_egress_path,
    "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1": evaluate_pod_network_path,
    "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1": evaluate_denied_by_rendered_set,
    "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1": evaluate_service_monitor,
    "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1": evaluate_pod_monitor,
    "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1": evaluate_monitoring_ingress,
    "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1": evaluate_role_ref_resolves,
    "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1": evaluate_service_account_subjects,
    "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1": evaluate_binding_scope,
    "IACGV_TF_REFERENCE_RESOLVES_V1": evaluate_reference_resolves,
    "IACGV_OPENTOFU_REFERENCE_RESOLVES_V1": evaluate_opentofu_reference_resolves,
}


def evaluate_native_request(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> NativePropertyObservation:
    if type(universe) is not ProtectedNativeUniverse:
        raise DomainError("native evaluator requires an exact protected universe")
    if type(request) is not NativePropertyRequest:
        raise DomainError("native evaluator requires an exact request")
    if request.protected_universe_identity != universe.identity:
        raise DomainError("native request is bound to a different protected universe")
    definition = NATIVE_PROPERTY_REGISTRY.get(request.property_id)
    if definition is None:
        raise DomainError("native property ID is not in the packaged registry")
    if request.property_version != definition.property_version:
        raise DomainError("native property version is unsupported")
    if request.artifact_class is not universe.artifact_class:
        raise DomainError("native request artifact class and protected universe disagree")
    try:
        jsonschema.Draft202012Validator(thaw_json(definition.parameter_schema)).validate(
            thaw_json(request.parameters)
        )
    except jsonschema.ValidationError as exc:
        raise DomainError(f"native property parameters violate the packaged schema: {exc.message}") from exc
    evaluator = _EVALUATORS.get(request.property_id)
    if evaluator is None:
        raise DomainError("native property has no packaged evaluator")
    try:
        outcome = evaluator(universe, request)
        witness = NativePropertyWitness.build(definition.witness_type, outcome.witness_contents)
        observation = NativePropertyObservation.build(
            request=request,
            definition=definition,
            result=outcome.result,
            reason_code=outcome.reason_code,
            subject_provenance=outcome.subject_provenance,
            witness=witness,
        )
    except DomainError as exc:
        witness = NativePropertyWitness.build(definition.witness_type, {
            "evaluation_error": "DOMAIN_ERROR",
            "detail": str(exc),
            "subject_identity": request.subject_identity,
            "protected_universe_identity": universe.identity,
        })
        observation = NativePropertyObservation.build(
            request=request,
            definition=definition,
            result=NativePropertyResult.ERROR,
            reason_code="NATIVE_EVALUATION_ERROR",
            subject_provenance={
                "subject_identity": request.subject_identity,
                "protected_universe_identity": universe.identity,
            },
            witness=witness,
        )
    validate_native_observation(observation)
    return observation


def evaluate_native_requests(
    universe: ProtectedNativeUniverse, requests: tuple[NativePropertyRequest, ...]
) -> tuple[NativePropertyObservation, ...]:
    if type(requests) is not tuple:
        raise DomainError("native requests must be an exact tuple")
    request_ids = [item.request_id for item in requests]
    if len(request_ids) != len(set(request_ids)):
        raise DomainError("native request IDs must be unique")
    return tuple(evaluate_native_request(universe, item) for item in requests)


__all__ = ["evaluate_native_request", "evaluate_native_requests"]
