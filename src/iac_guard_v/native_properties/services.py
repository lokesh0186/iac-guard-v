"""Service selector and ServicePort-to-container graph semantics."""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError
from .model import NativePropertyRequest, NativePropertyResult, thaw_json
from .outcome import EvaluationOutcome
from .selectors import evaluate_label_selector, service_selector_as_label_selector
from .universe import KubernetesResource, ProtectedNativeUniverse, WorkloadIdentity


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if type(value) not in (dict, MappingProxyType):
        raise DomainError(f"{label} must be a mapping")
    return value


def _service(universe: ProtectedNativeUniverse, identity: str) -> KubernetesResource:
    resource = universe.kubernetes_resource(identity)
    if resource.api_version != "v1" or resource.kind != "Service":
        raise DomainError("native Service property subject must be a v1 Service")
    return resource


def service_selection_witness(
    universe: ProtectedNativeUniverse, service: KubernetesResource
) -> tuple[tuple[WorkloadIdentity, ...], dict[str, Any]]:
    spec = _mapping(service.data.get("spec"), "Service spec")
    raw_selector = spec.get("selector")
    if raw_selector is None:
        raise DomainError("SERVICE_WITHOUT_SELECTOR")
    selector = service_selector_as_label_selector(raw_selector)
    if not selector["matchLabels"]:
        raise DomainError("SERVICE_EMPTY_SELECTOR_UNSUPPORTED")
    candidates = tuple(
        item for item in universe.workloads if item.namespace == service.namespace
    )
    evaluations = tuple(
        (item, evaluate_label_selector(selector, item.pod_labels)) for item in candidates
    )
    matches = tuple(item for item, evaluation in evaluations if evaluation.matched)
    witness = {
        "service": service.provenance_dict(),
        "service_namespace": service.namespace,
        "service_selector": dict(selector["matchLabels"]),
        "candidate_workloads": [
            {
                "identity": item.identity,
                "pod_labels": dict(item.pod_labels),
                "selector_evaluation": evaluation.canonical_dict(),
            }
            for item, evaluation in evaluations
        ],
        "matched_workloads": [item.identity for item in matches],
    }
    return matches, witness


def evaluate_service_selects_workload(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    service = _service(universe, request.subject_identity)
    try:
        matches, witness = service_selection_witness(universe, service)
    except DomainError as exc:
        reason = str(exc)
        if reason in {"SERVICE_WITHOUT_SELECTOR", "SERVICE_EMPTY_SELECTOR_UNSUPPORTED"}:
            return EvaluationOutcome(
                NativePropertyResult.UNSUPPORTED,
                reason,
                {
                    "service": service.provenance_dict(),
                    "service_namespace": service.namespace,
                    "service_selector": None,
                    "candidate_workloads": [],
                    "matched_workloads": [],
                    "expectation": thaw_json(request.parameters),
                },
                service.provenance_dict(),
            )
        raise
    params = thaw_json(request.parameters)
    expectation = params.get("expectation", "ANY_NONEMPTY")
    expected = params.get("expected_workloads", [])
    if type(expected) is not list or any(type(item) is not str for item in expected):
        raise DomainError("expected_workloads must be a string list")
    actual = {item.identity for item in matches}
    expected_set = set(expected)
    if expectation == "ANY_NONEMPTY":
        satisfied = bool(actual)
    elif expectation == "EXACT_ONE":
        satisfied = len(actual) == 1
    elif expectation == "EXACT_SET":
        if not expected_set:
            raise DomainError("EXACT_SET requires expected_workloads")
        satisfied = actual == expected_set
    elif expectation == "ALL_EXPECTED_PRESENT":
        if not expected_set:
            raise DomainError("ALL_EXPECTED_PRESENT requires expected_workloads")
        satisfied = expected_set.issubset(actual)
    else:
        raise DomainError("unsupported Service selection expectation")
    witness["expectation"] = expectation
    witness["expected_workloads"] = sorted(expected_set)
    witness["cardinality"] = len(actual)
    return EvaluationOutcome(
        NativePropertyResult.SATISFIED if satisfied else NativePropertyResult.VIOLATED,
        "SERVICE_SELECTION_EXPECTATION_SATISFIED" if satisfied else "SERVICE_SELECTION_EXPECTATION_VIOLATED",
        witness,
        service.provenance_dict(),
    )


def _service_ports(service: KubernetesResource) -> tuple[Mapping[str, Any], ...]:
    spec = _mapping(service.data.get("spec"), "Service spec")
    ports = spec.get("ports")
    if type(ports) not in (tuple, list) or not ports:
        raise DomainError("Service spec.ports must be a nonempty list")
    return tuple(_mapping(item, "ServicePort") for item in ports)


def select_service_port(
    service: KubernetesResource, selector: Mapping[str, Any]
) -> tuple[Mapping[str, Any], dict[str, Any]]:
    ports = _service_ports(service)
    name = selector.get("name")
    number = selector.get("port")
    protocol = selector.get("protocol", "TCP")
    if protocol not in {"TCP", "UDP", "SCTP"}:
        raise DomainError("ServicePort protocol is unsupported")
    if name is not None:
        if type(name) is not str or not name or number is not None:
            raise DomainError("ServicePort selector must use name or port, not both")
        matches = tuple(item for item in ports if item.get("name") == name)
        selector_witness = {"name": name, "protocol": protocol}
    else:
        if type(number) is not int or type(number) is bool or not 1 <= number <= 65535:
            raise DomainError("ServicePort selector port must be 1..65535")
        matches = tuple(
            item for item in ports
            if item.get("port") == number and item.get("protocol", "TCP") == protocol
        )
        selector_witness = {"port": number, "protocol": protocol}
    if len(matches) != 1:
        raise DomainError("SERVICE_PORT_MISSING_OR_AMBIGUOUS")
    port = matches[0]
    declared_port = port.get("port")
    declared_protocol = port.get("protocol", "TCP")
    if type(declared_port) is not int or type(declared_port) is bool or not 1 <= declared_port <= 65535:
        raise DomainError("ServicePort port is malformed")
    if declared_protocol not in {"TCP", "UDP", "SCTP"}:
        raise DomainError("ServicePort protocol is unsupported")
    if declared_protocol != protocol:
        raise DomainError("SERVICE_PORT_PROTOCOL_MISMATCH")
    return port, {
        "selector": selector_witness,
        "name": port.get("name", ""),
        "port": declared_port,
        "protocol": declared_protocol,
        "targetPort": port.get("targetPort", declared_port),
        "targetPort_defaulted": "targetPort" not in port,
    }


def resolve_service_port(
    universe: ProtectedNativeUniverse,
    service: KubernetesResource,
    port_selector: Mapping[str, Any],
) -> tuple[tuple[WorkloadIdentity, ...], tuple[int, ...], dict[str, Any]]:
    workloads, selection = service_selection_witness(universe, service)
    port, port_witness = select_service_port(service, port_selector)
    target = port.get("targetPort", port["port"])
    protocol = port.get("protocol", "TCP")
    resolutions: list[dict[str, Any]] = []
    numbers: set[int] = set()
    unresolved = False
    ambiguous = False
    for workload in workloads:
        if type(target) is int and type(target) is not bool:
            numbers.add(target)
            declared_occurrences = [
                container.identity
                for container in workload.containers
                if any(
                    item.number == target and item.protocol == protocol
                    for item in container.ports
                )
            ]
            resolutions.append({
                "workload": workload.identity,
                "resolution": "NUMERIC",
                "container_occurrence": (
                    declared_occurrences[0] if len(declared_occurrences) == 1 else None
                ),
                "declared_container_occurrences": declared_occurrences,
                "container_port": target,
                "protocol": protocol,
            })
            continue
        if type(target) is not str or not target:
            raise DomainError("ServicePort targetPort is malformed")
        occurrence_matches = []
        for container in workload.containers:
            for container_port in container.ports:
                if container_port.name == target and container_port.protocol == protocol:
                    occurrence_matches.append((container, container_port))
        if not occurrence_matches:
            unresolved = True
            resolutions.append({
                "workload": workload.identity,
                "resolution": "NAMED_PORT_NOT_FOUND",
                "container_occurrence": None,
                "container_port": None,
                "protocol": protocol,
            })
        elif len(occurrence_matches) > 1:
            ambiguous = True
            for container, container_port in occurrence_matches:
                resolutions.append({
                    "workload": workload.identity,
                    "resolution": "NAMED_PORT_AMBIGUOUS",
                    "container_occurrence": container.identity,
                    "container_port": container_port.number,
                    "protocol": container_port.protocol,
                })
                numbers.add(container_port.number)
        else:
            for container, container_port in occurrence_matches:
                numbers.add(container_port.number)
                resolutions.append({
                    "workload": workload.identity,
                    "resolution": "NAMED",
                    "container_occurrence": container.identity,
                    "container_port": container_port.number,
                    "protocol": container_port.protocol,
                })
    witness = {
        **selection,
        "service_port": port_witness,
        "resolutions": resolutions,
        "resolved_port_set": sorted(numbers),
        "unresolved_workloads": sorted({
            item["workload"] for item in resolutions if item["container_port"] is None
        }),
    }
    if not workloads:
        raise DomainError("SERVICE_SELECTS_NO_WORKLOAD")
    if unresolved:
        raise DomainError("SERVICE_TARGET_PORT_UNRESOLVED")
    if ambiguous or len(numbers) != 1:
        raise DomainError("SERVICE_TARGET_PORT_AMBIGUOUS")
    return workloads, tuple(sorted(numbers)), witness


def evaluate_service_port_resolution(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    service = _service(universe, request.subject_identity)
    params = thaw_json(request.parameters)
    selector = params.get("service_port")
    if type(selector) is not dict:
        raise DomainError("service_port parameter must be an object")
    try:
        workloads, numbers, witness = resolve_service_port(universe, service, selector)
    except DomainError as exc:
        reason = str(exc)
        if reason in {
            "SERVICE_WITHOUT_SELECTOR",
            "SERVICE_EMPTY_SELECTOR_UNSUPPORTED",
        }:
            result = NativePropertyResult.UNSUPPORTED
        elif reason in {
            "SERVICE_PORT_MISSING_OR_AMBIGUOUS",
            "SERVICE_PORT_PROTOCOL_MISMATCH",
            "SERVICE_SELECTS_NO_WORKLOAD",
            "SERVICE_TARGET_PORT_UNRESOLVED",
            "SERVICE_TARGET_PORT_AMBIGUOUS",
        }:
            result = NativePropertyResult.NOT_EVALUATED
        else:
            raise
        return EvaluationOutcome(
            result,
            reason,
            {
                "service": service.provenance_dict(),
                "service_namespace": service.namespace,
                "service_selector": None,
                "candidate_workloads": [],
                "matched_workloads": [],
                "service_port": selector,
                "resolutions": [],
                "resolved_port_set": [],
                "unresolved_workloads": [],
            },
            service.provenance_dict(),
        )
    expected_port = params.get("expected_port")
    satisfied = True
    if expected_port is not None:
        if type(expected_port) is not int or type(expected_port) is bool:
            raise DomainError("expected_port must be an exact integer")
        satisfied = numbers == (expected_port,)
    witness["expected_port"] = expected_port
    witness["selected_workload_count"] = len(workloads)
    return EvaluationOutcome(
        NativePropertyResult.SATISFIED if satisfied else NativePropertyResult.VIOLATED,
        "SERVICE_PORT_RESOLVED" if satisfied else "SERVICE_PORT_EXPECTATION_VIOLATED",
        witness,
        service.provenance_dict(),
    )


__all__ = [
    "evaluate_service_port_resolution",
    "evaluate_service_selects_workload",
    "resolve_service_port",
    "select_service_port",
    "service_selection_witness",
]
