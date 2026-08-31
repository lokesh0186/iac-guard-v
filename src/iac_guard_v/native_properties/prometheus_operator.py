"""Allowlisted Prometheus Operator ServiceMonitor/PodMonitor graph contracts."""
from __future__ import annotations

import hashlib
from importlib.resources import files
from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError
from .model import NativePropertyRequest, NativePropertyResult, thaw_json
from .network_policy import _endpoint_contract, evaluate_direction_path
from .outcome import EvaluationOutcome
from .selectors import evaluate_label_selector
from .services import resolve_service_port
from .universe import KubernetesResource, ProtectedNativeUniverse, WorkloadIdentity


PROMETHEUS_OPERATOR_API_VERSION = "monitoring.coreos.com/v1"
PROMETHEUS_OPERATOR_CONTRACT_RESOURCE = (
    "native_properties/contracts/prometheus-operator-v1.json"
)


def prometheus_operator_contract_digest() -> str:
    content = files("iac_guard_v").joinpath(PROMETHEUS_OPERATOR_CONTRACT_RESOURCE).read_bytes()
    return hashlib.sha256(content).hexdigest()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if type(value) not in (dict, MappingProxyType):
        raise DomainError(f"{label} must be a mapping")
    return value


def _monitor(
    universe: ProtectedNativeUniverse, identity: str, kind: str
) -> KubernetesResource:
    resource = universe.kubernetes_resource(identity)
    if resource.api_version != PROMETHEUS_OPERATOR_API_VERSION or resource.kind != kind:
        raise DomainError(f"native monitor property requires {PROMETHEUS_OPERATOR_API_VERSION}/{kind}")
    return resource


def _target_namespaces(
    universe: ProtectedNativeUniverse,
    monitor: KubernetesResource,
    spec: Mapping[str, Any],
) -> tuple[str, ...]:
    raw = spec.get("namespaceSelector")
    if raw is None:
        return (monitor.namespace,)
    selector = _mapping(raw, "monitor namespaceSelector")
    unknown = set(selector) - {"any", "matchNames"}
    if unknown:
        raise DomainError("MONITOR_NAMESPACE_SELECTOR_UNSUPPORTED")
    any_value = selector.get("any", False)
    names = selector.get("matchNames", ())
    if type(any_value) is not bool or type(names) not in (list, tuple):
        raise DomainError("monitor namespaceSelector is malformed")
    if any(type(item) is not str or not item for item in names):
        raise DomainError("monitor namespaceSelector.matchNames is malformed")
    if any_value and names:
        raise DomainError("monitor namespaceSelector cannot combine any and matchNames")
    if any_value:
        namespaces = {
            item.namespace for item in universe.kubernetes_resources
            if item.namespace != "_cluster"
        }
        return tuple(sorted(namespaces))
    if names:
        return tuple(sorted(set(names)))
    return (monitor.namespace,)


def _endpoint(spec: Mapping[str, Any], list_name: str, index: int) -> Mapping[str, Any]:
    endpoints = spec.get(list_name)
    if type(endpoints) not in (list, tuple) or not endpoints:
        raise DomainError("monitor endpoints must be a nonempty list")
    if type(index) is not int or type(index) is bool or not 0 <= index < len(endpoints):
        raise DomainError("monitor endpoint_index is out of range")
    endpoint = _mapping(endpoints[index], "monitor endpoint")
    common = {
        "authorization", "basicAuth", "bearerTokenSecret", "enableHttp2",
        "filterRunning", "followRedirects", "honorLabels", "honorTimestamps",
        "interval", "metricRelabelings", "noProxy", "oauth2", "params", "path",
        "port", "proxyConnectHeader", "proxyFromEnvironment", "proxyUrl",
        "relabelings", "scheme", "scrapeTimeout", "targetPort", "tlsConfig",
        "trackTimestampsStaleness",
    }
    allowed = common | ({"bearerTokenFile"} if list_name == "endpoints" else {"portNumber"})
    if set(endpoint) - allowed:
        raise DomainError("MONITOR_ENDPOINT_SCHEMA_FIELDS_UNSUPPORTED")
    if set(endpoint) & {"relabelings", "filterRunning"}:
        raise DomainError("MONITOR_ENDPOINT_SELECTION_FIELDS_UNSUPPORTED")
    return endpoint


def resolve_service_monitor(
    universe: ProtectedNativeUniverse,
    monitor: KubernetesResource,
    endpoint_index: int,
) -> tuple[tuple[tuple[KubernetesResource, tuple[WorkloadIdentity, ...], int], ...], dict[str, Any]]:
    spec = _mapping(monitor.data.get("spec"), "ServiceMonitor spec")
    selector = spec.get("selector")
    if selector is None:
        raise DomainError("ServiceMonitor spec.selector is required")
    namespaces = _target_namespaces(universe, monitor, spec)
    endpoint = _endpoint(spec, "endpoints", endpoint_index)
    port_name = endpoint.get("port")
    if type(port_name) is not str or not port_name:
        if "targetPort" in endpoint:
            raise DomainError("SERVICEMONITOR_TARGETPORT_WITHOUT_PORT_UNSUPPORTED")
        raise DomainError("ServiceMonitor endpoint.port is required")
    candidates = tuple(
        item for item in universe.kubernetes_resources
        if item.api_version == "v1" and item.kind == "Service" and item.namespace in namespaces
    )
    selector_evaluations = tuple(
        (item, evaluate_label_selector(selector, item.labels)) for item in candidates
    )
    services = tuple(item for item, evaluation in selector_evaluations if evaluation.matched)
    resolutions = []
    results = []
    for service in services:
        workloads, numbers, witness = resolve_service_port(
            universe, service, {"name": port_name}
        )
        results.append((service, workloads, numbers[0]))
        resolutions.append(witness)
    witness = {
        "monitor": monitor.provenance_dict(),
        "contract_digest": prometheus_operator_contract_digest(),
        "namespace_selection": list(namespaces),
        "endpoint_index": endpoint_index,
        "endpoint": {"port": port_name, "protocol": "TCP"},
        "service_candidates": [
            {
                "service": item.provenance_dict(),
                "labels": dict(item.labels),
                "selector_evaluation": evaluation.canonical_dict(),
            }
            for item, evaluation in selector_evaluations
        ],
        "matched_services": [item.identity for item in services],
        "service_port_resolutions": resolutions,
    }
    return tuple(results), witness


def evaluate_service_monitor(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    try:
        monitor = _monitor(universe, request.subject_identity, "ServiceMonitor")
    except DomainError:
        resource = universe.kubernetes_resource(request.subject_identity)
        return EvaluationOutcome(
            NativePropertyResult.UNSUPPORTED,
            "PROMETHEUS_OPERATOR_RESOURCE_CONTRACT_UNSUPPORTED",
            {
                "monitor": resource.provenance_dict(),
                "contract_digest": prometheus_operator_contract_digest(),
                "namespace_selection": [],
                "endpoint_index": 0,
            },
            resource.provenance_dict(),
        )
    params = thaw_json(request.parameters)
    endpoint_index = params.get("endpoint_index", 0)
    try:
        results, witness = resolve_service_monitor(universe, monitor, endpoint_index)
    except DomainError as exc:
        reason = str(exc)
        result = (
            NativePropertyResult.UNSUPPORTED
            if "UNSUPPORTED" in reason
            else NativePropertyResult.NOT_EVALUATED
        )
        return EvaluationOutcome(
            result,
            reason,
            {
                "monitor": monitor.provenance_dict(),
                "contract_digest": prometheus_operator_contract_digest(),
                "namespace_selection": [],
                "endpoint_index": endpoint_index,
                "endpoint": {},
                "service_candidates": [],
                "matched_services": [],
                "service_port_resolutions": [],
            },
            monitor.provenance_dict(),
        )
    expected_service = params.get("expected_service")
    actual = {item[0].identity for item in results}
    if expected_service is None:
        satisfied = bool(actual)
    else:
        if type(expected_service) is not str:
            raise DomainError("expected_service must be a string")
        satisfied = expected_service in actual
    witness["expected_service"] = expected_service
    return EvaluationOutcome(
        NativePropertyResult.SATISFIED if satisfied else NativePropertyResult.VIOLATED,
        "SERVICEMONITOR_TARGET_RESOLVED" if satisfied else "SERVICEMONITOR_TARGET_UNRESOLVED",
        witness,
        monitor.provenance_dict(),
    )


def resolve_pod_monitor(
    universe: ProtectedNativeUniverse,
    monitor: KubernetesResource,
    endpoint_index: int,
) -> tuple[tuple[tuple[WorkloadIdentity, int], ...], dict[str, Any]]:
    spec = _mapping(monitor.data.get("spec"), "PodMonitor spec")
    selector = spec.get("selector")
    if selector is None:
        raise DomainError("PodMonitor spec.selector is required")
    namespaces = _target_namespaces(universe, monitor, spec)
    endpoint = _endpoint(spec, "podMetricsEndpoints", endpoint_index)
    port_name = endpoint.get("port")
    port_number = endpoint.get("portNumber")
    if port_name is not None:
        if type(port_name) is not str or not port_name:
            raise DomainError("PodMonitor endpoint.port must be a nonempty string")
        if port_number is not None:
            raise DomainError("PODMONITOR_PORT_AND_PORTNUMBER_AMBIGUOUS")
        endpoint_port: str | int = port_name
    elif port_number is not None:
        if type(port_number) is not int or type(port_number) is bool or not 1 <= port_number <= 65535:
            raise DomainError("PodMonitor endpoint.portNumber is malformed")
        endpoint_port = port_number
    elif "targetPort" in endpoint:
        raise DomainError("PODMONITOR_TARGETPORT_WITHOUT_PORT_UNSUPPORTED")
    else:
        raise DomainError("PodMonitor endpoint.port or portNumber is required")
    candidates = tuple(item for item in universe.workloads if item.namespace in namespaces)
    selector_evaluations = tuple(
        (item, evaluate_label_selector(selector, item.pod_labels)) for item in candidates
    )
    workloads = tuple(item for item, evaluation in selector_evaluations if evaluation.matched)
    results = []
    port_witnesses = []
    for workload in workloads:
        if type(endpoint_port) is int:
            matches = [
                (container, port)
                for container in workload.containers
                for port in container.ports
                if port.number == endpoint_port and port.protocol == "TCP"
            ]
        else:
            matches = [
                (container, port)
                for container in workload.containers
                for port in container.ports
                if port.name == endpoint_port and port.protocol == "TCP"
            ]
        if len(matches) != 1:
            raise DomainError("PODMONITOR_PORT_MISSING_OR_AMBIGUOUS")
        number = matches[0][1].number
        occurrences = [matches[0][0].identity]
        results.append((workload, number))
        port_witnesses.append({
            "workload": workload.identity,
            "endpoint_port": endpoint_port,
            "container_occurrences": occurrences,
            "resolved_port": number,
        })
    witness = {
        "monitor": monitor.provenance_dict(),
        "contract_digest": prometheus_operator_contract_digest(),
        "namespace_selection": list(namespaces),
        "endpoint_index": endpoint_index,
        "endpoint": {"port": port_name, "portNumber": port_number, "protocol": "TCP"},
        "workload_candidates": [
            {
                "workload": item.identity,
                "pod_labels": dict(item.pod_labels),
                "selector_evaluation": evaluation.canonical_dict(),
            }
            for item, evaluation in selector_evaluations
        ],
        "matched_workloads": [item.identity for item in workloads],
        "port_resolutions": port_witnesses,
    }
    return tuple(results), witness


def evaluate_pod_monitor(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    try:
        monitor = _monitor(universe, request.subject_identity, "PodMonitor")
    except DomainError:
        resource = universe.kubernetes_resource(request.subject_identity)
        return EvaluationOutcome(
            NativePropertyResult.UNSUPPORTED,
            "PROMETHEUS_OPERATOR_RESOURCE_CONTRACT_UNSUPPORTED",
            {
                "monitor": resource.provenance_dict(),
                "contract_digest": prometheus_operator_contract_digest(),
                "namespace_selection": [],
                "endpoint_index": 0,
            },
            resource.provenance_dict(),
        )
    params = thaw_json(request.parameters)
    endpoint_index = params.get("endpoint_index", 0)
    try:
        results, witness = resolve_pod_monitor(universe, monitor, endpoint_index)
    except DomainError as exc:
        reason = str(exc)
        return EvaluationOutcome(
            NativePropertyResult.UNSUPPORTED if "UNSUPPORTED" in reason else NativePropertyResult.NOT_EVALUATED,
            reason,
            {
                "monitor": monitor.provenance_dict(),
                "contract_digest": prometheus_operator_contract_digest(),
                "namespace_selection": [],
                "endpoint_index": endpoint_index,
                "endpoint": {},
                "workload_candidates": [],
                "matched_workloads": [],
                "port_resolutions": [],
            },
            monitor.provenance_dict(),
        )
    satisfied = bool(results)
    return EvaluationOutcome(
        NativePropertyResult.SATISFIED if satisfied else NativePropertyResult.VIOLATED,
        "PODMONITOR_TARGET_RESOLVED" if satisfied else "PODMONITOR_TARGET_UNRESOLVED",
        witness,
        monitor.provenance_dict(),
    )


def evaluate_monitoring_ingress(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    monitor = universe.kubernetes_resource(request.subject_identity)
    params = thaw_json(request.parameters)
    endpoint_index = params.get("endpoint_index", 0)
    source = _endpoint_contract(universe, params.get("source"), role="monitoring source")
    targets: list[tuple[WorkloadIdentity, int]] = []
    if monitor.api_version != PROMETHEUS_OPERATOR_API_VERSION or monitor.kind not in {
        "ServiceMonitor", "PodMonitor"
    }:
        return EvaluationOutcome(
            NativePropertyResult.UNSUPPORTED,
            "PROMETHEUS_OPERATOR_RESOURCE_CONTRACT_UNSUPPORTED",
            {
                "monitor_resolution": {
                    "monitor": monitor.provenance_dict(),
                    "contract_digest": prometheus_operator_contract_digest(),
                },
                "source_contract": {
                    key: value for key, value in source.items() if key != "workload"
                },
                "target_evaluations": [],
                "manifest_semantics_only": True,
            },
            monitor.provenance_dict(),
        )
    try:
        if monitor.kind == "ServiceMonitor":
            results, monitor_witness = resolve_service_monitor(universe, monitor, endpoint_index)
            for _, workloads, port in results:
                targets.extend((workload, port) for workload in workloads)
        else:
            resolved, monitor_witness = resolve_pod_monitor(universe, monitor, endpoint_index)
            targets.extend(resolved)
    except DomainError as exc:
        reason = str(exc)
        return EvaluationOutcome(
            NativePropertyResult.UNSUPPORTED if "UNSUPPORTED" in reason else NativePropertyResult.NOT_EVALUATED,
            reason,
            {
                "monitor_resolution": {
                    "monitor": monitor.provenance_dict(),
                    "contract_digest": prometheus_operator_contract_digest(),
                    "endpoint_index": endpoint_index,
                },
                "source_contract": {
                    key: value for key, value in source.items() if key != "workload"
                },
                "target_evaluations": [],
                "manifest_semantics_only": True,
            },
            monitor.provenance_dict(),
        )
    evaluations = []
    final = NativePropertyResult.SATISFIED
    for workload, port in targets:
        result, reason, witness = evaluate_direction_path(
            universe,
            protected_workload=workload,
            endpoint=source,
            destination_workload=workload,
            direction="Ingress",
            port=port,
            protocol="TCP",
        )
        evaluations.append({
            "workload": workload.identity,
            "port": port,
            "result": result.value,
            "reason": reason,
            "network_policy_witness": witness,
        })
        if result is NativePropertyResult.NOT_EVALUATED:
            final = NativePropertyResult.NOT_EVALUATED
        elif result is NativePropertyResult.VIOLATED and final is NativePropertyResult.SATISFIED:
            final = NativePropertyResult.VIOLATED
    if not targets:
        final = NativePropertyResult.NOT_EVALUATED
    return EvaluationOutcome(
        final,
        "MONITORING_INGRESS_PATH_ALLOWED" if final is NativePropertyResult.SATISFIED else "MONITORING_INGRESS_PATH_NOT_ESTABLISHED",
        {
            "monitor_resolution": monitor_witness,
            "source_contract": {key: value for key, value in source.items() if key != "workload"},
            "target_evaluations": evaluations,
            "manifest_semantics_only": True,
        },
        monitor.provenance_dict(),
    )


__all__ = [
    "PROMETHEUS_OPERATOR_API_VERSION",
    "evaluate_monitoring_ingress",
    "evaluate_pod_monitor",
    "evaluate_service_monitor",
    "prometheus_operator_contract_digest",
    "resolve_pod_monitor",
    "resolve_service_monitor",
]
