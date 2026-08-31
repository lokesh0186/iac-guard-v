"""Bounded Kubernetes NetworkPolicy selection, isolation, closure and path semantics."""
from __future__ import annotations

import ipaddress
from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError
from .model import NativePropertyRequest, NativePropertyResult, thaw_json
from .outcome import EvaluationOutcome
from .selectors import evaluate_label_selector
from .services import resolve_service_port
from .universe import KubernetesResource, ProtectedNativeUniverse, WorkloadIdentity


def _mapping(value: Any, label: str, *, optional: bool = False) -> Mapping[str, Any]:
    if value is None and optional:
        return MappingProxyType({})
    if type(value) not in (dict, MappingProxyType):
        raise DomainError(f"{label} must be a mapping")
    return value


def _policies(universe: ProtectedNativeUniverse, namespace: str) -> tuple[KubernetesResource, ...]:
    return tuple(
        item for item in universe.kubernetes_resources
        if item.api_version == "networking.k8s.io/v1"
        and item.kind == "NetworkPolicy"
        and item.namespace == namespace
    )


def selecting_policy_witness(
    universe: ProtectedNativeUniverse,
    workload: WorkloadIdentity,
) -> tuple[tuple[KubernetesResource, ...], list[dict[str, Any]]]:
    evaluations: list[dict[str, Any]] = []
    selecting: list[KubernetesResource] = []
    for policy in _policies(universe, workload.namespace):
        spec = _mapping(policy.data.get("spec"), "NetworkPolicy spec")
        selector = spec.get("podSelector")
        if selector is None:
            raise DomainError("NetworkPolicy spec.podSelector is required")
        evaluation = evaluate_label_selector(selector, workload.pod_labels)
        evaluations.append({
            "policy": policy.provenance_dict(),
            "policy_selector": evaluation.canonical_dict(),
            "selected": evaluation.matched,
        })
        if evaluation.matched:
            selecting.append(policy)
    return tuple(selecting), evaluations


def effective_policy_types(policy: KubernetesResource) -> tuple[str, ...]:
    spec = _mapping(policy.data.get("spec"), "NetworkPolicy spec")
    declared = spec.get("policyTypes")
    if declared is None:
        types = ["Ingress"]
        if "egress" in spec:
            types.append("Egress")
        return tuple(types)
    if type(declared) not in (list, tuple) or not declared:
        raise DomainError("NetworkPolicy policyTypes must be a nonempty list when present")
    if any(item not in {"Ingress", "Egress"} for item in declared):
        raise DomainError("NetworkPolicy policyTypes contains an unsupported value")
    if len(declared) != len(set(declared)):
        raise DomainError("NetworkPolicy policyTypes contains duplicates")
    return tuple(declared)


def evaluate_workload_selected(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    workload = universe.workload(request.subject_identity)
    selecting, evaluations = selecting_policy_witness(universe, workload)
    params = thaw_json(request.parameters)
    policy_identity = params.get("policy_identity")
    if policy_identity is not None:
        if type(policy_identity) is not str:
            raise DomainError("policy_identity must be a string")
        considered = tuple(item for item in selecting if item.identity == policy_identity)
    else:
        considered = selecting
    satisfied = bool(considered)
    return EvaluationOutcome(
        NativePropertyResult.SATISFIED if satisfied else NativePropertyResult.VIOLATED,
        "WORKLOAD_SELECTED_BY_POLICY" if satisfied else "WORKLOAD_NOT_SELECTED_BY_POLICY",
        {
            "workload": workload.canonical_dict(),
            "namespace": workload.namespace,
            "requested_policy_identity": policy_identity,
            "policy_evaluations": evaluations,
            "selecting_policies": [item.identity for item in selecting],
        },
        workload.resource.provenance_dict(),
    )


def evaluate_workload_isolated(
    universe: ProtectedNativeUniverse,
    request: NativePropertyRequest,
    direction: str,
) -> EvaluationOutcome:
    workload = universe.workload(request.subject_identity)
    selecting, evaluations = selecting_policy_witness(universe, workload)
    typed = []
    establishing = []
    for policy in selecting:
        types = effective_policy_types(policy)
        typed.append({"policy": policy.identity, "effective_policy_types": list(types)})
        if direction in types:
            establishing.append(policy.identity)
    isolated = bool(establishing)
    return EvaluationOutcome(
        NativePropertyResult.SATISFIED if isolated else NativePropertyResult.VIOLATED,
        f"WORKLOAD_{direction.upper()}_ISOLATED" if isolated else f"WORKLOAD_{direction.upper()}_NOT_ISOLATED",
        {
            "workload": workload.canonical_dict(),
            "direction": direction,
            "policy_evaluations": evaluations,
            "selecting_policy_types": typed,
            "isolation_establishing_policies": establishing,
        },
        workload.resource.provenance_dict(),
    )


def evaluate_component_closure(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    params = thaw_json(request.parameters)
    workload_ids = params.get("workload_identities")
    policy_ids = params.get("policy_identities")
    membership_digest = params.get("membership_proof_digest")
    if (
        type(workload_ids) is not list or not workload_ids
        or any(type(item) is not str for item in workload_ids)
        or len(workload_ids) != len(set(workload_ids))
    ):
        raise DomainError("closure workload_identities must be a unique nonempty string list")
    if (
        type(policy_ids) is not list or not policy_ids
        or any(type(item) is not str for item in policy_ids)
        or len(policy_ids) != len(set(policy_ids))
    ):
        raise DomainError("closure policy_identities must be a unique nonempty string list")
    if type(membership_digest) is not str or len(membership_digest) != 64:
        raise DomainError("closure membership_proof_digest must be a SHA-256")
    workloads = tuple(universe.workload(item) for item in workload_ids)
    policy_resources = tuple(universe.kubernetes_resource(item) for item in policy_ids)
    if any(
        item.api_version != "networking.k8s.io/v1" or item.kind != "NetworkPolicy"
        for item in policy_resources
    ):
        raise DomainError("closure policies must be networking.k8s.io/v1 NetworkPolicies")
    member_witnesses = []
    uncovered = []
    for workload in workloads:
        matches = []
        evaluations = []
        for policy in policy_resources:
            if policy.namespace != workload.namespace:
                evaluations.append({
                    "policy": policy.identity,
                    "matched": False,
                    "reason": "NAMESPACE_MISMATCH",
                })
                continue
            spec = _mapping(policy.data.get("spec"), "NetworkPolicy spec")
            evaluation = evaluate_label_selector(spec.get("podSelector"), workload.pod_labels)
            evaluations.append({
                "policy": policy.identity,
                "matched": evaluation.matched,
                "selector_evaluation": evaluation.canonical_dict(),
            })
            if evaluation.matched:
                matches.append(policy.identity)
        if not matches:
            uncovered.append(workload.identity)
        member_witnesses.append({
            "workload": workload.canonical_dict(),
            "policy_evaluations": evaluations,
            "selecting_policies": sorted(matches),
        })
    satisfied = not uncovered
    return EvaluationOutcome(
        NativePropertyResult.SATISFIED if satisfied else NativePropertyResult.VIOLATED,
        "COMPONENT_POLICY_CLOSURE_COMPLETE" if satisfied else "COMPONENT_POLICY_CLOSURE_VIOLATED",
        {
            "component_identity": request.subject_identity,
            "membership_proof_digest": membership_digest,
            "workload_identities": sorted(workload_ids),
            "policy_identities": sorted(policy_ids),
            "members": member_witnesses,
            "uncovered_workloads": sorted(uncovered),
        },
        {"component_identity": request.subject_identity, "membership_proof_digest": membership_digest},
    )


def _namespace_labels(universe: ProtectedNativeUniverse, namespace: str) -> Mapping[str, str] | None:
    matches = tuple(
        item for item in universe.kubernetes_resources
        if item.api_version == "v1" and item.kind == "Namespace" and item.name == namespace
    )
    if len(matches) > 1:
        raise DomainError("duplicate Namespace identity in protected universe")
    return matches[0].labels if matches else None


def _endpoint_contract(
    universe: ProtectedNativeUniverse, raw: Any, *, role: str
) -> dict[str, Any]:
    contract = _mapping(raw, f"{role} endpoint contract")
    contract_type = contract.get("type")
    if contract_type == "WORKLOAD":
        identity = contract.get("identity")
        if type(identity) is not str:
            raise DomainError(f"{role} workload contract requires identity")
        workload = universe.workload(identity)
        namespace_labels = _namespace_labels(universe, workload.namespace)
        return {
            "type": "WORKLOAD",
            "identity": workload.identity,
            "namespace": workload.namespace,
            "namespace_labels": dict(namespace_labels) if namespace_labels is not None else None,
            "pod_labels": dict(workload.pod_labels),
            "ip": None,
            "workload": workload,
        }
    if contract_type in {"LABELS", "SYMBOLIC"}:
        namespace = contract.get("namespace")
        pod_labels = contract.get("pod_labels")
        namespace_labels = contract.get("namespace_labels")
        if type(namespace) is not str or type(pod_labels) is not dict:
            raise DomainError(f"{role} label contract requires namespace and pod_labels")
        if namespace_labels is not None and type(namespace_labels) is not dict:
            raise DomainError(f"{role} namespace_labels must be an object")
        if any(type(key) is not str or type(value) is not str for key, value in pod_labels.items()):
            raise DomainError(f"{role} pod_labels must contain strings")
        if namespace_labels is not None and any(
            type(key) is not str or type(value) is not str
            for key, value in namespace_labels.items()
        ):
            raise DomainError(f"{role} namespace_labels must contain strings")
        return {
            "type": contract_type,
            "identity": None,
            "namespace": namespace,
            "namespace_labels": namespace_labels,
            "pod_labels": pod_labels,
            "ip": None,
            "workload": None,
        }
    if contract_type == "IP":
        value = contract.get("ip")
        if type(value) is not str:
            raise DomainError(f"{role} IP contract requires ip")
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise DomainError(f"{role} IP contract is malformed") from exc
        return {
            "type": "IP",
            "identity": None,
            "namespace": None,
            "namespace_labels": None,
            "pod_labels": None,
            "ip": str(parsed),
            "workload": None,
        }
    raise DomainError(f"{role} endpoint contract type is unsupported")


def _public_endpoint(endpoint: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in endpoint.items() if key not in {"workload"}
    }


def _peer_match(
    universe: ProtectedNativeUniverse,
    peer: Mapping[str, Any],
    endpoint: Mapping[str, Any],
    policy_namespace: str,
) -> tuple[bool | None, str, dict[str, Any]]:
    unknown = set(peer) - {"podSelector", "namespaceSelector", "ipBlock"}
    if unknown:
        raise DomainError(f"NetworkPolicy peer contains unsupported fields: {sorted(unknown)}")
    if not peer:
        return True, "UNRESTRICTED_PEER", {"peer": {}, "matched": True}
    ip_block = peer.get("ipBlock")
    if ip_block is not None:
        if len(peer) != 1:
            raise DomainError("NetworkPolicy ipBlock cannot be combined with selectors")
        block = _mapping(ip_block, "NetworkPolicy ipBlock")
        unknown_block = set(block) - {"cidr", "except"}
        if unknown_block:
            raise DomainError("NetworkPolicy ipBlock contains unsupported fields")
        cidr = block.get("cidr")
        exceptions = block.get("except", ())
        if type(cidr) is not str or type(exceptions) not in (list, tuple):
            raise DomainError("NetworkPolicy ipBlock is malformed")
        try:
            network = ipaddress.ip_network(cidr, strict=True)
            excluded = tuple(ipaddress.ip_network(item, strict=True) for item in exceptions)
        except (ValueError, TypeError) as exc:
            raise DomainError("NetworkPolicy ipBlock CIDR is malformed") from exc
        if any(
            item.version != network.version or not item.subnet_of(network)
            for item in excluded
        ):
            raise DomainError("NetworkPolicy ipBlock except must be contained by cidr")
        if endpoint["ip"] is None:
            return None, "IP_UNKNOWN", {
                "peer": {"ipBlock": {"cidr": cidr, "except": list(exceptions)}},
                "matched": None,
                "reason": "IP_UNKNOWN",
            }
        address = ipaddress.ip_address(endpoint["ip"])
        matched = address in network and not any(address in item for item in excluded)
        return matched, "MATCH" if matched else "PEER_MISMATCH", {
            "peer": {"ipBlock": {"cidr": cidr, "except": list(exceptions)}},
            "matched": matched,
            "reason": "MATCH" if matched else "PEER_MISMATCH",
        }
    if endpoint["type"] == "IP":
        return False, "PEER_MISMATCH", {
            "peer": {key: peer[key] for key in peer},
            "matched": False,
            "reason": "PEER_MISMATCH",
        }
    namespace_selector = peer.get("namespaceSelector")
    pod_selector = peer.get("podSelector")
    namespace_match = True
    namespace_witness = None
    if namespace_selector is not None:
        labels = endpoint["namespace_labels"]
        normalized_empty = not _mapping(namespace_selector, "namespaceSelector")
        if labels is None and not normalized_empty:
            return None, "NAMESPACE_LABELS_UNKNOWN", {
                "peer": {key: peer[key] for key in peer},
                "matched": None,
                "reason": "NAMESPACE_LABELS_UNKNOWN",
            }
        evaluation = evaluate_label_selector(namespace_selector, labels or {})
        namespace_match = evaluation.matched
        namespace_witness = evaluation.canonical_dict()
    elif pod_selector is not None:
        namespace_match = endpoint["namespace"] == policy_namespace
    pod_match = True
    pod_witness = None
    if pod_selector is not None:
        evaluation = evaluate_label_selector(pod_selector, endpoint["pod_labels"] or {})
        pod_match = evaluation.matched
        pod_witness = evaluation.canonical_dict()
    matched = namespace_match and pod_match
    reason = "MATCH" if matched else (
        "NAMESPACE_MISMATCH" if not namespace_match else "PEER_MISMATCH"
    )
    return matched, reason, {
        "peer": {
            "namespaceSelector": namespace_witness,
            "podSelector": pod_witness,
        },
        "matched": matched,
        "reason": reason,
    }


def _named_port_numbers(workload: WorkloadIdentity | None, name: str, protocol: str) -> tuple[int, ...] | None:
    if workload is None:
        return None
    values = {
        port.number
        for container in workload.containers
        for port in container.ports
        if port.name == name and port.protocol == protocol
    }
    if len(values) != 1:
        return None
    return tuple(values)


def _port_match(
    raw_port: Mapping[str, Any],
    requested_port: int,
    protocol: str,
    destination_workload: WorkloadIdentity | None,
) -> tuple[bool | None, str, dict[str, Any]]:
    unknown = set(raw_port) - {"port", "protocol", "endPort"}
    if unknown:
        raise DomainError(f"NetworkPolicy port contains unsupported fields: {sorted(unknown)}")
    declared_protocol = raw_port.get("protocol", "TCP")
    if declared_protocol not in {"TCP", "UDP", "SCTP"}:
        raise DomainError("NetworkPolicy port protocol is unsupported")
    if declared_protocol != protocol:
        return False, "PROTOCOL_MISMATCH", {
            "port": dict(raw_port), "matched": False, "reason": "PROTOCOL_MISMATCH"
        }
    declared = raw_port.get("port")
    end = raw_port.get("endPort")
    if declared is None:
        if end is not None:
            raise DomainError("NetworkPolicy endPort requires numeric port")
        return True, "MATCH", {"port": dict(raw_port), "matched": True, "reason": "MATCH"}
    if type(declared) is int and type(declared) is not bool:
        if not 1 <= declared <= 65535:
            raise DomainError("NetworkPolicy numeric port is malformed")
        if end is None:
            matched = requested_port == declared
        else:
            if type(end) is not int or type(end) is bool or end < declared or end > 65535:
                raise DomainError("NetworkPolicy endPort is malformed")
            matched = declared <= requested_port <= end
        return matched, "MATCH" if matched else "PORT_MISMATCH", {
            "port": dict(raw_port),
            "matched": matched,
            "reason": "MATCH" if matched else "PORT_MISMATCH",
        }
    if type(declared) is str and declared:
        resolved = _named_port_numbers(destination_workload, declared, protocol)
        if resolved is None:
            return None, "NAMED_PORT_UNRESOLVED", {
                "port": dict(raw_port), "matched": None, "reason": "NAMED_PORT_UNRESOLVED"
            }
        matched = requested_port == resolved[0]
        return matched, "MATCH" if matched else "PORT_MISMATCH", {
            "port": dict(raw_port),
            "resolved_named_port": resolved[0],
            "matched": matched,
            "reason": "MATCH" if matched else "PORT_MISMATCH",
        }
    raise DomainError("NetworkPolicy port is malformed")


def _evaluate_rule(
    universe: ProtectedNativeUniverse,
    rule: Mapping[str, Any],
    *,
    direction: str,
    endpoint: Mapping[str, Any],
    destination_workload: WorkloadIdentity | None,
    policy_namespace: str,
    port: int,
    protocol: str,
) -> tuple[bool | None, dict[str, Any]]:
    peer_key = "from" if direction == "Ingress" else "to"
    unknown = set(rule) - {peer_key, "ports"}
    if unknown:
        raise DomainError(f"NetworkPolicy {direction} rule contains unsupported fields")
    raw_peers = rule.get(peer_key)
    if raw_peers is None or raw_peers == ():
        peer_results = [(True, "UNRESTRICTED_PEER", {"peer": {}, "matched": True})]
    else:
        if type(raw_peers) not in (list, tuple):
            raise DomainError("NetworkPolicy peers must be a list")
        peer_results = [
            _peer_match(universe, _mapping(item, "NetworkPolicy peer"), endpoint, policy_namespace)
            for item in raw_peers
        ]
    raw_ports = rule.get("ports")
    if raw_ports is None or raw_ports == ():
        port_results = [(True, "UNRESTRICTED_PORT", {"port": {}, "matched": True})]
    else:
        if type(raw_ports) not in (list, tuple):
            raise DomainError("NetworkPolicy ports must be a list")
        port_results = [
            _port_match(_mapping(item, "NetworkPolicy port"), port, protocol, destination_workload)
            for item in raw_ports
        ]
    peer_true = any(item[0] is True for item in peer_results)
    port_true = any(item[0] is True for item in port_results)
    unknown_match = (
        (not peer_true and any(item[0] is None for item in peer_results))
        or (not port_true and any(item[0] is None for item in port_results))
    )
    matched: bool | None = True if peer_true and port_true else (None if unknown_match else False)
    return matched, {
        "peer_evaluations": [item[2] for item in peer_results],
        "port_evaluations": [item[2] for item in port_results],
        "matched": matched,
        "reason": "MATCH" if matched is True else ("UNDECIDABLE" if matched is None else "NO_MATCH"),
    }


def evaluate_direction_path(
    universe: ProtectedNativeUniverse,
    *,
    protected_workload: WorkloadIdentity,
    endpoint: Mapping[str, Any],
    destination_workload: WorkloadIdentity | None,
    direction: str,
    port: int,
    protocol: str,
) -> tuple[NativePropertyResult, str, dict[str, Any]]:
    if direction not in {"Ingress", "Egress"}:
        raise DomainError("NetworkPolicy direction is unsupported")
    if type(port) is not int or type(port) is bool or not 1 <= port <= 65535:
        raise DomainError("network path port must be 1..65535")
    if protocol not in {"TCP", "UDP", "SCTP"}:
        raise DomainError("network path protocol is unsupported")
    selecting, selector_witness = selecting_policy_witness(universe, protected_workload)
    applicable = tuple(item for item in selecting if direction in effective_policy_types(item))
    policy_evaluations = []
    any_match = False
    undecidable = False
    rule_key = direction.lower()
    for policy in applicable:
        spec = _mapping(policy.data.get("spec"), "NetworkPolicy spec")
        raw_rules = spec.get(rule_key, ())
        if raw_rules is None:
            raw_rules = ()
        if type(raw_rules) not in (list, tuple):
            raise DomainError(f"NetworkPolicy {rule_key} must be a list")
        rule_evaluations = []
        for index, raw_rule in enumerate(raw_rules):
            matched, witness = _evaluate_rule(
                universe,
                _mapping(raw_rule, f"NetworkPolicy {rule_key} rule"),
                direction=direction,
                endpoint=endpoint,
                destination_workload=destination_workload,
                policy_namespace=policy.namespace,
                port=port,
                protocol=protocol,
            )
            witness["rule_index"] = index
            rule_evaluations.append(witness)
            any_match = any_match or matched is True
            undecidable = undecidable or matched is None
        policy_evaluations.append({
            "policy": policy.provenance_dict(),
            "effective_policy_types": list(effective_policy_types(policy)),
            "rule_evaluations": rule_evaluations,
        })
    witness = {
        "direction": direction,
        "protected_workload": protected_workload.canonical_dict(),
        "peer_endpoint": _public_endpoint(endpoint),
        "destination_port": port,
        "protocol": protocol,
        "policy_selector_evaluations": selector_witness,
        "selecting_policies": [item.identity for item in selecting],
        "isolation_establishing_policies": [item.identity for item in applicable],
        "policy_rule_evaluations": policy_evaluations,
        "manifest_semantics_only": True,
    }
    if not applicable:
        return NativePropertyResult.SATISFIED, f"{direction.upper()}_NOT_ISOLATED", witness
    if any_match:
        return NativePropertyResult.SATISFIED, f"{direction.upper()}_PATH_ALLOWED", witness
    if undecidable:
        return NativePropertyResult.NOT_EVALUATED, f"{direction.upper()}_PATH_UNDECIDABLE", witness
    return NativePropertyResult.VIOLATED, f"{direction.upper()}_PATH_NOT_ALLOWED", witness


def evaluate_ingress_path(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    destination = universe.workload(request.subject_identity)
    params = thaw_json(request.parameters)
    source = _endpoint_contract(universe, params.get("source"), role="source")
    result, reason, witness = evaluate_direction_path(
        universe,
        protected_workload=destination,
        endpoint=source,
        destination_workload=destination,
        direction="Ingress",
        port=params.get("port"),
        protocol=params.get("protocol", "TCP"),
    )
    return EvaluationOutcome(result, reason, witness, destination.resource.provenance_dict())


def evaluate_egress_path(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    source = universe.workload(request.subject_identity)
    params = thaw_json(request.parameters)
    destination = _endpoint_contract(universe, params.get("destination"), role="destination")
    result, reason, witness = evaluate_direction_path(
        universe,
        protected_workload=source,
        endpoint=destination,
        destination_workload=destination["workload"],
        direction="Egress",
        port=params.get("port"),
        protocol=params.get("protocol", "TCP"),
    )
    return EvaluationOutcome(result, reason, witness, source.resource.provenance_dict())


def _resolve_destination(
    universe: ProtectedNativeUniverse, params: Mapping[str, Any]
) -> tuple[tuple[WorkloadIdentity, ...], int, dict[str, Any]]:
    service_identity = params.get("destination_service")
    if service_identity is not None:
        if type(service_identity) is not str or type(params.get("service_port")) is not dict:
            raise DomainError("destination_service requires a service_port selector")
        service = universe.kubernetes_resource(service_identity)
        if service.api_version != "v1" or service.kind != "Service":
            raise DomainError("destination_service must identify a v1 Service")
        workloads, numbers, witness = resolve_service_port(
            universe, service, params["service_port"]
        )
        return workloads, numbers[0], witness
    workload_identity = params.get("destination_workload")
    port = params.get("port")
    if type(workload_identity) is not str or type(port) is not int or type(port) is bool:
        raise DomainError("network path requires destination_workload and numeric port")
    workload = universe.workload(workload_identity)
    return (workload,), port, {"direct_destination_workload": workload.canonical_dict()}


def evaluate_pod_network_path(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    source = universe.workload(request.subject_identity)
    params = thaw_json(request.parameters)
    destinations, port, service_witness = _resolve_destination(universe, params)
    protocol = params.get("protocol", "TCP")
    results = []
    final = NativePropertyResult.SATISFIED
    for destination in destinations:
        source_contract = _endpoint_contract(
            universe, {"type": "WORKLOAD", "identity": source.identity}, role="source"
        )
        destination_contract = _endpoint_contract(
            universe, {"type": "WORKLOAD", "identity": destination.identity}, role="destination"
        )
        egress = evaluate_direction_path(
            universe,
            protected_workload=source,
            endpoint=destination_contract,
            destination_workload=destination,
            direction="Egress",
            port=port,
            protocol=protocol,
        )
        ingress = evaluate_direction_path(
            universe,
            protected_workload=destination,
            endpoint=source_contract,
            destination_workload=destination,
            direction="Ingress",
            port=port,
            protocol=protocol,
        )
        results.append({
            "destination_workload": destination.identity,
            "egress": {"result": egress[0].value, "reason": egress[1], "witness": egress[2]},
            "ingress": {"result": ingress[0].value, "reason": ingress[1], "witness": ingress[2]},
        })
        directions = {egress[0], ingress[0]}
        if NativePropertyResult.NOT_EVALUATED in directions:
            final = NativePropertyResult.NOT_EVALUATED
        elif NativePropertyResult.VIOLATED in directions and final is NativePropertyResult.SATISFIED:
            final = NativePropertyResult.VIOLATED
    return EvaluationOutcome(
        final,
        "POD_NETWORK_PATH_ALLOWED" if final is NativePropertyResult.SATISFIED else "POD_NETWORK_PATH_NOT_ESTABLISHED",
        {
            "source_workload": source.canonical_dict(),
            "service_resolution": service_witness,
            "destination_port": port,
            "protocol": protocol,
            "destination_results": results,
            "manifest_semantics_only": True,
        },
        source.resource.provenance_dict(),
    )


def evaluate_denied_by_rendered_set(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    params = thaw_json(request.parameters)
    direction = params.get("direction", "Ingress")
    if direction == "Ingress":
        allowed = evaluate_ingress_path(universe, request)
    elif direction == "Egress":
        allowed = evaluate_egress_path(universe, request)
    else:
        raise DomainError("denied path direction must be Ingress or Egress")
    if allowed.result is NativePropertyResult.VIOLATED:
        result = NativePropertyResult.SATISFIED
        reason = f"{direction.upper()}_DENIED_BY_RENDERED_POLICY_SET"
    elif allowed.result is NativePropertyResult.SATISFIED:
        result = NativePropertyResult.VIOLATED
        reason = f"{direction.upper()}_NOT_DENIED_BY_RENDERED_POLICY_SET"
    else:
        result = allowed.result
        reason = allowed.reason_code
    return EvaluationOutcome(
        result,
        reason,
        {**allowed.witness_contents, "derived_property": "DENIED_BY_RENDERED_POLICY_SET"},
        allowed.subject_provenance,
    )


__all__ = [
    "effective_policy_types",
    "evaluate_component_closure",
    "evaluate_denied_by_rendered_set",
    "evaluate_direction_path",
    "evaluate_egress_path",
    "evaluate_ingress_path",
    "evaluate_pod_network_path",
    "evaluate_workload_isolated",
    "evaluate_workload_selected",
    "selecting_policy_witness",
]
