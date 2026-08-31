"""Semantic validation for native witnesses; JSON shape alone is insufficient."""
from __future__ import annotations

from typing import Any

from ..models import DomainError
from .model import NativePropertyObservation, NativePropertyResult, thaw_json


_REQUIRED_AUTHORITATIVE_KEYS: dict[str, frozenset[str]] = {
    "k8s_network_policy_selection_v1": frozenset({
        "workload", "namespace", "policy_evaluations", "selecting_policies"
    }),
    "k8s_network_policy_isolation_v1": frozenset({
        "workload", "direction", "selecting_policy_types", "isolation_establishing_policies"
    }),
    "k8s_component_policy_closure_v1": frozenset({
        "component_identity", "membership_proof_digest", "members", "uncovered_workloads"
    }),
    "k8s_service_selection_v1": frozenset({
        "service", "service_selector", "candidate_workloads", "matched_workloads", "expectation"
    }),
    "k8s_service_port_resolution_v1": frozenset({
        "service", "service_port", "matched_workloads", "resolutions", "resolved_port_set"
    }),
    "k8s_network_path_v1": frozenset({
        "direction", "protected_workload", "destination_port", "protocol",
        "selecting_policies", "isolation_establishing_policies", "policy_rule_evaluations",
        "manifest_semantics_only",
    }),
    "k8s_pod_network_path_v1": frozenset({
        "source_workload", "destination_port", "protocol", "destination_results",
        "manifest_semantics_only",
    }),
    "k8s_denied_path_v1": frozenset({
        "direction", "protected_workload", "destination_port", "protocol",
        "policy_rule_evaluations", "derived_property", "manifest_semantics_only",
    }),
    "prometheus_monitor_resolution_v1": frozenset({
        "monitor", "contract_digest", "namespace_selection", "endpoint_index"
    }),
    "prometheus_monitoring_ingress_v1": frozenset({
        "monitor_resolution", "source_contract", "target_evaluations", "manifest_semantics_only"
    }),
    "k8s_rbac_role_ref_v1": frozenset({
        "binding", "binding_kind", "role_ref", "scope_state", "authorization_simulated"
    }),
    "k8s_rbac_subject_v1": frozenset({
        "binding", "service_account_subjects", "authorization_simulated"
    }),
    "k8s_rbac_scope_v1": frozenset({
        "binding", "role_ref_scope", "service_account_subjects", "authorization_simulated"
    }),
    "terraform_reference_v1": frozenset({
        "source", "attribute_path", "expected_target", "observed_references",
        "complete_local_universe", "reference_contract_digest",
    }),
}


def _any_matching_rule(contents: dict[str, Any]) -> bool:
    return any(
        rule.get("matched") is True
        for policy in contents.get("policy_rule_evaluations", [])
        for rule in policy.get("rule_evaluations", [])
    )


def _validate_rule_derivations(contents: dict[str, Any]) -> None:
    for policy in contents.get("policy_rule_evaluations", []):
        for rule in policy.get("rule_evaluations", []):
            peers = rule.get("peer_evaluations")
            ports = rule.get("port_evaluations")
            if type(peers) is not list or not peers or type(ports) is not list or not ports:
                raise DomainError("network rule witness lacks peer/port evaluations")
            peer_values = [item.get("matched") for item in peers]
            port_values = [item.get("matched") for item in ports]
            if any(
                item is not True and item is not False and item is not None
                for item in peer_values + port_values
            ):
                raise DomainError("network rule witness has an invalid match value")
            peer_true = True in peer_values
            port_true = True in port_values
            undecidable = (
                (not peer_true and None in peer_values)
                or (not port_true and None in port_values)
            )
            expected = True if peer_true and port_true else (None if undecidable else False)
            if rule.get("matched") is not expected:
                raise DomainError("network rule witness derivation is contradictory")


def _service_matches(contents: dict[str, Any]) -> set[str]:
    candidates = contents.get("candidate_workloads")
    matches = contents.get("matched_workloads")
    if type(candidates) is not list or type(matches) is not list:
        raise DomainError("Service witness workload inventories are malformed")
    derived = {
        item.get("identity")
        for item in candidates
        if item.get("selector_evaluation", {}).get("matched") is True
    }
    if None in derived or set(matches) != derived or len(matches) != len(set(matches)):
        raise DomainError("Service witness selector result is contradictory")
    return derived


def validate_native_witness_payload(
    *, witness_type: str, result: NativePropertyResult, contents: dict[str, Any]
) -> None:
    required = _REQUIRED_AUTHORITATIVE_KEYS.get(witness_type)
    if required is None:
        raise DomainError("native witness type has no semantic validator")
    if result in {NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED}:
        missing = required - set(contents)
        if missing:
            raise DomainError(f"authoritative native witness is missing fields: {sorted(missing)}")
    if witness_type == "k8s_network_policy_selection_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        derived = {
            item.get("policy", {}).get("identity")
            for item in contents["policy_evaluations"]
            if item.get("selected") is True
        }
        if None in derived or set(contents["selecting_policies"]) != derived:
            raise DomainError("NetworkPolicy selection inventory is contradictory")
        expected = bool(contents["selecting_policies"])
        if contents.get("requested_policy_identity") is not None:
            expected = contents["requested_policy_identity"] in contents["selecting_policies"]
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("NetworkPolicy selection witness/result disagree")
    elif witness_type == "k8s_network_policy_isolation_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        direction = contents["direction"]
        derived = {
            item.get("policy")
            for item in contents["selecting_policy_types"]
            if direction in item.get("effective_policy_types", [])
        }
        if None in derived or set(contents["isolation_establishing_policies"]) != derived:
            raise DomainError("NetworkPolicy isolation inventory is contradictory")
        expected = bool(contents["isolation_establishing_policies"])
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("NetworkPolicy isolation witness/result disagree")
    elif witness_type == "k8s_component_policy_closure_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        derived = {
            item.get("workload", {}).get("identity")
            for item in contents["members"]
            if not item.get("selecting_policies")
        }
        if None in derived or set(contents["uncovered_workloads"]) != derived:
            raise DomainError("component closure inventory is contradictory")
        expected = not contents["uncovered_workloads"]
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("component closure witness/result disagree")
    elif witness_type == "k8s_network_path_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        _validate_rule_derivations(contents)
        isolated = bool(contents["isolation_establishing_policies"])
        expected = not isolated or _any_matching_rule(contents)
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("NetworkPolicy path witness/result disagree")
        if contents["manifest_semantics_only"] is not True:
            raise DomainError("network path witness must preserve the runtime boundary")
    elif witness_type == "k8s_denied_path_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        _validate_rule_derivations(contents)
        isolated = bool(contents["isolation_establishing_policies"])
        expected = isolated and not _any_matching_rule(contents)
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("denied-path witness/result disagree")
    elif witness_type == "k8s_service_selection_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        actual = _service_matches(contents)
        expectation = contents["expectation"]
        expected_set = set(contents.get("expected_workloads", []))
        expected = (
            bool(actual) if expectation == "ANY_NONEMPTY"
            else len(actual) == 1 if expectation == "EXACT_ONE"
            else actual == expected_set if expectation == "EXACT_SET"
            else expected_set.issubset(actual) if expectation == "ALL_EXPECTED_PRESENT"
            else None
        )
        if expected is None or (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("Service selection witness/result disagree")
    elif witness_type == "k8s_service_port_resolution_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        _service_matches(contents)
        ports = contents["resolved_port_set"]
        if type(ports) is not list or len(ports) != 1 or contents.get("unresolved_workloads"):
            raise DomainError("authoritative ServicePort witness is incomplete")
        expected_port = contents.get("expected_port")
        expected = expected_port is None or ports == [expected_port]
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("ServicePort witness/result disagree")
    elif witness_type == "k8s_pod_network_path_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        children = [
            direction.get("result")
            for item in contents["destination_results"]
            for direction in (item.get("egress", {}), item.get("ingress", {}))
        ]
        if not children or any(item not in {"SATISFIED", "VIOLATED"} for item in children):
            raise DomainError("authoritative Pod network-path witness is incomplete")
        expected = all(item == "SATISFIED" for item in children)
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("Pod network-path witness/result disagree")
        if contents["manifest_semantics_only"] is not True:
            raise DomainError("Pod network path must preserve the runtime boundary")
    elif witness_type == "prometheus_monitor_resolution_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        if "matched_services" in contents:
            targets = contents["matched_services"]
            expected_service = contents.get("expected_service")
            expected = bool(targets) if expected_service is None else expected_service in targets
        else:
            targets = contents.get("matched_workloads", [])
            expected = bool(targets)
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("monitor resolution witness/result disagree")
    elif witness_type == "prometheus_monitoring_ingress_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        target_results = [item.get("result") for item in contents["target_evaluations"]]
        if not target_results or any(item not in {"SATISFIED", "VIOLATED"} for item in target_results):
            raise DomainError("authoritative monitoring path witness is incomplete")
        expected = all(item == "SATISFIED" for item in target_results)
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("monitoring path witness/result disagree")
        if contents["manifest_semantics_only"] is not True:
            raise DomainError("monitoring path must preserve the runtime boundary")
    elif witness_type.startswith("k8s_rbac_") and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        if contents["authorization_simulated"] is not False:
            raise DomainError("RBAC relationship evidence must not claim authorization simulation")
        if witness_type == "k8s_rbac_role_ref_v1":
            expected = contents.get("resolved_target") is not None
            if contents.get("scope_state") == "SCOPE_INCONSISTENT":
                expected = False
        elif witness_type == "k8s_rbac_subject_v1":
            subjects = contents["service_account_subjects"]
            expected = bool(subjects) and all(
                item.get("resolved_target") is not None for item in subjects
            )
        else:
            expected = contents.get("role_ref_scope") != "SCOPE_INCONSISTENT" and all(
                item.get("namespace_valid") is True
                for item in contents["service_account_subjects"]
            )
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("RBAC relationship witness/result disagree")
    elif witness_type == "terraform_reference_v1" and result in {
        NativePropertyResult.SATISFIED, NativePropertyResult.VIOLATED
    }:
        observed = contents["observed_references"]
        expected = contents["expected_target"] in observed
        if (result is NativePropertyResult.SATISFIED) != expected:
            raise DomainError("Terraform reference witness/result disagree")
        if result is NativePropertyResult.SATISFIED and not contents.get("reference_span"):
            raise DomainError("satisfied Terraform reference requires an exact source span")
        if result is NativePropertyResult.VIOLATED and (
            contents.get("complete_local_universe") is not True
            or type(contents.get("reference_contract_digest")) is not str
            or len(contents["reference_contract_digest"]) != 64
        ):
            raise DomainError("violated Terraform reference lacks a complete reviewed domain")


def validate_native_observation(observation: NativePropertyObservation) -> None:
    if type(observation) is not NativePropertyObservation:
        raise DomainError("native evidence validator requires an exact observation")
    validate_native_witness_payload(
        witness_type=observation.witness.witness_type,
        result=observation.result,
        contents=thaw_json(observation.witness.contents),
    )


__all__ = ["validate_native_observation", "validate_native_witness_payload"]
