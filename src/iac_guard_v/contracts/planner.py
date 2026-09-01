"""Deterministic subject resolution and compilation to a9 native requests."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

import jsonschema

from ..models import DomainError, canonical_identifier, canonical_resource_scope
from ..native_properties.model import (
    NativeArtifactClass,
    NativePropertyRequest,
    canonical_digest,
    canonical_json,
    thaw_json,
)
from ..native_properties.registry import NATIVE_PROPERTY_REGISTRY, native_registry_identity
from ..native_properties.selectors import evaluate_label_selector
from ..native_properties.universe import ProtectedNativeUniverse
from .model import (
    ActivationEvidence,
    ActivationStatus,
    InfrastructureContract,
    Responsibility,
    contract_digest,
    contract_implementation_identity,
)


@dataclass(frozen=True, slots=True)
class SubjectResolution:
    candidates: tuple[Mapping[str, Any], ...]
    included: tuple[str, ...]
    excluded: tuple[str, ...]
    unresolved: tuple[str, ...]
    selected: tuple[str, ...]
    minimum: int
    maximum: int | None
    allow_empty: bool
    result: str
    reason_code: str
    resolution_digest: str

    @classmethod
    def build(cls, **values) -> "SubjectResolution":
        body = {
            "candidates": values["candidates"],
            "included": list(values["included"]),
            "excluded": list(values["excluded"]),
            "unresolved": list(values["unresolved"]),
            "selected": list(values["selected"]),
            "minimum": values["minimum"],
            "maximum": values["maximum"],
            "allow_empty": values["allow_empty"],
            "result": values["result"],
            "reason_code": values["reason_code"],
        }
        return cls(
            tuple(canonical_json(item) for item in values["candidates"]),
            tuple(values["included"]), tuple(values["excluded"]),
            tuple(values["unresolved"]), tuple(values["selected"]),
            values["minimum"], values["maximum"], values["allow_empty"],
            values["result"], values["reason_code"], canonical_digest(body),
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "candidates": [thaw_json(item) for item in self.candidates],
            "included": list(self.included), "excluded": list(self.excluded),
            "unresolved": list(self.unresolved), "selected": list(self.selected),
            "minimum": self.minimum, "maximum": self.maximum,
            "allow_empty": self.allow_empty, "result": self.result,
            "reason_code": self.reason_code, "resolution_digest": self.resolution_digest,
        }


@dataclass(frozen=True, slots=True)
class PlannedClause:
    clause_id: str
    property_id: str
    property_version: str
    required: bool
    target_minimum: int
    target_maximum: int | None
    requests: tuple[NativePropertyRequest, ...]
    parameters_digest: str
    activation_digest: str
    responsibility_digest: str
    clause_identity: str

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "clause_id": self.clause_id,
            "property_id": self.property_id,
            "property_version": self.property_version,
            "required": self.required,
            "target_minimum": self.target_minimum,
            "target_maximum": self.target_maximum,
            "requests": [item.canonical_dict() for item in self.requests],
            "parameters_digest": self.parameters_digest,
            "activation_digest": self.activation_digest,
            "responsibility_digest": self.responsibility_digest,
            "clause_identity": self.clause_identity,
        }


@dataclass(frozen=True, slots=True)
class ContractPlan:
    contract_identity: str
    execution_identity: str
    protected_universe_identity: str
    native_registry_identity: str
    compiler_identity: str
    activation: ActivationEvidence
    subjects: SubjectResolution
    clauses: tuple[PlannedClause, ...]
    plan_result: str
    reason_code: str
    plan_digest: str

    @classmethod
    def build(
        cls, contract: InfrastructureContract, universe: ProtectedNativeUniverse,
        activation: ActivationEvidence, subjects: SubjectResolution,
        clauses: tuple[PlannedClause, ...], plan_result: str, reason_code: str,
    ) -> "ContractPlan":
        compiler = contract_implementation_identity()
        execution_identity = contract_digest({
            "contract_identity": contract.identity,
            "protected_universe_identity": universe.identity,
            "activation_input_identity": activation.input_identity,
            "activation_evidence_digest": contract_digest(activation.canonical_dict()),
            "native_registry_identity": native_registry_identity(),
            "compiler_identity": compiler,
        })
        body = {
            "contract_identity": contract.identity,
            "execution_identity": execution_identity,
            "protected_universe_identity": universe.identity,
            "native_registry_identity": native_registry_identity(),
            "compiler_identity": compiler,
            "activation": activation.canonical_dict(),
            "subjects": subjects.canonical_dict(),
            "clauses": [item.canonical_dict() for item in clauses],
            "plan_result": plan_result,
            "reason_code": reason_code,
        }
        return cls(
            contract.identity, execution_identity, universe.identity,
            native_registry_identity(), compiler,
            activation, subjects, clauses, plan_result, reason_code, contract_digest(body),
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "contract_identity": self.contract_identity,
            "execution_identity": self.execution_identity,
            "protected_universe_identity": self.protected_universe_identity,
            "native_registry_identity": self.native_registry_identity,
            "compiler_identity": self.compiler_identity,
            "activation": self.activation.canonical_dict(),
            "subjects": self.subjects.canonical_dict(),
            "clauses": [item.canonical_dict() for item in self.clauses],
            "plan_result": self.plan_result, "reason_code": self.reason_code,
            "plan_digest": self.plan_digest,
        }


def _resource_records(universe: ProtectedNativeUniverse) -> tuple[tuple[str, str, str, str, Mapping[str, str]], ...]:
    if universe.artifact_class is NativeArtifactClass.TERRAFORM_SOURCE:
        return tuple((item.identity, "terraform", item.resource_type, "_source", MappingProxyType({})) for item in universe.terraform_resources)
    workloads = {item.identity: item for item in universe.workloads}
    records = []
    for resource in universe.kubernetes_resources:
        labels = workloads[resource.identity].pod_labels if resource.identity in workloads else resource.labels
        records.append((resource.identity, resource.api_version, resource.kind, resource.namespace, labels))
    return tuple(records)


def resolve_subjects(contract: InfrastructureContract, universe: ProtectedNativeUniverse) -> SubjectResolution:
    raw = thaw_json(contract.subjects)
    include = raw["include"]
    explicit = tuple(include.get("identities", ()))
    excluded = tuple(raw.get("exclude", {}).get("identities", ()))
    if set(explicit) & set(excluded):
        raise DomainError("an explicitly included identity cannot also be explicitly excluded")
    records = _resource_records(universe)
    identities = {item[0] for item in records}
    unresolved = tuple(sorted(identity for identity in explicit if identity not in identities))
    included = set(identity for identity in explicit if identity in identities)
    candidate_witnesses = []
    selector = include.get("selector")
    if selector is not None:
        if universe.artifact_class is not NativeArtifactClass.KUBERNETES_RENDERED:
            raise DomainError("label selector subject resolution is Kubernetes-only")
        api_versions = set(selector["apiVersions"])
        kinds = set(selector["kinds"])
        namespaces = set(selector["namespaces"])
        for identity, api_version, kind, namespace, labels in records:
            in_domain = api_version in api_versions and kind in kinds and namespace in namespaces
            evaluation = evaluate_label_selector(selector["labelSelector"], labels) if in_domain else None
            matched = bool(in_domain and evaluation is not None and evaluation.matched)
            candidate_witnesses.append({
                "identity": identity, "api_version": api_version, "kind": kind,
                "namespace": namespace, "in_domain": in_domain, "matched": matched,
                "selector_evaluation": evaluation.canonical_dict() if evaluation else None,
            })
            if matched:
                included.add(identity)
    selected = tuple(sorted(included - set(excluded)))
    recorded_exclusions = tuple(sorted(set(excluded)))
    cardinality = raw.get("cardinality", {})
    minimum = cardinality.get("min", 1)
    maximum = cardinality.get("max")
    allow_empty = cardinality.get("allowEmpty", False)
    if unresolved:
        result, reason = "NOT_EVALUATED", "SUBJECT_IDENTITY_UNRESOLVED"
    elif not selected and not allow_empty:
        result, reason = "VIOLATED", "ZERO_SUBJECT_MATCH"
    elif len(selected) < minimum:
        result, reason = "VIOLATED", "SUBJECT_CARDINALITY_BELOW_MINIMUM"
    elif maximum is not None and len(selected) > maximum:
        result, reason = "VIOLATED", "SUBJECT_CARDINALITY_ABOVE_MAXIMUM"
    else:
        result, reason = "SATISFIED", "SUBJECT_SET_RESOLVED"
    return SubjectResolution.build(
        candidates=tuple(candidate_witnesses), included=tuple(sorted(included)),
        excluded=recorded_exclusions, unresolved=unresolved, selected=selected,
        minimum=minimum, maximum=maximum, allow_empty=allow_empty,
        result=result, reason_code=reason,
    )


def _compile_clause(
    contract: InfrastructureContract,
    universe: ProtectedNativeUniverse,
    subjects: SubjectResolution,
    activation: ActivationEvidence,
    raw_clause: Mapping[str, Any],
) -> PlannedClause:
    clause = thaw_json(raw_clause)
    clause_id = canonical_identifier(clause["id"], "contract clause ID")
    property_spec = clause["property"]
    property_id = property_spec["id"]
    definition = NATIVE_PROPERTY_REGISTRY.get(property_id)
    if definition is None:
        raise DomainError("contract property is not in the packaged native registry")
    version = property_spec["version"]
    if property_spec["namespace"] != "iac_guard_v" or version != definition.property_version:
        raise DomainError("contract property namespace/version is unsupported")
    if definition.artifact_class is not universe.artifact_class:
        raise DomainError("contract property artifact class disagrees with protected universe")
    parameters = dict(clause.get("parameters", {}))
    request_subjects = subjects.selected
    if property_id == "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1":
        policies = parameters.get("policy_identities")
        if type(policies) is not list or not policies:
            raise DomainError("component closure contract requires policy_identities")
        parameters["workload_identities"] = list(subjects.selected)
        parameters["membership_proof_digest"] = subjects.resolution_digest
        request_subjects = (f"component/{contract.name}/{clause_id}",)
    try:
        jsonschema.Draft202012Validator(thaw_json(definition.parameter_schema)).validate(parameters)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"contract parameters violate native property definition: {exc.message}") from exc
    requests = tuple(
        NativePropertyRequest.build(
            request_id=f"{clause_id}-{index:04d}", property_id=property_id,
            property_version=version, artifact_class=universe.artifact_class,
            subject_identity=identity, parameters=parameters,
            protected_universe_identity=universe.identity,
        )
        for index, identity in enumerate(request_subjects, start=1)
    )
    relation = clause.get("relationCardinality", {})
    target_minimum = relation.get("targetMin", 1)
    target_maximum = relation.get("targetMax")
    activation_digest = contract_digest(activation.canonical_dict())
    responsibility_digest = contract_digest(contract.responsibility)
    body = {
        "contract_identity": contract.identity, "clause_id": clause_id,
        "property_id": property_id, "property_version": version,
        "subject_set_digest": canonical_digest(list(request_subjects)),
        "parameters_digest": canonical_digest(parameters),
        "activation_digest": activation_digest,
        "responsibility_digest": responsibility_digest,
        "target_minimum": target_minimum, "target_maximum": target_maximum,
        "required": clause.get("required", True),
    }
    return PlannedClause(
        clause_id, property_id, version, clause.get("required", True),
        target_minimum, target_maximum, requests, canonical_digest(parameters),
        activation_digest, responsibility_digest,
        canonical_digest(body),
    )


def plan_contract(
    contract: InfrastructureContract,
    universe: ProtectedNativeUniverse,
    activation: ActivationEvidence,
) -> ContractPlan:
    if type(contract) is not InfrastructureContract or type(universe) is not ProtectedNativeUniverse:
        raise DomainError("contract planning requires exact protected inputs")
    if contract.artifact_class != universe.artifact_class.value:
        raise DomainError("contract artifact class differs from protected universe")
    subjects = resolve_subjects(contract, universe)
    responsibility = Responsibility(thaw_json(contract.responsibility)["class"])
    if activation.status is ActivationStatus.INACTIVE_CONDITION_FALSE:
        return ContractPlan.build(contract, universe, activation, subjects, (), "NOT_EVALUATED", "CONTRACT_INACTIVE")
    if activation.status is not ActivationStatus.ACTIVE:
        return ContractPlan.build(contract, universe, activation, subjects, (), "NOT_EVALUATED", "CONTRACT_ACTIVATION_NOT_EVALUATED")
    if subjects.result != "SATISFIED":
        return ContractPlan.build(contract, universe, activation, subjects, (), subjects.result, subjects.reason_code)
    clauses = tuple(
        _compile_clause(contract, universe, subjects, activation, item)
        for item in contract.clauses
    )
    if responsibility is Responsibility.OUT_OF_CONTRACT:
        return ContractPlan.build(
            contract, universe, activation, subjects, clauses, "NOT_EVALUATED",
            "CONTRACT_SCOPE_EXPLICITLY_EXCLUDED",
        )
    return ContractPlan.build(contract, universe, activation, subjects, clauses, "SATISFIED", "CONTRACT_PLAN_COMPILED")


__all__ = [
    "ContractPlan", "PlannedClause", "SubjectResolution", "plan_contract",
    "resolve_subjects",
]
