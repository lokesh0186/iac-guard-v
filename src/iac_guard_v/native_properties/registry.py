"""Closed, packaged registry for the authorized a9 native properties."""
from __future__ import annotations

import hashlib
from importlib.resources import files
from typing import Any

from .model import (
    NativeArtifactClass,
    NativePropertyCapabilities,
    NativePropertyDefinition,
    NativePropertyImplementationIdentity,
    NativeSemanticVersionBinding,
    canonical_digest,
)
from .prometheus_operator import prometheus_operator_contract_digest


_KUBERNETES_CONTRACT = canonical_digest({
    "api": "Kubernetes v1.34.0",
    "label_selector": "metav1.LabelSelector In NotIn Exists DoesNotExist",
    "network_policy": "networking.k8s.io/v1 additive ingress/egress manifest semantics",
    "service": "v1 selector and targetPort manifest semantics",
    "rbac": "rbac.authorization.k8s.io/v1 identity and scope relationships",
    "runtime_claim": False,
})
_TERRAFORM_CONTRACT = canonical_digest({
    "parser": "python-hcl2 protected configuration source",
    "scope": "direct source-local resource traversals",
    "provider_evaluation": False,
    "plan_instances": False,
})
_OPENTOFU_CONTRACT = canonical_digest({
    "language": "OpenTofu",
    "file_set": "opentofu-fileset-v1",
    "extensions": [".tf", ".tf.json", ".tofu", ".tofu.json"],
    "precedence": ".tofu shadows same-basename .tf within syntax family",
    "scope": "exact direct source-local resource traversals with bounded local modules",
    "provider_evaluation": False,
    "plan_instances": False,
    "remote_modules": False,
})


def _module_identity(*modules: str) -> NativePropertyImplementationIdentity:
    records = []
    package = files("iac_guard_v")
    selected = set(modules) | {
        "fingerprints.py",
        "models.py",
        "native_properties/engine.py",
        "native_properties/evidence.py",
        "native_properties/model.py",
        "native_properties/outcome.py",
        "native_properties/registry.py",
        "native_properties/universe.py",
    }
    if any(item.endswith(("network_policy.py", "services.py", "prometheus_operator.py")) for item in modules):
        selected.add("native_properties/selectors.py")
    if any(item.endswith(("network_policy.py", "prometheus_operator.py")) for item in modules):
        selected.add("native_properties/services.py")
    if any(item.endswith("prometheus_operator.py") for item in modules):
        selected.add("native_properties/network_policy.py")
        selected.add("native_properties/contracts/prometheus-operator-v1.json")
    if any(item.endswith("terraform.py") for item in modules):
        selected.add("terraform_parser.py")
    if any(item.endswith("opentofu_reference.py") for item in modules):
        selected.add("terraform_parser.py")
        selected.add("native_properties/opentofu.py")
    for module in sorted(selected):
        digest = hashlib.sha256(package.joinpath(module).read_bytes()).hexdigest()
        records.append((module.replace("/", ".").removesuffix(".py").removesuffix(".json"), digest))
    implementation_digest = canonical_digest([
        {"module": module, "sha256": digest} for module, digest in records
    ])
    return NativePropertyImplementationIdentity("a9-v1", implementation_digest, tuple(records))


def _schema(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


_STRING = {"type": "string", "minLength": 1}
_BOOL = {"type": "boolean"}
_PORT = {"type": "integer", "minimum": 1, "maximum": 65535}
_PROTOCOL = {"enum": ["TCP", "UDP", "SCTP"]}
_ENDPOINT = {
    "type": "object",
    "required": ["type"],
    "properties": {
        "type": {"enum": ["WORKLOAD", "LABELS", "SYMBOLIC", "IP"]},
        "identity": _STRING,
        "namespace": _STRING,
        "pod_labels": {"type": "object", "additionalProperties": {"type": "string"}},
        "namespace_labels": {"type": "object", "additionalProperties": {"type": "string"}},
        "ip": _STRING,
    },
    "additionalProperties": False,
}
_SERVICE_PORT = {
    "type": "object",
    "properties": {"name": _STRING, "port": _PORT, "protocol": _PROTOCOL},
    "additionalProperties": False,
    "minProperties": 1,
}


def _definition(
    property_id: str,
    artifact: NativeArtifactClass,
    subject: str,
    schema: dict[str, Any],
    semantic: str,
    witness: str,
    module: str,
    *,
    relationship: bool = True,
    source_span: bool = False,
    monitor: bool = False,
) -> NativePropertyDefinition:
    binding_digest = (
        canonical_digest({
            "kubernetes": _KUBERNETES_CONTRACT,
            "prometheus_operator": prometheus_operator_contract_digest(),
        })
        if monitor else (
            _KUBERNETES_CONTRACT
            if artifact is NativeArtifactClass.KUBERNETES_RENDERED
            else _OPENTOFU_CONTRACT
            if artifact is NativeArtifactClass.OPENTOFU_SOURCE
            else _TERRAFORM_CONTRACT
        )
    )
    binding = NativeSemanticVersionBinding(
        "kubernetes" if artifact is NativeArtifactClass.KUBERNETES_RENDERED else (
            "opentofu" if artifact is NativeArtifactClass.OPENTOFU_SOURCE else "terraform"
        ),
        "v1.34.0" if artifact is NativeArtifactClass.KUBERNETES_RENDERED else (
            "source-fileset-v1" if artifact is NativeArtifactClass.OPENTOFU_SOURCE else "source-hcl-v1"
        ),
        binding_digest,
    )
    capabilities = NativePropertyCapabilities(True, True, True, relationship, source_span)
    return NativePropertyDefinition(
        "iac_guard_v",
        property_id,
        "1",
        artifact,
        subject,
        schema,
        canonical_digest(schema),
        canonical_digest({"property_id": property_id, "contract": semantic}),
        binding,
        capabilities,
        witness,
        _module_identity(module),
    )


_K8S = NativeArtifactClass.KUBERNETES_RENDERED
_TF = NativeArtifactClass.TERRAFORM_SOURCE
_OT = NativeArtifactClass.OPENTOFU_SOURCE

_DEFINITIONS = (
    _definition(
        "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", _K8S, "workload",
        _schema({"policy_identity": _STRING}),
        "At least one exact same-namespace NetworkPolicy podSelector selects the protected workload labels; an optional exact policy narrows the assertion.",
        "k8s_network_policy_selection_v1", "native_properties/network_policy.py",
    ),
    _definition(
        "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1", _K8S, "workload", _schema({}),
        "At least one selecting NetworkPolicy has effective type Ingress under Kubernetes defaulting.",
        "k8s_network_policy_isolation_v1", "native_properties/network_policy.py",
    ),
    _definition(
        "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1", _K8S, "workload", _schema({}),
        "At least one selecting NetworkPolicy has effective type Egress under Kubernetes defaulting.",
        "k8s_network_policy_isolation_v1", "native_properties/network_policy.py",
    ),
    _definition(
        "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1", _K8S, "component",
        _schema({
            "workload_identities": {"type": "array", "minItems": 1, "uniqueItems": True, "items": _STRING},
            "policy_identities": {"type": "array", "minItems": 1, "uniqueItems": True, "items": _STRING},
            "membership_proof_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        }, ("workload_identities", "policy_identities", "membership_proof_digest")),
        "Every caller-bound component workload is selected by at least one caller-bound policy; component intent is not inferred.",
        "k8s_component_policy_closure_v1", "native_properties/network_policy.py",
    ),
    _definition(
        "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1", _K8S, "service",
        _schema({
            "expectation": {"enum": ["ANY_NONEMPTY", "EXACT_ONE", "EXACT_SET", "ALL_EXPECTED_PRESENT"]},
            "expected_workloads": {"type": "array", "uniqueItems": True, "items": _STRING},
        }),
        "The exact Service selector is evaluated against every protected same-namespace Pod template and the requested cardinality/set expectation.",
        "k8s_service_selection_v1", "native_properties/services.py",
    ),
    _definition(
        "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1", _K8S, "service",
        _schema({"service_port": _SERVICE_PORT, "expected_port": _PORT}, ("service_port",)),
        "The selected ServicePort targetPort resolves without ambiguity for the complete selected protected workload set.",
        "k8s_service_port_resolution_v1", "native_properties/services.py",
    ),
    _definition(
        "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1", _K8S, "workload",
        _schema({"source": _ENDPOINT, "port": _PORT, "protocol": _PROTOCOL}, ("source", "port")),
        "The additive selecting NetworkPolicy ingress rules allow the exact source/destination port contract, or ingress is not isolated.",
        "k8s_network_path_v1", "native_properties/network_policy.py",
    ),
    _definition(
        "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1", _K8S, "workload",
        _schema({"destination": _ENDPOINT, "port": _PORT, "protocol": _PROTOCOL}, ("destination", "port")),
        "The additive selecting NetworkPolicy egress rules allow the exact destination/port contract, or egress is not isolated.",
        "k8s_network_path_v1", "native_properties/network_policy.py",
    ),
    _definition(
        "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1", _K8S, "workload",
        _schema({
            "destination_workload": _STRING,
            "destination_service": _STRING,
            "service_port": _SERVICE_PORT,
            "port": _PORT,
            "protocol": _PROTOCOL,
        }),
        "Both isolated source-egress and destination-ingress directions allow the exact protected Pod-to-Pod or Service-resolved path.",
        "k8s_pod_network_path_v1", "native_properties/network_policy.py",
    ),
    _definition(
        "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1", _K8S, "workload",
        _schema({
            "direction": {"enum": ["Ingress", "Egress"]},
            "source": _ENDPOINT,
            "destination": _ENDPOINT,
            "port": _PORT,
            "protocol": _PROTOCOL,
        }, ("direction", "port")),
        "The requested direction is isolated and no fully decidable additive rendered rule matches; this is not absence-as-pass.",
        "k8s_denied_path_v1", "native_properties/network_policy.py",
    ),
    _definition(
        "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1", _K8S, "service_monitor",
        _schema({"endpoint_index": {"type": "integer", "minimum": 0}, "expected_service": _STRING}),
        "An allowlisted monitoring.coreos.com/v1 ServiceMonitor endpoint.port resolves through selected protected Services and ServicePorts.",
        "prometheus_monitor_resolution_v1", "native_properties/prometheus_operator.py", monitor=True,
    ),
    _definition(
        "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1", _K8S, "pod_monitor",
        _schema({"endpoint_index": {"type": "integer", "minimum": 0}}),
        "An allowlisted monitoring.coreos.com/v1 PodMonitor endpoint resolves to selected protected Pod templates and container ports.",
        "prometheus_monitor_resolution_v1", "native_properties/prometheus_operator.py", monitor=True,
    ),
    _definition(
        "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1", _K8S, "monitor",
        _schema({"endpoint_index": {"type": "integer", "minimum": 0}, "source": _ENDPOINT}, ("source",)),
        "The allowlisted declared monitor target resolves and every destination ingress path is allowed for the explicit monitoring source contract.",
        "prometheus_monitoring_ingress_v1", "native_properties/prometheus_operator.py", monitor=True,
    ),
    _definition(
        "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", _K8S, "rbac_binding",
        _schema({"complete_expected_domain": _BOOL}),
        "RoleBinding roleRef resolves to same-namespace Role or ClusterRole; ClusterRoleBinding resolves only ClusterRole, within the declared protected domain.",
        "k8s_rbac_role_ref_v1", "native_properties/rbac.py",
    ),
    _definition(
        "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", _K8S, "rbac_binding",
        _schema({"complete_expected_domain": _BOOL}),
        "Every ServiceAccount subject resolves in the declared protected identity domain, using an explicit namespace or the Kubernetes RoleBinding-local default; User/Group authorization is not evaluated.",
        "k8s_rbac_subject_v1", "native_properties/rbac.py",
    ),
    _definition(
        "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", _K8S, "rbac_binding", _schema({}),
        "Binding kind, roleRef kind/scope, and ServiceAccount namespace semantics are mechanically consistent: RoleBinding-local omission defaults locally, cross-namespace subjects are valid, and ClusterRoleBinding subjects require an explicit namespace; permissions are not simulated.",
        "k8s_rbac_scope_v1", "native_properties/rbac.py",
    ),
    _definition(
        "IACGV_TF_REFERENCE_RESOLVES_V1", _TF, "terraform_resource",
        _schema({
            "attribute_path": {"type": "array", "minItems": 1, "items": {"anyOf": [_STRING, {"type": "integer", "minimum": 0}]}},
            "expected_target": _STRING,
            "mode": {"enum": ["DIRECT", "TRANSITIVE"]},
            "complete_expected_domain": _BOOL,
            "reference_contract_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        }, ("attribute_path", "expected_target")) | {
            "allOf": [{
                "if": {
                    "properties": {"complete_expected_domain": {"const": True}},
                    "required": ["complete_expected_domain"],
                },
                "then": {"required": ["reference_contract_digest"]},
            }]
        },
        "An exact direct source-local traversal at the bound attribute path resolves to the expected protected Terraform resource; provider evaluation is excluded.",
        "terraform_reference_v1", "native_properties/terraform.py", source_span=True,
    ),
    _definition(
        "IACGV_OPENTOFU_REFERENCE_RESOLVES_V1", _OT, "opentofu_resource",
        _schema({
            "attribute_path": {"type": "array", "minItems": 1, "items": {"anyOf": [_STRING, {"type": "integer", "minimum": 0}]}},
            "expected_target": _STRING,
            "mode": {"enum": ["DIRECT", "TRANSITIVE"]},
            "complete_expected_domain": _BOOL,
            "reference_contract_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        }, ("attribute_path", "expected_target")) | {
            "allOf": [{
                "if": {
                    "properties": {"complete_expected_domain": {"const": True}},
                    "required": ["complete_expected_domain"],
                },
                "then": {"required": ["reference_contract_digest"]},
            }]
        },
        "An exact direct source-local traversal in the protected effective OpenTofu file set resolves to the expected protected resource; precedence, bounded overrides, local-module identity, and shadowed files are witnessed while provider/runtime evaluation and remote acquisition are excluded.",
        "opentofu_reference_v1", "native_properties/opentofu_reference.py", source_span=True,
    ),
)

NATIVE_PROPERTY_REGISTRY = {item.property_id: item for item in _DEFINITIONS}
if len(NATIVE_PROPERTY_REGISTRY) != len(_DEFINITIONS):
    raise RuntimeError("duplicate native property ID in packaged registry")


def native_registry_identity() -> str:
    return canonical_digest([
        NATIVE_PROPERTY_REGISTRY[key].canonical_dict()
        for key in sorted(NATIVE_PROPERTY_REGISTRY)
    ])


__all__ = ["NATIVE_PROPERTY_REGISTRY", "native_registry_identity"]
