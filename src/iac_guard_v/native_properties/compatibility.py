"""Frozen a9/a10 native-definition snapshots for historical report validation."""
from __future__ import annotations

from typing import Any, Mapping

from ..models import DomainError
from .model import canonical_digest


A10_NATIVE_REGISTRY_IDENTITY = "de9a293ea2d3da8dbdbbbe3b12aa5b5d212ba789af225ea714b18d91dc501f90"
A10_CONTRACT_COMPILER_IDENTITY = "7990eeae19c6e93b7a6cee68ef3c2c582c2f85ef86d88029c50bfa48905daff7"
A10_CONTRACT_SCHEMA_IDENTITY = "c6baff537d854c2cea8204a5fc740d88bee79e9abb91b2aa5389dafbee4a65cc"

_A10_DEFINITION_DIGESTS = {
    "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1": "f59fa6a019985fec42f8b45eb060b0587e4ef136e7245982e321f523dbd283aa",
    "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1": "83803bc13f3793b85043e558fd6de6648ce32ae50bce34b5d516ad5c1d001f57",
    "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1": "638a071eb9a85bdb7f5e8dca3cab29e8abeeaad7edb141272b697dfb57df2f4b",
    "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1": "1d3ef97d8c54447e1ca253056763154514f1f67f7c38ec4dbd1629e6879e213b",
    "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1": "69f0e22fbb469c529176c82c4e89f6a35dd20a76e1682a2de3f9516818928b90",
    "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1": "11fb9c74cc20601c082a9fc08513635c09c3242d92f6021eb4fc37d862becbcb",
    "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1": "0ea0dac25070a9dfbf093ba1c64f7e804806a5132fcf944f2384b3682a96a143",
    "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1": "1eea2e3df054fd79f87a4da89ea77b181d81729b87ce7d07ed291231f55a2ad4",
    "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1": "54a99a12f96bb0cbf7c0f369f00c4f222b8393c36d0755dece7a320596502923",
    "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1": "3ed2e2ccc4d0c6cb97eb521d1318ae661e4ff0fed3da633661b3242859ea69b4",
    "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1": "04ced15f93aa7855f4a9a34e1de08d43046b0f99dd9b7ecf00a8457d51011279",
    "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1": "1370c1e2fa27bf26750dd2a315b0d9036a5235ffa50caa4835f2133bb641f354",
    "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1": "7b6d285628f8ba4f5dc1c6b244414bdbebb0b7e9b1880815419fa46ac60631bc",
    "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1": "443efb233ea9e0fc08bac01885efa5c4363542646e088b418d2d42a17b97782a",
    "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1": "6336422589669318a10588b471e120aa28aa58c821065ee62ffdfd220fc2caa6",
    "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1": "f6fff34bb8e8e995df783fedf9fe737edc1962862b61761349c55927ca691a78",
    "IACGV_TF_REFERENCE_RESOLVES_V1": "7493c1f18a1a4f9f8410f5d9ed98efb72857dbefc1241a1798d750c4ee89b75e",
}


def validate_a10_definition_snapshot(definition: Mapping[str, Any]) -> None:
    property_id = definition.get("property_id")
    expected = _A10_DEFINITION_DIGESTS.get(property_id)
    if expected is None or canonical_digest(definition) != expected:
        raise DomainError("historical native definition is not in the frozen a10 registry")


def is_a10_contract_identity(
    *, product_version: str, registry_identity: str,
    compiler_identity: str, schema_identity: str,
) -> bool:
    return (
        product_version == "0.1.0a10"
        and registry_identity == A10_NATIVE_REGISTRY_IDENTITY
        and compiler_identity == A10_CONTRACT_COMPILER_IDENTITY
        and schema_identity == A10_CONTRACT_SCHEMA_IDENTITY
    )


__all__ = [
    "A10_CONTRACT_COMPILER_IDENTITY", "A10_CONTRACT_SCHEMA_IDENTITY",
    "A10_NATIVE_REGISTRY_IDENTITY", "is_a10_contract_identity",
    "validate_a10_definition_snapshot",
]
