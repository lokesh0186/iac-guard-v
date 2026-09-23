"""Executable 1.x freeze for the 18 Beta1 native property contracts.

Implementation identities are intentionally excluded from this semantic surface:
their digests change when reviewed implementations are hardened.  Every field that
defines what a property means, accepts, witnesses, or supports is frozen here.
"""
from __future__ import annotations

from typing import Any

from ..models import DomainError
from .model import NativePropertyResult, canonical_digest
from .registry import NATIVE_PROPERTY_REGISTRY


STABLE_V1_PROPERTY_SURFACE_VERSION = "native-property-surface-v1"
STABLE_V1_PROPERTY_SURFACE_DIGEST = (
    "e57b3c6c65d907121cdac1c12c676745ecddb10ebc2f9c9853d26f2ab83f77ab"
)

STABLE_V1_PROPERTY_DIGESTS = {
    "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1": "b8db1a0242c2ab441b329608d3a5ce79bb5a2a42065ef084aac791c142b33aa6",
    "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1": "4fe726f7a0731b60dfab3c0c0262e28afb48215b66263010299cef23ae829eab",
    "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1": "933d7d5231949a78a28b4e340a2b3d5b8d42fb9084a5c7b7d7fa5f1d712c0d68",
    "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1": "e5d46d309c1fbf091d91a1ecc4127864b80ba5ef0df12c047374c2558fc5ac69",
    "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1": "1daac18a28cdae3ec85a4e60dbdb7bda287e59ee7853c443ea21ecd664c23182",
    "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1": "af213d996a010c932a8e1a8a2f18125f15a96c9123c8c66357e8cb185a1dbe88",
    "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1": "287ca6c8ac5314fd62f9fd1e164fe665ff1344ddbdea2b7e63bdee0953abdcd3",
    "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1": "0793edd527c06b427ab2623c3ad551bc407df44b0f2c8d2727fb2a9661b5d500",
    "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1": "894b5f3e872f47dc1b6b96e562d713a313f3c6440e5d295b97ccd7b38eabb959",
    "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1": "e1cda1b1f0fb17488dfe8f521666fcaabe6ae0f1467fb19975e9ab30a45dcacf",
    "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1": "a0035659c1b489b7bedcb190b061a097411fbd37a56d45e0c1697b57b43713aa",
    "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1": "0e913afcc47805dd7376df3bbe01a3557f9a69c4f3f60193d80460295b9f4e26",
    "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1": "1e5afc4932809b24b58092a9525ea10292b6283322d9d3937b3925b221dbc527",
    "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1": "0fd90d3d6272cb34e35f6f52b8a68043bb4b48171ac7bed8d3bf1127b961c3c3",
    "IACGV_OPENTOFU_REFERENCE_RESOLVES_V1": "3bd50f33f6fc55d510b97a36a98b8df80e636a5b73fc4d4c191dfb530c4e4e5c",
    "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1": "bc1a9349d0769372640d502f032015cb1c49e80f6eba22025c4e618d833faa8d",
    "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1": "52e934d928d4a8ce44439850788b4177b1a0a3bf405a8791e0575096b22776de",
    "IACGV_TF_REFERENCE_RESOLVES_V1": "64d1ce2109cb62229e3354b4f2b6d53e12e6698020e36db090f92e86346ab9f4",
}

# Each property is bound to executable fixture coverage and at least one public
# demand case.  The links are evidence locators, not claims that every project runs
# IaC-Guard-V in its own CI.
STABLE_V1_FIXTURE_COVERAGE = {
    property_id: paths
    for property_ids, paths in (
        ((
            "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1",
            "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1",
            "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1",
            "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1",
            "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1",
            "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1",
            "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1",
            "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1",
            "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1",
        ), (
            "tests/unit/test_native_kubernetes_a9.py",
            "tests/unit/test_native_adversarial_a9.py",
        )),
        ((
            "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1",
            "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1",
            "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1",
            "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1",
        ), (
            "tests/unit/test_native_kubernetes_a9.py",
            "tests/unit/test_native_adversarial_a9.py",
        )),
        ((
            "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1",
            "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1",
            "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1",
        ), (
            "tests/unit/test_native_rbac_scope_a9.py",
            "tests/unit/test_native_adversarial_a9.py",
        )),
        (("IACGV_TF_REFERENCE_RESOLVES_V1",), (
            "tests/unit/test_native_terraform_a9.py",
            "tests/unit/test_native_adversarial_a9.py",
        )),
        (("IACGV_OPENTOFU_REFERENCE_RESOLVES_V1",), (
            "tests/unit/test_native_opentofu_beta1.py",
        )),
    )
    for property_id in property_ids
}

STABLE_V1_PUBLIC_CASES = {
    "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1": "https://github.com/lokesh0186/iac-guard-v/releases/tag/v0.1.0-beta.1",
    "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1": "https://github.com/lokesh0186/iac-guard-v/releases/tag/v0.1.0-beta.1",
    "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1": "https://github.com/Quay/quay-operator/issues/1322",
    "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1": "https://github.com/dgraph-io/charts/pull/146",
    "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1": "https://github.com/dgraph-io/charts/pull/146",
    "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1": "https://github.com/stackrox/kube-linter/pull/1255",
    "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1": "https://github.com/stackrox/kube-linter/pull/1255",
    "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1": "https://github.com/stackrox/kube-linter/pull/1255",
    "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1": "https://github.com/kubescape/regolibrary/issues/805",
    "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1": "https://github.com/kubescape/regolibrary/issues/805",
    "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1": "https://github.com/Quay/quay-operator/issues/1322",
    "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1": "https://github.com/Quay/quay-operator/issues/1322",
    "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1": "https://github.com/dgraph-io/charts/pull/146",
    "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1": "https://github.com/dgraph-io/charts/pull/146",
    "IACGV_OPENTOFU_REFERENCE_RESOLVES_V1": "https://github.com/antonbabenko/pre-commit-terraform/issues/1013",
    "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1": "https://github.com/cert-manager/cert-manager/issues/9366",
    "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1": "https://github.com/k8sgpt-ai/k8sgpt-operator/pull/846",
    "IACGV_TF_REFERENCE_RESOLVES_V1": "https://github.com/bridgecrewio/checkov/issues/7668",
}


def stable_v1_property_record(property_id: str) -> dict[str, Any]:
    """Return the frozen semantic portion of one packaged definition."""
    try:
        record = NATIVE_PROPERTY_REGISTRY[property_id].canonical_dict()
    except KeyError as exc:
        raise DomainError(f"unknown stable native property {property_id}") from exc
    record.pop("implementation")
    return record


def stable_v1_property_surface() -> list[dict[str, Any]]:
    return [stable_v1_property_record(key) for key in sorted(NATIVE_PROPERTY_REGISTRY)]


def validate_stable_v1_property_surface() -> None:
    observed_ids = set(NATIVE_PROPERTY_REGISTRY)
    expected_ids = set(STABLE_V1_PROPERTY_DIGESTS)
    if observed_ids != expected_ids or len(observed_ids) != 18:
        raise DomainError("stable native property ID set changed")
    if set(STABLE_V1_FIXTURE_COVERAGE) != expected_ids:
        raise DomainError("stable native property fixture coverage is incomplete")
    if set(STABLE_V1_PUBLIC_CASES) != expected_ids:
        raise DomainError("stable native property demand evidence is incomplete")
    for property_id in sorted(expected_ids):
        record = stable_v1_property_record(property_id)
        if record["property_version"] != "1":
            raise DomainError(f"stable native property version changed: {property_id}")
        if canonical_digest(record) != STABLE_V1_PROPERTY_DIGESTS[property_id]:
            raise DomainError(f"stable native property semantics changed: {property_id}")
    if canonical_digest(stable_v1_property_surface()) != STABLE_V1_PROPERTY_SURFACE_DIGEST:
        raise DomainError("stable native property surface digest changed")
    if tuple(item.value for item in NativePropertyResult) != (
        "SATISFIED", "VIOLATED", "NOT_EVALUATED", "UNSUPPORTED", "ERROR"
    ):
        raise DomainError("stable native property result vocabulary changed")


__all__ = [
    "STABLE_V1_FIXTURE_COVERAGE", "STABLE_V1_PROPERTY_DIGESTS",
    "STABLE_V1_PROPERTY_SURFACE_DIGEST", "STABLE_V1_PROPERTY_SURFACE_VERSION",
    "STABLE_V1_PUBLIC_CASES", "stable_v1_property_record",
    "stable_v1_property_surface", "validate_stable_v1_property_surface",
]
