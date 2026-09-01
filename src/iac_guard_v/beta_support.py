"""Versioned beta capability metadata and safe onboarding templates."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from .models import DomainError
from .native_properties.registry import NATIVE_PROPERTY_REGISTRY, native_registry_identity
from .workflow import write_new_regular_file


SUPPORT_MATRIX_VERSION = "beta-support-matrix-v1"
SCANNER_DIAGNOSTICS_VERSION = "scanner-diagnostics-v1"


_SCANNER_CAPABILITY_DECLARATIONS = (
    {
        "name": "checkov",
        "reviewed_versions": ["3.3.0"],
        "authority": "AUTHORITATIVE_REVIEWED_PATHS",
        "artifact_classes": ["kubernetes", "terraform"],
        "exact_target_binding": True,
        "affirmative_target_pass": True,
        "advisory_only": False,
        "adapter_contract": "checkov-adapter-v4",
    },
    {
        "name": "kics",
        "reviewed_versions": ["2.1.20"],
        "authority": "ADVISORY",
        "artifact_classes": ["cloudformation", "kubernetes", "terraform"],
        "exact_target_binding": False,
        "affirmative_target_pass": False,
        "advisory_only": True,
        "adapter_contract": "kics-adapter-contract-v3",
    },
    {
        "name": "trivy",
        "reviewed_versions": ["0.73.0"],
        "authority": "ADVISORY",
        "artifact_classes": ["kubernetes", "terraform"],
        "exact_target_binding": False,
        "affirmative_target_pass": False,
        "advisory_only": True,
        "adapter_contract": "trivy-config-adapter-contract-v3",
        "reviewed_checks_version": "2.2.0",
    },
)

_FAMILIES: dict[str, tuple[str, str, str, dict]] = {
    "rbac-closure": (
        "kubernetes_rendered",
        "rbac.authorization.k8s.io/v1/RoleBinding/default/replace-me",
        "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", {},
    ),
    "servicemonitor-service": (
        "kubernetes_rendered",
        "monitoring.coreos.com/v1/ServiceMonitor/default/replace-me",
        "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1", {},
    ),
    "network-service-path": (
        "kubernetes_rendered", "apps/v1/Deployment/default/replace-me",
        "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1",
        {"source": {"type": "SYMBOLIC", "identity": "replace-source"}, "port": 443},
    ),
    "workload-policy-closure": (
        "kubernetes_rendered", "apps/v1/Deployment/default/replace-me",
        "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1",
        {
            "workload_identities": ["apps/v1/Deployment/default/replace-me"],
            "policy_identities": ["networking.k8s.io/v1/NetworkPolicy/default/replace-me"],
            "membership_proof_digest": "0" * 64,
        },
    ),
    "migration-database-path": (
        "kubernetes_rendered", "batch/v1/Job/default/replace-me",
        "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1", {"port": 5432, "protocol": "TCP"},
    ),
    "terraform-reference": (
        "terraform_source", "example_source.replace_me",
        "IACGV_TF_REFERENCE_RESOLVES_V1",
        {"attribute_path": ["replace_attribute"], "expected_target": "example_target.replace_me"},
    ),
    "opentofu-reference": (
        "opentofu_source", "example_source.replace_me",
        "IACGV_OPENTOFU_REFERENCE_RESOLVES_V1",
        {"attribute_path": ["replace_attribute"], "expected_target": "example_target.replace_me"},
    ),
}


def property_catalog() -> dict:
    """Return deterministic public property discovery metadata."""
    return {
        "schema_version": "native-property-catalog-v1",
        "registry_identity": native_registry_identity(),
        "properties": [
            {
                "property_id": item.property_id,
                "property_version": item.property_version,
                "artifact_class": item.artifact_class.value,
                "subject_class": item.subject_class,
                "semantic_system": item.semantic_binding.system,
                "semantic_version": item.semantic_binding.version,
                "semantic_contract_digest": item.semantic_binding.contract_digest,
                "witness_type": item.witness_type,
                "can_satisfy": item.capabilities.can_satisfy,
                "can_violate": item.capabilities.can_violate,
                "fail_closed": True,
            }
            for item in NATIVE_PROPERTY_REGISTRY.values()
        ],
    }


def describe_property(property_id: str) -> dict:
    definition = NATIVE_PROPERTY_REGISTRY.get(property_id)
    if definition is None:
        raise DomainError("native property ID is unsupported")
    return {
        "schema_version": "native-property-description-v1",
        "registry_identity": native_registry_identity(),
        "definition": definition.canonical_dict(),
        "support": {
            "authoritative_native_verdict": True,
            "scanner_required": False,
            "live_system_claim": False,
            "project_intent_claim": False,
            "uncertainty": "fail_closed",
        },
    }


def contract_template(family: str) -> bytes:
    """Build a non-evidentiary suggested contract with explicit placeholders."""
    try:
        artifact, subject_identity, property_id, parameters = _FAMILIES[family]
    except KeyError as exc:
        raise DomainError("contract template family is unsupported") from exc
    definition = NATIVE_PROPERTY_REGISTRY[property_id]
    payload = {
        "apiVersion": "iac-guard-v.io/v1alpha1",
        "kind": "InfrastructureContract",
        "metadata": {"name": f"suggested-{family}"},
        "spec": {
            "artifactClass": artifact,
            "responsibility": {
                "class": "PROJECT_MANAGED",
                "reason": "REPLACE_WITH_EXPLICIT_DOCUMENTED_RESPONSIBILITY",
            },
            "subjects": {
                "include": {"identities": [subject_identity]},
                "cardinality": {"min": 1, "allowEmpty": False},
            },
            "expect": [{
                "id": family,
                "property": {
                    "namespace": "iac_guard_v",
                    "id": property_id,
                    "version": definition.property_version,
                },
                "parameters": parameters,
            }],
        },
    }
    header = (
        "# Suggested contract template. It does not assert project-authored intent.\n"
        "# Replace every placeholder and review provenance before verification.\n"
    )
    return (header + yaml.safe_dump(payload, sort_keys=False)).encode("utf-8")


def initialize_contract(family: str, output: Path) -> dict:
    if not isinstance(output, Path):
        raise DomainError("contract template output must be pathlib.Path")
    raw = contract_template(family)
    write_new_regular_file(output, raw)
    return {
        "schema_version": "contract-init-receipt-v1",
        "family": family,
        "output": output.name,
        "provenance": "SUGGESTED_CONTRACT",
        "bytes": len(raw),
    }


def support_matrix() -> dict:
    """Return tested capability statements without conflating partial support."""
    return {
        "schema_version": SUPPORT_MATRIX_VERSION,
        "native_registry_identity": native_registry_identity(),
        "surfaces": [
            {"name": "Kubernetes manifests", "materialization": "DIRECT", "native": "BOUNDED", "scanner": "OPTIONAL", "boundary": "no live cluster/runtime"},
            {"name": "Helm", "materialization": "DETERMINISTIC_BOUNDED", "native": "KUBERNETES_AFTER_RENDER", "scanner": "OPTIONAL", "boundary": "no lookup or remote dependencies"},
            {"name": "Kustomize", "materialization": "DETERMINISTIC_BOUNDED", "native": "KUBERNETES_AFTER_RENDER", "scanner": "OPTIONAL", "boundary": "reviewed transformer subset"},
            {"name": "Terraform", "materialization": "SOURCE_LOCAL_TF_ONLY", "native": "REFERENCE_V1", "scanner": "CHECKOV_REVIEWED_PATHS", "boundary": "no plan/provider/remote modules"},
            {"name": "OpenTofu", "materialization": "PROTECTED_FILE_SET_V1", "native": "REFERENCE_V1", "scanner": "NOT_REQUIRED", "boundary": "local static subset; remote modules fail closed"},
            {"name": "Intent contracts", "materialization": "V1ALPHA1", "native": "COMPILED_EXISTING_PROPERTIES", "scanner": "NOT_REQUIRED", "boundary": "explicit intent only"},
            {"name": "Checkov", "materialization": "ADAPTER", "native": "NO", "scanner": "AUTHORITATIVE_REVIEWED_PATHS", "boundary": "3.3.0 locked identity"},
            {"name": "KICS", "materialization": "ADAPTER", "native": "NO", "scanner": "ADVISORY", "boundary": "zero findings is not target PASS"},
            {"name": "Trivy", "materialization": "ADAPTER", "native": "NO", "scanner": "ADVISORY", "boundary": "no target PASS without exact binding"},
        ],
    }


def scanner_diagnostics(checkov_evidence: dict) -> dict:
    """Return the reviewed adapter capabilities without fabricating local identity.

    KICS and Trivy use separately locked container inputs.  A general ``doctor`` run
    cannot infer those locks from a binary on ``PATH``, so their local readiness stays
    explicitly unconfigured until an actual protected request supplies them.
    """
    if type(checkov_evidence) is not dict:
        raise DomainError("scanner diagnostics require exact Checkov evidence")
    scanners = []
    for declared in _SCANNER_CAPABILITY_DECLARATIONS:
        item = dict(declared)
        if item["name"] == "checkov":
            ready = checkov_evidence.get("status") == "PASS"
            item.update({
                "configured_status": "READY" if ready else "NOT_READY",
                "identity_available": ready,
                "policy_bundle_identity": (
                    checkov_evidence.get("policy_inventory_digest", "") if ready else ""
                ),
                "offline_ready": ready,
                "blocking_reason": (
                    "NONE" if ready else checkov_evidence.get(
                        "reason_code", "CHECKOV_IDENTITY_NOT_AVAILABLE"
                    )
                ),
                "remediation": (
                    "none" if ready else checkov_evidence.get(
                        "remediation", "Install the reviewed Checkov environment."
                    )
                ),
            })
        else:
            item.update({
                "configured_status": "NOT_CONFIGURED",
                "identity_available": False,
                "policy_bundle_identity": "",
                "offline_ready": False,
                "blocking_reason": "PROTECTED_SCANNER_LOCK_NOT_SUPPLIED",
                "remediation": (
                    "Supply the separately reviewed locked container and policy/check "
                    "bundle through a protected scanner request."
                ),
            })
        scanners.append(item)
    return {
        "schema_version": SCANNER_DIAGNOSTICS_VERSION,
        "scanners": scanners,
        "voting": False,
    }


def support_matrix_json() -> str:
    return json.dumps(support_matrix(), sort_keys=True, separators=(",", ":")) + "\n"


def support_matrix_markdown() -> str:
    payload = support_matrix()
    lines = [
        "# Tested support matrix",
        "",
        "This matrix is generated from versioned product capability metadata. A bounded",
        "or advisory entry is not a claim of complete framework support.",
        "",
        f"Native registry: `{payload['native_registry_identity']}`",
        "",
        "| Surface | Protected input/materialization | Native semantics | Scanner authority | Major fail-closed boundary |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines.extend(
        f"| {item['name']} | `{item['materialization']}` | `{item['native']}` | "
        f"`{item['scanner']}` | {item['boundary']} |"
        for item in payload["surfaces"]
    )
    lines.extend([
        "",
        "Use `iac-guard support --format json` for the machine-readable form.",
        "",
    ])
    return "\n".join(lines)


__all__ = [
    "SCANNER_DIAGNOSTICS_VERSION", "SUPPORT_MATRIX_VERSION", "contract_template", "describe_property",
    "initialize_contract", "property_catalog", "support_matrix", "support_matrix_json",
    "support_matrix_markdown", "scanner_diagnostics",
]
