"""Declared Beta1 public compatibility surface."""
from __future__ import annotations

from .native_properties.model import canonical_digest


PUBLIC_API_SNAPSHOT_VERSION = "beta-public-api-v1"


def public_api_snapshot() -> dict:
    """Return the reviewed surface whose incompatible changes need versioning."""
    payload = {
        "schema_version": PUBLIC_API_SNAPSHOT_VERSION,
        "cli_commands": {
            "accept": [],
            "contract": ["init", "lint", "plan"],
            "demo": [],
            "differential": [],
            "doctor": [],
            "explain": [],
            "helm-accept": [],
            "helm-verify": [],
            "init": [],
            "kustomize-accept": [],
            "lock": [],
            "pr": [],
            "properties": ["describe", "list"],
            "scan": [],
            "support": [],
            "verify": [],
        },
        "contract_exit_codes": {
            "SATISFIED": 0, "VIOLATED": 10, "NOT_EVALUATED": 11,
            "UNSUPPORTED": 12, "INVALID": 20, "ERROR": 21,
        },
        "native_results": [
            "SATISFIED", "VIOLATED", "NOT_EVALUATED", "UNSUPPORTED", "ERROR",
        ],
        "contract_api_version": "iac-guard-v.io/v1alpha1",
        "contract_report_schema": "infrastructure-contract-report-v1alpha1",
        "native_request_schema": "native-property-request-v1",
        "native_report_schema": "native-property-report-v1",
        "python_exports": {
            "iac_guard_v": ["__version__", "api", "contracts", "native_properties"],
            "iac_guard_v.native_properties": [
                "NATIVE_PROPERTY_REGISTRY", "NativeArtifactClass",
                "NativePropertyCapabilities", "NativePropertyDefinition",
                "NativePropertyImplementationIdentity", "NativePropertyObservation",
                "NativePropertyRequest", "NativePropertyResult", "NativePropertyWitness",
                "NativeSemanticVersionBinding", "ProtectedNativeUniverse",
                "describe_native_property", "evaluate_native_request",
                "evaluate_native_requests", "list_native_properties",
                "load_protected_native_universe", "native_registry_identity",
            ],
            "iac_guard_v.contracts": [
                "ContractExecutionInput", "ContractReportV1", "ContractRun",
                "PreparedContract", "evaluate_contract", "lint_contract",
                "load_contract", "plan_contract", "prepare_contract_plan",
                "prepare_contract_run", "validate_contract_report_payload",
            ],
        },
    }
    return payload | {"snapshot_digest": canonical_digest(payload)}


__all__ = ["PUBLIC_API_SNAPSHOT_VERSION", "public_api_snapshot"]
