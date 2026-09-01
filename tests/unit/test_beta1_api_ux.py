from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from iac_guard_v import __version__
from iac_guard_v.beta_support import (
    contract_template, describe_property, initialize_contract, property_catalog,
    scanner_diagnostics, support_matrix, support_matrix_json, support_matrix_markdown,
)
from iac_guard_v.beta_api import public_api_snapshot
import iac_guard_v.contracts as contract_api
import iac_guard_v.native_properties as native_api
import iac_guard_v.cli as CLI
from iac_guard_v.cli import main
from iac_guard_v.contracts.parser import lint_contract
from iac_guard_v.models import DomainError
from iac_guard_v.native_properties.compatibility import (
    A10_NATIVE_REGISTRY_IDENTITY, validate_a10_definition_snapshot,
)
from iac_guard_v.native_properties.registry import NATIVE_PROPERTY_REGISTRY


_A10_SEMANTIC_DIGESTS = {
    "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1": "a7b9ab0b8188aa71871824bb09552322eaac98f16f37609277b14ab341f1d156",
    "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1": "cf068711d0f9552fbc7a9f067ba6cfb9e1d5c87889e9c6766bb829faf8b4939a",
    "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1": "a62fbbc35fc498874878a0d138d0e6d629d7a5bc3c4b468bb15e47e0af737964",
    "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1": "6699a4faa7086641a758ddf60b4fc017a46e98a6635ff478bbb72f87c855b34a",
    "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1": "9cd6ee4578c539bb941c0fbc43e9301bac8bd07d416289621e045582661e49f5",
    "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1": "b4ba4c6550c06dde10b10c278c025743052723a0b5e86539b3937ce4c83ad8d8",
    "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1": "4e53141f76375bbab9574f0cea1b524df29b86bcf81cdda7f8803a1ebed0bed6",
    "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1": "5b1c759b38209dd56c61adcae05716083900673ebdf74b8078976ce721566c30",
    "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1": "40949cd68e38f918a5e099281126e8b4d2963e6557aa3348b00d7dd5d69030a5",
    "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1": "875e9746f582485a293adc9759aa82d86375b2eecfa14dcb59953705012af199",
    "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1": "1d548554946507b9a6f5ec5fbda1f39af2fdc5416214ad6e0db8f6233e88d2d5",
    "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1": "db649adfef73966e8855e5c1a4864f0712766a9e8e60b049957d442285241830",
    "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1": "29f09ed08beef6b3bc60ab962a81175fc9c3fc7af53ba4ec00f320321c831fc5",
    "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1": "4cde18d0c774991fe5d1e92ed0adf5610991293123a6735823a2a84769e9f312",
    "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1": "3b145113c8629887b75c0174cffb6838b4ca01c5c1d09fb21b6b98293649e96e",
    "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1": "e838afb87d9907819d9c47db647eaf2df436fea9e7bfe3a6670219f8e618375e",
    "IACGV_TF_REFERENCE_RESOLVES_V1": "3f37230410f859ef57267f956f2c7363fc17f7c67243ada502e6aafb0fa68cfb",
}


def test_beta_version_and_registry_snapshot() -> None:
    assert __version__ == "0.1.0b1"
    catalog = property_catalog()
    assert catalog["registry_identity"]
    assert len(catalog["properties"]) == 18
    assert {item["property_id"] for item in catalog["properties"]} == set(
        NATIVE_PROPERTY_REGISTRY
    )
    assert "IACGV_TF_REFERENCE_RESOLVES_V2" not in NATIVE_PROPERTY_REGISTRY
    assert {
        key: NATIVE_PROPERTY_REGISTRY[key].semantic_definition_digest
        for key in _A10_SEMANTIC_DIGESTS
    } == _A10_SEMANTIC_DIGESTS


def test_declared_public_python_exports_and_wire_versions() -> None:
    snapshot = public_api_snapshot()
    assert snapshot["contract_api_version"] == "iac-guard-v.io/v1alpha1"
    assert snapshot["contract_report_schema"] == "infrastructure-contract-report-v1alpha1"
    assert snapshot["snapshot_digest"]
    assert set(native_api.__all__) == set(
        snapshot["python_exports"]["iac_guard_v.native_properties"]
    )
    assert set(contract_api.__all__) == set(
        snapshot["python_exports"]["iac_guard_v.contracts"]
    )


def test_cli_command_inventory_matches_public_snapshot() -> None:
    parser = CLI._parser()
    top = next(
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    actual = {}
    for name, subparser in sorted(top.choices.items()):
        nested = [
            action for action in subparser._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        actual[name] = sorted(nested[0].choices) if nested else []
    assert actual == public_api_snapshot()["cli_commands"]


def test_property_discovery_is_closed_and_scanner_independent(capsys) -> None:
    property_id = "IACGV_OPENTOFU_REFERENCE_RESOLVES_V1"
    assert main(["properties", "list", "--format", "json"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert any(item["property_id"] == property_id for item in catalog["properties"])
    assert main(["properties", "describe", property_id, "--format", "json"]) == 0
    described = json.loads(capsys.readouterr().out)
    assert described == describe_property(property_id)
    assert described["support"] == {
        "authoritative_native_verdict": True,
        "scanner_required": False,
        "live_system_claim": False,
        "project_intent_claim": False,
        "uncertainty": "fail_closed",
    }
    assert main(["properties", "describe", "IACGV_UNKNOWN_V1"]) == 2
    assert json.loads(capsys.readouterr().err)["reason_code"] == "INVALID_REQUEST"


@pytest.mark.parametrize(
    "family",
    (
        "rbac-closure", "servicemonitor-service", "network-service-path",
        "workload-policy-closure", "migration-database-path",
        "terraform-reference", "opentofu-reference",
    ),
)
def test_contract_init_templates_lint_and_refuse_overwrite(
    tmp_path: Path, capsys, family: str,
) -> None:
    output = tmp_path / f"{family}.yaml"
    assert main([
        "contract", "init", "--family", family, "--output", str(output),
        "--format", "json",
    ]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["provenance"] == "SUGGESTED_CONTRACT"
    raw = output.read_bytes()
    assert b"Suggested contract template" in raw
    assert b"PROJECT_AUTHORED" not in raw
    lint_contract(output)
    assert main([
        "contract", "init", "--family", family, "--output", str(output),
    ]) == 20
    assert output.read_bytes() == raw
    assert json.loads(capsys.readouterr().err)["reason_code"] == "INVALID_CONTRACT"


def test_native_doctor_and_support_matrix_are_scanner_optional(capsys, monkeypatch) -> None:
    monkeypatch.setattr("iac_guard_v.cli.shutil.which", lambda _name: None)
    result = main(["doctor", "--mode", "native", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["checkov"]["status"] == "NOT_REQUIRED"
    scanners = {item["name"]: item for item in payload["scanner_adapters"]["scanners"]}
    assert payload["scanner_adapters"]["voting"] is False
    assert scanners["checkov"]["configured_status"] == "NOT_READY"
    assert scanners["checkov"]["authority"] == "AUTHORITATIVE_REVIEWED_PATHS"
    assert scanners["kics"]["authority"] == "ADVISORY"
    assert scanners["kics"]["affirmative_target_pass"] is False
    assert scanners["trivy"]["authority"] == "ADVISORY"
    assert scanners["trivy"]["reviewed_checks_version"] == "2.2.0"
    assert all(not item["identity_available"] for item in scanners.values())
    assert result in {0, 3}  # package integrity, never scanner availability, decides readiness
    matrix = support_matrix()
    by_name = {item["name"]: item for item in matrix["surfaces"]}
    assert by_name["Checkov"]["scanner"] == "AUTHORITATIVE_REVIEWED_PATHS"
    assert by_name["KICS"]["scanner"] == "ADVISORY"
    assert by_name["Trivy"]["scanner"] == "ADVISORY"
    assert by_name["OpenTofu"]["native"] == "REFERENCE_V1"


def test_published_support_matrix_is_generated_from_product_metadata() -> None:
    path = Path(__file__).parents[2] / "docs" / "SUPPORT_MATRIX.md"
    assert path.read_text(encoding="utf-8") == support_matrix_markdown()


def test_frozen_a10_definition_snapshot_is_distinct_from_current_registry() -> None:
    # The compatibility reader recognizes an exact historical registry identity, but
    # it never silently substitutes the current definition or implementation.
    assert A10_NATIVE_REGISTRY_IDENTITY != property_catalog()["registry_identity"]
    current = NATIVE_PROPERTY_REGISTRY[
        "IACGV_TF_REFERENCE_RESOLVES_V1"
    ].canonical_dict()
    with pytest.raises(DomainError, match="frozen a10 registry"):
        validate_a10_definition_snapshot(current)


def test_beta_support_rejects_invalid_template_and_diagnostics_inputs(
    tmp_path: Path,
) -> None:
    with pytest.raises(DomainError, match="template family is unsupported"):
        contract_template("unknown-family")
    with pytest.raises(DomainError, match="must be pathlib.Path"):
        initialize_contract("rbac-closure", str(tmp_path / "contract.yaml"))  # type: ignore[arg-type]
    with pytest.raises(DomainError, match="exact Checkov evidence"):
        scanner_diagnostics([])  # type: ignore[arg-type]


def test_scanner_diagnostics_ready_identity_and_json_matrix_are_deterministic() -> None:
    evidence = {
        "status": "PASS",
        "policy_inventory_digest": "a" * 64,
    }
    first = scanner_diagnostics(evidence)
    second = scanner_diagnostics(dict(evidence))
    assert first == second
    checkov = next(item for item in first["scanners"] if item["name"] == "checkov")
    assert checkov["configured_status"] == "READY"
    assert checkov["identity_available"] is True
    assert checkov["policy_bundle_identity"] == "a" * 64
    assert checkov["offline_ready"] is True
    assert checkov["blocking_reason"] == "NONE"
    assert checkov["remediation"] == "none"
    assert json.loads(support_matrix_json()) == support_matrix()
