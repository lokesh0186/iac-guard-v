from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from iac_guard_v.contracts import ContractExecutionInput, prepare_contract_run
from iac_guard_v.contracts.model import ContractProvenance
from iac_guard_v.native_properties import evaluate_native_request

from test_native_kubernetes_a9 import (
    API, FIXTURE, PM, ROLE_BINDING, SERVICE, SM,
)
from test_native_terraform_a9 import TF


def _write_contract(
    project: Path, *, artifact: str, subject: str, property_id: str,
    parameters: dict | None = None, responsibility: str = "PROJECT_MANAGED",
) -> Path:
    directory = project / ".iac-guard-v"
    directory.mkdir(exist_ok=True)
    payload = {
        "apiVersion": "iac-guard-v.io/v1alpha1",
        "kind": "InfrastructureContract",
        "metadata": {"name": "differential"},
        "spec": {
            "artifactClass": artifact,
            "subjects": {
                "include": {"identities": [subject]},
                "cardinality": {"min": 1, "max": 1},
            },
            "responsibility": {"class": responsibility},
            "expect": [{
                "id": "relationship",
                "property": {
                    "namespace": "iac_guard_v", "id": property_id, "version": "1",
                },
                "parameters": parameters or {},
            }],
        },
    }
    path = directory / "contracts.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("property_id", "subject", "parameters"),
    [
        ("IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", API, {}),
        ("IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1", API, {}),
        ("IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1", API, {}),
        ("IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1", SERVICE, {"expectation": "EXACT_ONE", "expected_workloads": [API]}),
        ("IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1", SERVICE, {"service_port": {"name": "metrics", "protocol": "TCP"}, "expected_port": 6080}),
        ("IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1", API, {"source": {"type": "SYMBOLIC", "namespace": "monitoring", "namespace_labels": {"team": "observability"}, "pod_labels": {"app": "prometheus"}}, "port": 6080, "protocol": "TCP"}),
        ("IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1", SM, {}),
        ("IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1", PM, {}),
        ("IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1", SM, {"source": {"type": "SYMBOLIC", "namespace": "monitoring", "namespace_labels": {"team": "observability"}, "pod_labels": {"app": "prometheus"}}}),
        ("IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", ROLE_BINDING, {"complete_expected_domain": True}),
        ("IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", ROLE_BINDING, {"complete_expected_domain": True}),
        ("IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", ROLE_BINDING, {}),
    ],
)
def test_contract_compilation_is_native_differential(
    tmp_path: Path, property_id: str, subject: str, parameters: dict,
) -> None:
    project = tmp_path / "project"
    rendered = project / "rendered"
    rendered.mkdir(parents=True)
    (rendered / "all.yaml").write_text(FIXTURE, encoding="utf-8")
    contract = _write_contract(
        project, artifact="kubernetes_rendered", subject=subject,
        property_id=property_id, parameters=parameters,
    )
    with prepare_contract_run(ContractExecutionInput(
        contract, project, protected_root=rendered,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
        source_commit="e" * 40,
    )) as run:
        compiled = run.plan.clauses[0].requests[0]
        direct = evaluate_native_request(run.universe, compiled)
        observed = run.report.clauses[0].native_observations[0]
        assert observed.canonical_dict() == direct.canonical_dict()
        assert run.contract.source.provenance.value == "RESEARCH_HYPOTHESIS"


def test_component_closure_compiles_resolved_membership_and_exclusion(tmp_path: Path) -> None:
    project = tmp_path / "project"
    rendered = project / "rendered"
    rendered.mkdir(parents=True)
    (rendered / "all.yaml").write_text(FIXTURE, encoding="utf-8")
    contract = _write_contract(
        project, artifact="kubernetes_rendered", subject=API,
        property_id="IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1",
        parameters={"policy_identities": [
            "networking.k8s.io/v1/NetworkPolicy/apps/default-deny",
        ]},
    )
    with prepare_contract_run(ContractExecutionInput(
        contract, project, protected_root=rendered,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
        source_commit="f" * 40,
    )) as run:
        request = run.plan.clauses[0].requests[0]
        assert request.parameters["workload_identities"] == (API,)
        assert request.parameters["membership_proof_digest"] == run.plan.subjects.resolution_digest
        assert run.report.result.value == "SATISFIED"


def test_terraform_contract_preserves_exact_source_local_reference(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source = project / "source"
    source.mkdir(parents=True)
    (source / "main.tf").write_text(TF, encoding="utf-8")
    parameters = {
        "attribute_path": ["access_logs", 0, "bucket"],
        "expected_target": "aws_s3_bucket.logs",
        "complete_expected_domain": True,
        "reference_contract_digest": "f" * 64,
    }
    contract = _write_contract(
        project, artifact="terraform_source", subject="aws_lb.app",
        property_id="IACGV_TF_REFERENCE_RESOLVES_V1", parameters=parameters,
    )
    with prepare_contract_run(ContractExecutionInput(
        contract, project, protected_root=source,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
        source_commit="1" * 40,
    )) as run:
        native = run.report.clauses[0].native_observations[0]
        assert native.result.value == "SATISFIED"
        assert native.witness.contents["reference_span"]["start_line"] == 8
        assert json.loads(run.report.canonical_json())["result"] == "SATISFIED"
