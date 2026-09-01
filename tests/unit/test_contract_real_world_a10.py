from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from iac_guard_v.contracts import ContractExecutionInput, prepare_contract_run
from iac_guard_v.contracts.model import ContractProvenance
from iac_guard_v.native_properties import evaluate_native_request


def _write_contract(project: Path, name: str, spec: dict) -> Path:
    directory = project / ".iac-guard-v"
    directory.mkdir(parents=True)
    path = directory / "contracts.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "iac-guard-v.io/v1alpha1",
                "kind": "InfrastructureContract",
                "metadata": {"name": name},
                "spec": spec,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def _selection(identities: list[str], *, minimum: int, maximum: int) -> dict:
    return {
        "include": {"identities": identities},
        "cardinality": {"min": minimum, "max": maximum},
    }


def test_dgraph_public_bytes_compile_to_resolution_and_path_witness(tmp_path: Path) -> None:
    project = tmp_path / "project"
    rendered = project / "rendered"
    shutil.copytree(
        Path("examples/public-reproductions/dgraph-charts-146/rendered"), rendered
    )
    monitor = "monitoring.coreos.com/v1/ServiceMonitor/dgraph-system/adjudicate-dgraph"
    contract = _write_contract(
        project,
        "dgraph-monitoring-path-research",
        {
            "artifactClass": "kubernetes_rendered",
            "subjects": _selection([monitor], minimum=1, maximum=1),
            "responsibility": {"class": "PROJECT_MANAGED"},
            "expect": [
                {
                    "id": "monitor-resolves-zero-port",
                    "property": {
                        "namespace": "iac_guard_v",
                        "id": "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1",
                        "version": "1",
                    },
                    "parameters": {"endpoint_index": 1},
                },
                {
                    "id": "monitoring-ingress-is-allowed",
                    "property": {
                        "namespace": "iac_guard_v",
                        "id": "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1",
                        "version": "1",
                    },
                    "parameters": {
                        "endpoint_index": 1,
                        "source": {
                            "type": "SYMBOLIC",
                            "namespace": "monitoring",
                            "namespace_labels": {
                                "kubernetes.io/metadata.name": "monitoring"
                            },
                            "pod_labels": {"app": "prometheus"},
                        },
                    },
                },
            ],
        },
    )
    with prepare_contract_run(
        ContractExecutionInput(
            contract,
            project,
            protected_root=rendered,
            requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
            source_commit="fe013a6d24ef21b6812cd2f55f28246f444ef563",
            default_namespace="dgraph-system",
        )
    ) as run:
        assert run.report.result.value == "VIOLATED"
        assert [item.result.value for item in run.report.clauses] == [
            "SATISFIED",
            "VIOLATED",
        ]
        resolved = run.report.clauses[0].native_observations[0]
        assert resolved.witness.contents["service_port_resolutions"][0][
            "resolved_port_set"
        ] == (6080,)
        path = run.report.clauses[1].native_observations[0]
        assert path.reason_code == "MONITORING_INGRESS_PATH_NOT_ESTABLISHED"
        assert path.witness.contents["manifest_semantics_only"] is True
        for planned, observed in zip(run.plan.clauses, run.report.clauses, strict=True):
            direct = evaluate_native_request(run.universe, planned.requests[0])
            assert direct.canonical_dict() == observed.native_observations[0].canonical_dict()


def _quay_contract(project: Path, *, include_unsupported: bool) -> Path:
    supported = [
        "apps/v1/Deployment/quay-a8-validation/a8-clair-postgres",
        "apps/v1/Deployment/quay-a8-validation/a8-quay-app",
        "apps/v1/Deployment/quay-a8-validation/a8-quay-redis",
    ]
    unsupported = [
        "apps/v1/Deployment/quay-a8-validation/a8-clair-postgres-old",
        "batch/v1/Job/quay-a8-validation/a8-clair-postgres-upgrade",
    ]
    policies = [
        "networking.k8s.io/v1/NetworkPolicy/quay-a8-validation/a8-clair-postgres-allow-only-from-clair",
        "networking.k8s.io/v1/NetworkPolicy/quay-a8-validation/a8-quay-app-allow-all",
        "networking.k8s.io/v1/NetworkPolicy/quay-a8-validation/a8-redis-allow-only-from-quay-pods",
    ]
    selected = supported + unsupported if include_unsupported else supported
    return _write_contract(
        project,
        "quay-expanded-scope" if include_unsupported else "quay-supported-scope",
        {
            "artifactClass": "kubernetes_rendered",
            "subjects": _selection(selected, minimum=len(selected), maximum=len(selected)),
            "responsibility": {"class": "PROJECT_MANAGED"},
            "expect": [
                {
                    "id": "workload-policy-closure",
                    "property": {
                        "namespace": "iac_guard_v",
                        "id": "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1",
                        "version": "1",
                    },
                    "parameters": {"policy_identities": policies},
                }
            ],
        },
    )


def test_quay_public_bytes_separate_mechanics_from_intent_scope(tmp_path: Path) -> None:
    source = Path("examples/public-reproductions/quay-operator-1322/rendered")
    outcomes = []
    for include_unsupported in (False, True):
        project = tmp_path / ("reviewer" if include_unsupported else "project")
        rendered = project / "rendered"
        shutil.copytree(source, rendered)
        contract = _quay_contract(project, include_unsupported=include_unsupported)
        with prepare_contract_run(
            ContractExecutionInput(
                contract,
                project,
                protected_root=rendered,
                requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
                source_commit="1340fe9cdae651a0e36fc27a4322b2a2f5872223",
                default_namespace="quay-a8-validation",
            )
        ) as run:
            observation = run.report.clauses[0].native_observations[0]
            direct = evaluate_native_request(run.universe, run.plan.clauses[0].requests[0])
            assert direct.canonical_dict() == observation.canonical_dict()
            outcomes.append(
                (run.report.result.value, observation.witness.contents["uncovered_workloads"])
            )
    assert outcomes[0] == ("SATISFIED", ())
    assert outcomes[1][0] == "VIOLATED"
    assert outcomes[1][1] == (
        "apps/v1/Deployment/quay-a8-validation/a8-clair-postgres-old",
        "batch/v1/Job/quay-a8-validation/a8-clair-postgres-upgrade",
    )
