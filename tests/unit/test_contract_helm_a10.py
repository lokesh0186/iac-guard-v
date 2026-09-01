from __future__ import annotations

from pathlib import Path

import pytest

from iac_guard_v.contracts import ContractExecutionInput, prepare_contract_run
from iac_guard_v.contracts.activation import requested_activation_paths
from iac_guard_v.contracts.helm_values import bind_helm_effective_values
from iac_guard_v.contracts.model import ActivationStatus, ContractProvenance
from iac_guard_v.contracts.parser import load_contract
from iac_guard_v.helm import HelmRenderSpec, materialize_helm
from iac_guard_v.models import DomainError

from test_contract_core_a10 import MONITOR
from test_helm_materialization_a4 import _executable


def _helm_project(tmp_path: Path, *, with_service: bool, defaults: str, overrides=()) -> tuple[Path, HelmRenderSpec]:
    project = tmp_path / "project"
    chart = project / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "crds").mkdir()
    (project / ".iac-guard-v").mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: falco\nversion: 9.1.0\n", encoding="utf-8")
    (chart / "values.yaml").write_text(defaults, encoding="utf-8")
    (chart / "templates/monitor.yaml").write_text("{{ .Values.serviceMonitor.create }}\n", encoding="utf-8")
    crd = """apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: servicemonitors.monitoring.coreos.com}
spec:
  group: monitoring.coreos.com
  scope: Namespaced
  names: {plural: servicemonitors, singular: servicemonitor, kind: ServiceMonitor}
  versions: [{name: v1, served: true, storage: true, schema: {openAPIV3Schema: {type: object}}}]
"""
    (chart / "crds/monitoring.yaml").write_text(crd, encoding="utf-8")
    service = """
---
# Source: falco/templates/monitor.yaml
apiVersion: v1
kind: Service
metadata: {name: falco-metrics, namespace: falco, labels: {app: falco-metrics}}
spec: {selector: {app: falco}, ports: [{name: metrics, port: 8765, targetPort: metrics}]}
""" if with_service else ""
    rendered = f"""# Source: falco/templates/monitor.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata: {{name: falco, namespace: falco}}
spec:
  template:
    metadata: {{labels: {{app: falco}}}}
    spec: {{containers: [{{name: falco, image: falco, ports: [{{name: metrics, containerPort: 8765}}]}}]}}
{service}
---
# Source: falco/templates/monitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {{name: falco, namespace: falco}}
spec: {{selector: {{matchLabels: {{app: falco-metrics}}}}, endpoints: [{{port: metrics}}]}}
"""
    (chart / "rendered.fixture").write_text(rendered, encoding="utf-8")
    contract = project / ".iac-guard-v/contracts.yaml"
    contract.write_text(f"""apiVersion: iac-guard-v.io/v1alpha1
kind: InfrastructureContract
metadata: {{name: falco-monitoring}}
spec:
  artifactClass: kubernetes_rendered
  when:
    value: {{path: serviceMonitor.create, equals: true}}
  subjects:
    include: {{identities: [{MONITOR}]}}
  responsibility: {{class: PROJECT_MANAGED}}
  expect:
    - id: monitor
      property:
        namespace: iac_guard_v
        id: IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1
        version: "1"
      relationCardinality: {{targetMin: 1}}
""", encoding="utf-8")
    executable = _executable(project)
    return project, HelmRenderSpec(
        chart, executable, "falco", "falco", "1.31.0",
        set_values=tuple(overrides), protected_repository_root=project,
    )


@pytest.mark.parametrize(
    ("monitor", "service", "expected"),
    [(False, False, "NOT_EVALUATED"), (True, False, "VIOLATED"), (True, True, "SATISFIED")],
)
def test_falco_contract_matrix_activation_and_relationship(
    tmp_path: Path, monitor: bool, service: bool, expected: str,
) -> None:
    defaults = f"serviceMonitor:\n  create: {str(monitor).lower()}\nmetrics:\n  enabled: {str(service).lower()}\n"
    project, spec = _helm_project(tmp_path, with_service=service, defaults=defaults)
    with prepare_contract_run(ContractExecutionInput(
        project / ".iac-guard-v/contracts.yaml", project,
        helm_spec=spec, source_commit="5" * 40, default_namespace="falco",
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
    )) as run:
        assert run.report.result.value == expected
        if monitor:
            assert run.plan.activation.status is ActivationStatus.ACTIVE
        else:
            assert run.plan.activation.status is ActivationStatus.INACTIVE_CONDITION_FALSE


def test_helm_effective_value_origin_binds_default_and_override(tmp_path: Path) -> None:
    project, spec = _helm_project(
        tmp_path, with_service=True,
        defaults="serviceMonitor: {create: false}\nmetrics: {enabled: true}\n",
        overrides=(("serviceMonitor.create", "true"),),
    )
    evidence = materialize_helm(spec, tmp_path / "rendered")
    contract = load_contract(
        project / ".iac-guard-v/contracts.yaml", project_root=project,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
        source_commit="6" * 40,
    )
    values = bind_helm_effective_values(
        spec, evidence, requested_activation_paths(contract.when)
    )
    fact = values.find(".", "serviceMonitor.create")
    assert fact is not None
    assert fact.value is True
    assert fact.origin == "SET"
    assert fact.origin_evidence["key"] == "serviceMonitor.create"
    assert values.materialization_identity == evidence.materialization_identity


def test_helm_activation_rejects_foreign_materialization(tmp_path: Path) -> None:
    project, spec = _helm_project(
        tmp_path, with_service=True,
        defaults="serviceMonitor: {create: true}\nmetrics: {enabled: true}\n",
    )
    evidence = materialize_helm(spec, tmp_path / "rendered")
    (spec.chart_root / "values.yaml").write_text(
        "serviceMonitor: {create: false}\nmetrics: {enabled: true}\n", encoding="utf-8"
    )
    with pytest.raises(DomainError, match="differs|disagree"):
        bind_helm_effective_values(spec, evidence, ((".", "serviceMonitor.create"),))


def test_falco_explicit_metrics_service_disable_binds_all_effective_values(tmp_path: Path) -> None:
    project, spec = _helm_project(
        tmp_path, with_service=False,
        defaults=(
            "serviceMonitor: {create: true}\n"
            "metrics:\n  enabled: true\n  service: {create: true}\n"
        ),
        overrides=(("metrics.service.create", "false"),),
    )
    materialization = materialize_helm(spec, tmp_path / "rendered-values")
    values = bind_helm_effective_values(spec, materialization, (
        (".", "serviceMonitor.create"),
        (".", "metrics.enabled"),
        (".", "metrics.service.create"),
    ))
    observed = {item.path: item for item in values.facts}
    assert observed["serviceMonitor.create"].value is True
    assert observed["serviceMonitor.create"].origin == "DEFAULT"
    assert observed["metrics.enabled"].value is True
    assert observed["metrics.service.create"].value is False
    assert observed["metrics.service.create"].origin == "SET"
    with prepare_contract_run(ContractExecutionInput(
        project / ".iac-guard-v/contracts.yaml", project,
        helm_spec=spec, source_commit="7" * 40, default_namespace="falco",
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
    )) as run:
        assert run.report.result.value == "VIOLATED"


def test_falco_custom_selector_with_matching_protected_service(tmp_path: Path) -> None:
    project, spec = _helm_project(
        tmp_path, with_service=True,
        defaults="serviceMonitor: {create: true}\nmetrics: {enabled: true}\n",
    )
    fixture = spec.chart_root / "rendered.fixture"
    fixture.write_text(
        fixture.read_text(encoding="utf-8").replace("app: falco-metrics", "app: custom-metrics"),
        encoding="utf-8",
    )
    with prepare_contract_run(ContractExecutionInput(
        project / ".iac-guard-v/contracts.yaml", project,
        helm_spec=spec, source_commit="8" * 40, default_namespace="falco",
        requested_provenance=ContractProvenance.USER_AUTHORED,
    )) as run:
        assert run.report.result.value == "SATISFIED"
        witness = run.report.clauses[0].native_observations[0].witness.contents
        assert len(witness["matched_services"]) == 1


def test_falco_custom_external_relationship_is_explicitly_out_of_contract(tmp_path: Path) -> None:
    project, spec = _helm_project(
        tmp_path, with_service=False,
        defaults="serviceMonitor: {create: true}\nmetrics: {enabled: false}\n",
    )
    fixture = spec.chart_root / "rendered.fixture"
    fixture.write_text(
        fixture.read_text(encoding="utf-8").replace("app: falco-metrics", "app: external-metrics"),
        encoding="utf-8",
    )
    contract = project / ".iac-guard-v/contracts.yaml"
    contract.write_text(
        contract.read_text(encoding="utf-8").replace(
            "responsibility: {class: PROJECT_MANAGED}",
            "responsibility: {class: OUT_OF_CONTRACT, reason: External Service is user managed.}",
        ),
        encoding="utf-8",
    )
    with prepare_contract_run(ContractExecutionInput(
        contract, project, helm_spec=spec, source_commit="9" * 40,
        default_namespace="falco",
        requested_provenance=ContractProvenance.USER_AUTHORED,
    )) as run:
        assert run.report.result.value == "NOT_EVALUATED"
        assert run.report.reason_code == "CONTRACT_SCOPE_EXPLICITLY_EXCLUDED"
        assert run.report.clauses[0].native_observations[0].result.value == "VIOLATED"


def test_falco_multiple_services_obeys_explicit_target_maximum(tmp_path: Path) -> None:
    project, spec = _helm_project(
        tmp_path, with_service=True,
        defaults="serviceMonitor: {create: true}\nmetrics: {enabled: true}\n",
    )
    fixture = spec.chart_root / "rendered.fixture"
    fixture.write_text(fixture.read_text(encoding="utf-8") + """
---
# Source: falco/templates/monitor.yaml
apiVersion: v1
kind: Service
metadata: {name: falco-metrics-two, namespace: falco, labels: {app: falco-metrics}}
spec: {selector: {app: falco}, ports: [{name: metrics, port: 8765, targetPort: metrics}]}
""", encoding="utf-8")
    contract = project / ".iac-guard-v/contracts.yaml"
    contract.write_text(
        contract.read_text(encoding="utf-8").replace(
            "relationCardinality: {targetMin: 1}",
            "relationCardinality: {targetMin: 1, targetMax: 1}",
        ),
        encoding="utf-8",
    )
    with prepare_contract_run(ContractExecutionInput(
        contract, project, helm_spec=spec, source_commit="a" * 40,
        default_namespace="falco",
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
    )) as run:
        assert run.report.result.value == "VIOLATED"
        assert run.report.clauses[0].reason_code == "TARGET_CARDINALITY_ABOVE_MAXIMUM"
        assert run.report.clauses[0].target_count == 2


@pytest.mark.parametrize("defaults", (
    "metrics: {enabled: false}\n",
    "serviceMonitor: {create: 'true'}\nmetrics: {enabled: false}\n",
))
def test_falco_missing_or_wrong_typed_activation_is_not_evaluated(
    tmp_path: Path, defaults: str,
) -> None:
    project, spec = _helm_project(tmp_path, with_service=False, defaults=defaults)
    with prepare_contract_run(ContractExecutionInput(
        project / ".iac-guard-v/contracts.yaml", project,
        helm_spec=spec, source_commit="b" * 40, default_namespace="falco",
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
    )) as run:
        assert run.report.result.value == "NOT_EVALUATED"
        assert run.plan.activation.status is ActivationStatus.ACTIVATION_NOT_EVALUATED
