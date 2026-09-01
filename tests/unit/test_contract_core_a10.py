from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from iac_guard_v.contracts import ContractExecutionInput, load_contract, prepare_contract_run
from iac_guard_v.contracts.activation import evaluate_activation, requested_activation_paths
from iac_guard_v.contracts.helm_values import direct_effective_values
from iac_guard_v.contracts.historical import (
    HistoricalReproducibilityReason,
    HistoricalReproducibilityRecord,
)
from iac_guard_v.contracts.model import (
    ActivationStatus,
    ContractProvenance,
    ContractResult,
    contract_implementation_identity,
    contract_schema_identity,
)
from iac_guard_v.contracts.parser import contract_schema
from iac_guard_v.contracts.report import validate_contract_report_payload
from iac_guard_v.models import DomainError
from iac_guard_v.native_properties.model import canonical_digest


MONITOR = "monitoring.coreos.com/v1/ServiceMonitor/falco/falco"


def _project(tmp_path: Path, *, service: bool = True) -> tuple[Path, Path]:
    project = tmp_path / "project"
    rendered = project / "rendered"
    contract_dir = project / ".iac-guard-v"
    rendered.mkdir(parents=True)
    contract_dir.mkdir()
    service_yaml = """
---
apiVersion: v1
kind: Service
metadata: {name: falco-metrics, namespace: falco, labels: {app: falco-metrics}}
spec:
  selector: {app: falco}
  ports: [{name: metrics, port: 8765, targetPort: metrics, protocol: TCP}]
""" if service else ""
    (rendered / "objects.yaml").write_text(f"""apiVersion: apps/v1
kind: DaemonSet
metadata: {{name: falco, namespace: falco}}
spec:
  selector: {{matchLabels: {{app: falco}}}}
  template:
    metadata: {{labels: {{app: falco}}}}
    spec:
      containers:
        - name: falco
          image: falco
          ports: [{{name: metrics, containerPort: 8765, protocol: TCP}}]
{service_yaml}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {{name: falco, namespace: falco}}
spec:
  selector: {{matchLabels: {{app: falco-metrics}}}}
  endpoints: [{{port: metrics}}]
""", encoding="utf-8")
    contract = contract_dir / "contracts.yaml"
    contract.write_text(f"""apiVersion: iac-guard-v.io/v1alpha1
kind: InfrastructureContract
metadata:
  name: falco-monitoring
spec:
  artifactClass: kubernetes_rendered
  when:
    all:
      - value: {{path: serviceMonitor.create, equals: true}}
      - value: {{path: metrics.enabled, equals: true}}
  subjects:
    include:
      identities: [{MONITOR}]
    cardinality: {{min: 1, max: 1}}
  responsibility:
    class: PROJECT_MANAGED
    reason: Built-in monitor and metrics service relationship.
  expect:
    - id: monitor-resolves
      property:
        namespace: iac_guard_v
        id: IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1
        version: "1"
      relationCardinality: {{targetMin: 1}}
""", encoding="utf-8")
    values = project / "activation.yaml"
    values.write_text("serviceMonitor: {create: true}\nmetrics: {enabled: true}\n", encoding="utf-8")
    return project, values


def _run(project: Path, values: Path):
    return prepare_contract_run(ContractExecutionInput(
        contract_path=project / ".iac-guard-v/contracts.yaml",
        project_root=project,
        protected_root=project / "rendered",
        activation_values_path=values,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
        source_commit="a" * 40,
    ))


def test_contract_native_monitoring_differential_satisfied(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    with _run(project, values) as run:
        assert run.plan.activation.status is ActivationStatus.ACTIVE
        assert run.report.result is ContractResult.SATISFIED
        assert run.report.clauses[0].native_observations[0].result.value == "SATISFIED"
        payload = json.loads(run.report.canonical_json())
        validate_contract_report_payload(payload)
        assert payload["clauses"][0]["native_observations"][0]["request"] == run.plan.clauses[0].requests[0].canonical_dict()
        assert payload["contract"]["source"]["provenance"] == "RESEARCH_HYPOTHESIS"
        assert "/Users/" not in run.report.canonical_json()


def test_contract_native_monitoring_violation_and_nonvacuous_target(tmp_path: Path) -> None:
    project, values = _project(tmp_path, service=False)
    with _run(project, values) as run:
        assert run.report.result is ContractResult.VIOLATED
        clause = run.report.clauses[0]
        assert clause.result is ContractResult.VIOLATED
        assert clause.native_observations[0].result.value == "VIOLATED"


@pytest.mark.parametrize(
    "mutation",
    ("service-label", "service-port-name", "monitor-endpoint", "multiple-services"),
)
def test_monitoring_relationship_mutations_never_false_satisfy(
    tmp_path: Path, mutation: str,
) -> None:
    project, values = _project(tmp_path)
    manifests = project / "rendered/objects.yaml"
    text = manifests.read_text(encoding="utf-8")
    if mutation == "service-label":
        text = text.replace("labels: {app: falco-metrics}", "labels: {app: drifted}")
    elif mutation == "service-port-name":
        text = text.replace("name: metrics, port: 8765", "name: stale, port: 8765")
    elif mutation == "monitor-endpoint":
        text = text.replace("endpoints: [{port: metrics}]", "endpoints: [{port: missing}]")
    else:
        duplicate = """
---
apiVersion: v1
kind: Service
metadata: {name: falco-metrics-duplicate, namespace: falco, labels: {app: falco-metrics}}
spec:
  selector: {app: falco}
  ports: [{name: metrics, port: 8765, targetPort: metrics, protocol: TCP}]
"""
        text += duplicate
        contract = project / ".iac-guard-v/contracts.yaml"
        contract.write_text(
            contract.read_text(encoding="utf-8").replace(
                "relationCardinality: {targetMin: 1}",
                "relationCardinality: {targetMin: 1, targetMax: 1}",
            ), encoding="utf-8",
        )
    manifests.write_text(text, encoding="utf-8")
    with _run(project, values) as run:
        assert run.report.result is not ContractResult.SATISFIED


def test_activation_false_missing_type_and_origin_are_distinct(tmp_path: Path) -> None:
    project, _ = _project(tmp_path)
    contract = load_contract(
        project / ".iac-guard-v/contracts.yaml", project_root=project,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
        source_commit="b" * 40,
    )
    paths = requested_activation_paths(contract.when)
    assert paths == ((".", "metrics.enabled"), (".", "serviceMonitor.create"))
    false_values = direct_effective_values(
        {"serviceMonitor": {"create": True}, "metrics": {"enabled": False}},
        input_identity="1" * 64, requested_paths=paths,
    )
    assert evaluate_activation(contract.when, false_values).status is ActivationStatus.INACTIVE_CONDITION_FALSE
    missing = direct_effective_values({}, input_identity="2" * 64, requested_paths=paths)
    assert evaluate_activation(contract.when, missing).status is ActivationStatus.ACTIVATION_NOT_EVALUATED
    wrong_type = direct_effective_values(
        {"serviceMonitor": {"create": "true"}, "metrics": {"enabled": True}},
        input_identity="3" * 64, requested_paths=paths,
    )
    assert evaluate_activation(contract.when, wrong_type).status is ActivationStatus.ACTIVATION_NOT_EVALUATED
    assert evaluate_activation(contract.when, None).reason_code == "ACTIVATION_INPUT_UNAVAILABLE"


def test_subject_zero_match_is_violation_not_vacuous_truth(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    path = project / ".iac-guard-v/contracts.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace(MONITOR, "monitoring.coreos.com/v1/ServiceMonitor/falco/missing"), encoding="utf-8")
    with _run(project, values) as run:
        assert run.plan.subjects.result == "NOT_EVALUATED"
        assert run.report.result is ContractResult.NOT_EVALUATED


def test_explicit_out_of_contract_scope_preserves_subject_witness_without_evaluation(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    path = project / ".iac-guard-v/contracts.yaml"
    path.write_text(
        path.read_text(encoding="utf-8").replace("class: PROJECT_MANAGED", "class: OUT_OF_CONTRACT"),
        encoding="utf-8",
    )
    with _run(project, values) as run:
        assert run.report.result is ContractResult.NOT_EVALUATED
        assert run.plan.reason_code == "CONTRACT_SCOPE_EXPLICITLY_EXCLUDED"
        assert run.plan.subjects.selected == (MONITOR,)
        assert len(run.report.clauses) == 1
        assert run.report.clauses[0].native_observations[0].result.value == "SATISFIED"


def test_parser_rejects_duplicates_aliases_unknown_and_contradictory_cardinality(tmp_path: Path) -> None:
    project, _ = _project(tmp_path)
    path = project / ".iac-guard-v/contracts.yaml"
    original = path.read_text(encoding="utf-8")
    for bad, message in (
        (original.replace("name: falco-monitoring", "name: one\n  name: two"), "strict UTF-8 YAML"),
        (original.replace("metadata:\n", "unknown: true\nmetadata:\n"), "contract violation"),
        (original.replace("min: 1, max: 1", "min: 2, max: 1"), "maximum"),
        (
            original.replace("name: falco-monitoring", "name: &contract_name falco-monitoring")
            .replace("reason: Built-in monitor and metrics service relationship.", "reason: *contract_name"),
            "strict UTF-8 YAML",
        ),
    ):
        path.write_text(bad, encoding="utf-8")
        with pytest.raises(DomainError, match=message):
            load_contract(
                path, project_root=project,
                requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
            )
    path.write_text(original, encoding="utf-8")
    assert contract_schema()["additionalProperties"] is False


def test_contract_provenance_is_derived_and_external_never_project_authored(tmp_path: Path) -> None:
    project, _ = _project(tmp_path)
    canonical = project / ".iac-guard-v/contracts.yaml"
    subprocess.run(("git", "init", "-q", str(project)), check=True)
    subprocess.run(("git", "-C", str(project), "add", ".iac-guard-v/contracts.yaml"), check=True)
    subprocess.run((
        "git", "-C", str(project), "-c", "user.name=Test", "-c",
        "user.email=test@example.invalid", "commit", "-q", "-m", "contract",
    ), check=True)
    source_commit = subprocess.run(
        ("git", "-C", str(project), "rev-parse", "HEAD"), check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    one = load_contract(canonical, project_root=project, source_commit=source_commit)
    moved = project / "review.yaml"
    moved.write_bytes(canonical.read_bytes())
    with pytest.raises(DomainError, match="noncanonical"):
        load_contract(moved, project_root=project)
    two = load_contract(
        moved, project_root=project,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
        source_commit=source_commit,
    )
    assert one.source.provenance is ContractProvenance.PROJECT_AUTHORED
    assert two.source.provenance is ContractProvenance.RESEARCH_HYPOTHESIS
    assert one.source.project_root_identity != two.source.project_root_identity
    canonical.write_bytes(canonical.read_bytes() + b"\n")
    with pytest.raises(DomainError, match="bytes differ"):
        load_contract(canonical, project_root=project, source_commit=source_commit)


def test_project_authorship_rejects_uncommitted_or_forged_canonical_contract(tmp_path: Path) -> None:
    project, _ = _project(tmp_path)
    path = project / ".iac-guard-v/contracts.yaml"
    with pytest.raises(DomainError, match="exact lowercase Git commit"):
        load_contract(path, project_root=project)
    with pytest.raises(DomainError, match="protected local Git repository"):
        load_contract(path, project_root=project, source_commit="d" * 40)


def test_report_semantics_reject_tamper_even_when_outer_digest_is_recomputed(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    with _run(project, values) as run:
        payload = json.loads(run.report.canonical_json())
    native = payload["clauses"][0]["native_observations"][0]
    native["witness"]["contents"]["matched_services"] = []
    native["witness"]["witness_digest"] = canonical_digest({
        "witness_type": native["witness"]["witness_type"],
        "contents": native["witness"]["contents"],
    })
    native_body = dict(native)
    native_body.pop("observation_digest")
    native["observation_digest"] = canonical_digest(native_body)
    clause = payload["clauses"][0]
    clause_body = dict(clause)
    clause_body.pop("observation_digest")
    clause["observation_digest"] = canonical_digest(clause_body)
    body = dict(payload)
    body.pop("report_digest")
    body.pop("exit_code")
    payload["report_digest"] = canonical_digest(body)
    with pytest.raises(DomainError, match="witness|contradictory"):
        validate_contract_report_payload(payload)


def test_report_rejects_rehashed_clause_and_contract_semantic_tamper(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    with _run(project, values) as run:
        original = json.loads(run.report.canonical_json())

    clause_tamper = json.loads(json.dumps(original))
    clause = clause_tamper["clauses"][0]
    clause["result"] = "VIOLATED"
    clause["reason_code"] = "NATIVE_PROPERTY_VIOLATED"
    clause_body = dict(clause)
    clause_body.pop("observation_digest")
    clause["observation_digest"] = canonical_digest(clause_body)
    clause_tamper["summary"]["SATISFIED"] = 0
    clause_tamper["summary"]["VIOLATED"] = 1
    clause_tamper["result"] = "VIOLATED"
    clause_tamper["reason_code"] = "REQUIRED_CLAUSE_VIOLATED"
    clause_tamper["exit_code"] = 10
    body = dict(clause_tamper)
    body.pop("report_digest")
    body.pop("exit_code")
    clause_tamper["report_digest"] = canonical_digest(body)
    with pytest.raises(DomainError, match="clause result"):
        validate_contract_report_payload(clause_tamper)

    contract_tamper = json.loads(json.dumps(original))
    contract_tamper["contract"]["canonical_payload"]["metadata"]["name"] = "forged"
    body = dict(contract_tamper)
    body.pop("report_digest")
    body.pop("exit_code")
    contract_tamper["report_digest"] = canonical_digest(body)
    with pytest.raises(DomainError, match="canonical contract digest"):
        validate_contract_report_payload(contract_tamper)

    activation_tamper = json.loads(json.dumps(original))
    activation_tamper["activation"]["status"] = "INACTIVE_CONDITION_FALSE"
    activation_tamper["activation"]["reason_code"] = "ACTIVATION_CONDITION_FALSE"
    activation_tamper["plan"]["activation"] = activation_tamper["activation"]
    plan_body = dict(activation_tamper["plan"])
    plan_body.pop("plan_digest")
    activation_tamper["plan"]["plan_digest"] = canonical_digest(plan_body)
    body = dict(activation_tamper)
    body.pop("report_digest")
    body.pop("exit_code")
    activation_tamper["report_digest"] = canonical_digest(body)
    with pytest.raises(DomainError, match="activation result"):
        validate_contract_report_payload(activation_tamper)


def test_historical_reproducibility_reason_never_substitutes() -> None:
    record = HistoricalReproducibilityRecord.build(
        case_id="llm-helm-fix-1", question="replay historical render",
        expected_artifact_class="kubernetes_rendered",
        available_identities=({"source": "public"},),
        missing_identities=("historical-render",),
        reason=HistoricalReproducibilityReason.HISTORICAL_RENDER_INPUTS_UNAVAILABLE,
        product_version="0.1.0a10",
    )
    assert record.substitute_used is False
    assert len(record.record_digest) == 64
    with pytest.raises(DomainError, match="missing"):
        HistoricalReproducibilityRecord.build(
            case_id="x", question="q", expected_artifact_class="terraform_source",
            available_identities=(), missing_identities=(),
            reason=HistoricalReproducibilityReason.EXTERNAL_BASELINE_BYTES_UNAVAILABLE,
            product_version="0.1.0a10",
        )


def test_contract_implementation_and_schema_identities_are_stable() -> None:
    assert len(contract_implementation_identity()) == 64
    assert len(contract_schema_identity()) == 64
    assert contract_implementation_identity() == contract_implementation_identity()
