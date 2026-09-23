from __future__ import annotations

import json
from pathlib import Path

import pytest

from iac_guard_v.contracts import ContractExecutionInput, prepare_contract_run
from iac_guard_v.contracts.model import ContractProvenance, contract_schema_identity
from iac_guard_v.contracts.report import validate_contract_report_payload
from iac_guard_v.contracts.schema_bridge import (
    CONTRACT_API_V1,
    CONTRACT_API_V1ALPHA1,
    CONTRACT_REPORT_V1,
    CONTRACT_REPORT_V1ALPHA1,
    CONTRACT_SCHEMA_V1,
    CONTRACT_SCHEMA_V1ALPHA1,
    api_version_for_schema_version,
    contract_report_schema,
    contract_schema_for_api_version,
    convert_contract_api_version,
    is_contract_report_version,
    report_version_for_schema_version,
    schema_version_for_api_version,
    schema_version_for_report_version,
)
from iac_guard_v.models import DomainError


def _case(tmp_path: Path, api_version: str) -> tuple[Path, Path, Path]:
    project = tmp_path / api_version.rsplit("/", 1)[-1]
    rendered = project / "rendered"
    contract_dir = project / ".iac-guard-v"
    rendered.mkdir(parents=True)
    contract_dir.mkdir()
    (rendered / "objects.yaml").write_text("""apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: system}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
        - name: app
          image: example.invalid/app
          ports: [{name: metrics, containerPort: 9402, protocol: TCP}]
---
apiVersion: v1
kind: Service
metadata: {name: metrics, namespace: system, labels: {app: metrics}}
spec:
  selector: {app: app}
  ports: [{name: metrics, port: 9402, targetPort: metrics, protocol: TCP}]
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: app, namespace: system}
spec:
  selector: {matchLabels: {app: metrics}}
  endpoints: [{port: metrics}]
""", encoding="utf-8")
    contract = contract_dir / "contracts.yaml"
    contract.write_text(f"""apiVersion: {api_version}
kind: InfrastructureContract
metadata: {{name: stable-bridge}}
spec:
  artifactClass: kubernetes_rendered
  subjects:
    include:
      identities: [monitoring.coreos.com/v1/ServiceMonitor/system/app]
    cardinality: {{min: 1, max: 1}}
  responsibility: {{class: USER_MANAGED}}
  expect:
    - id: monitor-resolves
      property:
        namespace: iac_guard_v
        id: IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1
        version: "1"
""", encoding="utf-8")
    return project, rendered, contract


def _run(project: Path, rendered: Path, contract: Path):
    return prepare_contract_run(ContractExecutionInput(
        contract_path=contract,
        project_root=project,
        protected_root=rendered,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
        source_commit="a" * 40,
    ))


@pytest.mark.parametrize(
    ("api_version", "schema_version", "report_version"),
    (
        (CONTRACT_API_V1ALPHA1, CONTRACT_SCHEMA_V1ALPHA1, CONTRACT_REPORT_V1ALPHA1),
        (CONTRACT_API_V1, CONTRACT_SCHEMA_V1, CONTRACT_REPORT_V1),
    ),
)
def test_both_schema_versions_execute_without_semantic_reinterpretation(
    tmp_path: Path, api_version: str, schema_version: str, report_version: str,
) -> None:
    project, rendered, contract_path = _case(tmp_path, api_version)
    with _run(project, rendered, contract_path) as run:
        payload = json.loads(run.report.canonical_json())
        validate_contract_report_payload(payload)
        assert run.contract.schema_version == schema_version
        assert payload["schema_version"] == report_version
        assert payload["result"] == "SATISFIED"
        assert payload["contract"]["schema_identity"] == contract_schema_identity(schema_version)
        assert payload["clauses"][0]["native_observations"][0]["result"] == "SATISFIED"


def test_explicit_alpha_stable_conversion_is_bidirectional_and_content_preserving() -> None:
    payload = {
        "apiVersion": CONTRACT_API_V1ALPHA1,
        "kind": "InfrastructureContract",
        "metadata": {"name": "bridge"},
        "spec": {
            "artifactClass": "kubernetes_rendered",
            "subjects": {"include": {"identities": ["v1/Service/default/app"]}},
            "responsibility": {"class": "USER_MANAGED"},
            "expect": [{
                "id": "service-selects",
                "property": {
                    "namespace": "iac_guard_v",
                    "id": "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1",
                    "version": "1",
                },
            }],
        },
    }
    stable = convert_contract_api_version(payload, CONTRACT_API_V1)
    restored = convert_contract_api_version(stable, CONTRACT_API_V1ALPHA1)
    assert stable["apiVersion"] == CONTRACT_API_V1
    assert restored == payload
    assert {key: value for key, value in stable.items() if key != "apiVersion"} == {
        key: value for key, value in payload.items() if key != "apiVersion"
    }


def test_stable_schema_changes_only_identifier_and_api_discriminator() -> None:
    alpha = contract_schema_for_api_version(CONTRACT_API_V1ALPHA1)
    stable = contract_schema_for_api_version(CONTRACT_API_V1)
    stable["$id"] = alpha["$id"]
    stable["properties"]["apiVersion"] = alpha["properties"]["apiVersion"]
    assert stable == alpha


def test_unknown_schema_versions_fail_closed() -> None:
    with pytest.raises(DomainError, match="unsupported infrastructure contract apiVersion"):
        contract_schema_for_api_version("iac-guard-v.io/v2")
    with pytest.raises(DomainError, match="unsupported infrastructure contract report version"):
        contract_report_schema("infrastructure-contract-report-v2")
    with pytest.raises(DomainError, match="unsupported infrastructure contract apiVersion"):
        schema_version_for_api_version("iac-guard-v.io/v2")
    with pytest.raises(DomainError, match="unsupported infrastructure contract schema version"):
        api_version_for_schema_version("infrastructure-contract-v2")
    with pytest.raises(DomainError, match="unsupported infrastructure contract schema version"):
        report_version_for_schema_version("infrastructure-contract-v2")
    with pytest.raises(DomainError, match="unsupported infrastructure contract report version"):
        schema_version_for_report_version("infrastructure-contract-report-v2")
    assert not is_contract_report_version("infrastructure-contract-report-v2")


def test_conversion_rejects_non_objects_and_invalid_source_documents() -> None:
    with pytest.raises(DomainError, match="conversion input must be an object"):
        convert_contract_api_version([], CONTRACT_API_V1)  # type: ignore[arg-type]
    with pytest.raises(DomainError, match="source infrastructure contract is invalid"):
        convert_contract_api_version(
            {"apiVersion": CONTRACT_API_V1ALPHA1}, CONTRACT_API_V1,
        )
