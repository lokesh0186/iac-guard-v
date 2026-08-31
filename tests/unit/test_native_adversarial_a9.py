from __future__ import annotations

from pathlib import Path

import pytest

from iac_guard_v.models import DomainError
from iac_guard_v.native_properties import (
    NativeArtifactClass,
    NativePropertyRequest,
    NativePropertyResult,
    evaluate_native_request,
    load_protected_native_universe,
)


def _kube(tmp_path: Path, text: str):
    (tmp_path / "objects.yaml").write_text(text, encoding="utf-8")
    return load_protected_native_universe(tmp_path, NativeArtifactClass.KUBERNETES_RENDERED)


def _request(universe, property_id, subject, parameters=None):
    return NativePropertyRequest.build(
        request_id="adversarial",
        property_id=property_id,
        property_version="1",
        artifact_class=universe.artifact_class,
        subject_identity=subject,
        parameters=parameters or {},
        protected_universe_identity=universe.identity,
    )


def test_pod_cronjob_and_ephemeral_occurrence_paths(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: v1
kind: Pod
metadata: {name: debug, labels: {app: debug}}
spec:
  containers: [{name: main, image: x}]
  ephemeralContainers: [{name: debugger, image: x, ports: [{name: debug, containerPort: 4444}]}]
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: periodic}
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        metadata: {labels: {app: periodic}}
        spec:
          restartPolicy: Never
          containers: [{name: task, image: x}]
""")
    pod = universe.workload("v1/Pod/default/debug")
    cron = universe.workload("batch/v1/CronJob/default/periodic")
    assert [item.container_class for item in pod.containers] == ["containers", "ephemeralContainers"]
    assert cron.pod_template_path == ("spec", "jobTemplate", "spec", "template")
    assert dict(cron.pod_labels) == {"app": "periodic"}


def test_policy_defaulting_empty_rule_and_endport(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: ns}
spec:
  template:
    metadata: {labels: {app: x}}
    spec: {containers: [{name: c, image: x}]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  podSelector: {}
  egress: []
  ingress:
    - from: [{}]
      ports: [{port: 1000, endPort: 1010}]
""")
    workload = "apps/v1/Deployment/ns/app"
    ingress_isolated = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1", workload)
    )
    egress_isolated = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1", workload)
    )
    assert ingress_isolated.result is NativePropertyResult.SATISFIED
    assert egress_isolated.result is NativePropertyResult.SATISFIED
    allowed = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1", workload,
            {"source": {"type": "IP", "ip": "192.0.2.4"}, "port": 1005},
        ),
    )
    assert allowed.result is NativePropertyResult.SATISFIED
    denied = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1", workload,
            {"source": {"type": "IP", "ip": "192.0.2.4"}, "port": 1011},
        ),
    )
    assert denied.result is NativePropertyResult.VIOLATED


def test_pod_ip_against_ipblock_is_not_manufactured(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: apps/v1
kind: Deployment
metadata: {name: source, namespace: ns}
spec: {template: {metadata: {labels: {app: source}}, spec: {containers: [{name: c, image: x}]}}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: dest, namespace: ns}
spec: {template: {metadata: {labels: {app: dest}}, spec: {containers: [{name: c, image: x}]}}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: dest, namespace: ns}
spec:
  podSelector: {matchLabels: {app: dest}}
  ingress: [{from: [{ipBlock: {cidr: 10.0.0.0/8}}]}]
""")
    observation = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1",
            "apps/v1/Deployment/ns/dest",
            {"source": {"type": "WORKLOAD", "identity": "apps/v1/Deployment/ns/source"}, "port": 80},
        ),
    )
    assert observation.result is NativePropertyResult.NOT_EVALUATED
    assert observation.reason_code == "INGRESS_PATH_UNDECIDABLE"


def test_service_without_selector_and_named_port_ambiguity_fail_closed(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  template:
    metadata: {labels: {app: x}}
    spec:
      containers:
        - {name: a, image: x, ports: [{name: http, containerPort: 8080}]}
        - {name: b, image: x, ports: [{name: http, containerPort: 9090}]}
---
apiVersion: v1
kind: Service
metadata: {name: ambiguous}
spec: {selector: {app: x}, ports: [{name: web, port: 80, targetPort: http}]}
---
apiVersion: v1
kind: Service
metadata: {name: external}
spec: {ports: [{name: web, port: 80}]}
""")
    ambiguous = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1",
            "v1/Service/default/ambiguous", {"service_port": {"name": "web"}},
        ),
    )
    assert ambiguous.result is NativePropertyResult.NOT_EVALUATED
    external = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1",
            "v1/Service/default/external",
        ),
    )
    assert external.result is NativePropertyResult.UNSUPPORTED


def test_service_multiple_workloads_is_set_valued_not_automatically_wrong(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: apps/v1
kind: Deployment
metadata: {name: a}
spec: {template: {metadata: {labels: {app: x}}, spec: {containers: [{name: a, image: x}]}}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: b}
spec: {template: {metadata: {labels: {app: x}}, spec: {containers: [{name: b, image: x}]}}}
---
apiVersion: v1
kind: Service
metadata: {name: app}
spec: {selector: {app: x}, ports: [{port: 80}]}
""")
    any_result = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1", "v1/Service/default/app"),
    )
    unique_result = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1", "v1/Service/default/app",
            {"expectation": "EXACT_ONE"},
        ),
    )
    assert any_result.result is NativePropertyResult.SATISFIED
    assert unique_result.result is NativePropertyResult.VIOLATED


def test_monitor_missing_port_and_api_contract_mismatch_fail_closed(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: v1
kind: Service
metadata: {name: app, labels: {monitor: "yes"}}
spec: {selector: {app: x}, ports: [{name: metrics, port: 9090}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {template: {metadata: {labels: {app: x}}, spec: {containers: [{name: c, image: x}]}}}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: missing}
spec: {selector: {matchLabels: {monitor: "yes"}}, endpoints: [{port: absent}]}
---
apiVersion: monitoring.coreos.com/v1beta1
kind: ServiceMonitor
metadata: {name: wrong-version}
spec: {selector: {matchLabels: {monitor: "yes"}}, endpoints: [{port: metrics}]}
""")
    missing = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1",
            "monitoring.coreos.com/v1/ServiceMonitor/default/missing",
        ),
    )
    assert missing.result is NativePropertyResult.NOT_EVALUATED
    mismatch = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1",
            "monitoring.coreos.com/v1beta1/ServiceMonitor/default/wrong-version",
        ),
    )
    assert mismatch.result is NativePropertyResult.UNSUPPORTED


def test_podmonitor_portnumber_and_selection_affecting_fields_are_bounded(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  template:
    metadata: {labels: {app: x}}
    spec: {containers: [{name: app, image: x, ports: [{containerPort: 9090}]}]}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: numeric}
spec: {selector: {matchLabels: {app: x}}, podMetricsEndpoints: [{portNumber: 9090}]}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: relabeled}
spec:
  selector: {matchLabels: {app: x}}
  podMetricsEndpoints: [{portNumber: 9090, relabelings: [{action: drop}]}]
""")
    numeric = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1",
            "monitoring.coreos.com/v1/PodMonitor/default/numeric",
        ),
    )
    bounded = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1",
            "monitoring.coreos.com/v1/PodMonitor/default/relabeled",
        ),
    )
    assert numeric.result is NativePropertyResult.SATISFIED
    assert bounded.result is NativePropertyResult.UNSUPPORTED
    assert bounded.reason_code == "MONITOR_ENDPOINT_SELECTION_FIELDS_UNSUPPORTED"


def test_rbac_wrong_scope_missing_namespace_and_external_domain(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: local, namespace: ns}
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: wrong}
subjects: [{kind: ServiceAccount, name: absent}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local}
""")
    binding = "rbac.authorization.k8s.io/v1/ClusterRoleBinding/_cluster/wrong"
    scope = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", binding)
    )
    subject = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", binding,
            {"complete_expected_domain": True},
        ),
    )
    role = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", binding),
    )
    assert scope.result is NativePropertyResult.VIOLATED
    assert subject.result is NativePropertyResult.NOT_EVALUATED
    assert role.result is NativePropertyResult.VIOLATED


def test_malformed_label_types_and_cluster_namespace_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="labels"):
        _kube(tmp_path, """apiVersion: v1
kind: Pod
metadata: {name: bad, labels: {number: 1}}
spec: {containers: [{name: c, image: x}]}
""")
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(DomainError, match="cluster-scoped"):
        _kube(other, """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: bad, namespace: ns}
rules: []
""")


def test_terraform_cycle_and_duplicate_reference_span_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("""resource "thing" "a" {
  peer = thing.b.id
}
resource "thing" "b" {
  peer = thing.a.id
}
""", encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.TERRAFORM_SOURCE)
    cycle = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_TF_REFERENCE_RESOLVES_V1", "thing.a",
            {"attribute_path": ["peer"], "expected_target": "thing.b", "complete_expected_domain": True, "reference_contract_digest": "f" * 64},
        ),
    )
    assert cycle.result is NativePropertyResult.NOT_EVALUATED
    assert cycle.reason_code == "TERRAFORM_REFERENCE_GRAPH_CYCLIC"


def test_universe_snapshot_is_stable_after_source_mutation(tmp_path: Path) -> None:
    source = tmp_path / "main.tf"
    source.write_text("""resource "thing" "b" {}
resource "thing" "a" { peer = thing.b.id }
""", encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.TERRAFORM_SOURCE)
    identity = universe.identity
    source.write_text('resource "thing" "changed" {}\n', encoding="utf-8")
    observation = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_TF_REFERENCE_RESOLVES_V1", "thing.a",
            {"attribute_path": ["peer"], "expected_target": "thing.b", "complete_expected_domain": True, "reference_contract_digest": "f" * 64},
        ),
    )
    assert universe.identity == identity
    assert observation.result is NativePropertyResult.SATISFIED


def test_duplicate_yaml_aliases_and_container_occurrences_fail_closed(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate"
    duplicate.mkdir()
    with pytest.raises(DomainError, match="invalid"):
        _kube(duplicate, """apiVersion: v1
kind: Pod
metadata: {name: first, name: second}
spec: {containers: [{name: app, image: x}]}
""")
    alias = tmp_path / "alias"
    alias.mkdir()
    with pytest.raises(DomainError, match="invalid"):
        _kube(alias, """apiVersion: v1
kind: Pod
metadata: &meta {name: app}
spec:
  containers: [{name: app, image: x}]
  copied: *meta
""")
    occurrences = tmp_path / "occurrences"
    occurrences.mkdir()
    with pytest.raises(DomainError, match="unique"):
        _kube(occurrences, """apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers: [{name: same, image: x}]
  initContainers: [{name: same, image: x}]
""")


def test_named_service_port_collision_same_number_is_not_authoritative(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  template:
    metadata: {labels: {app: x}}
    spec:
      containers:
        - {name: first, image: x, ports: [{name: metrics, containerPort: 9090}]}
        - {name: second, image: x, ports: [{name: metrics, containerPort: 9090}]}
---
apiVersion: v1
kind: Service
metadata: {name: app}
spec:
  selector: {app: x}
  ports: [{name: metrics, port: 9090, targetPort: metrics}]
""")
    observation = evaluate_native_request(
        universe,
        _request(
            universe,
            "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1",
            "v1/Service/default/app",
            {"service_port": {"name": "metrics"}},
        ),
    )
    assert observation.result is NativePropertyResult.NOT_EVALUATED
    assert observation.reason_code == "SERVICE_TARGET_PORT_AMBIGUOUS"


def test_malformed_ipblock_except_and_serviceaccount_apigroup_fail_closed(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: ns}
spec: {template: {metadata: {labels: {app: x}}, spec: {containers: [{name: app, image: x}]}}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: app, namespace: ns}
spec:
  podSelector: {matchLabels: {app: x}}
  ingress: [{from: [{ipBlock: {cidr: 10.0.0.0/8, except: [192.168.0.0/16]}}]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: bad, namespace: ns}
subjects: [{kind: ServiceAccount, apiGroup: rbac.authorization.k8s.io, name: app, namespace: ns}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: view}
""")
    path = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1",
            "apps/v1/Deployment/ns/app",
            {"source": {"type": "IP", "ip": "10.1.2.3"}, "port": 80},
        ),
    )
    assert path.result is NativePropertyResult.ERROR
    rbac = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1",
            "rbac.authorization.k8s.io/v1/RoleBinding/ns/bad",
        ),
    )
    assert rbac.result is NativePropertyResult.ERROR
