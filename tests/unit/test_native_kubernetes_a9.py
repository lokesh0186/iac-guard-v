from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from iac_guard_v.native_properties import (
    NativeArtifactClass,
    NativePropertyRequest,
    NativePropertyResult,
    evaluate_native_request,
    load_protected_native_universe,
)


FIXTURE = """
apiVersion: v1
kind: Namespace
metadata:
  name: apps
  labels: {team: platform}
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels: {team: observability}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: apps}
spec:
  template:
    metadata: {labels: {app: api, component: backend}}
    spec:
      initContainers:
        - name: migrate
          image: example
          ports: [{name: admin, containerPort: 9090}]
      containers:
        - name: api
          image: example
          ports: [{name: http, containerPort: 8080}, {name: metrics, containerPort: 6080}]
        - name: sidecar
          image: example
          ports: [{name: sidecar, containerPort: 15000}]
---
apiVersion: batch/v1
kind: Job
metadata: {name: migrate, namespace: apps}
spec:
  template:
    metadata: {labels: {app: migration}}
    spec:
      restartPolicy: Never
      containers: [{name: migrate, image: example}]
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: apps
  labels: {monitor: enabled}
spec:
  selector: {app: api}
  ports:
    - {name: web, port: 80, targetPort: http}
    - {name: metrics, port: 6080, targetPort: metrics}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: apps}
spec:
  podSelector: {matchLabels: {app: api}}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-monitor, namespace: apps}
spec:
  podSelector: {matchLabels: {component: backend}}
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {team: observability}}
          podSelector: {matchLabels: {app: prometheus}}
      ports: [{protocol: TCP, port: 6080}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-dns, namespace: apps}
spec:
  podSelector: {matchLabels: {app: api}}
  policyTypes: [Egress]
  egress:
    - to: [{ipBlock: {cidr: 10.0.0.0/8, except: [10.1.0.0/16]}}]
      ports: [{protocol: UDP, port: 53}]
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: api, namespace: monitoring}
spec:
  namespaceSelector: {matchNames: [apps]}
  selector: {matchLabels: {monitor: enabled}}
  endpoints: [{port: metrics}]
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: api-pods, namespace: monitoring}
spec:
  namespaceSelector: {matchNames: [apps]}
  selector: {matchLabels: {app: api}}
  podMetricsEndpoints: [{port: metrics}]
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: controller, namespace: apps}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader, namespace: apps}
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: global-reader}
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: reader, namespace: apps}
subjects:
  - {kind: ServiceAccount, name: controller, namespace: apps}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: reader}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: global-reader}
subjects:
  - {kind: ServiceAccount, name: controller, namespace: apps}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: global-reader}
"""


def _universe(tmp_path: Path):
    (tmp_path / "all.yaml").write_text(FIXTURE, encoding="utf-8")
    return load_protected_native_universe(
        tmp_path, NativeArtifactClass.KUBERNETES_RENDERED
    )


def _request(universe, property_id, subject, parameters=None, request_id="r"):
    return NativePropertyRequest.build(
        request_id=request_id,
        property_id=property_id,
        property_version="1",
        artifact_class=NativeArtifactClass.KUBERNETES_RENDERED,
        subject_identity=subject,
        parameters=parameters or {},
        protected_universe_identity=universe.identity,
    )


API = "apps/v1/Deployment/apps/api"
JOB = "batch/v1/Job/apps/migrate"
SERVICE = "v1/Service/apps/api"
SM = "monitoring.coreos.com/v1/ServiceMonitor/monitoring/api"
PM = "monitoring.coreos.com/v1/PodMonitor/monitoring/api-pods"
ROLE_BINDING = "rbac.authorization.k8s.io/v1/RoleBinding/apps/reader"
CLUSTER_BINDING = "rbac.authorization.k8s.io/v1/ClusterRoleBinding/_cluster/global-reader"


def test_workload_identity_occurrences_and_selection(tmp_path: Path) -> None:
    universe = _universe(tmp_path)
    workload = universe.workload(API)
    assert dict(workload.pod_labels) == {"app": "api", "component": "backend"}
    assert [(item.container_class, item.index, item.name) for item in workload.containers] == [
        ("containers", 0, "api"), ("containers", 1, "sidecar"),
        ("initContainers", 0, "migrate"),
    ]
    observation = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", API)
    )
    assert observation.result is NativePropertyResult.SATISFIED
    assert len(observation.witness.contents["selecting_policies"]) == 3
    job = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", JOB)
    )
    assert job.result is NativePropertyResult.VIOLATED


def test_directional_isolation_and_component_closure(tmp_path: Path) -> None:
    universe = _universe(tmp_path)
    ingress = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1", API)
    )
    egress = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1", API)
    )
    assert ingress.result is NativePropertyResult.SATISFIED
    assert egress.result is NativePropertyResult.SATISFIED
    policies = [
        "networking.k8s.io/v1/NetworkPolicy/apps/default-deny",
        "networking.k8s.io/v1/NetworkPolicy/apps/allow-monitor",
    ]
    digest = hashlib.sha256(b"explicit-component-membership").hexdigest()
    closure = evaluate_native_request(
        universe,
        _request(
            universe,
            "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1",
            "component/apps/backend",
            {
                "workload_identities": [API, JOB],
                "policy_identities": policies,
                "membership_proof_digest": digest,
            },
        ),
    )
    assert closure.result is NativePropertyResult.VIOLATED
    assert list(closure.witness.contents["uncovered_workloads"]) == [JOB]


def test_service_set_and_port_graph(tmp_path: Path) -> None:
    universe = _universe(tmp_path)
    selection = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1", SERVICE,
            {"expectation": "EXACT_SET", "expected_workloads": [API]},
        ),
    )
    assert selection.result is NativePropertyResult.SATISFIED
    port = evaluate_native_request(
        universe,
        _request(
            universe,
            "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1",
            SERVICE,
            {"service_port": {"name": "metrics"}, "expected_port": 6080},
        ),
    )
    assert port.result is NativePropertyResult.SATISFIED
    assert list(port.witness.contents["resolved_port_set"]) == [6080]
    wrong = evaluate_native_request(
        universe,
        _request(
            universe,
            "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1",
            SERVICE,
            {"service_port": {"name": "metrics"}, "expected_port": 9999},
        ),
    )
    assert wrong.result is NativePropertyResult.VIOLATED


def test_additive_ingress_peer_and_port_semantics(tmp_path: Path) -> None:
    universe = _universe(tmp_path)
    source = {
        "type": "SYMBOLIC",
        "namespace": "monitoring",
        "namespace_labels": {"team": "observability"},
        "pod_labels": {"app": "prometheus"},
    }
    allowed = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1", API,
            {"source": source, "port": 6080, "protocol": "TCP"},
        ),
    )
    assert allowed.result is NativePropertyResult.SATISFIED
    matching = [
        rule
        for policy in allowed.witness.contents["policy_rule_evaluations"]
        for rule in policy["rule_evaluations"]
        if rule["matched"] is True
    ]
    assert len(matching) == 1
    denied = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1", API,
            {"source": source, "port": 8080, "protocol": "TCP"},
        ),
    )
    assert denied.result is NativePropertyResult.VIOLATED


def test_ipblock_except_and_protocol_are_direction_specific(tmp_path: Path) -> None:
    universe = _universe(tmp_path)
    allowed = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1", API,
            {"destination": {"type": "IP", "ip": "10.2.3.4"}, "port": 53, "protocol": "UDP"},
        ),
    )
    assert allowed.result is NativePropertyResult.SATISFIED
    excepted = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1", API,
            {"destination": {"type": "IP", "ip": "10.1.2.3"}, "port": 53, "protocol": "UDP"},
        ),
    )
    assert excepted.result is NativePropertyResult.VIOLATED
    protocol = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1", API,
            {"destination": {"type": "IP", "ip": "10.2.3.4"}, "port": 53, "protocol": "TCP"},
        ),
    )
    assert protocol.result is NativePropertyResult.VIOLATED


def test_service_monitor_pod_monitor_and_monitoring_path(tmp_path: Path) -> None:
    universe = _universe(tmp_path)
    sm = evaluate_native_request(
        universe,
        _request(universe, "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1", SM),
    )
    pm = evaluate_native_request(
        universe,
        _request(universe, "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1", PM),
    )
    assert sm.result is NativePropertyResult.SATISFIED
    assert pm.result is NativePropertyResult.SATISFIED
    path = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1", SM,
            {"source": {
                "type": "SYMBOLIC", "namespace": "monitoring",
                "namespace_labels": {"team": "observability"},
                "pod_labels": {"app": "prometheus"},
            }},
        ),
    )
    assert path.result is NativePropertyResult.SATISFIED


def test_rbac_role_subject_and_scope_relationships(tmp_path: Path) -> None:
    universe = _universe(tmp_path)
    for binding in (ROLE_BINDING, CLUSTER_BINDING):
        role = evaluate_native_request(
            universe, _request(universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", binding)
        )
        subjects = evaluate_native_request(
            universe,
            _request(universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", binding),
        )
        scope = evaluate_native_request(
            universe, _request(universe, "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1", binding)
        )
        assert role.result is NativePropertyResult.SATISFIED
        assert subjects.result is NativePropertyResult.SATISFIED
        assert scope.result is NativePropertyResult.SATISFIED
        assert role.witness.contents["authorization_simulated"] is False


def test_dgraph_public_packet_native_regression() -> None:
    root = Path("examples/public-reproductions/dgraph-charts-146/rendered")
    universe = load_protected_native_universe(
        root, NativeArtifactClass.KUBERNETES_RENDERED
    )
    monitor = "monitoring.coreos.com/v1/ServiceMonitor/dgraph-system/adjudicate-dgraph"
    resolution = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1", monitor,
            {"endpoint_index": 1},
        ),
    )
    assert resolution.result is NativePropertyResult.SATISFIED
    assert list(
        resolution.witness.contents["service_port_resolutions"][0]["resolved_port_set"]
    ) == [6080]
    path = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1", monitor,
            {
                "endpoint_index": 1,
                "source": {
                    "type": "SYMBOLIC",
                    "namespace": "monitoring",
                    "namespace_labels": {"kubernetes.io/metadata.name": "monitoring"},
                    "pod_labels": {"app": "prometheus"},
                },
            },
        ),
    )
    assert path.result is NativePropertyResult.VIOLATED
    assert path.witness.contents["manifest_semantics_only"] is True


def test_quay_public_packet_component_closure_regression() -> None:
    root = Path("examples/public-reproductions/quay-operator-1322/rendered")
    universe = load_protected_native_universe(
        root, NativeArtifactClass.KUBERNETES_RENDERED
    )
    workloads = [
        "apps/v1/Deployment/default/clair-postgres",
        "apps/v1/Deployment/default/clair-postgres-old",
        "batch/v1/Job/default/clair-postgres-upgrade",
    ]
    # Bind identities from the immutable packet rather than relying on display names.
    clair = [item.identity for item in universe.workloads if "clair" in item.identity and "postgres" in item.identity]
    policies = [
        item.identity for item in universe.kubernetes_resources
        if item.kind == "NetworkPolicy" and "clair" in item.identity
    ]
    assert len(clair) >= 3 and policies
    observation = evaluate_native_request(
        universe,
        _request(
            universe, "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1", "component/quay/clair-upgrade",
            {
                "workload_identities": clair,
                "policy_identities": policies,
                "membership_proof_digest": hashlib.sha256(b"quay-public-packet-membership").hexdigest(),
            },
        ),
    )
    assert observation.result is NativePropertyResult.VIOLATED
    assert observation.witness.contents["uncovered_workloads"]
