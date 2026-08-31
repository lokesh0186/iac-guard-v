from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from iac_guard_v.models import DomainError
from iac_guard_v.native_properties import (
    NATIVE_PROPERTY_REGISTRY,
    NativeArtifactClass,
    NativePropertyRequest,
    NativePropertyResult,
    evaluate_native_request,
    evaluate_native_requests,
    load_protected_native_universe,
)
from iac_guard_v.native_properties.evidence import validate_native_witness_payload
from iac_guard_v.native_properties.model import (
    NativePropertyCapabilities,
    NativePropertyImplementationIdentity,
    NativePropertyObservation,
    NativePropertyWitness,
    NativeSemanticVersionBinding,
    canonical_digest,
    canonical_json,
)
from iac_guard_v.native_properties.network_policy import (
    _endpoint_contract,
    _peer_match,
    _port_match,
    evaluate_component_closure,
    effective_policy_types,
    evaluate_direction_path,
)
from iac_guard_v.native_properties.prometheus_operator import (
    _endpoint,
    _target_namespaces,
)
from iac_guard_v.native_properties.public import (
    PublicNativePropertyRun,
    load_native_property_config,
    verify_native_properties,
)
from iac_guard_v.native_properties.rbac import _complete_domain
from iac_guard_v.native_properties.report import (
    NativePropertyReportV1,
    render_native_console,
    validate_native_report_payload,
)
from iac_guard_v.native_properties.selectors import (
    evaluate_label_selector,
    normalize_label_selector,
    service_selector_as_label_selector,
)
from iac_guard_v.native_properties.services import select_service_port
from iac_guard_v.native_properties.terraform import (
    _attribute_value,
    _reference_span,
    _references,
    _resource_block_span,
    evaluate_reference_resolves,
)
from iac_guard_v.native_properties.universe import (
    NativeSourceFile,
    ProtectedNativeUniverse,
)


def _kube(tmp_path: Path, text: str):
    (tmp_path / "objects.yaml").write_text(text, encoding="utf-8")
    return load_protected_native_universe(tmp_path, NativeArtifactClass.KUBERNETES_RENDERED)


def _tf(tmp_path: Path, text: str):
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    return load_protected_native_universe(tmp_path, NativeArtifactClass.TERRAFORM_SOURCE)


def _request(universe, property_id: str, subject: str, parameters=None, request_id="coverage"):
    return NativePropertyRequest.build(
        request_id=request_id,
        property_id=property_id,
        property_version="1",
        artifact_class=universe.artifact_class,
        subject_identity=subject,
        parameters=parameters or {},
        protected_universe_identity=universe.identity,
    )


BASE = """apiVersion: v1
kind: Namespace
metadata: {name: ns, labels: {group: one}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: source, namespace: ns}
spec:
  template:
    metadata: {labels: {app: source}}
    spec: {containers: [{name: source, image: x, ports: [{name: client, containerPort: 1234}]}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: dest, namespace: ns}
spec:
  template:
    metadata: {labels: {app: dest}}
    spec: {containers: [{name: dest, image: x, ports: [{name: http, containerPort: 8080}]}]}
---
apiVersion: v1
kind: Service
metadata: {name: dest, namespace: ns, labels: {monitored: "yes"}}
spec:
  selector: {app: dest}
  ports:
    - {name: web, port: 80, targetPort: http}
    - {name: direct, port: 8081, targetPort: 8080}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: dest, namespace: ns}
spec:
  podSelector: {matchLabels: {app: dest}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: source}}}]
      ports: [{port: http, protocol: TCP}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: view}
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: binding, namespace: ns}
subjects:
  - {kind: ServiceAccount, name: missing, namespace: ns}
  - {kind: User, name: someone, apiGroup: rbac.authorization.k8s.io}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: view}
"""


def test_model_defensive_contracts() -> None:
    with pytest.raises(DomainError):
        canonical_json({"": 1})
    with pytest.raises(DomainError):
        NativePropertyCapabilities(True, True, False, True, 1)  # type: ignore[arg-type]
    with pytest.raises(DomainError):
        NativeSemanticVersionBinding("kubernetes", "v1", "x")
    module = (("module", "0" * 64),)
    with pytest.raises(DomainError):
        NativePropertyImplementationIdentity("v1", "0" * 64, module)
    with pytest.raises(DomainError):
        NativePropertyImplementationIdentity("v1", canonical_digest([{"module": "module", "sha256": "0" * 64}]), ())
    with pytest.raises(DomainError):
        NativePropertyImplementationIdentity(
            "v1", canonical_digest([{"module": "module", "sha256": "0" * 64}]),
            (("module", "0" * 64), ("module", "0" * 64)),
        )
    definition = NATIVE_PROPERTY_REGISTRY["IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1"]
    with pytest.raises(DomainError):
        replace(definition, property_namespace="other")
    with pytest.raises(DomainError):
        replace(definition, parameter_schema_digest="0" * 64)
    with pytest.raises(DomainError):
        replace(definition, artifact_class="bad")  # type: ignore[arg-type]


def test_universe_list_json_and_defensive_inputs(tmp_path: Path) -> None:
    root = tmp_path / "list"
    root.mkdir()
    universe = _kube(root, """apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata: {name: one}
    spec: {containers: [{name: c, image: x}]}
  - apiVersion: v1
    kind: Service
    metadata: {name: one}
    spec: {selector: {app: none}, ports: [{port: 80}]}
---
""")
    assert universe.kubernetes_resources[0].list_index in {0, 1}
    assert universe.source_files[0].canonical_dict()["size"] > 0
    assert universe.workloads[0].containers[0].canonical_dict()["identity"]
    with pytest.raises(DomainError):
        universe.kubernetes_resource("missing")
    with pytest.raises(DomainError):
        universe.terraform_resource("missing")
    with pytest.raises(DomainError):
        ProtectedNativeUniverse(
            universe.root, universe.artifact_class, universe.default_namespace,
            universe.source_files, universe.kubernetes_resources, universe.workloads, (),
            universe.input_manifest_digest, universe.resource_inventory_digest, universe.identity,
        )
    with pytest.raises(DomainError):
        load_protected_native_universe("bad", NativeArtifactClass.KUBERNETES_RENDERED)  # type: ignore[arg-type]
    with pytest.raises(DomainError):
        load_protected_native_universe(root, "bad")  # type: ignore[arg-type]
    with pytest.raises(DomainError):
        load_protected_native_universe(root, NativeArtifactClass.KUBERNETES_RENDERED, default_namespace="bad/name")


@pytest.mark.parametrize(
    "manifest",
    [
        "- not-an-object\n",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: bad, namespace: 1}\nspec: {containers: []}\n",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: bad}\nspec: {containers: bad}\n",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: bad}\nspec: {containers: [{name: c, ports: bad}]}\n",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: bad}\nspec: {containers: [{name: c, ports: [{containerPort: true}]}]}\n",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: bad}\nspec: {containers: [{name: c, ports: [{containerPort: 80, protocol: ICMP}]}]}\n",
    ],
)
def test_universe_malformed_objects_fail_closed(tmp_path: Path, manifest: str) -> None:
    with pytest.raises(DomainError):
        _kube(tmp_path, manifest)


def test_selector_edge_contracts() -> None:
    assert evaluate_label_selector(
        {"matchExpressions": [{"key": "x", "operator": "DoesNotExist"}]}, {}
    ).matched
    assert not evaluate_label_selector(
        {"matchExpressions": [{"key": "x", "operator": "Exists"}]}, {}
    ).matched
    assert not evaluate_label_selector(
        {"matchExpressions": [{"key": "x", "operator": "In", "values": ["a"]}]}, {}
    ).matched
    assert not evaluate_label_selector(
        {"matchExpressions": [{"key": "x", "operator": "NotIn", "values": ["a"]}]}, {"x": "a"}
    ).matched
    with pytest.raises(DomainError):
        normalize_label_selector([])
    with pytest.raises(DomainError):
        normalize_label_selector({"matchLabels": []})
    with pytest.raises(DomainError):
        normalize_label_selector({"matchExpressions": ["bad"]})
    with pytest.raises(DomainError):
        normalize_label_selector({"matchExpressions": [{"key": "", "operator": "Exists"}]})
    with pytest.raises(DomainError):
        service_selector_as_label_selector({"x": 1})


def test_networkpolicy_defaulting_selection_and_endpoint_contracts(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    policy = universe.kubernetes_resource("networking.k8s.io/v1/NetworkPolicy/ns/dest")
    assert effective_policy_types(policy) == ("Ingress",)
    for bad in (
        "spec: {podSelector: {}, policyTypes: []}",
        "spec: {podSelector: {}, policyTypes: [Other]}",
        "spec: {podSelector: {}, policyTypes: [Ingress, Ingress]}",
    ):
        root = tmp_path / canonical_digest(bad)[:8]
        root.mkdir()
        malformed = _kube(root, f"apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {{name: p}}\n{bad}\n")
        with pytest.raises(DomainError):
            effective_policy_types(malformed.kubernetes_resources[0])
    workload = _endpoint_contract(universe, {"type": "WORKLOAD", "identity": "apps/v1/Deployment/ns/source"}, role="source")
    assert workload["namespace_labels"] == {"group": "one"}
    assert _endpoint_contract(universe, {"type": "IP", "ip": "192.0.2.1"}, role="source")["ip"] == "192.0.2.1"
    for bad in (
        {"type": "WORKLOAD"}, {"type": "IP", "ip": "bad"},
        {"type": "LABELS", "namespace": "ns", "pod_labels": {"x": 1}},
        {"type": "LABELS", "namespace": "ns", "pod_labels": {}, "namespace_labels": []},
        {"type": "UNKNOWN"},
    ):
        with pytest.raises(DomainError):
            _endpoint_contract(universe, bad, role="source")


def test_peer_and_port_low_level_fail_closed(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    symbolic = _endpoint_contract(
        universe, {"type": "SYMBOLIC", "namespace": "other", "pod_labels": {"app": "source"}}, role="source"
    )
    ip = _endpoint_contract(universe, {"type": "IP", "ip": "10.0.0.1"}, role="source")
    assert _peer_match(universe, {}, symbolic, "ns")[0] is True
    assert _peer_match(universe, {"podSelector": {}}, symbolic, "ns")[0] is False
    assert _peer_match(universe, {"podSelector": {}}, ip, "ns")[0] is False
    assert _peer_match(universe, {"namespaceSelector": {}}, symbolic, "ns")[0] is True
    unknown_labels = dict(symbolic)
    unknown_labels["namespace_labels"] = None
    assert _peer_match(
        universe, {"namespaceSelector": {"matchLabels": {"group": "one"}}}, unknown_labels, "ns"
    )[0] is None
    for peer in (
        {"unknown": {}},
        {"ipBlock": {"cidr": "10.0.0.0/8"}, "podSelector": {}},
        {"ipBlock": {"cidr": "10.0.0.0/8", "unknown": 1}},
        {"ipBlock": {"cidr": "10.0.0.1/8"}},
    ):
        with pytest.raises(DomainError):
            _peer_match(universe, peer, ip, "ns")
    destination = universe.workload("apps/v1/Deployment/ns/dest")
    assert _port_match({}, 80, "TCP", destination)[0] is True
    assert _port_match({"port": "http"}, 8080, "TCP", destination)[0] is True
    assert _port_match({"port": "missing"}, 8080, "TCP", destination)[0] is None
    assert _port_match({"port": 8080, "protocol": "UDP"}, 8080, "TCP", destination)[0] is False
    for port in (
        {"bad": 1}, {"protocol": "ICMP"}, {"endPort": 5},
        {"port": 0}, {"port": 10, "endPort": 9}, {"port": []},
    ):
        with pytest.raises(DomainError):
            _port_match(port, 10, "TCP", destination)


def test_path_composition_unisolated_named_and_denied(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    source = "apps/v1/Deployment/ns/source"
    destination = "apps/v1/Deployment/ns/dest"
    pod_path = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1", source, {
            "destination_service": "v1/Service/ns/dest", "service_port": {"name": "web"}
        }),
    )
    assert pod_path.result is NativePropertyResult.SATISFIED
    denied = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1", destination, {
            "direction": "Ingress", "source": {"type": "IP", "ip": "192.0.2.1"}, "port": 8080
        }),
    )
    assert denied.result is NativePropertyResult.SATISFIED
    not_denied = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1", destination, {
            "direction": "Ingress", "source": {"type": "WORKLOAD", "identity": source}, "port": 8080
        }),
    )
    assert not_denied.result is NativePropertyResult.VIOLATED
    unisolated = evaluate_direction_path(
        universe,
        protected_workload=universe.workload(source),
        endpoint=_endpoint_contract(universe, {"type": "IP", "ip": "192.0.2.1"}, role="destination"),
        destination_workload=None,
        direction="Egress", port=443, protocol="TCP",
    )
    assert unisolated[0] is NativePropertyResult.SATISFIED
    for direction, port, protocol in (("Other", 80, "TCP"), ("Ingress", 0, "TCP"), ("Ingress", 80, "ICMP")):
        with pytest.raises(DomainError):
            evaluate_direction_path(
                universe, protected_workload=universe.workload(destination),
                endpoint=_endpoint_contract(universe, {"type": "IP", "ip": "192.0.2.1"}, role="source"),
                destination_workload=universe.workload(destination), direction=direction,
                port=port, protocol=protocol,
            )


def test_service_selection_and_ports_error_matrix(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    service = universe.kubernetes_resource("v1/Service/ns/dest")
    assert select_service_port(service, {"port": 8081})[1]["targetPort"] == 8080
    assert select_service_port(service, {"name": "web"})[1]["protocol"] == "TCP"
    for selector in (
        {"protocol": "ICMP", "port": 80}, {"name": "web", "port": 80},
        {"port": True}, {"name": "missing"}, {"name": "web", "protocol": "UDP"},
    ):
        with pytest.raises(DomainError):
            select_service_port(service, selector)
    for expectation, expected in (
        ("ALL_EXPECTED_PRESENT", ["apps/v1/Deployment/ns/dest"]),
        ("EXACT_SET", ["apps/v1/Deployment/ns/source"]),
        ("BAD", []),
    ):
        if expectation == "BAD":
            with pytest.raises(DomainError):
                evaluate_native_request(
                    universe,
                    _request(universe, "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1", service.identity, {
                        "expectation": expectation, "expected_workloads": expected
                    }),
                )
            continue
        observation = evaluate_native_request(
            universe,
            _request(universe, "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1", service.identity, {
                "expectation": expectation, "expected_workloads": expected
            }),
        )
        if expectation == "BAD":
            raise AssertionError("schema-invalid expectation was accepted")
        elif expectation == "ALL_EXPECTED_PRESENT":
            assert observation.result is NativePropertyResult.SATISFIED
        else:
            assert observation.result is NativePropertyResult.VIOLATED


def test_monitor_namespace_endpoint_and_resolution_matrix(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE + """---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: sm, namespace: ns}
spec:
  namespaceSelector: {any: true}
  selector: {matchLabels: {monitored: "yes"}}
  endpoints: [{port: web}]
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: pm, namespace: ns}
spec:
  selector: {matchLabels: {app: dest}}
  podMetricsEndpoints: [{port: http}]
""")
    sm = universe.kubernetes_resource("monitoring.coreos.com/v1/ServiceMonitor/ns/sm")
    assert "ns" in _target_namespaces(universe, sm, sm.data["spec"])
    assert _endpoint(sm.data["spec"], "endpoints", 0)["port"] == "web"
    for spec in (
        {"namespaceSelector": {"any": True, "matchNames": ["ns"]}},
        {"namespaceSelector": {"unknown": True}},
        {"namespaceSelector": {"any": "yes"}},
    ):
        with pytest.raises(DomainError):
            _target_namespaces(universe, sm, spec)
    for index in (-1, True, 2):
        with pytest.raises(DomainError):
            _endpoint(sm.data["spec"], "endpoints", index)
    sm_observation = evaluate_native_request(
        universe, _request(universe, "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1", sm.identity, {"expected_service": "v1/Service/ns/other"})
    )
    pm_observation = evaluate_native_request(
        universe, _request(universe, "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1", "monitoring.coreos.com/v1/PodMonitor/ns/pm")
    )
    assert sm_observation.result is NativePropertyResult.VIOLATED
    assert pm_observation.result is NativePropertyResult.SATISFIED


def test_rbac_complete_and_incomplete_domains(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    binding = "rbac.authorization.k8s.io/v1/RoleBinding/ns/binding"
    complete_subject = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", binding, {"complete_expected_domain": True})
    )
    incomplete_subject = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", binding)
    )
    assert complete_subject.result is NativePropertyResult.VIOLATED
    assert incomplete_subject.result is NativePropertyResult.NOT_EVALUATED
    assert _complete_domain({}) is False
    with pytest.raises(DomainError):
        _complete_domain({"complete_expected_domain": 1})
    role = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", binding)
    )
    assert role.result is NativePropertyResult.SATISFIED


def test_terraform_reference_helpers_and_negative_paths(tmp_path: Path) -> None:
    universe = _tf(tmp_path, """resource "thing" "target" {}
resource "thing" "source" {
  # brace } in a comment
  text = "brace { in string"
  peer = thing.target.id
  list = [thing.target.id]
}
""")
    source = universe.terraform_resource("thing.source")
    assert _attribute_value(source.body, ["peer"])
    assert _attribute_value(source.body, ["missing"]) is not None
    assert _references(["thing.target.id", {"x": 1}]) == (("thing.target", "thing.target.id"),)
    start, end = _resource_block_span(source)
    assert end > start
    with pytest.raises(DomainError, match="SPAN_AMBIGUOUS"):
        _reference_span(source, "thing.target.id")
    for value in ("var.x", "thing.target.id + 1", object()):
        with pytest.raises(DomainError):
            _references(value)
    with pytest.raises(DomainError):
        _attribute_value(source.body, [True])
    absent = evaluate_native_request(
        universe,
        _request(universe, "IACGV_TF_REFERENCE_RESOLVES_V1", "thing.source", {
            "attribute_path": ["missing"], "expected_target": "thing.target",
            "complete_expected_domain": True, "reference_contract_digest": "f" * 64,
        }),
    )
    assert absent.result is NativePropertyResult.VIOLATED
    incomplete = evaluate_native_request(
        universe,
        _request(universe, "IACGV_TF_REFERENCE_RESOLVES_V1", "thing.source", {
            "attribute_path": ["missing"], "expected_target": "thing.target"
        }),
    )
    assert incomplete.result is NativePropertyResult.NOT_EVALUATED


def test_engine_dispatch_error_and_report_exit_precedence(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    malformed = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", "apps/v1/Deployment/ns/missing"),
    )
    assert malformed.result is NativePropertyResult.ERROR
    violated = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", "apps/v1/Deployment/ns/source", request_id="violated")
    )
    report = NativePropertyReportV1.build(universe, (malformed, violated))
    assert report.exit_code == 4
    assert "ERROR=1" in render_native_console(report)
    with pytest.raises(DomainError):
        evaluate_native_requests(universe, [])  # type: ignore[arg-type]
    with pytest.raises(DomainError):
        NativePropertyReportV1.build(universe, ())


def _rehash_report(payload: dict) -> None:
    for observation in payload["observations"]:
        witness = observation["witness"]
        witness["witness_digest"] = canonical_digest({
            "witness_type": witness["witness_type"], "contents": witness["contents"]
        })
        body = dict(observation)
        body.pop("observation_digest")
        observation["observation_digest"] = canonical_digest(body)
    body = dict(payload)
    body.pop("report_digest")
    body.pop("exit_code")
    payload["report_digest"] = canonical_digest(body)


def test_serialized_report_semantic_mutation_matrix(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    observation = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", "apps/v1/Deployment/ns/dest")
    )
    report = NativePropertyReportV1.build(universe, (observation,))
    original = json.loads(report.canonical_json())
    mutators = (
        lambda p: p.update({"registry_identity": "0" * 64}),
        lambda p: p["observations"][0]["request"].update({"parameters_digest": "0" * 64}),
        lambda p: p["observations"][0]["witness"].update({"witness_type": "wrong"}),
        lambda p: p.update({"exit_code": 1}),
        lambda p: p["summary"].update({"TOTAL": 9}),
    )
    for mutate in mutators:
        payload = json.loads(json.dumps(original))
        mutate(payload)
        _rehash_report(payload)
        with pytest.raises(DomainError):
            validate_native_report_payload(payload)


def test_witness_validator_adversarial_derivations() -> None:
    with pytest.raises(DomainError):
        validate_native_witness_payload(witness_type="unknown", result=NativePropertyResult.SATISFIED, contents={})
    with pytest.raises(DomainError):
        validate_native_witness_payload(
            witness_type="k8s_network_path_v1", result=NativePropertyResult.SATISFIED,
            contents={"direction": "Ingress", "protected_workload": {}, "destination_port": 80,
                      "protocol": "TCP", "selecting_policies": ["p"],
                      "isolation_establishing_policies": ["p"], "policy_rule_evaluations": [],
                      "manifest_semantics_only": True},
        )
    with pytest.raises(DomainError):
        validate_native_witness_payload(
            witness_type="terraform_reference_v1", result=NativePropertyResult.VIOLATED,
            contents={"source": {}, "attribute_path": ["x"], "expected_target": "a.b",
                      "observed_references": [], "complete_local_universe": False,
                      "reference_contract_digest": None},
        )


def test_public_loader_path_and_type_failures(tmp_path: Path) -> None:
    with pytest.raises(DomainError):
        load_native_property_config("bad")  # type: ignore[arg-type]
    bad = tmp_path / "bad.json"
    bad.write_text("not-json", encoding="utf-8")
    with pytest.raises(DomainError):
        load_native_property_config(bad)
    with pytest.raises(DomainError):
        verify_native_properties(object())  # type: ignore[arg-type]
    source = NativeSourceFile("x", "0" * 64, 0)
    assert source.canonical_dict()["file_path"] == "x"


def test_observation_exact_type_guards(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    observation = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", "apps/v1/Deployment/ns/dest")
    )
    with pytest.raises(DomainError):
        NativePropertyObservation(
            object(), observation.definition, observation.result, observation.reason_code,
            observation.subject_provenance, observation.witness, observation.observation_digest,
        )
    with pytest.raises(DomainError):
        NativePropertyWitness(observation.witness.witness_type, observation.witness.contents, "0" * 64)
    assert PublicNativePropertyRun(universe, (observation.request,)).universe is universe


def test_engine_identity_dispatch_guards(tmp_path: Path, monkeypatch) -> None:
    universe = _kube(tmp_path, BASE)
    good = _request(
        universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1",
        "apps/v1/Deployment/ns/dest",
    )
    with pytest.raises(DomainError, match="exact protected universe"):
        evaluate_native_request(object(), good)  # type: ignore[arg-type]
    with pytest.raises(DomainError, match="exact request"):
        evaluate_native_request(universe, object())  # type: ignore[arg-type]
    with pytest.raises(DomainError, match="not in the packaged registry"):
        evaluate_native_request(universe, replace(good, property_id="IACGV_UNKNOWN_V1"))
    with pytest.raises(DomainError, match="version"):
        evaluate_native_request(universe, replace(good, property_version="2"))
    with pytest.raises(DomainError, match="artifact class"):
        evaluate_native_request(
            universe, replace(good, artifact_class=NativeArtifactClass.TERRAFORM_SOURCE)
        )
    from iac_guard_v.native_properties import engine

    monkeypatch.delitem(engine._EVALUATORS, good.property_id)
    with pytest.raises(DomainError, match="no packaged evaluator"):
        evaluate_native_request(universe, good)


def test_component_closure_complete_namespace_and_input_guards(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE + """---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: other, namespace: other}
spec: {podSelector: {}}
""")
    request = _request(
        universe, "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1", "component/ns/dest",
        {
            "workload_identities": ["apps/v1/Deployment/ns/dest"],
            "policy_identities": ["networking.k8s.io/v1/NetworkPolicy/ns/dest"],
            "membership_proof_digest": "f" * 64,
        },
    )
    assert evaluate_native_request(universe, request).result is NativePropertyResult.SATISFIED
    mismatched = replace(
        request,
        parameters=canonical_json({
            "workload_identities": ["apps/v1/Deployment/ns/dest"],
            "policy_identities": ["networking.k8s.io/v1/NetworkPolicy/other/other"],
            "membership_proof_digest": "f" * 64,
        }),
        parameters_digest=canonical_digest({
            "workload_identities": ["apps/v1/Deployment/ns/dest"],
            "policy_identities": ["networking.k8s.io/v1/NetworkPolicy/other/other"],
            "membership_proof_digest": "f" * 64,
        }),
    )
    assert evaluate_native_request(universe, mismatched).result is NativePropertyResult.VIOLATED
    for params in (
        {"workload_identities": [], "policy_identities": ["p"], "membership_proof_digest": "f" * 64},
        {"workload_identities": ["x"], "policy_identities": [], "membership_proof_digest": "f" * 64},
        {"workload_identities": ["x"], "policy_identities": ["p"], "membership_proof_digest": "short"},
    ):
        bad = NativePropertyRequest.build(
            request_id="bad-closure", property_id=request.property_id, property_version="1",
            artifact_class=universe.artifact_class, subject_identity="component/ns/x",
            parameters=params, protected_universe_identity=universe.identity,
        )
        with pytest.raises(DomainError):
            evaluate_component_closure(universe, bad)


def test_network_policy_malformed_rule_matrix(tmp_path: Path) -> None:
    cases = (
        "spec: {podSelector: {matchLabels: {app: dest}}, ingress: bad}",
        "spec: {podSelector: {matchLabels: {app: dest}}, ingress: [{from: bad}]}",
        "spec: {podSelector: {matchLabels: {app: dest}}, ingress: [{ports: bad}]}",
        "spec: {podSelector: {matchLabels: {app: dest}}, ingress: [{unexpected: true}]}",
    )
    for index, policy in enumerate(cases):
        root = tmp_path / str(index)
        root.mkdir()
        universe = _kube(root, """apiVersion: apps/v1
kind: Deployment
metadata: {name: dest}
spec: {template: {metadata: {labels: {app: dest}}, spec: {containers: [{name: c, image: x}]}}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: p}
""" + policy + "\n")
        observation = evaluate_native_request(
            universe,
            _request(universe, "IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1", "apps/v1/Deployment/default/dest", {
                "source": {"type": "IP", "ip": "192.0.2.1"}, "port": 80,
            }),
        )
        assert observation.result is NativePropertyResult.ERROR


def test_service_resolution_zero_unresolved_and_malformed(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {template: {metadata: {labels: {app: x}}, spec: {containers: [{name: c, image: x}]}}}
---
apiVersion: v1
kind: Service
metadata: {name: zero}
spec: {selector: {app: absent}, ports: [{name: web, port: 80}]}
---
apiVersion: v1
kind: Service
metadata: {name: unresolved}
spec: {selector: {app: x}, ports: [{name: web, port: 80, targetPort: missing}]}
---
apiVersion: v1
kind: Service
metadata: {name: malformed}
spec: {selector: {app: x}, ports: [{name: web, port: 0}]}
""")
    for name, expected in (("zero", "SERVICE_SELECTS_NO_WORKLOAD"), ("unresolved", "SERVICE_TARGET_PORT_UNRESOLVED")):
        observation = evaluate_native_request(
            universe,
            _request(universe, "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1", f"v1/Service/default/{name}", {"service_port": {"name": "web"}}),
        )
        assert observation.result is NativePropertyResult.NOT_EVALUATED
        assert observation.reason_code == expected
    malformed = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1", "v1/Service/default/malformed", {"service_port": {"name": "web"}}),
    )
    assert malformed.result is NativePropertyResult.ERROR


def test_monitor_fail_closed_variant_matrix(tmp_path: Path) -> None:
    variants = (
        ("sm-no-selector", "ServiceMonitor", "spec: {endpoints: [{port: web}]}", NativePropertyResult.NOT_EVALUATED),
        ("sm-target", "ServiceMonitor", "spec: {selector: {}, endpoints: [{targetPort: web}]}", NativePropertyResult.UNSUPPORTED),
        ("pm-both", "PodMonitor", "spec: {selector: {}, podMetricsEndpoints: [{port: web, portNumber: 80}]}", NativePropertyResult.NOT_EVALUATED),
        ("pm-number", "PodMonitor", "spec: {selector: {}, podMetricsEndpoints: [{portNumber: true}]}", NativePropertyResult.NOT_EVALUATED),
        ("pm-none", "PodMonitor", "spec: {selector: {}, podMetricsEndpoints: [{}]}", NativePropertyResult.NOT_EVALUATED),
        ("pm-target", "PodMonitor", "spec: {selector: {}, podMetricsEndpoints: [{targetPort: web}]}", NativePropertyResult.UNSUPPORTED),
    )
    manifests = ["""apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {template: {metadata: {labels: {app: x}}, spec: {containers: [{name: c, image: x, ports: [{name: web, containerPort: 80}]}]}}}
"""]
    for name, kind, spec, _ in variants:
        manifests.append(f"apiVersion: monitoring.coreos.com/v1\nkind: {kind}\nmetadata: {{name: {name}}}\n{spec}\n")
    universe = _kube(tmp_path, "---\n".join(manifests))
    for name, kind, _, expected in variants:
        property_id = (
            "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1"
            if kind == "ServiceMonitor" else "IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1"
        )
        observation = evaluate_native_request(
            universe, _request(universe, property_id, f"monitoring.coreos.com/v1/{kind}/default/{name}")
        )
        assert observation.result is expected
    wrong_subject = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1", "apps/v1/Deployment/default/app", {
            "source": {"type": "IP", "ip": "192.0.2.1"}
        }),
    )
    assert wrong_subject.result is NativePropertyResult.UNSUPPORTED


def test_rbac_unresolved_no_subject_and_malformed_matrix(tmp_path: Path) -> None:
    universe = _kube(tmp_path, """apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: missing, namespace: ns}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: absent}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: users, namespace: ns}
subjects: [{kind: User, name: x, apiGroup: rbac.authorization.k8s.io}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: absent}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: malformed, namespace: ns}
subjects: bad
roleRef: {apiGroup: wrong, kind: Role, name: x}
""")
    missing = "rbac.authorization.k8s.io/v1/RoleBinding/ns/missing"
    assert evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", missing)
    ).result is NativePropertyResult.NOT_EVALUATED
    assert evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", missing, {"complete_expected_domain": True})
    ).result is NativePropertyResult.VIOLATED
    users = "rbac.authorization.k8s.io/v1/RoleBinding/ns/users"
    no_subject = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", users)
    )
    assert no_subject.reason_code == "NO_SERVICEACCOUNT_SUBJECTS"
    malformed = "rbac.authorization.k8s.io/v1/RoleBinding/ns/malformed"
    assert evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", malformed)
    ).result is NativePropertyResult.ERROR
    assert evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1", malformed)
    ).result is NativePropertyResult.ERROR


def test_terraform_target_instance_and_span_ambiguity(tmp_path: Path) -> None:
    universe = _tf(tmp_path, """resource "thing" "target" { count = 1 }
resource "thing" "source" {
  peer = thing.target.id
  duplicate = thing.target.id
}
""")
    target_instance = evaluate_native_request(
        universe,
        _request(universe, "IACGV_TF_REFERENCE_RESOLVES_V1", "thing.source", {
            "attribute_path": ["peer"], "expected_target": "thing.target",
            "complete_expected_domain": True, "reference_contract_digest": "f" * 64,
        }),
    )
    assert target_instance.reason_code == "TERRAFORM_INSTANCE_IDENTITY_UNRESOLVED"
    # Removing instance expansion reaches the duplicate source-span fail-closed branch.
    other = tmp_path / "span"
    other.mkdir()
    span_universe = _tf(other, """resource "thing" "target" {}
resource "thing" "source" {
  peer = "thing.target.id thing.target.id"
}
""")
    ambiguous = evaluate_native_request(
        span_universe,
        _request(span_universe, "IACGV_TF_REFERENCE_RESOLVES_V1", "thing.source", {
            "attribute_path": ["peer"], "expected_target": "thing.target",
        }),
    )
    assert ambiguous.result is NativePropertyResult.NOT_EVALUATED
    assert ambiguous.reason_code == "TERRAFORM_REFERENCE_SOURCE_SPAN_AMBIGUOUS"


def test_report_builder_and_payload_guard_matrix(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE)
    observation = evaluate_native_request(
        universe, _request(universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", "apps/v1/Deployment/ns/dest")
    )
    with pytest.raises(DomainError):
        NativePropertyReportV1.build(object(), (observation,))  # type: ignore[arg-type]
    with pytest.raises(DomainError):
        NativePropertyReportV1.build(universe, [observation])  # type: ignore[arg-type]
    with pytest.raises(DomainError):
        NativePropertyReportV1.build(universe, (observation, observation))
    original = json.loads(NativePropertyReportV1.build(universe, (observation,)).canonical_json())
    mutations = (
        ("request-shape", lambda p: p["observations"][0]["request"].update({"extra": True})),
        ("definition", lambda p: p["observations"][0].update({"definition": {}})),
        ("version", lambda p: p["observations"][0]["request"].update({"property_version": "2"})),
        ("parameters", lambda p: p["observations"][0]["request"].update({"parameters": {"policy_identity": 1}})),
        ("result", lambda p: p["observations"][0].update({"result": "INVALID"})),
    )
    for name, mutate in mutations:
        payload = json.loads(json.dumps(original))
        mutate(payload)
        request = payload["observations"][0]["request"]
        request["parameters_digest"] = canonical_digest(request.get("parameters"))
        _rehash_report(payload)
        try:
            validate_native_report_payload(payload)
        except DomainError:
            continue
        raise AssertionError(f"report mutation {name} was accepted")


@pytest.mark.parametrize(
    ("witness_type", "result", "contents"),
    [
        ("k8s_network_policy_selection_v1", NativePropertyResult.SATISFIED,
         {"workload": {}, "namespace": "ns", "policy_evaluations": [], "selecting_policies": []}),
        ("k8s_network_policy_isolation_v1", NativePropertyResult.SATISFIED,
         {"workload": {}, "direction": "Ingress", "selecting_policy_types": [], "isolation_establishing_policies": []}),
        ("k8s_component_policy_closure_v1", NativePropertyResult.SATISFIED,
         {"component_identity": "x", "membership_proof_digest": "f" * 64,
          "members": [{"workload": {"identity": "w"}, "selecting_policies": []}], "uncovered_workloads": []}),
        ("k8s_service_selection_v1", NativePropertyResult.SATISFIED,
         {"service": {}, "service_selector": {}, "candidate_workloads": [], "matched_workloads": [], "expectation": "ANY_NONEMPTY"}),
        ("k8s_service_port_resolution_v1", NativePropertyResult.SATISFIED,
         {"service": {}, "service_port": {}, "candidate_workloads": [], "matched_workloads": [],
          "resolutions": [], "resolved_port_set": [], "unresolved_workloads": []}),
        ("k8s_pod_network_path_v1", NativePropertyResult.SATISFIED,
         {"source_workload": {}, "destination_port": 80, "protocol": "TCP",
          "destination_results": [], "manifest_semantics_only": True}),
        ("prometheus_monitor_resolution_v1", NativePropertyResult.SATISFIED,
         {"monitor": {}, "contract_digest": "f" * 64, "namespace_selection": [],
          "endpoint_index": 0, "matched_services": []}),
        ("prometheus_monitoring_ingress_v1", NativePropertyResult.SATISFIED,
         {"monitor_resolution": {}, "source_contract": {}, "target_evaluations": [],
          "manifest_semantics_only": True}),
        ("k8s_rbac_role_ref_v1", NativePropertyResult.SATISFIED,
         {"binding": {}, "binding_kind": "RoleBinding", "role_ref": {},
          "scope_state": "NAMESPACED_ROLE", "resolved_target": None, "authorization_simulated": False}),
        ("k8s_rbac_subject_v1", NativePropertyResult.SATISFIED,
         {"binding": {}, "service_account_subjects": [], "authorization_simulated": False}),
        ("k8s_rbac_scope_v1", NativePropertyResult.SATISFIED,
         {"binding": {}, "role_ref_scope": "SCOPE_INCONSISTENT",
          "service_account_subjects": [], "authorization_simulated": False}),
    ],
)
def test_witness_result_contradiction_matrix(witness_type, result, contents) -> None:
    with pytest.raises(DomainError):
        validate_native_witness_payload(witness_type=witness_type, result=result, contents=contents)


def test_network_rule_witness_rejects_integer_truth_alias() -> None:
    contents = {
        "direction": "Ingress", "protected_workload": {}, "destination_port": 80,
        "protocol": "TCP", "selecting_policies": ["p"],
        "isolation_establishing_policies": ["p"], "manifest_semantics_only": True,
        "policy_rule_evaluations": [{"rule_evaluations": [{
            "peer_evaluations": [{"matched": 1}],
            "port_evaluations": [{"matched": True}], "matched": True,
        }]}],
    }
    with pytest.raises(DomainError, match="invalid match value"):
        validate_native_witness_payload(
            witness_type="k8s_network_path_v1",
            result=NativePropertyResult.SATISFIED,
            contents=contents,
        )


def test_witness_validator_structural_and_runtime_boundary_guards() -> None:
    with pytest.raises(DomainError, match="missing fields"):
        validate_native_witness_payload(
            witness_type="k8s_network_policy_selection_v1",
            result=NativePropertyResult.SATISFIED,
            contents={},
        )
    with pytest.raises(DomainError, match="workload inventories"):
        validate_native_witness_payload(
            witness_type="k8s_service_selection_v1",
            result=NativePropertyResult.SATISFIED,
            contents={
                "service": {}, "service_selector": {}, "candidate_workloads": {},
                "matched_workloads": [], "expectation": "ANY_NONEMPTY",
            },
        )
    with pytest.raises(DomainError, match="selector result"):
        validate_native_witness_payload(
            witness_type="k8s_service_selection_v1",
            result=NativePropertyResult.SATISFIED,
            contents={
                "service": {}, "service_selector": {},
                "candidate_workloads": [{
                    "identity": "w", "selector_evaluation": {"matched": True}
                }],
                "matched_workloads": [], "expectation": "ANY_NONEMPTY",
            },
        )
    for witness_type, contents, message in (
        (
            "k8s_network_path_v1",
            {
                "direction": "Ingress", "protected_workload": {},
                "destination_port": 80, "protocol": "TCP",
                "selecting_policies": [], "isolation_establishing_policies": [],
                "policy_rule_evaluations": [], "manifest_semantics_only": False,
            },
            "runtime boundary",
        ),
        (
            "k8s_pod_network_path_v1",
            {
                "source_workload": {}, "destination_port": 80, "protocol": "TCP",
                "destination_results": [{
                    "egress": {"result": "SATISFIED"},
                    "ingress": {"result": "SATISFIED"},
                }],
                "manifest_semantics_only": False,
            },
            "runtime boundary",
        ),
        (
            "prometheus_monitoring_ingress_v1",
            {
                "monitor_resolution": {}, "source_contract": {},
                "target_evaluations": [{"result": "SATISFIED"}],
                "manifest_semantics_only": False,
            },
            "runtime boundary",
        ),
    ):
        with pytest.raises(DomainError, match=message):
            validate_native_witness_payload(
                witness_type=witness_type,
                result=NativePropertyResult.SATISFIED,
                contents=contents,
            )


def test_monitor_low_level_schema_and_namespace_guards(tmp_path: Path) -> None:
    universe = _kube(tmp_path, BASE + """---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: sm, namespace: ns}
spec: {selector: {}, endpoints: [{port: web}]}
""")
    sm = universe.kubernetes_resource("monitoring.coreos.com/v1/ServiceMonitor/ns/sm")
    assert _target_namespaces(
        universe, sm, {"namespaceSelector": {"matchNames": ["ns", "other"]}}
    ) == ("ns", "other")
    for spec in (
        {"namespaceSelector": []},
        {"namespaceSelector": {"matchNames": [1]}},
    ):
        with pytest.raises(DomainError):
            _target_namespaces(universe, sm, spec)
    for spec in (
        {},
        {"endpoints": []},
        {"endpoints": [{"unknown": True}]},
        {"endpoints": [{"port": "web", "relabelings": []}]},
    ):
        with pytest.raises(DomainError):
            _endpoint(spec, "endpoints", 0)


def test_terraform_direct_evaluator_and_parser_guard_branches(tmp_path: Path) -> None:
    universe = _tf(tmp_path, """resource "thing" "target" {}
resource "thing" "source" { peer = thing.target.id }
""")
    source = universe.terraform_resource("thing.source")
    assert _attribute_value(source.body, ["peer", 99]) is not None
    for path in ([], ["peer", True]):
        request = _request(
            universe, "IACGV_TF_REFERENCE_RESOLVES_V1", "thing.source",
            {"attribute_path": path, "expected_target": "thing.target"},
        )
        with pytest.raises(DomainError):
            evaluate_reference_resolves(universe, request)
    bad_complete = _request(
        universe, "IACGV_TF_REFERENCE_RESOLVES_V1", "thing.source",
        {
            "attribute_path": ["peer"], "expected_target": "thing.target",
            "complete_expected_domain": 1,
        },
    )
    with pytest.raises(DomainError, match="exact bool"):
        evaluate_reference_resolves(universe, bad_complete)
    with pytest.raises(DomainError, match="RESOURCE_SPAN_AMBIGUOUS"):
        _resource_block_span(replace(source, source_text="resource \"thing\" \"other\" {}"))
