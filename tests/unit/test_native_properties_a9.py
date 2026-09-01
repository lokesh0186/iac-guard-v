from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
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
    native_registry_identity,
)
from iac_guard_v.native_properties.model import (
    NativePropertyWitness,
    canonical_digest,
    canonical_json,
    thaw_json,
)
from iac_guard_v.native_properties.report import (
    NativePropertyReportV1,
    validate_native_report_payload,
)
from iac_guard_v.native_properties.selectors import (
    evaluate_label_selector,
    normalize_label_selector,
    service_selector_as_label_selector,
)


def _write(root: Path, name: str, text: str) -> None:
    (root / name).write_text(text, encoding="utf-8")


def _request(universe, property_id: str, subject: str, parameters=None, request_id="r1"):
    return NativePropertyRequest.build(
        request_id=request_id,
        property_id=property_id,
        property_version="1",
        artifact_class=universe.artifact_class,
        subject_identity=subject,
        parameters=parameters or {},
        protected_universe_identity=universe.identity,
    )


def test_registry_is_closed_versioned_and_scanner_independent() -> None:
    assert len(NATIVE_PROPERTY_REGISTRY) == 18
    assert "IACGV_OPENTOFU_REFERENCE_RESOLVES_V1" in NATIVE_PROPERTY_REGISTRY
    assert len(native_registry_identity()) == 64
    assert all(item.property_namespace == "iac_guard_v" for item in NATIVE_PROPERTY_REGISTRY.values())
    assert all(item.property_version == "1" for item in NATIVE_PROPERTY_REGISTRY.values())
    assert not any("checkov" in item.opaque_id.lower() for item in NATIVE_PROPERTY_REGISTRY.values())
    deferred = {
        "ALLOW_PRIVILEGE_ESCALATION", "RUN_AS_NON_ROOT", "READ_ONLY_ROOT_FILESYSTEM",
        "CAPABILITIES_DROP", "SECCOMP_PROFILE", "ATTRIBUTE_EQUALS", "ATTRIBUTE_PRESENT",
    }
    assert not any(any(token in key for token in deferred) for key in NATIVE_PROPERTY_REGISTRY)


def test_implementation_identity_binds_shared_semantic_dependencies() -> None:
    network = NATIVE_PROPERTY_REGISTRY["IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1"]
    network_modules = {item[0] for item in network.implementation.module_digests}
    assert {
        "native_properties.engine",
        "native_properties.evidence",
        "native_properties.network_policy",
        "native_properties.selectors",
        "native_properties.services",
        "native_properties.universe",
    } <= network_modules
    terraform = NATIVE_PROPERTY_REGISTRY["IACGV_TF_REFERENCE_RESOLVES_V1"]
    assert "terraform_parser" in {item[0] for item in terraform.implementation.module_digests}


def test_canonical_json_is_deeply_immutable_and_typed() -> None:
    source = {"z": [1, {"a": True}], "a": None}
    frozen = canonical_json(source)
    source["z"][1]["a"] = False
    assert thaw_json(frozen) == {"a": None, "z": [1, {"a": True}]}
    with pytest.raises(TypeError):
        frozen["x"] = 1
    with pytest.raises(DomainError, match="unsupported JSON type"):
        canonical_json({"bad": 1.5})
    with pytest.raises(DomainError, match="keys"):
        canonical_json({1: "bad"})


def test_request_and_witness_reject_forged_digests() -> None:
    digest = "0" * 64
    with pytest.raises(DomainError, match="parameters digest"):
        NativePropertyRequest(
            "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", "1",
            NativeArtifactClass.KUBERNETES_RENDERED,
            "apps/v1/Deployment/default/app", {}, digest, digest, "r",
        )
    with pytest.raises(DomainError, match="witness digest"):
        NativePropertyWitness("test", {"x": 1}, digest)
    witness = NativePropertyWitness.build("test", {"x": [1]})
    with pytest.raises(FrozenInstanceError):
        witness.witness_digest = digest


def test_selectors_cover_all_reviewed_operators_and_empty_semantics() -> None:
    selector = {
        "matchLabels": {"app": "demo"},
        "matchExpressions": [
            {"key": "tier", "operator": "In", "values": ["api", "web"]},
            {"key": "old", "operator": "NotIn", "values": ["yes"]},
            {"key": "metrics", "operator": "Exists"},
            {"key": "disabled", "operator": "DoesNotExist"},
        ],
    }
    result = evaluate_label_selector(
        selector, {"app": "demo", "tier": "api", "old": "no", "metrics": "yes"}
    )
    assert result.matched
    assert len(result.expressions) == 5
    assert evaluate_label_selector({}, {}).matched
    assert evaluate_label_selector(
        {"matchExpressions": [{"key": "missing", "operator": "NotIn", "values": ["x"]}]},
        {},
    ).matched
    assert service_selector_as_label_selector({"app": "x"})["matchLabels"]["app"] == "x"


@pytest.mark.parametrize(
    "selector",
    [
        {"unsupported": {}},
        {"matchExpressions": "bad"},
        {"matchExpressions": [{"key": "x", "operator": "Bogus"}]},
        {"matchExpressions": [{"key": "x", "operator": "In", "values": []}]},
        {"matchExpressions": [{"key": "x", "operator": "Exists", "values": ["x"]}]},
        {"matchLabels": {"x": 3}},
    ],
)
def test_malformed_selectors_fail_closed(selector) -> None:
    with pytest.raises(DomainError):
        normalize_label_selector(selector)


def test_duplicate_kubernetes_identity_rejected(tmp_path: Path) -> None:
    manifest = """apiVersion: v1
kind: Service
metadata: {name: duplicate}
spec: {selector: {app: x}, ports: [{port: 80}]}
"""
    _write(tmp_path, "a.yaml", manifest)
    _write(tmp_path, "b.yaml", manifest)
    with pytest.raises(DomainError, match="duplicate canonical Kubernetes"):
        load_protected_native_universe(
            tmp_path, NativeArtifactClass.KUBERNETES_RENDERED
        )


def test_request_binding_and_duplicate_request_ids_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "pod.yaml", """apiVersion: v1
kind: Pod
metadata: {name: p, labels: {app: x}}
spec: {containers: [{name: c, image: x}]}
""")
    universe = load_protected_native_universe(
        tmp_path, NativeArtifactClass.KUBERNETES_RENDERED
    )
    request = _request(
        universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", "v1/Pod/default/p"
    )
    forged = NativePropertyRequest.build(
        request_id="bad",
        property_id=request.property_id,
        property_version="1",
        artifact_class=request.artifact_class,
        subject_identity=request.subject_identity,
        parameters={},
        protected_universe_identity="0" * 64,
    )
    with pytest.raises(DomainError, match="different protected universe"):
        evaluate_native_request(universe, forged)
    with pytest.raises(DomainError, match="request IDs"):
        evaluate_native_requests(universe, (request, request))


def test_report_digest_schema_and_exit_semantics(tmp_path: Path) -> None:
    _write(tmp_path, "pod.yaml", """apiVersion: v1
kind: Pod
metadata: {name: p, labels: {app: x}}
spec: {containers: [{name: c, image: x}]}
""")
    universe = load_protected_native_universe(
        tmp_path, NativeArtifactClass.KUBERNETES_RENDERED
    )
    observation = evaluate_native_request(
        universe,
        _request(universe, "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1", "v1/Pod/default/p"),
    )
    assert observation.result is NativePropertyResult.VIOLATED
    report = NativePropertyReportV1.build(universe, (observation,))
    payload = json.loads(report.canonical_json())
    assert report.exit_code == 1
    assert payload["summary"]["VIOLATED"] == 1
    assert payload["summary"]["TOTAL"] == 1
    payload["report_digest"] = "0" * 64
    with pytest.raises(DomainError, match="digest"):
        validate_native_report_payload(payload)
