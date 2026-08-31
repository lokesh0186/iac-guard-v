from __future__ import annotations

import json
from pathlib import Path

import pytest

from iac_guard_v.models import DomainError
from iac_guard_v.native_properties.__main__ import main
from iac_guard_v.native_properties.public import (
    load_native_property_config,
    verify_native_properties,
)
from iac_guard_v.native_properties.report import validate_native_report_payload


def _config(tmp_path: Path) -> Path:
    manifests = tmp_path / "rendered"
    manifests.mkdir()
    (manifests / "objects.yaml").write_text("""apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: demo}
spec:
  template:
    metadata: {labels: {app: demo}}
    spec: {containers: [{name: app, image: example}]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: app, namespace: demo}
spec: {podSelector: {matchLabels: {app: demo}}, ingress: []}
""", encoding="utf-8")
    config = tmp_path / "native.json"
    config.write_text(json.dumps({
        "schema_version": "native-property-request-v1",
        "root": "rendered",
        "artifact_class": "kubernetes_rendered",
        "requests": [{
            "request_id": "selection",
            "property_id": "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1",
            "property_version": "1",
            "subject_identity": "apps/v1/Deployment/demo/app",
            "parameters": {},
        }],
    }), encoding="utf-8")
    return config


def test_public_loader_and_native_report(tmp_path: Path) -> None:
    report = verify_native_properties(load_native_property_config(_config(tmp_path)))
    payload = json.loads(report.canonical_json())
    validate_native_report_payload(payload)
    assert report.exit_code == 0
    assert payload["schema_version"] == "native-property-report-v1"
    assert payload["observations"][0]["result"] == "SATISFIED"
    assert payload["product_semantics"].startswith("scanner-independent")


def test_native_cli_json_and_console(tmp_path: Path, capsys) -> None:
    config = _config(tmp_path)
    assert main(["--config", str(config), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["SATISFIED"] == 1
    assert main(["--config", str(config), "--format", "console"]) == 0
    output = capsys.readouterr().out
    assert "manifest semantics only" in output
    assert "project-defect claim" in output


def test_public_loader_rejects_escape_and_unknown_fields(tmp_path: Path) -> None:
    config = _config(tmp_path)
    payload = json.loads(config.read_text(encoding="utf-8"))
    payload["unknown"] = True
    config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DomainError, match="contract violation"):
        load_native_property_config(config)
    payload.pop("unknown")
    payload["root"] = "../outside"
    config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DomainError):
        load_native_property_config(config)


def test_serialized_semantic_witness_tamper_is_rejected(tmp_path: Path) -> None:
    report = verify_native_properties(load_native_property_config(_config(tmp_path)))
    payload = json.loads(report.canonical_json())
    observation = payload["observations"][0]
    observation["witness"]["contents"]["selecting_policies"] = []
    # A caller who recomputes only outer hashes still cannot bypass result/witness logic.
    from iac_guard_v.native_properties.model import canonical_digest

    observation["witness"]["witness_digest"] = canonical_digest({
        "witness_type": observation["witness"]["witness_type"],
        "contents": observation["witness"]["contents"],
    })
    body = dict(observation)
    body.pop("observation_digest")
    observation["observation_digest"] = canonical_digest(body)
    report_body = dict(payload)
    report_body.pop("report_digest")
    report_body.pop("exit_code")
    payload["report_digest"] = canonical_digest(report_body)
    with pytest.raises(DomainError, match="contradictory|witness/result"):
        validate_native_report_payload(payload)
