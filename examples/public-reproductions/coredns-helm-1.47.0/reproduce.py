#!/usr/bin/env python3
"""Create the exact public-a9 CoreDNS 1.47.0 negative/positive witness pair."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from iac_guard_v.native_properties import (
    NativeArtifactClass,
    NativePropertyRequest,
    evaluate_native_requests,
    load_protected_native_universe,
    native_registry_identity,
)
from iac_guard_v.native_properties.report import NativePropertyReportV1


RELEASE_COMMIT = "fd5b836b84e80f6ca5be9b59b77e4d2dd3505467"
RELEASE_TREE = "7e1d80e7366f7f97f65fc91debf4f4fd989657a4"
PROPERTY = "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1"
MONITOR = "monitoring.coreos.com/v1/ServiceMonitor/default/a9-impact-coredns"
EXPECTED_SERVICE = "v1/Service/a9-impact/a9-impact-coredns-metrics"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def git_value(root: Path, expression: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", expression], text=True
    ).strip()


def render_twice(
    helm: Path, source: Path, destination: Path, service_enabled: bool
) -> tuple[bytes, list[str]]:
    command = [
        str(helm),
        "template",
        "a9-impact",
        str(source / "charts/coredns"),
        "--namespace",
        "a9-impact",
        "--skip-tests",
        "--api-versions",
        "monitoring.coreos.com/v1/ServiceMonitor",
        "--set",
        "prometheus.monitor.enabled=true",
        "--set",
        f"prometheus.service.enabled={'true' if service_enabled else 'false'}",
    ]
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(destination / "home"),
        "HELM_CACHE_HOME": str(destination / "helm-cache"),
        "HELM_CONFIG_HOME": str(destination / "helm-config"),
        "HELM_DATA_HOME": str(destination / "helm-data"),
    }
    outputs = []
    for number in (1, 2):
        completed = subprocess.run(
            command, env=environment, capture_output=True, check=True
        )
        (destination / f"render-{number}.yaml").write_bytes(completed.stdout)
        (destination / f"render-{number}.stderr").write_bytes(completed.stderr)
        outputs.append(completed.stdout)
    if outputs[0] != outputs[1]:
        raise RuntimeError("render pair is not byte-identical")
    protected = destination / "protected"
    protected.mkdir()
    (protected / "objects.yaml").write_bytes(outputs[0])
    return outputs[0], [
        "helm", *command[1:3], "<COREDNS_RELEASE_SOURCE>/charts/coredns", *command[4:]
    ]


def evaluate(destination: Path, request_id: str) -> dict[str, object]:
    universe = load_protected_native_universe(
        destination / "protected", NativeArtifactClass.KUBERNETES_RENDERED
    )
    request = NativePropertyRequest.build(
        request_id=request_id,
        property_id=PROPERTY,
        property_version="1",
        artifact_class=universe.artifact_class,
        subject_identity=MONITOR,
        parameters={"endpoint_index": 0, "expected_service": EXPECTED_SERVICE},
        protected_universe_identity=universe.identity,
    )
    observations = evaluate_native_requests(universe, (request,))
    report = NativePropertyReportV1.build(universe, observations)
    report_bytes = report.canonical_json().encode()
    (destination / "native-property-report-v1.json").write_bytes(report_bytes)
    observation = observations[0]
    return {
        "protected_universe_identity": universe.identity,
        "report_sha256": digest(report_bytes),
        "report_digest": report.report_digest,
        "result": observation.result.value,
        "reason_code": observation.reason_code,
        "witness_digest": observation.witness.witness_digest,
        "witness": observation.witness.canonical_dict(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--helm", default="helm", type=Path)
    arguments = parser.parse_args()
    source = arguments.source.resolve()
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if git_value(source, "HEAD") != RELEASE_COMMIT:
        raise RuntimeError("release commit mismatch")
    if git_value(source, "HEAD^{tree}") != RELEASE_TREE:
        raise RuntimeError("release tree mismatch")

    cases = []
    for name, service_enabled, expected in (
        ("monitor-on-service-off", False, "VIOLATED"),
        ("monitor-on-service-on", True, "SATISFIED"),
    ):
        destination = output / name
        destination.mkdir()
        rendered, command = render_twice(
            arguments.helm, source, destination, service_enabled
        )
        native = evaluate(destination, f"coredns-1470-{name}")
        if native["result"] != expected:
            raise RuntimeError(f"{name}: expected {expected}, got {native['result']}")
        cases.append(
            {
                "case": name,
                "configuration": {
                    "prometheus.monitor.enabled": True,
                    "prometheus.service.enabled": service_enabled,
                },
                "command": command,
                "render_pair_byte_identical": True,
                "render_sha256": digest(rendered),
                **native,
            }
        )

    record = {
        "schema": "coredns-1470-final-ab-v1",
        "repository": "https://github.com/coredns/helm",
        "release": "coredns-1.47.0",
        "source_commit": RELEASE_COMMIT,
        "source_tree": RELEASE_TREE,
        "iac_guard_v_version": "0.1.0a9",
        "iac_guard_v_registry_identity": native_registry_identity(),
        "property": PROPERTY,
        "property_version": "1",
        "cases": cases,
    }
    record_bytes = canonical_json(record)
    (output / "execution.json").write_bytes(record_bytes)
    print(digest(record_bytes))


if __name__ == "__main__":
    main()
