#!/usr/bin/env python3
"""Reproduce the public IaC-Guard-V a10 Falco 9.1.0 A/B evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

import iac_guard_v
from iac_guard_v.contracts import ContractExecutionInput, prepare_contract_run
from iac_guard_v.contracts.model import ContractProvenance
from iac_guard_v.contracts.report import validate_contract_report_payload
from iac_guard_v.native_properties import native_registry_identity
import yaml


RELEASE_COMMIT = "53586de4fb9d8d02006131ade702b161cd7e06e3"
RELEASE_TREE = "ce376e495fdb9ee84daf44b118adc759090bd231"
CHART_SHA256 = "2a767d6aeccf2392c5e263ae1f5e0950520affe3a9908ff7986ac213649c45b4"
PROPERTY = "IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1"
MONITOR = "monitoring.coreos.com/v1/ServiceMonitor/a10-impact/a10-impact-falco"
SERVICE = "v1/Service/a10-impact/a10-impact-falco-metrics"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def git_value(root: Path, expression: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", expression], text=True
    ).strip()


def render_twice(
    helm: Path, chart: Path, destination: Path, metrics_enabled: bool
) -> tuple[bytes, list[str]]:
    command = [
        str(helm),
        "template",
        "a10-impact",
        str(chart),
        "--namespace",
        "a10-impact",
        "--skip-tests",
        "--kube-version",
        "1.34.0",
        "--api-versions",
        "monitoring.coreos.com/v1/ServiceMonitor",
        "--set",
        "serviceMonitor.create=true",
        "--set",
        f"metrics.enabled={'true' if metrics_enabled else 'false'}",
        "--set",
        "metrics.service.create=true",
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
    public_command = [
        "helm",
        *command[1:3],
        "<FALCO_9_1_0_CHART>",
        *command[4:],
    ]
    return outputs[0], public_command


def evaluate(
    contract: Path,
    destination: Path,
    metrics_enabled: bool,
) -> dict[str, object]:
    protected = destination / "protected"
    protected.mkdir()
    (protected / "objects.yaml").write_bytes(
        (destination / "render-1.yaml").read_bytes()
    )
    activation = destination / "effective-values.yaml"
    activation.write_text(
        "serviceMonitor:\n  create: true\n"
        f"metrics:\n  enabled: {'true' if metrics_enabled else 'false'}\n"
        "  service:\n    create: true\n",
        encoding="utf-8",
    )
    with prepare_contract_run(
        ContractExecutionInput(
            contract_path=contract,
            project_root=destination,
            protected_root=protected,
            activation_values_path=activation,
            requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
            source_commit=RELEASE_COMMIT,
            default_namespace="a10-impact",
        )
    ) as run:
        payload = run.report.canonical_dict()
        validate_contract_report_payload(payload)
        native = run.report.clauses[0].native_observations[0]
        return {
            "report": payload,
            "contract_result": run.report.result.value,
            "contract_reason": run.report.reason_code,
            "native_result": native.result.value,
            "native_reason": native.reason_code,
            "native_witness_digest": native.witness.witness_digest,
            "matched_services": list(native.witness.contents["matched_services"]),
            "protected_universe_identity": run.universe.identity,
            "resource_inventory": [
                item.identity for item in run.universe.kubernetes_resources
            ],
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--chart-archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--helm", default="helm", type=Path)
    arguments = parser.parse_args()
    source = arguments.source.resolve(strict=True)
    archive = arguments.chart_archive.resolve(strict=True)
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    contract = Path(__file__).with_name("CONTRACT.yaml").resolve(strict=True)
    helm = arguments.helm.resolve(strict=True)

    if iac_guard_v.__version__ != "0.1.0a10":
        raise RuntimeError("public IaC-Guard-V 0.1.0a10 is required")
    if git_value(source, "HEAD") != RELEASE_COMMIT:
        raise RuntimeError("release commit mismatch")
    if git_value(source, "HEAD^{tree}") != RELEASE_TREE:
        raise RuntimeError("release tree mismatch")
    if digest(archive.read_bytes()) != CHART_SHA256:
        raise RuntimeError("published chart archive digest mismatch")

    cases = []
    reports = {}
    with tempfile.TemporaryDirectory(prefix="iacgv-falco-910-") as temporary:
        temporary_root = Path(temporary)
        chart_parent = temporary_root / "published-chart"
        chart_parent.mkdir()
        with tarfile.open(archive, "r:gz") as package:
            package.extractall(chart_parent, filter="data")
        chart = (chart_parent / "falco").resolve(strict=True)
        defaults = yaml.safe_load((chart / "values.yaml").read_text(encoding="utf-8"))
        if defaults["serviceMonitor"]["create"] is not False:
            raise RuntimeError("released ServiceMonitor default changed")
        if defaults["metrics"]["enabled"] is not False:
            raise RuntimeError("released metrics default changed")
        if defaults["metrics"]["service"]["create"] is not True:
            raise RuntimeError("released metrics Service default changed")
        for name, metrics_enabled, expected in (
            ("monitor-on-metrics-off", False, "VIOLATED"),
            ("monitor-on-metrics-on", True, "SATISFIED"),
        ):
            destination = temporary_root / name
            destination.mkdir()
            rendered, command = render_twice(
                helm, chart, destination, metrics_enabled
            )
            evaluated = evaluate(
                contract, destination, metrics_enabled
            )
            if evaluated["contract_result"] != expected:
                raise RuntimeError(
                    f"{name}: expected {expected}, got {evaluated['contract_result']}"
                )
            manifest = evaluated["report"]["protected_universe"]["input_manifest"]
            if len(manifest) != 1 or manifest[0]["sha256"] != digest(rendered):
                raise RuntimeError("contract render and direct render identity disagree")
            report_name = (
                "REPORT_CASE_A_A10.json"
                if not metrics_enabled
                else "REPORT_CASE_B_A10.json"
            )
            report_bytes = canonical_json(evaluated.pop("report"))
            (output / report_name).write_bytes(report_bytes)
            reports[name] = digest(report_bytes)
            cases.append(
                {
                    "case": name,
                    "configuration": {
                        "serviceMonitor.create": True,
                        "metrics.enabled": metrics_enabled,
                        "metrics.service.create": True,
                    },
                    "command": command,
                    "render_pair_byte_identical": True,
                    "render_sha256": digest(rendered),
                    "report_file": report_name,
                    "report_sha256": reports[name],
                    **evaluated,
                }
            )

    record = {
        "schema": "falco-helm-910-a10-final-ab-v1",
        "repository": "https://github.com/falcosecurity/charts",
        "release": "falco-9.1.0",
        "source_commit": RELEASE_COMMIT,
        "source_tree": RELEASE_TREE,
        "published_chart_sha256": CHART_SHA256,
        "iac_guard_v_version": iac_guard_v.__version__,
        "iac_guard_v_registry_identity": native_registry_identity(),
        "contract_provenance": "RESEARCH_HYPOTHESIS",
        "property": PROPERTY,
        "property_version": "1",
        "monitor_identity": MONITOR,
        "expected_service_identity": SERVICE,
        "cases": cases,
    }
    record_bytes = canonical_json(record)
    (output / "A_B_EXECUTION.json").write_bytes(record_bytes)
    print(digest(record_bytes))


if __name__ == "__main__":
    main()
