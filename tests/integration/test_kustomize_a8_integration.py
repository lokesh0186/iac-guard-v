"""Pinned Kustomize a8 offline/double-build compatibility integration."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from iac_guard_v.kustomize import KustomizeBuildSpec, materialize_kustomize


def _locked_executable() -> Path:
    raw = os.environ.get("IACGV_KUSTOMIZE_EXECUTABLE", "")
    if not raw:
        local_probe = Path("/private/tmp/iacgv-kustomize-5.7.1/kustomize")
        if local_probe.is_file():
            raw = str(local_probe)
    if not raw:
        pytest.skip("IACGV_KUSTOMIZE_EXECUTABLE is not configured")
    path = Path(raw)
    if not path.is_file():
        pytest.fail("configured Kustomize executable is unavailable")
    return path


def test_pinned_engine_builds_exact_protected_transform_universe(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo}\n"
        "spec:\n  replicas: 1\n  selector: {matchLabels: {app: demo}}\n"
        "  template:\n    metadata: {labels: {app: demo}}\n"
        "    spec:\n      containers:\n      - {name: app, image: nginx:1.0}\n",
        encoding="utf-8",
    )
    (repository / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
        "resources: [deployment.yaml]\nnamespace: research\nnamePrefix: pre-\n"
        "commonLabels: {team: platform}\n"
        "images:\n- {name: nginx, newName: registry.example/nginx, newTag: '2.0'}\n"
        "patches:\n- target: {kind: Deployment, name: demo}\n"
        "  patch: |-\n    - {op: replace, path: /spec/replicas, value: 2}\n"
        "configMapGenerator:\n- name: settings\n  literals: [mode=static]\n"
        "generatorOptions: {disableNameSuffixHash: true}\n",
        encoding="utf-8",
    )
    evidence = materialize_kustomize(
        KustomizeBuildSpec(repository, repository, _locked_executable()),
        tmp_path / "output",
    )
    assert evidence.output["fresh_build_count"] == 2
    assert evidence.build["build_1_raw_output_sha256"] == (
        evidence.build["build_2_raw_output_sha256"]
    )
    resources = list(yaml.safe_load_all(
        (tmp_path / "output" / "rendered.yaml").read_text(encoding="utf-8")
    ))
    by_kind = {item["kind"]: item for item in resources}
    deployment = by_kind["Deployment"]
    assert deployment["metadata"]["name"] == "pre-demo"
    assert deployment["metadata"]["namespace"] == "research"
    assert deployment["metadata"]["labels"]["team"] == "platform"
    assert deployment["spec"]["replicas"] == 2
    assert deployment["spec"]["template"]["spec"]["containers"][0]["image"] == (
        "registry.example/nginx:2.0"
    )
    assert by_kind["ConfigMap"]["metadata"]["name"] == "pre-settings"
