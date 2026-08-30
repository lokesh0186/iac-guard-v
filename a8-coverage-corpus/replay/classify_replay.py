#!/usr/bin/env python3
"""Bind reviewed comparison classifications to an immutable a8 replay."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


IMPLEMENTATION_DEFECTS = {
    "helm-004-cortex-helm-chart-cortex": (
        "The protected memcached-6.14.0.tgz contains its declared common "
        "dependency under memcached/charts/common, but a8 reports that nested "
        "dependency closure inside an archive is not modeled. Nested LOCAL "
        "dependency closure for local archives is part of the frozen a8 contract."
    ),
}

DESIGN_PREDICTION_ERRORS = {
    "helm-013-grafana-promtail": (
        "The design predicted namespace support would be the final blocker, but "
        "the protected source reaches an action graph outside the bounded grammar."
    ),
    "helm-018-jenkins-helm-jenkins": (
        "The design inventory did not account for contradictory namespace "
        "declarations in the participating source template."
    ),
    "helm-022-onlyoffice-docs-docs": (
        "The design predicted support after bounded namespace handling, but a "
        "participating template action remains outside the closed action grammar."
    ),
    "helm-025-opentelemetry-opentelemetry-demo": (
        "The design predicted partial reachability after alias handling, but the "
        "protected source still declares a dependency without local vendored bytes."
    ),
    "helm-028-opentelemetry-opentelemetry-operator": (
        "The design predicted support without proving custom-resource scope from "
        "local CRD evidence; the implementation correctly refuses namespace identity."
    ),
    "helm-032-prometheus-community-prometheus-adapter": (
        "The design inventory did not account for contradictory namespace "
        "declarations in the participating source template."
    ),
    "helm-035-prometheus-community-prometheus-operator-admission-webhook": (
        "The design inventory did not account for contradictory namespace "
        "declarations in the participating source template."
    ),
}

EXECUTION_ENVIRONMENT_PROBLEMS = {
    "kustomize-001-azure-blob-csi-deploy-v1.27.9",
    "kustomize-002-airflow-chart-kustomize-overlays-kerberos",
    "kustomize-003-airflow-chart-kustomize-overlays-keda",
    "kustomize-005-argo-workflows-manifests-cluster-install",
    "kustomize-006-argo-workflows-manifests-namespace-install",
    "kustomize-009-descheduler-kubernetes-base",
    "kustomize-010-flux-source-controller-config-default",
    "kustomize-012-gateway-api-config-crd",
    "kustomize-013-metrics-server-manifests-base",
    "kustomize-014-metrics-server-manifests-overlays-release",
    "kustomize-015-prometheus-operator-root",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def classify(item: dict) -> tuple[str, str]:
    surface_id = item["surface_id"]
    if item["comparison_classification"] == "MATCH":
        return "MATCH", "Observed disposition equals the frozen design prediction."
    if surface_id in IMPLEMENTATION_DEFECTS:
        return "IMPLEMENTATION_DEFECT", IMPLEMENTATION_DEFECTS[surface_id]
    if surface_id in DESIGN_PREDICTION_ERRORS:
        return "DESIGN_PREDICTION_ERROR", DESIGN_PREDICTION_ERRORS[surface_id]
    if surface_id in EXECUTION_ENVIRONMENT_PROBLEMS:
        return "EXTERNAL_INPUT_IDENTITY_PROBLEM", (
            "The protected source identity is intact, but the authoritative local "
            "Kustomize path could not enter its required macOS sandbox because this "
            "replay already runs under a managed host sandbox. This is an execution-"
            "environment obstruction, not a candidate-source or semantic verdict."
        )
    raise RuntimeError(f"UNCLASSIFIED_REPLAY_MISMATCH: {surface_id}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("CLASSIFIED_REPLAY_OUTPUT_ALREADY_EXISTS")
    raw = json.loads(args.input.read_text(encoding="utf-8"))
    if raw.get("surface_count") != 55 or len(raw.get("results", [])) != 55:
        raise RuntimeError("REPLAY_SURFACE_COUNT_MISMATCH")
    rows = []
    counts: dict[str, int] = {}
    for item in raw["results"]:
        classification, rationale = classify(item)
        counts[classification] = counts.get(classification, 0) + 1
        rows.append({
            "surface_id": item["surface_id"],
            "prediction": item["original_design_prediction"],
            "observation": item["status"],
            "reason_code": item["reason_code"],
            "classification": classification,
            "rationale": rationale,
            "evidence_digest": item["evidence_digest"],
        })
    report = {
        "schema_version": "iac-guard-v-a8-coverage-replay-classification-v1",
        "raw_replay_path": args.input.as_posix(),
        "raw_replay_sha256": sha256_file(args.input),
        "raw_replay_evidence_root_sha256": raw["replay_evidence_root_sha256"],
        "surface_count": 55,
        "classification_counts": dict(sorted(counts.items())),
        "results": rows,
    }
    report["classification_evidence_root_sha256"] = canonical_sha(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
