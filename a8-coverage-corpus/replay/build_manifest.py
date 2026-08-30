#!/usr/bin/env python3
"""Reconstruct the exact a8 55-surface design corpus manifest.

This generator is intentionally data-only.  It reads the preserved original audit
inventory and content-addressed public source archives; it does not fetch, render, or
execute candidate repository code.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath


CORPUS_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = CORPUS_ROOT.parent
INVENTORY = CORPUS_ROOT / "configs/original-audit/inventory.json"
A7_PROBE = CORPUS_ROOT / "configs/original-audit/a7_probe.json"
OUTPUT = WORKSPACE / "A8_55_SURFACE_CORPUS_MANIFEST.json"
OUTPUT_MD = WORKSPACE / "A8_55_SURFACE_CORPUS_MANIFEST.md"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha(value: object) -> str:
    return sha256_bytes(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"))


REPOSITORIES = {
    "airflow": ("apache/airflow", "9d54ac94826d8f46c0d6d1032ee7d9988e562d70", "f598988108217c65570f05bdc1fc22a151d7c887", "airflow"),
    "argo-helm": ("argoproj/argo-helm", "e0e82f7a9b543405ee25798ce8c899705503a3d1", "09e1cc5e643ae8747e8352c49ec4cbd459142e0a", "argo-helm"),
    "coder-enterprise-helm": ("coder/enterprise-helm", "b096a369fe2d1b2de75a0b85af01fa9e272b221e", "eb222290d36fb794b0499576b44b62ca07fed408", "coder-enterprise-helm"),
    "cortex-helm-chart": ("cortexproject/cortex-helm-chart", "73337e251edec84ed394b47649ec0e4763cdb591", "787e8654316af2a6217f07ebeceb72ce1fdfb816", "cortex-helm-chart"),
    "csi-driver-smb": ("kubernetes-csi/csi-driver-smb", "0f879a3208930a1a61cbe6fc2353719495845ba9", "b5866935107c6a97c78e8acea6fe1f032017f056", "csi-driver-smb"),
    "external-secrets": ("external-secrets/external-secrets", "8488600898e856d74a7e0f53ed5e3cc79d89f4e8", "816e037251bf68375e22982757f87ab744406223", "external-secrets"),
    "grafana": ("grafana/helm-charts", "7a0ab968961a165318ab95ff678908c3b9bc3240", "ea29bffdffbe09e395f771b9f26ab89a4c317010", "grafana"),
    "harbor-helm": ("goharbor/harbor-helm", "acb552529b7c73d86840130eee226f17dc79a5ab", "efabb59b2f05bcaa61e513d71d6fff036c42fb7d", "harbor-helm"),
    "harness-gitops-agent": ("harness/gitops-agent-helm-chart", "c4bfa0297cfbd27f0cc591f26a9ec39119ddbcb0", "b4b367c9acf1e4908ff0846e10d6424f29ccb811", "harness-gitops-agent"),
    "jenkins-helm": ("jenkinsci/helm-charts", "41eeb20f3f00dda2515d2c5724b1343c5a237762", "4689d8ca56275154e85f49dd9f956ba5e46f287a", "jenkins-helm"),
    "kyverno": ("kyverno/kyverno", "dc12fe22eb32b0aa8c4ba39e4b2f2a3bf5aacf34", "2c81fc4ca8f461439e14b2a3f6f19d73ee7cbeec", "kyverno"),
    "neo4j-helm": ("neo4j/helm-charts", "bd85d80c591e016fcf12e9960d626712ffddb642", "a123170722190c192925f60033813e72c40a0fd4", "neo4j-helm"),
    "onlyoffice-docs": ("ONLYOFFICE/Kubernetes-Docs", "c0e9bdfc515858758cbe4bf23eeec23376595e70", "66b173ca3f64b31a6361f18661e868a1c21f5ebe", "onlyoffice-docs"),
    "onlyoffice-docspace": ("ONLYOFFICE/Kubernetes-DocSpace", "ae9cfca78e8485491a3cd7fcffe875abd3737579", "0c043995831f30e877b4e1d2757b399a94b79650", "onlyoffice-docspace"),
    "opencost": ("opencost/opencost-helm-chart", "4242feee70e745ea540fc5d3177d4899b307dc2d", "4581a61f6418e19baeb734dde77c6e76407523e3", "opencost"),
    "opentelemetry": ("open-telemetry/opentelemetry-helm-charts", "b1f24a2f0cc9bcee70bd1bf8e7b989240496385f", "8f3c18c6c9e7601d4d1078364c543da8849a6dbf", "opentelemetry"),
    "prometheus-community": ("prometheus-community/helm-charts", "ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988", "55a654617f1f778527346c9b0b57b14adc3c7a12", "prometheus-community"),
    "valkey-io": ("valkey-io/valkey-helm", "dd2d78213ae4e7b229074d473612999c7324d9be", "0ad76f09ceca4750d8c5a23e66d42d225e63357f", "valkey-helm"),
    "azure-blob-csi": ("kubernetes-sigs/blob-csi-driver", "d50172c7fbab36573ed92ef0b1f4b4b32d41ff19", "7920b18aff86a1871efeb236279b5fed8a33abec", "azure-blob-csi"),
    "argo-workflows": ("argoproj/argo-workflows", "bde5adf915fbc2600a49e6e864a699544fb91368", "5004d1ddfdc929ae35183d0bf05b1206d7524047", "argo-workflows"),
    "aws-load-balancer-controller": ("kubernetes-sigs/aws-load-balancer-controller", "7040d02b38580b8b8b47ba3fb2b279da9698f5d9", "9cf462b3cc592730d57061332aa32a164a212856", "aws-load-balancer-controller"),
    "cloudnative-pg": ("cloudnative-pg/cloudnative-pg", "8179beb0592398b9ae3221d8488c815b73e94b2c", "f029b8f8468992fc01b205795377d5d646a2e138", "cloudnative-pg"),
    "descheduler": ("kubernetes-sigs/descheduler", "8bbd0bd661f2328ade2615ab0bd7f8dcafa3e723", "389f804ed1e9a7638529b77ca1bbc905bb7bc767", "descheduler"),
    "flux-source-controller": ("fluxcd/source-controller", "208961aa7bf334cbef95bee390712b27a925dec2", "d7c70f0d748d82adac68686fcc4f78c3cc580513", "flux-source-controller"),
    "flux-kustomize-controller": ("fluxcd/kustomize-controller", "186fb3b29138ce82ff61ba1a9370b96a3dd598fe", "bbaf44b12f1b5fbbe94779f6a8999b97eb49bee1", "flux-kustomize-controller"),
    "gateway-api": ("kubernetes-sigs/gateway-api", "1ab0781ac715b26a25ff201ce444058a47703c4c", "be7eacc94b3c15aef268a793d071c809712d441e", "gateway-api"),
    "metrics-server": ("kubernetes-sigs/metrics-server", "4062beeed6ef996ba3ff7164967edafd3470e2e4", "0e1deb8a4c0ec7879cf1c1e03ccb2434e8230b37", "metrics-server"),
    "prometheus-operator": ("prometheus-operator/prometheus-operator", "146a99723a91c4b96abc41aeb46a147b04cf092b", "015fb4f49271a382818a989cd6f057e495dde7b2", "prometheus-operator"),
}

ORIGINAL_DIRS = {
    "opencost": "opencost-helm-chart",
    "opentelemetry": "opentelemetry-helm-charts",
    "prometheus-community": "prometheus",
    "valkey-io": "valkey-helm",
    "azure-blob-csi": "blob-csi-driver",
}

PREDICTION_SUPPORTED = {
    "cortex-helm-chart:cortex", "csi-driver-smb:csi-driver-smb",
    "grafana:grafana-agent-operator", "grafana:promtail",
    "jenkins-helm:jenkins", "onlyoffice-docs:docs",
    "opentelemetry:opentelemetry-operator",
    "opentelemetry:opentelemetry-target-allocator",
    "prometheus-community:alertmanager",
    "prometheus-community:prometheus-adapter",
    "prometheus-community:prometheus-blackbox-exporter",
    "prometheus-community:prometheus-node-exporter",
    "prometheus-community:prometheus-operator-admission-webhook",
    "prometheus-community:prometheus-pushgateway",
    "prometheus-community:prometheus-snmp-exporter",
    "valkey-io:valkey-operator",
}

PREDICTION_PARTIAL = {
    "grafana:pdc-agent", "harness-gitops-agent:gitops-agent",
    "neo4j-helm:neo4j", "onlyoffice-docspace:docspace",
    "opentelemetry:opentelemetry-demo",
    "opentelemetry:opentelemetry-collector",
}

KUSTOMIZE_SUPPORTED = {
    "azure-blob-csi:deploy/v1.27.9",
    "airflow:chart/kustomize-overlays/kerberos",
    "airflow:chart/kustomize-overlays/keda",
    "argo-workflows:manifests/cluster-install",
    "argo-workflows:manifests/namespace-install",
    "descheduler:kubernetes/base",
    "flux-source-controller:config/default",
    "gateway-api:config/crd",
    "metrics-server:manifests/base",
    "metrics-server:manifests/overlays/release",
    "prometheus-operator:.",
}

AUXILIARY = {
    "onlyoffice-docspace": [
        ("Chart.lock", "configs/onlyoffice-docspace/Chart.lock"),
        ("charts/docs-6.1.1.tgz", "configs/onlyoffice-docspace/charts/docs-6.1.1.tgz"),
    ]
}


def archive_records(archive: Path) -> tuple[str, list[dict]]:
    records: list[dict] = []
    prefix: str | None = None
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            raw = PurePosixPath(member.name)
            if raw.is_absolute() or ".." in raw.parts or not raw.parts:
                raise ValueError(f"unsafe archive member: {member.name}")
            if prefix is None:
                prefix = raw.parts[0]
            if raw.parts[0] != prefix:
                raise ValueError("source archive has multiple roots")
            relative = PurePosixPath(*raw.parts[1:])
            if not relative.parts or member.isdir():
                continue
            if member.isfile():
                stream = bundle.extractfile(member)
                if stream is None:
                    raise ValueError(f"unreadable archive member: {member.name}")
                content = stream.read()
                records.append({
                    "path": relative.as_posix(), "type": "file",
                    "mode": member.mode & 0o777, "size": len(content),
                    "sha256": sha256_bytes(content),
                })
            elif member.issym():
                target = PurePosixPath(member.linkname)
                if target.is_absolute():
                    raise ValueError(f"absolute archive symlink: {member.name}")
                records.append({
                    "path": relative.as_posix(), "type": "symlink",
                    "mode": member.mode & 0o777, "target": member.linkname,
                })
            else:
                raise ValueError(f"unsupported archive member type: {member.name}")
    if prefix is None:
        raise ValueError("empty source archive")
    return prefix, sorted(records, key=lambda item: item["path"])


def apply_auxiliary(repo: str, records: list[dict]) -> tuple[list[dict], list[dict]]:
    by_path = {item["path"]: item for item in records}
    evidence = []
    for target, source_name in AUXILIARY.get(repo, []):
        if target in by_path:
            raise ValueError(f"auxiliary input would overwrite committed source: {target}")
        source = CORPUS_ROOT / source_name
        record = {
            "path": target, "type": "file", "mode": 0o644,
            "size": source.stat().st_size, "sha256": sha256_file(source),
        }
        by_path[target] = record
        evidence.append({
            "target_path": target, "source_path": source_name,
            "sha256": record["sha256"], "size": record["size"],
            "recovery_basis": "present in original audit checkout before inventory/probe",
        })
    return sorted(by_path.values(), key=lambda item: item["path"]), evidence


def root_from_original_path(repo: str, surface: str) -> str:
    dirname = ORIGINAL_DIRS.get(repo, repo)
    marker = f"/{dirname}/"
    if marker in surface:
        return surface.split(marker, 1)[1]
    if surface.endswith(f"/{dirname}"):
        return "."
    raise ValueError(f"cannot recover relative root for {repo}: {surface}")


def root_manifest(records: list[dict], root: str) -> str:
    if root == ".":
        selected = records
    else:
        selected = [
            {**item, "path": item["path"][len(root) + 1:]}
            for item in records if item["path"] == root or item["path"].startswith(root + "/")
        ]
    if not selected:
        raise ValueError(f"selected root is absent: {root}")
    return canonical_sha(selected)


def control_hashes(records: list[dict], root: str, artifact: str) -> list[dict]:
    names = ("Chart.yaml", "Chart.lock", "values.yaml") if artifact == "HELM" else (
        "kustomization.yaml", "kustomization.yml", "Kustomization",
    )
    prefix = "" if root == "." else root + "/"
    by_path = {item["path"]: item for item in records}
    found = []
    for name in names:
        item = by_path.get(prefix + name)
        if item is not None and item["type"] == "file":
            found.append({"path": name, "sha256": item["sha256"], "size": item["size"]})
    if not found or found[0]["path"] not in {"Chart.yaml", "kustomization.yaml", "kustomization.yml", "Kustomization"}:
        raise ValueError(f"required root control file is absent: {root}")
    return found


def main() -> None:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    a7_probe = json.loads(A7_PROBE.read_text(encoding="utf-8"))
    a7_by_key = {(row["repo"], row["chart"]): row for row in a7_probe}
    repository_records: dict[str, list[dict]] = {}
    repositories = {}
    for repo, (slug, commit, tree, archive_name) in REPOSITORIES.items():
        archive_rel = f"repositories/{archive_name}-{commit}.tar.gz"
        archive = CORPUS_ROOT / archive_rel
        prefix, records = archive_records(archive)
        records, auxiliary = apply_auxiliary(repo, records)
        repository_records[repo] = records
        repositories[repo] = {
            "repository": slug,
            "repository_url": f"https://github.com/{slug}",
            "commit_sha": commit,
            "commit_tree_sha": tree,
            "archive_path": archive_rel,
            "archive_sha256": sha256_file(archive),
            "archive_root_prefix": prefix,
            "snapshot_manifest_root": canonical_sha(records),
            "snapshot_file_count": len(records),
            "auxiliary_protected_inputs": auxiliary,
        }

    surfaces = []
    for index, item in enumerate(inventory["helm"], 1):
        repo = item["repo"]
        if item["sha"] != REPOSITORIES[repo][1]:
            raise ValueError(f"inventory SHA mismatch for {repo}")
        root = root_from_original_path(repo, item["surface"])
        key = f"{repo}:{item['chart']}"
        prediction = (
            "SUPPORTED" if key in PREDICTION_SUPPORTED else
            "PARTIALLY_REACHABLE" if key in PREDICTION_PARTIAL else
            "FAIL_CLOSED_PRODUCT_BOUNDARY"
        )
        a7 = a7_by_key[(repo, Path(item["surface"]).name)]
        surfaces.append({
            "surface_id": f"helm-{index:03d}-{repo}-{item['chart']}",
            "repository_id": repo,
            "repository": REPOSITORIES[repo][0],
            "repository_url": f"https://github.com/{REPOSITORIES[repo][0]}",
            "commit_sha": REPOSITORIES[repo][1],
            "commit_tree_sha": REPOSITORIES[repo][2],
            "artifact_class": "HELM",
            "root_path": root,
            "configuration": {
                "values_files": [], "set_values": [], "set_strings": [],
                "include_crds": False, "include_tests": False,
            },
            "release_name": "a8-audit",
            "namespace": "default",
            "kube_version": "1.31.0",
            "api_versions": [],
            "dependency_assumptions": {
                "declared": item["dependencies"],
                "aliases": item["dependency_aliases"],
                "missing_vendored_dependencies": item["missing_vendored_dependencies"],
                "vendored_archives": item["vendored_archives"],
                "vendored_directories": item["vendored_directories"],
                "chart_lock_present": item["chart_lock"],
                "remote_resolution_permitted": False,
            },
            "protected_input_manifest_root": repositories[repo]["snapshot_manifest_root"],
            "selected_root_manifest_root": root_manifest(repository_records[repo], root),
            "root_control_files": control_hashes(repository_records[repo], root, "HELM"),
            "expected_materializer": "IAC_GUARD_V_BOUNDED_HELM_A8",
            "original_a7_observation": {
                "status": a7["status"], "reason": a7.get("reason"),
            },
            "original_design_prediction": prediction,
            "recovery_source": [
                "A8_PREIMPLEMENTATION_COVERAGE_AUDIT.md",
                "A8_FINAL_PREIMPLEMENTATION_DESIGN.md",
                "configs/original-audit/inventory.json",
                "configs/original-audit/a7_probe.json",
                "retained original local checkout and Codex session log",
            ],
            "recovery_confidence": "HIGH",
            "selected_property_request": None,
        })

    for index, item in enumerate(inventory["kustomize"], 1):
        repo = item["repo"]
        if item["sha"] != REPOSITORIES[repo][1]:
            raise ValueError(f"inventory SHA mismatch for {repo}")
        root = root_from_original_path(repo, item["surface"])
        prediction = (
            "SUPPORTED" if f"{repo}:{root}" in KUSTOMIZE_SUPPORTED
            else "FAIL_CLOSED_PRODUCT_BOUNDARY"
        )
        surfaces.append({
            "surface_id": f"kustomize-{index:03d}-{repo}-{root.replace('/', '-') if root != '.' else 'root'}",
            "repository_id": repo,
            "repository": REPOSITORIES[repo][0],
            "repository_url": f"https://github.com/{REPOSITORIES[repo][0]}",
            "commit_sha": REPOSITORIES[repo][1],
            "commit_tree_sha": REPOSITORIES[repo][2],
            "artifact_class": "KUSTOMIZE",
            "root_path": root,
            "configuration": {},
            "release_name": None,
            "namespace": None,
            "kube_version": None,
            "api_versions": [],
            "dependency_assumptions": {
                "remote_references": item["remote_references"],
                "path_traversal_references": item["path_traversal_references"],
                "remote_resolution_permitted": False,
                "plugins_permitted": False,
                "exec_permitted": False,
                "helm_inflation_permitted": False,
            },
            "protected_input_manifest_root": repositories[repo]["snapshot_manifest_root"],
            "selected_root_manifest_root": root_manifest(repository_records[repo], root),
            "root_control_files": control_hashes(repository_records[repo], root, "KUSTOMIZE"),
            "expected_materializer": "IAC_GUARD_V_BOUNDED_LOCAL_KUSTOMIZE_A8",
            "original_a7_observation": {
                "status": "FAIL_CLOSED_PRODUCT_BOUNDARY",
                "reason": "KUSTOMIZATION_CONTROL_DOCUMENT_NOT_TARGET_RESOURCE",
            },
            "original_design_prediction": prediction,
            "recovery_source": [
                "A8_PREIMPLEMENTATION_COVERAGE_AUDIT.md",
                "A8_FINAL_PREIMPLEMENTATION_DESIGN.md",
                "configs/original-audit/inventory.json",
                "retained original local checkout and Codex session log",
            ],
            "recovery_confidence": "HIGH",
            "selected_property_request": None,
        })

    counts = {}
    for item in surfaces:
        value = item["original_design_prediction"]
        counts[value] = counts.get(value, 0) + 1
    expected_counts = {
        "SUPPORTED": 27, "PARTIALLY_REACHABLE": 6,
        "FAIL_CLOSED_PRODUCT_BOUNDARY": 22,
    }
    if counts != expected_counts or len(surfaces) != 55:
        raise ValueError(f"recovered prediction counts differ: {counts}")

    body = {
        "schema_version": "iac-guard-v-a8-55-surface-corpus-v1",
        "corpus_id": "a8-original-design-55-surfaces",
        "surface_count": 55,
        "artifact_counts": {"HELM": 40, "KUSTOMIZE": 15},
        "repository_count": 28,
        "recovery_status": "EXACT_ORIGINAL_SURFACES_RECOVERED",
        "original_design_prediction_counts": expected_counts,
        "source_evidence": {
            "coverage_audit": {
                "path": "A8_PREIMPLEMENTATION_COVERAGE_AUDIT.md",
                "sha256": sha256_file(WORKSPACE / "A8_PREIMPLEMENTATION_COVERAGE_AUDIT.md"),
            },
            "final_design": {
                "path": "A8_FINAL_PREIMPLEMENTATION_DESIGN.md",
                "sha256": sha256_file(WORKSPACE / "A8_FINAL_PREIMPLEMENTATION_DESIGN.md"),
            },
            "original_inventory": {
                "path": "a8-coverage-corpus/configs/original-audit/inventory.json",
                "sha256": sha256_file(INVENTORY),
            },
            "original_a7_probe": {
                "path": "a8-coverage-corpus/configs/original-audit/a7_probe.json",
                "sha256": sha256_file(A7_PROBE),
            },
        },
        "tool_contract": {
            "helm": {
                "path": "tools/helm-v4.2.4-darwin-arm64",
                "version": "v4.2.4+g3900f43",
                "sha256": sha256_file(CORPUS_ROOT / "tools/helm-v4.2.4-darwin-arm64"),
            },
            "kustomize": {
                "path": "tools/kustomize",
                "version": "5.7.1",
                "sha256": sha256_file(CORPUS_ROOT / "tools/kustomize"),
                "archive_path": "tools/kustomize_v5.7.1_darwin_arm64.tar.gz",
                "archive_sha256": sha256_file(CORPUS_ROOT / "tools/kustomize_v5.7.1_darwin_arm64.tar.gz"),
            },
        },
        "replay_protocol": {
            "mode": "MATERIALIZATION_REACHABILITY",
            "product_path": "public Python materializer API used by CLI acceptance paths",
            "network": "FORBIDDEN",
            "candidate_source_mutation": "FORBIDDEN",
            "render_count_per_surface": 1,
            "internal_materializer_fresh_builds": 2,
            "selected_property_request": "not applicable to original construct-frequency surfaces",
        },
        "repositories": repositories,
        "surfaces": surfaces,
    }
    body["manifest_payload_sha256"] = canonical_sha(body)
    OUTPUT.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# A8 55-surface corpus manifest", "",
        f"- Corpus: `{body['corpus_id']}`",
        f"- Surfaces: `{len(surfaces)}` (40 Helm, 15 Kustomize)",
        f"- Repositories: `{len(repositories)}`",
        f"- Manifest payload SHA256: `{body['manifest_payload_sha256']}`",
        f"- Original inventory SHA256: `{body['source_evidence']['original_inventory']['sha256']}`",
        "- Recovery: exact roots, commits, default inputs, and dependency absence/presence",
        "", "## Surfaces", "",
        "| ID | Repository | SHA | Class | Root | Original a8 prediction | Confidence |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in surfaces:
        lines.append(
            f"| `{item['surface_id']}` | `{item['repository']}` | "
            f"`{item['commit_sha']}` | {item['artifact_class']} | "
            f"`{item['root_path']}` | `{item['original_design_prediction']}` | "
            f"`{item['recovery_confidence']}` |"
        )
    lines.extend([
        "", "## Replay", "",
        "```sh",
        ".nox/tests-3-12/bin/python a8-coverage-corpus/replay/replay.py \\",
        "  --manifest A8_55_SURFACE_CORPUS_MANIFEST.json \\",
        "  --output a8-coverage-corpus/results/implemented-a8-replay.json",
        "```", "",
        "Validation without rendering:", "",
        "```sh",
        ".nox/tests-3-12/bin/python a8-coverage-corpus/replay/replay.py \\",
        "  --manifest A8_55_SURFACE_CORPUS_MANIFEST.json --validate-only",
        "```", "",
    ])
    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
