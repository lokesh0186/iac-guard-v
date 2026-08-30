#!/usr/bin/env python3
"""Static construct inventory for the a8 pre-implementation audit.

This does not render charts or execute repository code.  It inventories protected
public source bytes and deliberately reports syntax/metadata, not semantic support.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

import yaml


SWEEP = Path("/private/tmp/iacgv-consistency-sweep")
NEW = Path("/private/tmp/iacgv-a8-coverage-corpus")
OUT = Path("/private/tmp/iacgv-a8-coverage-audit")

HELM = [
    ("airflow", SWEEP / "airflow/chart"),
    ("argo-helm", SWEEP / "argo-helm/charts/argo-cd"),
    ("coder-enterprise-helm", SWEEP / "coder-enterprise-helm"),
    ("cortex-helm-chart", SWEEP / "cortex-helm-chart"),
    ("csi-driver-smb", SWEEP / "csi-driver-smb/charts/latest/csi-driver-smb"),
    ("external-secrets", SWEEP / "external-secrets/deploy/charts/external-secrets"),
    ("grafana", SWEEP / "grafana/charts/agent-operator"),
    ("grafana", SWEEP / "grafana/charts/enterprise-logs"),
    ("grafana", SWEEP / "grafana/charts/enterprise-metrics"),
    ("grafana", SWEEP / "grafana/charts/grafana-sampling"),
    ("grafana", SWEEP / "grafana/charts/lgtm-distributed"),
    ("grafana", SWEEP / "grafana/charts/pdc-agent"),
    ("grafana", SWEEP / "grafana/charts/promtail"),
    ("grafana", SWEEP / "grafana/charts/rollout-operator"),
    ("grafana", SWEEP / "grafana/charts/tempo-distributed"),
    ("harbor-helm", SWEEP / "harbor-helm"),
    ("harness-gitops-agent", SWEEP / "harness-gitops-agent"),
    ("jenkins-helm", SWEEP / "jenkins-helm/charts/jenkins"),
    ("kyverno", SWEEP / "kyverno/charts/kyverno"),
    ("kyverno", SWEEP / "kyverno/charts/kyverno-policies"),
    ("neo4j-helm", SWEEP / "neo4j-helm/neo4j"),
    ("onlyoffice-docs", SWEEP / "onlyoffice-docs"),
    ("onlyoffice-docspace", SWEEP / "onlyoffice-docspace"),
    ("opencost", SWEEP / "opencost-helm-chart/charts/opencost"),
    ("opentelemetry", SWEEP / "opentelemetry-helm-charts/charts/opentelemetry-demo"),
    ("opentelemetry", SWEEP / "opentelemetry-helm-charts/charts/opentelemetry-collector"),
    ("opentelemetry", SWEEP / "opentelemetry-helm-charts/charts/opentelemetry-kube-stack"),
    ("opentelemetry", SWEEP / "opentelemetry-helm-charts/charts/opentelemetry-operator"),
    ("opentelemetry", SWEEP / "opentelemetry-helm-charts/charts/opentelemetry-target-allocator"),
    ("prometheus-community", SWEEP / "prometheus/charts/alertmanager"),
    ("prometheus-community", SWEEP / "prometheus/charts/kube-prometheus-stack"),
    ("prometheus-community", SWEEP / "prometheus/charts/prometheus-adapter"),
    ("prometheus-community", SWEEP / "prometheus/charts/prometheus-blackbox-exporter"),
    ("prometheus-community", SWEEP / "prometheus/charts/prometheus-node-exporter"),
    ("prometheus-community", SWEEP / "prometheus/charts/prometheus-operator-admission-webhook"),
    ("prometheus-community", SWEEP / "prometheus/charts/prometheus-pushgateway"),
    ("prometheus-community", SWEEP / "prometheus/charts/prometheus-snmp-exporter"),
    ("prometheus-community", SWEEP / "prometheus/charts/prometheus"),
    ("valkey-io", SWEEP / "valkey-helm/valkey"),
    ("valkey-io", SWEEP / "valkey-helm/valkey-operator"),
]

KUSTOMIZE = [
    ("azure-blob-csi", SWEEP / "blob-csi-driver/deploy/v1.27.9"),
    ("airflow", SWEEP / "airflow/chart/kustomize-overlays/kerberos"),
    ("airflow", SWEEP / "airflow/chart/kustomize-overlays/keda"),
    ("kyverno", SWEEP / "kyverno/scripts/config/kwok"),
    ("argo-workflows", NEW / "argo-workflows/manifests/cluster-install"),
    ("argo-workflows", NEW / "argo-workflows/manifests/namespace-install"),
    ("aws-load-balancer-controller", NEW / "aws-load-balancer-controller/config/default"),
    ("cloudnative-pg", NEW / "cloudnative-pg/config/default"),
    ("descheduler", NEW / "descheduler/kubernetes/base"),
    ("flux-source-controller", NEW / "flux-source-controller/config/default"),
    ("flux-kustomize-controller", NEW / "flux-kustomize-controller/config/default"),
    ("gateway-api", NEW / "gateway-api/config/crd"),
    ("metrics-server", NEW / "metrics-server/manifests/base"),
    ("metrics-server", NEW / "metrics-server/manifests/overlays/release"),
    ("prometheus-operator", NEW / "prometheus-operator"),
]

FUNC_PATTERNS = {
    "include": r"\binclude\s+",
    "template": r"\btemplate\s+",
    "tpl": r"\btpl\s+",
    "printf_print": r"\b(?:printf|print)\s+",
    "files_get": r"\.Files\.Get\b",
    "files_glob": r"\.Files\.Glob\b",
    "release_namespace": r"\.Release\.Namespace\b",
    "values_namespace": r"\.Values(?:\.[A-Za-z0-9_-]+)*\.namespace\b|\.Values\.namespace\b",
    "range": r"\brange\b",
    "with": r"\bwith\b",
    "if": r"\bif\b",
    "else": r"\belse\b",
    "variable_assignment": r"\$[A-Za-z_][A-Za-z0-9_]*\s*(?::=|=)",
    "dict": r"\bdict\b",
    "list": r"\blist\b",
    "merge": r"\b(?:merge|mergeOverwrite|mustMerge|mustMergeOverwrite)\b",
    "default": r"\bdefault\b",
    "coalesce": r"\bcoalesce\b",
    "required": r"\brequired\b",
    "fail": r"\bfail\b",
    "lookup": r"\blookup\b",
    "random_time_crypto": r"\b(?:randAlpha|randNumeric|randAscii|randAlphaNum|randBytes|uuidv4|now|dateInZone|unixEpoch|genPrivateKey|genCA|genSelfSignedCert|derivePassword|encryptAES)\b",
    "global_values": r"\.Values\.global\b",
    "toyaml_tpl": r"\btpl\s*\(?\s*(?:toYaml|toJson|toPrettyJson)\b",
    "files_tpl": r"\btpl\s*\(?\s*\(?\s*\.Files\.(?:Get|Glob)\b",
}

ACTION_RE = re.compile(r"{{[-]?\s*(.*?)\s*[-]?}}", re.S)
DEFINE_RE = re.compile(r"^\s*define\s+[\"']([^\"']+)[\"']\s*$", re.S)
LITERAL_CALL_RE = re.compile(r"^\s*(include|template)\s+[\"']([^\"']+)[\"']", re.S)
CALL_RE = re.compile(r"^\s*(include|template)\s+(.+)$", re.S)
NAMESPACE_LINE_RE = re.compile(r"(?m)^\s*namespace\s*:\s*(.*)$")
NS_HELPER_CALL_RE = re.compile(
    r'{{-?\s*(include|template)\s+"([^"\r\n]+)"\s+(\$root|[.$])'
    r'(?P<pipeline>\s*\|\s*quote)?\s*-?}}'
)


def load_yaml(path: Path):
    try:
        return yaml.safe_load(path.read_text(errors="replace"))
    except Exception:
        return None


def git_sha(path: Path) -> str:
    p = path
    while p != p.parent and not (p / ".git").exists():
        p = p.parent
    if not (p / ".git").exists():
        return "preserved-tree"
    return subprocess.check_output(["git", "-C", str(p), "rev-parse", "HEAD"], text=True).strip()


def git_root(path: Path) -> Path:
    p = path.resolve()
    while p != p.parent and not (p / ".git").exists():
        p = p.parent
    return p


def template_files(root: Path):
    base = root / "templates"
    if not base.is_dir():
        return []
    return [p for p in base.rglob("*") if p.is_file() and p.suffix.lower() in {".yaml", ".yml", ".tpl", ".txt"}]


def helm_record(repo: str, root: Path):
    assert (root / "Chart.yaml").is_file(), root
    chart = load_yaml(root / "Chart.yaml") or {}
    texts = []
    files = template_files(root)
    for p in files:
        texts.append((p.relative_to(root).as_posix(), p.read_text(errors="replace")))
    combined = "\n".join(t for _, t in texts)
    actions = []
    definitions = defaultdict(list)
    definition_actions = defaultdict(list)
    calls = []
    for source, text in texts:
        parsed = [m.group(1).strip() for m in ACTION_RE.finditer(text)]
        current_name = None
        current_actions = []
        depth = 0
        for body in parsed:
            actions.append((source, body))
            dm = DEFINE_RE.match(body)
            if dm:
                definitions[dm.group(1)].append({"source": source, "body": body})
                if current_name is None:
                    current_name = dm.group(1)
                    current_actions = []
                    depth = 1
                    continue
            if current_name is not None:
                if re.match(r"^\s*(?:if|range|with|block)(?:\s|$)", body):
                    depth += 1
                    current_actions.append(body)
                    continue
                if re.match(r"^\s*end(?:\s|$)", body):
                    depth -= 1
                    if depth == 0:
                        definition_actions[current_name].append({"source": source, "actions": current_actions[:]})
                        current_name = None
                        current_actions = []
                        continue
                    current_actions.append(body)
                    continue
                current_actions.append(body)
            cm = CALL_RE.match(body)
            if cm:
                lm = LITERAL_CALL_RE.match(body)
                calls.append({"kind": cm.group(1), "source": source, "body": body, "literal": bool(lm)})
    dep_records = chart.get("dependencies") if isinstance(chart, dict) else []
    if not isinstance(dep_records, list):
        dep_records = []
    deps = [d for d in dep_records if isinstance(d, dict)]
    archive_names = {p.name for p in (root / "charts").glob("*.tgz")} if (root / "charts").is_dir() else set()
    dir_names = {p.name for p in (root / "charts").iterdir() if p.is_dir()} if (root / "charts").is_dir() else set()
    missing = []
    for d in deps:
        name = str(d.get("name", ""))
        alias = str(d.get("alias", ""))
        candidates = {name, alias} - {""}
        if not any(c in dir_names or any(a.startswith(c + "-") and a.endswith(".tgz") for a in archive_names) for c in candidates):
            missing.append(name or alias)
    duplicate_equivalent = 0
    duplicate_nonequivalent = 0
    for name, defs in definitions.items():
        if len(defs) > 1:
            # Full definition bodies are compared later by the public parser; here
            # exact action equality is only a conservative static proxy.
            if len({d["body"] for d in defs}) == 1:
                duplicate_equivalent += 1
            else:
                duplicate_nonequivalent += 1
    counts = {k: len(re.findall(v, combined)) for k, v in FUNC_PATTERNS.items()}
    ns_lines = [m.group(1).strip() for _, text in texts for m in NAMESPACE_LINE_RE.finditer(text)]
    namespace_forms = Counter()
    for line in ns_lines:
        if ".Release.Namespace" in line:
            namespace_forms["release"] += 1
        elif re.search(r"\.Values(?:\.[\w-]+)*\.namespace\b|\.Values\.namespace\b", line):
            namespace_forms["values"] += 1
        elif re.search(r"{{-?\s*include\s+[\"']", line):
            namespace_forms["include_literal"] += 1
        elif re.search(r"{{-?\s*template\s+[\"']", line):
            namespace_forms["template_literal"] += 1
        elif "{{" in line:
            namespace_forms["other_template"] += 1
        elif line:
            namespace_forms["literal"] += 1
    nested_calls = sum(1 for _, body in actions if re.search(r"\b(?:include|template)\b.*\b(?:include|template)\b", body))
    dynamic_calls = sum(1 for c in calls if not c["literal"])
    bounded_print_calls = sum(1 for c in calls if not c["literal"] and re.search(r"\((?:print|printf)\b", c["body"]))
    root_alias_context = sum(1 for c in calls if re.search(r"\s\$root\s*$", c["body"]))
    namespace_helper_calls = []
    for source, text in texts:
        for line_match in NAMESPACE_LINE_RE.finditer(text):
            line = line_match.group(1).strip()
            match = NS_HELPER_CALL_RE.search(line)
            if match is None:
                continue
            name = match.group(2)
            members = definition_actions.get(name, [])
            helper_class = "missing_or_duplicate"
            if len(members) == 1:
                body = " ; ".join(members[0]["actions"])
                compact = " ".join(body.split())
                if re.fullmatch(r"(?:if \.[^;]+ ; \.[^;]+ ; else ; \$?\.Release\.Namespace ; end)", compact):
                    helper_class = "if_values_else_release"
                elif re.fullmatch(r"default \$?\.Release\.Namespace \.[^|;]+", compact):
                    helper_class = "default_release_values"
                elif re.fullmatch(r"default \$?\.Release\.Namespace \.[^;]+ \| trunc 63 \| trimSuffix \"-\"", compact):
                    helper_class = "default_release_values_normalized"
                elif compact in {".Release.Namespace", "$.Release.Namespace"} or re.fullmatch(r"\.Values\.[A-Za-z0-9_.-]+", compact):
                    helper_class = "direct_release_or_values"
                else:
                    helper_class = "other_deterministic_or_unknown"
            namespace_helper_calls.append({
                "source": source,
                "kind": match.group(1),
                "name": name,
                "context": match.group(3),
                "quote_pipeline": bool(match.group("pipeline")),
                "helper_class": helper_class,
            })
    return {
        "repo": repo,
        "sha": git_sha(root),
        "surface": root.as_posix(),
        "chart": chart.get("name", root.name) if isinstance(chart, dict) else root.name,
        "template_files": len(files),
        "actions": len(actions),
        "constructs": counts,
        "definitions": sum(len(v) for v in definitions.values()),
        "definition_names": len(definitions),
        "duplicate_equivalent_proxy": duplicate_equivalent,
        "duplicate_nonequivalent_proxy": duplicate_nonequivalent,
        "calls": len(calls),
        "dynamic_calls": dynamic_calls,
        "bounded_print_calls": bounded_print_calls,
        "nested_calls": nested_calls,
        "root_alias_context_calls": root_alias_context,
        "namespace_helper_calls": namespace_helper_calls,
        "namespace_forms": dict(namespace_forms),
        "dependencies": len(deps),
        "dependency_aliases": sum(bool(d.get("alias")) for d in deps),
        "dependency_conditions": sum(bool(d.get("condition")) for d in deps),
        "dependency_tags": sum(bool(d.get("tags")) for d in deps),
        "dependency_file_repos": sum(str(d.get("repository", "")).startswith("file://") for d in deps),
        "dependency_remote_repos": sum(bool(d.get("repository")) and not str(d.get("repository", "")).startswith("file://") for d in deps),
        "vendored_archives": len(archive_names),
        "vendored_directories": len(dir_names),
        "missing_vendored_dependencies": missing,
        "chart_lock": (root / "Chart.lock").is_file(),
    }


def is_remote(value: str) -> bool:
    return bool(re.match(r"^(?:https?|git|ssh|oci)://", value)) or "github.com/" in value or "?ref=" in value


def kustomize_record(repo: str, root: Path):
    repo_root = git_root(root)
    visited = set()
    nodes = []

    def find_control(directory: Path):
        candidates = [directory / "kustomization.yaml", directory / "kustomization.yml", directory / "Kustomization"]
        return next((p for p in candidates if p.is_file()), None)

    def visit(directory: Path):
        path = find_control(directory)
        if path is None:
            return
        resolved = path.resolve()
        if resolved in visited:
            return
        visited.add(resolved)
        data = load_yaml(path) or {}
        keys = set(data) if isinstance(data, dict) else set()
        refs = []
        for key in ("resources", "bases", "components"):
            val = data.get(key, []) if isinstance(data, dict) else []
            if isinstance(val, list):
                refs.extend(str(x) for x in val)
        node = {"path": path.as_posix(), "data": data, "keys": keys, "references": refs}
        nodes.append(node)
        for ref in refs:
            if is_remote(ref):
                continue
            candidate = directory / ref
            if candidate.is_dir():
                try:
                    candidate.resolve().relative_to(repo_root.resolve())
                except ValueError:
                    continue
                visit(candidate)

    visit(root)
    assert nodes, root
    root_data = nodes[0]["data"]
    references = [ref for n in nodes for ref in n["references"]]
    all_keys = set().union(*(n["keys"] for n in nodes))
    symlinks = []
    path_traversal = []
    remote_references = []
    local_references = []
    for node in nodes:
        parent = Path(node["path"]).parent
        for ref in node["references"]:
            if is_remote(ref):
                remote_references.append(ref)
                continue
            local_references.append(ref)
            if ".." in Path(ref).parts:
                path_traversal.append(ref)
            p = parent / ref
            if p.is_symlink():
                symlinks.append(ref)
    generator_keys = []
    for node in nodes:
        generator_keys.extend(k for k in ("configMapGenerator", "secretGenerator") if k in node["keys"])
    plugins = any("generators" in n["keys"] or "transformers" in n["keys"] for n in nodes)

    def total(key):
        count = 0
        for node in nodes:
            data = node["data"]
            value = data.get(key, []) if isinstance(data, dict) else []
            if isinstance(value, list):
                count += len(value)
        return count

    def key_nodes(key):
        return sum(key in n["keys"] for n in nodes)

    return {
        "repo": repo,
        "sha": git_sha(root),
        "surface": root.as_posix(),
        "control_document": True,
        "api_version": root_data.get("apiVersion") if isinstance(root_data, dict) else None,
        "kind": root_data.get("kind") if isinstance(root_data, dict) else None,
        "control_documents": len(nodes),
        "control_paths": [n["path"] for n in nodes],
        "keys": sorted(all_keys),
        "resources": total("resources"),
        "bases": total("bases"),
        "components": total("components"),
        "patches": total("patches"),
        "patchesStrategicMerge": total("patchesStrategicMerge"),
        "patchesJson6902": total("patchesJson6902"),
        "namespace": key_nodes("namespace"),
        "namePrefix": key_nodes("namePrefix"),
        "nameSuffix": key_nodes("nameSuffix"),
        "commonLabels": key_nodes("commonLabels"),
        "labels": key_nodes("labels"),
        "images": total("images"),
        "replacements": total("replacements"),
        "builtin_generators": generator_keys,
        "plugins_or_external_generators": plugins,
        "helmCharts": key_nodes("helmCharts"),
        "remote_references": remote_references,
        "local_references": local_references,
        "path_traversal_references": path_traversal,
        "symlinks": symlinks,
    }


def aggregate(records, kind):
    occurrences = Counter()
    surfaces = defaultdict(set)
    repos = defaultdict(set)
    if kind == "helm":
        for i, r in enumerate(records):
            for k, v in r["constructs"].items():
                occurrences[k] += v
                if v:
                    surfaces[k].add(i)
                    repos[k].add(r["repo"])
            extras = {
                "dependencies": r["dependencies"],
                "dependency_aliases": r["dependency_aliases"],
                "dependency_conditions": r["dependency_conditions"],
                "dependency_tags": r["dependency_tags"],
                "file_dependencies": r["dependency_file_repos"],
                "remote_dependency_metadata": r["dependency_remote_repos"],
                "vendored_subcharts": r["vendored_archives"] + r["vendored_directories"],
                "missing_vendored_dependencies": len(r["missing_vendored_dependencies"]),
                "named_templates": r["definitions"],
                "dynamic_include_template_names": r["dynamic_calls"],
                "bounded_print_names": r["bounded_print_calls"],
                "nested_include_template": r["nested_calls"],
                "root_alias_context": r["root_alias_context_calls"],
                "equivalent_duplicate_definitions_proxy": r["duplicate_equivalent_proxy"],
                "nonequivalent_duplicate_definitions_proxy": r["duplicate_nonequivalent_proxy"],
            }
            for k, v in extras.items():
                occurrences[k] += v
                if v:
                    surfaces[k].add(i)
                    repos[k].add(r["repo"])
            for form, v in r["namespace_forms"].items():
                k = "namespace_" + form
                occurrences[k] += v
                if v:
                    surfaces[k].add(i)
                    repos[k].add(r["repo"])
            for call in r["namespace_helper_calls"]:
                labels = [
                    "namespace_helper_call_" + call["kind"],
                    "namespace_helper_body_" + call["helper_class"],
                    "namespace_helper_context_" + call["context"].replace("$", "dollar").replace(".", "dot"),
                ]
                if call["quote_pipeline"]:
                    labels.append("namespace_helper_quote_pipeline")
                for k in labels:
                    occurrences[k] += 1
                    surfaces[k].add(i)
                    repos[k].add(r["repo"])
    else:
        fields = [
            "resources", "bases", "components", "patches", "patchesStrategicMerge", "patchesJson6902",
            "namespace", "namePrefix", "nameSuffix", "commonLabels", "labels", "images", "replacements",
            "plugins_or_external_generators", "helmCharts",
        ]
        for i, r in enumerate(records):
            occurrences["kustomization_control_document"] += r["control_documents"]
            surfaces["kustomization_control_document"].add(i)
            repos["kustomization_control_document"].add(r["repo"])
            for k in fields:
                v = r[k]
                n = int(v) if isinstance(v, bool) else int(v or 0)
                occurrences[k] += n
                if n:
                    surfaces[k].add(i)
                    repos[k].add(r["repo"])
            list_fields = {
                "builtin_generators": len(r["builtin_generators"]),
                "remote_resources_bases": len(r["remote_references"]),
                "path_traversal": len(r["path_traversal_references"]),
                "symlinks": len(r["symlinks"]),
                "local_resources_bases_components": len(r["local_references"]),
            }
            for k, n in list_fields.items():
                occurrences[k] += n
                if n:
                    surfaces[k].add(i)
                    repos[k].add(r["repo"])
    return {
        k: {"occurrences": occurrences[k], "surfaces": len(surfaces[k]), "repositories": len(repos[k])}
        for k in sorted(occurrences)
    }


def main():
    helm = [helm_record(repo, root) for repo, root in HELM]
    kustomize = [kustomize_record(repo, root) for repo, root in KUSTOMIZE]
    result = {
        "corpus": {
            "helm_surfaces": len(helm),
            "helm_repositories": len({r["repo"] for r in helm}),
            "kustomize_surfaces": len(kustomize),
            "kustomize_repositories": len({r["repo"] for r in kustomize}),
        },
        "helm": helm,
        "helm_aggregate": aggregate(helm, "helm"),
        "kustomize": kustomize,
        "kustomize_aggregate": aggregate(kustomize, "kustomize"),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "inventory.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["corpus"], indent=2))


if __name__ == "__main__":
    main()
