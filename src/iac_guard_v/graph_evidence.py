"""Bounded, fail-closed evidence for Checkov connection graph checks.

The scanner's JSON names only the primary resource for many CKV2 checks.  This
module independently inventories the supported source relationships and binds a
positive or negative scanner evaluation to exact nodes, edges, input bytes, and
the installed graph-policy definition.  Unsupported query or source shapes stay
inconclusive.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hcl2
import yaml
from lark.exceptions import LarkError

from .enums import ArtifactKind, CheckEvaluationResult, Status
from .models import (
    BoundInputFile,
    DomainError,
    ExpectedResource,
    GraphCheckEvidence,
    GraphEdgeEvidence,
    GraphParticipant,
    canonical_identifier,
    canonical_repo_path,
)
from .terraform_parser import TerraformParserError, parse_terraform_structure


_GRAPH_CHECK_CLASS = "checkov.common.graph.checks_infra.base_check"
_TERRAFORM_REFERENCE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]*\.[A-Za-z][A-Za-z0-9_-]*)(?:\.|\[)"
)
_KUBERNETES_WORKLOAD_KINDS = frozenset({
    "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
})
_SUPPORTED_GRAPH_FRAMEWORKS = frozenset({"terraform", "kubernetes"})


def _sha256_json(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def input_manifest_sha256(files: tuple[BoundInputFile, ...]) -> str:
    if type(files) is not tuple:
        raise DomainError("graph input files must be an exact tuple")
    return _sha256_json([item.canonical_dict() for item in files])


@dataclass(frozen=True, slots=True)
class _GraphNode:
    participant: GraphParticipant
    graph_types: tuple[str, ...]
    aliases: tuple[str, ...]
    attributes: dict

    def __post_init__(self) -> None:
        if type(self.participant) is not GraphParticipant:
            raise DomainError("graph node requires an exact participant")
        if type(self.graph_types) is not tuple or not self.graph_types:
            raise DomainError("graph node types must be a nonempty exact tuple")
        if type(self.aliases) is not tuple or not self.aliases:
            raise DomainError("graph node aliases must be a nonempty exact tuple")
        if type(self.attributes) is not dict:
            raise DomainError("graph node attributes must be an exact mapping")


@dataclass(frozen=True, slots=True)
class _GraphQuery:
    primary_types: tuple[str, ...]
    connected_types: tuple[str, ...]
    attribute_requirements: tuple[tuple[str, tuple[str, ...], object], ...]
    policy_definition_sha256: str
    query_identity_sha256: str


@dataclass(frozen=True, slots=True)
class GraphEvidenceContext:
    nodes: tuple[_GraphNode, ...]
    edges: tuple[GraphEdgeEvidence, ...]
    ambiguous_nodes: tuple[tuple[str, str], ...]
    ambiguous_relations: tuple[tuple[str, str], ...]
    manifest_sha256: str
    source_snapshot_sha256: str
    source_snapshot_bound: bool
    policy_inventory_sha256: str
    queries: tuple[tuple[str, str, _GraphQuery | None], ...]
    auxiliary_identities: tuple[tuple[str, str], ...]
    frameworks: tuple[str, ...]

    def _resolve(self, file_path: str, native_resource: str) -> _GraphNode | None:
        path = canonical_repo_path(file_path)
        matches = tuple(
            item for item in self.nodes
            if item.participant.file_path == path and native_resource in item.aliases
        )
        if not matches:
            return None
        if len(matches) != 1:
            raise DomainError("graph primary target identity is missing or ambiguous")
        return matches[0]

    def evidence_for(
        self,
        *,
        framework: str,
        file_path: str,
        native_resource: str,
        rule_id: str,
        check_class: object,
        native_result: CheckEvaluationResult,
    ) -> GraphCheckEvidence | None:
        rule = canonical_identifier(rule_id, "graph check id")
        query_matches = tuple(
            item[2] for item in self.queries
            if item[0] == framework and item[1] == rule
        )
        query = query_matches[0] if len(query_matches) == 1 else None
        is_graph_rule = rule.startswith("CKV2_")
        if not is_graph_rule:
            return None
        primary = self._resolve(file_path, native_resource)
        if primary is None:
            return None
        is_graph_class = check_class == _GRAPH_CHECK_CLASS
        if not self.source_snapshot_bound:
            return _inconclusive(
                primary.participant, self, "GRAPH_SNAPSHOT_IDENTITY_UNBOUND", query
            )
        if query is None or not is_graph_class:
            return _inconclusive(
                primary.participant,
                self,
                "GRAPH_POLICY_OR_CLASS_UNSUPPORTED",
            )
        if not set(primary.graph_types).intersection(query.primary_types):
            return _inconclusive(
                primary.participant, self, "GRAPH_PRIMARY_TYPE_MISMATCH", query
            )
        if (primary.participant.file_path, primary.participant.resource_address) in set(
            self.ambiguous_nodes
        ):
            return _inconclusive(
                primary.participant, self, "GRAPH_PRIMARY_IDENTITY_AMBIGUOUS", query
            )
        adjacent: list[tuple[GraphEdgeEvidence, _GraphNode]] = []
        nodes_by_key = {item.participant.canonical_key: item for item in self.nodes}
        for edge in self.edges:
            other = None
            if edge.source.canonical_key == primary.participant.canonical_key:
                other = nodes_by_key.get(edge.target.canonical_key)
            elif edge.target.canonical_key == primary.participant.canonical_key:
                other = nodes_by_key.get(edge.source.canonical_key)
            if other is not None and set(other.graph_types).intersection(
                query.connected_types
            ):
                adjacent.append((edge, other))
        ambiguity_keys = set(self.ambiguous_relations)
        if any(
            key[0] == primary.participant.resource_address
            or key[1] == primary.participant.resource_address
            for key in ambiguity_keys
        ):
            return _inconclusive(
                primary.participant, self, "GRAPH_RELATIONSHIP_AMBIGUOUS", query
            )
        satisfying: list[tuple[GraphEdgeEvidence, _GraphNode]] = []
        for edge, node in adjacent:
            if _attributes_satisfy(node, query.attribute_requirements):
                satisfying.append((edge, node))
        computed_pass = bool(satisfying)
        scanner_pass = native_result is CheckEvaluationResult.PASSED
        scanner_fail = native_result is CheckEvaluationResult.FAILED
        if not (scanner_pass or scanner_fail):
            selected = adjacent
        elif computed_pass != scanner_pass:
            return _inconclusive(
                primary.participant, self, "GRAPH_RESULT_MISMATCH", query
            )
        else:
            selected = satisfying if scanner_pass else adjacent
        participants = [primary.participant]
        edges = []
        for edge, node in selected:
            participants.append(node.participant)
            edges.append(edge)
        return GraphCheckEvidence(
            Status.PASS,
            "GRAPH_EVIDENCE_COMPLETE",
            primary.participant,
            tuple(participants),
            tuple(edges),
            self.manifest_sha256,
            self.source_snapshot_sha256,
            self.policy_inventory_sha256,
            query.policy_definition_sha256,
            query.query_identity_sha256,
        )


def _inconclusive(
    primary: GraphParticipant,
    context: GraphEvidenceContext,
    reason: str,
    query: _GraphQuery | None = None,
) -> GraphCheckEvidence:
    empty_digest = hashlib.sha256(b"").hexdigest()
    return GraphCheckEvidence(
        Status.INCONCLUSIVE,
        reason,
        primary,
        (primary,),
        (),
        context.manifest_sha256,
        context.source_snapshot_sha256,
        context.policy_inventory_sha256,
        query.policy_definition_sha256 if query else empty_digest,
        query.query_identity_sha256 if query else empty_digest,
    )


def _attributes_satisfy(
    node: _GraphNode,
    requirements: tuple[tuple[str, tuple[str, ...], object], ...],
) -> bool:
    for attribute, resource_types, expected in requirements:
        if not set(node.graph_types).intersection(resource_types):
            continue
        value: object = node.attributes
        for part in attribute.split("."):
            if type(value) is not dict or part not in value:
                return False
            value = value[part]
        if value != expected and value != [expected]:
            return False
    return True


def _installation_roots(executable: Path) -> tuple[Path, ...]:
    resolved = executable.resolve(strict=True)
    try:
        first_line = resolved.read_bytes().splitlines()[0].decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError, IndexError) as exc:
        raise DomainError("Checkov launcher cannot identify graph policy roots") from exc
    candidates = []
    if first_line.startswith("#!"):
        interpreter = Path(first_line[2:].strip().split()[0])
        if interpreter.is_absolute():
            candidates.append(interpreter.parent.parent)
    candidates.append(resolved.parent.parent)
    for candidate in candidates:
        roots = tuple(sorted(
            root.resolve(strict=True)
            for root in candidate.glob("lib/python*/site-packages/checkov")
        ))
        if roots:
            return roots
    raise DomainError("Checkov graph policy roots are unavailable")


def _load_graph_queries(
    roots: tuple[Path, ...], frameworks: tuple[str, ...]
) -> tuple[tuple[str, str, _GraphQuery | None], ...]:
    matches: dict[tuple[str, str], list[tuple[bytes, dict]]] = {}
    for framework in frameworks:
        if framework not in _SUPPORTED_GRAPH_FRAMEWORKS:
            continue
        for root in roots:
            graph_root = root / framework / "checks" / "graph_checks"
            if not graph_root.is_dir():
                continue
            paths = tuple(graph_root.rglob("*.yaml")) + tuple(
                graph_root.rglob("*.json")
            )
            for path in sorted(paths):
                if path.is_symlink() or not path.is_file():
                    raise DomainError(
                        "Checkov graph policy must be a regular nonsymlink file"
                    )
                raw = path.read_bytes()
                if len(raw) > 1024 * 1024:
                    raise DomainError("Checkov graph policy exceeds its size limit")
                try:
                    value = (
                        json.loads(raw.decode("utf-8", errors="strict"))
                        if path.suffix == ".json" else yaml.safe_load(raw)
                    )
                except (
                    UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError
                ) as exc:
                    raise DomainError("Checkov graph policy document is malformed") from exc
                if type(value) is not dict:
                    continue
                metadata = value.get("metadata")
                raw_rule = metadata.get("id") if type(metadata) is dict else None
                if type(raw_rule) is not str or not raw_rule.startswith("CKV2_"):
                    continue
                rule = canonical_identifier(raw_rule, "graph check id")
                matches.setdefault((framework, rule), []).append((raw, value))
    result = []
    for (framework, rule), policies in sorted(matches.items()):
        query = (
            _parse_graph_query(policies[0][0], policies[0][1], rule)
            if len(policies) == 1 else None
        )
        result.append((framework, rule, query))
    return tuple(result)


def _parse_graph_query(raw: bytes, policy: dict, rule: str) -> _GraphQuery | None:
    definition = policy.get("definition")
    if type(definition) is not dict or set(definition) != {"and"}:
        return None
    conditions = definition["and"]
    if type(conditions) is not list or not conditions:
        return None
    connection = []
    primary_filter: set[str] | None = None
    attributes = []
    for condition in conditions:
        if type(condition) is not dict:
            return None
        cond_type = condition.get("cond_type")
        if cond_type == "connection":
            if condition.get("operator") != "exists":
                return None
            primary = condition.get("resource_types")
            connected = condition.get("connected_resource_types")
            if (
                type(primary) is not list or not primary
                or type(connected) is not list or not connected
                or any(type(item) is not str for item in (*primary, *connected))
            ):
                return None
            connection.append((tuple(primary), tuple(connected)))
        elif cond_type == "filter":
            if (
                condition.get("attribute") != "resource_type"
                or condition.get("operator") != "within"
                or type(condition.get("value")) is not list
                or any(type(item) is not str for item in condition["value"])
            ):
                return None
            primary_filter = set(condition["value"])
        elif cond_type == "attribute":
            resource_types = condition.get("resource_types")
            attribute = condition.get("attribute")
            if (
                condition.get("operator") != "equals"
                or type(resource_types) is not list or not resource_types
                or any(type(item) is not str for item in resource_types)
                or type(attribute) is not str or not attribute
            ):
                return None
            attributes.append((attribute, tuple(resource_types), condition.get("value")))
        else:
            return None
    if len(connection) != 1:
        return None
    primary_types, connected_types = connection[0]
    if primary_filter is not None:
        primary_types = tuple(item for item in primary_types if item in primary_filter)
    if not primary_types:
        return None
    payload = {
        "contract": "iacgv-checkov-connection-query-v1",
        "rule_id": rule,
        "primary_types": sorted(set(primary_types)),
        "connected_types": sorted(set(connected_types)),
        "attribute_requirements": [
            [attribute, sorted(set(types)), expected]
            for attribute, types, expected in attributes
        ],
    }
    return _GraphQuery(
        tuple(sorted(set(primary_types))),
        tuple(sorted(set(connected_types))),
        tuple(sorted(attributes, key=lambda item: (item[0], item[1]))),
        hashlib.sha256(raw).hexdigest(),
        _sha256_json(payload),
    )


def _terraform_nodes_and_edges(
    scan_root: Path, expected: tuple[ExpectedResource, ...]
) -> tuple[
    list[_GraphNode], list[GraphEdgeEvidence], list[tuple[str, str]],
    list[tuple[str, str]],
]:
    terraform = tuple(
        item for item in expected if item.artifact_kind is ArtifactKind.TERRAFORM_HCL
    )
    expected_by_key = {(item.file_path, item.resource_address): item for item in terraform}
    nodes = []
    auxiliary = []
    for file_path in sorted({item.file_path for item in terraform}):
        try:
            document = parse_terraform_structure(
                (scan_root / file_path).read_bytes()
            ).document
        except TerraformParserError as exc:
            raise DomainError(str(exc)) from exc
        except (OSError, LarkError) as exc:
            raise DomainError("Terraform graph inventory could not parse bound source") from exc
        if type(document) is not dict:
            raise DomainError("Terraform graph parser returned an invalid document")
        data_blocks = document.get("data", [])
        if type(data_blocks) is not list:
            raise DomainError("Terraform graph data structure is invalid")
        for block in data_blocks:
            if type(block) is not dict:
                raise DomainError("Terraform graph data block is invalid")
            for data_type, instances in block.items():
                if type(data_type) is not str or type(instances) is not dict:
                    raise DomainError("Terraform graph data identity is invalid")
                for name in instances:
                    if type(name) is not str:
                        raise DomainError("Terraform graph data identity is invalid")
                    auxiliary.append((file_path, f"{data_type}.{name}"))
        provider_blocks = document.get("provider", [])
        if type(provider_blocks) is not list:
            raise DomainError("Terraform graph provider structure is invalid")
        for block in provider_blocks:
            if type(block) is not dict:
                raise DomainError("Terraform graph provider block is invalid")
            for provider_type, attributes in block.items():
                if type(provider_type) is not str or type(attributes) is not dict:
                    raise DomainError("Terraform graph provider identity is invalid")
                alias = attributes.get("alias", "default")
                if type(alias) is not str:
                    raise DomainError("Terraform graph provider alias is unresolved")
                auxiliary.append((file_path, f"{provider_type}.{alias}"))
        blocks = document.get("resource", []) if type(document) is dict else []
        if type(blocks) is not list:
            raise DomainError("Terraform graph resource structure is invalid")
        for block in blocks:
            if type(block) is not dict:
                raise DomainError("Terraform graph resource block is invalid")
            for resource_type, instances in block.items():
                if type(resource_type) is not str or type(instances) is not dict:
                    raise DomainError("Terraform graph resource identity is invalid")
                for name, attrs in instances.items():
                    address = f"{resource_type}.{name}"
                    item = expected_by_key.get((file_path, address))
                    if item is None or type(attrs) is not dict:
                        raise DomainError("Terraform graph inventory disagrees with resources")
                    participant = GraphParticipant(
                        file_path, address, ArtifactKind.TERRAFORM_HCL, resource_type
                    )
                    nodes.append(_GraphNode(participant, (resource_type,), (address,), attrs))
    address_nodes: dict[str, list[_GraphNode]] = {}
    for node in nodes:
        address_nodes.setdefault(node.participant.resource_address, []).append(node)
    edges = []
    ambiguous = []
    resource_types = {item.participant.resource_type for item in nodes}
    for node in nodes:
        for attribute_path, reference in _references(node.attributes):
            target_nodes = address_nodes.get(reference, [])
            if len(target_nodes) == 1:
                target = target_nodes[0]
                if target.participant.canonical_key != node.participant.canonical_key:
                    edges.append(GraphEdgeEvidence(
                        node.participant,
                        target.participant,
                        "terraform_reference",
                        f"{attribute_path}:{reference}",
                    ))
            elif len(target_nodes) > 1 or reference.split(".", 1)[0] in resource_types:
                ambiguous.append((node.participant.resource_address, reference))
    unique_edges = {item.canonical_key: item for item in edges}
    expected_keys = set(expected_by_key)
    bounded_auxiliary = sorted(set(auxiliary) - expected_keys)
    return nodes, list(unique_edges.values()), sorted(set(ambiguous)), bounded_auxiliary


def _references(value: object, path: str = "resource") -> tuple[tuple[str, str], ...]:
    result = []
    if type(value) is dict:
        for key, child in sorted(value.items()):
            if type(key) is str:
                result.extend(_references(child, f"{path}.{key}"))
    elif type(value) is list:
        for index, child in enumerate(value):
            result.extend(_references(child, f"{path}[{index}]"))
    elif type(value) is str:
        result.extend((path, match.group(1)) for match in _TERRAFORM_REFERENCE.finditer(value))
    return tuple(result)


def _kubernetes_documents(path: Path) -> tuple[dict, ...]:
    try:
        if path.suffix.lower() == ".json":
            value = json.loads(path.read_text(encoding="utf-8"))
            values = (value,)
        else:
            values = tuple(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise DomainError("Kubernetes graph inventory could not parse bound source") from exc
    result = []
    for value in values:
        if value is None:
            continue
        if type(value) is not dict:
            raise DomainError("Kubernetes graph document must be a mapping")
        if value.get("kind") == "List":
            items = value.get("items")
            if type(items) is not list or any(type(item) is not dict for item in items):
                raise DomainError("Kubernetes graph List items must be mappings")
            result.extend(items)
        else:
            result.append(value)
    return tuple(result)


def _kubernetes_nodes_and_edges(
    scan_root: Path, expected: tuple[ExpectedResource, ...]
) -> tuple[list[_GraphNode], list[GraphEdgeEvidence], list[tuple[str, str]]]:
    kubernetes = tuple(
        item for item in expected
        if item.artifact_kind in {ArtifactKind.KUBERNETES_YAML, ArtifactKind.KUBERNETES_JSON}
    )
    expected_by_key = {(item.file_path, item.resource_address): item for item in kubernetes}
    nodes = []
    selector_ambiguities = []
    for file_path in sorted({item.file_path for item in kubernetes}):
        for document in _kubernetes_documents(scan_root / file_path):
            metadata = document.get("metadata")
            api_version = document.get("apiVersion")
            kind = document.get("kind")
            if type(metadata) is not dict or type(api_version) is not str or type(kind) is not str:
                continue
            name = metadata.get("name")
            namespace = metadata.get("namespace", "default") or "default"
            if type(name) is not str or type(namespace) is not str:
                continue
            address = f"{api_version}/{kind}/{namespace}/{name}"
            item = expected_by_key.get((file_path, address))
            if item is None:
                raise DomainError("Kubernetes graph inventory disagrees with resources")
            participant = GraphParticipant(file_path, address, item.artifact_kind, kind)
            graph_types = [kind]
            aliases = [item.scanner_native_lookup]
            if kind in _KUBERNETES_WORKLOAD_KINDS:
                labels = _workload_labels(document, kind)
                if labels is not None:
                    graph_types.append("Pod")
                    declared_suffix = "".join(
                        f".{key}-{value}" for key, value in labels.items()
                    )
                    canonical_suffix = "".join(
                        f".{key}-{value}" for key, value in sorted(labels.items())
                    )
                    aliases.extend((
                        f"Pod.{namespace}.{name}{declared_suffix}",
                        f"Pod.{namespace}.{name}{canonical_suffix}",
                    ))
                else:
                    selector_ambiguities.append((address, "Pod"))
            nodes.append(_GraphNode(
                participant,
                tuple(sorted(set(graph_types))),
                tuple(sorted(set(aliases))),
                document,
            ))
    edges = []
    policies = [node for node in nodes if "NetworkPolicy" in node.graph_types]
    workloads = [node for node in nodes if "Pod" in node.graph_types]
    for policy in policies:
        policy_metadata = policy.attributes.get("metadata", {})
        namespace = policy_metadata.get("namespace", "default") or "default"
        selector = policy.attributes.get("spec", {}).get("podSelector")
        selector_digest = _sha256_json(selector)
        for workload in workloads:
            workload_metadata = workload.attributes.get("metadata", {})
            workload_namespace = workload_metadata.get("namespace", "default") or "default"
            labels = _workload_labels(
                workload.attributes, workload.participant.resource_type
            )
            matched = _selector_matches(selector, labels)
            if matched is None:
                selector_ambiguities.append((
                    workload.participant.resource_address,
                    policy.participant.resource_address,
                ))
            elif namespace == workload_namespace and matched:
                edges.append(GraphEdgeEvidence(
                    policy.participant,
                    workload.participant,
                    "kubernetes_network_policy_selector",
                    f"spec.podSelector:{selector_digest}",
                ))
    unique_edges = {item.canonical_key: item for item in edges}
    return nodes, list(unique_edges.values()), sorted(set(selector_ambiguities))


def _workload_labels(document: dict, kind: str) -> dict[str, str] | None:
    if kind == "Pod":
        metadata = document.get("metadata")
    elif kind == "CronJob":
        metadata = (
            document.get("spec", {}).get("jobTemplate", {}).get("spec", {})
            .get("template", {}).get("metadata")
        )
    else:
        metadata = document.get("spec", {}).get("template", {}).get("metadata")
    if type(metadata) is not dict:
        return None
    labels = metadata.get("labels", {})
    if type(labels) is not dict or any(
        type(key) is not str or type(value) is not str for key, value in labels.items()
    ):
        return None
    return labels


def _selector_matches(selector: object, labels: dict[str, str] | None) -> bool | None:
    if labels is None or type(selector) is not dict:
        return None
    match_labels = selector.get("matchLabels", {})
    match_expressions = selector.get("matchExpressions", [])
    if (
        type(match_labels) is not dict
        or any(type(key) is not str or type(value) is not str for key, value in match_labels.items())
        or type(match_expressions) is not list
    ):
        return None
    if any(labels.get(key) != value for key, value in match_labels.items()):
        return False
    for expression in match_expressions:
        if type(expression) is not dict or type(expression.get("key")) is not str:
            return None
        key = expression["key"]
        operator = expression.get("operator")
        values = expression.get("values", [])
        if type(values) is not list or any(type(value) is not str for value in values):
            return None
        if operator == "In" and labels.get(key) not in values:
            return False
        if operator == "NotIn" and (key not in labels or labels[key] in values):
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
        if operator not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            return None
    return True


def build_graph_evidence_context(
    *,
    executable: Path,
    scan_root: Path,
    frameworks: tuple[str, ...],
    expected_resources: tuple[ExpectedResource, ...],
    input_files: tuple[BoundInputFile, ...],
    source_snapshot_sha256: str,
    policy_inventory_sha256: str,
) -> GraphEvidenceContext:
    """Build a complete bounded graph from the exact request-bound source bytes."""
    nodes = []
    edges = []
    ambiguous_relations = []
    auxiliary_identities = []
    if "terraform" in frameworks:
        tf_nodes, tf_edges, tf_ambiguous, tf_auxiliary = _terraform_nodes_and_edges(
            scan_root, expected_resources
        )
        nodes.extend(tf_nodes)
        edges.extend(tf_edges)
        ambiguous_relations.extend(tf_ambiguous)
        auxiliary_identities.extend(tf_auxiliary)
    if "kubernetes" in frameworks:
        k8s_nodes, k8s_edges, k8s_ambiguous = _kubernetes_nodes_and_edges(
            scan_root, expected_resources
        )
        nodes.extend(k8s_nodes)
        edges.extend(k8s_edges)
        ambiguous_relations.extend(k8s_ambiguous)
    participant_keys = [item.participant.canonical_key for item in nodes]
    ambiguous_nodes = []
    by_address: dict[str, list[_GraphNode]] = {}
    for node in nodes:
        by_address.setdefault(node.participant.resource_address, []).append(node)
    for address, matches in by_address.items():
        if len(matches) > 1:
            ambiguous_nodes.extend(
                (item.participant.file_path, address) for item in matches
            )
    if len(participant_keys) != len(set(participant_keys)):
        raise DomainError("graph inventory contains duplicate participant identities")
    snapshot_bound = (
        type(source_snapshot_sha256) is str
        and re.fullmatch(r"[0-9a-f]{64}", source_snapshot_sha256) is not None
    )
    snapshot_identity = (
        source_snapshot_sha256
        if snapshot_bound
        else hashlib.sha256(b"unbound-source-snapshot").hexdigest()
    )
    policy_roots = _installation_roots(executable)
    return GraphEvidenceContext(
        tuple(sorted(nodes, key=lambda item: item.participant.canonical_key)),
        tuple(sorted(edges, key=lambda item: item.canonical_key)),
        tuple(sorted(set(ambiguous_nodes))),
        tuple(sorted(set(ambiguous_relations))),
        input_manifest_sha256(input_files),
        snapshot_identity,
        snapshot_bound,
        policy_inventory_sha256,
        _load_graph_queries(policy_roots, tuple(sorted(frameworks))),
        tuple(sorted(set(auxiliary_identities))),
        tuple(sorted(frameworks)),
    )


__all__ = ["GraphEvidenceContext", "build_graph_evidence_context", "input_manifest_sha256"]
