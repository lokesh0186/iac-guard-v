"""Strict, bounded parser for the one a10 contract convention."""
from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from ..models import DomainError
from .model import (
    ContractProvenance, InfrastructureContract, canonical_contract_bytes,
    contract_digest,
)
from .provenance import _regular_bytes, derive_contract_source


class _ContractLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise ConstructorError("while parsing contract", None, "YAML aliases are unsupported", event.start_mark)
        return super().compose_node(parent, index)


def _unique_mapping(loader: _ContractLoader, node: MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str:
            raise ConstructorError("while parsing contract", node.start_mark, "mapping keys must be strings", key_node.start_mark)
        if key in result:
            raise ConstructorError("while parsing contract", node.start_mark, f"duplicate key {key!r}", key_node.start_mark)
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_ContractLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def contract_schema() -> dict:
    return json.loads(files("iac_guard_v").joinpath(
        "schemas/infrastructure-contract-v1alpha1.schema.json"
    ).read_text(encoding="utf-8"))


def _depth(value: Any, current: int = 0) -> int:
    if current > 32:
        return current
    if type(value) is dict:
        return max(([_depth(item, current + 1) for item in value.values()] or [current]))
    if type(value) is list:
        return max(([_depth(item, current + 1) for item in value] or [current]))
    return current


def _parse_contract_content(content: bytes) -> dict:
    try:
        text = content.decode("utf-8")
        payload = yaml.load(text, Loader=_ContractLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise DomainError("contract is not strict UTF-8 YAML") from exc
    if type(payload) is not dict:
        raise DomainError("contract document must be a mapping")
    if _depth(payload) > 16:
        raise DomainError("contract document nesting exceeds the limit")
    try:
        jsonschema.Draft202012Validator(contract_schema()).validate(payload)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"infrastructure contract violation: {exc.message}") from exc
    canonical = json.loads(canonical_contract_bytes(payload))
    clauses = canonical["spec"]["expect"]
    clause_ids = [item["id"] for item in clauses]
    if len(clause_ids) != len(set(clause_ids)):
        raise DomainError("contract clause IDs must be unique")
    if not any(item.get("required", True) for item in clauses):
        raise DomainError("contract must contain at least one required clause")
    subjects = canonical["spec"]["subjects"]
    cardinality = subjects.get("cardinality", {})
    minimum = cardinality.get("min", 1)
    maximum = cardinality.get("max")
    allow_empty = cardinality.get("allowEmpty", False)
    if allow_empty and minimum > 0:
        raise DomainError("allowEmpty=true contradicts a positive subject minimum")
    if maximum is not None and maximum < minimum:
        raise DomainError("subject maximum must be at least its minimum")
    for clause in clauses:
        relation = clause.get("relationCardinality", {})
        if relation.get("targetMax") is not None and relation.get("targetMax") < relation.get("targetMin", 1):
            raise DomainError("target maximum must be at least its minimum")
    return canonical


def lint_contract(path: Path) -> dict:
    """Validate contract bytes and declarations without assigning provenance."""
    if not isinstance(path, Path):
        raise DomainError("contract lint path must use pathlib.Path")
    canonical = _parse_contract_content(_regular_bytes(path))
    return {
        "contract_name": canonical["metadata"]["name"],
        "canonical_digest": contract_digest(canonical),
    }


def load_contract(
    path: Path,
    *,
    project_root: Path,
    requested_provenance: ContractProvenance | None = None,
    source_commit: str = "WORKTREE",
) -> InfrastructureContract:
    source, content = derive_contract_source(
        path, project_root, requested_provenance, source_commit=source_commit
    )
    canonical = _parse_contract_content(content)
    spec = canonical["spec"]
    return InfrastructureContract(
        canonical["metadata"]["name"],
        spec["artifactClass"],
        spec.get("when"),
        spec["subjects"],
        spec["responsibility"],
        tuple(spec["expect"]),
        canonical,
        contract_digest(canonical),
        source,
    )


__all__ = ["contract_schema", "lint_contract", "load_contract"]
