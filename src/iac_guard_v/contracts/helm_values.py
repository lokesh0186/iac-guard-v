"""Protected effective Helm values used only for contract activation."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from ..helm import (
    HelmMaterializationEvidence,
    HelmRenderSpec,
    _dependency_path_value,
    _effective_values_projection,
    _effective_values_sha256,
    _inventory,
    _protected_values,
    _sha256,
    _strict_yaml,
    _validate_dependencies,
    _values_for_source,
)
from ..models import DomainError
from ..native_properties.model import canonical_digest
from .model import contract_canonical_json, contract_digest, contract_thaw


_ORIGINS = frozenset({
    "DEFAULT", "VALUES_FILE", "SET", "SET_STRING", "DEPENDENCY",
    "GLOBAL_OR_IMPORT", "DIRECT_INPUT", "ABSENT",
})


@dataclass(frozen=True, slots=True)
class EffectiveValueFact:
    context: str
    path: str
    present: bool
    value: Any
    origin: str
    origin_evidence: Mapping[str, Any]
    fact_digest: str

    @classmethod
    def build(
        cls, *, context: str, path: str, present: bool, value: Any,
        origin: str, origin_evidence: Mapping[str, Any],
    ) -> "EffectiveValueFact":
        if origin not in _ORIGINS:
            raise DomainError("effective value origin is unsupported")
        body = {
            "context": context,
            "path": path,
            "present": present,
            "value": value if present else None,
            "origin": origin,
            "origin_evidence": contract_thaw(contract_canonical_json(origin_evidence)),
        }
        return cls(
            context, path, present, contract_canonical_json(value) if present else None,
            origin, contract_canonical_json(origin_evidence), contract_digest(body),
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "path": self.path,
            "present": self.present,
            "value": contract_thaw(self.value) if self.present else None,
            "origin": self.origin,
            "origin_evidence": contract_thaw(self.origin_evidence),
            "fact_digest": self.fact_digest,
        }


@dataclass(frozen=True, slots=True)
class EffectiveValueUniverse:
    source_kind: str
    values_identity: str
    materialization_identity: str
    facts: tuple[EffectiveValueFact, ...]

    def __post_init__(self) -> None:
        if len({(item.context, item.path) for item in self.facts}) != len(self.facts):
            raise DomainError("effective value facts must be unique")

    @property
    def identity(self) -> str:
        return contract_digest({
            "source_kind": self.source_kind,
            "values_identity": self.values_identity,
            "materialization_identity": self.materialization_identity,
            "facts": [item.canonical_dict() for item in self.facts],
        })

    def find(self, context: str, path: str) -> EffectiveValueFact | None:
        return next((item for item in self.facts if item.context == context and item.path == path), None)


def _mapping_defines_path(value: object, path: str) -> bool:
    current = value
    parts = path.split(".")
    for index, part in enumerate(parts):
        if type(current) is not dict or part not in current:
            return False
        current = current[part]
        if index < len(parts) - 1 and type(current) is not dict:
            return True
    return True


def _root_origin(spec: HelmRenderSpec, path: str, present: bool) -> tuple[str, dict]:
    selected = "ABSENT"
    evidence: dict[str, Any] = {"source": "none"}
    default = spec.chart_root / "values.yaml"
    if default.is_file() and not default.is_symlink():
        value = _strict_yaml(default, "values.yaml")
        if _mapping_defines_path(value, path):
            selected = "DEFAULT"
            evidence = {"source": "values.yaml", "sha256": _sha256(default.read_bytes())}
    for ordinal, relative in enumerate(spec.values_files):
        candidate = spec.chart_root / relative
        value = _strict_yaml(candidate, "Helm values file")
        if _mapping_defines_path(value, path):
            selected = "VALUES_FILE"
            evidence = {"source": relative, "ordinal": ordinal, "sha256": _sha256(candidate.read_bytes())}
    for ordinal, (key, raw) in enumerate(spec.set_values):
        if key == path or path.startswith(f"{key}."):
            selected = "SET"
            evidence = {"key": key, "ordinal": ordinal, "value_sha256": _sha256(raw.encode("utf-8"))}
    for ordinal, (key, raw) in enumerate(spec.set_strings):
        if key == path or path.startswith(f"{key}."):
            selected = "SET_STRING"
            evidence = {"key": key, "ordinal": ordinal, "value_sha256": _sha256(raw.encode("utf-8"))}
    if not present and selected != "ABSENT":
        evidence = {**evidence, "effect": "PATH_ABSENT_AFTER_OVERRIDE"}
    return selected, evidence


def bind_helm_effective_values(
    spec: HelmRenderSpec,
    materialization: HelmMaterializationEvidence,
    requested_paths: tuple[tuple[str, str], ...],
) -> EffectiveValueUniverse:
    """Bind requested scalar paths to the same protected Values used by rendering."""
    if type(spec) is not HelmRenderSpec or type(materialization) is not HelmMaterializationEvidence:
        raise DomainError("Helm activation evidence requires exact materialization inputs")
    if type(requested_paths) is not tuple or len(requested_paths) > 256:
        raise DomainError("Helm activation path request is invalid")
    _, chart_root_sha = _inventory(spec.chart_root)
    if materialization.chart["inventory_root_sha256"] != chart_root_sha:
        raise DomainError("Helm activation chart differs from materialized chart")
    chart_value = _strict_yaml(spec.chart_root / "Chart.yaml", "Chart.yaml")
    root_values, _ = _protected_values(spec)
    dependencies = _validate_dependencies(
        spec.chart_root, chart_value, protected_values=root_values,
        repository_root=spec.protected_repository_root,
    )
    protected_values, values_identity = _protected_values(spec, dependencies)
    projection = _effective_values_projection(protected_values)
    rendered_values = materialization.render_inputs["protected_root_effective_values_sha256"]
    if _effective_values_sha256(protected_values) != rendered_values:
        raise DomainError("Helm activation values disagree with materialization evidence")
    facts = []
    for context, path in requested_paths:
        values = protected_values if context == "." else _values_for_source(protected_values, context)
        if projection.get("unmodeled") and context == ".":
            raise DomainError("Helm effective values include an unmodeled override")
        found, value = _dependency_path_value(values, path)
        if found and type(value) not in (str, bool, int, float) and value is not None:
            raise DomainError("contract activation path does not resolve to a scalar")
        if type(value) is float and (value != value or value in (float("inf"), float("-inf"))):
            raise DomainError("contract activation value is non-finite")
        if context == ".":
            origin, evidence = _root_origin(spec, path, found)
        else:
            origin = "GLOBAL_OR_IMPORT" if path.startswith("global.") else "DEPENDENCY"
            evidence = {
                "context": context,
                "chart_inventory_root_sha256": chart_root_sha,
                "dependency_closure_identity": dependencies.get("closure_identity", canonical_digest(dependencies)),
            }
        facts.append(EffectiveValueFact.build(
            context=context, path=path, present=found, value=value,
            origin=origin, origin_evidence=evidence,
        ))
    return EffectiveValueUniverse(
        "HELM_EFFECTIVE_VALUES_V1",
        values_identity,
        materialization.materialization_identity,
        tuple(sorted(facts, key=lambda item: (item.context, item.path))),
    )


def direct_effective_values(
    values: Mapping[str, Any], *, input_identity: str,
    requested_paths: tuple[tuple[str, str], ...],
) -> EffectiveValueUniverse:
    if type(values) not in (dict, MappingProxyType):
        raise DomainError("direct activation values must be a mapping")
    copied = contract_thaw(contract_canonical_json(values))
    facts = []
    for context, path in requested_paths:
        if context != ".":
            raise DomainError("direct activation values support only root context")
        found, value = _dependency_path_value(copied, path)
        if found and type(value) not in (str, bool, int, float) and value is not None:
            raise DomainError("direct activation path does not resolve to a scalar")
        facts.append(EffectiveValueFact.build(
            context=".", path=path, present=found, value=value,
            origin="DIRECT_INPUT" if found else "ABSENT",
            origin_evidence={"protected_input_identity": input_identity},
        ))
    return EffectiveValueUniverse(
        "PROTECTED_DIRECT_VALUES_V1", input_identity, input_identity,
        tuple(sorted(facts, key=lambda item: item.path)),
    )


__all__ = [
    "EffectiveValueFact", "EffectiveValueUniverse", "bind_helm_effective_values",
    "direct_effective_values",
]
