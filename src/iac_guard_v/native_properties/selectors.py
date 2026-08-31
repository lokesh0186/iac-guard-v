"""Exact Kubernetes LabelSelector evaluation with expression witnesses."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError


@dataclass(frozen=True, slots=True)
class SelectorExpressionWitness:
    key: str
    operator: str
    values: tuple[str, ...]
    observed_present: bool
    observed_value: str | None
    matched: bool

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "operator": self.operator,
            "values": list(self.values),
            "observed_present": self.observed_present,
            "observed_value": self.observed_value,
            "matched": self.matched,
        }


@dataclass(frozen=True, slots=True)
class SelectorEvaluation:
    selector: Mapping[str, Any]
    target_labels: Mapping[str, str]
    expressions: tuple[SelectorExpressionWitness, ...]
    matched: bool

    def canonical_dict(self) -> dict[str, Any]:
        match_labels = self.selector.get("matchLabels", {})
        match_expressions = self.selector.get("matchExpressions", ())
        return {
            "selector": {
                "matchLabels": dict(match_labels),
                "matchExpressions": [
                    {
                        "key": item["key"],
                        "operator": item["operator"],
                        "values": list(item.get("values", ())),
                    }
                    for item in match_expressions
                ],
            },
            "target_labels": dict(self.target_labels),
            "expressions": [item.canonical_dict() for item in self.expressions],
            "matched": self.matched,
        }


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if type(value) not in (dict, MappingProxyType):
        raise DomainError(f"{label} must be a mapping")
    return value


def _labels(value: Any, label: str) -> Mapping[str, str]:
    mapping = _mapping(value, label)
    result: dict[str, str] = {}
    for key, item in mapping.items():
        if type(key) is not str or not key or type(item) is not str:
            raise DomainError(f"{label} must contain nonempty string keys and string values")
        result[key] = item
    return MappingProxyType(dict(sorted(result.items())))


def normalize_label_selector(selector: Any) -> Mapping[str, Any]:
    raw = _mapping(selector, "Kubernetes LabelSelector")
    unknown = set(raw) - {"matchLabels", "matchExpressions"}
    if unknown:
        raise DomainError(f"unsupported Kubernetes LabelSelector fields: {sorted(unknown)}")
    match_labels = _labels(raw.get("matchLabels", {}), "selector.matchLabels")
    raw_expressions = raw.get("matchExpressions", ())
    if raw_expressions is None:
        raw_expressions = ()
    if type(raw_expressions) not in (list, tuple):
        raise DomainError("selector.matchExpressions must be a list")
    expressions: list[Mapping[str, Any]] = []
    for raw_expression in raw_expressions:
        expression = _mapping(raw_expression, "selector expression")
        if set(expression) - {"key", "operator", "values"}:
            raise DomainError("selector expression contains unsupported fields")
        key = expression.get("key")
        operator = expression.get("operator")
        if type(key) is not str or not key or operator not in {
            "In", "NotIn", "Exists", "DoesNotExist"
        }:
            raise DomainError("selector expression key/operator is malformed or unsupported")
        values = expression.get("values", ())
        if values is None:
            values = ()
        if type(values) not in (list, tuple) or any(type(item) is not str for item in values):
            raise DomainError("selector expression values must be a string list")
        values_tuple = tuple(values)
        if operator in {"In", "NotIn"} and not values_tuple:
            raise DomainError(f"selector operator {operator} requires nonempty values")
        if operator in {"Exists", "DoesNotExist"} and values_tuple:
            raise DomainError(f"selector operator {operator} requires empty values")
        expressions.append(MappingProxyType({
            "key": key,
            "operator": operator,
            "values": values_tuple,
        }))
    return MappingProxyType({
        "matchLabels": match_labels,
        "matchExpressions": tuple(expressions),
    })


def service_selector_as_label_selector(selector: Any) -> Mapping[str, Any]:
    labels = _labels(selector, "Service selector")
    return MappingProxyType({"matchLabels": labels, "matchExpressions": ()})


def evaluate_label_selector(selector: Any, labels: Any) -> SelectorEvaluation:
    normalized = normalize_label_selector(selector)
    target = _labels(labels, "target labels")
    witnesses: list[SelectorExpressionWitness] = []
    matched = True
    for key, expected in normalized["matchLabels"].items():
        present = key in target
        observed = target.get(key)
        expression_match = present and observed == expected
        witnesses.append(SelectorExpressionWitness(
            key, "Equals", (expected,), present, observed, expression_match
        ))
        matched = matched and expression_match
    for expression in normalized["matchExpressions"]:
        key = expression["key"]
        operator = expression["operator"]
        values = expression["values"]
        present = key in target
        observed = target.get(key)
        if operator == "In":
            expression_match = present and observed in values
        elif operator == "NotIn":
            # Kubernetes set-based negative selectors also match resources for
            # which the key is absent.  This deliberately differs from In.
            expression_match = not present or observed not in values
        elif operator == "Exists":
            expression_match = present
        else:
            expression_match = not present
        witnesses.append(SelectorExpressionWitness(
            key, operator, values, present, observed, expression_match
        ))
        matched = matched and expression_match
    return SelectorEvaluation(normalized, target, tuple(witnesses), matched)


__all__ = [
    "SelectorEvaluation",
    "SelectorExpressionWitness",
    "evaluate_label_selector",
    "normalize_label_selector",
    "service_selector_as_label_selector",
]
