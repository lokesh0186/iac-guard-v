"""Closed tri-state activation evaluation."""
from __future__ import annotations

from typing import Any, Mapping

from ..models import DomainError
from .helm_values import EffectiveValueUniverse
from .model import ActivationEvidence, ActivationStatus, contract_digest, contract_thaw


_SENSITIVE_VALUE_LEAVES = frozenset({
    "accesskey", "access_key", "apikey", "api_key", "clientsecret",
    "client_secret", "credential", "credentials", "password", "passwd",
    "privatekey", "private_key", "secretkey", "secret_key", "token",
})


def requested_activation_paths(expression: Mapping[str, Any] | None) -> tuple[tuple[str, str], ...]:
    if expression is None:
        return ()
    result: set[tuple[str, str]] = set()

    def walk(node: Mapping[str, Any], depth: int) -> None:
        if depth > 4:
            raise DomainError("contract activation nesting exceeds the limit")
        if "value" in node:
            condition = node["value"]
            path = condition["path"]
            if path.rsplit(".", 1)[-1].lower() in _SENSITIVE_VALUE_LEAVES:
                raise DomainError("contract activation refuses a secret-bearing value path")
            result.add((condition.get("context", "."), path))
            return
        children = node.get("all", node.get("any"))
        if type(children) not in (list, tuple):
            raise DomainError("contract activation expression is malformed")
        for child in children:
            walk(child, depth + 1)

    walk(expression, 0)
    return tuple(sorted(result))


def evaluate_activation(
    expression: Mapping[str, Any] | None,
    universe: EffectiveValueUniverse | None,
) -> ActivationEvidence:
    if expression is None:
        return ActivationEvidence(
            ActivationStatus.ACTIVE, "CONTRACT_UNCONDITIONAL", (),
            contract_digest({"activation": "unconditional"}),
        )
    if universe is None:
        return ActivationEvidence(
            ActivationStatus.ACTIVATION_NOT_EVALUATED,
            "ACTIVATION_INPUT_UNAVAILABLE", (), contract_digest({"activation": "missing"}),
        )
    facts: list[dict[str, Any]] = []

    def evaluate(node: Mapping[str, Any], depth: int) -> bool | None:
        if depth > 4:
            raise DomainError("contract activation nesting exceeds the limit")
        if "value" in node:
            condition = contract_thaw(node["value"])
            context = condition.get("context", ".")
            path = condition["path"]
            fact = universe.find(context, path)
            if fact is None:
                facts.append({"context": context, "path": path, "state": "UNAVAILABLE"})
                return None
            required_origin = condition.get("requireOrigin", "ANY_PROTECTED")
            origin_matches = required_origin == "ANY_PROTECTED" or fact.origin == required_origin
            if not origin_matches:
                state = None
            elif "present" in condition:
                state = fact.present is condition["present"]
            elif not fact.present:
                state = None
            else:
                expected = condition["equals"]
                state = None if type(fact.value) is not type(expected) else fact.value == expected
            facts.append({
                "context": context,
                "path": path,
                "condition": condition,
                "observed": fact.canonical_dict(),
                "origin_matches": origin_matches,
                "state": "UNKNOWN" if state is None else state,
            })
            return state
        if "all" in node:
            states = [evaluate(child, depth + 1) for child in node["all"]]
            if False in states:
                return False
            if None in states:
                return None
            return True
        if "any" in node:
            states = [evaluate(child, depth + 1) for child in node["any"]]
            if True in states:
                return True
            if None in states:
                return None
            return False
        raise DomainError("contract activation expression is malformed")

    try:
        state = evaluate(expression, 0)
    except DomainError:
        raise
    status = (
        ActivationStatus.ACTIVE if state is True
        else ActivationStatus.INACTIVE_CONDITION_FALSE if state is False
        else ActivationStatus.ACTIVATION_NOT_EVALUATED
    )
    reason = {
        ActivationStatus.ACTIVE: "ACTIVATION_CONDITION_TRUE",
        ActivationStatus.INACTIVE_CONDITION_FALSE: "ACTIVATION_CONDITION_FALSE",
        ActivationStatus.ACTIVATION_NOT_EVALUATED: "ACTIVATION_CONDITION_UNCERTAIN",
    }[status]
    return ActivationEvidence(status, reason, tuple(facts), universe.identity)


__all__ = ["evaluate_activation", "requested_activation_paths"]
