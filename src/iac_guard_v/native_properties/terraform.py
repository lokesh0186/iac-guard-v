"""Exact source-local Terraform resource-reference relationships."""
from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError
from .model import NativePropertyRequest, NativePropertyResult, thaw_json
from .outcome import EvaluationOutcome
from .universe import ProtectedNativeUniverse, TerraformResource


_DIRECT_TRAVERSAL = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]*)"
    r"((?:\.[A-Za-z_][A-Za-z0-9_-]*|\[[^\]]+\])+)?"
)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if type(value) not in (dict, MappingProxyType):
        raise DomainError(f"{label} must be a mapping")
    return value


def _attribute_value(body: Mapping[str, Any], path: list[Any]) -> Any:
    current: Any = body
    for token in path:
        while type(current) in (list, tuple) and len(current) == 1 and type(token) is str:
            current = current[0]
        if type(token) is str:
            current = _mapping(current, "Terraform attribute path").get(token, _MISSING)
        elif type(token) is int and type(token) is not bool:
            if type(current) not in (list, tuple) or not 0 <= token < len(current):
                return _MISSING
            current = current[token]
        else:
            raise DomainError("Terraform attribute path tokens must be strings or integers")
        if current is _MISSING:
            return _MISSING
    return current


_MISSING = object()


def _references(value: Any) -> tuple[tuple[str, str], ...]:
    found: set[tuple[str, str]] = set()

    def visit(item: Any) -> None:
        if type(item) is str:
            matches = tuple(_DIRECT_TRAVERSAL.finditer(item))
            for match in matches:
                address = match.group(1)
                root = address.split(".", 1)[0]
                if root in {"var", "local", "module", "data", "path", "terraform"}:
                    raise DomainError("TERRAFORM_REFERENCE_EXPRESSION_UNSUPPORTED")
                found.add((address, match.group(0)))
            stripped = item
            for match in reversed(matches):
                stripped = stripped[:match.start()] + stripped[match.end():]
            stripped = stripped.replace("${", "").replace("}", "").strip()
            if stripped and any(character in stripped for character in "()?*+/!=<>"):
                raise DomainError("TERRAFORM_REFERENCE_EXPRESSION_UNSUPPORTED")
        elif type(item) in (tuple, list):
            for child in item:
                visit(child)
        elif type(item) in (dict, MappingProxyType):
            for child in item.values():
                visit(child)
        elif item is None or type(item) in (bool, int, float):
            return
        else:
            raise DomainError("TERRAFORM_REFERENCE_EXPRESSION_UNSUPPORTED")

    visit(value)
    return tuple(sorted(found))


def _resource_block_span(resource: TerraformResource) -> tuple[int, int]:
    pattern = re.compile(
        r'\bresource\s+"' + re.escape(resource.resource_type) + r'"\s+"'
        + re.escape(resource.resource_name) + r'"\s*\{'
    )
    matches = tuple(pattern.finditer(resource.source_text))
    if len(matches) != 1:
        raise DomainError("TERRAFORM_SOURCE_RESOURCE_SPAN_AMBIGUOUS")
    start = matches[0].start()
    opening = matches[0].end() - 1
    depth = 0
    index = opening
    state = "code"
    while index < len(resource.source_text):
        char = resource.source_text[index]
        nxt = resource.source_text[index + 1] if index + 1 < len(resource.source_text) else ""
        if state == "string":
            if char == "\\":
                index += 2
                continue
            if char == '"':
                state = "code"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                state = "code"
                index += 2
                continue
        else:
            if char == '"':
                state = "string"
            elif char == "#" or (char == "/" and nxt == "/"):
                state = "line_comment"
                if char == "/":
                    index += 1
            elif char == "/" and nxt == "*":
                state = "block_comment"
                index += 1
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return start, index + 1
        index += 1
    raise DomainError("TERRAFORM_SOURCE_RESOURCE_SPAN_UNTERMINATED")


def _reference_span(resource: TerraformResource, traversal: str) -> dict[str, int]:
    start, end = _resource_block_span(resource)
    block = resource.source_text[start:end]
    matches = tuple(re.finditer(re.escape(traversal), block))
    if len(matches) != 1:
        raise DomainError("TERRAFORM_REFERENCE_SOURCE_SPAN_AMBIGUOUS")
    absolute_start = start + matches[0].start()
    absolute_end = start + matches[0].end()
    return {
        "start_byte": len(resource.source_text[:absolute_start].encode("utf-8")),
        "end_byte": len(resource.source_text[:absolute_end].encode("utf-8")),
        "start_line": resource.source_text.count("\n", 0, absolute_start) + 1,
        "end_line": resource.source_text.count("\n", 0, absolute_end) + 1,
    }


def _reference_cycle(
    universe: ProtectedNativeUniverse, source_identity: str, target_identity: str
) -> bool:
    edges: dict[str, set[str]] = {}
    protected = {item.identity for item in universe.terraform_resources}
    for resource in universe.terraform_resources:
        try:
            references = _references(resource.body)
        except DomainError:
            references = ()
        edges[resource.identity] = {
            address for address, _ in references if address in protected
        }
    pending = [target_identity]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current == source_identity:
            return True
        if current in seen:
            continue
        seen.add(current)
        pending.extend(sorted(edges.get(current, ())))
    return False


def evaluate_reference_resolves(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome:
    source = universe.terraform_resource(request.subject_identity)
    params = thaw_json(request.parameters)
    path = params.get("attribute_path")
    expected_target = params.get("expected_target")
    mode = params.get("mode", "DIRECT")
    complete = params.get("complete_expected_domain", False)
    reference_contract = params.get("reference_contract_digest")
    if type(path) is not list or not path:
        raise DomainError("Terraform reference attribute_path must be a nonempty list")
    if type(expected_target) is not str:
        raise DomainError("Terraform reference expected_target must be a string")
    if mode != "DIRECT":
        return EvaluationOutcome(
            NativePropertyResult.UNSUPPORTED,
            "TERRAFORM_TRANSITIVE_REFERENCE_UNSUPPORTED",
            {
                "source": source.provenance_dict(),
                "attribute_path": path,
                "expected_target": expected_target,
                "mode": mode,
                "observed_references": [],
                "complete_local_universe": complete,
            },
            source.provenance_dict(),
        )
    if type(complete) is not bool:
        raise DomainError("complete_expected_domain must be an exact bool")
    if complete and (
        type(reference_contract) is not str
        or re.fullmatch(r"[0-9a-f]{64}", reference_contract) is None
    ):
        raise DomainError("complete reference domain requires a reviewed contract digest")
    if "count" in source.body or "for_each" in source.body:
        return EvaluationOutcome(
            NativePropertyResult.NOT_EVALUATED,
            "TERRAFORM_INSTANCE_IDENTITY_UNRESOLVED",
            {
                "source": source.provenance_dict(),
                "attribute_path": path,
                "expected_target": expected_target,
                "mode": mode,
                "observed_references": [],
                "complete_local_universe": complete,
                "reference_contract_digest": reference_contract,
            },
            source.provenance_dict(),
        )
    expected_matches = tuple(
        item for item in universe.terraform_resources if item.identity == expected_target
    )
    if len(expected_matches) != 1:
        return EvaluationOutcome(
            NativePropertyResult.NOT_EVALUATED,
            "TERRAFORM_EXPECTED_TARGET_NOT_UNIQUELY_PROTECTED",
            {
                "source": source.provenance_dict(),
                "attribute_path": path,
                "expected_target": expected_target,
                "mode": mode,
                "observed_references": [],
                "complete_local_universe": complete,
                "reference_contract_digest": reference_contract,
                "resource_universe_digest": universe.resource_inventory_digest,
            },
            source.provenance_dict(),
        )
    if "count" in expected_matches[0].body or "for_each" in expected_matches[0].body:
        return EvaluationOutcome(
            NativePropertyResult.NOT_EVALUATED,
            "TERRAFORM_INSTANCE_IDENTITY_UNRESOLVED",
            {
                "source": source.provenance_dict(),
                "attribute_path": path,
                "expected_target": expected_target,
                "mode": mode,
                "observed_references": [],
                "complete_local_universe": complete,
                "reference_contract_digest": reference_contract,
            },
            source.provenance_dict(),
        )
    value = _attribute_value(source.body, path)
    if value is _MISSING:
        result = NativePropertyResult.VIOLATED if complete else NativePropertyResult.NOT_EVALUATED
        reason = (
            "TERRAFORM_REFERENCE_PATH_ABSENT_IN_COMPLETE_DOMAIN"
            if complete else "TERRAFORM_REFERENCE_PATH_ABSENT"
        )
        return EvaluationOutcome(
            result,
            reason,
            {
                "source": source.provenance_dict(),
                "attribute_path": path,
                "expected_target": expected_target,
                "mode": mode,
                "observed_references": [],
                "complete_local_universe": complete,
                "reference_contract_digest": reference_contract,
                "resource_universe_digest": universe.resource_inventory_digest,
            },
            source.provenance_dict(),
        )
    try:
        references = _references(value)
    except DomainError as exc:
        return EvaluationOutcome(
            NativePropertyResult.NOT_EVALUATED,
            str(exc),
            {
                "source": source.provenance_dict(),
                "attribute_path": path,
                "expected_target": expected_target,
                "mode": mode,
                "observed_references": [],
                "complete_local_universe": complete,
                "reference_contract_digest": reference_contract,
                "resource_universe_digest": universe.resource_inventory_digest,
            },
            source.provenance_dict(),
        )
    observed = {item[0] for item in references}
    satisfied = expected_target in observed
    if satisfied and _reference_cycle(universe, source.identity, expected_target):
        return EvaluationOutcome(
            NativePropertyResult.NOT_EVALUATED,
            "TERRAFORM_REFERENCE_GRAPH_CYCLIC",
            {
                "source": source.provenance_dict(),
                "attribute_path": path,
                "expected_target": expected_target,
                "mode": mode,
                "observed_references": sorted(observed),
                "complete_local_universe": complete,
                "resource_universe_digest": universe.resource_inventory_digest,
            },
            source.provenance_dict(),
        )
    if satisfied:
        traversal = next(item[1] for item in references if item[0] == expected_target)
        try:
            span = _reference_span(source, traversal)
        except DomainError as exc:
            return EvaluationOutcome(
                NativePropertyResult.NOT_EVALUATED,
                str(exc),
                {
                    "source": source.provenance_dict(),
                    "attribute_path": path,
                    "expected_target": expected_target,
                    "mode": mode,
                    "observed_references": sorted(observed),
                    "complete_local_universe": complete,
                    "reference_contract_digest": reference_contract,
                    "resource_universe_digest": universe.resource_inventory_digest,
                },
                source.provenance_dict(),
            )
        result = NativePropertyResult.SATISFIED
        reason = "TERRAFORM_SOURCE_LOCAL_REFERENCE_RESOLVED"
    elif complete:
        span = None
        result = NativePropertyResult.VIOLATED
        reason = "TERRAFORM_SOURCE_LOCAL_REFERENCE_NOT_RESOLVED"
    else:
        span = None
        result = NativePropertyResult.NOT_EVALUATED
        reason = "TERRAFORM_REFERENCE_ABSENCE_DOMAIN_INCOMPLETE"
    target = expected_matches[0]
    return EvaluationOutcome(
        result,
        reason,
        {
            "source": source.provenance_dict(),
            "attribute_path": path,
            "expected_target": expected_target,
            "expected_target_provenance": target.provenance_dict(),
            "mode": mode,
            "observed_references": sorted(observed),
            "reference_span": span,
            "complete_local_universe": complete,
            "reference_contract_digest": reference_contract,
            "resource_universe_digest": universe.resource_inventory_digest,
        },
        source.provenance_dict(),
    )


__all__ = ["evaluate_reference_resolves"]
