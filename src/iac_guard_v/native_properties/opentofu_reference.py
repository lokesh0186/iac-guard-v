"""Exact protected OpenTofu source-local resource-reference property."""
from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError
from .model import NativePropertyRequest, NativePropertyResult, thaw_json
from .opentofu import OPENTOFU_FILESET_CONTRACT
from .outcome import EvaluationOutcome
from .terraform import _MISSING, _attribute_value, _references
from .universe import ProtectedNativeUniverse, TerraformResource


def _qualified(module_identity: str, address: str) -> str:
    return address if module_identity == "root" else f"{module_identity}::{address}"


def _origin(resource: TerraformResource, path: list[Any]) -> Mapping[str, Any] | None:
    if not path or type(path[0]) is not str or resource.attribute_sources is None:
        return None
    value = resource.attribute_sources.get(path[0])
    return value if type(value) in (dict, MappingProxyType) else None


def _span(origin: Mapping[str, Any], traversal: str) -> dict[str, int] | None:
    text = origin.get("source_text")
    if type(text) is not str:
        return None
    matches = tuple(re.finditer(re.escape(traversal), text))
    if len(matches) != 1:
        return None
    start, end = matches[0].span()
    return {
        "start_byte": len(text[:start].encode("utf-8")),
        "end_byte": len(text[:end].encode("utf-8")),
        "start_line": text.count("\n", 0, start) + 1,
        "end_line": text.count("\n", 0, end) + 1,
    }


def _issue_result(
    universe: ProtectedNativeUniverse, request: NativePropertyRequest
) -> EvaluationOutcome | None:
    if not universe.module_issues:
        return None
    issues = [dict(item) for item in universe.module_issues]
    reasons = {item.get("reason") for item in issues}
    result = (
        NativePropertyResult.UNSUPPORTED
        if reasons.intersection({
            "OPENTOFU_REMOTE_MODULE_UNSUPPORTED",
            "OPENTOFU_DYNAMIC_MODULE_SOURCE_UNSUPPORTED",
            "OPENTOFU_MODULE_OVERRIDE_UNSUPPORTED",
            "OPENTOFU_COMPLEX_OVERRIDE_UNSUPPORTED",
        })
        else NativePropertyResult.NOT_EVALUATED
    )
    return EvaluationOutcome(
        result,
        "OPENTOFU_PROTECTED_SOURCE_CLOSURE_INCOMPLETE",
        {
            "source_mode": "opentofu",
            "fileset_contract": OPENTOFU_FILESET_CONTRACT,
            "source_set_digest": universe.source_set_digest,
            "protected_files": [dict(item) for item in universe.source_file_semantics],
            "module_issues": issues,
            "observed_references": [],
            "expected_target": thaw_json(request.parameters).get("expected_target", "unresolved"),
        },
        {
            "protected_universe_identity": universe.identity,
            "source_set_digest": universe.source_set_digest,
        },
    )


def evaluate_opentofu_reference_resolves(
    universe: ProtectedNativeUniverse,
    request: NativePropertyRequest,
) -> EvaluationOutcome:
    issue = _issue_result(universe, request)
    if issue is not None:
        return issue
    source = universe.terraform_resource(request.subject_identity)
    params = thaw_json(request.parameters)
    path = params.get("attribute_path")
    expected_target = params.get("expected_target")
    mode = params.get("mode", "DIRECT")
    complete = params.get("complete_expected_domain", False)
    reference_contract = params.get("reference_contract_digest")
    if type(path) is not list or not path:
        raise DomainError("OpenTofu reference attribute_path must be a nonempty list")
    if type(expected_target) is not str:
        raise DomainError("OpenTofu reference expected_target must be a string")
    base_witness = {
        "source_mode": "opentofu",
        "fileset_contract": OPENTOFU_FILESET_CONTRACT,
        "source_set_digest": universe.source_set_digest,
        "protected_files": [dict(item) for item in universe.source_file_semantics],
        "module_issues": [],
        "source": source.provenance_dict(),
        "attribute_path": path,
        "expected_target": expected_target,
        "mode": mode,
        "complete_local_universe": complete,
        "reference_contract_digest": reference_contract,
        "observed_references": [],
        "reference_span": None,
        "attribute_origin": None,
    }
    if mode != "DIRECT":
        return EvaluationOutcome(
            NativePropertyResult.UNSUPPORTED,
            "OPENTOFU_TRANSITIVE_REFERENCE_UNSUPPORTED",
            base_witness,
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
            "OPENTOFU_INSTANCE_IDENTITY_UNRESOLVED",
            base_witness,
            source.provenance_dict(),
        )
    expected = tuple(
        item for item in universe.terraform_resources if item.identity == expected_target
    )
    if len(expected) != 1:
        return EvaluationOutcome(
            NativePropertyResult.NOT_EVALUATED,
            "OPENTOFU_EXPECTED_TARGET_NOT_UNIQUELY_PROTECTED",
            base_witness | {"resource_universe_digest": universe.resource_inventory_digest},
            source.provenance_dict(),
        )
    value = _attribute_value(source.body, path)
    if value is _MISSING:
        result = NativePropertyResult.VIOLATED if complete else NativePropertyResult.NOT_EVALUATED
        reason = (
            "OPENTOFU_REFERENCE_ATTRIBUTE_ABSENT_IN_COMPLETE_DOMAIN"
            if complete else "OPENTOFU_REFERENCE_ATTRIBUTE_ABSENT"
        )
        return EvaluationOutcome(result, reason, base_witness, source.provenance_dict())
    try:
        raw_references = _references(value)
    except DomainError:
        return EvaluationOutcome(
            NativePropertyResult.NOT_EVALUATED,
            "OPENTOFU_REFERENCE_EXPRESSION_UNSUPPORTED",
            base_witness,
            source.provenance_dict(),
        )
    references = tuple(
        (_qualified(source.module_identity, address), traversal)
        for address, traversal in raw_references
    )
    observed = [address for address, _ in references]
    origin = _origin(source, path)
    witness = base_witness | {
        "observed_references": observed,
        "attribute_origin": (
            {
                "file_path": origin["file_path"],
                "source_sha256": origin["source_sha256"],
                "source_format": origin["source_format"],
            }
            if origin is not None else None
        ),
    }
    matching = tuple(traversal for address, traversal in references if address == expected_target)
    if matching:
        reference_span = _span(origin, matching[0]) if origin is not None else None
        if reference_span is None:
            return EvaluationOutcome(
                NativePropertyResult.NOT_EVALUATED,
                "OPENTOFU_REFERENCE_SOURCE_SPAN_AMBIGUOUS",
                witness,
                source.provenance_dict(),
            )
        return EvaluationOutcome(
            NativePropertyResult.SATISFIED,
            "OPENTOFU_DIRECT_REFERENCE_RESOLVED",
            witness | {"reference_span": reference_span},
            source.provenance_dict(),
        )
    if complete:
        return EvaluationOutcome(
            NativePropertyResult.VIOLATED,
            "OPENTOFU_EXPECTED_REFERENCE_ABSENT_IN_COMPLETE_DOMAIN",
            witness,
            source.provenance_dict(),
        )
    return EvaluationOutcome(
        NativePropertyResult.NOT_EVALUATED,
        "OPENTOFU_EXPECTED_REFERENCE_NOT_OBSERVED_IN_INCOMPLETE_DOMAIN",
        witness,
        source.provenance_dict(),
    )


__all__ = ["evaluate_opentofu_reference_resolves"]
