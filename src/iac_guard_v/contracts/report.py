"""Authoritative a10 contract report and semantic validation."""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

import jsonschema

from .. import __version__
from ..models import DomainError, canonical_identifier
from ..native_properties.evidence import (
    validate_native_observation,
    validate_native_witness_payload,
)
from ..native_properties.model import NativePropertyResult, canonical_digest, thaw_json
from ..native_properties.registry import NATIVE_PROPERTY_REGISTRY, native_registry_identity
from ..native_properties.universe import ProtectedNativeUniverse
from .evaluator import ClauseObservation
from .model import (
    CONTRACT_REPORT_VERSION,
    CONTRACT_SCHEMA_VERSION,
    ContractResult,
    InfrastructureContract,
    contract_digest,
    contract_implementation_identity,
    contract_schema_identity,
    contract_thaw,
)
from .parser import contract_schema
from .planner import ContractPlan


_SEMANTICS = (
    "declared intent over protected deterministic native-property evidence; "
    "no automatic project-defect or runtime claim"
)


def _schema() -> dict:
    return json.loads(files("iac_guard_v").joinpath(
        "schemas/infrastructure-contract-report-v1alpha1.schema.json"
    ).read_text(encoding="utf-8"))


def _exit(result: ContractResult) -> int:
    return {
        ContractResult.SATISFIED: 0,
        ContractResult.VIOLATED: 10,
        ContractResult.NOT_EVALUATED: 11,
        ContractResult.UNSUPPORTED: 12,
        ContractResult.ERROR: 21,
    }[result]


@dataclass(frozen=True, slots=True)
class ContractReportV1:
    contract: InfrastructureContract
    universe: ProtectedNativeUniverse
    plan: ContractPlan
    clauses: tuple[ClauseObservation, ...]
    result: ContractResult
    reason_code: str
    report_digest: str

    @classmethod
    def build(
        cls, contract: InfrastructureContract, universe: ProtectedNativeUniverse,
        plan: ContractPlan, clauses: tuple[ClauseObservation, ...],
        result: ContractResult, reason_code: str,
    ) -> "ContractReportV1":
        if plan.contract_identity != contract.identity or plan.protected_universe_identity != universe.identity:
            raise DomainError("contract report evidence identities disagree")
        for clause in clauses:
            for observation in clause.native_observations:
                if observation.request.protected_universe_identity != universe.identity:
                    raise DomainError("contract report contains a foreign native observation")
                validate_native_observation(observation)
        reason_code = canonical_identifier(reason_code, "contract reason code")
        body = _payload_body(contract, universe, plan, clauses, result, reason_code)
        return cls(contract, universe, plan, clauses, result, reason_code, contract_digest(body))

    @property
    def exit_code(self) -> int:
        return _exit(self.result)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            **_payload_body(
                self.contract, self.universe, self.plan, self.clauses,
                self.result, self.reason_code,
            ),
            "exit_code": self.exit_code,
            "report_digest": self.report_digest,
        }

    def canonical_json(self) -> str:
        payload = self.canonical_dict()
        validate_contract_report_payload(payload)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _payload_body(
    contract: InfrastructureContract,
    universe: ProtectedNativeUniverse,
    plan: ContractPlan,
    clauses: tuple[ClauseObservation, ...],
    result: ContractResult,
    reason_code: str,
) -> dict[str, Any]:
    counts = Counter(item.result.value for item in clauses)
    return {
        "schema_version": CONTRACT_REPORT_VERSION,
        "product_version": __version__,
        "product_semantics": _SEMANTICS,
        "contract": {
            "identity": contract.identity, "name": contract.name,
            "schema_identity": contract_schema_identity(),
            "canonical_digest": contract.canonical_digest,
            "canonical_payload": contract_thaw(contract.canonical_payload),
            "responsibility": thaw_json(contract.responsibility),
            "source": contract.source.canonical_dict(),
        },
        "protected_universe": {
            "identity": universe.identity,
            "artifact_class": universe.artifact_class.value,
            "input_manifest": [item.canonical_dict() for item in universe.source_files],
            "input_manifest_digest": universe.input_manifest_digest,
            "resource_inventory": [
                item.identity for item in (
                    universe.kubernetes_resources
                    if universe.artifact_class.value == "kubernetes_rendered"
                    else universe.terraform_resources
                )
            ],
            "resource_inventory_digest": universe.resource_inventory_digest,
        },
        "native_registry_identity": native_registry_identity(),
        "compiler_identity": contract_implementation_identity(),
        "activation": plan.activation.canonical_dict(),
        "plan": plan.canonical_dict(),
        "clauses": [item.canonical_dict() for item in clauses],
        "summary": {key: counts[key] for key in (
            "SATISFIED", "VIOLATED", "NOT_EVALUATED", "UNSUPPORTED", "ERROR"
        )} | {"TOTAL": len(clauses)},
        "result": result.value,
        "reason_code": reason_code,
    }


def _validate_native_payload(observation: dict, universe_identity: str) -> None:
    request = observation.get("request", {})
    definition = observation.get("definition", {})
    witness = observation.get("witness", {})
    packaged = NATIVE_PROPERTY_REGISTRY.get(request.get("property_id"))
    if packaged is None or definition != packaged.canonical_dict():
        raise DomainError("contract report native definition is stale or forged")
    if request.get("protected_universe_identity") != universe_identity:
        raise DomainError("contract report native request belongs to another universe")
    if canonical_digest(request.get("parameters")) != request.get("parameters_digest"):
        raise DomainError("contract report native parameters digest is contradictory")
    if canonical_digest({
        "witness_type": witness.get("witness_type"), "contents": witness.get("contents")
    }) != witness.get("witness_digest"):
        raise DomainError("contract report native witness digest is contradictory")
    body = dict(observation)
    digest = body.pop("observation_digest", None)
    if canonical_digest(body) != digest:
        raise DomainError("contract report native observation digest is contradictory")
    result = NativePropertyResult(observation["result"])
    validate_native_witness_payload(
        witness_type=witness["witness_type"], result=result, contents=witness["contents"]
    )


_TARGET_KEYS = (
    "matched_services", "matched_workloads", "resolved_targets", "target_evaluations",
    "resolved_port_set", "resolved_subjects",
)


def _target_count_payload(observations: list[dict]) -> int | None:
    counts: list[int] = []
    for observation in observations:
        contents = observation["witness"]["contents"]
        for key in _TARGET_KEYS:
            value = contents.get(key)
            if type(value) is list:
                counts.append(len(value))
                break
    return sum(counts) if counts else None


def _expected_clause_result(plan_clause: dict, observations: list[dict]) -> tuple[str, str, int | None]:
    if not observations:
        return "SATISFIED", "EMPTY_SUBJECT_SET_EXPLICITLY_ALLOWED", 0
    results = {item["result"] for item in observations}
    if "ERROR" in results:
        result, reason = "ERROR", "NATIVE_PROPERTY_ERROR"
    elif "VIOLATED" in results:
        result, reason = "VIOLATED", "NATIVE_PROPERTY_VIOLATED"
    elif "UNSUPPORTED" in results:
        result, reason = "UNSUPPORTED", "NATIVE_PROPERTY_UNSUPPORTED"
    elif "NOT_EVALUATED" in results:
        result, reason = "NOT_EVALUATED", "NATIVE_PROPERTY_NOT_EVALUATED"
    else:
        result, reason = "SATISFIED", "NATIVE_PROPERTIES_SATISFIED"
    count = _target_count_payload(observations)
    if result == "SATISFIED" and count is not None:
        if count < plan_clause["target_minimum"]:
            result, reason = "VIOLATED", "TARGET_CARDINALITY_BELOW_MINIMUM"
        elif (
            plan_clause["target_maximum"] is not None
            and count > plan_clause["target_maximum"]
        ):
            result, reason = "VIOLATED", "TARGET_CARDINALITY_ABOVE_MAXIMUM"
    return result, reason, count


def _expected_aggregate(plan: dict, clauses: list[dict]) -> tuple[str, str]:
    if plan["plan_result"] != "SATISFIED":
        return plan["plan_result"], plan["reason_code"]
    results = {item["result"] for item in clauses if item["required"]}
    for result, reason in (
        ("ERROR", "REQUIRED_CLAUSE_ERROR"),
        ("VIOLATED", "REQUIRED_CLAUSE_VIOLATED"),
        ("UNSUPPORTED", "REQUIRED_CLAUSE_UNSUPPORTED"),
        ("NOT_EVALUATED", "REQUIRED_CLAUSE_NOT_EVALUATED"),
    ):
        if result in results:
            return result, reason
    return "SATISFIED", "ALL_REQUIRED_CLAUSES_SATISFIED"


def _validate_activation(expression: dict | None, activation: dict) -> None:
    if set(activation) != {"status", "reason_code", "facts", "input_identity"}:
        raise DomainError("contract report activation evidence shape is invalid")
    if (
        type(activation["input_identity"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", activation["input_identity"]) is None
        or type(activation["facts"]) is not list
    ):
        raise DomainError("contract report activation identity is invalid")
    if expression is None:
        expected = (
            "ACTIVE", "CONTRACT_UNCONDITIONAL", [],
            contract_digest({"activation": "unconditional"}),
        )
        observed = (
            activation["status"], activation["reason_code"], activation["facts"],
            activation["input_identity"],
        )
        if observed != expected:
            raise DomainError("contract report unconditional activation is contradictory")
        return
    if (
        activation["status"] == "ACTIVATION_NOT_EVALUATED"
        and activation["reason_code"] == "ACTIVATION_INPUT_UNAVAILABLE"
        and activation["facts"] == []
    ):
        if activation["input_identity"] != contract_digest({"activation": "missing"}):
            raise DomainError("contract report unavailable activation identity is contradictory")
        return

    facts = iter(activation["facts"])

    def evaluate(node: dict, depth: int) -> bool | None:
        if depth > 4:
            raise DomainError("contract report activation nesting exceeds the limit")
        if "value" in node:
            condition = node["value"]
            try:
                fact = next(facts)
            except StopIteration as exc:
                raise DomainError("contract report activation fact is missing") from exc
            context = condition.get("context", ".")
            path = condition["path"]
            if type(fact) is not dict:
                raise DomainError("contract report activation fact is invalid")
            if fact == {"context": context, "path": path, "state": "UNAVAILABLE"}:
                return None
            if set(fact) != {
                "context", "path", "condition", "observed", "origin_matches", "state"
            }:
                raise DomainError("contract report activation fact shape is invalid")
            if fact["context"] != context or fact["path"] != path or fact["condition"] != condition:
                raise DomainError("contract report activation condition witness is contradictory")
            observed = fact["observed"]
            if type(observed) is not dict:
                raise DomainError("contract report effective value witness is invalid")
            if set(observed) != {
                "context", "path", "present", "value", "origin", "origin_evidence",
                "fact_digest",
            }:
                raise DomainError("contract report effective value witness shape is invalid")
            observed_body = {
                "context": observed["context"], "path": observed["path"],
                "present": observed["present"],
                "value": observed["value"] if observed["present"] else None,
                "origin": observed["origin"],
                "origin_evidence": observed["origin_evidence"],
            }
            if contract_digest(observed_body) != observed["fact_digest"]:
                raise DomainError("contract report effective value digest is contradictory")
            if observed["context"] != context or observed["path"] != path:
                raise DomainError("contract report effective value identity is contradictory")
            if type(observed["present"]) is not bool or type(fact["origin_matches"]) is not bool:
                raise DomainError("contract report activation Boolean witness is invalid")
            required_origin = condition.get("requireOrigin", "ANY_PROTECTED")
            origin_matches = required_origin == "ANY_PROTECTED" or observed["origin"] == required_origin
            if fact["origin_matches"] is not origin_matches:
                raise DomainError("contract report activation origin witness is contradictory")
            if not origin_matches:
                state = None
            elif "present" in condition:
                state = observed["present"] is condition["present"]
            elif not observed["present"]:
                state = None
            else:
                expected_value = condition["equals"]
                state = (
                    None if type(observed["value"]) is not type(expected_value)
                    else observed["value"] == expected_value
                )
            rendered_state = "UNKNOWN" if state is None else state
            if fact["state"] != rendered_state:
                raise DomainError("contract report activation state witness is contradictory")
            return state
        if "all" in node:
            states = [evaluate(item, depth + 1) for item in node["all"]]
            return False if False in states else None if None in states else True
        if "any" in node:
            states = [evaluate(item, depth + 1) for item in node["any"]]
            return True if True in states else None if None in states else False
        raise DomainError("contract report activation expression is malformed")

    state = evaluate(expression, 0)
    try:
        next(facts)
    except StopIteration:
        pass
    else:
        raise DomainError("contract report contains extra activation facts")
    expected_status = (
        "ACTIVE" if state is True
        else "INACTIVE_CONDITION_FALSE" if state is False
        else "ACTIVATION_NOT_EVALUATED"
    )
    expected_reason = {
        "ACTIVE": "ACTIVATION_CONDITION_TRUE",
        "INACTIVE_CONDITION_FALSE": "ACTIVATION_CONDITION_FALSE",
        "ACTIVATION_NOT_EVALUATED": "ACTIVATION_CONDITION_UNCERTAIN",
    }[expected_status]
    if (activation["status"], activation["reason_code"]) != (expected_status, expected_reason):
        raise DomainError("contract report activation result is contradictory")


def _validate_contract_and_plan(payload: dict) -> None:
    contract_record = payload["contract"]
    canonical = contract_record["canonical_payload"]
    try:
        jsonschema.Draft202012Validator(contract_schema()).validate(canonical)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"contract report canonical contract is invalid: {exc.message}") from exc
    if not any(item.get("required", True) for item in canonical["spec"]["expect"]):
        raise DomainError("contract report has no required clause")
    if contract_digest(canonical) != contract_record["canonical_digest"]:
        raise DomainError("contract report canonical contract digest is contradictory")
    if canonical["metadata"]["name"] != contract_record["name"]:
        raise DomainError("contract report contract name is contradictory")
    if canonical["spec"]["responsibility"] != contract_record["responsibility"]:
        raise DomainError("contract report responsibility is contradictory")
    source = contract_record["source"]
    expected_identity = contract_digest({
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "name": contract_record["name"],
        "provenance": source["provenance"],
        "source": source,
        "canonical_contract_digest": contract_record["canonical_digest"],
    })
    if contract_record["identity"] != expected_identity:
        raise DomainError("contract report contract identity is contradictory")

    _validate_activation(canonical["spec"].get("when"), payload["activation"])

    plan = payload["plan"]
    protected = payload["protected_universe"]
    if canonical_digest(protected["input_manifest"]) != protected["input_manifest_digest"]:
        raise DomainError("contract report protected input manifest is contradictory")
    if canonical_digest(protected["resource_inventory"]) != protected["resource_inventory_digest"]:
        raise DomainError("contract report protected resource inventory is contradictory")
    if protected["resource_inventory"] != sorted(set(protected["resource_inventory"])):
        raise DomainError("contract report protected resource inventory must be sorted and unique")
    expected_execution_identity = contract_digest({
        "contract_identity": contract_record["identity"],
        "protected_universe_identity": payload["protected_universe"]["identity"],
        "activation_input_identity": payload["activation"]["input_identity"],
        "activation_evidence_digest": contract_digest(payload["activation"]),
        "native_registry_identity": payload["native_registry_identity"],
        "compiler_identity": payload["compiler_identity"],
    })
    if (
        plan["contract_identity"] != contract_record["identity"]
        or plan["execution_identity"] != expected_execution_identity
        or plan["protected_universe_identity"] != payload["protected_universe"]["identity"]
        or plan["native_registry_identity"] != payload["native_registry_identity"]
        or plan["compiler_identity"] != payload["compiler_identity"]
        or plan["activation"] != payload["activation"]
    ):
        raise DomainError("contract report plan evidence identities are contradictory")

    subjects = plan["subjects"]
    for key in ("included", "excluded", "unresolved", "selected"):
        if subjects[key] != sorted(set(subjects[key])):
            raise DomainError("contract report subject identities must be sorted and unique")
    if not set(subjects["selected"]) <= set(subjects["included"]):
        raise DomainError("contract report selected subjects were not included")
    if set(subjects["selected"]) & set(subjects["excluded"]):
        raise DomainError("contract report selected subjects were also excluded")
    if subjects["unresolved"]:
        subject_result, subject_reason = "NOT_EVALUATED", "SUBJECT_IDENTITY_UNRESOLVED"
    elif not subjects["selected"] and not subjects["allow_empty"]:
        subject_result, subject_reason = "VIOLATED", "ZERO_SUBJECT_MATCH"
    elif len(subjects["selected"]) < subjects["minimum"]:
        subject_result, subject_reason = "VIOLATED", "SUBJECT_CARDINALITY_BELOW_MINIMUM"
    elif subjects["maximum"] is not None and len(subjects["selected"]) > subjects["maximum"]:
        subject_result, subject_reason = "VIOLATED", "SUBJECT_CARDINALITY_ABOVE_MAXIMUM"
    else:
        subject_result, subject_reason = "SATISFIED", "SUBJECT_SET_RESOLVED"
    if (subjects["result"], subjects["reason_code"]) != (subject_result, subject_reason):
        raise DomainError("contract report subject-resolution result is contradictory")

    activation = payload["activation"]["status"]
    responsibility = canonical["spec"]["responsibility"]["class"]
    if activation == "INACTIVE_CONDITION_FALSE":
        expected_plan = ("NOT_EVALUATED", "CONTRACT_INACTIVE")
    elif activation != "ACTIVE":
        expected_plan = ("NOT_EVALUATED", "CONTRACT_ACTIVATION_NOT_EVALUATED")
    elif subject_result != "SATISFIED":
        expected_plan = (subject_result, subject_reason)
    elif responsibility == "OUT_OF_CONTRACT":
        expected_plan = ("NOT_EVALUATED", "CONTRACT_SCOPE_EXPLICITLY_EXCLUDED")
    else:
        expected_plan = ("SATISFIED", "CONTRACT_PLAN_COMPILED")
    if (plan["plan_result"], plan["reason_code"]) != expected_plan:
        raise DomainError("contract report plan result is contradictory")

    expected_clauses = (
        canonical["spec"]["expect"]
        if plan["plan_result"] == "SATISFIED"
        or plan["reason_code"] == "CONTRACT_SCOPE_EXPLICITLY_EXCLUDED"
        else []
    )
    if len(plan["clauses"]) != len(expected_clauses):
        raise DomainError("contract report compiled clause count is contradictory")
    for ordinal, (planned, declared) in enumerate(zip(plan["clauses"], expected_clauses), start=1):
        if (
            planned["clause_id"] != declared["id"]
            or planned["property_id"] != declared["property"]["id"]
            or planned["property_version"] != declared["property"]["version"]
            or planned["required"] != declared.get("required", True)
        ):
            raise DomainError("contract report compiled clause differs from declared contract")
        requests = planned["requests"]
        for request_index, request in enumerate(requests, start=1):
            if (
                request["request_id"] != f"{planned['clause_id']}-{request_index:04d}"
                or request["property_id"] != planned["property_id"]
                or request["property_version"] != planned["property_version"]
                or request["protected_universe_identity"] != payload["protected_universe"]["identity"]
                or request["parameters_digest"] != planned["parameters_digest"]
            ):
                raise DomainError("contract report compiled native request is contradictory")
        if requests:
            if any(request["parameters"] != requests[0]["parameters"] for request in requests):
                raise DomainError("contract report clause requests disagree on parameters")
        elif canonical_digest(declared.get("parameters", {})) != planned["parameters_digest"]:
            raise DomainError("contract report empty clause parameters are contradictory")
        request_subjects = [item["subject_identity"] for item in requests]
        if planned["property_id"] != "IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1":
            if request_subjects != subjects["selected"]:
                raise DomainError("contract report native request subject set is contradictory")
            if requests and requests[0]["parameters"] != declared.get("parameters", {}):
                raise DomainError("contract report native parameters differ from the contract")
        elif len(requests) != 1:
            raise DomainError("contract report component closure request is contradictory")
        relation = declared.get("relationCardinality", {})
        if (
            planned["target_minimum"] != relation.get("targetMin", 1)
            or planned["target_maximum"] != relation.get("targetMax")
        ):
            raise DomainError("contract report relationship cardinality is contradictory")
        expected_clause_identity = canonical_digest({
            "contract_identity": contract_record["identity"],
            "clause_id": planned["clause_id"],
            "property_id": planned["property_id"],
            "property_version": planned["property_version"],
            "subject_set_digest": canonical_digest(request_subjects),
            "parameters_digest": planned["parameters_digest"],
            "activation_digest": contract_digest(payload["activation"]),
            "responsibility_digest": contract_digest(contract_record["responsibility"]),
            "target_minimum": planned["target_minimum"],
            "target_maximum": planned["target_maximum"],
            "required": planned["required"],
        })
        if planned["clause_identity"] != expected_clause_identity:
            raise DomainError(f"contract report compiled clause {ordinal} identity is contradictory")
        if (
            planned["activation_digest"] != contract_digest(payload["activation"])
            or planned["responsibility_digest"] != contract_digest(contract_record["responsibility"])
        ):
            raise DomainError("contract report clause activation/responsibility identity is contradictory")


def _validate_contract_report_payload(payload: dict) -> None:
    try:
        jsonschema.Draft202012Validator(_schema()).validate(payload)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"contract report schema violation: {exc.message}") from exc
    body = dict(payload)
    report_digest = body.pop("report_digest")
    exit_code = body.pop("exit_code")
    if contract_digest(body) != report_digest:
        raise DomainError("contract report digest is contradictory")
    if payload["native_registry_identity"] != native_registry_identity():
        raise DomainError("contract report native registry is stale")
    if payload["compiler_identity"] != contract_implementation_identity():
        raise DomainError("contract report compiler identity is stale")
    if payload["contract"]["schema_identity"] != contract_schema_identity():
        raise DomainError("contract report schema identity is stale")
    if payload["product_version"] != __version__:
        raise DomainError("contract report product version is stale")
    if _exit(ContractResult(payload["result"])) != exit_code:
        raise DomainError("contract report exit code disagrees with result")
    _validate_contract_and_plan(payload)
    plan = payload["plan"]
    plan_body = dict(plan)
    plan_digest = plan_body.pop("plan_digest", None)
    if contract_digest(plan_body) != plan_digest:
        raise DomainError("contract report plan digest is contradictory")
    subjects = plan["subjects"]
    subjects_body = dict(subjects)
    resolution_digest = subjects_body.pop("resolution_digest", None)
    if canonical_digest(subjects_body) != resolution_digest:
        raise DomainError("contract report subject-resolution digest is contradictory")
    if len(payload["clauses"]) != len(plan["clauses"]):
        raise DomainError("contract report clause observations do not match the plan")
    clause_ids = []
    for clause, planned in zip(payload["clauses"], plan["clauses"]):
        clause_ids.append(canonical_identifier(clause["clause_id"], "contract clause ID"))
        if (
            clause["clause_id"] != planned["clause_id"]
            or clause["clause_identity"] != planned["clause_identity"]
            or clause["required"] != planned["required"]
        ):
            raise DomainError("contract clause observation differs from the compiled plan")
        if len(clause["native_observations"]) != len(planned["requests"]):
            raise DomainError("contract clause native observations do not match requests")
        for observation, request in zip(clause["native_observations"], planned["requests"]):
            if observation["request"] != request:
                raise DomainError("contract clause native observation request is contradictory")
        clause_body = dict(clause)
        observation_digest = clause_body.pop("observation_digest", None)
        if canonical_digest(clause_body) != observation_digest:
            raise DomainError("contract clause observation digest is contradictory")
        for observation in clause["native_observations"]:
            _validate_native_payload(observation, payload["protected_universe"]["identity"])
        expected_result, expected_reason, expected_count = _expected_clause_result(
            planned, clause["native_observations"]
        )
        if (
            clause["result"], clause["reason_code"], clause["target_count"]
        ) != (expected_result, expected_reason, expected_count):
            raise DomainError("contract clause result is contradictory")
    if len(clause_ids) != len(set(clause_ids)):
        raise DomainError("contract report clause IDs must be unique")
    counts = Counter(item["result"] for item in payload["clauses"])
    expected_summary = {key: counts[key] for key in (
        "SATISFIED", "VIOLATED", "NOT_EVALUATED", "UNSUPPORTED", "ERROR"
    )} | {"TOTAL": len(payload["clauses"])}
    if payload.get("summary") != expected_summary:
        raise DomainError("contract report summary is contradictory")
    expected_result, expected_reason = _expected_aggregate(plan, payload["clauses"])
    if (payload["result"], payload["reason_code"]) != (expected_result, expected_reason):
        raise DomainError("contract report aggregate result is contradictory")


def validate_contract_report_payload(payload: dict) -> None:
    """Validate schema plus every self-contained semantic relationship.

    Loose or malicious nested JSON must fail as a typed domain error rather than
    escaping as an implementation exception.
    """
    try:
        _validate_contract_report_payload(payload)
    except DomainError:
        raise
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise DomainError("contract report semantic structure is invalid") from exc


def render_contract_console(report: ContractReportV1) -> str:
    lines = [
        "IaC-Guard-V infrastructure contract report",
        f"contract: {report.contract.name}",
        f"provenance: {report.contract.source.provenance.value}",
        f"responsibility: {report.contract.responsibility['class']}",
        f"activation: {report.plan.activation.status.value}",
        f"subjects: selected={len(report.plan.subjects.selected)} excluded={len(report.plan.subjects.excluded)} unresolved={len(report.plan.subjects.unresolved)}",
    ]
    for clause in report.clauses:
        lines.append(f"{clause.clause_id}: {clause.result.value} ({clause.reason_code})")
    lines.extend((
        f"result: {report.result.value} ({report.reason_code})",
        "scope: declared protected IaC intent only; no automatic project-defect, vulnerability, outage, or runtime claim",
    ))
    if report.contract.source.provenance.value == "RESEARCH_HYPOTHESIS":
        lines.append("provenance notice: This invariant was supplied by the researcher and is not claimed to represent project-authored intent.")
    return "\n".join(lines) + "\n"


__all__ = ["ContractReportV1", "render_contract_console", "validate_contract_report_payload"]
