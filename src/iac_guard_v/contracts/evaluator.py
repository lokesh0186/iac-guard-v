"""Clause evaluation and fail-closed contract aggregation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import DomainError
from ..native_properties.engine import evaluate_native_requests
from ..native_properties.model import (
    NativePropertyObservation,
    NativePropertyResult,
    canonical_digest,
)
from ..native_properties.universe import ProtectedNativeUniverse
from .model import ContractResult, InfrastructureContract
from .planner import ContractPlan, PlannedClause


@dataclass(frozen=True, slots=True)
class ClauseObservation:
    clause_id: str
    clause_identity: str
    required: bool
    result: ContractResult
    reason_code: str
    target_count: int | None
    native_observations: tuple[NativePropertyObservation, ...]
    observation_digest: str

    @classmethod
    def build(
        cls, clause: PlannedClause, result: ContractResult, reason_code: str,
        target_count: int | None, observations: tuple[NativePropertyObservation, ...],
    ) -> "ClauseObservation":
        body = {
            "clause_id": clause.clause_id, "clause_identity": clause.clause_identity,
            "required": clause.required, "result": result.value,
            "reason_code": reason_code, "target_count": target_count,
            "native_observations": [item.canonical_dict() for item in observations],
        }
        return cls(
            clause.clause_id, clause.clause_identity, clause.required, result,
            reason_code, target_count, observations, canonical_digest(body),
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "clause_id": self.clause_id, "clause_identity": self.clause_identity,
            "required": self.required, "result": self.result.value,
            "reason_code": self.reason_code, "target_count": self.target_count,
            "native_observations": [item.canonical_dict() for item in self.native_observations],
            "observation_digest": self.observation_digest,
        }


_TARGET_KEYS = (
    "matched_services", "matched_workloads", "resolved_targets", "target_evaluations",
    "resolved_port_set", "resolved_subjects",
)


def _target_count(observations: tuple[NativePropertyObservation, ...]) -> int | None:
    counts = []
    for observation in observations:
        contents = observation.witness.contents
        selected = None
        for key in _TARGET_KEYS:
            value = contents.get(key)
            if type(value) is tuple:
                selected = len(value)
                break
        if selected is not None:
            counts.append(selected)
    return sum(counts) if counts else None


def _clause_result(
    clause: PlannedClause, observations: tuple[NativePropertyObservation, ...]
) -> ClauseObservation:
    if not observations:
        return ClauseObservation.build(
            clause, ContractResult.SATISFIED, "EMPTY_SUBJECT_SET_EXPLICITLY_ALLOWED", 0, (),
        )
    native_results = {item.result for item in observations}
    if NativePropertyResult.ERROR in native_results:
        result, reason = ContractResult.ERROR, "NATIVE_PROPERTY_ERROR"
    elif NativePropertyResult.VIOLATED in native_results:
        result, reason = ContractResult.VIOLATED, "NATIVE_PROPERTY_VIOLATED"
    elif NativePropertyResult.UNSUPPORTED in native_results:
        result, reason = ContractResult.UNSUPPORTED, "NATIVE_PROPERTY_UNSUPPORTED"
    elif NativePropertyResult.NOT_EVALUATED in native_results:
        result, reason = ContractResult.NOT_EVALUATED, "NATIVE_PROPERTY_NOT_EVALUATED"
    else:
        result, reason = ContractResult.SATISFIED, "NATIVE_PROPERTIES_SATISFIED"
    count = _target_count(observations)
    if result is ContractResult.SATISFIED and count is not None:
        if count < clause.target_minimum:
            result, reason = ContractResult.VIOLATED, "TARGET_CARDINALITY_BELOW_MINIMUM"
        elif clause.target_maximum is not None and count > clause.target_maximum:
            result, reason = ContractResult.VIOLATED, "TARGET_CARDINALITY_ABOVE_MAXIMUM"
    return ClauseObservation.build(clause, result, reason, count, observations)


def aggregate_clause_results(
    plan: ContractPlan, clauses: tuple[ClauseObservation, ...]
) -> tuple[ContractResult, str]:
    if plan.plan_result != "SATISFIED":
        return ContractResult(plan.plan_result), plan.reason_code
    required = tuple(item for item in clauses if item.required)
    results = {item.result for item in required}
    for result, reason in (
        (ContractResult.ERROR, "REQUIRED_CLAUSE_ERROR"),
        (ContractResult.VIOLATED, "REQUIRED_CLAUSE_VIOLATED"),
        (ContractResult.UNSUPPORTED, "REQUIRED_CLAUSE_UNSUPPORTED"),
        (ContractResult.NOT_EVALUATED, "REQUIRED_CLAUSE_NOT_EVALUATED"),
    ):
        if result in results:
            return result, reason
    if not required and any(item.required for item in plan.clauses):
        return ContractResult.NOT_EVALUATED, "REQUIRED_CLAUSE_MISSING"
    return ContractResult.SATISFIED, "ALL_REQUIRED_CLAUSES_SATISFIED"


def evaluate_contract(
    contract: InfrastructureContract,
    universe: ProtectedNativeUniverse,
    plan: ContractPlan,
) -> tuple[tuple[ClauseObservation, ...], ContractResult, str]:
    if plan.contract_identity != contract.identity or plan.protected_universe_identity != universe.identity:
        raise DomainError("contract plan belongs to different protected evidence")
    clauses = []
    for clause in plan.clauses:
        observations = evaluate_native_requests(universe, clause.requests) if clause.requests else ()
        clauses.append(_clause_result(clause, observations))
    frozen = tuple(clauses)
    result, reason = aggregate_clause_results(plan, frozen)
    return frozen, result, reason


__all__ = ["ClauseObservation", "aggregate_clause_results", "evaluate_contract"]
