"""D6 policy truth table, exception binding, and provenance boundary."""
from __future__ import annotations

from datetime import date

import pytest

import iac_guard_v.engine as ENGINE
from iac_guard_v.engine import TargetOutcomeEvidence, VerificationResult
from iac_guard_v.enums import (
    EXIT_CODES,
    ExceptionOrigin,
    Outcome,
    Status,
    Verdict,
)
from iac_guard_v.models import (
    DomainError,
    ExceptionPolicy,
    ExceptionRecord,
    GateResult,
    TargetDecision,
)
from iac_guard_v.policy import (
    PolicyRequest,
    PolicyResult,
    evaluate_policy,
    require_trusted_policy_result,
)
from test_engine import (
    IDENTITY,
    _executable,
    _gate,
    _run,
    _scan_request,
    observation,
)
from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.engine import VerificationRequest, run_checkov_verification
from iac_guard_v.models import RequiredGates, Target


TODAY = date(2026, 8, 11)


@pytest.fixture
def verified_engine(monkeypatch, tmp_path) -> VerificationResult:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, request: _run(request, baseline=request is baseline),
    )
    request = VerificationRequest(
        baseline,
        candidate,
        (Target(IDENTITY, 1),),
        RequiredGates(("validator",), ("oracle",)),
        "a" * 64,
        "a" * 64,
    )
    return run_checkov_verification(request, _gate_executor=_gate)


def _replace_engine(run: VerificationResult, **changes) -> VerificationResult:
    values = {
        name: getattr(run, name)
        for name in VerificationResult.__dataclass_fields__
        if not name.startswith("_")
    }
    values.update(changes)
    return VerificationResult(
        **values,
        _trusted_context=ENGINE._TRUSTED_ENGINE_CONTEXT,
    )


def _outcome(run: VerificationResult, outcome: Outcome) -> VerificationResult:
    changes = {
        Outcome.FIXED: {},
        Outcome.STILL_PRESENT: {"candidate_matches": 1},
        Outcome.PARTIALLY_FIXED: {"baseline_occurrences": 3, "candidate_matches": 1},
        Outcome.SUPPRESSED: {"suppression_absence": Status.FAIL},
        Outcome.RESOURCE_DELETED: {"target_resource_presence": Status.FAIL},
        Outcome.FILE_DELETED_OR_RENAMED: {"target_file_presence": Status.FAIL},
        Outcome.OUT_OF_SCOPE: {"artifact_eligibility": Status.FAIL},
        Outcome.RULE_OR_SCANNER_DRIFT: {"ruleset_integrity": Status.FAIL},
        Outcome.SCANNER_ERROR: {"scanner_integrity": Status.ERROR},
        Outcome.INCONCLUSIVE: {"occurrence_evidence": Status.INCONCLUSIVE},
    }[outcome]
    observed = observation(**changes)
    evidence = TargetOutcomeEvidence(
        IDENTITY,
        outcome,
        observed,
        "TEST_TARGET_EVIDENCE",
        _trusted_context=ENGINE._TRUSTED_ENGINE_CONTEXT,
    )
    return _replace_engine(run, target_outcomes=(evidence,))


def _record(
    outcome: Outcome,
    *,
    exception_id: str = "EX-1",
    identity=IDENTITY,
    origin: ExceptionOrigin = ExceptionOrigin.TRUSTED_BASE,
    created: date = date(2026, 1, 1),
    expires: date = date(2026, 12, 31),
) -> ExceptionRecord:
    return ExceptionRecord(
        exception_id,
        identity,
        "accepted risk tracked in TICKET-42",
        "platform-team",
        created,
        expires,
        origin,
        frozenset({outcome}),
    )


def _verdict(run, *, exceptions=None, **kwargs):
    return evaluate_policy(
        PolicyRequest(run, TODAY, exceptions=exceptions, **kwargs)
    )


def test_clean_affirmative_evidence_is_verified(verified_engine) -> None:
    result = _verdict(verified_engine)
    assert result.verdict is Verdict.VERIFIED
    assert result.exit_code == EXIT_CODES[Verdict.VERIFIED] == 0
    assert require_trusted_policy_result(result) is result


@pytest.mark.parametrize("outcome", [
    Outcome.STILL_PRESENT,
    Outcome.PARTIALLY_FIXED,
    Outcome.SUPPRESSED,
    Outcome.RESOURCE_DELETED,
    Outcome.FILE_DELETED_OR_RENAMED,
    Outcome.OUT_OF_SCOPE,
])
def test_definite_unpermitted_target_outcomes_fail(verified_engine, outcome) -> None:
    assert _verdict(_outcome(verified_engine, outcome)).verdict is Verdict.FAILED


@pytest.mark.parametrize("outcome", [
    Outcome.SCANNER_ERROR,
    Outcome.RULE_OR_SCANNER_DRIFT,
    Outcome.INCONCLUSIVE,
])
def test_uncertain_target_outcomes_are_inconclusive(verified_engine, outcome) -> None:
    assert _verdict(_outcome(verified_engine, outcome)).verdict is Verdict.INCONCLUSIVE


@pytest.mark.parametrize("outcome", [
    Outcome.SUPPRESSED,
    Outcome.RESOURCE_DELETED,
    Outcome.FILE_DELETED_OR_RENAMED,
])
def test_exact_trusted_event_exception_permits_only_eligible_event(
    verified_engine, outcome
) -> None:
    run = _outcome(verified_engine, outcome)
    result = _verdict(run, exceptions=ExceptionPolicy((_record(outcome),)))
    assert result.verdict is Verdict.VERIFIED
    assert result.decisions[0].outcome is outcome
    assert result.decisions[0].policy_permitted is True
    assert result.decisions[0].exception_id == "EX-1"


def test_exception_for_suppression_does_not_authorize_deletion(verified_engine) -> None:
    run = _outcome(verified_engine, Outcome.RESOURCE_DELETED)
    result = _verdict(
        run,
        exceptions=ExceptionPolicy((_record(Outcome.SUPPRESSED),)),
    )
    assert result.verdict is Verdict.FAILED
    assert result.decisions[0].policy_permitted is False


@pytest.mark.parametrize("record", [
    _record(Outcome.SUPPRESSED, origin=ExceptionOrigin.CANDIDATE_HEAD),
    _record(Outcome.SUPPRESSED, expires=date(2026, 8, 10)),
    _record(Outcome.SUPPRESSED, created=date(2026, 8, 12)),
])
def test_untrusted_or_out_of_window_exception_cannot_permit(verified_engine, record) -> None:
    result = _verdict(
        _outcome(verified_engine, Outcome.SUPPRESSED),
        exceptions=ExceptionPolicy((record,)),
    )
    assert result.verdict is Verdict.FAILED
    assert result.decisions[0].rejection_reason


@pytest.mark.parametrize(("status", "expected"), [
    (Status.PASS, Verdict.VERIFIED),
    (Status.FAIL, Verdict.FAILED),
    (Status.ERROR, Verdict.INCONCLUSIVE),
    (Status.TIMEOUT, Verdict.INCONCLUSIVE),
    (Status.UNSUPPORTED, Verdict.INCONCLUSIVE),
    (Status.SKIPPED, Verdict.INCONCLUSIVE),
    (Status.PARTIAL, Verdict.INCONCLUSIVE),
    (Status.INCONCLUSIVE, Verdict.INCONCLUSIVE),
])
def test_validator_truth_table(verified_engine, status, expected) -> None:
    run = _replace_engine(
        verified_engine,
        validator_results=(GateResult("validator", status),),
    )
    assert _verdict(run).verdict is expected


@pytest.mark.parametrize(("status", "expected"), [
    (Status.PASS, Verdict.VERIFIED),
    (Status.FAIL, Verdict.FAILED),
    (Status.ERROR, Verdict.INCONCLUSIVE),
    (Status.TIMEOUT, Verdict.INCONCLUSIVE),
    (Status.UNSUPPORTED, Verdict.INCONCLUSIVE),
    (Status.SKIPPED, Verdict.INCONCLUSIVE),
    (Status.PARTIAL, Verdict.INCONCLUSIVE),
    (Status.INCONCLUSIVE, Verdict.INCONCLUSIVE),
])
def test_oracle_truth_table(verified_engine, status, expected) -> None:
    run = _replace_engine(
        verified_engine,
        oracle_results=(GateResult("oracle", status),),
    )
    assert _verdict(run).verdict is expected


@pytest.mark.parametrize("field", ["regression", "suppression"])
@pytest.mark.parametrize(("status", "expected"), [
    (Status.PASS, Verdict.VERIFIED),
    (Status.FAIL, Verdict.FAILED),
    (Status.ERROR, Verdict.INCONCLUSIVE),
    (Status.SKIPPED, Verdict.INCONCLUSIVE),
])
def test_policy_gate_truth_table(verified_engine, field, status, expected) -> None:
    run = _replace_engine(
        verified_engine,
        **{field: GateResult(field, status)},
    )
    assert _verdict(run).verdict is expected


def test_trusted_optional_skipped_gate_may_continue(verified_engine) -> None:
    run = _replace_engine(
        verified_engine,
        regression=GateResult("regression", Status.SKIPPED),
    )
    result = _verdict(
        run,
        optional_gates=frozenset({"regression"}),
        optional_gates_origin=ExceptionOrigin.TRUSTED_BASE,
    )
    assert result.verdict is Verdict.VERIFIED


def test_uncertainty_dominates_real_failure(verified_engine) -> None:
    run = _replace_engine(
        _outcome(verified_engine, Outcome.STILL_PRESENT),
        oracle_results=(GateResult("oracle", Status.ERROR),),
    )
    assert _verdict(run).verdict is Verdict.INCONCLUSIVE


def test_policy_drift_is_definite_failure(verified_engine) -> None:
    assert _verdict(
        _replace_engine(verified_engine, policy_drift=True)
    ).verdict is Verdict.FAILED


@pytest.mark.parametrize("field", [
    "coverage_decreased_on_required_scanner",
    "rule_substituted_on_required_target",
])
def test_integrity_uncertainty_flags_are_inconclusive(verified_engine, field) -> None:
    assert _verdict(_replace_engine(verified_engine, **{field: True})).verdict is Verdict.INCONCLUSIVE


def test_policy_output_is_canonical_and_input_order_independent(verified_engine) -> None:
    run = _outcome(verified_engine, Outcome.SUPPRESSED)
    active = _record(Outcome.SUPPRESSED, exception_id="EX-Z")
    expired = _record(
        Outcome.SUPPRESSED,
        exception_id="EX-A",
        expires=date(2026, 8, 10),
    )
    a = _verdict(run, exceptions=(active, expired)).canonical_dict()
    b = _verdict(run, exceptions=(expired, active)).canonical_dict()
    assert a == b


def test_policy_boundary_rejects_invalid_optional_gate_provenance(verified_engine) -> None:
    with pytest.raises(DomainError, match="protected"):
        PolicyRequest(
            verified_engine,
            TODAY,
            optional_gates=frozenset({"regression"}),
            optional_gates_origin=ExceptionOrigin.CANDIDATE_HEAD,
        )
    with pytest.raises(DomainError, match="unknown"):
        PolicyRequest(verified_engine, TODAY, optional_gates=frozenset({"other"}))


def test_caller_cannot_construct_authoritative_policy_result() -> None:
    with pytest.raises(DomainError, match="trusted policy"):
        PolicyResult(
            Verdict.FAILED,
            1,
            (TargetDecision(IDENTITY, Outcome.STILL_PRESENT),),
            TODAY,
        )
