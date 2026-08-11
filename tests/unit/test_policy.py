"""D6 policy truth table, exception binding, and provenance boundary."""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

import iac_guard_v.engine as ENGINE
from iac_guard_v.engine import EngineEventEvaluation, TargetOutcomeEvidence, VerificationResult
from iac_guard_v.enums import (
    EXIT_CODES,
    ArtifactKind,
    ExceptionOrigin,
    DeltaClass,
    Outcome,
    Status,
    Verdict,
)
from iac_guard_v.models import (
    DomainError,
    ExceptionPolicy,
    ExceptionRecord,
    GateResult,
    ResolvedTargetBinding,
    TargetDecision,
)
from iac_guard_v.policy import (
    PolicyRequest,
    PolicyResult,
    evaluate_policy,
    load_candidate_policy,
    load_operator_policy,
    require_trusted_policy_result,
)
from test_engine import (
    IDENTITY,
    _config,
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


def _clock() -> datetime:
    return datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def verified_engine(monkeypatch, tmp_path) -> VerificationResult:
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, request: _run(
            request, baseline=request.scan_root == baseline.scan_root
        ),
    )
    gates = RequiredGates(("validator",), ("oracle",))
    request = VerificationRequest(
        baseline,
        candidate,
        (Target(IDENTITY, 1),),
        _config(baseline, candidate, gates),
    )
    return run_checkov_verification(request)


def _replace_engine(run: VerificationResult, **changes) -> VerificationResult:
    values = {
        name: getattr(run, name)
        for name in VerificationResult.__dataclass_fields__
        if not name.startswith("_")
    }
    if "verification_config" in changes:
        config = changes["verification_config"]
        for name in ("baseline_snapshot", "candidate_snapshot"):
            snapshot = values[name]
            snapshot_values = {
                field_name: getattr(snapshot, field_name)
                for field_name in ENGINE.SealedVerificationSnapshot.__dataclass_fields__
                if not field_name.startswith("_")
            }
            snapshot_values["config_sha256"] = config.config_sha256
            values[name] = ENGINE.SealedVerificationSnapshot(
                **snapshot_values,
                _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
            )
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
        run.target_outcomes[0].binding,
        outcome,
        observed,
        "TEST_TARGET_EVIDENCE",
        _trusted_context=ENGINE._TRUSTED_ENGINE_CONTEXT,
    )
    return _replace_engine(run, target_outcomes=(evidence,))


def _engine_event(run: VerificationResult, delta_class: DeltaClass, status: Status) -> VerificationResult:
    events = tuple(
        EngineEventEvaluation(
            delta_class=item.delta_class,
            status=status if item.delta_class is delta_class else item.status,
            reason_code=(
                "TEST_EVENT_STATE" if item.delta_class is delta_class
                else item.reason_code
            ),
            affected_resource_records=item.affected_resource_records,
            affected_resources=item.affected_resources,
            affected_paths=item.affected_paths,
            detail=item.detail,
        )
        for item in run.engine_events
    )
    return _replace_engine(run, engine_events=events)


def _record(
    outcome: Outcome,
    *,
    exception_id: str = "EX-1",
    identity=IDENTITY,
    origin: ExceptionOrigin = ExceptionOrigin.TRUSTED_BASE,
    created: date = date(2026, 1, 1),
    expires: date = date(2026, 12, 31),
    resolved_target=None,
) -> ExceptionRecord:
    if resolved_target is None:
        resolved_target = ResolvedTargetBinding(
            identity, "main.tf", ArtifactKind.TERRAFORM_HCL, identity.scope
        )
    return ExceptionRecord(
        exception_id,
        identity,
        "accepted risk tracked in TICKET-42",
        "platform-team",
        created,
        expires,
        origin,
        frozenset({outcome}),
        resolved_target,
    )


def _policy_payload(*, exceptions=None, optional_gates=frozenset()) -> dict:
    if exceptions is None:
        policy = ExceptionPolicy(())
    elif type(exceptions) is ExceptionPolicy:
        policy = exceptions
    else:
        policy = ExceptionPolicy(exceptions)
    records = [
        {
            "exception_id": record.exception_id,
            "target": {
                "scanner": record.target.scanner,
                "rule_id": record.target.rule_id,
                "scope": record.target.scope,
                "file_path": record.resolved_target.file_path,
                "artifact_kind": record.resolved_target.artifact_kind.value,
                "scanner_native_lookup": record.resolved_target.scanner_native_lookup,
            },
            "reason": record.reason,
            "owner": record.owner,
            "created": record.created.isoformat(),
            "expires": record.expires.isoformat(),
            "origin": record.origin.value,
            "permitted_outcomes": sorted(item.value for item in record.permitted_outcomes),
        }
        for record in policy.records
    ]
    return {
        "exceptions": records,
        "optional_gates": sorted(optional_gates),
    }


def _bundle(*, config, exceptions=None, optional_gates=frozenset(), candidate_payload=None):
    context = __import__(
        "iac_guard_v.policy", fromlist=["load_operator_execution_context"]
    ).load_operator_execution_context(config)
    return load_operator_policy(
        _policy_payload(exceptions=exceptions, optional_gates=optional_gates),
        candidate_payload=candidate_payload,
        context=context,
    )


def _verdict(run, *, exceptions=None, optional_gates=frozenset()):
    return evaluate_policy(PolicyRequest(
        run, _bundle(
            config=run.verification_config,
            exceptions=exceptions, optional_gates=optional_gates,
        )
    ))


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
    _record(Outcome.SUPPRESSED, expires=date(2026, 8, 10)),
    _record(Outcome.SUPPRESSED, created=date(2026, 8, 12)),
])
def test_out_of_window_exception_cannot_permit(verified_engine, record) -> None:
    result = _verdict(
        _outcome(verified_engine, Outcome.SUPPRESSED),
        exceptions=ExceptionPolicy((record,)),
    )
    assert result.verdict is Verdict.FAILED
    assert result.decisions[0].rejection_reason


def test_candidate_policy_cannot_be_used_as_trusted_bundle(verified_engine) -> None:
    payload = _policy_payload(exceptions=(
        _record(Outcome.SUPPRESSED, origin=ExceptionOrigin.CANDIDATE_HEAD),
    ))
    candidate = load_candidate_policy(payload)
    assert candidate.records[0].origin is ExceptionOrigin.CANDIDATE_HEAD
    with pytest.raises(DomainError, match="TrustedPolicyBundle"):
        PolicyRequest(_outcome(verified_engine, Outcome.SUPPRESSED), candidate)


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
        _engine_event(verified_engine, DeltaClass.POLICY_DRIFT, Status.FAIL)
    ).verdict is Verdict.FAILED


@pytest.mark.parametrize("delta_class", [
    DeltaClass.COVERAGE_DECREASED,
    DeltaClass.RULE_SUBSTITUTED,
])
def test_integrity_uncertainty_flags_are_inconclusive(verified_engine, delta_class) -> None:
    assert _verdict(
        _engine_event(verified_engine, delta_class, Status.INCONCLUSIVE)
    ).verdict is Verdict.INCONCLUSIVE


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
    candidate = load_candidate_policy({"exceptions": [], "optional_gates": ["regression"]})
    with pytest.raises(DomainError, match="TrustedPolicyBundle"):
        PolicyRequest(verified_engine, candidate)
    with pytest.raises(DomainError, match="unknown"):
        _bundle(
            config=verified_engine.verification_config,
            optional_gates=frozenset({"other"}),
        )


def test_caller_cannot_construct_authoritative_policy_result() -> None:
    with pytest.raises(DomainError, match="policy evidence"):
        PolicyResult(
            Verdict.FAILED,
            1,
            (TargetDecision(IDENTITY, Outcome.STILL_PRESENT),),
            object(),
        )
