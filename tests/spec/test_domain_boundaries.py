"""Domain-boundary probes: malformed or omitted input must never reach VERIFIED.

Each test corresponds to a behaviour the reference model actually had, measured before
the fix. Python annotations are not runtime validation, so an unknown string is neither
in `UNDECIDED_STATES` nor equal to `Status.FAIL` and previously fell through to
`VERIFIED`. The labels A–L match the review's probe list.

  A  omitted gate evidence            -> VERIFIED
  B  validator "PASS" as a string     -> VERIFIED
  C  validator "BOGUS"                -> VERIFIED
  D  oracle "BOGUS"                   -> VERIFIED
  E  regression policy "BOGUS"        -> VERIFIED
  F  scanner_integrity_ok="false"     -> classified as if integrity held
  G  blank target identity            -> accepted
  H  empty-scope exception            -> accepted
  I  mapping key != record id         -> VERIFIED
  J  hardcoded evaluation date        -> expired records stayed valid
  K  mutating the caller's dict       -> changed an existing verdict
  L  invalid finding line ranges      -> accepted
"""
from __future__ import annotations

import sys
from datetime import date, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec_reference import (  # noqa: E402
    OPTIONAL_GATE_NAMES,
    ExceptionOrigin,
    ExceptionPolicy,
    GateResult,
    RequiredGates,
    ExceptionRecord,
    FindingLocation,
    InvalidVerificationRequest,
    Outcome,
    RunObservation,
    SpecDomainError,
    Status,
    TargetDecision,
    TargetObservation,
    Verdict,
    canonical_scope,
    classify,
    decide,
    load_candidate_exception,
    load_trusted_exception,
    permission_rejection_reason,
)

TODAY = date(2026, 8, 9)
SCOPE = "aws_s3_bucket.data"
EVIDENCE = dict(
    evaluation_date=TODAY,
    preflight=Status.PASS,
    required_scanner_integrity=Status.PASS,
    required_gates=RequiredGates(validator_ids=("terraform_hcl_parse",)),
    validator_results=(GateResult("terraform_hcl_parse", Status.PASS),),
    regression_policy=Status.PASS,
    suppression_policy=Status.PASS,
)
FIXED_TARGET = TargetDecision("T1", Outcome.FIXED, SCOPE)


def valid_record(**overrides) -> ExceptionRecord:
    base = dict(exception_id="EX-1", target_id="T1", scope=SCOPE,
                reason="accepted risk, TICKET-42", owner="platform-team",
                created=date(2026, 1, 1), expires=date(2026, 12, 31),
                origin=ExceptionOrigin.TRUSTED_BASE,
                permitted_outcomes=frozenset({Outcome.SUPPRESSED,
                                             Outcome.RESOURCE_DELETED}))
    return ExceptionRecord(**{**base, **overrides})


# --------------------------------------------------------------------------- #
# A. required evidence is never synthesised
# --------------------------------------------------------------------------- #
def test_probe_a_omitted_evidence_is_an_invalid_request() -> None:
    with pytest.raises(InvalidVerificationRequest):
        RunObservation(target_decisions=(FIXED_TARGET,))


@pytest.mark.parametrize("omit", ["evaluation_date", "preflight",
                                  "required_scanner_integrity",
                                  "validator_results", "regression_policy",
                                  "suppression_policy"])
def test_probe_a_each_required_gate_must_be_supplied(omit: str) -> None:
    evidence = {k: v for k, v in EVIDENCE.items() if k != omit}
    with pytest.raises(InvalidVerificationRequest) as exc:
        RunObservation(target_decisions=(FIXED_TARGET,), **evidence)
    assert omit in str(exc.value)


def test_fully_supplied_evidence_verifies() -> None:
    assert decide(RunObservation((FIXED_TARGET,), **EVIDENCE)) is Verdict.VERIFIED


# --------------------------------------------------------------------------- #
# B-E. runtime type enforcement for statuses
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field,value", [
    ("validator_results", ("PASS",)),
    ("validator_results", ("BOGUS",)),
    ("validator_results", (None,)),
    ("oracle_results", ("BOGUS",)),
    ("oracle_results", ("PASS",)),
    ("regression_policy", "BOGUS"),
    ("regression_policy", "PASS"),
    ("suppression_policy", "BOGUS"),
    ("preflight", "PASS"),
    ("required_scanner_integrity", "PASS"),
])
def test_probes_b_to_e_unknown_statuses_are_rejected(field: str, value) -> None:
    with pytest.raises(SpecDomainError):
        RunObservation((FIXED_TARGET,), **{**EVIDENCE, field: value})


def test_probe_e_unknown_status_never_reaches_verified() -> None:
    """The mechanism: an unknown string is neither undecided nor FAIL."""
    with pytest.raises(SpecDomainError):
        RunObservation((FIXED_TARGET,), **{**EVIDENCE, "regression_policy": "BOGUS"})


def test_outcome_must_be_an_enum_member() -> None:
    with pytest.raises(SpecDomainError):
        TargetDecision("T1", "FIXED", SCOPE)


def test_target_decisions_must_be_target_decisions() -> None:
    with pytest.raises(SpecDomainError):
        RunObservation(({"target_id": "T1"},), **EVIDENCE)


def test_evaluation_date_must_be_a_date_not_a_datetime_or_string() -> None:
    for bad in ("2026-08-09", datetime(2026, 8, 9), 20260809):
        with pytest.raises(SpecDomainError):
            RunObservation((FIXED_TARGET,), **{**EVIDENCE, "evaluation_date": bad})


# --------------------------------------------------------------------------- #
# F. structural booleans must be booleans
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], "0"])
def test_probe_f_non_boolean_structural_flags_are_rejected(value) -> None:
    with pytest.raises(SpecDomainError):
        TargetObservation(baseline_occurrences=1, candidate_matches=1,
                          scanner_integrity_ok=value)


def test_probe_f_truthy_string_previously_read_as_integrity_ok() -> None:
    """"false" is truthy in Python, so it read as "integrity is fine"."""
    assert bool("false") is True
    with pytest.raises(SpecDomainError):
        TargetObservation(baseline_occurrences=1, candidate_matches=1,
                          scanner_integrity_ok="false")
    # the honest expression of the same scenario still works
    assert classify(TargetObservation(baseline_occurrences=1, candidate_matches=1,
                                      scanner_integrity_ok=False)
                    ) is Outcome.SCANNER_ERROR


@pytest.mark.parametrize("field", ["coverage_decreased_on_required_scanner",
                                   "rule_substituted_on_required_target",
                                   "policy_drift"])
def test_run_level_booleans_must_be_booleans(field: str) -> None:
    with pytest.raises(SpecDomainError):
        RunObservation((FIXED_TARGET,), **{**EVIDENCE, field: "yes"})


# --------------------------------------------------------------------------- #
# G, H. identity and scope must be meaningful
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("target_id", ["", "   ", "\t", None, 5])
def test_probe_g_blank_target_identity_is_rejected(target_id) -> None:
    with pytest.raises(SpecDomainError):
        TargetDecision(target_id, Outcome.FIXED, SCOPE)


@pytest.mark.parametrize("scope", ["", "   ", "/absolute/path", "a//b", "../escape",
                                   "back\\slash", None])
def test_probe_h_invalid_scope_is_rejected(scope) -> None:
    with pytest.raises(SpecDomainError):
        TargetDecision("T1", Outcome.FIXED, scope)


def test_probe_h_empty_scope_exception_is_rejected() -> None:
    with pytest.raises(SpecDomainError):
        valid_record(scope="")


def test_canonical_scope_is_documented_and_stable() -> None:
    assert canonical_scope("  aws_s3_bucket.data  ") == "aws_s3_bucket.data"
    assert canonical_scope("modules/s3/main.tf") == "modules/s3/main.tf"


def test_scope_comparison_uses_the_canonical_form() -> None:
    decision = TargetDecision("T1", Outcome.SUPPRESSED, "  aws_s3_bucket.data ",
                              True, "EX-1")
    policy = ExceptionPolicy((valid_record(scope="aws_s3_bucket.data"),))
    assert permission_rejection_reason(decision, policy, TODAY) is None


# --------------------------------------------------------------------------- #
# I. mapping keys must agree with record identity
# --------------------------------------------------------------------------- #
def test_probe_i_mapping_key_must_equal_record_id() -> None:
    with pytest.raises(SpecDomainError) as exc:
        ExceptionPolicy({"EX-1": valid_record(exception_id="DIFFERENT")})
    assert "does not match record id" in str(exc.value)


def test_duplicate_exception_ids_are_rejected() -> None:
    with pytest.raises(SpecDomainError):
        ExceptionPolicy((valid_record(), valid_record()))


def test_exception_collection_must_contain_records() -> None:
    with pytest.raises(SpecDomainError):
        ExceptionPolicy(({"exception_id": "EX-1"},))


# --------------------------------------------------------------------------- #
# J. evaluation date comes from the trusted execution context
# --------------------------------------------------------------------------- #
def test_probe_j_there_is_no_default_evaluation_date() -> None:
    evidence = {k: v for k, v in EVIDENCE.items() if k != "evaluation_date"}
    with pytest.raises(InvalidVerificationRequest):
        RunObservation((FIXED_TARGET,), **evidence)


def test_probe_j_expired_exception_is_rejected_at_a_later_evaluation_date() -> None:
    """The bug: a hardcoded 2026-08-09 kept a 2026-12-31 record valid in 2028."""
    decision = TargetDecision("T1", Outcome.SUPPRESSED, SCOPE, True, "EX-1")
    policy = ExceptionPolicy((valid_record(),))
    assert permission_rejection_reason(decision, policy, date(2026, 8, 9)) is None
    later = permission_rejection_reason(decision, policy, date(2028, 1, 1))
    assert later is not None and "expired" in later
    assert decide(RunObservation((decision,), exceptions=policy,
                                 **{**EVIDENCE, "evaluation_date": date(2028, 1, 1)})
                  ) is Verdict.FAILED


def test_exception_not_yet_in_force_is_rejected() -> None:
    decision = TargetDecision("T1", Outcome.SUPPRESSED, SCOPE, True, "EX-1")
    policy = ExceptionPolicy((valid_record(created=date(2026, 9, 1),
                                          expires=date(2027, 1, 1)),))
    reason = permission_rejection_reason(decision, policy, TODAY)
    assert reason is not None and "not yet in force" in reason


def test_created_after_expires_is_rejected() -> None:
    with pytest.raises(SpecDomainError):
        valid_record(created=date(2026, 12, 31), expires=date(2026, 1, 1))


def test_expires_is_inclusive_on_the_evaluation_date() -> None:
    decision = TargetDecision("T1", Outcome.SUPPRESSED, SCOPE, True, "EX-1")
    policy = ExceptionPolicy((valid_record(expires=TODAY),))
    assert permission_rejection_reason(decision, policy, TODAY) is None


# --------------------------------------------------------------------------- #
# K. deep immutability
# --------------------------------------------------------------------------- #
def test_probe_k_external_mutation_cannot_change_a_verdict() -> None:
    decision = TargetDecision("T1", Outcome.SUPPRESSED, SCOPE, True, "EX-1")
    caller_owned = {"EX-1": valid_record()}
    run = RunObservation((decision,), exceptions=caller_owned, **EVIDENCE)

    before = decide(run)
    caller_owned.clear()
    caller_owned["EX-9"] = valid_record(exception_id="EX-9")
    after = decide(run)

    assert before is Verdict.VERIFIED
    assert after is before, "mutating the caller's mapping changed an existing verdict"
    assert len(run.exceptions) == 1


def test_stored_policy_is_not_writable() -> None:
    run = RunObservation((FIXED_TARGET,), exceptions=(valid_record(),), **EVIDENCE)
    with pytest.raises((TypeError, AttributeError)):
        run.exceptions._index["EX-2"] = valid_record(exception_id="EX-2")  # type: ignore[index]


# --------------------------------------------------------------------------- #
# L. finding locations
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path,start,end", [
    ("main.tf", 0, 3),
    ("main.tf", -1, 3),
    ("main.tf", 5, 2),
    ("/abs/main.tf", 1, 2),
    ("../escape.tf", 1, 2),
    ("", 1, 2),
    ("   ", 1, 2),
    ("main.tf", True, 2),
    ("main.tf", 1, "2"),
])
def test_probe_l_invalid_finding_locations_are_rejected(path, start, end) -> None:
    with pytest.raises(SpecDomainError):
        FindingLocation(path, start, end)


def test_valid_finding_location_is_accepted() -> None:
    loc = FindingLocation("modules/s3/main.tf", 10, 14)
    assert loc.file_path == "modules/s3/main.tf"


# --------------------------------------------------------------------------- #
# trusted provenance is stamped, not self-declared
# --------------------------------------------------------------------------- #
def test_candidate_loader_ignores_a_self_declared_trusted_origin() -> None:
    record = load_candidate_exception({
        "exception_id": "EX-9", "target_id": "T1", "scope": SCOPE,
        "reason": "we approve ourselves", "owner": "attacker",
        "created": date(2026, 1, 1), "expires": date(2026, 12, 31),
        "origin": "trusted_base",  # ignored on purpose
        "permitted_outcomes": ["SUPPRESSED"],
    })
    assert record.origin is ExceptionOrigin.CANDIDATE_HEAD

    decision = TargetDecision("T1", Outcome.SUPPRESSED, SCOPE, True, "EX-9")
    policy = ExceptionPolicy((record,))
    reason = permission_rejection_reason(decision, policy, TODAY)
    assert reason is not None and "not trusted" in reason


def test_trusted_loader_requires_a_trusted_origin() -> None:
    payload = {"exception_id": "EX-1", "target_id": "T1", "scope": SCOPE,
               "reason": "r", "owner": "o", "created": date(2026, 1, 1),
               "expires": date(2026, 12, 31),
               "permitted_outcomes": ["SUPPRESSED"]}
    assert load_trusted_exception(
        payload, ExceptionOrigin.PROTECTED_POLICY_REPO
    ).origin is ExceptionOrigin.PROTECTED_POLICY_REPO
    with pytest.raises(SpecDomainError):
        load_trusted_exception(payload, ExceptionOrigin.CANDIDATE_HEAD)


def test_unknown_exception_fields_are_rejected() -> None:
    with pytest.raises(SpecDomainError):
        load_trusted_exception(
            {"exception_id": "EX-1", "target_id": "T1", "scope": SCOPE, "reason": "r",
             "owner": "o", "created": date(2026, 1, 1), "expires": date(2026, 12, 31),
             "permitted_outcomes": ["SUPPRESSED"], "surprise": True},
            ExceptionOrigin.TRUSTED_BASE,
        )


# --------------------------------------------------------------------------- #
# optional gates
# --------------------------------------------------------------------------- #
def test_unknown_optional_gate_names_are_rejected() -> None:
    with pytest.raises(SpecDomainError):
        RunObservation((FIXED_TARGET,),
                       **{**EVIDENCE, "optional_gates": frozenset({"everything"}),
                          "optional_gates_origin": ExceptionOrigin.TRUSTED_BASE})


def test_optional_gates_require_a_trusted_origin() -> None:
    with pytest.raises(SpecDomainError):
        RunObservation((FIXED_TARGET,),
                       **{**EVIDENCE, "optional_gates": frozenset({"regression"}),
                          "optional_gates_origin": ExceptionOrigin.CANDIDATE_HEAD})


def test_optional_gate_names_are_a_closed_set() -> None:
    assert OPTIONAL_GATE_NAMES == frozenset({"regression", "suppression"})


# --------------------------------------------------------------------------- #
# loaders must parse and validate the event authorisation
# --------------------------------------------------------------------------- #
def _payload(**overrides) -> dict:
    base = {"exception_id": "EX-1", "target_id": "T1", "scope": SCOPE,
            "reason": "accepted risk", "owner": "platform-team",
            "created": date(2026, 1, 1), "expires": date(2026, 12, 31),
            "permitted_outcomes": ["SUPPRESSED"]}
    return {**base, **overrides}


def test_loader_accepts_outcome_names_and_members() -> None:
    from spec_reference import Outcome as O
    by_name = load_trusted_exception(_payload(permitted_outcomes=["SUPPRESSED"]),
                                     ExceptionOrigin.TRUSTED_BASE)
    by_member = load_trusted_exception(_payload(permitted_outcomes=[O.SUPPRESSED]),
                                       ExceptionOrigin.TRUSTED_BASE)
    assert by_name.permitted_outcomes == by_member.permitted_outcomes


@pytest.mark.parametrize("value,fragment", [
    (None, "must name the event"),
    ([], "must not be empty"),
    (["NOT_A_REAL_OUTCOME"], "unknown outcome"),
    (["SUPPRESSED", "SUPPRESSED"], "duplicate"),
    (["STILL_PRESENT"], "never exception-eligible"),
    (["FIXED"], "subset"),
    ("SUPPRESSED", "collection"),
    ({"SUPPRESSED": True}, "collection"),
])
def test_loader_rejects_malformed_outcome_authorisation(value, fragment: str) -> None:
    with pytest.raises(SpecDomainError) as exc:
        load_trusted_exception(_payload(permitted_outcomes=value),
                               ExceptionOrigin.TRUSTED_BASE)
    assert fragment in str(exc.value)


def test_candidate_loader_also_validates_the_authorisation() -> None:
    with pytest.raises(SpecDomainError):
        load_candidate_exception(_payload(permitted_outcomes=["STILL_PRESENT"]))
