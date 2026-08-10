"""Event binding: an exception authorises the events it names, and nothing else.

The defect this closes was reproduced directly: one `ExceptionRecord` bound to a target
and scope authorised all three exception-eligible outcomes, so a record approving a
Checkov suppression also approved deleting the whole Terraform resource and renaming the
file out of scanner scope. Those are not interchangeable remediations.

The written semantics already required "the **specific** non-fix event" to be permitted;
the executable record simply had no field for it.
"""
from __future__ import annotations

import itertools
import sys
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "spec"))
sys.path.insert(0, str(REPO / "src"))

import spec_reference as SPEC  # noqa: E402
from iac_guard_v import enums as PENUMS  # noqa: E402
from iac_guard_v import models as PMODELS  # noqa: E402

TODAY = date(2026, 8, 9)
SCOPE = "aws_s3_bucket.data"
ELIGIBLE = tuple(sorted(SPEC.PERMITTABLE_EXCEPTION_OUTCOMES, key=lambda o: o.value))

EVIDENCE = dict(
    evaluation_date=TODAY,
    preflight=SPEC.Status.PASS,
    required_scanner_integrity=SPEC.Status.PASS,
    required_gates=SPEC.RequiredGates(("terraform_hcl_parse",)),
    validator_results=(SPEC.GateResult("terraform_hcl_parse", SPEC.Status.PASS),),
    regression_policy=SPEC.Status.PASS,
    suppression_policy=SPEC.Status.PASS,
)


def record(permits, **overrides) -> SPEC.ExceptionRecord:
    base = dict(exception_id="EX-1", target_id="T1", scope=SCOPE,
                reason="accepted risk, TICKET-42", owner="platform-team",
                created=date(2026, 1, 1), expires=date(2026, 12, 31),
                origin=SPEC.ExceptionOrigin.TRUSTED_BASE,
                permitted_outcomes=frozenset(permits))
    return SPEC.ExceptionRecord(**{**base, **overrides})


def verdict_for(decision_outcome, permits) -> SPEC.Verdict:
    decision = SPEC.TargetDecision("T1", decision_outcome, SCOPE, True, "EX-1")
    run = SPEC.RunObservation((decision,),
                              exceptions=SPEC.ExceptionPolicy((record(permits),)),
                              **EVIDENCE)
    return SPEC.decide(run)


# --------------------------------------------------------------------------- #
# the full 3x3 matrix
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("permitted,attempted",
                         list(itertools.product(ELIGIBLE, ELIGIBLE)),
                         ids=[f"permits_{p.value}-attempts_{a.value}"
                              for p, a in itertools.product(ELIGIBLE, ELIGIBLE)])
def test_only_the_named_event_is_authorised(permitted, attempted) -> None:
    expected = SPEC.Verdict.VERIFIED if permitted is attempted else SPEC.Verdict.FAILED
    assert verdict_for(attempted, {permitted}) is expected


def test_suppression_approval_does_not_authorise_deletion() -> None:
    """The concrete case: approving a skip comment is not approving `terraform destroy`."""
    assert verdict_for(SPEC.Outcome.RESOURCE_DELETED,
                       {SPEC.Outcome.SUPPRESSED}) is SPEC.Verdict.FAILED


def test_deletion_approval_does_not_authorise_file_rename() -> None:
    assert verdict_for(SPEC.Outcome.FILE_DELETED_OR_RENAMED,
                       {SPEC.Outcome.RESOURCE_DELETED}) is SPEC.Verdict.FAILED


def test_file_rename_approval_does_not_authorise_suppression() -> None:
    assert verdict_for(SPEC.Outcome.SUPPRESSED,
                       {SPEC.Outcome.FILE_DELETED_OR_RENAMED}) is SPEC.Verdict.FAILED


@pytest.mark.parametrize("attempted", ELIGIBLE, ids=[o.value for o in ELIGIBLE])
def test_an_explicit_multi_outcome_exception_permits_exactly_what_it_lists(
    attempted,
) -> None:
    listed = {SPEC.Outcome.SUPPRESSED, SPEC.Outcome.RESOURCE_DELETED}
    expected = (SPEC.Verdict.VERIFIED if attempted in listed else SPEC.Verdict.FAILED)
    assert verdict_for(attempted, listed) is expected


def test_the_rejection_names_what_was_authorised_and_what_was_attempted() -> None:
    decision = SPEC.TargetDecision("T1", SPEC.Outcome.RESOURCE_DELETED, SCOPE, True,
                                   "EX-1")
    policy = SPEC.ExceptionPolicy((record({SPEC.Outcome.SUPPRESSED}),))
    reason = SPEC.permission_rejection_reason(decision, policy, TODAY)
    assert reason is not None
    assert "authorises ['SUPPRESSED']" in reason
    assert "not RESOURCE_DELETED" in reason


# --------------------------------------------------------------------------- #
# the authorisation set itself is constrained
# --------------------------------------------------------------------------- #
def test_empty_authorisation_is_invalid() -> None:
    with pytest.raises(SPEC.SpecDomainError):
        record(set())


def test_missing_authorisation_is_invalid() -> None:
    with pytest.raises(SPEC.InvalidVerificationRequest):
        SPEC.ExceptionRecord(
            exception_id="EX-1", target_id="T1", scope=SCOPE, reason="r",
            owner="o", created=date(2026, 1, 1), expires=date(2026, 12, 31),
            origin=SPEC.ExceptionOrigin.TRUSTED_BASE,
        )


@pytest.mark.parametrize("never", sorted(SPEC.NEVER_PERMITTABLE_OUTCOMES,
                                         key=lambda o: o.value))
def test_never_permittable_outcomes_cannot_be_listed(never) -> None:
    with pytest.raises(SPEC.SpecDomainError):
        record({never})


def test_fixed_cannot_be_listed_and_needs_no_exception() -> None:
    with pytest.raises(SPEC.SpecDomainError):
        record({SPEC.Outcome.FIXED})
    unpermitted = SPEC.TargetDecision("T1", SPEC.Outcome.FIXED, SCOPE)
    assert SPEC.decide(SPEC.RunObservation((unpermitted,), **EVIDENCE)) \
        is SPEC.Verdict.VERIFIED


@pytest.mark.parametrize("bad,label", [
    ({SPEC.Outcome.SUPPRESSED}, "mutable set"),
    ([SPEC.Outcome.SUPPRESSED], "list"),
    ((SPEC.Outcome.SUPPRESSED,), "tuple"),
    ("SUPPRESSED", "string"),
    (SPEC.Outcome.SUPPRESSED, "bare enum member"),
], ids=lambda v: v if isinstance(v, str) else "value")
def test_authorisation_must_be_an_exact_frozenset(bad, label: str) -> None:
    """A mutable or subclassed collection could change after validation.

    The record is constructed directly rather than through the helper, because the helper
    coerces to `frozenset` and would hide exactly what this test checks.
    """
    with pytest.raises(SPEC.SpecDomainError):
        SPEC.ExceptionRecord(
            exception_id="EX-1", target_id="T1", scope=SCOPE, reason="r", owner="o",
            created=date(2026, 1, 1), expires=date(2026, 12, 31),
            origin=SPEC.ExceptionOrigin.TRUSTED_BASE, permitted_outcomes=bad,
        )


def test_frozenset_subclass_is_also_rejected() -> None:
    class SneakySet(frozenset):
        pass

    with pytest.raises(SPEC.SpecDomainError):
        SPEC.ExceptionRecord(
            exception_id="EX-1", target_id="T1", scope=SCOPE, reason="r", owner="o",
            created=date(2026, 1, 1), expires=date(2026, 12, 31),
            origin=SPEC.ExceptionOrigin.TRUSTED_BASE,
            permitted_outcomes=SneakySet({SPEC.Outcome.SUPPRESSED}),
        )


def test_authorisation_survives_the_deep_copy() -> None:
    source = record({SPEC.Outcome.RESOURCE_DELETED})
    stored = SPEC.ExceptionPolicy((source,)).records[0]
    assert stored is not source
    assert stored.permitted_outcomes == frozenset({SPEC.Outcome.RESOURCE_DELETED})
    assert type(stored.permitted_outcomes) is frozenset


def test_event_binding_is_checked_alongside_every_other_clause() -> None:
    """Naming the right event does not excuse a wrong target, scope, origin or window."""
    right_event = {SPEC.Outcome.RESOURCE_DELETED}
    decision = SPEC.TargetDecision("T1", SPEC.Outcome.RESOURCE_DELETED, SCOPE, True,
                                   "EX-1")
    cases = {
        "target": record(right_event, target_id="T-OTHER"),
        "scope": record(right_event, scope="aws_s3_bucket.other"),
        "origin": record(right_event, origin=SPEC.ExceptionOrigin.CANDIDATE_HEAD),
        "expired": record(right_event, expires=date(2026, 1, 2)),
        "not yet": record(right_event, created=date(2026, 9, 1),
                          expires=date(2027, 1, 1)),
    }
    for label, rec in cases.items():
        policy = SPEC.ExceptionPolicy((rec,))
        assert SPEC.permission_rejection_reason(decision, policy, TODAY) is not None, label


# --------------------------------------------------------------------------- #
# the production model enforces the same binding
# --------------------------------------------------------------------------- #
def test_production_record_requires_and_enforces_event_binding() -> None:
    identity = PMODELS.TargetIdentity("checkov", "CKV_AWS_18", SCOPE)
    rec = PMODELS.ExceptionRecord(
        exception_id="EX-1", target=identity, reason="accepted risk",
        owner="platform-team", created=date(2026, 1, 1), expires=date(2026, 12, 31),
        origin=PENUMS.ExceptionOrigin.TRUSTED_BASE,
        permitted_outcomes=frozenset({PENUMS.Outcome.SUPPRESSED}),
    )
    policy = PMODELS.ExceptionPolicy((rec,))
    wrong = PMODELS.TargetDecision(identity, PENUMS.Outcome.RESOURCE_DELETED, True,
                                   "EX-1")
    right = PMODELS.TargetDecision(identity, PENUMS.Outcome.SUPPRESSED, True, "EX-1")
    assert "not RESOURCE_DELETED" in PMODELS.permission_rejection_reason(wrong, policy,
                                                                        TODAY)
    assert PMODELS.permission_rejection_reason(right, policy, TODAY) is None


def test_production_record_rejects_never_permittable_authorisation() -> None:
    with pytest.raises(PMODELS.DomainError):
        PMODELS.ExceptionRecord(
            exception_id="EX-1",
            target=PMODELS.TargetIdentity("checkov", "CKV_AWS_18", SCOPE),
            reason="r", owner="o",
            created=date(2026, 1, 1), expires=date(2026, 12, 31),
            origin=PENUMS.ExceptionOrigin.TRUSTED_BASE,
            permitted_outcomes=frozenset({PENUMS.Outcome.STILL_PRESENT}),
        )


def test_the_two_models_agree_on_the_closed_sets() -> None:
    """The production model must not diverge from the conformance oracle."""
    assert ({o.value for o in SPEC.PERMITTABLE_EXCEPTION_OUTCOMES}
            == {o.value for o in PENUMS.PERMITTABLE_EXCEPTION_OUTCOMES})
    assert ({o.value for o in SPEC.NEVER_PERMITTABLE_OUTCOMES}
            == {o.value for o in PENUMS.NEVER_PERMITTABLE_OUTCOMES})
    assert ({o.value for o in SPEC.Outcome} == {o.value for o in PENUMS.Outcome})
    assert ({s.value for s in SPEC.Status} == {s.value for s in PENUMS.Status})
