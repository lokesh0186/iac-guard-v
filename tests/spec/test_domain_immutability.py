"""Probes for the two fail-open defects found in the D0 domain model, plus the
boundaries added while fixing them.

Both defects were independently reproduced before this file existed:

  1. `ExceptionPolicy` was not frozen. `policy._records = ()` and
     `policy._index = MappingProxyType({})` changed an already-constructed run's verdict
     from `VERIFIED` to `FAILED`, because `RunObservation` stored the caller's object by
     reference and only rebuilt it when it was not already an `ExceptionPolicy`.

  2. `TargetDecision.target_scope` defaulted to `"unspecified/scope"`. A caller that
     omitted the scope entirely got a placeholder, and a trusted exception carrying the
     same placeholder matched it exactly — so a `RESOURCE_DELETED` with no real scope
     verified.

Also covered here: gate identities (counting `PASS` results is not covering the required
gates), control characters, Windows drive-absolute paths, and the separation of resource
scopes from repository paths.
"""
from __future__ import annotations

import dataclasses
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec_reference import (  # noqa: E402
    RESERVED_PLACEHOLDERS,
    ExceptionOrigin,
    ExceptionPolicy,
    ExceptionRecord,
    GateResult,
    InvalidVerificationRequest,
    Outcome,
    RequiredGates,
    RunObservation,
    SpecDomainError,
    Status,
    TargetDecision,
    Verdict,
    canonical_identifier,
    canonical_repo_path,
    canonical_resource_scope,
    coerce_exception_policy,
    decide,
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


def record(**overrides) -> ExceptionRecord:
    base = dict(exception_id="EX-1", target_id="T1", scope=SCOPE,
                reason="accepted risk, TICKET-42", owner="platform-team",
                created=date(2026, 1, 1), expires=date(2026, 12, 31),
                origin=ExceptionOrigin.TRUSTED_BASE)
    return ExceptionRecord(**{**base, **overrides})


def permitted_deletion() -> TargetDecision:
    return TargetDecision("T1", Outcome.RESOURCE_DELETED, SCOPE, True, "EX-1")


# --------------------------------------------------------------------------- #
# defect 1: ExceptionPolicy immutability
# --------------------------------------------------------------------------- #
def test_policy_is_a_frozen_dataclass() -> None:
    assert dataclasses.is_dataclass(ExceptionPolicy)
    params = ExceptionPolicy.__dataclass_params__
    assert params.frozen is True


@pytest.mark.parametrize("attribute,value", [
    ("records", ()),
    ("index", {}),
])
def test_policy_internals_cannot_be_reassigned(attribute: str, value) -> None:
    """The exact mutation that previously flipped a verdict."""
    policy = ExceptionPolicy((record(),))
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(policy, attribute, value)


def test_mutating_a_caller_owned_policy_cannot_change_a_stored_verdict() -> None:
    policy = ExceptionPolicy((record(),))
    run = RunObservation((permitted_deletion(),), exceptions=policy, **EVIDENCE)
    before = decide(run)
    assert before is Verdict.VERIFIED

    # every mutation route the reviewer exercised, plus rebinding the local name
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.records = ()
    policy = ExceptionPolicy(())  # rebinding the caller's variable

    assert decide(run) is before
    assert len(run.exceptions) == 1
    assert run.exceptions.records[0].exception_id == "EX-1"


def test_run_does_not_retain_the_callers_policy_object() -> None:
    policy = ExceptionPolicy((record(),))
    run = RunObservation((permitted_deletion(),), exceptions=policy, **EVIDENCE)
    assert run.exceptions is not policy, "the policy must be rebuilt, not aliased"
    assert run.exceptions.records == policy.records


def test_mutating_the_source_mapping_cannot_change_a_stored_verdict() -> None:
    caller_owned = {"EX-1": record()}
    run = RunObservation((permitted_deletion(),), exceptions=caller_owned, **EVIDENCE)
    before = decide(run)
    caller_owned.clear()
    caller_owned["EX-2"] = record(exception_id="EX-2")
    assert decide(run) is before is Verdict.VERIFIED


def test_records_are_canonically_sorted_for_determinism() -> None:
    a = record(exception_id="EX-a")
    b = record(exception_id="EX-b")
    c = record(exception_id="EX-c")
    assert (ExceptionPolicy((c, a, b)).records
            == ExceptionPolicy((a, b, c)).records
            == (a, b, c))


def test_policy_subclasses_are_rejected_at_the_boundary() -> None:
    """isinstance would accept a subclass that overrides get() or index."""

    @dataclasses.dataclass(frozen=True, slots=True)
    class SneakyPolicy(ExceptionPolicy):
        def get(self, exception_id):  # noqa: D102 - always approves
            return record(exception_id=exception_id or "EX-1")

    sneaky = SneakyPolicy((record(),))
    with pytest.raises(SpecDomainError):
        coerce_exception_policy(sneaky)
    with pytest.raises(SpecDomainError):
        RunObservation((permitted_deletion(),), exceptions=sneaky, **EVIDENCE)


def test_lookalike_objects_are_rejected() -> None:
    class NotAPolicy:
        records = ()

        def get(self, _):
            return record()

    with pytest.raises(SpecDomainError):
        coerce_exception_policy(NotAPolicy())


# --------------------------------------------------------------------------- #
# defect 2: target scope is mandatory and must be meaningful
# --------------------------------------------------------------------------- #
def test_omitted_target_scope_is_rejected() -> None:
    with pytest.raises(InvalidVerificationRequest) as exc:
        TargetDecision("T1", Outcome.FIXED)
    assert "target_scope" in str(exc.value)


def test_omitted_scope_on_a_deletion_is_rejected() -> None:
    with pytest.raises(InvalidVerificationRequest):
        TargetDecision(target_id="T1", outcome=Outcome.RESOURCE_DELETED,
                       policy_permitted=True, exception_id="EX-1")


@pytest.mark.parametrize("placeholder", sorted(RESERVED_PLACEHOLDERS))
def test_placeholder_scopes_are_rejected(placeholder: str) -> None:
    with pytest.raises(SpecDomainError):
        TargetDecision("T1", Outcome.RESOURCE_DELETED, placeholder)
    with pytest.raises(SpecDomainError):
        record(scope=placeholder)


@pytest.mark.parametrize("placeholder", ["unspecified", "UNKNOWN", "Default/Scope", "n/a"])
def test_placeholder_identifiers_are_rejected(placeholder: str) -> None:
    with pytest.raises(SpecDomainError):
        canonical_identifier(placeholder, "target_id")


def test_a_placeholder_scoped_exception_cannot_exist_to_authorise_anything() -> None:
    """The end-to-end version of defect 2."""
    with pytest.raises(SpecDomainError):
        record(scope="unspecified/scope")


def test_two_targets_cannot_be_distinguished_by_placeholder_scopes() -> None:
    with pytest.raises(SpecDomainError):
        TargetDecision("T-A", Outcome.RESOURCE_DELETED, "unspecified/scope")


def test_explicit_distinct_scopes_are_required_and_respected() -> None:
    a = TargetDecision("T-A", Outcome.RESOURCE_DELETED, "aws_s3_bucket.a", True, "EX-A")
    b = TargetDecision("T-B", Outcome.RESOURCE_DELETED, "aws_s3_bucket.b")
    policy = ExceptionPolicy((record(exception_id="EX-A", target_id="T-A",
                                    scope="aws_s3_bucket.a"),))
    assert decide(RunObservation((a,), exceptions=policy, **EVIDENCE)) is Verdict.VERIFIED
    assert decide(RunObservation((a, b), exceptions=policy, **EVIDENCE)) is Verdict.FAILED


# --------------------------------------------------------------------------- #
# identifier, scope, and path validation are separate concerns
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", [
    "a\x00b", "a\nb", "a\rb", "a\tb", "a\u2028b", "a\u200eb",
])
def test_control_characters_are_rejected_everywhere(bad: str) -> None:
    for fn, name in ((canonical_identifier, "id"), (canonical_resource_scope, "scope"),
                     (canonical_repo_path, "path")):
        with pytest.raises(SpecDomainError):
            fn(bad, name)


@pytest.mark.parametrize("bad", ["C:/x/y", "c:\\x\\y", "/etc/passwd", "a//b", "../up",
                                 "./here", ""])
def test_absolute_and_traversal_forms_are_rejected(bad: str) -> None:
    with pytest.raises(SpecDomainError):
        canonical_resource_scope(bad, "scope")
    with pytest.raises(SpecDomainError):
        canonical_repo_path(bad, "path")


def test_repo_paths_and_resource_scopes_are_validated_separately() -> None:
    """One path-oriented helper for both is how the placeholder slipped through."""
    assert canonical_resource_scope("module.net.aws_security_group.web[0]") == \
        "module.net.aws_security_group.web[0]"
    assert canonical_repo_path("modules/s3/main.tf") == "modules/s3/main.tf"
    with pytest.raises(SpecDomainError):
        canonical_repo_path("modules/s3/", "path")  # a directory, not a file


def test_unicode_is_normalised_before_comparison() -> None:
    """Composed and decomposed forms must not be two different identities."""
    composed = canonical_identifier("caf\u00e9", "target_id")     # café
    decomposed = canonical_identifier("cafe\u0301", "target_id")  # cafe + combining acute
    assert composed == decomposed


def test_duplicate_detection_uses_normalised_identifiers() -> None:
    a = TargetDecision("caf\u00e9", Outcome.FIXED, SCOPE)
    b = TargetDecision("cafe\u0301", Outcome.FIXED, "aws_s3_bucket.other")
    with pytest.raises(SpecDomainError):
        RunObservation((a, b), **EVIDENCE)


# --------------------------------------------------------------------------- #
# required gate identities, not status counts
# --------------------------------------------------------------------------- #
def test_missing_required_gate_is_an_invalid_request() -> None:
    with pytest.raises(InvalidVerificationRequest) as exc:
        RunObservation((TargetDecision("T1", Outcome.FIXED, SCOPE),),
                       **{**EVIDENCE,
                          "required_gates": RequiredGates(("terraform_hcl_parse",
                                                           "kubeconform"))})
    assert "kubeconform" in str(exc.value)


def test_one_pass_cannot_satisfy_two_required_validators() -> None:
    with pytest.raises(InvalidVerificationRequest):
        RunObservation((TargetDecision("T1", Outcome.FIXED, SCOPE),),
                       **{**EVIDENCE,
                          "required_gates": RequiredGates(("a_parse", "b_parse")),
                          "validator_results": (GateResult("a_parse", Status.PASS),)})


def test_duplicate_gate_results_are_rejected() -> None:
    with pytest.raises(SpecDomainError):
        RunObservation((TargetDecision("T1", Outcome.FIXED, SCOPE),),
                       **{**EVIDENCE,
                          "validator_results": (
                              GateResult("terraform_hcl_parse", Status.PASS),
                              GateResult("terraform_hcl_parse", Status.PASS))})


def test_substituted_unknown_gate_cannot_stand_in() -> None:
    with pytest.raises(InvalidVerificationRequest) as exc:
        RunObservation((TargetDecision("T1", Outcome.FIXED, SCOPE),),
                       **{**EVIDENCE,
                          "validator_results": (GateResult("something_else",
                                                           Status.PASS),)})
    assert "something_else" in str(exc.value)


def test_duplicate_required_gate_ids_are_rejected() -> None:
    with pytest.raises(SpecDomainError):
        RequiredGates(("hcl_parse", "hcl_parse"))


def test_empty_oracle_results_are_valid_only_when_none_are_required() -> None:
    target = TargetDecision("T1", Outcome.FIXED, SCOPE)
    assert decide(RunObservation((target,), **EVIDENCE)) is Verdict.VERIFIED
    with pytest.raises(InvalidVerificationRequest):
        RunObservation((target,),
                       **{**EVIDENCE,
                          "required_gates": RequiredGates(("terraform_hcl_parse",),
                                                          ("bucket_oracle",))})


def test_required_gates_must_name_at_least_one_validator() -> None:
    with pytest.raises(InvalidVerificationRequest):
        RequiredGates(())


def test_gate_result_status_must_be_typed() -> None:
    with pytest.raises(SpecDomainError):
        GateResult("terraform_hcl_parse", "PASS")


def test_gate_ids_are_validated_identifiers() -> None:
    for bad in ("", "  ", "unknown", "a\nb"):
        with pytest.raises(SpecDomainError):
            GateResult(bad, Status.PASS)
