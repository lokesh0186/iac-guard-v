"""Immutability and aliasing matrix for every persistent domain class.

Applied to both the specification reference model and the production models, because the
production model must not inherit the weaknesses the reference model had.

Each probe corresponds to a behaviour that was independently reproduced:

  A  `RunObservation.__dict__["policy_drift"] = True`        flipped a stored verdict
  B  `ExceptionRecord.__dict__["scope"] = ...`               flipped a stored verdict
  C  `TargetObservation.__dict__["candidate_matches"] = -1`  produced FIXED from an
                                                             impossible state
  D  `FindingLocation.__dict__["start_line"] = -100`         kept an invalid object
  E  mutating a source `ExceptionRecord`                     changed a run, because the
                                                             policy was rebuilt but its
                                                             records were aliased
  F  a `tuple` subclass with a mutable `__iter__`            changed a stored verdict
  G  a `TargetDecision` subclass reporting FIXED while
     storing STILL_PRESENT                                   reached VERIFIED
  H  an `ExceptionRecord` subclass                           was accepted by isinstance
  I  tuple/list/mapping subclasses                           stayed aliased
  J  equivalent input in a different order                    serialised differently

Out of scope, deliberately: trusted code calling `object.__setattr__` on a frozen
instance. That is what the constructor itself does, so it cannot be distinguished.
"""
from __future__ import annotations

import dataclasses
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

SPEC_EVIDENCE = dict(
    evaluation_date=TODAY,
    preflight=SPEC.Status.PASS,
    required_scanner_integrity=SPEC.Status.PASS,
    required_gates=SPEC.RequiredGates(("terraform_hcl_parse",)),
    validator_results=(SPEC.GateResult("terraform_hcl_parse", SPEC.Status.PASS),),
    regression_policy=SPEC.Status.PASS,
    suppression_policy=SPEC.Status.PASS,
)


def spec_record(**overrides) -> SPEC.ExceptionRecord:
    base = dict(exception_id="EX-1", target_id="T1", scope=SCOPE,
                reason="accepted risk, TICKET-42", owner="platform-team",
                created=date(2026, 1, 1), expires=date(2026, 12, 31),
                origin=SPEC.ExceptionOrigin.TRUSTED_BASE,
                permitted_outcomes=frozenset({SPEC.Outcome.RESOURCE_DELETED}))
    return SPEC.ExceptionRecord(**{**base, **overrides})


def prod_record(**overrides) -> PMODELS.ExceptionRecord:
    base = dict(exception_id="EX-1", target_id="T1", scope=SCOPE,
                reason="accepted risk, TICKET-42", owner="platform-team",
                created=date(2026, 1, 1), expires=date(2026, 12, 31),
                origin=PENUMS.ExceptionOrigin.TRUSTED_BASE,
                permitted_outcomes=frozenset({PENUMS.Outcome.RESOURCE_DELETED}))
    return PMODELS.ExceptionRecord(**{**base, **overrides})


def permitted_deletion() -> SPEC.TargetDecision:
    return SPEC.TargetDecision("T1", SPEC.Outcome.RESOURCE_DELETED, SCOPE, True, "EX-1")


ALL_CLASSES = [
    *[(SPEC, cls) for cls in SPEC.PERSISTENT_DOMAIN_CLASSES],
    *[(PMODELS, cls) for cls in PMODELS.PERSISTENT_MODELS],
]
CLASS_IDS = [f"{mod.__name__.split('.')[-1]}.{cls.__name__}" for mod, cls in ALL_CLASSES]


# --------------------------------------------------------------------------- #
# structural matrix: frozen, slotted, no __dict__
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("module,cls", ALL_CLASSES, ids=CLASS_IDS)
def test_every_persistent_class_is_a_frozen_slotted_dataclass(module, cls) -> None:
    assert dataclasses.is_dataclass(cls), f"{cls.__name__} must be a dataclass"
    assert cls.__dataclass_params__.frozen is True, f"{cls.__name__} must be frozen"
    assert "__slots__" in cls.__dict__, f"{cls.__name__} must declare __slots__"
    assert "__dict__" not in cls.__dict__, f"{cls.__name__} must not carry a __dict__"


def _instances() -> list[tuple[str, object]]:
    loc = PMODELS.FindingLocation("modules/s3/main.tf", 10, 14)
    finding = PMODELS.Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, loc)
    return [
        ("spec.TargetObservation",
         SPEC.TargetObservation(baseline_occurrences=1, candidate_matches=0)),
        ("spec.ExceptionRecord", spec_record()),
        ("spec.ExceptionPolicy", SPEC.ExceptionPolicy((spec_record(),))),
        ("spec.TargetDecision", SPEC.TargetDecision("T1", SPEC.Outcome.FIXED, SCOPE)),
        ("spec.FindingLocation", SPEC.FindingLocation("main.tf", 1, 2)),
        ("spec.GateResult", SPEC.GateResult("g", SPEC.Status.PASS)),
        ("spec.RequiredGates", SPEC.RequiredGates(("g",))),
        ("spec.RunObservation",
         SPEC.RunObservation((permitted_deletion(),), exceptions=(spec_record(),),
                             **SPEC_EVIDENCE)),
        ("prod.FindingLocation", loc),
        ("prod.Finding", finding),
        ("prod.CoverageCounters", PMODELS.CoverageCounters(3, 3, 3)),
        ("prod.ScannerRun",
         PMODELS.ScannerRun("checkov", "3.2.517", PENUMS.Status.PASS, (finding,))),
        ("prod.GateResult", PMODELS.GateResult("g", PENUMS.Status.PASS)),
        ("prod.RequiredGates", PMODELS.RequiredGates(("g",))),
        ("prod.ExceptionRecord", prod_record()),
        ("prod.ExceptionPolicy", PMODELS.ExceptionPolicy((prod_record(),))),
        ("prod.Target", PMODELS.Target("checkov", "CKV_AWS_18", SCOPE)),
        ("prod.TargetDecision",
         PMODELS.TargetDecision("T1", PENUMS.Outcome.FIXED, SCOPE)),
    ]


@pytest.mark.parametrize("label,instance", _instances(), ids=[n for n, _ in _instances()])
def test_no_instance_exposes_a_dict(label: str, instance: object) -> None:
    """Probes A-D: with no __dict__ there is nothing to write through."""
    assert not hasattr(instance, "__dict__"), f"{label} exposes __dict__"


@pytest.mark.parametrize("label,instance", _instances(), ids=[n for n, _ in _instances()])
def test_no_instance_accepts_attribute_assignment(label: str, instance: object) -> None:
    first_field = dataclasses.fields(instance)[0].name
    original = getattr(instance, first_field)
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError, TypeError)):
        setattr(instance, first_field, None)
    assert getattr(instance, first_field) == original, "assignment must not take effect"


@pytest.mark.parametrize("label,instance", _instances(), ids=[n for n, _ in _instances()])
def test_no_instance_accepts_new_attributes(label: str, instance: object) -> None:
    """The guarantee is that assignment does not succeed, not which error is raised.

    A frozen dataclass with `slots=True` is recreated by `dataclasses`, so the generated
    `__setattr__` closure references the pre-slots class. Assigning an *undeclared*
    attribute therefore surfaces as `TypeError` from `super().__setattr__` rather than
    `FrozenInstanceError`. Either way there is no slot and no `__dict__`, so nothing is
    stored — which is what the test asserts.
    """
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError, TypeError)):
        setattr(instance, "injected_attribute", "x")
    assert not hasattr(instance, "injected_attribute")


# --------------------------------------------------------------------------- #
# A-D: the exact mutations that previously worked
# --------------------------------------------------------------------------- #
def test_probe_a_run_dict_mutation_is_unavailable() -> None:
    run = SPEC.RunObservation((permitted_deletion(),), exceptions=(spec_record(),),
                              **SPEC_EVIDENCE)
    before = SPEC.decide(run)
    with pytest.raises(AttributeError):
        run.__dict__["policy_drift"] = True  # type: ignore[attr-defined]
    assert SPEC.decide(run) is before is SPEC.Verdict.VERIFIED


def test_probe_b_exception_record_dict_mutation_is_unavailable() -> None:
    with pytest.raises(AttributeError):
        spec_record().__dict__["scope"] = "other.scope"  # type: ignore[attr-defined]


def test_probe_c_target_observation_dict_mutation_is_unavailable() -> None:
    obs = SPEC.TargetObservation(baseline_occurrences=1, candidate_matches=0)
    with pytest.raises(AttributeError):
        obs.__dict__["candidate_matches"] = -1  # type: ignore[attr-defined]
    assert SPEC.classify(obs) is SPEC.Outcome.FIXED
    assert obs.candidate_matches == 0


def test_probe_d_finding_location_dict_mutation_is_unavailable() -> None:
    loc = SPEC.FindingLocation("main.tf", 10, 14)
    with pytest.raises(AttributeError):
        loc.__dict__["start_line"] = -100  # type: ignore[attr-defined]
    assert loc.start_line == 10


# --------------------------------------------------------------------------- #
# E: nested records are reconstructed, not aliased
# --------------------------------------------------------------------------- #
def test_probe_e_stored_record_is_not_the_source_object() -> None:
    source = spec_record()
    run = SPEC.RunObservation((permitted_deletion(),),
                              exceptions=SPEC.ExceptionPolicy((source,)), **SPEC_EVIDENCE)
    stored = run.exceptions.records[0]
    assert stored is not source, "the policy must deep-copy its records"
    assert stored == source
    assert SPEC.decide(run) is SPEC.Verdict.VERIFIED


def test_probe_e_production_policy_also_deep_copies() -> None:
    source = prod_record()
    policy = PMODELS.ExceptionPolicy((source,))
    assert policy.records[0] is not source
    assert policy.records[0] == source


def test_probe_e_findings_are_reconstructed_in_scanner_runs() -> None:
    loc = PMODELS.FindingLocation("main.tf", 1, 2)
    finding = PMODELS.Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, loc)
    run = PMODELS.ScannerRun("checkov", "3.2.517", PENUMS.Status.PASS, [finding])
    assert run.findings[0] is not finding
    assert run.findings[0] == finding
    assert type(run.findings) is tuple


# --------------------------------------------------------------------------- #
# F, I: caller-owned collections are never retained
# --------------------------------------------------------------------------- #
def test_probe_f_mutable_tuple_subclass_cannot_change_a_verdict() -> None:
    class ShiftyTuple(tuple):
        swap = False

        def __iter__(self):
            if ShiftyTuple.swap:
                return iter((SPEC.TargetDecision("T1", SPEC.Outcome.STILL_PRESENT,
                                                 SCOPE),))
            return super().__iter__()

    source = ShiftyTuple((SPEC.TargetDecision("T1", SPEC.Outcome.FIXED, SCOPE),))
    run = SPEC.RunObservation(source, **SPEC_EVIDENCE)
    before = SPEC.decide(run)
    ShiftyTuple.swap = True
    try:
        assert SPEC.decide(run) is before is SPEC.Verdict.VERIFIED
        assert type(run.target_decisions) is tuple, "must store an exact built-in tuple"
    finally:
        ShiftyTuple.swap = False


def test_probe_i_collection_subclasses_are_not_retained() -> None:
    class MyList(list):
        pass

    class MyDict(dict):
        pass

    run = SPEC.RunObservation(MyList([SPEC.TargetDecision("T1", SPEC.Outcome.FIXED,
                                                          SCOPE)]),
                              exceptions=MyDict({"EX-1": spec_record()}), **SPEC_EVIDENCE)
    assert type(run.target_decisions) is tuple
    assert type(run.exceptions) is SPEC.ExceptionPolicy
    assert type(run.exceptions.records) is tuple


def test_probe_f_source_sequence_mutation_cannot_change_a_verdict() -> None:
    source = [SPEC.TargetDecision("T1", SPEC.Outcome.FIXED, SCOPE)]
    run = SPEC.RunObservation(source, **SPEC_EVIDENCE)
    before = SPEC.decide(run)
    source.clear()
    source.append(SPEC.TargetDecision("T9", SPEC.Outcome.STILL_PRESENT, SCOPE))
    assert SPEC.decide(run) is before is SPEC.Verdict.VERIFIED


# --------------------------------------------------------------------------- #
# G, H: subclasses rejected at security boundaries
# --------------------------------------------------------------------------- #
def test_probe_g_target_decision_subclass_is_rejected() -> None:
    class SneakyTarget(SPEC.TargetDecision):
        __slots__ = ()

        @property
        def canonical_key(self):  # pretends to be a different, benign target
            return ("T1", SCOPE, "FIXED", "")

    sneaky = SneakyTarget("T1", SPEC.Outcome.STILL_PRESENT, SCOPE)
    assert sneaky.outcome is SPEC.Outcome.STILL_PRESENT
    with pytest.raises(SPEC.SpecDomainError):
        SPEC.RunObservation((sneaky,), **SPEC_EVIDENCE)
    with pytest.raises(SPEC.SpecDomainError):
        SPEC.rebuild_target_decision(sneaky)


def test_probe_h_exception_record_subclass_is_rejected() -> None:
    class SneakyRecord(SPEC.ExceptionRecord):
        __slots__ = ()

    sneaky = SneakyRecord(
        exception_id="EX-1", target_id="T1", scope=SCOPE, reason="r",
        owner="o", created=date(2026, 1, 1), expires=date(2026, 12, 31),
        origin=SPEC.ExceptionOrigin.TRUSTED_BASE,
        permitted_outcomes=frozenset({SPEC.Outcome.RESOURCE_DELETED}),
    )
    with pytest.raises(SPEC.SpecDomainError):
        SPEC.ExceptionPolicy((sneaky,))
    with pytest.raises(SPEC.SpecDomainError):
        SPEC.rebuild_exception_record(sneaky)


@pytest.mark.parametrize("factory", [
    lambda: type("P", (SPEC.ExceptionPolicy,), {"__slots__": ()})(()),
    lambda: type("G", (SPEC.GateResult,), {"__slots__": ()})("g", SPEC.Status.PASS),
    lambda: type("R", (SPEC.RequiredGates,), {"__slots__": ()})(("g",)),
])
def test_other_domain_subclasses_are_rejected(factory) -> None:
    sub = factory()
    decision = SPEC.TargetDecision("T1", SPEC.Outcome.FIXED, SCOPE)
    kwargs = dict(SPEC_EVIDENCE)
    if type(sub).__bases__[0] is SPEC.ExceptionPolicy:
        kwargs["exceptions"] = sub
    elif type(sub).__bases__[0] is SPEC.GateResult:
        kwargs["validator_results"] = (sub,)
    else:
        kwargs["required_gates"] = sub
    with pytest.raises(SPEC.SpecDomainError):
        SPEC.RunObservation((decision,), **kwargs)


def test_production_boundaries_also_reject_subclasses() -> None:
    class SneakyProdDecision(PMODELS.TargetDecision):
        __slots__ = ()

    sneaky = SneakyProdDecision("T1", PENUMS.Outcome.FIXED, SCOPE)
    with pytest.raises(PMODELS.DomainError):
        PMODELS.rebuild_target_decision(sneaky)

    class SneakyProdPolicy(PMODELS.ExceptionPolicy):
        __slots__ = ()

    with pytest.raises(PMODELS.DomainError):
        PMODELS.coerce_exception_policy(SneakyProdPolicy(()))


# --------------------------------------------------------------------------- #
# J: canonical ordering and deterministic serialisation
# --------------------------------------------------------------------------- #
def test_probe_j_input_order_does_not_change_serialisation() -> None:
    a = SPEC.TargetDecision("T-a", SPEC.Outcome.FIXED, "aws_s3_bucket.a")
    b = SPEC.TargetDecision("T-b", SPEC.Outcome.FIXED, "aws_s3_bucket.b")
    c = SPEC.TargetDecision("T-c", SPEC.Outcome.FIXED, "aws_s3_bucket.c")
    forward = SPEC.RunObservation((a, b, c), **SPEC_EVIDENCE)
    reverse = SPEC.RunObservation((c, b, a), **SPEC_EVIDENCE)
    assert forward.canonical_dict() == reverse.canonical_dict()
    assert SPEC.decide(forward) is SPEC.decide(reverse)


def test_probe_j_exception_order_does_not_change_serialisation() -> None:
    r1 = spec_record(exception_id="EX-1")
    r2 = spec_record(exception_id="EX-2")
    assert (SPEC.ExceptionPolicy((r1, r2)).canonical_list()
            == SPEC.ExceptionPolicy((r2, r1)).canonical_list())


def test_probe_j_production_findings_sort_canonically() -> None:
    loc1 = PMODELS.FindingLocation("a.tf", 1, 2)
    loc2 = PMODELS.FindingLocation("b.tf", 1, 2)
    f1 = PMODELS.Finding("checkov", "3.2.517", "CKV_AWS_18", "aws_s3_bucket.a", loc1)
    f2 = PMODELS.Finding("checkov", "3.2.517", "CKV_AWS_19", "aws_s3_bucket.b", loc2)
    forward = PMODELS.ScannerRun("checkov", "3.2.517", PENUMS.Status.PASS, (f1, f2))
    reverse = PMODELS.ScannerRun("checkov", "3.2.517", PENUMS.Status.PASS, (f2, f1))
    assert forward.canonical_dict() == reverse.canonical_dict()


def test_permitted_outcomes_serialise_deterministically() -> None:
    both = frozenset({SPEC.Outcome.SUPPRESSED, SPEC.Outcome.RESOURCE_DELETED})
    record = spec_record(permitted_outcomes=both)
    assert record.canonical_dict()["permitted_outcomes"] == [
        "RESOURCE_DELETED", "SUPPRESSED"
    ]


# --------------------------------------------------------------------------- #
# production statuses stay typed
# --------------------------------------------------------------------------- #
def test_production_scanner_run_keeps_the_full_status() -> None:
    for status in PENUMS.Status:
        run = PMODELS.ScannerRun("checkov", "3.2.517", status)
        assert run.status is status
        assert run.canonical_dict()["status"] == status.value


def test_production_models_declare_no_provider_dependency() -> None:
    """The core stays model-agnostic and offline-capable."""
    source = (REPO / "src" / "iac_guard_v" / "models.py").read_text(encoding="utf-8")
    for token in ("boto3", "bedrock", "openai", "anthropic", "requests", "urllib.request"):
        assert token not in source, f"models.py references {token}"
