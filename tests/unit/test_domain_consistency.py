"""Domain-consistency probes for the four defects found after D1.

Each was independently reproduced against the production models:

  1  `f"{scanner}:{rule_id}@{scope}"` collided for two genuinely different targets, and
     exceptions bind to target identity, so one target's approval could authorise another;
  2  a `ScannerRun` claiming to be Checkov accepted a Trivy finding at version 9.9;
  3  two findings sharing an exact identity serialised in caller order, so equivalent
     input produced different canonical JSON;
  4  a custom `Mapping` returning `("EX-1", record EX-1)` from `items()` and
     `record DIFFERENT` from `values()` built a policy containing `DIFFERENT` — the key
     check proved nothing about what was consumed.
"""
from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from iac_guard_v.enums import (  # noqa: E402
    ExceptionOrigin,
    Outcome,
    Severity,
    Status,
)
from iac_guard_v.models import (  # noqa: E402
    DomainError,
    ExceptionPolicy,
    ExceptionRecord,
    Finding,
    FindingLocation,
    ScannerRun,
    Target,
    TargetDecision,
    TargetIdentity,
    coerce_exception_policy,
    permission_rejection_reason,
)
from iac_guard_v.normalisation import (  # noqa: E402
    assign_occurrence_indices,
    canonical_sort_key,
)

TODAY = date(2026, 8, 9)
SCOPE = "aws_s3_bucket.data"
LOC = FindingLocation("modules/s3/main.tf", 10, 14)


def record(target: TargetIdentity, permits=(Outcome.SUPPRESSED,),
           exception_id: str = "EX-1") -> ExceptionRecord:
    return ExceptionRecord(
        exception_id=exception_id, target=target, reason="accepted risk, TICKET-42",
        owner="platform-team", created=date(2026, 1, 1), expires=date(2026, 12, 31),
        origin=ExceptionOrigin.TRUSTED_BASE, permitted_outcomes=frozenset(permits),
    )


# --------------------------------------------------------------------------- #
# 1. structured target identity
# --------------------------------------------------------------------------- #
COLLISION_PAIRS = [
    (("checkov", "RULE@X", "scope"), ("checkov", "RULE", "X@scope")),
    (("foo:bar", "baz", "scope"), ("foo", "bar:baz", "scope")),
]


@pytest.mark.parametrize("first,second", COLLISION_PAIRS)
def test_previously_colliding_targets_are_structurally_distinct(first, second) -> None:
    a, b = TargetIdentity(*first), TargetIdentity(*second)
    assert a.display_ref == b.display_ref, "the display form is still ambiguous by design"
    assert a.canonical_key != b.canonical_key
    assert a != b
    assert a.opaque_id != b.opaque_id
    assert a.reference != b.reference


@pytest.mark.parametrize("first,second", COLLISION_PAIRS)
def test_an_exception_for_one_target_cannot_authorise_its_collision_partner(
    first, second
) -> None:
    """The reason this matters: authorisation binds identity."""
    approved, other = TargetIdentity(*first), TargetIdentity(*second)
    policy = ExceptionPolicy((record(approved, (Outcome.SUPPRESSED,)),))

    permitted = TargetDecision(approved, Outcome.SUPPRESSED, True, "EX-1")
    assert permission_rejection_reason(permitted, policy, TODAY) is None

    spoofed = TargetDecision(other, Outcome.SUPPRESSED, True, "EX-1")
    reason = permission_rejection_reason(spoofed, policy, TODAY)
    assert reason is not None and "binds a different target" in reason


def test_reference_round_trips_exactly() -> None:
    for identity in (TargetIdentity("checkov", "CKV_AWS_18", SCOPE),
                     TargetIdentity("checkov", "RULE@X", "scope"),
                     TargetIdentity("foo:bar", "baz", "a/b.c")):
        assert TargetIdentity.parse_reference(identity.reference) == identity


@pytest.mark.parametrize("scanner,rule,scope", [
    ("sc;anner", "rule", "scope.x"),
    ("scanner", "ru=le", "scope.x"),
    ("scanner", "ru%le", "scope.x"),
    ("scanner", "rule", "sc%3Bope.x"),
    ("s;=%", "r;=%", "a/b;=%.c"),
])
def test_reference_grammar_is_unambiguous_under_delimiter_characters(
    scanner, rule, scope
) -> None:
    """A value containing the delimiters must not be able to forge a field boundary."""
    identity = TargetIdentity(scanner, rule, scope)
    assert TargetIdentity.parse_reference(identity.reference) == identity
    assert identity.reference.count(";") == 2
    assert identity.reference.count("=") == 3


@pytest.mark.parametrize("bad", [
    "scanner=a;rule=b",                      # missing scope
    "scanner=a;rule=b;scope=c;extra=d",      # unknown field
    "scanner=a;rule=b;scope=c;scope=d",      # duplicate field
    "a;b;c",                                 # not name=value
    "",
])
def test_malformed_references_are_rejected(bad: str) -> None:
    with pytest.raises(DomainError):
        TargetIdentity.parse_reference(bad)


def test_display_reference_is_never_parsed_back() -> None:
    """Parsing the human form must not be possible, so it cannot be trusted."""
    identity = TargetIdentity("checkov", "RULE@X", "scope")
    with pytest.raises(DomainError):
        TargetIdentity.parse_reference(identity.display_ref)


def test_canonical_serialisation_retains_the_structured_fields() -> None:
    identity = TargetIdentity("checkov", "CKV_AWS_18", SCOPE)
    payload = identity.canonical_dict()
    assert payload["scanner"] == "checkov"
    assert payload["rule_id"] == "CKV_AWS_18"
    assert payload["scope"] == SCOPE
    assert payload["opaque_id"].startswith("tid1:")
    assert json.dumps(payload, sort_keys=True) == json.dumps(
        TargetIdentity("checkov", "CKV_AWS_18", SCOPE).canonical_dict(), sort_keys=True
    )


def test_opaque_id_is_versioned_and_length_prefixed() -> None:
    """Length prefixes mean a value cannot impersonate a field boundary."""
    a = TargetIdentity("ab", "c", "scope.x")
    b = TargetIdentity("a", "bc", "scope.x")
    assert a.opaque_id != b.opaque_id
    assert a.opaque_id.split(":", 1)[0] == "tid1"


def test_target_convenience_constructor_builds_a_structured_identity() -> None:
    target = Target.of("checkov", "CKV_AWS_18", SCOPE, 3)
    assert target.identity == TargetIdentity("checkov", "CKV_AWS_18", SCOPE)
    assert target.baseline_occurrences == 3
    assert target.scanner == "checkov" and target.rule_id == "CKV_AWS_18"


def test_target_decision_requires_a_structured_identity() -> None:
    with pytest.raises(DomainError):
        TargetDecision("checkov:CKV_AWS_18@aws_s3_bucket.data", Outcome.FIXED)


# --------------------------------------------------------------------------- #
# 2. scanner run provenance consistency
# --------------------------------------------------------------------------- #
def test_a_run_rejects_a_finding_from_another_scanner() -> None:
    foreign = Finding("trivy", "0.71.1", "AVD-AWS-0088", SCOPE, LOC)
    with pytest.raises(DomainError) as exc:
        ScannerRun("checkov", "0.71.1", Status.PASS, (foreign,))
    assert "cannot appear in a 'checkov' run" in str(exc.value)


def test_a_run_rejects_a_finding_from_another_version() -> None:
    older = Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, LOC)
    with pytest.raises(DomainError) as exc:
        ScannerRun("checkov", "3.3.0", Status.PASS, (older,))
    assert "version" in str(exc.value)


def test_matching_provenance_is_accepted_and_preserved() -> None:
    finding = Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, LOC)
    run = ScannerRun("checkov", "3.2.517", Status.PASS, (finding,))
    stored = run.findings[0]
    assert stored is not finding, "findings are reconstructed"
    assert stored.scanner == run.scanner == "checkov"
    assert stored.scanner_version == run.scanner_version == "3.2.517"


def test_provenance_is_not_silently_rewritten() -> None:
    """The contradiction is reported, not normalised away."""
    foreign = Finding("trivy", "0.71.1", "AVD-AWS-0088", SCOPE, LOC)
    with pytest.raises(DomainError):
        ScannerRun("checkov", "0.71.1", Status.PASS, (foreign,))
    assert foreign.scanner == "trivy", "the caller's finding must be untouched"


# --------------------------------------------------------------------------- #
# 3. duplicate exact identities and deterministic occurrence indices
# --------------------------------------------------------------------------- #
def _pair_sharing_an_exact_key() -> tuple[Finding, Finding]:
    one = Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, LOC, Severity.HIGH, 0,
                  message="one")
    two = Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, LOC, Severity.LOW, 0,
                  message="two")
    assert one.exact_key == two.exact_key
    return one, two


def test_dense_ordinals_do_not_manufacture_distinct_authoritative_identities() -> None:
    one, two = _pair_sharing_an_exact_key()
    run = ScannerRun("checkov", "3.2.517", Status.PASS, (one, two))
    assert len(run.findings) == 2
    assert len({item.exact_key for item in run.findings}) == 1


def test_repeated_findings_receive_stable_distinct_occurrence_indices() -> None:
    one, two = _pair_sharing_an_exact_key()
    indexed = assign_occurrence_indices((one, two))
    assert sorted(f.occurrence_index for f in indexed) == [0, 1]
    assert len({f.exact_key for f in indexed}) == 1
    assert len({f.occurrence_index for f in indexed}) == 2


def test_reversing_native_order_produces_identical_normalised_findings() -> None:
    one, two = _pair_sharing_an_exact_key()
    forward = assign_occurrence_indices((one, two))
    reverse = assign_occurrence_indices((two, one))
    assert forward == reverse
    assert (ScannerRun("checkov", "3.2.517", Status.PASS, forward).canonical_dict()
            == ScannerRun("checkov", "3.2.517", Status.PASS, reverse).canonical_dict())


def test_identical_findings_are_a_duplicate_not_a_second_occurrence() -> None:
    """Indexing two identical findings 0 and 1 would invent a finding."""
    finding = Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, LOC, message="same")
    twin = Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, LOC, message="same")
    assert canonical_sort_key(finding) == canonical_sort_key(twin)
    with pytest.raises(DomainError):
        assign_occurrence_indices((finding, twin))


def test_same_rule_on_different_resources_remains_valid() -> None:
    a = Finding("checkov", "3.2.517", "CKV_AWS_18", "aws_s3_bucket.a", LOC)
    b = Finding("checkov", "3.2.517", "CKV_AWS_18", "aws_s3_bucket.b", LOC)
    run = ScannerRun("checkov", "3.2.517", Status.PASS, (a, b))
    assert len(run.findings) == 2
    assert all(f.occurrence_index == 0 for f in run.findings)


def test_same_rule_and_resource_with_distinct_indices_remains_valid() -> None:
    a = Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE, LOC, occurrence_index=0)
    b = Finding("checkov", "3.2.517", "CKV_AWS_18", SCOPE,
                FindingLocation("modules/s3/main.tf", 30, 34), occurrence_index=1)
    run = ScannerRun("checkov", "3.2.517", Status.PASS, (a, b))
    assert [f.occurrence_index for f in run.findings] == [0, 1]


def test_occurrence_indices_are_per_resource_group() -> None:
    findings = [
        Finding("checkov", "3.2.517", "CKV_AWS_18", "aws_s3_bucket.a", LOC, message="a1"),
        Finding("checkov", "3.2.517", "CKV_AWS_18", "aws_s3_bucket.a", LOC, message="a2"),
        Finding("checkov", "3.2.517", "CKV_AWS_18", "aws_s3_bucket.b", LOC, message="b1"),
    ]
    indexed = assign_occurrence_indices(findings)
    by_resource: dict[str, list[int]] = {}
    for f in indexed:
        by_resource.setdefault(f.resource_address, []).append(f.occurrence_index)
    assert by_resource["aws_s3_bucket.a"] == [0, 1]
    assert by_resource["aws_s3_bucket.b"] == [0]


# --------------------------------------------------------------------------- #
# 4. Mapping time-of-check / time-of-use
# --------------------------------------------------------------------------- #
def _two_faced_mapping() -> Mapping:
    identity = TargetIdentity("checkov", "CKV_AWS_18", SCOPE)
    honest = record(identity, exception_id="EX-1")
    smuggled = record(identity, exception_id="DIFFERENT")

    class TwoFaced(Mapping):
        """items() agrees with the key; values() returns something else."""

        def items(self):
            return [("EX-1", honest)]

        def values(self):
            return [smuggled]

        def __getitem__(self, key):
            return honest

        def __iter__(self):
            return iter(["EX-1"])

        def __len__(self) -> int:
            return 1

    return TwoFaced()


def test_two_faced_mapping_is_rejected_by_the_policy_constructor() -> None:
    with pytest.raises(DomainError) as exc:
        ExceptionPolicy(_two_faced_mapping())
    assert "not an exact dict" in str(exc.value)


def test_two_faced_mapping_is_rejected_by_coercion() -> None:
    with pytest.raises(DomainError):
        coerce_exception_policy(_two_faced_mapping())


def test_no_policy_containing_the_smuggled_record_can_be_built() -> None:
    """The concrete failure: a policy containing 'DIFFERENT' must be impossible here."""
    try:
        policy = ExceptionPolicy(_two_faced_mapping())
    except DomainError:
        return
    pytest.fail(f"built a policy containing {[r.exception_id for r in policy.records]}")


@pytest.mark.parametrize("factory", [
    lambda rec: type("DictSub", (dict,), {})({"EX-1": rec}),
    lambda rec: type("Weird", (dict,), {"items": lambda self: []})({"EX-1": rec}),
])
def test_dict_subclasses_are_rejected(factory) -> None:
    rec = record(TargetIdentity("checkov", "CKV_AWS_18", SCOPE))
    with pytest.raises(DomainError):
        ExceptionPolicy(factory(rec))


def test_exact_dict_is_accepted_and_snapshotted() -> None:
    rec = record(TargetIdentity("checkov", "CKV_AWS_18", SCOPE))
    source = {"EX-1": rec}
    policy = ExceptionPolicy(source)
    source.clear()
    assert [r.exception_id for r in policy.records] == ["EX-1"]


def test_mapping_key_mismatch_is_still_caught_for_exact_dicts() -> None:
    identity = TargetIdentity("checkov", "CKV_AWS_18", SCOPE)
    with pytest.raises(DomainError) as exc:
        ExceptionPolicy({"EX-1": record(identity, exception_id="OTHER")})
    assert "does not match record id" in str(exc.value)
