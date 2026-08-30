"""Frozen-a8 Helm dependency constraint compatibility and abuse tests."""
from __future__ import annotations

import pytest

import iac_guard_v.helm as H
import iac_guard_v.helm_semver as S


@pytest.mark.parametrize(
    ("constraint", "resolved", "expected"),
    (
        ("2.18.0", "2.18.0", True),
        ("2.x.x", "2.18.0", True),
        ("1.x.x", "2.18.0", False),
        ("2.X", "2.18.0", True),
        ("2.*", "2.18.0", True),
        ("*", "2.18.0", True),
        (">= 2.0.0, < 3.0.0", "2.18.0", True),
        (">= 2.0.0 < 3.0.0", "2.18.0", True),
        (">2.18", "2.18.99", False),
        (">2.18", "2.19.0", True),
        ("<=2.18.x", "2.18.99", True),
        ("<=2.18.x", "2.19.0", False),
        ("~2.18.0", "2.18.7", True),
        ("~2.18.0", "2.19.0", False),
        ("^2.0.0", "2.18.0", True),
        ("^2.0.0", "3.0.0", False),
        ("^0.2.3", "0.2.9", True),
        ("^0.2.3", "0.3.0", False),
        ("^0.0.3", "0.0.3", True),
        ("^0.0.3", "0.0.4", False),
        ("2.0 - 2.18.0", "2.18.0", True),
        ("2.0 - 2.18.0", "2.18.1", False),
        ("1.x || 2.x", "2.18.0", True),
        ("!=2.17.0", "2.18.0", True),
        ("!=2.x", "2.18.0", False),
        (">=2.0.0 <3.0.0", "2.18.0-beta.1", False),
        (">=2.0.0-0 <3.0.0", "2.18.0-beta.1", True),
        ("2.18.0", "2.18.0+build.7", True),
        ("2.18.0+other", "2.18.0+build.7", True),
    ),
)
def test_masterminds_3_5_0_compatibility_matrix(
    constraint: str, resolved: str, expected: bool,
) -> None:
    proof = S.prove_constraint(constraint, resolved)
    assert proof["satisfied"] is expected
    assert proof["constraint_engine"] == "github.com/Masterminds/semver/v3"
    assert proof["constraint_engine_version"] == "3.5.0"
    assert proof["constraint_engine_identity"] == S.ENGINE_IDENTITY


@pytest.mark.parametrize(
    ("constraint", "reason"),
    (
        ("", "MALFORMED_CONSTRAINT"),
        (">=>2.0.0", "MALFORMED_CONSTRAINT"),
        ("2.x.1", "UNSUPPORTED_CONSTRAINT"),
        ("x.2.3", "UNSUPPORTED_CONSTRAINT"),
        ("2.18.0 ||", "MALFORMED_CONSTRAINT"),
        ("2.18.0,,3.0.0", "MALFORMED_CONSTRAINT"),
        ("２.x.x", "MALFORMED_CONSTRAINT"),
        ("2.18.0\u00a0|| 3.x", "MALFORMED_CONSTRAINT"),
        ("0" * (S.MAX_CONSTRAINT_BYTES + 1), "RESOURCE_LIMIT"),
    ),
)
def test_constraint_parser_fails_closed(constraint: str, reason: str) -> None:
    with pytest.raises(S.HelmSemverError) as caught:
        S.prove_constraint(constraint, "2.18.0")
    assert caught.value.reason == reason


@pytest.mark.parametrize(
    "resolved",
    (
        "", "2.18", "v2.18.0", "02.18.0", "2.018.0", "2.18.00",
        "2.18.0-01", "2.18.0+", "２.18.0",
    ),
)
def test_resolved_identity_requires_strict_semver(resolved: str) -> None:
    with pytest.raises(S.HelmSemverError) as caught:
        S.prove_constraint("2.x.x", resolved)
    assert caught.value.reason in {
        "MALFORMED_RESOLVED_VERSION", "UNSUPPORTED_COERCION"
    }


def test_non_string_inputs_and_resource_limits_fail_closed() -> None:
    for constraint in (None, 2, [], {}):
        with pytest.raises(S.HelmSemverError, match="constraint is empty"):
            S.prove_constraint(constraint, "2.18.0")  # type: ignore[arg-type]
    for resolved in (None, 2, [], {}):
        with pytest.raises(S.HelmSemverError, match="resolved version is empty"):
            S.prove_constraint("2.x.x", resolved)  # type: ignore[arg-type]
    huge = "2.18.0+" + "a" * S.MAX_VERSION_BYTES
    with pytest.raises(S.HelmSemverError) as caught:
        S.prove_constraint("2.x.x", huge)
    assert caught.value.reason == "RESOURCE_LIMIT"
    groups = " || ".join("2.x" for _ in range(S.MAX_CONSTRAINT_GROUPS + 1))
    with pytest.raises(S.HelmSemverError) as caught:
        S.prove_constraint(groups, "2.18.0")
    assert caught.value.reason in {"RESOURCE_LIMIT"}


def test_dependency_wrapper_uses_typed_fail_closed_reasons() -> None:
    with pytest.raises(H.HelmMaterializationError) as mismatch:
        H._dependency_version_proof("1.x.x", "2.18.0")
    assert mismatch.value.reason_code == (
        "HELM_DEPENDENCY_VERSION_CONSTRAINT_MISMATCH"
    )
    with pytest.raises(H.HelmMaterializationError) as malformed:
        H._dependency_version_proof(">=>2.0.0", "2.18.0")
    assert malformed.value.reason_code == (
        "HELM_DEPENDENCY_VERSION_CONSTRAINT_UNSUPPORTED"
    )
    with pytest.raises(H.HelmMaterializationError) as resolved:
        H._dependency_version_proof("2.x.x", "version-two")
    assert resolved.value.reason_code == "HELM_DEPENDENCY_RESOLVED_VERSION_INVALID"


def test_constraint_evidence_preserves_original_whitespace_and_semantics() -> None:
    proof = S.prove_constraint("  >= 2.0.0,   < 3.0.0  ", "2.18.0")
    assert proof["declared_constraint"] == "  >= 2.0.0,   < 3.0.0  "
    assert proof["satisfied"] is True
    assert proof["parsed_constraint_semantic_identity"] == S._canonical_sha(
        proof["constraint_ast"]
    )
