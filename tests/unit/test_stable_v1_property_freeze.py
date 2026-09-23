from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from iac_guard_v.models import DomainError
from iac_guard_v.native_properties.model import canonical_digest
from iac_guard_v.native_properties.stable_v1 import (
    STABLE_V1_FIXTURE_COVERAGE,
    STABLE_V1_PROPERTY_DIGESTS,
    STABLE_V1_PROPERTY_SURFACE_DIGEST,
    STABLE_V1_PUBLIC_CASES,
    stable_v1_property_record,
    stable_v1_property_surface,
    validate_stable_v1_property_surface,
)


ROOT = Path(__file__).resolve().parents[2]


def test_all_eighteen_beta1_properties_are_frozen_for_stable_v1() -> None:
    validate_stable_v1_property_surface()
    assert len(STABLE_V1_PROPERTY_DIGESTS) == 18
    assert canonical_digest(stable_v1_property_surface()) == STABLE_V1_PROPERTY_SURFACE_DIGEST


@pytest.mark.parametrize("property_id", sorted(STABLE_V1_PROPERTY_DIGESTS))
def test_each_property_has_executable_coverage_and_public_demand(property_id: str) -> None:
    assert all((ROOT / path).is_file() for path in STABLE_V1_FIXTURE_COVERAGE[property_id])
    assert STABLE_V1_PUBLIC_CASES[property_id].startswith("https://github.com/")
    assert canonical_digest(stable_v1_property_record(property_id)) == STABLE_V1_PROPERTY_DIGESTS[property_id]


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("property_version", "2"),
        ("artifact_class", "terraform_source"),
        ("subject_class", "changed_subject"),
        ("parameter_schema", {"type": "object"}),
        ("semantic_definition_digest", "0" * 64),
        ("semantic_binding", {"system": "changed", "version": "v1", "contract_digest": "0" * 64}),
        ("capabilities", {"can_satisfy": False}),
        ("witness_type", "changed_witness"),
    ),
)
def test_semantic_surface_mutations_cannot_match_the_freeze(field: str, replacement: object) -> None:
    property_id = "IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1"
    record = deepcopy(stable_v1_property_record(property_id))
    record[field] = replacement
    assert canonical_digest(record) != STABLE_V1_PROPERTY_DIGESTS[property_id]


def test_unknown_property_fails_closed() -> None:
    with pytest.raises(DomainError, match="unknown stable native property"):
        stable_v1_property_record("IACGV_UNKNOWN_V1")
