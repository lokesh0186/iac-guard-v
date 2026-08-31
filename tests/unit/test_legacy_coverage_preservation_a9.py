from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest

from iac_guard_v.api import _reconcile_acceptance_with_neutral_evidence
from iac_guard_v.config import (
    PublicAcceptanceProperty,
    PublicCandidateAcceptanceRequest,
)
from iac_guard_v.models import ArtifactKind
from iac_guard_v.models import DomainError
from iac_guard_v.report import (
    _iter_helm_dependency_artifacts,
    _require_sha,
    validate_report_payload,
)
from iac_guard_v.scanner_core import ScannerObservationResult


def test_legacy_report_sha_and_nested_dependency_guards_remain_covered() -> None:
    _require_sha("", "optional", allow_empty=True)
    _require_sha("f" * 64, "required")
    with pytest.raises(DomainError, match="canonical SHA-256"):
        _require_sha("bad", "required")
    nested = {"artifacts": [{"name": "child"}]}
    root = {"artifacts": [{"name": "parent", "dependencies": nested}]}
    assert [item["name"] for item in _iter_helm_dependency_artifacts(root)] == [
        "parent", "child"
    ]


def test_legacy_scanner_neutral_reconciliation_still_fails_closed() -> None:
    _reconcile_acceptance_with_neutral_evidence((), None)
    resource = SimpleNamespace(resource_address="r", file_path="f")
    property_ = SimpleNamespace(
        resource=resource, outcome="SATISFIED", rule_id="RULE"
    )
    evidence = SimpleNamespace(observations=(SimpleNamespace(
        target=SimpleNamespace(
            property_identity=SimpleNamespace(policy_id="RULE"),
            protected_resource_identity="r",
            file_path="f",
        ),
        result=ScannerObservationResult.FAIL,
    ),))
    with pytest.raises(DomainError, match="evidence disagree"):
        _reconcile_acceptance_with_neutral_evidence((property_,), evidence)


def test_legacy_public_report_schema_rejection_remains_covered() -> None:
    with pytest.raises(DomainError, match="contract violation"):
        validate_report_payload({})


def test_legacy_acceptance_input_guards_remain_covered(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="artifact_kind"):
        PublicAcceptanceProperty("RULE", "resource", artifact_kind="bad")  # type: ignore[arg-type]
    item = PublicAcceptanceProperty(
        "RULE", "resource", artifact_kind=ArtifactKind.TERRAFORM_HCL
    )
    with pytest.raises(DomainError, match="pathlib.Path"):
        PublicCandidateAcceptanceRequest("bad", (item,))  # type: ignore[arg-type]
    missing = tmp_path / "missing"
    with pytest.raises(DomainError, match="does not exist"):
        PublicCandidateAcceptanceRequest(missing, (item,))
    source = tmp_path / "source.txt"
    source.write_text("x", encoding="utf-8")
    with pytest.raises(DomainError, match="directory"):
        PublicCandidateAcceptanceRequest(source, (item,))
    with pytest.raises(DomainError, match="unique"):
        PublicCandidateAcceptanceRequest(tmp_path, (item, item))
