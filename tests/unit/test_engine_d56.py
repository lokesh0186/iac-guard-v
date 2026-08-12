"""D5.6 complete validator and portable snapshot provenance."""
from __future__ import annotations

import json

import iac_guard_v.engine as ENGINE


def test_hcl2_behavior_mutation_changes_only_parser_dependency_identity(monkeypatch) -> None:
    before = ENGINE.production_gate_registry().implementations[0]
    monkeypatch.setattr(ENGINE.hcl2, "loads", lambda _value: {"resource": []})
    after = ENGINE.production_gate_registry().implementations[0]
    assert before.code_sha256 == after.code_sha256
    assert before.dependency_identity != after.dependency_identity
    assert before.schema_loader_contract_digest == after.schema_loader_contract_digest


def test_gate_records_separate_contract_build_dependency_and_loader_identity() -> None:
    record = ENGINE.production_gate_registry().implementations[0].canonical_dict()
    assert record["contract_version"] == record["version"] == "4"
    assert record["product_build_digest"] == record["code_sha256"]
    assert record["parser_dependency_digest"] == record["dependency_identity"]
    assert len(record["schema_loader_contract_digest"]) == 64


def test_absolute_symlink_target_is_private_but_still_bound() -> None:
    first = ENGINE.FilesystemArtifactEntry(
        "link", "SYMLINK", 0, None, "/Users/alice/private/project", False, False,
        "UNSAFE_SYMLINK_ENTRY",
    )
    second = ENGINE.FilesystemArtifactEntry(
        "link", "SYMLINK", 0, None, "/Users/alice/private/other", False, False,
        "UNSAFE_SYMLINK_ENTRY",
    )
    canonical = first.canonical_dict()
    encoded = json.dumps(canonical, sort_keys=True)
    assert "/Users/alice" not in encoded
    assert "symlink_target" not in canonical
    assert canonical["symlink_target_kind"] == "absolute"
    assert len(canonical["symlink_target_sha256"]) == 64
    assert first.canonical_dict() != second.canonical_dict()
