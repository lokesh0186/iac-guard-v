"""D5.6 complete validator and portable snapshot provenance."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import iac_guard_v.engine as ENGINE
import importlib.metadata
import pytest

from iac_guard_v.models import DomainError


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


def test_non_python_callable_behavior_is_still_bound() -> None:
    assert len(ENGINE._callable_behavior_digest(len)) == 64


def test_parser_distribution_must_exist_and_have_a_manifest(monkeypatch) -> None:
    def missing(_name):
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(importlib.metadata, "distribution", missing)
    with pytest.raises(DomainError, match="unavailable"):
        ENGINE._verified_parser_distribution_digest("missing")

    monkeypatch.setattr(
        importlib.metadata, "distribution", lambda _name: SimpleNamespace(files=None)
    )
    with pytest.raises(DomainError, match="no RECORD"):
        ENGINE._verified_parser_distribution_digest("manifestless")


class _RecordEntry:
    def __init__(self, relative: str, data: bytes, *, mode="sha256", size=True):
        self.relative = relative
        self.hash = SimpleNamespace(
            mode=mode,
            value=base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("="),
        )
        self.size = len(data) if size else None

    def __str__(self) -> str:
        return self.relative


class _FakeDistribution:
    def __init__(self, root: Path, entries):
        self.root = root
        self.files = entries

    def locate_file(self, entry):
        return self.root / entry.relative


def test_parser_distribution_rejects_record_mismatch_and_unsafe_types(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "parser.py"
    source.write_bytes(b"trusted")
    entry = _RecordEntry("parser.py", b"different")
    monkeypatch.setattr(
        importlib.metadata, "distribution", lambda _name: _FakeDistribution(tmp_path, [entry])
    )
    with pytest.raises(DomainError, match="hash mismatch"):
        ENGINE._verified_parser_distribution_digest("parser")

    source.unlink()
    source.mkdir()
    with pytest.raises(DomainError, match="unsafe file type"):
        ENGINE._verified_parser_distribution_digest("parser")


def test_parser_distribution_rejects_unhashed_and_unsupported_records(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "parser.py"
    source.write_bytes(b"trusted")
    entry = _RecordEntry("parser.py", b"trusted")
    entry.hash = None
    monkeypatch.setattr(
        importlib.metadata, "distribution", lambda _name: _FakeDistribution(tmp_path, [entry])
    )
    with pytest.raises(DomainError, match="lacks RECORD hash"):
        ENGINE._verified_parser_distribution_digest("parser")

    entry.hash = SimpleNamespace(mode="sha512", value="AA")
    with pytest.raises(DomainError, match="unsupported RECORD digest"):
        ENGINE._verified_parser_distribution_digest("parser")


def test_parser_distribution_rejects_missing_and_wrong_size_files(
    tmp_path: Path, monkeypatch
) -> None:
    entry = _RecordEntry("parser.py", b"trusted")
    monkeypatch.setattr(
        importlib.metadata, "distribution", lambda _name: _FakeDistribution(tmp_path, [entry])
    )
    with pytest.raises(DomainError, match="file is missing"):
        ENGINE._verified_parser_distribution_digest("parser")

    source = tmp_path / "parser.py"
    source.write_bytes(b"trusted")
    entry.size += 1
    with pytest.raises(DomainError, match="size mismatch"):
        ENGINE._verified_parser_distribution_digest("parser")
