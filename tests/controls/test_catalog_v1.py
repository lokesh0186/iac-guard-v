from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_catalog", ROOT / "tools/check_catalog.py")
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def _catalog(tmp_path: Path, mutate) -> Path:
    data = yaml.safe_load((ROOT / "controls/catalog-v1.yml").read_text())
    mutate(data)
    target = tmp_path / "catalog.yml"
    target.write_text(yaml.safe_dump(data, sort_keys=False))
    return target


def test_catalog_is_valid_and_deliberately_has_no_exact_mapping() -> None:
    data = CHECKER.validate_catalog(ROOT / "controls/catalog-v1.yml")
    assert data["exact_mapping_count"] == 0
    assert {item["classification"] for item in data["relationships"]} == {"OVERLAPPING"}


def test_exact_mapping_without_independent_signoff_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["relationships"][0]["classification"] = "EXACT"
        data["relationships"][0]["exact_blockers"] = []
        data["exact_mapping_count"] = 1

    with pytest.raises(ValueError, match="independent sign-off"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_mutable_source_identity_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["scanner_locks"]["kics"]["source_commit"] = "main"

    with pytest.raises(ValueError, match="not immutable"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_unknown_relationship_class_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["relationships"][0]["classification"] = "SAME_ENOUGH"

    with pytest.raises(ValueError, match="classification"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_missing_boundary_fixture_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["relationships"][0]["fixtures"]["boundary"] = "controls/fixtures/absent.yml"

    with pytest.raises(ValueError, match="fixture"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))
