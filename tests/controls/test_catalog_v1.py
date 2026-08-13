from __future__ import annotations

import importlib.util
import hashlib
import json
import shutil
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

    with pytest.raises(ValueError, match="mechanically verified sign-off"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_mutable_source_identity_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["scanner_locks"]["kics"]["source_commit"] = "main"

    with pytest.raises(ValueError, match="reviewed lock"):
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


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("repository", "https://github.com/attacker/checkov", "not approved"),
        ("commit", "a" * 40, "not the release commit"),
        ("url", "https://example.invalid/unrelated", "not commit-pinned"),
        ("sha256", "b" * 64, "reviewed source"),
    ),
)
def test_forged_source_evidence_is_rejected(
    tmp_path: Path, field: str, value: str, message: str,
) -> None:
    def mutate(data):
        data["relationships"][0]["authoritative_sources"]["checkov"][field] = value

    with pytest.raises(ValueError, match=message):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_random_valid_looking_release_commit_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["scanner_locks"]["checkov"]["source_commit"] = "a" * 40
        data["scanner_locks"]["checkov"]["tag_ref_commit"] = "a" * 40

    with pytest.raises(ValueError, match="reviewed lock"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_runtime_evidence_digest_and_complete_matrix_are_required(
    tmp_path: Path, monkeypatch,
) -> None:
    source_root = ROOT
    copied_root = tmp_path / "root"
    (copied_root / "controls").mkdir(parents=True)
    shutil.copytree(source_root / "controls/fixtures", copied_root / "controls/fixtures")
    evidence = json.loads(
        (source_root / "controls/runtime-evidence-v1.json").read_text(encoding="utf-8")
    )
    evidence["records"].pop()
    payload = dict(evidence)
    payload.pop("evidence_root_sha256")
    evidence["evidence_root_sha256"] = CHECKER._canonical_sha(payload)
    runtime = copied_root / "controls/runtime-evidence-v1.json"
    runtime.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    catalog = yaml.safe_load(
        (source_root / "controls/catalog-v1.yml").read_text(encoding="utf-8")
    )
    catalog["runtime_evidence"]["sha256"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
    path = copied_root / "controls/catalog-v1.yml"
    path.write_text(yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(CHECKER, "ROOT", copied_root)
    with pytest.raises(ValueError, match="does not cover every"):
        CHECKER.validate_catalog(path)


def test_runtime_evidence_outer_digest_is_enforced(tmp_path: Path) -> None:
    def mutate(data):
        data["runtime_evidence"]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="file digest"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))
