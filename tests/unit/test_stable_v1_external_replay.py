from __future__ import annotations

from pathlib import Path

from tools.compatibility.external_replay import CASES, replay_external_cases


ROOT = Path(__file__).resolve().parents[2]


def test_external_manifest_is_complete_and_replays_without_breakage() -> None:
    result = replay_external_cases(ROOT)
    assert result["case_total"] == 32
    assert result["counts"] == {
        "UNCHANGED": 32,
        "STRICTER_BUT_COMPATIBLE": 0,
        "BREAKING": 0,
        "NEWLY_UNSUPPORTED": 0,
        "BLOCKED_BY_EXTERNAL_DRIFT": 0,
    }, [item for item in result["records"] if item["classification"] != "UNCHANGED"]


def test_every_case_has_public_provenance_and_executable_or_archived_proof() -> None:
    assert len(CASES) == len({item.public_url for item in CASES})
    for case in CASES:
        assert case.public_url.startswith("https://github.com/")
        assert case.report_globs or case.semantic_tests
        assert case.evidence_paths


def test_every_replayed_case_binds_its_preserved_evidence_by_sha256() -> None:
    result = replay_external_cases(ROOT)
    for record in result["records"]:
        assert record["evidence_bindings"]
        assert all(binding["kind"] in {"file", "directory"} for binding in record["evidence_bindings"])
        assert all(len(binding["sha256"]) == 64 for binding in record["evidence_bindings"])
