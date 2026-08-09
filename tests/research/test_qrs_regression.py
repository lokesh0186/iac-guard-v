"""Research regression tests for the QRS 2026 freeze.

Two assertions that must never be conflated:

* Byte preservation  - the 4,842 frozen files are bit-identical, verified without
  any normalisation, by research/verify_byte_manifest.py.
* Semantic reproduction - the derived tables regenerate with equal content after a
  declared CRLF->LF canonicalisation, verified by
  research/replay_from_frozen_runs.py.

A third group builds a synthetic repository to prove the manifest verifier actually
fails on tampering, rather than trusting that it would. Those tests never touch the
real research data.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "research" / "qrs2026-byte-manifest.jsonl"
VERIFIER = REPO / "research" / "verify_byte_manifest.py"
BUILDER = REPO / "research" / "build_byte_manifest.py"
REPLAY = REPO / "research" / "replay_from_frozen_runs.py"

EXPECTED_ENTRIES = 4842
EXPECTED_RUNS = 630
EXPECTED_COMPARISONS = 10_080
DERIVED_TABLE_COUNT = 7


def run(*args: str, cwd: Path = REPO) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args], cwd=cwd, capture_output=True, text=True
    )


# --------------------------------------------------------------------------- #
# byte preservation
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def manifest_result() -> dict:
    proc = run(str(VERIFIER), "--manifest", str(MANIFEST), "--root", str(REPO),
               "--expect-entries", str(EXPECTED_ENTRIES), "--strict", "--json")
    assert proc.returncode in (0, 1), proc.stderr
    return json.loads(proc.stdout)


def test_frozen_files_are_byte_identical(manifest_result: dict) -> None:
    assert manifest_result["failures"] == []
    assert manifest_result["status"] == "PASS"


def test_frozen_file_count_is_exact(manifest_result: dict) -> None:
    assert manifest_result["files_checked"] == EXPECTED_ENTRIES


def test_manifest_root_matches(manifest_result: dict) -> None:
    assert manifest_result["manifest_root_computed"]
    assert manifest_result["manifest_root_computed"] == manifest_result["manifest_root_recorded"]


def test_manifest_holds_no_metadata_records() -> None:
    """entry_count must mean file count and nothing else."""
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip():
            assert set(json.loads(line)) == {
                "path", "git_mode", "git_blob_oid", "size_bytes", "sha256"
            }


def test_root_digest_lives_in_the_sidecar() -> None:
    sidecar = json.loads(
        MANIFEST.with_suffix(".root").read_text(encoding="utf-8")
    )
    assert sidecar["record_type"] == "manifest_root"
    assert sidecar["entry_count"] == EXPECTED_ENTRIES
    assert sidecar["normalisation"] == "none"
    assert sidecar["frozen_snapshot_commit"] == "7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5"


# --------------------------------------------------------------------------- #
# the verifier must actually fail on tampering (synthetic repo, no real data)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def synthetic_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "synthetic"
    (repo / "scripts").mkdir(parents=True)
    (repo / "runs").mkdir()
    (repo / "scripts" / "a.py").write_text("print('a')\n", encoding="utf-8")
    (repo / "runs" / "r.json").write_text('{"x": 1}\n', encoding="utf-8")
    (repo / "requirements.txt").write_text("checkov==3.2.517\n", encoding="utf-8")
    (repo / "README.md").write_text("mutable\n", encoding="utf-8")  # outside frozen scope
    for cmd in (
        ["git", "init", "-q"],
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"],
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "init"],
    ):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
    proc = run(str(BUILDER), "--root", str(repo), "--output-dir", str(repo / "research"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return repo


def verify_synthetic(repo: Path, entries: int = 3) -> dict:
    proc = run(str(VERIFIER), "--manifest",
               str(repo / "research" / "qrs2026-byte-manifest.jsonl"),
               "--root", str(repo), "--expect-entries", str(entries), "--strict", "--json")
    return json.loads(proc.stdout)


def test_synthetic_baseline_passes(synthetic_repo: Path) -> None:
    result = verify_synthetic(synthetic_repo)
    assert result["status"] == "PASS", result["failures"]
    assert result["files_checked"] == 3  # README.md is outside the frozen scope


def test_mutable_file_change_does_not_trip_the_freeze(synthetic_repo: Path) -> None:
    (synthetic_repo / "README.md").write_text("edited freely\n", encoding="utf-8")
    assert verify_synthetic(synthetic_repo)["status"] == "PASS"


@pytest.mark.parametrize(
    "mutate,expected_code",
    [
        (lambda r: (r / "scripts" / "a.py").write_text("print('tampered')\n"),
         "SHA256_CHANGED"),
        (lambda r: (r / "scripts" / "b.py").write_text("new file\n"),
         "ADDED_UNTRACKED_FILE_UNDER_FROZEN_PREFIX"),
        (lambda r: (r / "runs" / "r.json").unlink(),
         "MISSING_FILE"),
    ],
)
def test_tampering_is_detected(synthetic_repo: Path, mutate, expected_code: str) -> None:
    mutate(synthetic_repo)
    result = verify_synthetic(synthetic_repo)
    assert result["status"] == "FAIL"
    assert any(f.startswith(expected_code) for f in result["failures"]), result["failures"]


def test_symlink_replacement_is_detected(synthetic_repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.py"
    target.write_text("print('a')\n", encoding="utf-8")
    victim = synthetic_repo / "scripts" / "a.py"
    victim.unlink()
    victim.symlink_to(target)
    result = verify_synthetic(synthetic_repo)
    assert result["status"] == "FAIL"
    assert any(f.startswith("SYMLINK_APPEARED") for f in result["failures"])


def test_wrong_expected_count_is_detected(synthetic_repo: Path) -> None:
    result = verify_synthetic(synthetic_repo, entries=2)
    assert result["status"] == "FAIL"
    assert any(f.startswith("ENTRY_COUNT") for f in result["failures"])


# --------------------------------------------------------------------------- #
# semantic reproduction
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def replay_result() -> dict:
    proc = run(str(REPLAY), "--root", str(REPO), "--json")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_all_runs_reconstructs_exactly(replay_result: dict) -> None:
    rec = replay_result["reconstruction"]
    assert rec["run_files"] == EXPECTED_RUNS
    assert rec["committed_rows"] == EXPECTED_RUNS
    assert rec["comparisons"] == EXPECTED_COMPARISONS
    assert rec["equal"] == EXPECTED_COMPARISONS
    assert rec["mismatches"] == []
    assert rec["unmatched_runs"] == []
    assert rec["unmatched_rows"] == []


def test_frozen_verification_blobs_parse_without_eval(replay_result: dict) -> None:
    rec = replay_result["reconstruction"]
    assert rec["attempts_parsed"] > 0
    assert rec["attempt_parse_failures"] == []
    assert rec["verdict_consistency_failures"] == []


def test_replay_tooling_never_uses_eval() -> None:
    for script in (REPO / "research").glob("*.py"):
        source = script.read_text(encoding="utf-8")
        assert "eval(" not in source.replace("literal_eval(", ""), script.name


def test_derived_tables_reproduce_semantically(replay_result: dict) -> None:
    tables = replay_result["reproduction"]["tables"]
    assert len(tables) == DERIVED_TABLE_COUNT
    for name, info in tables.items():
        assert info["status"] == "SEMANTIC_MATCH", (name, info)


def test_semantic_match_is_not_claimed_as_byte_equality(replay_result: dict) -> None:
    """Regenerated CSVs legitimately differ in line endings; the report must say so."""
    tables = replay_result["reproduction"]["tables"]
    non_byte_identical = [n for n, i in tables.items() if not i["byte_identical"]]
    for name in non_byte_identical:
        assert tables[name]["eol_canonicalisation_applied"] is True, name
        assert tables[name]["status"] == "SEMANTIC_MATCH", name


def test_analysis_scripts_exit_cleanly(replay_result: dict) -> None:
    for script, info in replay_result["reproduction"]["script_runs"].items():
        assert info["returncode"] == 0, (script, info)


# --------------------------------------------------------------------------- #
# inference discipline
# --------------------------------------------------------------------------- #
def test_research_replay_tooling_makes_no_provider_calls() -> None:
    """NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V, enforced statically."""
    forbidden = ("boto3", "bedrock-runtime", "invoke_model", "openai", "anthropic")
    for script in (REPO / "research").glob("*.py"):
        source = script.read_text(encoding="utf-8").lower()
        for token in forbidden:
            assert token not in source, f"{script.name} references {token}"
