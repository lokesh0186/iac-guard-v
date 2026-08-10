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
               "--tag", "qrs-2026-replication-v1",
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


def test_manifest_is_bound_to_the_freeze_tag() -> None:
    """The tag annotation must declare exactly one root, equal to the sidecar root."""
    import re

    sidecar = json.loads(MANIFEST.with_suffix(".root").read_text(encoding="utf-8"))
    annotation = subprocess.run(
        ["git", "-C", str(REPO), "cat-file", "tag", "qrs-2026-replication-v1"],
        capture_output=True, text=True, check=True,
    ).stdout
    # Whitespace-tolerant, matching the verifier: the message aligns its columns.
    roots = re.findall(r"MANIFEST_ROOT:\s*([0-9a-f]{64})", annotation)
    assert len(roots) == 1, f"expected exactly one MANIFEST_ROOT, found {len(roots)}"
    assert roots[0] == sidecar["manifest_root"]


def test_freeze_tag_message_points_at_the_right_place() -> None:
    """The tagged commit predates the verifier; the message must say so."""
    annotation = subprocess.run(
        ["git", "-C", str(REPO), "cat-file", "tag", "qrs-2026-replication-v1"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "NOT CONTAINED IN THIS SNAPSHOT" in annotation
    tagged_tree = subprocess.run(
        ["git", "-C", str(REPO), "ls-tree", "-r", "--name-only",
         "qrs-2026-replication-v1"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "research/verify_byte_manifest.py" not in tagged_tree


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
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    proc = run(str(BUILDER), "--root", str(repo), "--output-dir", str(repo / "research"),
               "--frozen-snapshot-commit", head)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return repo


def verify_synthetic(repo: Path, entries: int = 3) -> dict:
    proc = run(str(VERIFIER), "--manifest",
               str(repo / "research" / "qrs2026-byte-manifest.jsonl"),
               "--root", str(repo), "--allow-unbound",
               "--expect-entries", str(entries), "--strict", "--json")
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
         "UNLISTED_PHYSICAL_FILE_UNDER_FROZEN_PREFIX"),
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


def test_stored_verification_values_are_reported_accurately(replay_result: dict) -> None:
    """The counts must describe what the data actually contains."""
    rec = replay_result["reconstruction"]
    assert rec["attempts_total"] == 762
    assert rec["verification_dicts"] == 759
    assert rec["verification_repr_strings"] == 0, (
        "this artifact stores JSON objects; ast.literal_eval is not exercised"
    )
    assert rec["verification_missing"] == 3
    assert rec["verification_parse_failures"] == []
    assert rec["final_verdicts_checked"] == 627
    assert len(rec["final_verdicts_unavailable"]) == 3
    assert all(u["expected"] for u in rec["final_verdicts_unavailable"])
    assert all(u["final_attempt_error"] == "empty_extraction"
               for u in rec["final_verdicts_unavailable"])
    assert rec["final_verdict_mismatches"] == []
    assert rec["target_rule_inconsistencies"] == []


def test_replay_rejects_duplicate_and_missing_data(replay_result: dict) -> None:
    rec = replay_result["reconstruction"]
    assert rec["duplicate_csv_keys"] == []
    assert rec["duplicate_run_keys"] == []
    assert rec["missing_json_fields"] == []


def test_replay_workspace_excludes_build_artifacts(replay_result: dict) -> None:
    """The workspace copy must never carry ignored build artifacts.

    The previous assertion was `all(...) or excluded_artifacts`, which is satisfied by
    an empty list and by a non-empty one, so it proved nothing. This one inspects the
    copy method and asserts that no artifact-shaped path was copied.
    """
    rep = replay_result["reproduction"]
    assert rep["copy_method"] in ("git-ls-files", "filesystem-walk-with-exclusions")
    assert rep["copied_files"] > 600, rep["copied_files"]
    # Anything reported as excluded must genuinely look like a build artifact.
    for artifact in rep["excluded_artifacts"]:
        assert (
            "__pycache__" in artifact
            or artifact.endswith((".pyc", ".pyo"))
            or Path(artifact).name in {".DS_Store", ".pytest_cache"}
        ), artifact


def test_replay_workspace_copy_rejects_artifacts_that_exist(tmp_path: Path) -> None:
    """Directly exercise the copy logic with artifacts present.

    A `.pyc` is planted under `scripts/` in a synthetic tree, and the fallback
    filesystem walk must not copy it. This fails if the exclusion list is removed,
    which the previous test did not.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "replay_mod", REPO / "research" / "replay_from_frozen_runs.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    fake = tmp_path / "repo"
    (fake / "scripts" / "__pycache__").mkdir(parents=True)
    (fake / "runs" / "raw").mkdir(parents=True)
    (fake / "results" / "tables").mkdir(parents=True)
    (fake / "scripts" / "analyze_part1.py").write_text("print(1)\n", encoding="utf-8")
    (fake / "scripts" / "__pycache__" / "analyze_part1.cpython-311.pyc").write_bytes(b"x")
    (fake / "scripts" / "stray.pyo").write_bytes(b"x")
    (fake / "runs" / "raw" / ".DS_Store").write_bytes(b"x")
    (fake / "runs" / "raw" / "r1.json").write_text("{}\n", encoding="utf-8")
    (fake / "results" / "tables" / "all_runs.csv").write_text("a,b\n", encoding="utf-8")

    # No git in this tree, so the fallback walk is exercised.
    out = module.reproduce_tables(fake)
    assert out["copy_method"] == "filesystem-walk-with-exclusions"

    copied = out.get("copied_relative_paths", [])
    assert copied, "the copy path must report what it copied for this test to mean anything"
    offenders = [
        rel for rel in copied
        if "__pycache__" in rel or rel.endswith((".pyc", ".pyo"))
        or Path(rel).name == ".DS_Store"
    ]
    assert not offenders, f"build artifacts entered the replay workspace: {offenders}"
    assert "scripts/analyze_part1.py" in copied
    assert "runs/raw/r1.json" in copied


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
    """NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V, enforced statically.

    Checked by parsing imports rather than by substring search: a tool is allowed to
    mention a provider SDK by name (research/verify_reproduction_env.py asserts that
    boto3 is absent from the replay lock), but no research tool may import one or
    construct a client.
    """
    import ast

    forbidden_modules = {"boto3", "botocore", "openai", "anthropic", "google"}
    forbidden_calls = {"invoke_model", "invoke_model_with_response_stream", "converse"}

    scripts = list((REPO / "research").rglob("*.py"))
    assert scripts, "no research tooling found to check"

    for script in scripts:
        tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_module = alias.name.split(".")[0]
                    assert root_module not in forbidden_modules, (
                        f"{script.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                root_module = node.module.split(".")[0]
                assert root_module not in forbidden_modules, (
                    f"{script.name} imports from {node.module}"
                )
            elif isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                assert name not in forbidden_calls, (
                    f"{script.name} calls {name}()"
                )


def test_legacy_wrapper_is_quarantined() -> None:
    """The legacy profile must be unreachable from the product surface."""
    wrapper = REPO / "research" / "compat" / "legacy_verify.py"
    profile = REPO / "research" / "compat" / "qrs2026.yml"
    assert wrapper.is_file() and profile.is_file()

    source = wrapper.read_text(encoding="utf-8")
    assert "--acknowledge-legacy-non-production-semantics" in source
    assert "LEGACY_REPLAY_RESULT" in source
    # It must never be able to signal success to a CI gate.
    assert "return 0" not in source

    profile_text = profile.read_text(encoding="utf-8")
    for required in (
        "status: reproduction_only",
        "selectable_by_product_config: false",
        "selectable_by_github_action: false",
        "emits_production_verdict: false",
        "result_label: LEGACY_REPLAY_RESULT",
    ):
        assert required in profile_text, required


def test_legacy_wrapper_refuses_without_acknowledgement() -> None:
    artifact = REPO / "benchmark" / "raw" / "BM-0002.tf"
    baseline = REPO / "scanners" / "outputs" / "baseline" / "BM-0002_baseline.json"
    if not (artifact.is_file() and baseline.is_file()):
        pytest.skip("frozen fixture not present")
    proc = run(
        str(REPO / "research" / "compat" / "legacy_verify.py"),
        "--before", str(artifact), "--after", str(artifact),
        "--target-rule", "CKV_AWS_233", "--baseline", str(baseline),
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stderr
    assert proc.stdout.strip() == "", "banner must go to stderr so --json stays clean"


# --------------------------------------------------------------------------- #
# environment records: historical facts must stay separate from replay facts
# --------------------------------------------------------------------------- #
ORIGINAL = REPO / "research" / "ORIGINAL_EXPERIMENT_METADATA.json"
REPLAY_ENV = REPO / "research" / "VALIDATED_REPLAY_ENVIRONMENT.json"


def test_environment_records_verify() -> None:
    proc = run(str(REPO / "research" / "verify_reproduction_env.py"),
               "--original", str(ORIGINAL), "--replay", str(REPLAY_ENV),
               "--root", str(REPO), "--json")
    payload = json.loads(proc.stdout)
    assert payload["status"] == "PASS", payload["failures"]
    assert payload["evidenced_fields"] > 0
    assert payload["not_recorded_fields"] > 0


def test_historical_record_never_claims_host_environment() -> None:
    fields = json.loads(ORIGINAL.read_text(encoding="utf-8"))["fields"]
    for key in (
        "experiment_host_python_version",
        "experiment_host_os_and_architecture",
        "experiment_host_library_versions",
        "experiment_start_timestamp",
        "bedrock_request_ids",
    ):
        assert fields[key]["status"] == "not_recorded", key
        assert fields[key]["value"] is None, key


def test_replay_record_disclaims_being_the_original() -> None:
    replay = json.loads(REPLAY_ENV.read_text(encoding="utf-8"))
    assert "is_not" in replay
    assert replay["model_calls_made"] == 0
    assert replay["result"]["derived_tables_byte_identical"] == 0
    assert replay["inference_statement"] == "NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED"
