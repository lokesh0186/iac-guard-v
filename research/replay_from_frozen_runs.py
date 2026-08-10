#!/usr/bin/env python3
"""Reconstruct the QRS 2026 results from frozen artifacts, with no model calls.

Two independent things are checked, and they are deliberately not the same check:

1. RECONSTRUCTION (exact, field by field)
   `results/tables/all_runs.csv` has no regeneration path in the repository — it is
   written only by the Bedrock-dependent experiment runner. This script rebuilds it
   from the 630 frozen `runs/raw/*.json` records and compares every cell as text.
   Expected: 630 rows x 16 columns = 10,080 comparisons, all equal.

2. SEMANTIC REPRODUCTION (canonicalised)
   The three frozen analysis scripts are re-run in a throwaway tree and their seven
   derived tables are compared against the committed ones after a declared
   canonicalisation: CRLF -> LF and exactly one trailing newline. Python's csv writer
   emits CRLF while git stores LF under `* text=auto`, so a byte comparison here
   would fail for a reason that has nothing to do with research correctness.

   The result is reported as SEMANTIC_MATCH or SEMANTIC_DIFF, never as byte equality.
   Byte equality is the separate job of `research/verify_byte_manifest.py`.

Reporting honesty note: an earlier revision reported "759 attempt blobs parsed via
ast.literal_eval". That was wrong on both counts. In this artifact every stored
`verification` value is already a JSON object; none is a Python repr string, so
`ast.literal_eval` is a compatibility path that is **not exercised** by this data.
The counts below are reported separately so the claim matches what happened.

Usage:
    python research/replay_from_frozen_runs.py --check
    python research/replay_from_frozen_runs.py --check --json
"""
from __future__ import annotations

import argparse
import ast
import csv
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

RUNS_SUBDIR = Path("runs/raw")
ALL_RUNS = Path("results/tables/all_runs.csv")
ANALYSIS_SCRIPTS = ("analyze_part1.py", "analyze_part2.py", "analyze_part3.py")

DERIVED_TABLES = (
    "main_results_with_ci.csv",
    "results_by_violation_class.csv",
    "cost_effectiveness.csv",
    "statistical_tests.csv",
    "convergence.csv",
    "difficulty_terraform.csv",
    "difficulty_kubernetes.csv",
)

EXPECTED_RUNS = 630
EXPECTED_COMPARISONS = 10_080  # 630 rows x 16 columns

# Known, explained gaps in the frozen data: three verify-loop runs whose final attempt
# produced no extractable patch, so no verification object exists for that attempt.
# They are classified, not skipped.
KNOWN_UNAVAILABLE_FINAL_VERIFICATION = {
    "BM-0276_claude-opus-4.6_verify_loop.json",
    "BM-0276_claude-sonnet-4.6_verify_loop.json",
    "BM-0279_claude-sonnet-4.6_verify_loop.json",
}
EXPECTED_ATTEMPTS_TOTAL = 762
EXPECTED_UNAVAILABLE = 3


def canonicalise(text: str) -> str:
    """The one declared canonicalisation for regenerated text comparison."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip("\n") + "\n"


def parse_rows(text: str) -> tuple[list[str], list[list[str]]]:
    reader = csv.reader(io.StringIO(canonicalise(text)))
    rows = [r for r in reader if r]
    return (rows[0], rows[1:]) if rows else ([], [])


def parse_verification(value: object) -> tuple[dict | None, str, str | None]:
    """Return (parsed, kind, error).

    kind is one of: dict, repr_string, missing, unexpected_type.
    `ast.literal_eval` is retained as a compatibility path for repr-encoded values;
    `eval` is never used, because these strings contain model-influenced text.
    """
    if value is None:
        return None, "missing", None
    if isinstance(value, dict):
        return value, "dict", None
    if isinstance(value, str):
        try:
            parsed = ast.literal_eval(value)
        except (ValueError, SyntaxError) as exc:
            return None, "repr_string", str(exc)
        if not isinstance(parsed, dict):
            return None, "repr_string", f"parsed to {type(parsed).__name__}, not dict"
        return parsed, "repr_string", None
    return None, "unexpected_type", type(value).__name__


def reconstruct(root: Path) -> dict:
    committed_text = (root / ALL_RUNS).read_bytes().decode("utf-8")
    header, committed_rows = parse_rows(committed_text)

    result: dict = {
        "run_files": 0,
        "committed_rows": len(committed_rows),
        "columns": len(header),
        "comparisons": 0,
        "equal": 0,
        "mismatches": [],
        "duplicate_csv_keys": [],
        "duplicate_run_keys": [],
        "missing_json_fields": [],
        "unmatched_runs": [],
        "unmatched_rows": [],
        "attempts_total": 0,
        "verification_dicts": 0,
        "verification_repr_strings": 0,
        "verification_missing": 0,
        "verification_unexpected_type": 0,
        "verification_parse_failures": [],
        "final_verdicts_checked": 0,
        "final_verdicts_unavailable": [],
        "final_verdict_mismatches": [],
        "target_rule_inconsistencies": [],
    }

    # Duplicate composite keys in the CSV must fail rather than silently collapse.
    key_counts = Counter((r[0], r[1], r[2]) for r in committed_rows if len(r) >= 3)
    for key, count in sorted(key_counts.items()):
        if count > 1:
            result["duplicate_csv_keys"].append(f"{key} appears {count} times")
    committed = {(r[0], r[1], r[2]): r for r in committed_rows}

    run_files = sorted((root / RUNS_SUBDIR).glob("*.json"))
    result["run_files"] = len(run_files)
    seen_keys: set[tuple[str, str, str]] = set()

    for path in run_files:
        record = json.loads(path.read_text(encoding="utf-8"))

        # Every CSV column must be present as a key. A missing key is a data defect,
        # not an empty string.
        for col in header:
            if col not in record:
                result["missing_json_fields"].append(f"{path.name}: missing {col!r}")

        key = (record.get("artifact_id"), record.get("model"), record.get("method"))
        if key in seen_keys:
            result["duplicate_run_keys"].append(f"{path.name} -> {key}")
        seen_keys.add(key)

        row = ["" if record.get(col) is None else str(record.get(col, "")) for col in header]

        if key not in committed:
            result["unmatched_runs"].append(f"{path.name} -> {key}")
        else:
            for col, rebuilt_value, committed_value in zip(header, row, committed[key]):
                result["comparisons"] += 1
                if rebuilt_value == committed_value:
                    result["equal"] += 1
                else:
                    result["mismatches"].append({
                        "run": path.name, "column": col,
                        "rebuilt": rebuilt_value, "committed": committed_value,
                    })

        attempts = record.get("attempts") or []
        result["attempts_total"] += len(attempts)
        for attempt in attempts:
            parsed, kind, error = parse_verification(attempt.get("verification"))
            result[f"verification_{kind}s" if kind == "dict" else f"verification_{kind}"] = (
                result.get(f"verification_{kind}s" if kind == "dict" else f"verification_{kind}", 0) + 1
            )
            if error:
                result["verification_parse_failures"].append(f"{path.name}: {error}")
            if parsed and parsed.get("target_rule_id") not in (
                None, record.get("checkov_rule_id")
            ):
                result["target_rule_inconsistencies"].append(
                    f"{path.name}: attempt target {parsed.get('target_rule_id')!r} != "
                    f"record rule {record.get('checkov_rule_id')!r}"
                )

        # The record's own verdict must agree with its final attempt, when one exists.
        if attempts:
            parsed, kind, _ = parse_verification(attempts[-1].get("verification"))
            if parsed is not None and "overall_verified_fix" in parsed:
                result["final_verdicts_checked"] += 1
                if str(parsed["overall_verified_fix"]) != str(record.get("overall_verified_fix")):
                    result["final_verdict_mismatches"].append(
                        f"{path.name}: record {record.get('overall_verified_fix')} != "
                        f"final attempt {parsed['overall_verified_fix']}"
                    )
            else:
                result["final_verdicts_unavailable"].append({
                    "file": path.name,
                    "verification_kind": kind,
                    "final_attempt_error": attempts[-1].get("error"),
                    "record_verdict": record.get("overall_verified_fix"),
                    "expected": path.name in KNOWN_UNAVAILABLE_FINAL_VERIFICATION,
                })

    result["unmatched_rows"] = [str(k) for k in sorted(set(committed) - seen_keys)]
    return result


def reproduce_tables(root: Path, keep: Path | None = None) -> dict:
    out: dict = {"tables": {}, "script_runs": {}, "copied_files": 0,
                 "copy_method": None, "excluded_artifacts": []}
    tmp = Path(tempfile.mkdtemp(prefix="iacg-replay-"))
    work = tmp / "repo"
    try:
        (work / "results" / "tables").mkdir(parents=True)
        (work / RUNS_SUBDIR).mkdir(parents=True)
        (work / "scripts").mkdir(parents=True)

        # Copy only the research inputs the analysis scripts need, and never ignored
        # build artifacts such as scripts/__pycache__/*.pyc. `git ls-files` is
        # preferred because it is authoritative about what is tracked; the minimal
        # reproduction container has no git, so a filesystem walk with an explicit
        # exclusion list is the documented fallback. The method used is reported.
        EXCLUDED_NAMES = {"__pycache__", ".DS_Store", ".pytest_cache"}
        EXCLUDED_SUFFIXES = (".pyc", ".pyo")

        def copy_rel(rel: str) -> None:
            dest = work / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / rel, dest)
            out["copied_files"] += 1

        tracked: list[str] = []
        try:
            tracked = [
                rel for rel in subprocess.run(
                    ["git", "-C", str(root), "ls-files", "-z", "scripts", str(RUNS_SUBDIR)],
                    capture_output=True, text=True, check=True,
                ).stdout.split("\0") if rel
            ]
            out["copy_method"] = "git-ls-files"
        except (FileNotFoundError, subprocess.CalledProcessError):
            out["copy_method"] = "filesystem-walk-with-exclusions"
            for top in ("scripts", str(RUNS_SUBDIR)):
                for dirpath, dirnames, filenames in os.walk(root / top, followlinks=False):
                    dirnames[:] = [d for d in dirnames if d not in EXCLUDED_NAMES]
                    for fn in filenames:
                        if fn in EXCLUDED_NAMES or fn.endswith(EXCLUDED_SUFFIXES):
                            continue
                        tracked.append(
                            (Path(dirpath) / fn).relative_to(root).as_posix()
                        )

        skipped = [
            rel for rel in tracked
            if Path(rel).name in EXCLUDED_NAMES
            or rel.endswith(EXCLUDED_SUFFIXES)
            or any(part in EXCLUDED_NAMES for part in Path(rel).parts)
        ]
        out["excluded_artifacts"] = sorted(skipped)
        for rel in tracked:
            if rel in skipped:
                continue
            copy_rel(rel)
        shutil.copy2(root / ALL_RUNS, work / ALL_RUNS)
        out["copied_files"] += 1

        for script in ANALYSIS_SCRIPTS:
            proc = subprocess.run(
                [sys.executable, f"scripts/{script}"], cwd=work,
                capture_output=True, text=True,
            )
            out["script_runs"][script] = {
                "returncode": proc.returncode,
                "stderr_tail": proc.stderr.strip().splitlines()[-3:] if proc.stderr else [],
            }

        for name in DERIVED_TABLES:
            committed_path = root / "results" / "tables" / name
            produced_path = work / "results" / "tables" / name
            if not produced_path.is_file():
                out["tables"][name] = {"status": "NOT_PRODUCED"}
                continue
            committed_bytes = committed_path.read_bytes()
            produced_bytes = produced_path.read_bytes()
            c_header, c_rows = parse_rows(committed_bytes.decode("utf-8"))
            p_header, p_rows = parse_rows(produced_bytes.decode("utf-8"))
            byte_identical = committed_bytes == produced_bytes
            same = c_header == p_header and c_rows == p_rows
            diffs: list[str] = []
            if not same:
                if c_header != p_header:
                    diffs.append(f"header {c_header} != {p_header}")
                for i, (a, b) in enumerate(zip(c_rows, p_rows)):
                    if a != b:
                        diffs.append(f"row {i}: {a} != {b}")
                    if len(diffs) >= 5:
                        break
                if len(c_rows) != len(p_rows):
                    diffs.append(f"row count {len(c_rows)} != {len(p_rows)}")
            out["tables"][name] = {
                "status": "SEMANTIC_MATCH" if same else "SEMANTIC_DIFF",
                "rows": len(c_rows),
                "byte_identical": byte_identical,
                "eol_canonicalisation_applied": not byte_identical and same,
                "diffs": diffs,
            }
        if keep:
            shutil.copytree(work / "results" / "tables", keep, dirs_exist_ok=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--check", action="store_true", help="exit non-zero on any difference")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep-output", type=Path, default=None)
    args = ap.parse_args()
    root = args.root.resolve()

    rec = reconstruct(root)
    rep = reproduce_tables(root, args.keep_output)

    problems: list[str] = []
    if rec["run_files"] != EXPECTED_RUNS:
        problems.append(f"expected {EXPECTED_RUNS} frozen runs, found {rec['run_files']}")
    if rec["committed_rows"] != EXPECTED_RUNS:
        problems.append(f"expected {EXPECTED_RUNS} committed rows, found {rec['committed_rows']}")
    if rec["comparisons"] != EXPECTED_COMPARISONS:
        problems.append(
            f"expected {EXPECTED_COMPARISONS} field comparisons, made {rec['comparisons']}"
        )
    if rec["equal"] != rec["comparisons"]:
        problems.append(f"{len(rec['mismatches'])} field mismatch(es)")
    if rec["attempts_total"] != EXPECTED_ATTEMPTS_TOTAL:
        problems.append(
            f"expected {EXPECTED_ATTEMPTS_TOTAL} attempts, found {rec['attempts_total']}"
        )
    for key in ("duplicate_csv_keys", "duplicate_run_keys", "missing_json_fields",
                "unmatched_runs", "unmatched_rows", "verification_parse_failures",
                "final_verdict_mismatches", "target_rule_inconsistencies"):
        if rec[key]:
            problems.append(f"{key}: {len(rec[key])}")

    # Unavailable final verifications are permitted only if they are the three known,
    # explained records. An unexpected one is a problem.
    unexpected = [u for u in rec["final_verdicts_unavailable"] if not u["expected"]]
    if unexpected:
        problems.append(f"unexpected unavailable final verification: {len(unexpected)}")
    if len(rec["final_verdicts_unavailable"]) != EXPECTED_UNAVAILABLE:
        problems.append(
            f"expected {EXPECTED_UNAVAILABLE} unavailable final verifications, "
            f"found {len(rec['final_verdicts_unavailable'])}"
        )

    for name, info in rep["tables"].items():
        if info["status"] != "SEMANTIC_MATCH":
            problems.append(f"{name}: {info['status']}")
    for script, info in rep["script_runs"].items():
        if info["returncode"] != 0:
            problems.append(f"{script} exited {info['returncode']}")

    status = "PASS" if not problems else "FAIL"

    if args.json:
        print(json.dumps({"status": status, "reconstruction": rec, "reproduction": rep,
                          "problems": problems}, indent=2, default=str))
    else:
        print("== 1. exact reconstruction of results/tables/all_runs.csv ==")
        print(f"frozen run records:        {rec['run_files']}/{EXPECTED_RUNS}")
        print(f"committed rows matched:    {len(rec['unmatched_rows']) == 0} "
              f"({rec['committed_rows']} rows, 0 unmatched)")
        print(f"field comparisons:         {rec['equal']}/{rec['comparisons']} equal "
              f"(expected {EXPECTED_COMPARISONS})")
        print(f"duplicate CSV keys:        {len(rec['duplicate_csv_keys'])}")
        print(f"duplicate run keys:        {len(rec['duplicate_run_keys'])}")
        print(f"missing JSON fields:       {len(rec['missing_json_fields'])}")
        print()
        print("-- stored verification values (ast.literal_eval is a compatibility path) --")
        print(f"attempts_total:            {rec['attempts_total']}")
        print(f"verification_dicts:        {rec['verification_dicts']}")
        print(f"verification_repr_strings: {rec['verification_repr_strings']}"
              f"  <- ast.literal_eval exercised this many times")
        print(f"verification_missing:      {rec['verification_missing']}")
        print(f"verification_unexpected:   {rec['verification_unexpected_type']}")
        print(f"verification_parse_failures: {len(rec['verification_parse_failures'])}")
        print()
        print(f"final_verdicts_checked:     {rec['final_verdicts_checked']}")
        print(f"final_verdicts_unavailable: {len(rec['final_verdicts_unavailable'])}")
        for u in rec["final_verdicts_unavailable"]:
            print(f"    {u['file']}: final attempt error={u['final_attempt_error']!r}, "
                  f"record verdict={u['record_verdict']}, "
                  f"{'known and explained' if u['expected'] else 'UNEXPECTED'}")
        print(f"final_verdict_mismatches:   {len(rec['final_verdict_mismatches'])}")
        for m in rec["mismatches"][:5]:
            print(f"  MISMATCH {m['run']} [{m['column']}] "
                  f"rebuilt={m['rebuilt']!r} committed={m['committed']!r}")
        print()
        print("== 2. semantic reproduction of derived tables (CRLF->LF canonicalised) ==")
        print(f"files copied into the workspace: {rep['copied_files']} "
              f"via {rep['copy_method']}")
        if rep["excluded_artifacts"]:
            print(f"  excluded build artifacts: {len(rep['excluded_artifacts'])} "
                  f"e.g. {rep['excluded_artifacts'][:2]}")
        for script, info in rep["script_runs"].items():
            print(f"{script:20s} exit={info['returncode']}")
        for name, info in rep["tables"].items():
            extra = "  [content equal; line endings differed]" if info.get(
                "eol_canonicalisation_applied") else ""
            print(f"  {info['status']:15s} {name:34s} rows={info.get('rows','?')}{extra}")
            for d in info.get("diffs", [])[:3]:
                print(f"      {d}")
        print()
        print("figures: not regenerated (no frozen analysis script calls savefig)")
        print("all_runs.csv: input to the analysis scripts, not an output")
        for p in problems:
            print(f"  PROBLEM {p}")
        print(status)

    return 1 if (args.check and problems) else 0


if __name__ == "__main__":
    sys.exit(main())
