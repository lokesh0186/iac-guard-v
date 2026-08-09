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
   derived tables are compared against the committed ones after an explicitly
   declared canonicalisation: CRLF -> LF, exactly one trailing newline, and
   row/column comparison after parsing. Python's csv writer emits CRLF while git
   stores LF under `* text=auto`, so a byte comparison here would fail for a reason
   that has nothing to do with research correctness.

   The result is reported as SEMANTIC_MATCH or SEMANTIC_DIFF. It is never described
   as byte equality. Byte equality is the separate job of
   `research/verify_byte_manifest.py`.

The `verification` blob inside each frozen attempt is a Python repr, not JSON, so it
is parsed with `ast.literal_eval`. `eval` must never be used here: that string
contains model-influenced text.

Figures are not regenerated: no frozen analysis script calls savefig.

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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RUNS_SUBDIR = Path("runs/raw")
ALL_RUNS = Path("results/tables/all_runs.csv")
ANALYSIS_SCRIPTS = ("analyze_part1.py", "analyze_part2.py", "analyze_part3.py")

# Written by the frozen analysis scripts; all_runs.csv is their input, not output.
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


def canonicalise(text: str) -> str:
    """The one declared canonicalisation for regenerated text comparison."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip("\n") + "\n"


def parse_rows(text: str) -> tuple[list[str], list[list[str]]]:
    reader = csv.reader(io.StringIO(canonicalise(text)))
    rows = [r for r in reader if r]
    return (rows[0], rows[1:]) if rows else ([], [])


# --------------------------------------------------------------------------- #
# 1. exact reconstruction of all_runs.csv
# --------------------------------------------------------------------------- #
def reconstruct(root: Path) -> dict:
    committed_text = (root / ALL_RUNS).read_text(encoding="utf-8")
    header, committed_rows = parse_rows(committed_text)
    committed = {(r[0], r[1], r[2]): r for r in committed_rows}

    run_files = sorted((root / RUNS_SUBDIR).glob("*.json"))
    result: dict = {
        "run_files": len(run_files),
        "committed_rows": len(committed_rows),
        "columns": len(header),
        "comparisons": 0,
        "equal": 0,
        "mismatches": [],
        "unmatched_runs": [],
        "unmatched_rows": [],
        "attempts_parsed": 0,
        "attempt_parse_failures": [],
        "verdict_consistency_failures": [],
        "rebuilt_rows": 0,
    }

    seen_keys: set[tuple[str, str, str]] = set()
    rebuilt: list[list[str]] = []

    for path in run_files:
        record = json.loads(path.read_text(encoding="utf-8"))
        key = (record["artifact_id"], record["model"], record["method"])

        # Rebuild the CSV row in the committed column order, using str() exactly as
        # csv.DictWriter would have rendered these Python values.
        row = ["" if record.get(col) is None else str(record.get(col, "")) for col in header]
        rebuilt.append(row)

        if key not in committed:
            result["unmatched_runs"].append(f"{path.name} -> {key}")
            continue
        seen_keys.add(key)
        for col, rebuilt_value, committed_value in zip(header, row, committed[key]):
            result["comparisons"] += 1
            if rebuilt_value == committed_value:
                result["equal"] += 1
            else:
                result["mismatches"].append(
                    {
                        "run": path.name,
                        "column": col,
                        "rebuilt": rebuilt_value,
                        "committed": committed_value,
                    }
                )

        # Exercise the repr-encoded verification blob and check self-consistency.
        for attempt in record.get("attempts", []):
            blob = attempt.get("verification")
            if blob is None:
                continue
            try:
                parsed = ast.literal_eval(blob) if isinstance(blob, str) else blob
                result["attempts_parsed"] += 1
            except (ValueError, SyntaxError) as exc:
                result["attempt_parse_failures"].append(f"{path.name}: {exc}")
                continue
            if not isinstance(parsed, dict):
                result["attempt_parse_failures"].append(
                    f"{path.name}: verification is {type(parsed).__name__}, not dict"
                )
                continue
            if parsed.get("target_rule_id") not in (None, record.get("checkov_rule_id")):
                result["verdict_consistency_failures"].append(
                    f"{path.name}: attempt target {parsed.get('target_rule_id')!r} "
                    f"!= record rule {record.get('checkov_rule_id')!r}"
                )

        # The record's own verdict must agree with its final attempt.
        attempts = record.get("attempts") or []
        if attempts:
            last = attempts[-1].get("verification")
            try:
                last_parsed = ast.literal_eval(last) if isinstance(last, str) else last
            except (ValueError, SyntaxError):
                last_parsed = None
            if isinstance(last_parsed, dict) and "overall_verified_fix" in last_parsed:
                if str(last_parsed["overall_verified_fix"]) != str(
                    record.get("overall_verified_fix")
                ):
                    result["verdict_consistency_failures"].append(
                        f"{path.name}: record verdict {record.get('overall_verified_fix')} "
                        f"!= final attempt {last_parsed['overall_verified_fix']}"
                    )

    result["unmatched_rows"] = [f"{k}" for k in sorted(set(committed) - seen_keys)]
    result["rebuilt_rows"] = len(rebuilt)
    return result


# --------------------------------------------------------------------------- #
# 2. semantic reproduction of the derived tables
# --------------------------------------------------------------------------- #
def reproduce_tables(root: Path, keep: Path | None = None) -> dict:
    out: dict = {"tables": {}, "script_runs": {}, "workdir": None}
    tmp = Path(tempfile.mkdtemp(prefix="iacg-replay-"))
    work = tmp / "repo"
    try:
        (work / "results" / "tables").mkdir(parents=True)
        shutil.copytree(root / "scripts", work / "scripts")
        shutil.copytree(root / RUNS_SUBDIR, work / RUNS_SUBDIR)
        shutil.copy2(root / ALL_RUNS, work / ALL_RUNS)

        for script in ANALYSIS_SCRIPTS:
            proc = subprocess.run(
                [sys.executable, f"scripts/{script}"],
                cwd=work,
                capture_output=True,
                text=True,
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
            # Read bytes for the byte comparison: read_text() applies universal
            # newline translation, which would silently hide the CRLF/LF difference
            # that this flag exists to surface.
            committed_bytes = committed_path.read_bytes()
            produced_bytes = produced_path.read_bytes()
            committed_text = committed_bytes.decode("utf-8")
            produced_text = produced_bytes.decode("utf-8")
            c_header, c_rows = parse_rows(committed_text)
            p_header, p_rows = parse_rows(produced_text)
            byte_identical = committed_bytes == produced_bytes
            same = c_header == p_header and c_rows == p_rows
            diffs = []
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
            out["workdir"] = str(keep)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--check", action="store_true", help="exit non-zero on any difference")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep-output", type=Path, default=None,
                    help="copy regenerated tables here for inspection")
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
    for k in ("unmatched_runs", "unmatched_rows", "attempt_parse_failures",
              "verdict_consistency_failures"):
        if rec[k]:
            problems.append(f"{k}: {len(rec[k])}")
    for name, info in rep["tables"].items():
        if info["status"] != "SEMANTIC_MATCH":
            problems.append(f"{name}: {info['status']}")
    for script, info in rep["script_runs"].items():
        if info["returncode"] != 0:
            problems.append(f"{script} exited {info['returncode']}")

    status = "PASS" if not problems else "FAIL"

    if args.json:
        print(json.dumps(
            {"status": status, "reconstruction": rec, "reproduction": rep,
             "problems": problems}, indent=2, default=str))
    else:
        print("== 1. exact reconstruction of results/tables/all_runs.csv ==")
        print(f"frozen run records:      {rec['run_files']}/{EXPECTED_RUNS}")
        print(f"committed rows matched:  {rec['rebuilt_rows']}/{rec['committed_rows']}")
        print(f"field comparisons:       {rec['equal']}/{rec['comparisons']} equal "
              f"(expected {EXPECTED_COMPARISONS})")
        print(f"attempt blobs parsed:    {rec['attempts_parsed']} via ast.literal_eval, "
              f"{len(rec['attempt_parse_failures'])} failure(s)")
        print(f"verdict consistency:     {len(rec['verdict_consistency_failures'])} failure(s)")
        for m in rec["mismatches"][:5]:
            print(f"  MISMATCH {m['run']} [{m['column']}] "
                  f"rebuilt={m['rebuilt']!r} committed={m['committed']!r}")
        print()
        print("== 2. semantic reproduction of derived tables (CRLF->LF canonicalised) ==")
        for script, info in rep["script_runs"].items():
            print(f"{script:20s} exit={info['returncode']}")
        for name, info in rep["tables"].items():
            extra = ""
            if info.get("eol_canonicalisation_applied"):
                extra = "  [content equal; line endings differed]"
            print(f"  {info['status']:15s} {name:34s} rows={info.get('rows', '?')}{extra}")
            for d in info.get("diffs", [])[:3]:
                print(f"      {d}")
        print()
        print("figures: not regenerated (no frozen analysis script calls savefig)")
        print("all_runs.csv: input to the analysis scripts, not an output")
        for p in problems:
            print(f"  PROBLEM {p}")
        print(status)

    if args.check and problems:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
