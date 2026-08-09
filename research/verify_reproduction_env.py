#!/usr/bin/env python3
"""Verify the two environment records, and that they stay separate.

The failure this guards against is subtle and tempting: a successful 2026 replay
environment quietly becomes "the environment the experiment ran in". Once that
happens the artifact asserts something nobody ever measured.

Checks performed:

  A. Every `evidenced` field in ORIGINAL_EXPERIMENT_METADATA.json
     - cites a source inside the frozen scope,
     - the cited file's SHA-256 still matches,
     - the cited line exists and contains the recorded excerpt,
     - the excerpt (or the file, for hash-valued fields) supports the value,
     - and any corroborating evidence set is complete.
  B. Every `not_recorded` field has a null value and an explanatory note.
  C. No host/interpreter/library fact is marked `evidenced` in the historical file.
  D. No value in the historical file was taken from the replay record.
  E. VALIDATED_REPLAY_ENVIRONMENT.json declares its own scope, records the replay
     result, and agrees with requirements-reproduction.lock.

Usage:
    python research/verify_reproduction_env.py \
        --original research/ORIGINAL_EXPERIMENT_METADATA.json \
        --replay   research/VALIDATED_REPLAY_ENVIRONMENT.json \
        --lock     research/requirements-reproduction.lock
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

FROZEN_PREFIXES = ("benchmark/", "runs/", "results/", "prompts/", "scanners/", "scripts/")
FROZEN_FILES = ("requirements.txt",)

# Facts about the machine that ran the experiment. None of these were recorded, so
# none may ever be "evidenced" in the historical file.
HOST_FACT_PATTERN = re.compile(
    r"(python|pandas|numpy|scipy|matplotlib|host|os_|architecture|platform|interpreter)",
    re.IGNORECASE,
)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def in_frozen_scope(rel: str) -> bool:
    return rel in FROZEN_FILES or rel.startswith(FROZEN_PREFIXES) or rel.rstrip("/") in (
        "runs", "results", "benchmark", "prompts", "scanners", "scripts"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--original", type=Path, required=True)
    ap.add_argument("--replay", type=Path, required=True)
    ap.add_argument("--lock", type=Path, default=Path("research/requirements-reproduction.lock"))
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = args.root.resolve()
    failures: list[str] = []
    notes: list[str] = []

    original = json.loads(args.original.read_text(encoding="utf-8"))
    replay = json.loads(args.replay.read_text(encoding="utf-8"))
    fields: dict = original["fields"]

    evidenced = [k for k, v in fields.items() if v["status"] == "evidenced"]
    not_recorded = [k for k, v in fields.items() if v["status"] == "not_recorded"]

    # ---- A ----------------------------------------------------------------
    for key in evidenced:
        field = fields[key]
        prov = field.get("provenance") or {}
        src = prov.get("source")
        value = field.get("value")

        if value is None:
            failures.append(f"A/{key}: status evidenced but value is null")
            continue
        if not src:
            failures.append(f"A/{key}: evidenced without a source")
            continue
        if not in_frozen_scope(src):
            failures.append(f"A/{key}: source {src} is outside the frozen scope")
            continue

        src_path = root / src
        if src_path.is_dir():
            notes.append(f"A/{key}: source is a directory ({src}); hash check skipped")
        elif not src_path.is_file():
            failures.append(f"A/{key}: cited source does not exist: {src}")
            continue
        else:
            recorded_hash = prov.get("source_sha256")
            actual = sha256_of(src_path)
            if recorded_hash is None:
                failures.append(f"A/{key}: no source_sha256 recorded for {src}")
            elif recorded_hash != actual:
                failures.append(
                    f"A/{key}: source hash changed for {src}: "
                    f"recorded {recorded_hash[:12]}… actual {actual[:12]}…"
                )

            line_no = prov.get("line")
            excerpt = prov.get("excerpt")
            if line_no is not None:
                lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line_no < 1 or line_no > len(lines):
                    failures.append(
                        f"A/{key}: cited line {src}:{line_no} out of range (1..{len(lines)})"
                    )
                elif excerpt and excerpt.strip() not in lines[line_no - 1]:
                    failures.append(
                        f"A/{key}: excerpt not found at {src}:{line_no}\n"
                        f"        expected: {excerpt!r}\n"
                        f"        actual:   {lines[line_no - 1].strip()!r}"
                    )
                elif excerpt and str(value) not in excerpt:
                    failures.append(
                        f"A/{key}: value {value!r} not supported by excerpt {excerpt!r}"
                    )
            elif excerpt is None and key.startswith("prompt_sha256_"):
                # Hash-valued field: the value must be the digest of the cited file.
                if str(value) != actual:
                    failures.append(
                        f"A/{key}: recorded digest {value} != actual {actual}"
                    )

        corr = (prov.get("corroboration") or {})
        if corr:
            glob_pat = corr.get("evidence_set_glob")
            expect = corr.get("expect_files")
            must = corr.get("must_contain")
            matched = sorted(root.glob(glob_pat)) if glob_pat else []
            if expect is not None and len(matched) != expect:
                failures.append(
                    f"A/{key}: corroboration set {glob_pat} has {len(matched)} files, "
                    f"expected {expect}"
                )
            missing = [
                p.relative_to(root).as_posix()
                for p in matched
                if must and must not in p.read_text(encoding="utf-8", errors="replace")
            ]
            if missing:
                failures.append(
                    f"A/{key}: {len(missing)} corroboration file(s) lack {must!r}, "
                    f"e.g. {missing[:3]}"
                )

    # ---- B ----------------------------------------------------------------
    for key in not_recorded:
        field = fields[key]
        if field.get("value") is not None:
            failures.append(f"B/{key}: not_recorded but has a value {field['value']!r}")
        if not (field.get("provenance") or {}).get("note"):
            failures.append(f"B/{key}: not_recorded without an explanatory note")

    for key, field in fields.items():
        if field["status"] not in ("evidenced", "not_recorded"):
            failures.append(f"B/{key}: invalid status {field['status']!r}")

    # ---- C ----------------------------------------------------------------
    for key in evidenced:
        if HOST_FACT_PATTERN.search(key):
            failures.append(
                f"C/{key}: host or library facts must never be evidenced in the "
                f"historical record (the experiment host was not captured)"
            )

    # ---- D ----------------------------------------------------------------
    replay_values = {
        str(replay["interpreter"]["python"]),
        *(str(v) for v in replay["packages"].values()),
        str(replay["replay_performed_on"]),
        str(replay["scanner_not_exercised"]["checkov_installed_locally"]),
    }
    for key in evidenced:
        value = str(fields[key].get("value"))
        if value in replay_values:
            failures.append(
                f"D/{key}: value {value!r} also appears in the replay record; "
                f"a replay fact must not be presented as a historical fact"
            )

    # ---- E ----------------------------------------------------------------
    for required in ("is_not", "replay_performed_on", "result", "packages", "interpreter"):
        if required not in replay:
            failures.append(f"E: replay record missing {required!r}")
    result = replay.get("result", {})
    expectations = {
        "frozen_run_records": 630,
        "field_comparisons": 10080,
        "field_comparisons_equal": 10080,
        "derived_tables_compared": 7,
        "derived_tables_semantic_match": 7,
    }
    for key, want in expectations.items():
        if result.get(key) != want:
            failures.append(f"E/result.{key}: {result.get(key)} != {want}")
    if result.get("derived_tables_byte_identical") != 0:
        failures.append(
            "E/result: derived tables are not byte-identical (line endings differ); "
            "claiming otherwise would conflate byte and semantic equality"
        )
    if replay.get("model_calls_made") != 0:
        failures.append("E: replay record must state model_calls_made = 0")

    if args.lock.is_file():
        lock_text = args.lock.read_text(encoding="utf-8")
        for name, version in replay["packages"].items():
            if f"{name}=={version}" not in lock_text:
                failures.append(f"E/lock: {name}=={version} not pinned in {args.lock.name}")
        checkov_required = replay["scanner_not_exercised"]["checkov_required_for_replication"]
        if f"checkov=={checkov_required}" not in lock_text:
            failures.append(f"E/lock: checkov=={checkov_required} not pinned")
        if "boto3" in lock_text.split("# Deliberately excluded")[0]:
            failures.append("E/lock: boto3 must not be a replay dependency")
    else:
        failures.append(f"E: lock file not found: {args.lock}")

    status = "PASS" if not failures else "FAIL"
    if args.json:
        print(json.dumps({
            "status": status,
            "evidenced_fields": len(evidenced),
            "not_recorded_fields": len(not_recorded),
            "failures": failures,
            "notes": notes,
        }, indent=2))
    else:
        print(f"evidenced fields:     {len(evidenced)}")
        print(f"not_recorded fields:  {len(not_recorded)}")
        for n in notes:
            print(f"  NOTE {n}")
        for f in failures:
            print(f"  FAIL {f}")
        print(status)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
