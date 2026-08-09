#!/usr/bin/env python3
"""Verify the byte-exact freeze manifest.

This is the Gate B byte check. It replaces `shasum -c`, which cannot validate a
manifest that binds mode and size in addition to a digest: `shasum` treats
everything after the digest as a single filename, so a four-field record fails with
"FAILED open or read" against a path that does not exist.

The verifier answers eight questions, and a single "no" fails the gate:

  1. Does the manifest hold exactly the expected number of records?
  2. Is every listed file still present?
  3. Is any file present under a frozen prefix that the manifest does not list?
  4. Did any git mode change?
  5. Did any byte size change?
  6. Did any SHA-256 change?
  7. Did a symlink appear anywhere under a frozen prefix?
  8. Does MANIFEST_ROOT still match the canonical record set?

Question 3 matters as much as question 6. Without it, a new file dropped into
`scripts/` or `runs/` would leave all 4,842 recorded hashes intact and pass.

Usage:
    python research/verify_byte_manifest.py \
        --manifest research/qrs2026-byte-manifest.jsonl \
        --root . --expect-entries 4842 --strict
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

FROZEN_PREFIXES: tuple[str, ...] = (
    "benchmark/",
    "runs/",
    "results/",
    "prompts/",
    "scanners/",
    "scripts/",
)
FROZEN_FILES: tuple[str, ...] = ("requirements.txt",)
REQUIRED_KEYS = {"path", "git_mode", "git_blob_oid", "size_bytes", "sha256"}


def is_frozen(rel_path: str) -> bool:
    return rel_path in FROZEN_FILES or rel_path.startswith(FROZEN_PREFIXES)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def canonical_line(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_of(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def normalise_ok(rel: str) -> str | None:
    """Return an error string if the path is not a safe repo-relative path."""
    if rel != rel.strip():
        return "leading/trailing whitespace"
    if rel.startswith("/"):
        return "absolute path"
    if "\\" in rel:
        return "backslash separator"
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "non-normalised path component"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--expect-entries", type=int, default=None)
    ap.add_argument("--strict", action="store_true",
                    help="treat untracked files under frozen prefixes as failures")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable summary")
    args = ap.parse_args()

    root = args.root.resolve()
    root_file = args.manifest.with_suffix(".root")

    failures: list[str] = []
    warnings: list[str] = []

    # ---- load manifest -----------------------------------------------------
    records: list[dict] = []
    lines_raw: list[str] = []
    for lineno, raw in enumerate(
        args.manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as exc:
            failures.append(f"MANIFEST_PARSE line {lineno}: {exc}")
            continue
        if not isinstance(rec, dict) or set(rec) != REQUIRED_KEYS:
            failures.append(
                f"MANIFEST_SCHEMA line {lineno}: keys {sorted(rec)} != {sorted(REQUIRED_KEYS)}"
            )
            continue
        if "record_type" in rec:  # defensive: metadata must not live in the JSONL
            failures.append(f"MANIFEST_SCHEMA line {lineno}: metadata record in JSONL")
            continue
        records.append(rec)
        lines_raw.append(raw)

    if failures:
        _report(failures, warnings, 0, args.json, None, None)
        return 1

    listed = {r["path"]: r for r in records}

    # ---- 1. entry count ----------------------------------------------------
    if args.expect_entries is not None and len(records) != args.expect_entries:
        failures.append(
            f"ENTRY_COUNT: manifest has {len(records)}, expected {args.expect_entries}"
        )

    # ---- path hygiene ------------------------------------------------------
    for rel in listed:
        if (why := normalise_ok(rel)) is not None:
            failures.append(f"PATH_NOT_NORMALISED: {rel} ({why})")
        if not is_frozen(rel):
            failures.append(f"PATH_OUTSIDE_FROZEN_SCOPE: {rel}")

    # ---- current tracked state --------------------------------------------
    tracked: dict[str, str] = {}          # rel -> git mode
    tracked_oid: dict[str, str] = {}      # rel -> git blob oid
    for record in git(root, "ls-files", "-s", "-z").split("\0"):
        if not record:
            continue
        meta, _, rel = record.partition("\t")
        if is_frozen(rel):
            fields = meta.split()
            tracked[rel] = fields[0]
            tracked_oid[rel] = fields[1]

    # ---- 3. unlisted / added files -----------------------------------------
    for rel in sorted(set(tracked) - set(listed)):
        failures.append(f"ADDED_TRACKED_FILE_UNDER_FROZEN_PREFIX: {rel}")

    untracked = [
        rel
        for rel in git(root, "ls-files", "--others", "--exclude-standard", "-z").split("\0")
        if rel and is_frozen(rel)
    ]
    for rel in sorted(untracked):
        msg = f"ADDED_UNTRACKED_FILE_UNDER_FROZEN_PREFIX: {rel}"
        (failures if args.strict else warnings).append(msg)

    # ---- 2, 4, 5, 6, 7 per-file checks ------------------------------------
    checked = 0
    for rel, rec in sorted(listed.items()):
        abs_path = root / rel
        if abs_path.is_symlink():
            failures.append(f"SYMLINK_APPEARED: {rel}")
            continue
        if not abs_path.is_file():
            failures.append(f"MISSING_FILE: {rel}")
            continue
        current_mode = tracked.get(rel)
        if current_mode is None:
            failures.append(f"UNTRACKED_LISTED_FILE: {rel}")
        elif current_mode != rec["git_mode"]:
            failures.append(
                f"MODE_CHANGED: {rel} {rec['git_mode']} -> {current_mode}"
            )
        if current_mode == "120000":
            failures.append(f"SYMLINK_APPEARED: {rel} (git mode 120000)")

        # Platform-independent anchor: git's stored blob identity.
        current_oid = tracked_oid.get(rel)
        oid_matches = current_oid == rec["git_blob_oid"]
        if current_oid is not None and not oid_matches:
            failures.append(
                f"GIT_BLOB_CHANGED: {rel} {rec['git_blob_oid'][:12]}… -> {current_oid[:12]}…"
            )

        digest, size = sha256_of(abs_path)
        if digest != rec["sha256"]:
            # A matching index OID is not sufficient to call this an encoding
            # difference: an unstaged edit also leaves the index OID untouched.
            # Compare the working-tree bytes against the stored blob content, and
            # only accept "line endings differ" when that is literally the case.
            classification = "SHA256_CHANGED"
            if oid_matches:
                blob = subprocess.run(
                    ["git", "-C", str(root), "cat-file", "blob", rec["git_blob_oid"]],
                    check=False, capture_output=True,
                ).stdout
                working = abs_path.read_bytes()
                if working == blob:
                    classification = None  # cannot happen: digests would match
                elif working.replace(b"\r\n", b"\n") == blob.replace(b"\r\n", b"\n"):
                    classification = "WORKING_TREE_BYTES_DIFFER_EOL_ONLY"
                else:
                    classification = "WORKING_TREE_CONTENT_CHANGED_UNSTAGED"

            if classification == "WORKING_TREE_BYTES_DIFFER_EOL_ONLY":
                failures.append(
                    f"WORKING_TREE_BYTES_DIFFER_EOL_ONLY: {rel} "
                    f"(stored blob content identical; only line endings differ from "
                    f"the LF checkout the manifest was built from)"
                )
            elif classification == "WORKING_TREE_CONTENT_CHANGED_UNSTAGED":
                failures.append(
                    f"SHA256_CHANGED: {rel} {rec['sha256'][:12]}… -> {digest[:12]}… "
                    f"(unstaged working-tree edit; git index still holds the original "
                    f"blob, so this is a content change, not an encoding difference)"
                )
            elif classification == "SHA256_CHANGED":
                failures.append(
                    f"SHA256_CHANGED: {rel} {rec['sha256'][:12]}… -> {digest[:12]}…"
                )
        if size != rec["size_bytes"] and digest == rec["sha256"]:
            failures.append(
                f"SIZE_CHANGED: {rel} {rec['size_bytes']} -> {size} bytes"
            )
        elif size != rec["size_bytes"] and not oid_matches:
            failures.append(
                f"SIZE_CHANGED: {rel} {rec['size_bytes']} -> {size} bytes"
            )
        checked += 1

    # ---- 8. MANIFEST_ROOT --------------------------------------------------
    # Canonical order is defined as: records sorted by UTF-8 path bytes, each
    # serialised with sorted keys and compact separators. Sorting by the serialised
    # line instead would be wrong, because canonical JSON puts "git_blob_oid"
    # before "path" alphabetically, so line order would follow blob ids.
    canonical = [
        canonical_line(r)
        for r in sorted(records, key=lambda r: r["path"].encode("utf-8"))
    ]
    computed_root = hashlib.sha256(
        ("\n".join(canonical) + "\n").encode("utf-8")
    ).hexdigest()

    recorded_root = None
    if not root_file.is_file():
        failures.append(f"MISSING_ROOT_SIDECAR: {root_file.name}")
    else:
        side = json.loads(root_file.read_text(encoding="utf-8"))
        if side.get("record_type") != "manifest_root":
            failures.append("ROOT_SIDECAR_SCHEMA: record_type != manifest_root")
        recorded_root = side.get("manifest_root")
        if side.get("entry_count") != len(records):
            failures.append(
                f"ROOT_ENTRY_COUNT: sidecar {side.get('entry_count')} != manifest {len(records)}"
            )
        if recorded_root != computed_root:
            failures.append(
                f"MANIFEST_ROOT_MISMATCH: recorded {recorded_root} != computed {computed_root}"
            )
        if lines_raw != canonical:
            failures.append(
                "MANIFEST_NOT_CANONICAL: file lines differ from canonical sorted form"
            )

    _report(failures, warnings, checked, args.json, computed_root, recorded_root)
    return 1 if failures else 0


def _report(failures, warnings, checked, as_json, computed_root, recorded_root) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "status": "FAIL" if failures else "PASS",
                    "files_checked": checked,
                    "failures": failures,
                    "warnings": warnings,
                    "manifest_root_computed": computed_root,
                    "manifest_root_recorded": recorded_root,
                },
                indent=2,
            )
        )
        return
    print(f"files checked:          {checked}")
    print(f"MANIFEST_ROOT computed: {computed_root}")
    print(f"MANIFEST_ROOT recorded: {recorded_root}")
    for w in warnings:
        print(f"  WARN {w}")
    for f in failures:
        print(f"  FAIL {f}")
    print("FAIL" if failures else "PASS")


if __name__ == "__main__":
    sys.exit(main())
