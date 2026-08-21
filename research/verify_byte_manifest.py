#!/usr/bin/env python3
"""Verify the byte-exact freeze manifest, bound to the freeze tag.

This is the Gate B byte check. It replaces `shasum -c`, which cannot validate a
manifest binding mode, blob identity, and size alongside a digest.

An earlier revision of this file passed four attacks that it should have failed, all
found by adversarial review rather than by its own tests:

  A. `chmod +x` on a frozen file with no `git add` — the index mode was unchanged, so
     reading mode from `git ls-files -s` saw nothing.
  B. a git-ignored `scripts/__pycache__/evil.pyc` — `git ls-files --others
     --exclude-standard` deliberately omits ignored files, so an unlisted file under a
     frozen prefix was invisible.
  C. replacing the whole `scripts/` directory with a symlink to an outside directory
     holding identical files — only the final path component was checked for symlinks.
  D. editing a frozen file, regenerating the manifest, and hand-preserving the old
     `frozen_snapshot_commit` string — nothing bound the manifest to the tag, so the
     freeze could be moved onto changed data.

The verifier therefore trusts the filesystem and the tag, not the index alone:

  1  manifest schema, canonical ordering, and MANIFEST_ROOT
  2  tag exists, is an annotated tag object, and peels to the expected commit
  3  sidecar `frozen_snapshot_commit` equals the peeled commit
  4  the tag annotation's MANIFEST_ROOT equals the sidecar's
  5  every manifest path, git mode, and blob oid equals `git ls-tree -r <tag>`
  6  every working-tree byte sequence equals the manifest
  7  physical executable bits match the recorded git mode
  8  every parent path component is a real directory, never a symlink
  9  every resolved path stays inside the repository root
 10  the physical filesystem under frozen prefixes is enumerated in full,
     including git-ignored files, and any unlisted entry fails

Usage:
    python research/verify_byte_manifest.py \
        --manifest research/qrs2026-byte-manifest.jsonl \
        --root . --tag qrs-2026-replication-v1 \
        --expect-entries 4842 --strict
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
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
FROZEN_ROOTS: tuple[str, ...] = tuple(p.rstrip("/") for p in FROZEN_PREFIXES)
FROZEN_FILES: tuple[str, ...] = ("requirements.txt",)
REQUIRED_KEYS = {"path", "git_mode", "git_blob_oid", "size_bytes", "sha256"}
# Line-anchored and exact. An unanchored pattern also matched misleading labels such
# as "NOT_MANIFEST_ROOT: <root>" or "XMANIFEST_ROOT: <root>", and tolerated trailing
# text after the digest, so provenance could be spoofed by decoration.
ROOT_IN_TAG = re.compile(r"(?m)^[ \t]*MANIFEST_ROOT:[ \t]*([0-9a-f]{64})[ \t]*$")


def is_frozen(rel_path: str) -> bool:
    return rel_path in FROZEN_FILES or rel_path.startswith(FROZEN_PREFIXES)


def git(root: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


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


def path_shape_problem(rel: str) -> str | None:
    if rel != rel.strip():
        return "leading or trailing whitespace"
    if rel.startswith("/"):
        return "absolute path"
    if "\\" in rel:
        return "backslash separator"
    if any(part in ("", ".", "..") for part in rel.split("/")):
        return "non-normalised component"
    return None


def exec_bit_fidelity() -> bool:
    """False on filesystems that cannot represent the executable bit."""
    return os.name == "posix"


def enumerate_physical(root: Path) -> tuple[set[str], list[str]]:
    """Every physical file under a frozen prefix, including git-ignored ones.

    `git ls-files --others --exclude-standard` is deliberately not used: it omits
    ignored files, which is how a `__pycache__/*.pyc` slipped past the previous
    implementation.
    """
    found: set[str] = set()
    symlinked_dirs: list[str] = []

    for name in FROZEN_FILES:
        if (root / name).exists():
            found.add(name)

    for top in FROZEN_ROOTS:
        base = root / top
        if not base.exists():
            continue
        if base.is_symlink():
            symlinked_dirs.append(top)
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            rel_dir = Path(dirpath).relative_to(root).as_posix()
            # Record and prune symlinked subdirectories rather than walking them.
            for d in list(dirnames):
                if (Path(dirpath) / d).is_symlink():
                    symlinked_dirs.append(f"{rel_dir}/{d}")
                    dirnames.remove(d)
            for fn in filenames:
                found.add(f"{rel_dir}/{fn}" if rel_dir != "." else fn)
    return found, symlinked_dirs


def parent_symlink(root: Path, rel: str) -> str | None:
    """Return the first parent component that is a symlink, if any."""
    current = root
    for part in Path(rel).parts[:-1]:
        current = current / part
        if current.is_symlink():
            return current.relative_to(root).as_posix()
    return None


def main() -> int:  # noqa: C901 - a verifier is a list of checks
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--expect-entries", type=int, default=None)
    ap.add_argument("--tag", default=None,
                    help="freeze tag the manifest must be bound to")
    ap.add_argument("--allow-unbound", action="store_true",
                    help="development only: skip tag binding (checks 2-5)")
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings as failures")
    ap.add_argument("--allow-missing-exec-bit-fidelity", action="store_true",
                    help="permitted on filesystems that cannot store the exec bit")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = args.root.resolve()
    root_file = args.manifest.with_suffix(".root")
    failures: list[str] = []
    warnings: list[str] = []
    notes: list[str] = []

    if args.tag is None and not args.allow_unbound:
        print("FAIL: TAG_BINDING_REQUIRED: pass --tag <freeze tag>, or --allow-unbound "
              "for a development check that does not prove the freeze")
        return 1

    # ---- 1. manifest load, schema, canonical form, root ---------------------
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
                f"MANIFEST_SCHEMA line {lineno}: keys {sorted(rec) if isinstance(rec, dict) else type(rec).__name__}"
                f" != {sorted(REQUIRED_KEYS)}"
            )
            continue
        records.append(rec)
        lines_raw.append(raw)

    if failures:
        return _report(failures, warnings, notes, 0, args.json, None, None)

    listed = {r["path"]: r for r in records}
    if len(listed) != len(records):
        failures.append("MANIFEST_DUPLICATE_PATHS: the same path appears more than once")

    canonical = [
        canonical_line(r) for r in sorted(records, key=lambda r: r["path"].encode("utf-8"))
    ]
    computed_root = hashlib.sha256(
        ("\n".join(canonical) + "\n").encode("utf-8")
    ).hexdigest()
    if lines_raw != canonical:
        failures.append("MANIFEST_NOT_CANONICAL: file lines differ from canonical sorted form")

    if args.expect_entries is not None and len(records) != args.expect_entries:
        failures.append(
            f"ENTRY_COUNT: manifest has {len(records)}, expected {args.expect_entries}"
        )

    recorded_root = None
    sidecar: dict = {}
    if not root_file.is_file():
        failures.append(f"MISSING_ROOT_SIDECAR: {root_file.name}")
    else:
        sidecar = json.loads(root_file.read_text(encoding="utf-8"))
        if sidecar.get("record_type") != "manifest_root":
            failures.append("ROOT_SIDECAR_SCHEMA: record_type != manifest_root")
        recorded_root = sidecar.get("manifest_root")
        if sidecar.get("entry_count") != len(records):
            failures.append(
                f"ROOT_ENTRY_COUNT: sidecar {sidecar.get('entry_count')} != manifest {len(records)}"
            )
        if recorded_root != computed_root:
            failures.append(
                f"MANIFEST_ROOT_MISMATCH: recorded {recorded_root} != computed {computed_root}"
            )

    for rel in listed:
        if (why := path_shape_problem(rel)) is not None:
            failures.append(f"PATH_NOT_NORMALISED: {rel} ({why})")
        if not is_frozen(rel):
            failures.append(f"PATH_OUTSIDE_FROZEN_SCOPE: {rel}")

    # ---- 2-5. tag binding ---------------------------------------------------
    if args.tag:
        tag_type = git(root, "cat-file", "-t", args.tag, check=False).strip()
        if tag_type != "tag":
            failures.append(
                f"TAG_NOT_ANNOTATED: {args.tag} is {tag_type or 'absent'}, expected an "
                f"annotated tag object"
            )
        else:
            peeled = git(root, "rev-parse", f"{args.tag}^{{commit}}").strip()
            claimed = sidecar.get("frozen_snapshot_commit")
            if claimed != peeled:
                failures.append(
                    f"TAG_COMMIT_MISMATCH: sidecar frozen_snapshot_commit {claimed} != "
                    f"tag {args.tag} peels to {peeled}"
                )
            annotation = git(root, "cat-file", "tag", args.tag)
            found_roots = ROOT_IN_TAG.findall(annotation)
            # Exactly one root, not "the right one is in there somewhere". An
            # annotation carrying several roots is ambiguous provenance: a reader
            # cannot tell which one the freeze claims, and a lenient parser would
            # accept a forged root sitting beside the real one.
            if not found_roots:
                failures.append(
                    f"TAG_ROOT_ABSENT: tag {args.tag} annotation records no MANIFEST_ROOT"
                )
            elif len(found_roots) > 1:
                failures.append(
                    f"TAG_ROOT_AMBIGUOUS: tag {args.tag} annotation records "
                    f"{len(found_roots)} MANIFEST_ROOT values "
                    f"({', '.join(r[:12] + '…' for r in found_roots)}); exactly one is required"
                )
            elif found_roots[0] != recorded_root:
                failures.append(
                    f"TAG_ROOT_MISMATCH: tag annotation MANIFEST_ROOT {found_roots[0]} != "
                    f"sidecar {recorded_root}"
                )

            # 5. manifest records must equal the tag tree exactly.
            tree: dict[str, tuple[str, str]] = {}
            for line in git(root, "ls-tree", "-r", "-z", args.tag).split("\0"):
                if not line:
                    continue
                meta, _, rel = line.partition("\t")
                mode, obj_type, oid = meta.split()[:3]
                if is_frozen(rel):
                    if obj_type != "blob":
                        failures.append(f"TAG_TREE_NON_BLOB: {rel} is {obj_type}")
                    tree[rel] = (mode, oid)
            for rel in sorted(set(tree) - set(listed)):
                failures.append(f"TAG_TREE_PATH_NOT_IN_MANIFEST: {rel}")
            for rel in sorted(set(listed) - set(tree)):
                failures.append(f"MANIFEST_PATH_NOT_IN_TAG_TREE: {rel}")
            for rel in sorted(set(tree) & set(listed)):
                mode, oid = tree[rel]
                if mode != listed[rel]["git_mode"]:
                    failures.append(
                        f"TAG_TREE_MODE_MISMATCH: {rel} tag {mode} != manifest "
                        f"{listed[rel]['git_mode']}"
                    )
                if oid != listed[rel]["git_blob_oid"]:
                    failures.append(
                        f"TAG_TREE_BLOB_MISMATCH: {rel} tag {oid[:12]}… != manifest "
                        f"{listed[rel]['git_blob_oid'][:12]}…"
                    )
    else:
        notes.append("TAG_BINDING_SKIPPED: --allow-unbound was passed; this run does "
                     "not prove the freeze")

    # ---- index state, used only as supporting evidence ---------------------
    index_mode: dict[str, str] = {}
    index_oid: dict[str, str] = {}
    for line in git(root, "ls-files", "-s", "-z").split("\0"):
        if not line:
            continue
        meta, _, rel = line.partition("\t")
        if is_frozen(rel):
            fields = meta.split()
            index_mode[rel], index_oid[rel] = fields[0], fields[1]

    # ---- 10. physical enumeration -----------------------------------------
    physical, symlinked_dirs = enumerate_physical(root)
    for rel in sorted(symlinked_dirs):
        failures.append(
            f"SYMLINKED_DIRECTORY_UNDER_FROZEN_PREFIX: {rel} is a symlink; a frozen "
            f"directory must be a real directory"
        )
    for rel in sorted(physical - set(listed)):
        failures.append(f"UNLISTED_PHYSICAL_FILE_UNDER_FROZEN_PREFIX: {rel}")
    for rel in sorted(set(listed) - physical):
        failures.append(f"MISSING_FILE: {rel}")

    # ---- 6-9. per-file checks ---------------------------------------------
    checked = 0
    fidelity = exec_bit_fidelity()
    if not fidelity:
        message = ("EXEC_BIT_FIDELITY_UNAVAILABLE: this filesystem cannot represent the "
                   "executable bit; physical mode checks are skipped")
        if args.allow_missing_exec_bit_fidelity:
            warnings.append(message)
        else:
            failures.append(message + " (pass --allow-missing-exec-bit-fidelity to accept)")

    for rel, rec in sorted(listed.items()):
        abs_path = root / rel

        if (bad_parent := parent_symlink(root, rel)) is not None:
            failures.append(
                f"SYMLINK_IN_PARENT_COMPONENT: {rel} traverses symlinked directory "
                f"{bad_parent}"
            )
            continue
        if not abs_path.exists():
            continue  # already reported as MISSING_FILE
        if abs_path.is_symlink():
            failures.append(f"SYMLINK_APPEARED: {rel}")
            continue

        st = abs_path.lstat()
        if not stat.S_ISREG(st.st_mode):
            failures.append(f"NOT_A_REGULAR_FILE: {rel} (mode {stat.S_IFMT(st.st_mode):#o})")
            continue
        try:
            resolved = abs_path.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            failures.append(f"PATH_ESCAPES_REPOSITORY: {rel} resolves outside {root.name}")
            continue

        # 7. physical executable bit vs recorded git mode
        if fidelity:
            physical_exec = bool(st.st_mode & 0o111)
            expected_exec = rec["git_mode"] == "100755"
            if physical_exec != expected_exec:
                failures.append(
                    f"PHYSICAL_MODE_CHANGED: {rel} recorded git mode {rec['git_mode']} "
                    f"but working-tree exec bit is {'set' if physical_exec else 'unset'} "
                    f"(st_mode {stat.S_IMODE(st.st_mode):#o})"
                )

        current_index_mode = index_mode.get(rel)
        if current_index_mode is not None and current_index_mode != rec["git_mode"]:
            failures.append(
                f"INDEX_MODE_CHANGED: {rel} {rec['git_mode']} -> {current_index_mode}"
            )

        current_oid = index_oid.get(rel)
        oid_matches = current_oid == rec["git_blob_oid"]
        if current_oid is not None and not oid_matches:
            failures.append(
                f"GIT_BLOB_CHANGED: {rel} {rec['git_blob_oid'][:12]}… -> {current_oid[:12]}…"
            )

        digest, size = sha256_of(abs_path)
        if digest != rec["sha256"]:
            classification = "SHA256_CHANGED"
            if oid_matches:
                blob = subprocess.run(
                    ["git", "-C", str(root), "cat-file", "blob", rec["git_blob_oid"]],
                    check=False, capture_output=True,
                ).stdout
                working = abs_path.read_bytes()
                if working.replace(b"\r\n", b"\n") == blob.replace(b"\r\n", b"\n"):
                    classification = "WORKING_TREE_BYTES_DIFFER_EOL_ONLY"
                else:
                    classification = "WORKING_TREE_CONTENT_CHANGED_UNSTAGED"

            if classification == "WORKING_TREE_BYTES_DIFFER_EOL_ONLY":
                failures.append(
                    f"WORKING_TREE_BYTES_DIFFER_EOL_ONLY: {rel} (stored blob content "
                    f"identical; only line endings differ from the LF checkout the "
                    f"manifest was built from)"
                )
            elif classification == "WORKING_TREE_CONTENT_CHANGED_UNSTAGED":
                failures.append(
                    f"SHA256_CHANGED: {rel} {rec['sha256'][:12]}… -> {digest[:12]}… "
                    f"(unstaged working-tree edit; the git index still holds the original "
                    f"blob, so this is a content change, not an encoding difference)"
                )
            else:
                failures.append(
                    f"SHA256_CHANGED: {rel} {rec['sha256'][:12]}… -> {digest[:12]}…"
                )
        if size != rec["size_bytes"]:
            failures.append(f"SIZE_CHANGED: {rel} {rec['size_bytes']} -> {size} bytes")
        checked += 1

    if args.strict:
        failures.extend(warnings)
        warnings = []

    return _report(failures, warnings, notes, checked, args.json, computed_root, recorded_root)


def _report(failures, warnings, notes, checked, as_json, computed, recorded) -> int:
    if as_json:
        print(json.dumps({
            "status": "FAIL" if failures else "PASS",
            "files_checked": checked,
            "failures": failures,
            "warnings": warnings,
            "notes": notes,
            "manifest_root_computed": computed,
            "manifest_root_recorded": recorded,
        }, indent=2))
    else:
        print(f"files checked:          {checked}")
        print(f"MANIFEST_ROOT computed: {computed}")
        print(f"MANIFEST_ROOT recorded: {recorded}")
        for n in notes:
            print(f"  NOTE {n}")
        for w in warnings:
            print(f"  WARN {w}")
        for f in failures:
            print(f"  FAIL {f}")
        print("FAIL" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
