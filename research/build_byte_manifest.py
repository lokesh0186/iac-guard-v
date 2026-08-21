#!/usr/bin/env python3
"""Build the byte-exact freeze manifest for the QRS 2026 research artifact.

The manifest binds four properties per file — repository-relative path, git mode,
byte size, and SHA-256 of the raw bytes — with **no normalisation of any kind**.
Line endings, trailing newlines, and encodings are preserved exactly as stored.

Two separate artifacts are produced, deliberately:

  research/qrs2026-byte-manifest.jsonl   exactly one JSON record per frozen file
  research/qrs2026-byte-manifest.root    a typed sidecar holding MANIFEST_ROOT

The root digest lives in the sidecar so that the JSONL record count is
unambiguously the file count and nothing else. A metadata record mixed into the
JSONL would make "4,842 entries" mean two different things.

Usage:
    python research/build_byte_manifest.py --root . --output-dir research
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

# Frozen prefixes. A path is frozen if it equals, or is under, one of these.
FROZEN_PREFIXES: tuple[str, ...] = (
    "benchmark/",
    "runs/",
    "results/",
    "prompts/",
    "scanners/",
    "scripts/",
)
FROZEN_FILES: tuple[str, ...] = ("requirements.txt",)

MANIFEST_NAME = "qrs2026-byte-manifest.jsonl"
ROOT_NAME = "qrs2026-byte-manifest.root"
ROOT_RECORD_TYPE = "manifest_root"
ALGORITHM = "sha256-jsonl-v1"


def is_frozen(rel_path: str) -> bool:
    return rel_path in FROZEN_FILES or rel_path.startswith(FROZEN_PREFIXES)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def tracked_frozen_entries(root: Path) -> list[tuple[str, str, str]]:
    """Return sorted (rel_path, git_mode, git_blob_oid) for every tracked frozen file."""
    out = git(root, "ls-files", "-s", "-z")
    entries: list[tuple[str, str, str]] = []
    for record in out.split("\0"):
        if not record:
            continue
        meta, _, rel = record.partition("\t")
        fields = meta.split()
        mode, oid = fields[0], fields[1]
        if is_frozen(rel):
            entries.append((rel, mode, oid))
    entries.sort(key=lambda e: e[0].encode("utf-8"))
    return entries


def sha256_of(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def canonical_line(record: dict) -> str:
    """One canonical serialisation, used for both the file and the root digest."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def manifest_root(lines: list[str]) -> str:
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--output-dir", type=Path, default=Path("research"))
    ap.add_argument("--commit", default=None, help="commit the manifest is built from")
    ap.add_argument(
        "--frozen-snapshot-commit",
        default=None,
        help=(
            "REQUIRED for canonical output. The pre-productization commit the freeze "
            "represents; the frozen scope must be identical between it and the build tree."
        ),
    )
    ap.add_argument(
        "--unbound-development-output",
        default=None,
        help=(
            "development only: write an unbound manifest to this non-canonical filename "
            "stem instead of the canonical one. Cannot be combined with canonical output."
        ),
    )
    args = ap.parse_args()

    # An unbound manifest must never be able to become the canonical one: that is the
    # artifact the freeze tag is bound to, and a manifest with no snapshot binding can
    # be regenerated over changed research data.
    if not args.frozen_snapshot_commit and not args.unbound_development_output:
        print("FAIL: SNAPSHOT_BINDING_REQUIRED: pass --frozen-snapshot-commit <sha> to "
              "write the canonical manifest, or --unbound-development-output <stem> to "
              "write a non-canonical development copy.")
        return 1
    if args.frozen_snapshot_commit and args.unbound_development_output:
        print("FAIL: pass either --frozen-snapshot-commit or "
              "--unbound-development-output, not both.")
        return 1

    root = args.root.resolve()
    entries = tracked_frozen_entries(root)
    if not entries:
        print("FAIL: no frozen files found; wrong --root?")
        return 1

    lines: list[str] = []
    symlinks: list[str] = []
    for rel, mode, oid in entries:
        abs_path = root / rel
        if abs_path.is_symlink() or mode == "120000":
            symlinks.append(rel)
            continue
        digest, size = sha256_of(abs_path)
        lines.append(
            canonical_line(
                {
                    "path": rel,
                    "git_mode": mode,
                    "git_blob_oid": oid,
                    "size_bytes": size,
                    "sha256": digest,
                }
            )
        )

    if symlinks:
        print(f"FAIL: refusing to freeze symlinks: {symlinks[:5]}")
        return 1

    commit = args.commit or git(root, "rev-parse", "HEAD").strip()
    root_digest = manifest_root(lines)

    snapshot = args.frozen_snapshot_commit
    if snapshot:
        # The manifest may be generated from a later working tree, but only if the
        # frozen scope is byte-identical to the snapshot it claims to represent.
        drift = git(
            root, "diff", "--name-only", snapshot, "--",
            *FROZEN_PREFIXES, *FROZEN_FILES,
        ).strip()
        if drift:
            print("FAIL: frozen scope differs from the claimed snapshot commit:")
            for line in drift.splitlines()[:20]:
                print(f"  {line}")
            return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.unbound_development_output:
        stem = args.unbound_development_output
        if stem in (MANIFEST_NAME, ROOT_NAME, "qrs2026-byte-manifest"):
            print("FAIL: refusing to write an unbound manifest under the canonical name")
            return 1
        manifest_path = args.output_dir / f"{stem}.jsonl"
        root_path = args.output_dir / f"{stem}.root"
    else:
        manifest_path = args.output_dir / MANIFEST_NAME
        root_path = args.output_dir / ROOT_NAME

    # Written with explicit "\n" so the manifest itself is byte-stable.
    with manifest_path.open("w", encoding="utf-8", newline="\n") as fh:
        for line in lines:
            fh.write(line + "\n")

    sidecar = {
        "record_type": ROOT_RECORD_TYPE,
        "algorithm": ALGORITHM,
        "manifest_file": manifest_path.name,
        "entry_count": len(lines),
        "manifest_root": root_digest,
        "built_from_commit": commit,
        "frozen_snapshot_commit": snapshot,
        "frozen_prefixes": list(FROZEN_PREFIXES),
        "frozen_files": list(FROZEN_FILES),
        "normalisation": "none",
        "note": (
            "manifest_root is sha256 over the canonical sorted JSONL record lines "
            "joined by \\n with a trailing \\n. It is stored here, outside the "
            "JSONL, so entry_count is exactly the frozen file count."
        ),
    }
    with root_path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(sidecar, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(f"entries:       {len(lines)}")
    print(f"MANIFEST_ROOT: {root_digest}")
    print(f"built_from:    {commit}")
    print(f"snapshot:      {snapshot}")
    print(f"written:       {manifest_path}")
    print(f"written:       {root_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
