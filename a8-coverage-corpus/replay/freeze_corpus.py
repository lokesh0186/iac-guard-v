#!/usr/bin/env python3
"""Create or verify the permanent content lock for the a8 coverage corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXCLUDED_NAMES = {"CORPUS_CONTENT_LOCK.json"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def inventory(workspace: Path) -> list[dict]:
    corpus = workspace / "a8-coverage-corpus"
    paths = [
        workspace / "A8_55_SURFACE_CORPUS_MANIFEST.json",
        workspace / "A8_55_SURFACE_CORPUS_MANIFEST.md",
    ]
    paths.extend(sorted(path for path in corpus.rglob("*") if path.is_file()))
    rows = []
    for path in paths:
        if path.name in EXCLUDED_NAMES or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        rows.append({
            "path": path.relative_to(workspace).as_posix(),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        })
    return sorted(rows, key=lambda row: row["path"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    rows = inventory(workspace)
    root = canonical_sha(rows)
    lock = {
        "schema_version": "iac-guard-v-a8-coverage-corpus-content-lock-v1",
        "file_count": len(rows),
        "content_root_sha256": root,
        "files": rows,
    }
    if args.verify:
        existing = json.loads(args.output.read_text(encoding="utf-8"))
        if existing != lock:
            raise RuntimeError("CORPUS_CONTENT_LOCK_MISMATCH")
        print(json.dumps({"status": "PASS", "content_root_sha256": root}, sort_keys=True))
        return
    if args.output.exists():
        raise RuntimeError("CORPUS_CONTENT_LOCK_ALREADY_EXISTS")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
