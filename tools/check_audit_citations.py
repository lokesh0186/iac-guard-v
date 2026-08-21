#!/usr/bin/env python3
"""Gate A: verify the current-state audit cites concrete repository evidence.

An audit that says "the verifier is unsafe" is not actionable. An audit that says
"scripts/verify_patch.py:66 returns {} on empty stdout" is. This checker enforces
the difference mechanically: every citation must name a file that exists and a
line number that is within that file's line count.

Usage:
    python tools/check_audit_citations.py docs/spec/CURRENT_STATE_AUDIT.md --min 15
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Matches `path/to/file.py:123` or `path/to/file.py:123-456`, optionally inside
# backticks. Deliberately requires a file extension so prose like "Section 3:12"
# is not mistaken for a citation.
CITATION = re.compile(
    r"(?P<path>[A-Za-z0-9_./-]+\.(?:py|md|csv|json|yml|yaml|txt|cff|pdf|tf))"
    r":(?P<start>\d+)(?:-(?P<end>\d+))?"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("audit", type=Path)
    ap.add_argument("--min", type=int, default=15, help="minimum valid citations")
    ap.add_argument("--root", type=Path, default=Path("."))
    args = ap.parse_args()

    if not args.audit.is_file():
        print(f"FAIL: audit file not found: {args.audit}")
        return 1

    text = args.audit.read_text(encoding="utf-8")
    seen: set[tuple[str, int]] = set()
    valid: list[str] = []
    problems: list[str] = []

    for m in CITATION.finditer(text):
        rel, start = m.group("path"), int(m.group("start"))
        end = int(m.group("end") or start)
        key = (rel, start)
        target = args.root / rel

        if not target.is_file():
            problems.append(f"cited file does not exist: {rel} (at :{start})")
            continue
        try:
            n_lines = sum(1 for _ in target.open("rb"))
        except OSError as exc:  # pragma: no cover - unreadable file
            problems.append(f"cited file unreadable: {rel} ({exc})")
            continue
        if start < 1 or end > n_lines or end < start:
            problems.append(
                f"citation out of range: {rel}:{start}"
                f"{'-' + str(end) if end != start else ''} (file has {n_lines} lines)"
            )
            continue
        if key not in seen:
            seen.add(key)
            valid.append(f"{rel}:{start}")

    print(f"distinct valid citations: {len(valid)} (minimum {args.min})")
    for c in sorted(valid):
        print(f"  OK  {c}")
    for p in problems:
        print(f"  BAD {p}")

    if problems:
        print(f"FAIL: {len(problems)} invalid citation(s)")
        return 1
    if len(valid) < args.min:
        print(f"FAIL: {len(valid)} valid citations < required {args.min}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
