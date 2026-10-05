"""Materialize ten archived TerraRepair repairs for the generic patch runner.

Reads only public, pinned source repositories and preserved repair records.
It does not generate repairs or invoke any model or scanner.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

COMMITS = {
    "terrarepair": "dd759a88ec831b6777132506b5a9d04522e92a57",
    "terragoat": "729f8da62c6a85ce4af5ad3d123de97776d954c4",
    "kaimonkey": "3feb0bf1a5ab81a79f225407a5ed16db3acd59a4",
}
SAMPLE_SHA256 = "5fae1316dd294bbfd0e4e2c6499490abae2547b02d9c9462dee54d8be34322bd"
# First ten PRIMARY_BASELINE_EXACT cases in the predeclared alpha7 manifest order.
# Selection is fixed by prior rank, not by alpha7 or 1.0 verdict.
SAMPLE_NUMBERS = (135, 66, 108, 30, 35, 61, 51, 69, 15, 122)
RESOURCE = re.compile(r'^\s*resource\s+"?(?P<kind>[A-Za-z0-9_-]+)"?\s+"(?P<name>[^"]+)"\s*\{')


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_checkout(path: Path, expected: str) -> Path:
    root = path.resolve(strict=True)
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                            text=True, check=True)
    if result.stdout.strip() != expected:
        raise ValueError(f"expected {expected} at {root}")
    if subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root,
                      capture_output=True, text=True, check=True).stdout.strip():
        raise ValueError(f"source checkout is dirty: {root}")
    return root


def source_root(record: dict, terragoat: Path, kaimonkey: Path) -> Path:
    repository = record.get("repository")
    if repository == "terragoat/aws":
        return terragoat / "terraform" / "aws"
    if repository in {"modules/compute", "scenarios/ssrf-iam-breach"}:
        return kaimonkey / "terraform" / "aws" / repository
    raise ValueError(f"unexpected source slice: {repository}")


def materialize(terrarepair: Path, terragoat: Path, kaimonkey: Path, output: Path) -> None:
    terrarepair = checked_checkout(terrarepair, COMMITS["terrarepair"])
    terragoat = checked_checkout(terragoat, COMMITS["terragoat"])
    kaimonkey = checked_checkout(kaimonkey, COMMITS["kaimonkey"])
    sample = terrarepair / "semantic_sample_llm_rated_gpt-5_4.json"
    if sha(sample) != SAMPLE_SHA256:
        raise ValueError("TerraRepair preserved sample hash differs")
    records = json.loads(sample.read_text(encoding="utf-8"))
    by_number = {record["number"]: record for record in records}
    if len(by_number) != len(records):
        raise ValueError("duplicate sample number")
    output = output.resolve()
    if output.exists():
        raise ValueError("output directory must be new")
    prepared = []
    for number in SAMPLE_NUMBERS:
        record = by_number[number]
        source = source_root(record, terragoat, kaimonkey)
        relative = Path(record["target_file"])
        if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".tf":
            raise ValueError(f"invalid target path in record {number}")
        target = source / relative
        if target.is_symlink() or not target.is_file():
            raise ValueError(f"missing or symlink target in record {number}")
        original = record["original_block"]
        repaired = record["repaired_block"]
        text = target.read_text(encoding="utf-8")
        if text.count(original) != 1 or original == repaired:
            raise ValueError(f"record {number} is not a unique, material baseline-exact repair")
        header = RESOURCE.match(original)
        if not header or RESOURCE.match(repaired) is None:
            raise ValueError(f"record {number} has an unparseable resource header")
        repaired_header = RESOURCE.match(repaired)
        if (header.group("kind"), header.group("name")) != (
            repaired_header.group("kind"), repaired_header.group("name")
        ):
            raise ValueError(f"record {number} changes the target resource identity")
        rule = record["rule_id"]
        if not re.fullmatch(r"CKV_[A-Z0-9_]+", rule):
            raise ValueError(f"record {number} has unsupported rule {rule}")
        for path in source.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"symlink in source snapshot: {path}")
        case_id = f"terrarepair-{number:03d}"
        before = output / "cases" / case_id / "before"
        before.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, before)
        after_text = text.replace(original, repaired, 1)
        diff_lines = list(difflib.unified_diff(
            text.splitlines(keepends=True), after_text.splitlines(keepends=True),
            fromfile=f"a/{relative.as_posix()}", tofile=f"b/{relative.as_posix()}",
        ))
        if not diff_lines:
            raise ValueError(f"record {number} produced no file diff")
        patch = output / "repairs" / f"{case_id}.patch"
        patch.parent.mkdir(parents=True, exist_ok=True)
        body = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                       for line in diff_lines)
        patch.write_text(f"diff --git a/{relative.as_posix()} b/{relative.as_posix()}\n"
                         + body, encoding="utf-8")
        prepared.append({"id": case_id,
                         "target": f"{rule}={header.group('kind')}.{header.group('name')}",
                         "sample_number": number, "source_repository": record["repository"],
                         "target_file": relative.as_posix(), "source_file_sha256": sha(target),
                         "original_block_sha256": hashlib.sha256(original.encode()).hexdigest(),
                         "repaired_block_sha256": hashlib.sha256(repaired.encode()).hexdigest(),
                         "patch_sha256": sha(patch)})
    (output / "cases.json").write_text(json.dumps({"schema": "iac-guard-repair-batch-v1",
                                                      "cases": [{"id": item["id"], "target": item["target"]}
                                                                for item in prepared]}, indent=2) + "\n",
                                         encoding="utf-8")
    (output / "provenance.json").write_text(json.dumps({"schema": "terrarepair-v1-adapter-provenance",
                                                         "source_commits": COMMITS,
                                                         "sample_sha256": SAMPLE_SHA256,
                                                         "selection": "first ten baseline-exact cases in prior predeclared alpha7 rank order",
                                                         "cases": prepared}, indent=2, sort_keys=True) + "\n",
                                             encoding="utf-8")
    print(f"prepared {len(prepared)} cases at {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terrarepair", type=Path, required=True)
    parser.add_argument("--terragoat", type=Path, required=True)
    parser.add_argument("--kaimonkey", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        materialize(args.terrarepair, args.terragoat, args.kaimonkey, args.output)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"adapter could not prepare inputs: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
