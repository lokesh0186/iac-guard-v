"""Capture Trivy #11192 source-precedence behavior from exact PR revisions."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

PR_HEAD = "d3ad0f949a529c47f451a9859b09e60a6a6294de"
PR_BASE = "99fde13b1439de741034e564c22b358b4880bbe8"
HERE = Path(__file__).resolve().parent


def run(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False, timeout=900)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", choices=("base", "fix"), required=True)
    parser.add_argument("--trivy", type=Path, required=True, help="binary built from selected revision")
    parser.add_argument("--checkout", type=Path, required=True, help="Trivy checkout at selected revision")
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    expected_commit = PR_BASE if args.revision == "base" else PR_HEAD
    checkout = args.checkout.resolve(strict=True)
    head = run(["git", "rev-parse", "HEAD"], checkout)
    if head.returncode or head.stdout.strip() != expected_commit:
        raise ValueError(f"expected Trivy {args.revision} {expected_commit}, found {head.stdout.strip()}")
    trivy = args.trivy.resolve(strict=True)
    provenance = run(["go", "version", "-m", str(trivy)])
    if (provenance.returncode or f"vcs.revision={expected_commit}" not in provenance.stdout
            or "vcs.modified=true" in provenance.stdout):
        raise ValueError("Trivy binary must embed the clean, selected commit as its VCS revision")
    output = args.output.resolve()
    if output.exists() or output == HERE or HERE in output.parents:
        raise ValueError("output must be a new directory outside this packet")
    expected: dict[str, str] = {}
    for line in (HERE / "inputs.sha256").read_text(encoding="ascii").splitlines():
        digest, name = line.split("  ", 1)
        expected[name] = digest
    actual = {path.relative_to(HERE).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in (HERE / "fixtures").rglob("*") if path.is_file() and not path.is_symlink()}
    if actual != expected:
        raise ValueError("fixture file set or hashes differ from inputs.sha256")
    output.mkdir(parents=True)
    binary_sha = hashlib.sha256(trivy.read_bytes()).hexdigest()
    version = run([str(trivy), "--version"])
    observations = []
    for name in ("hcl", "json", "cross"):
        result_file = output / f"{name}.json"
        completed = run([str(trivy), "config", "--misconfig-scanners", "terraform", "--include-non-failures",
                         "--skip-check-update", "--disable-telemetry", "--format", "json",
                         "--output", str(result_file), f"fixtures/{name}"], cwd=HERE)
        (output / f"{name}.stdout.txt").write_text(completed.stdout, encoding="utf-8")
        (output / f"{name}.stderr.txt").write_text(completed.stderr, encoding="utf-8")
        try:
            payload = json.loads(result_file.read_text(encoding="utf-8")) if result_file.is_file() else None
        except json.JSONDecodeError:
            payload = None
        results = payload.get("Results") if isinstance(payload, dict) else None
        observations.append({"case": name, "exit_code": completed.returncode,
                             "targets": [item.get("Target") for item in results if isinstance(item, dict)]
                             if isinstance(results, list) else None,
                             "report_sha256": hashlib.sha256(result_file.read_bytes()).hexdigest()
                             if result_file.is_file() else None})
    summary = {"revision": args.revision, "trivy_source_commit": expected_commit,
               "trivy_binary_sha256": binary_sha,
               "trivy_version": version.stdout.strip(), "fixture_sha256": expected,
               "go_build_vcs_revision": expected_commit,
               "go_build_vcs_modified": "vcs.modified=true" in provenance.stdout,
               "observations": observations,
               "interpretation": "Raw capture only; compare findings and parser test against source-precedence expectation"}
    (output / "run-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                                              encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if all(item["exit_code"] == 0 and item["report_sha256"] for item in observations) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"reproduction could not complete: {error}", file=sys.stderr)
        raise SystemExit(4) from error
