"""Reproduce one public IaCSecBench pair with IaC-Guard-V 1.0.

Source validation can be run with --check-only. The verification command is
reserved for the independent operator using the released binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SOURCE_COMMIT = "762d28e3d9cce4cf3bb3807a4b1f893a4d80a611"
CASE_ROOT = Path("benchmark/internal/cases")
BEFORE = CASE_ROOT / "ENC-UNENCRYPTED-VOLUME-VULN"
AFTER = CASE_ROOT / "ENC-UNENCRYPTED-VOLUME-SAFE"
TARGET = "CKV_AWS_3=aws_ebs_volume.target"
HASH_FILE = Path(__file__).with_name("inputs.sha256")


def command_output(command: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def expected_hashes() -> dict[Path, str]:
    expected: dict[Path, str] = {}
    for line in HASH_FILE.read_text(encoding="ascii").splitlines():
        digest, relative = line.split("  ", 1)
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or path in expected:
            raise ValueError(f"invalid input hash entry: {relative}")
        expected[path] = digest
    return expected


def validate_source(repo: Path) -> dict[str, str]:
    if command_output(["git", "rev-parse", "HEAD"], cwd=repo) != SOURCE_COMMIT:
        raise ValueError(f"IaCSecBench must be at exact commit {SOURCE_COMMIT}")
    if command_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo):
        raise ValueError("IaCSecBench worktree must be clean")

    expected = expected_hashes()
    actual: set[Path] = set()
    for directory in (BEFORE, AFTER):
        for path in (repo / directory).rglob("*"):
            if path.is_symlink():
                raise ValueError(f"case contains a symlink: {path}")
            if path.is_file():
                actual.add(path.relative_to(repo))
    if actual != set(expected):
        raise ValueError(
            f"case file set differs; missing={sorted(set(expected) - actual)}, "
            f"extra={sorted(actual - set(expected))}"
        )
    for relative, digest in expected.items():
        actual_digest = hashlib.sha256((repo / relative).read_bytes()).hexdigest()
        if actual_digest != digest:
            raise ValueError(f"input hash differs: {relative}")
    return {str(path): digest for path, digest in expected.items()}


def exact_executable(value: str, version: str) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"not an executable file: {path}")
    observed = command_output([str(path), "--version"])
    if not re.search(rf"(?<![0-9]){re.escape(version)}(?![0-9])", observed):
        raise ValueError(f"expected version {version}; observed {observed!r}")
    return path


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(args: argparse.Namespace) -> int:
    repo = Path(args.repo).expanduser().resolve(strict=True)
    hashes = validate_source(repo)
    if args.check_only:
        print(json.dumps({"source_commit": SOURCE_COMMIT, "inputs": hashes}, indent=2))
        return 0

    if not args.iac_guard or not args.checkov or not args.output:
        raise ValueError("--iac-guard, --checkov, and --output are required for a real run")
    guard = exact_executable(args.iac_guard, "1.0.0")
    checkov = exact_executable(args.checkov, "3.3.0")
    output = Path(args.output).expanduser().resolve()
    if output == repo or repo in output.parents:
        raise ValueError("output directory must be outside the IaCSecBench checkout")
    output.mkdir(parents=True, exist_ok=False)

    started = now_utc()
    doctor = subprocess.run(
        [str(guard), "doctor", "--mode", "local-trusted", "--checkov-executable", str(checkov)],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    (output / "doctor.stdout.txt").write_text(doctor.stdout, encoding="utf-8")
    (output / "doctor.stderr.txt").write_text(doctor.stderr, encoding="utf-8")
    if doctor.returncode != 0:
        (output / "run-summary.json").write_text(
            json.dumps(
                {
                    "case": "ENC_UNENCRYPTED_VOLUME",
                    "source_commit": SOURCE_COMMIT,
                    "input_sha256": hashes,
                    "phase": "environment_doctor",
                    "doctor_exit_code": doctor.returncode,
                    "started_utc": started,
                    "completed_utc": now_utc(),
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"environment doctor failed; inspect {output}", file=sys.stderr)
        return 4

    report = output / "report.json"
    command = [
        str(guard),
        "verify",
        "--before",
        str(repo / BEFORE),
        "--after",
        str(repo / AFTER),
        "--framework",
        "terraform",
        "--local-trusted",
        "--checkov-executable",
        str(checkov),
        "--target",
        TARGET,
        "--format",
        "json",
        "--output",
        str(report),
        "--quiet",
    ]
    completed = subprocess.run(
        command, cwd=repo, capture_output=True, text=True, check=False, timeout=900
    )
    (output / "verify.stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (output / "verify.stderr.txt").write_text(completed.stderr, encoding="utf-8")

    try:
        payload = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else None
    except json.JSONDecodeError:
        payload = None
    verdict = payload.get("verdict") if isinstance(payload, dict) else None
    report_exit = payload.get("exit_code") if isinstance(payload, dict) else None
    verification = payload.get("verification") if isinstance(payload, dict) else None
    targets = verification.get("targets") if isinstance(verification, dict) else None
    target = targets[0] if isinstance(targets, list) and len(targets) == 1 else None
    identity = target.get("identity") if isinstance(target, dict) else None
    target_fixed = (
        isinstance(target, dict)
        and target.get("outcome") == "FIXED"
        and isinstance(identity, dict)
        and identity.get("scanner") == "checkov"
        and identity.get("rule_id") == "CKV_AWS_3"
        and identity.get("scope") == "aws_ebs_volume.target"
    )
    summary = {
        "case": "ENC_UNENCRYPTED_VOLUME",
        "source_commit": SOURCE_COMMIT,
        "input_sha256": hashes,
        "iac_guard_v_version": "1.0.0",
        "checkov_version": "3.3.0",
        "target": TARGET,
        "started_utc": started,
        "completed_utc": now_utc(),
        "process_exit_code": completed.returncode,
        "report_exit_code": report_exit,
        "report_schema": payload.get("schema_version") if isinstance(payload, dict) else None,
        "result_kind": payload.get("result_kind") if isinstance(payload, dict) else None,
        "verdict": verdict,
        "target_fixed": target_fixed,
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest()
        if report.is_file()
        else None,
    }
    (output / "run-summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, sort_keys=True, indent=2))
    if (
        summary["report_schema"] != "report-v1"
        or report_exit != completed.returncode
        or (verdict == "VERIFIED" and summary["result_kind"] != "verification")
        or (verdict == "VERIFIED" and not target_fixed)
    ):
        return 4
    return 0 if verdict == "VERIFIED" and completed.returncode == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="clean IaCSecBench v2.1.0 checkout")
    parser.add_argument("--iac-guard", help="IaC-Guard-V 1.0.0 executable")
    parser.add_argument("--checkov", help="Checkov 3.3.0 executable")
    parser.add_argument("--output", help="new output directory outside IaCSecBench")
    parser.add_argument("--check-only", action="store_true", help="validate source without running tools")
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"rerun could not complete: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
