"""Run released IaC-Guard-V against externally supplied, local repair patches."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
MAX_PATCH_BYTES = 1_000_000
MAX_CASES = 100


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    content = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink in case tree: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content.update(len(relative).to_bytes(8, "big"))
            content.update(relative)
            content.update(bytes.fromhex(digest(path)))
    return content.hexdigest()


def safe_case(root: Path, case: dict) -> tuple[str, Path, Path, str]:
    if not isinstance(case, dict):
        raise ValueError("each case must be an object")
    case_id = case.get("id")
    target = case.get("target")
    if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
        raise ValueError(f"invalid case id: {case_id!r}")
    if not isinstance(target, str) or not re.fullmatch(r"CKV_[A-Z0-9_]+=[^\s=]+", target):
        raise ValueError(f"invalid exact Checkov target in {case_id}")
    before = root / "cases" / case_id / "before"
    patch = root / "repairs" / f"{case_id}.patch"
    for path in (root / "cases", root / "cases" / case_id, before, root / "repairs", patch):
        if path.is_symlink():
            raise ValueError(f"symlink in case path: {path}")
    if not before.is_dir() or not patch.is_file():
        raise ValueError(f"missing before directory or patch for {case_id}")
    if patch.stat().st_size > MAX_PATCH_BYTES:
        raise ValueError(f"patch exceeds {MAX_PATCH_BYTES} bytes: {case_id}")
    tree_digest(before)
    return case_id, before, patch, target


def validate_patch(patch: Path) -> None:
    payload = patch.read_text(encoding="utf-8")
    headers = re.findall(r"^diff --git a/(.+) b/(.+)$", payload, re.MULTILINE)
    if not headers:
        raise ValueError(f"patch has no git diff headers: {patch}")
    if any(line.startswith(("GIT binary patch", "Binary files ", "rename from ", "copy from ",
                             "new file mode 120000", "old mode 120000"))
           for line in payload.splitlines()):
        raise ValueError(f"unsupported binary, rename, copy, or symlink patch: {patch}")
    for old, new in headers:
        for value in (old, new):
            path = Path(value)
            if (path.is_absolute() or ".." in path.parts or ".git" in path.parts
                    or any(part in {"", "."} for part in path.parts)):
                raise ValueError(f"unsafe patch path: {value}")


def run_command(command: list[str], *, cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False,
                              timeout=timeout, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    except subprocess.TimeoutExpired as error:
        return subprocess.CompletedProcess(command, 124, "", f"timed out after {error.timeout} seconds")


def version(executable: Path, expected: str) -> None:
    result = run_command([str(executable), "--version"], timeout=30)
    if result.returncode or not re.search(rf"(?<![0-9]){re.escape(expected)}(?![0-9])", result.stdout):
        raise ValueError(f"expected {expected} from {executable}; observed {result.stdout!r} {result.stderr!r}")


def consistent_report(payload: object, process_exit: int, target: str) -> bool:
    if not isinstance(payload, dict) or payload.get("schema_version") != "report-v1":
        return False
    verdict = payload.get("verdict")
    if (verdict, payload.get("result_kind"), payload.get("exit_code"), process_exit) not in {
        ("VERIFIED", "verification", 0, 0),
        ("FAILED", "verification", 1, 1),
        ("INCONCLUSIVE", "operational_uncertainty", 3, 3),
    }:
        return False
    if verdict != "VERIFIED":
        return True
    verification = payload.get("verification")
    targets = verification.get("targets") if isinstance(verification, dict) else None
    selected = targets[0] if isinstance(targets, list) and len(targets) == 1 else None
    identity = selected.get("identity") if isinstance(selected, dict) else None
    rule, scope = target.split("=", 1)
    return (isinstance(selected, dict) and selected.get("outcome") == "FIXED"
            and isinstance(identity, dict) and identity.get("scanner") == "checkov"
            and identity.get("rule_id") == rule and identity.get("scope") == scope)


def evaluate(root: Path, output: Path, guard: Path, checkov: Path) -> int:
    root = root.resolve(strict=True)
    output = output.resolve()
    if output == root or root in output.parents or output.exists():
        raise ValueError("output must be a new directory outside the input root")
    manifest = root / "cases.json"
    if manifest.is_symlink():
        raise ValueError("symlink manifest is forbidden")
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != "iac-guard-repair-batch-v1":
        raise ValueError("expected iac-guard-repair-batch-v1 manifest")
    entries = raw.get("cases")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_CASES:
        raise ValueError(f"expected 1–{MAX_CASES} cases")
    cases = [safe_case(root, item) for item in entries]
    if len({item[0] for item in cases}) != len(cases):
        raise ValueError("duplicate case id")
    for _, _, patch, _ in cases:
        validate_patch(patch)
    guard = guard.resolve(strict=True)
    checkov = checkov.resolve(strict=True)
    version(guard, "1.0.0")
    version(checkov, "3.3.0")
    doctor = run_command([str(guard), "doctor", "--mode", "local-trusted",
                          "--checkov-executable", str(checkov)], timeout=120)
    if doctor.returncode:
        raise RuntimeError(f"environment doctor failed: {doctor.stdout.strip()} {doctor.stderr.strip()}")
    output.mkdir(parents=True)
    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="iacgv-repair-eval-") as temporary:
        workspace = Path(temporary)
        for case_id, before, patch, target in cases:
            case_out = output / case_id
            case_out.mkdir()
            candidate = workspace / case_id
            shutil.copytree(before, candidate)
            before_sha = tree_digest(before)
            patch_sha = digest(patch)
            apply_check = run_command(["git", "apply", "--check", str(patch)], cwd=candidate, timeout=30)
            if apply_check.returncode:
                result = {"id": case_id, "status": "PATCH_ERROR", "verdict": None,
                          "process_exit_code": None, "before_tree_sha256": before_sha,
                          "patch_sha256": patch_sha, "report_sha256": None,
                          "detail": apply_check.stderr.strip()}
            else:
                applied = run_command(["git", "apply", str(patch)], cwd=candidate, timeout=30)
                if applied.returncode:
                    result = {"id": case_id, "status": "PATCH_ERROR", "verdict": None,
                              "process_exit_code": None, "before_tree_sha256": before_sha,
                              "patch_sha256": patch_sha, "report_sha256": None,
                              "detail": applied.stderr.strip()}
                    results.append(result)
                    continue
                after_sha = tree_digest(candidate)
                report = case_out / "report.json"
                completed = run_command([
                    str(guard), "verify", "--before", str(before), "--after", str(candidate),
                    "--framework", "terraform", "--local-trusted", "--checkov-executable",
                    str(checkov), "--target", target, "--format", "json", "--output",
                    str(report), "--quiet"], timeout=900)
                (case_out / "verify.stdout.txt").write_text(completed.stdout, encoding="utf-8")
                (case_out / "verify.stderr.txt").write_text(completed.stderr, encoding="utf-8")
                try:
                    payload = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else None
                except json.JSONDecodeError:
                    payload = None
                verdict = payload.get("verdict") if isinstance(payload, dict) else None
                valid = consistent_report(payload, completed.returncode, target)
                if isinstance(payload, dict) and report.is_file():
                    explained = run_command([str(guard), "explain", str(report)], timeout=120)
                    (case_out / "explain.stdout.txt").write_text(explained.stdout, encoding="utf-8")
                    (case_out / "explain.stderr.txt").write_text(explained.stderr, encoding="utf-8")
                    valid = valid and explained.returncode == 0
                result = {"id": case_id, "status": verdict if valid else "OPERATIONAL_ERROR",
                          "verdict": verdict, "process_exit_code": completed.returncode,
                          "before_tree_sha256": before_sha, "after_tree_sha256": after_sha,
                          "patch_sha256": patch_sha,
                          "report_sha256": digest(report) if report.is_file() else None,
                          "detail": None if valid else "missing, invalid, or inconsistent report-v1"}
            results.append(result)
    summary = {status: sum(item["status"] == status for item in results)
               for status in ("VERIFIED", "FAILED", "INCONCLUSIVE", "PATCH_ERROR", "OPERATIONAL_ERROR")}
    (output / "results.json").write_text(json.dumps({"schema": "iac-guard-repair-results-v1",
                                                        "cases": results, "counts": summary}, indent=2, sort_keys=True) + "\n",
                                          encoding="utf-8")
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "status", "verdict", "process_exit_code",
                                                      "before_tree_sha256", "after_tree_sha256",
                                                      "patch_sha256", "report_sha256", "detail"],
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
    receipt = {"schema": "iac-guard-repair-receipt-v1",
               "meaning": "Unsigned run record; inspect raw reports before citing outcomes",
               "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "manifest_sha256": digest(manifest), "iac_guard_v_version": "1.0.0",
               "checkov_version": "3.3.0", "iac_guard_executable_sha256": digest(guard),
               "checkov_executable_sha256": digest(checkov),
               "results_sha256": digest(output / "results.json"),
               "summary_csv_sha256": digest(output / "summary.csv")}
    (output / "verification_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                                                        encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["VERIFIED"] == len(results) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iac-guard", type=Path, required=True)
    parser.add_argument("--checkov", type=Path, required=True)
    args = parser.parse_args()
    try:
        return evaluate(args.input, args.output, args.iac_guard, args.checkov)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"evaluation could not complete: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
