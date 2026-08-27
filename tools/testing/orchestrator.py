"""Bounded orchestration for matrix and pre-PR profiles."""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence

from .env_manager import HarnessError, repository_root
from .results import RunSummary


SUPPORTED_PYTHONS = ("3.10", "3.11", "3.12", "3.13")
MATRIX_DEFAULT_PARALLELISM = 4


def _parallelism() -> int:
    raw = os.environ.get("IACGV_MATRIX_JOBS", str(MATRIX_DEFAULT_PARALLELISM))
    try:
        value = int(raw)
    except ValueError as exc:
        raise HarnessError("PARALLELISM_BENCHMARK_UNSAFE: jobs must be an integer") from exc
    if not 1 <= value <= len(SUPPORTED_PYTHONS):
        raise HarnessError("PARALLELISM_BENCHMARK_UNSAFE: jobs must be between 1 and 4")
    return value


def _child_environment(identifier: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({
        "IACGV_TEST_RUN_ID": identifier,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    })
    return environment


def _run_nox(
    root: Path, session: str, arguments: Sequence[str], identifier: str,
) -> tuple[str, int, float]:
    command = [sys.executable, "-m", "nox", "-s", session]
    if arguments:
        command.extend(("--", *arguments))
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=root,
        env=_child_environment(identifier),
        check=False,
    )
    return session, completed.returncode, time.monotonic() - started


def _add_child_result(
    root: Path,
    summary: RunSummary,
    *,
    child_identifier: str,
    identity: str,
    returncode: int,
    duration_seconds: float,
) -> None:
    child_summary = root / ".test-results" / child_identifier / "summary.json"
    if child_summary.is_file() and not child_summary.is_symlink():
        summary.add_child_summary(
            child_summary,
            identity=identity,
            returncode=returncode,
            duration_seconds=duration_seconds,
        )
        return
    summary.add_command(
        identity=identity,
        returncode=returncode,
        duration_seconds=duration_seconds,
    )


def run_matrix(root: Path, summary: RunSummary) -> bool:
    jobs = _parallelism()
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        for version in SUPPORTED_PYTHONS:
            session = f"tests-{version}"
            identifier = f"{summary.identifier}-py{version.replace('.', '')}"
            futures.append(executor.submit(_run_nox, root, session, ("matrix",), identifier))
        results = [future.result() for future in futures]
    success = True
    for session, returncode, duration in sorted(results):
        version = session.removeprefix("tests-")
        identifier = f"{summary.identifier}-py{version.replace('.', '')}"
        _add_child_result(
            root,
            summary,
            child_identifier=identifier,
            identity=session,
            returncode=returncode,
            duration_seconds=duration,
        )
        success = success and returncode == 0
    for metadata in sorted((root / ".nox").glob(f"tests-*/.iacgv-test-env.json")):
        summary.add_environment(metadata, reused=True)
    return success


def run_pr(root: Path, summary: RunSummary) -> bool:
    if not run_matrix(root, summary):
        return False
    for session in ("coverage", "checkov", "qrs", "package", "golden"):
        identity = f"{summary.identifier}-{session}"
        _name, returncode, duration = _run_nox(root, session, (), identity)
        _add_child_result(
            root,
            summary,
            child_identifier=identity,
            identity=session,
            returncode=returncode,
            duration_seconds=duration,
        )
        if returncode:
            return False
    scanner_metadata = (
        root / ".testenvs/scanners/checkov-3.3.0-py312/.iacgv-test-env.json"
    )
    if scanner_metadata.exists():
        summary.add_environment(scanner_metadata, reused=True)
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run bounded IaC-Guard-V test profiles")
    parser.add_argument("profile", choices=("matrix", "pr"))
    args = parser.parse_args(argv)
    root = repository_root()
    summary = RunSummary(root, args.profile)
    try:
        success = run_matrix(root, summary) if args.profile == "matrix" else run_pr(root, summary)
    except (HarnessError, OSError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        summary.finish(status="FAILED")
        return 2
    destination = summary.finish(status="PASS" if success else "FAILED")
    print(f"TEST_RESULT_SUMMARY={destination.relative_to(root)}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
