"""Machine-readable diagnostics for substantial local test profiles."""
from __future__ import annotations

import datetime as dt
import json
import os
import platform
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .env_manager import (
    RESULT_SCHEMA,
    HarnessError,
    assert_managed_path,
    canonical_json,
    read_metadata,
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, text=True, check=True,
    )
    return completed.stdout.strip()


def run_id(profile: str) -> str:
    supplied = os.environ.get("IACGV_TEST_RUN_ID")
    if (
        supplied and len(supplied) <= 96
        and supplied.replace("-", "").replace("_", "").isalnum()
    ):
        return supplied
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{profile.replace('.', '-')}"


def junit_counts(path: Path) -> dict[str, int]:
    if not path.is_file():
        return {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    return {
        field: sum(int(suite.attrib.get(field, 0)) for suite in suites)
        for field in ("tests", "failures", "errors", "skipped")
    }


@dataclass(slots=True)
class RunSummary:
    root: Path
    profile: str
    identifier: str = field(init=False)
    started_utc: str = field(init=False)
    started_monotonic: float = field(init=False)
    commands: list[dict[str, object]] = field(default_factory=list)
    environments: list[dict[str, object]] = field(default_factory=list)
    coverage: dict[str, dict[str, object]] = field(default_factory=dict)
    qrs: dict[str, object] | None = None

    def __post_init__(self) -> None:
        self.identifier = run_id(self.profile)
        self.started_utc = _utc_now()
        self.started_monotonic = time.monotonic()

    @property
    def directory(self) -> Path:
        managed = self.root / ".test-results"
        if managed.is_symlink():
            raise HarnessError("TEST_RESULT_PATH_UNSAFE: .test-results is a symlink")
        managed.mkdir(parents=True, exist_ok=True)
        path = managed / self.identifier
        assert_managed_path(self.root, path)
        if path.is_symlink():
            raise HarnessError("TEST_RESULT_PATH_UNSAFE: run directory is a symlink")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def junit_path(self, name: str) -> Path:
        return self.directory / f"{name}.xml"

    def add_command(
        self, *, identity: str, returncode: int, duration_seconds: float,
        junit: Path | None = None, counts: Mapping[str, int] | None = None,
    ) -> None:
        self.commands.append({
            "identity": identity,
            "returncode": returncode,
            "duration_seconds": round(duration_seconds, 3),
            "counts": dict(counts) if counts is not None else (
                junit_counts(junit) if junit else None
            ),
        })

    def add_coverage(self, identity: str, path: Path) -> None:
        """Retain only aggregate coverage facts, never source file paths."""
        payload = json.loads(path.read_text(encoding="utf-8"))
        totals = payload["totals"]
        self.coverage[identity] = {
            key: totals[key]
            for key in (
                "covered_lines",
                "num_statements",
                "percent_covered",
                "percent_covered_display",
                "missing_lines",
                "excluded_lines",
                "num_branches",
                "covered_branches",
                "missing_branches",
            )
            if key in totals
        }

    def add_child_summary(
        self, path: Path, *, identity: str, returncode: int,
        duration_seconds: float,
    ) -> None:
        """Aggregate a bounded child profile without copying paths or commands."""
        payload = json.loads(path.read_text(encoding="utf-8"))
        counts = payload.get("test_counts")
        self.add_command(
            identity=identity,
            returncode=returncode,
            duration_seconds=duration_seconds,
            counts=counts if isinstance(counts, dict) else None,
        )
        child_coverage = payload.get("coverage")
        if isinstance(child_coverage, dict):
            for name, result in child_coverage.items():
                if isinstance(name, str) and isinstance(result, dict):
                    self.coverage[name] = result
        child_qrs = payload.get("qrs")
        if isinstance(child_qrs, dict):
            self.qrs = child_qrs

    def add_environment(self, metadata_path: Path, *, reused: bool) -> None:
        metadata = read_metadata(metadata_path)
        self.environments.append({
            "kind": metadata.get("kind"),
            "session": metadata.get("session"),
            "environment_fingerprint": metadata.get("environment_fingerprint"),
            "python": metadata.get("python"),
            "scanner_identity": metadata.get("scanner_identity"),
            "reused": reused,
        })

    def finish(self, *, status: str) -> Path:
        tests = failures = errors = skipped = 0
        for command in self.commands:
            counts = command.get("counts")
            if not counts:
                continue
            tests += int(counts["tests"])
            failures += int(counts["failures"])
            errors += int(counts["errors"])
            skipped += int(counts["skipped"])
        payload: Mapping[str, object] = {
            "schema": RESULT_SCHEMA,
            "profile": self.profile,
            "git_commit": _git(self.root, "rev-parse", "HEAD"),
            "dirty": bool(_git(self.root, "status", "--porcelain=v1", "-uall")),
            "started_utc": self.started_utc,
            "ended_utc": _utc_now(),
            "duration_seconds": round(time.monotonic() - self.started_monotonic, 3),
            "architecture": platform.machine(),
            "commands": self.commands,
            "environments": self.environments,
            "test_counts": {
                "tests": tests,
                "failures": failures,
                "errors": errors,
                "skipped": skipped,
            },
            "coverage": self.coverage,
            "qrs": self.qrs,
            "status": status,
        }
        destination = self.directory / "summary.json"
        destination.write_bytes(canonical_json(payload))
        return destination
