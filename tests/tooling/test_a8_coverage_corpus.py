"""Release-integrity guard for the runnable a8 coverage-study corpus."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_coverage_study_has_runnable_content_bound_manifest() -> None:
    study = ROOT / "A8_PREIMPLEMENTATION_COVERAGE_AUDIT.md"
    design = ROOT / "A8_FINAL_PREIMPLEMENTATION_DESIGN.md"
    if not study.exists() and not design.exists():
        return
    manifest = ROOT / "A8_55_SURFACE_CORPUS_MANIFEST.json"
    driver = ROOT / "a8-coverage-corpus/replay/replay.py"
    assert manifest.is_file(), "coverage study requires a runnable corpus manifest"
    assert driver.is_file(), "coverage study requires its replay driver"
    completed = subprocess.run(
        [sys.executable, str(driver), "--manifest", str(manifest), "--validate-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {
        "manifest_payload_sha256": result["manifest_payload_sha256"],
        "reason_code": "COVERAGE_CORPUS_VALIDATED",
        "status": "PASS",
        "surface_count": 55,
    }
    lock = ROOT / "a8-coverage-corpus/manifest/CORPUS_CONTENT_LOCK.json"
    freezer = ROOT / "a8-coverage-corpus/replay/freeze_corpus.py"
    assert lock.is_file(), "coverage study requires a permanent content lock"
    completed = subprocess.run(
        [
            sys.executable,
            str(freezer),
            "--workspace",
            str(ROOT),
            "--output",
            str(lock),
            "--verify",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
