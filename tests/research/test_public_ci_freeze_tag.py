"""Public-clone regression tests for the local-only QRS freeze tag."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[2]
HELPER = ROOT / "tools/ensure_ci_freeze_tag.py"
WORKFLOW = ROOT / ".github/workflows/python-compat.yml"
TAG = "qrs-2026-replication-v1"
COMMIT = "7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5"


def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True, text=True, check=False,
    )


def test_public_no_tag_clone_creates_only_an_ephemeral_local_tag(tmp_path: Path) -> None:
    clone = tmp_path / "public-clone"
    cloned = subprocess.run(
        [
            "git", "clone", "--quiet", "--no-tags", "--depth=1",
            f"file://{ROOT}", str(clone),
        ],
        capture_output=True, text=True, check=False,
    )
    assert cloned.returncode == 0, cloned.stderr
    assert _git(clone, "show-ref", "--verify", f"refs/tags/{TAG}").returncode != 0
    assert _git(clone, "cat-file", "-t", COMMIT).returncode != 0

    fetched = _git(clone, "fetch", "--no-tags", "--unshallow", "origin")
    assert fetched.returncode == 0, fetched.stderr
    assert _git(clone, "cat-file", "-t", COMMIT).stdout.strip() == "commit"

    for expected_word in ("created", "verified"):
        completed = subprocess.run(
            [sys.executable, str(HELPER), "--repository", str(clone)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert expected_word in completed.stdout
    assert _git(clone, "cat-file", "-t", TAG).stdout.strip() == "tag"
    assert _git(clone, "rev-parse", f"{TAG}^{{commit}}").stdout.strip() == COMMIT


def test_public_workflow_fetches_history_and_never_pushes_the_tag() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert workflow.count("fetch-depth: 0") == 2
    assert "python tools/ensure_ci_freeze_tag.py" in workflow
    assert "git push" not in workflow
    helper = HELPER.read_text(encoding="utf-8")
    assert '"push"' not in helper
