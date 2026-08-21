"""Adversarial regression tests for the byte-freeze verifier.

Every test here corresponds to an attack that an earlier revision of
`research/verify_byte_manifest.py` **passed**. They were found by adversarial review,
not by the original test suite, which is why they are now permanent:

  A  `chmod +x` on a frozen file with no `git add`
  B  a git-ignored `scripts/__pycache__/evil.pyc`
  C  replacing a frozen directory with a symlink to an outside copy
  D  editing a frozen file, regenerating the manifest, and hand-preserving the old
     `frozen_snapshot_commit` so the freeze appears to still describe the tag

All tests run against a hermetic synthetic repository with its own freeze tag. None
touches the real research data.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BUILDER = REPO / "research" / "build_byte_manifest.py"
VERIFIER = REPO / "research" / "verify_byte_manifest.py"
TAG = "qrs-2026-replication-v1"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        capture_output=True, text=True, check=True,
    ).stdout


@pytest.fixture()
def frozen_repo(tmp_path: Path) -> Path:
    """A synthetic repository with frozen content, a manifest, and a freeze tag."""
    repo = tmp_path / "frozen"
    (repo / "scripts").mkdir(parents=True)
    (repo / "runs" / "raw").mkdir(parents=True)
    (repo / "scripts" / "verify_patch.py").write_text("print('frozen')\n", encoding="utf-8")
    (repo / "scripts" / "analyze.py").write_text("print('analyze')\n", encoding="utf-8")
    (repo / "runs" / "raw" / "r1.json").write_text('{"x": 1}\n', encoding="utf-8")
    (repo / "requirements.txt").write_text("checkov==3.2.517\n", encoding="utf-8")
    (repo / "README.md").write_text("mutable\n", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")

    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "frozen snapshot")
    snapshot = git(repo, "rev-parse", "HEAD").strip()

    built = run(str(BUILDER), "--root", str(repo), "--output-dir", str(repo / "research"),
                "--frozen-snapshot-commit", snapshot)
    assert built.returncode == 0, built.stdout + built.stderr

    sidecar = json.loads(
        (repo / "research" / "qrs2026-byte-manifest.root").read_text(encoding="utf-8")
    )
    git(repo, "tag", "-a", TAG, snapshot, "-m",
        f"Frozen snapshot\nMANIFEST_ROOT: {sidecar['manifest_root']}\n")
    return repo


def verify(repo: Path, entries: int = 4) -> dict:
    proc = run(str(VERIFIER),
               "--manifest", str(repo / "research" / "qrs2026-byte-manifest.jsonl"),
               "--root", str(repo), "--tag", TAG,
               "--expect-entries", str(entries), "--strict", "--json")
    return json.loads(proc.stdout)


def codes(result: dict) -> list[str]:
    return [f.split(":", 1)[0] for f in result["failures"]]


def test_baseline_passes(frozen_repo: Path) -> None:
    result = verify(frozen_repo)
    assert result["status"] == "PASS", result["failures"]
    assert result["files_checked"] == 4  # README.md is outside the frozen scope


def test_tag_binding_is_mandatory(frozen_repo: Path) -> None:
    """A run without --tag must refuse rather than silently prove less."""
    proc = run(str(VERIFIER),
               "--manifest", str(frozen_repo / "research" / "qrs2026-byte-manifest.jsonl"),
               "--root", str(frozen_repo), "--expect-entries", "4", "--strict")
    assert proc.returncode == 1
    assert "TAG_BINDING_REQUIRED" in proc.stdout


def test_mutable_file_may_change_freely(frozen_repo: Path) -> None:
    (frozen_repo / "README.md").write_text("edited\n", encoding="utf-8")
    assert verify(frozen_repo)["status"] == "PASS"


# --------------------------------------------------------------------------- #
# A. unstaged executable-bit change
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(os.name != "posix", reason="exec bit not representable")
def test_attack_a_unstaged_chmod_is_detected(frozen_repo: Path) -> None:
    victim = frozen_repo / "scripts" / "verify_patch.py"
    victim.chmod(0o755)  # no git add: the index mode is unchanged
    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    assert "PHYSICAL_MODE_CHANGED" in codes(result), result["failures"]


# --------------------------------------------------------------------------- #
# B. git-ignored file under a frozen prefix
# --------------------------------------------------------------------------- #
def test_attack_b_ignored_pyc_is_detected(frozen_repo: Path) -> None:
    cache = frozen_repo / "scripts" / "__pycache__"
    cache.mkdir()
    (cache / "evil.pyc").write_bytes(b"payload")
    # Confirm the fixture really is ignored, so the test proves what it claims.
    ignored = subprocess.run(
        ["git", "-C", str(frozen_repo), "check-ignore", "scripts/__pycache__/evil.pyc"],
        capture_output=True, text=True,
    )
    assert ignored.returncode == 0, "fixture must be git-ignored to be meaningful"

    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    assert "UNLISTED_PHYSICAL_FILE_UNDER_FROZEN_PREFIX" in codes(result), result["failures"]


# --------------------------------------------------------------------------- #
# C. frozen directory replaced by a symlink to identical content
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(os.name != "posix", reason="symlink semantics differ")
def test_attack_c_symlinked_directory_is_detected(frozen_repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside_scripts"
    outside.mkdir()
    for name in ("verify_patch.py", "analyze.py"):
        (outside / name).write_text(
            (frozen_repo / "scripts" / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    real = frozen_repo / "scripts"
    for child in real.iterdir():
        child.unlink()
    real.rmdir()
    (frozen_repo / "scripts").symlink_to(outside, target_is_directory=True)

    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    failure_codes = codes(result)
    assert "SYMLINKED_DIRECTORY_UNDER_FROZEN_PREFIX" in failure_codes, result["failures"]
    # The content is byte-identical, so a hash-only verifier would have passed.
    assert any(c in failure_codes for c in ("MISSING_FILE", "SYMLINK_IN_PARENT_COMPONENT"))


# --------------------------------------------------------------------------- #
# D. manifest regenerated over changed data, snapshot commit hand-preserved
# --------------------------------------------------------------------------- #
def test_attack_d_moved_freeze_is_detected(frozen_repo: Path) -> None:
    snapshot = subprocess.run(
        ["git", "-C", str(frozen_repo), "rev-parse", f"{TAG}^{{commit}}"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    (frozen_repo / "runs" / "raw" / "r1.json").write_text('{"x": 999}\n', encoding="utf-8")
    rebuilt = run(str(BUILDER), "--root", str(frozen_repo),
                  "--output-dir", str(frozen_repo / "research"),
                  "--frozen-snapshot-commit", snapshot)
    # The builder itself should already refuse, because the frozen scope no longer
    # matches the claimed snapshot.
    assert rebuilt.returncode == 1
    assert "frozen scope differs from the claimed snapshot commit" in rebuilt.stdout

    # Force the situation anyway: build unbound, then hand-write the sidecar so it
    # claims the original snapshot. This is the attack the tag binding must catch.
    unbound = run(str(BUILDER), "--root", str(frozen_repo),
                  "--output-dir", str(frozen_repo / "research"),
                  "--unbound-development-output", "attack")
    assert unbound.returncode == 0, unbound.stdout + unbound.stderr
    research = frozen_repo / "research"
    (research / "qrs2026-byte-manifest.jsonl").write_text(
        (research / "attack.jsonl").read_text(encoding="utf-8"), encoding="utf-8"
    )
    forged = json.loads((research / "attack.root").read_text(encoding="utf-8"))
    forged["frozen_snapshot_commit"] = snapshot
    (research / "qrs2026-byte-manifest.root").write_text(
        json.dumps(forged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    failure_codes = codes(result)
    assert "TAG_ROOT_MISMATCH" in failure_codes, result["failures"]


def test_attack_d_staged_tamper_is_detected_against_the_tag_tree(frozen_repo: Path) -> None:
    """The same attack with the edit staged: caught by the tag tree comparison."""
    (frozen_repo / "runs" / "raw" / "r1.json").write_text('{"x": 999}\n', encoding="utf-8")
    git(frozen_repo, "add", "runs/raw/r1.json")
    git(frozen_repo, "commit", "-q", "-m", "tamper")

    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    failure_codes = codes(result)
    assert any(c in failure_codes for c in ("GIT_BLOB_CHANGED", "SHA256_CHANGED")), \
        result["failures"]


def test_builder_refuses_unbound_canonical_output(frozen_repo: Path) -> None:
    proc = run(str(BUILDER), "--root", str(frozen_repo),
               "--output-dir", str(frozen_repo / "research"))
    assert proc.returncode == 1
    assert "SNAPSHOT_BINDING_REQUIRED" in proc.stdout


# --------------------------------------------------------------------------- #
# E. ambiguous provenance: a forged root sitting beside the real one
# --------------------------------------------------------------------------- #
def test_attack_e_duplicate_tag_roots_are_rejected(frozen_repo: Path) -> None:
    """A tag annotation must declare exactly one MANIFEST_ROOT.

    Accepting "the correct root appears somewhere among several" lets an attacker add a
    root without removing the real one, leaving provenance that reads as valid to a
    lenient parser and as contradictory to a human.
    """
    sidecar = json.loads(
        (frozen_repo / "research" / "qrs2026-byte-manifest.root").read_text(encoding="utf-8")
    )
    real = sidecar["manifest_root"]
    fake = "0" * 64
    git(frozen_repo, "tag", "-d", TAG)
    git(frozen_repo, "tag", "-a", TAG,
        subprocess.run(["git", "-C", str(frozen_repo), "rev-parse", "HEAD"],
                       capture_output=True, text=True, check=True).stdout.strip(),
        "-m", f"probe\nMANIFEST_ROOT: {fake}\nMANIFEST_ROOT: {real}\n")

    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    assert "TAG_ROOT_AMBIGUOUS" in codes(result), result["failures"]


def test_tag_without_any_root_is_rejected(frozen_repo: Path) -> None:
    git(frozen_repo, "tag", "-d", TAG)
    git(frozen_repo, "tag", "-a", TAG,
        subprocess.run(["git", "-C", str(frozen_repo), "rev-parse", "HEAD"],
                       capture_output=True, text=True, check=True).stdout.strip(),
        "-m", "no root recorded here")
    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    assert "TAG_ROOT_ABSENT" in codes(result), result["failures"]


def test_single_wrong_root_is_a_mismatch_not_ambiguity(frozen_repo: Path) -> None:
    git(frozen_repo, "tag", "-d", TAG)
    git(frozen_repo, "tag", "-a", TAG,
        subprocess.run(["git", "-C", str(frozen_repo), "rev-parse", "HEAD"],
                       capture_output=True, text=True, check=True).stdout.strip(),
        "-m", f"probe\nMANIFEST_ROOT: {'1' * 64}\n")
    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    failure_codes = codes(result)
    assert "TAG_ROOT_MISMATCH" in failure_codes, result["failures"]
    assert "TAG_ROOT_AMBIGUOUS" not in failure_codes


@pytest.mark.parametrize("label_template,expected_code", [
    ("NOT_MANIFEST_ROOT: {root}", "TAG_ROOT_ABSENT"),
    ("XMANIFEST_ROOT: {root}", "TAG_ROOT_ABSENT"),
    ("MANIFEST_ROOT: {root} trailing-text", "TAG_ROOT_ABSENT"),
    ("MANIFEST_ROOT:{root}extra", "TAG_ROOT_ABSENT"),
    ("prefix MANIFEST_ROOT: {root}", "TAG_ROOT_ABSENT"),
])
def test_malformed_root_labels_are_not_accepted(
    frozen_repo: Path, label_template: str, expected_code: str
) -> None:
    """A decorated label must not count as a root declaration.

    An unanchored parser accepted all of these, so provenance could be spoofed by
    writing the real root under a lookalike key.
    """
    sidecar = json.loads(
        (frozen_repo / "research" / "qrs2026-byte-manifest.root").read_text(encoding="utf-8")
    )
    head = subprocess.run(["git", "-C", str(frozen_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    git(frozen_repo, "tag", "-d", TAG)
    git(frozen_repo, "tag", "-a", TAG, head,
        "-m", "probe\n" + label_template.format(root=sidecar["manifest_root"]) + "\n")

    result = verify(frozen_repo)
    assert result["status"] == "FAIL"
    assert expected_code in codes(result), result["failures"]


def test_indented_exact_root_is_accepted(frozen_repo: Path) -> None:
    """Alignment whitespace is fine; the declaration just has to be exact."""
    sidecar = json.loads(
        (frozen_repo / "research" / "qrs2026-byte-manifest.root").read_text(encoding="utf-8")
    )
    head = subprocess.run(["git", "-C", str(frozen_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    git(frozen_repo, "tag", "-d", TAG)
    git(frozen_repo, "tag", "-a", TAG, head,
        "-m", f"probe\n    MANIFEST_ROOT:     {sidecar['manifest_root']}   \n")
    assert verify(frozen_repo)["status"] == "PASS"


def test_builder_refuses_canonical_name_for_unbound_output(frozen_repo: Path) -> None:
    proc = run(str(BUILDER), "--root", str(frozen_repo),
               "--output-dir", str(frozen_repo / "research"),
               "--unbound-development-output", "qrs2026-byte-manifest")
    assert proc.returncode == 1
    assert "refusing to write an unbound manifest under the canonical name" in proc.stdout
