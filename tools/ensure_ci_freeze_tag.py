#!/usr/bin/env python3
"""Create and verify the local-only QRS freeze tag needed by public CI.

The historical tag is intentionally not fetched or published.  A full public clone
contains its target commit, so CI can recreate the annotated tag locally from the
reviewed message without changing any remote ref.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


TAG = "qrs-2026-replication-v1"
COMMIT = "7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5"
MESSAGE = Path("research/TAG_MESSAGE_REPLACEMENT.txt")
ROOT_SIDECAR = Path("research/qrs2026-byte-manifest.root")


class FreezeTagError(RuntimeError):
    """The local CI freeze-tag contract could not be established."""


def _git(repository: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise FreezeTagError(f"git {' '.join(arguments)} failed: {detail}")
    return completed


def ensure_ci_freeze_tag(repository: Path) -> str:
    """Return the verified local tag object ID, creating it when absent."""
    repository = repository.resolve(strict=True)
    message_path = repository / MESSAGE
    sidecar_path = repository / ROOT_SIDECAR
    if not message_path.is_file() or message_path.is_symlink():
        raise FreezeTagError(f"reviewed tag message is unavailable: {MESSAGE}")
    if not sidecar_path.is_file() or sidecar_path.is_symlink():
        raise FreezeTagError(f"manifest sidecar is unavailable: {ROOT_SIDECAR}")

    commit_type = _git(repository, "cat-file", "-t", COMMIT, check=False)
    if commit_type.returncode or commit_type.stdout.strip() != "commit":
        raise FreezeTagError(
            "freeze commit is absent; CI checkout must use fetch-depth: 0"
        )

    existing = _git(repository, "show-ref", "--verify", f"refs/tags/{TAG}", check=False)
    created = existing.returncode != 0
    if created:
        _git(
            repository,
            "-c", "user.name=IaC-Guard-V public CI",
            "-c", "user.email=ci-tag@iac-guard-v.invalid",
            "tag", "-a", TAG, COMMIT, "-F", str(message_path),
        )

    if _git(repository, "cat-file", "-t", TAG).stdout.strip() != "tag":
        raise FreezeTagError(f"{TAG} is not an annotated tag")
    target = _git(repository, "rev-parse", f"{TAG}^{{commit}}").stdout.strip()
    if target != COMMIT:
        raise FreezeTagError(f"{TAG} targets {target}, expected {COMMIT}")

    annotation = _git(repository, "cat-file", "tag", TAG).stdout
    rendered_message = _git(
        repository, "for-each-ref", "--format=%(contents)", f"refs/tags/{TAG}"
    ).stdout
    expected_message = message_path.read_text(encoding="utf-8")
    if rendered_message != expected_message + "\n":
        raise FreezeTagError("freeze-tag annotation differs from the reviewed message")
    roots = re.findall(r"MANIFEST_ROOT:\s*([0-9a-f]{64})", annotation)
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    expected_root = sidecar.get("manifest_root")
    if roots != [expected_root]:
        raise FreezeTagError("freeze-tag MANIFEST_ROOT does not match the sidecar")
    if "NOT CONTAINED IN THIS SNAPSHOT" not in annotation:
        raise FreezeTagError("freeze-tag annotation lacks the historical-tooling warning")

    object_id = _git(repository, "rev-parse", f"refs/tags/{TAG}").stdout.strip()
    state = "created" if created else "verified"
    print(f"{state} local-only {TAG} {object_id} -> {COMMIT}")
    return object_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create and verify the local-only QRS freeze tag for public CI."
    )
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        ensure_ci_freeze_tag(args.repository)
    except (FreezeTagError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
