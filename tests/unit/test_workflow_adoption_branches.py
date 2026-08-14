"""Defensive branch probes for the Git and output adoption workflow."""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import iac_guard_v.workflow as W
from iac_guard_v.config import PublicTarget
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import DomainError


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    return before, after


def _materialization(tmp_path: Path, **changes):
    before, after = _roots(tmp_path)
    values = {
        "repository_identity": "git_repository_v1_" + "a" * 64,
        "base_commit": "a" * 40,
        "base_tree": "b" * 40,
        "head_commit": "c" * 40,
        "head_tree": "d" * 40,
        "changed_paths": ("main.tf",),
        "baseline_root": before,
        "candidate_root": after,
        "context_identity": "git_pr_v1_" + "e" * 64,
        "_trusted_context": W._GIT_CONTEXT,
    }
    values.update(changes)
    return W.GitVerificationMaterialization(**values)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"base_commit": "short"}, "object ID"),
        ({"repository_identity": "NOT CANONICAL"}, "not canonical"),
        ({"changed_paths": ["main.tf"]}, "exact nonblank tuple"),
        ({"changed_paths": ("main.tf", "main.tf")}, "duplicates"),
        ({"_trusted_context": object()}, "protected workflow provenance"),
    ],
)
def test_git_materialization_shape_rejections(tmp_path: Path, changes, message) -> None:
    with pytest.raises(DomainError, match=message):
        _materialization(tmp_path, **changes)


def test_git_materialization_rejects_missing_root(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(DomainError, match="must be a directory"):
        _materialization(tmp_path, baseline_root=missing)


def test_git_executable_inspection_failures(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(W.shutil, "which", lambda _name: None)
    with pytest.raises(DomainError, match="unavailable"):
        W._git_executable()
    missing = tmp_path / "missing"
    monkeypatch.setattr(W.shutil, "which", lambda _name: str(missing))
    with pytest.raises(DomainError, match="cannot be inspected"):
        W._git_executable()
    directory = tmp_path / "directory"
    directory.mkdir()
    monkeypatch.setattr(W.shutil, "which", lambda _name: str(directory))
    with pytest.raises(DomainError, match="executable regular file"):
        W._git_executable()


def test_git_command_failures(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "git"
    executable.write_bytes(b"git")
    with pytest.raises(DomainError, match="arguments"):
        W._git(executable, tmp_path, ["status"])
    monkeypatch.setattr(W.subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(DomainError, match="command failed"):
        W._git(executable, tmp_path, ("status",))
    monkeypatch.setattr(
        W.subprocess, "run",
        lambda *_a, **_k: SimpleNamespace(stdout=b"xx", stderr=b"", returncode=0),
    )
    with pytest.raises(DomainError, match="output limit"):
        W._git(executable, tmp_path, ("status",), max_output_bytes=1)
    monkeypatch.setattr(
        W.subprocess, "run",
        lambda *_a, **_k: SimpleNamespace(stdout=b"", stderr=b"bad", returncode=1),
    )
    with pytest.raises(DomainError, match="rejected"):
        W._git(executable, tmp_path, ("status",))


@pytest.mark.parametrize("value", ["", "-unsafe", "bad\nref", "x" * 257, 4])
def test_safe_ref_rejections(value) -> None:
    with pytest.raises(DomainError, match="Git ref"):
        W._safe_ref(value, "base_ref")


def test_object_and_tree_contract_failures(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "git"
    monkeypatch.setattr(W, "_git", lambda *_a, **_k: b"not-an-object\n")
    with pytest.raises(DomainError, match="noncanonical"):
        W._object_id(executable, tmp_path, "HEAD", "commit")

    records = [
        (b"malformed\0", "malformed"),
        (b"040000 tree " + b"a" * 40 + b" 1\tdir\0", "unsupported entry"),
        (b"100644 blob invalid 1\tmain.tf\0", "identity is malformed"),
        (b"100644 blob " + b"a" * 40 + b" 999\tmain.tf\0", "per-file limit"),
    ]
    monkeypatch.setattr(W, "_MAX_FILE_BYTES", 10)
    for raw, message in records:
        monkeypatch.setattr(W, "_git", lambda *_a, _raw=raw, **_k: _raw)
        with pytest.raises(DomainError, match=message):
            W._git_tree_entries(executable, tmp_path, "a" * 40)

    duplicate = (
        b"100644 blob " + b"a" * 40 + b" 1\tmain.tf\0"
        b"100644 blob " + b"b" * 40 + b" 1\tmain.tf\0"
    )
    monkeypatch.setattr(W, "_git", lambda *_a, **_k: duplicate)
    with pytest.raises(DomainError, match="duplicate"):
        W._git_tree_entries(executable, tmp_path, "a" * 40)


def test_write_all_handles_interrupt_and_zero_write(monkeypatch) -> None:
    calls = iter([InterruptedError(), 2])

    def interrupted(_descriptor, _payload):
        value = next(calls)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(W.os, "write", interrupted)
    W._write_all(3, b"xx")
    monkeypatch.setattr(W.os, "write", lambda *_: 0)
    with pytest.raises(DomainError, match="zero-byte write"):
        W._write_all(3, b"x")


def test_materialization_detects_size_and_symlink_failures(monkeypatch, tmp_path: Path) -> None:
    destination = tmp_path / "view"
    monkeypatch.setattr(
        W, "_git_tree_entries",
        lambda *_: (("main.tf", "100644", "a" * 40, 2),),
    )
    monkeypatch.setattr(W, "_git", lambda *_a, **_k: b"x")
    with pytest.raises(DomainError, match="size changed"):
        W._materialize_git_tree(tmp_path / "git", tmp_path, "a" * 40, destination)

    destination = tmp_path / "links"
    monkeypatch.setattr(
        W, "_git_tree_entries",
        lambda *_: (("link", "120000", "a" * 40, 1),),
    )
    monkeypatch.setattr(W, "_git", lambda *_a, **_k: b"\xff")
    with pytest.raises(DomainError, match="symlink"):
        W._materialize_git_tree(tmp_path / "git", tmp_path, "a" * 40, destination)


def test_bind_inventory_target_rejections_and_empty_scope(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    target = PublicTarget("CKV_X", "aws_x.r")
    assert W.bind_inventory_targets(empty, (target,), ("terraform",)) == (target,)

    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    with pytest.raises(DomainError, match="does not resolve"):
        W.bind_inventory_targets(
            root, (PublicTarget("CKV_X", "aws_other.r"),), ("terraform",),
        )
    (root / "second.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    with pytest.raises(DomainError, match="ambiguous"):
        W.bind_inventory_targets(root, (target,), ("terraform",))


def test_output_contract_rejects_invalid_limits_and_paths(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="pathlib"):
        W.write_new_regular_file("report.json", b"x")
    with pytest.raises(DomainError, match="limit"):
        W.write_new_regular_file(tmp_path / "report.json", b"x", max_bytes=0)
    with pytest.raises(DomainError, match="nonempty bytes"):
        W.write_new_regular_file(tmp_path / "report.json", b"")
    with pytest.raises(DomainError, match="parent does not exist"):
        W.write_new_regular_file(tmp_path / "missing" / "report.json", b"x")
