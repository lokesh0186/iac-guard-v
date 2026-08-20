"""Coverage and regression tests for scanner-neutral adapter safeguards."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import iac_guard_v.adapters.base as base
from iac_guard_v.adapters.base import (
    AdapterReason,
    ScannerContract,
    read_locked_output_directory,
    remove_private_tree,
    require_hardened_docker_argv,
    semantic_output_manifest,
)
from iac_guard_v.models import DomainError


def _docker_argv() -> tuple[str, ...]:
    return (
        "docker", "run", "--pull", "never", "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt",
        "no-new-privileges", "--pids-limit", "128", "--memory", "512m",
        "--cpus", "1.0", "--user", "65532:65532", "scanner@example",
    )


def _require_hardened(argv: tuple[str, ...], *, user: str = "65532:65532") -> None:
    require_hardened_docker_argv(
        argv, pids_limit="128", memory="512m", cpus="1.0", user=user,
    )


def test_scanner_contract_is_sorted_and_canonical() -> None:
    contract = ScannerContract(
        "checkov", ("3.3.1", "3.3.0"), ("terraform", "kubernetes"), (1, 0),
    )
    assert contract.canonical_dict() == {
        "name": "checkov",
        "supported_versions": ["3.3.0", "3.3.1"],
        "frameworks": ["kubernetes", "terraform"],
        "expected_exit_codes": [0, 1],
    }


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("supported_versions", ["3.3.0"]),
        ("frameworks", ["terraform"]),
        ("expected_exit_codes", [0]),
    ),
)
def test_scanner_contract_requires_exact_tuple_fields(field: str, value: object) -> None:
    values = {
        "supported_versions": ("3.3.0",),
        "frameworks": ("terraform",),
        "expected_exit_codes": (0,),
    }
    values[field] = value
    with pytest.raises(DomainError, match=f"{field} must be an exact tuple"):
        ScannerContract("checkov", **values)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("supported_versions", ()),
        ("frameworks", ()),
        ("expected_exit_codes", ()),
        ("frameworks", ("terraform", "terraform")),
        ("expected_exit_codes", (0, 0)),
    ),
)
def test_scanner_contract_rejects_empty_or_duplicate_fields(
    field: str, value: tuple[object, ...],
) -> None:
    values = {
        "supported_versions": ("3.3.0",),
        "frameworks": ("terraform",),
        "expected_exit_codes": (0,),
    }
    values[field] = value
    with pytest.raises(DomainError, match="must not (?:be empty|contain duplicates)"):
        ScannerContract("checkov", **values)


def test_locked_output_directory_reads_and_hashes_exact_files(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "a.json").write_bytes(b"a")
    (output / "b.json").write_bytes(b"bc")

    files, manifest_root = read_locked_output_directory(
        output,
        allowed_files=("a.json", "b.json"),
        max_file_bytes=2,
        max_total_bytes=3,
    )

    manifest = [
        {
            "path": name,
            "kind": "REGULAR_FILE",
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for name, content in files.items()
    ]
    expected = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert files == {"a.json": b"a", "b.json": b"bc"}
    assert manifest_root == expected


@pytest.mark.parametrize(
    ("allowed_files", "max_file_bytes", "max_total_bytes", "message"),
    (
        (["result.json"], 2, 2, "exact tuple"),
        (("result.json", "result.json"), 2, 2, "unique and sorted"),
        (("z.json", "a.json"), 2, 2, "unique and sorted"),
        (("result.json",), 0, 2, "limits must be positive"),
        (("result.json",), 2, 0, "limits must be positive"),
    ),
)
def test_locked_output_directory_rejects_invalid_contract(
    tmp_path: Path,
    allowed_files: object,
    max_file_bytes: int,
    max_total_bytes: int,
    message: str,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "result.json").write_bytes(b"{}")
    with pytest.raises(DomainError, match=message):
        read_locked_output_directory(
            output,
            allowed_files=allowed_files,  # type: ignore[arg-type]
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )


def test_locked_output_directory_rejects_missing_or_symlink_root(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            tmp_path / "missing", allowed_files=(), max_file_bytes=1, max_total_bytes=1,
        )

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            link, allowed_files=(), max_file_bytes=1, max_total_bytes=1,
        )


def test_locked_output_directory_rejects_allowlist_mismatch(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "unexpected.json").write_bytes(b"{}")
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            output, allowed_files=("result.json",), max_file_bytes=2, max_total_bytes=2,
        )


def test_locked_output_directory_rejects_entry_stat_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    output.mkdir()

    class BrokenEntry:
        name = "result.json"

        @staticmethod
        def stat(*, follow_symlinks: bool) -> object:
            assert follow_symlinks is False
            raise OSError("stat failed")

    monkeypatch.setattr(base.os, "scandir", lambda _root: [BrokenEntry()])
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            output, allowed_files=("result.json",), max_file_bytes=2, max_total_bytes=2,
        )


def test_locked_output_directory_rejects_symlink_and_size_limits(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    target = tmp_path / "target"
    target.write_bytes(b"x")
    (output / "result.json").symlink_to(target)
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            output, allowed_files=("result.json",), max_file_bytes=2, max_total_bytes=2,
        )

    (output / "result.json").unlink()
    (output / "result.json").write_bytes(b"abc")
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            output, allowed_files=("result.json",), max_file_bytes=2, max_total_bytes=3,
        )

    (output / "second.json").write_bytes(b"x")
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            output,
            allowed_files=("result.json", "second.json"),
            max_file_bytes=3,
            max_total_bytes=3,
        )


def test_locked_output_directory_rejects_opened_file_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "result.json").write_bytes(b"x")
    monkeypatch.setattr(
        base.os, "fstat", lambda _descriptor: SimpleNamespace(st_mode=stat.S_IFREG, st_size=2),
    )
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            output, allowed_files=("result.json",), max_file_bytes=2, max_total_bytes=2,
        )


def test_locked_output_directory_rejects_open_and_read_races(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "result.json").write_bytes(b"x")

    def fail_open(*_args: object, **_kwargs: object) -> int:
        raise OSError("open failed")

    monkeypatch.setattr(base.os, "open", fail_open)
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            output, allowed_files=("result.json",), max_file_bytes=1, max_total_bytes=1,
        )

    monkeypatch.undo()
    monkeypatch.setattr(base.os, "read", lambda _descriptor, _size: b"xx")
    with pytest.raises(DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value):
        read_locked_output_directory(
            output, allowed_files=("result.json",), max_file_bytes=1, max_total_bytes=1,
        )


def test_remove_private_tree_restores_nested_owner_permissions(tmp_path: Path) -> None:
    root = tmp_path / "private"
    nested = root / "nested"
    nested.mkdir(parents=True)
    file_path = nested / "result.json"
    file_path.write_bytes(b"{}")
    os.chmod(file_path, 0)
    os.chmod(nested, 0o500)
    os.chmod(root, 0o500)

    remove_private_tree(root)

    assert not root.exists()


def test_hardened_docker_contract_accepts_exact_guards() -> None:
    _require_hardened(_docker_argv())


def test_hardened_docker_contract_rejects_changed_duplicate_and_malformed_values() -> None:
    changed = list(_docker_argv())
    changed[changed.index("--memory") + 1] = "1g"
    with pytest.raises(DomainError, match="changes --memory"):
        _require_hardened(tuple(changed))

    duplicated = _docker_argv() + ("--network", "none")
    with pytest.raises(DomainError, match="omits --network"):
        _require_hardened(duplicated)

    without_read_only = tuple(value for value in _docker_argv() if value != "--read-only")
    with pytest.raises(DomainError, match="omits read-only root"):
        _require_hardened(without_read_only)

    malformed_user = list(_docker_argv())
    malformed_user[malformed_user.index("--user") + 1] = "not-a-uid"
    with pytest.raises(DomainError, match="user is malformed"):
        _require_hardened(tuple(malformed_user), user="not-a-uid")

    root_user = list(_docker_argv())
    root_user[root_user.index("--user") + 1] = "0:0"
    with pytest.raises(DomainError, match="must be non-root"):
        _require_hardened(tuple(root_user), user="0:0")


def test_semantic_output_manifest_is_stable_and_validated() -> None:
    digest = "a" * 64
    expected = hashlib.sha256(
        json.dumps(
            [{"path": "results.json", "kind": "REGULAR_FILE", "semantic_sha256": digest}],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    assert semantic_output_manifest("results.json", digest) == expected
    with pytest.raises(DomainError, match="must be a SHA-256"):
        semantic_output_manifest("results.json", "A" * 64)
