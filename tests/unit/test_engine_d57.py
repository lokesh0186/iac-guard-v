"""D5.7 physical parser implementation identity regressions."""
from __future__ import annotations

import base64
import hashlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import importlib.metadata
import pytest

import iac_guard_v.engine as ENGINE
from iac_guard_v.enums import Status
from iac_guard_v.models import GateResult
from iac_guard_v.models import DomainError


class _RecordEntry:
    def __init__(self, relative: str, data: bytes):
        self.relative = relative
        self.hash = SimpleNamespace(
            mode="sha256",
            value=base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("="),
        )
        self.size = len(data)

    def __str__(self) -> str:
        return self.relative


class _FakeDistribution:
    def __init__(self, root: Path, entries):
        self.root = root
        self.files = entries

    def locate_file(self, entry):
        relative = entry.relative if hasattr(entry, "relative") else str(entry)
        return self.root / relative


def test_unlisted_parser_bytecode_is_rejected(tmp_path: Path, monkeypatch) -> None:
    package = tmp_path / "parser_pkg"
    package.mkdir()
    source = package / "parser.py"
    source.write_bytes(b"def parse(value): return value\n")
    entry = _RecordEntry("parser_pkg/parser.py", source.read_bytes())
    distribution = _FakeDistribution(tmp_path, [entry])
    monkeypatch.setattr(importlib.metadata, "distribution", lambda _name: distribution)

    before = ENGINE._verified_parser_distribution_digest("parser")
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "evil.cpython-313.pyc").write_bytes(b"malicious-valid-bytecode-shape")

    with pytest.raises(DomainError, match="bytecode/cache"):
        ENGINE._verified_parser_distribution_digest("parser")
    assert before


@pytest.mark.parametrize("suffix", (".py", ".pyi", ".so", ".pyd", ".dylib"))
def test_unlisted_executable_parser_files_are_rejected(
    tmp_path: Path, monkeypatch, suffix: str
) -> None:
    package = tmp_path / "parser_pkg"
    package.mkdir()
    source = package / "parser.py"
    source.write_bytes(b"trusted")
    distribution = _FakeDistribution(
        tmp_path, [_RecordEntry("parser_pkg/parser.py", b"trusted")]
    )
    monkeypatch.setattr(importlib.metadata, "distribution", lambda _name: distribution)
    (package / f"extra{suffix}").write_bytes(b"unlisted")
    with pytest.raises(DomainError, match="unlisted executable code"):
        ENGINE._verified_parser_distribution_digest("parser")


def test_parser_package_symlink_is_rejected(tmp_path: Path, monkeypatch) -> None:
    package = tmp_path / "parser_pkg"
    package.mkdir()
    source = package / "parser.py"
    source.write_bytes(b"trusted")
    distribution = _FakeDistribution(
        tmp_path, [_RecordEntry("parser_pkg/parser.py", b"trusted")]
    )
    monkeypatch.setattr(importlib.metadata, "distribution", lambda _name: distribution)
    (package / "helper.py").symlink_to(source)
    with pytest.raises(DomainError, match="symlink"):
        ENGINE._verified_parser_distribution_digest("parser")


def test_parser_record_path_escape_is_rejected(tmp_path: Path, monkeypatch) -> None:
    outside = tmp_path.parent / "outside-parser.py"
    outside.write_bytes(b"trusted")
    distribution = _FakeDistribution(
        tmp_path, [_RecordEntry("../outside-parser.py", b"trusted")]
    )
    monkeypatch.setattr(importlib.metadata, "distribution", lambda _name: distribution)
    try:
        with pytest.raises(DomainError, match="path escape"):
            ENGINE._verified_parser_distribution_digest("parser")
    finally:
        outside.unlink()


def test_editable_parser_install_is_rejected(tmp_path: Path, monkeypatch) -> None:
    info = tmp_path / "parser-1.dist-info"
    info.mkdir()
    direct = info / "direct_url.json"
    direct.write_bytes(b'{"dir_info":{"editable":true},"url":"file:///candidate"}')
    distribution = _FakeDistribution(
        tmp_path,
        [_RecordEntry("parser-1.dist-info/direct_url.json", direct.read_bytes())],
    )
    monkeypatch.setattr(importlib.metadata, "distribution", lambda _name: distribution)
    with pytest.raises(DomainError, match="editable install"):
        ENGINE._verified_parser_distribution_digest("parser")


def test_parser_path_injection_file_is_rejected(tmp_path: Path, monkeypatch) -> None:
    injection = tmp_path / "parser.pth"
    injection.write_bytes(b"/candidate/code\n")
    distribution = _FakeDistribution(
        tmp_path, [_RecordEntry("parser.pth", injection.read_bytes())]
    )
    monkeypatch.setattr(importlib.metadata, "distribution", lambda _name: distribution)
    with pytest.raises(DomainError, match="path injection"):
        ENGINE._verified_parser_distribution_digest("parser")


def test_unverified_parser_environment_makes_gate_inconclusive(monkeypatch) -> None:
    monkeypatch.setattr(
        ENGINE, "_verified_parser_environment",
        lambda: (_ for _ in ()).throw(DomainError("unsafe parser environment")),
    )
    registry = ENGINE.production_gate_registry()
    result = registry.execute("validator", "terraform_hcl_parse", object())
    assert result.status is Status.INCONCLUSIVE
    assert result.reason_code == "GATE_IMPLEMENTATION_INTEGRITY_INCONCLUSIVE"


def test_validator_disables_bytecode_and_revalidates_environment(monkeypatch) -> None:
    expected = "a" * 64
    observed = []
    monkeypatch.setattr(ENGINE, "_parser_environment_digest", lambda: expected)

    def validator(_kind, gate_id, _snapshot):
        observed.append((os.environ.get("PYTHONDONTWRITEBYTECODE"), sys.dont_write_bytecode))
        return GateResult(gate_id, Status.PASS, "VALIDATOR_COMPLETED")

    monkeypatch.setattr(ENGINE, "_production_gate_executor", validator)
    result = ENGINE._integrity_bound_gate_executor(expected)(
        "validator", "terraform_hcl_parse", object()
    )
    assert result.status is Status.PASS
    assert observed == [("1", True)]


def test_validator_detects_parser_environment_mutation(monkeypatch) -> None:
    values = iter(("a" * 64, "b" * 64))
    monkeypatch.setattr(ENGINE, "_parser_environment_digest", lambda: next(values))
    monkeypatch.setattr(
        ENGINE, "_production_gate_executor",
        lambda _kind, gate_id, _snapshot: GateResult(
            gate_id, Status.PASS, "VALIDATOR_COMPLETED"
        ),
    )
    result = ENGINE._integrity_bound_gate_executor("a" * 64)(
        "validator", "terraform_hcl_parse", object()
    )
    assert result.status is Status.INCONCLUSIVE
    assert result.reason_code == "GATE_IMPLEMENTATION_CHANGED"
