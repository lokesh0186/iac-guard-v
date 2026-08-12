"""D4.8 executable scanner-environment closure."""
from __future__ import annotations

import py_compile
from pathlib import Path

import pytest

import iac_guard_v.adapters.checkov as CHECKOV
from iac_guard_v.enums import Status
from iac_guard_v.models import DomainError
from iac_guard_v.process import CommandResult, ProcessReason

from test_checkov_adapter import document, request


def _pass(command, stdout: bytes = b"") -> CommandResult:
    return CommandResult(
        argv=command.argv,
        status=Status.PASS,
        exit_code=0,
        stdout=stdout,
        stderr=b"",
        duration_ms=1,
        truncated=False,
        timed_out=False,
        killed_signal=None,
        reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
        resolved_executable=str(command.argv[0]),
    )


def test_timestamp_valid_malicious_bytecode_is_rejected(tmp_path: Path) -> None:
    req = request(tmp_path)
    malicious = tmp_path / "malicious.py"
    malicious.write_text("RAISED = 'malicious'\n", encoding="utf-8")
    compiled = Path(py_compile.compile(str(malicious), doraise=True))
    cache = next(
        (tmp_path / "trusted-checkov/libexec").glob(
            "lib/python*/site-packages/checkov"
        )
    ) / "__pycache__"
    cache.mkdir()
    (cache / "rule.cpython-311.pyc").write_bytes(compiled.read_bytes())
    with pytest.raises(DomainError, match="bytecode/cache"):
        CHECKOV.checkov_distribution_identity(req.executable, "3.3.0")


def test_scanner_commands_disable_and_recheck_bytecode(monkeypatch, tmp_path: Path) -> None:
    req = request(tmp_path)
    calls = []

    def fake_run(command):
        calls.append(command)
        assert dict(command.env_extra) == {"PYTHONDONTWRITEBYTECODE": "1"}
        if command.argv[1:] == ("--version",):
            return _pass(command, b"3.3.0\n")
        cache = next(
            (tmp_path / "trusted-checkov/libexec").glob(
                "lib/python*/site-packages/checkov"
            )
        ) / "__pycache__"
        cache.mkdir()
        (cache / "late.pyc").write_bytes(b"late")
        return _pass(command)

    monkeypatch.setattr(CHECKOV, "run_command", fake_run)
    run = CHECKOV.CheckovAdapter().scan(req)
    assert len(calls) == 2
    assert run.status is Status.ERROR
    assert run.diagnostics == ("SCANNER_ENVIRONMENT_MISMATCH",)
