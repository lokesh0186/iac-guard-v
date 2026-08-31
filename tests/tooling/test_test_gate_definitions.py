"""The local gate catalog must remain closed and executable."""
from pathlib import Path

import pytest

from tools.testing.gates import (
    COVERAGE_GATES,
    validate_focused_selection,
    validate_paths,
)
from tools.testing import ci_gates


ROOT = Path(__file__).resolve().parents[2]


def test_all_gate_paths_exist_and_thresholds_remain_90() -> None:
    validate_paths(ROOT)
    assert len(COVERAGE_GATES) == 10
    assert all(gate.threshold == 90 for gate in COVERAGE_GATES)
    assert all(gate.modules for gate in COVERAGE_GATES)
    assert all(gate.tests for gate in COVERAGE_GATES)


def test_coverage_gate_argv_is_structured_not_shell_text() -> None:
    for gate in COVERAGE_GATES:
        argv = gate.pytest_argv()
        assert all(type(item) is str and item for item in argv)
        assert not any(";" in item or "&&" in item for item in argv)
        assert f"--cov-fail-under={gate.threshold}" in argv
        assert ("--cov-branch" in argv) is gate.branch


def test_focused_selection_accepts_only_bounded_test_filters() -> None:
    validate_focused_selection(
        ROOT,
        ("tests/tooling/test_test_gate_definitions.py", "-k", "coverage", "--lf"),
    )


@pytest.mark.parametrize(
    "selection",
    (
        ("--basetemp=/tmp/unsafe",),
        ("-p", "unsafe_plugin"),
        ("pyproject.toml",),
        ("../outside.py",),
        ("-k",),
    ),
)
def test_focused_selection_rejects_unsafe_passthrough(
    selection: tuple[str, ...],
) -> None:
    with pytest.raises(RuntimeError):
        validate_focused_selection(ROOT, selection)


def test_ci_runner_builds_exact_structured_gate_commands() -> None:
    for gate in COVERAGE_GATES:
        assert ci_gates.gate_command(gate.name) == [
            ci_gates.sys.executable,
            "-m",
            "pytest",
            *gate.pytest_argv(),
        ]
        assert ci_gates.gate_command(gate.name, collect_only=True)[-1] == (
            "--collect-only"
        )


def test_ci_runner_stops_on_first_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    class Result:
        returncode = 7

    def fake_run(command: list[str], **_kwargs: object) -> Result:
        calls.append(command)
        return Result()

    monkeypatch.setattr(ci_gates, "validate_paths", lambda _root: None)
    monkeypatch.setattr(ci_gates.subprocess, "run", fake_run)
    result = ci_gates.execute(("d3-fingerprints", "d3-matching"))
    assert result == 7
    assert calls == [ci_gates.gate_command("d3-fingerprints")]


def test_public_workflow_uses_shared_gates_in_clean_environment() -> None:
    workflow = (ROOT / ".github/workflows/python-compat.yml").read_text(encoding="utf-8")
    assert workflow.count("-m tools.testing.ci_gates") == 6
    assert workflow.count('PYTHONDONTWRITEBYTECODE: "1"') == 6
    assert "python -m pytest tests/unit/test_fingerprints.py" not in workflow
    assert "python -m venv --copies /tmp/iacgv-compat" in workflow
    assert 'install --no-compile -e ".[compat-test]"' in workflow
