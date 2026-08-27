"""The local gate catalog must remain closed and executable."""
from pathlib import Path

import pytest

from tools.testing.gates import (
    COVERAGE_GATES,
    validate_focused_selection,
    validate_paths,
)


ROOT = Path(__file__).resolve().parents[2]


def test_all_gate_paths_exist_and_thresholds_remain_90() -> None:
    validate_paths(ROOT)
    assert len(COVERAGE_GATES) == 8
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
