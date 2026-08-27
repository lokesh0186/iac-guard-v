"""Execute the closed coverage-gate catalog in clean public CI environments."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from tools.testing.gates import COVERAGE_GATES, gate_by_name, validate_paths


ROOT = Path(__file__).resolve().parents[2]
GATE_NAMES = tuple(gate.name for gate in COVERAGE_GATES)


def gate_command(name: str, *, collect_only: bool = False) -> list[str]:
    """Return an argv-only pytest command for one closed gate identity."""
    command = [sys.executable, "-m", "pytest", *gate_by_name(name).pytest_argv()]
    if collect_only:
        command.append("--collect-only")
    return command


def execute(names: Sequence[str], *, collect_only: bool = False) -> int:
    """Run selected gates in order and stop at the first nonzero result."""
    validate_paths(ROOT)
    for name in names:
        completed = subprocess.run(
            gate_command(name, collect_only=collect_only),
            cwd=ROOT,
            check=False,
        )
        if completed.returncode:
            return completed.returncode
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run exact IaC-Guard-V coverage gates from the shared catalog."
    )
    parser.add_argument(
        "gates",
        choices=GATE_NAMES,
        nargs="+",
        help="one or more closed gate identities, executed in the supplied order",
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="collect the same gate nodes without executing them",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    return execute(arguments.gates, collect_only=arguments.collect_only)


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
