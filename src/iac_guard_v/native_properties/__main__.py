"""Isolated command entry point for scanner-independent native properties."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..models import DomainError
from .public import load_native_property_config, verify_native_properties
from .report import render_native_console


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m iac_guard_v.native_properties")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--format", choices=("json", "console"), default="console")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = verify_native_properties(load_native_property_config(args.config))
        rendered = (
            report.canonical_json()
            if args.format == "json"
            else render_native_console(report)
        )
        if args.output is not None:
            args.output.write_text(rendered, encoding="utf-8")
            if not args.quiet:
                print(args.output)
        elif not args.quiet:
            print(rendered, end="")
        return report.exit_code
    except (DomainError, OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised by the module entry point
    raise SystemExit(main())
