"""Command-line boundary for report-v1 and deterministic environment diagnosis."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from . import __version__
from .adapters.checkov import CHECKOV_CONTRACT, checkov_distribution_identity
from .api import verify
from .config import load_public_config
from .models import DomainError
from .report import OperationalReportV1, render_console, validate_report_payload
from .redaction import redact_detail


@dataclass(frozen=True, slots=True)
class DoctorReportV1:
    checkov: object
    hardened_container: object

    def __post_init__(self) -> None:
        object.__setattr__(self, "checkov", _freeze(self.checkov))
        object.__setattr__(self, "hardened_container", _freeze(self.hardened_container))

    def canonical_dict(self) -> dict:
        return {
            "schema_version": "doctor-v1",
            "product_version": __version__,
            "checkov": _thaw(self.checkov),
            "hardened_container": _thaw(self.hardened_container),
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":")
        ) + "\n"


def _version(executable: Path) -> str:
    try:
        completed = subprocess.run(
            [str(executable), "--version"], check=False, capture_output=True,
            text=True, timeout=10, env={"PATH": "", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DomainError("Checkov version probe failed") from exc
    value = (completed.stdout or completed.stderr).strip().splitlines()
    if completed.returncode != 0 or not value:
        raise DomainError("Checkov version probe failed")
    return value[-1].strip().removeprefix("Checkov ")


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in sorted(value.items())})
    if type(value) in (list, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, MappingProxyType):
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw(item) for item in value]
    return value


def doctor() -> DoctorReportV1:
    discovered = shutil.which("checkov")
    if discovered is None:
        checkov = {
            "status": "UNAVAILABLE",
            "reason_code": "CHECKOV_NOT_FOUND",
            "remediation": "Install exactly Checkov 3.3.0 in a dedicated copied-file virtual environment.",
        }
    else:
        executable = Path(discovered).resolve(strict=True)
        try:
            version = _version(executable)
            identity = checkov_distribution_identity(executable, version)
            supported = version in CHECKOV_CONTRACT.supported_versions
            checkov = {
                "status": "PASS" if supported else "UNSUPPORTED",
                "reason_code": "CHECKOV_ENVIRONMENT_VERIFIED" if supported else "CHECKOV_VERSION_UNSUPPORTED",
                "launcher_name": executable.name,
                "launcher_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "version": version,
                "scanner_environment_digest": identity.scanner_environment_digest,
                "policy_inventory_digest": identity.policy_inventory_digest,
                "installed_distribution_digest": identity.installed_distribution_digest,
                "dependency_lock_digest": identity.dependency_lock_digest,
                "remediation": (
                    "Environment is usable only with explicit reduced-isolation."
                    if supported else "Install exactly Checkov 3.3.0."
                ),
            }
        except (DomainError, OSError) as exc:
            detail = str(exc)
            unsafe_bytecode = "bytecode/cache" in detail
            unverifiable = "RECORD" in detail or "executable code" in detail
            checkov = {
                "status": "INCONCLUSIVE",
                "reason_code": (
                    "CHECKOV_ENVIRONMENT_UNSAFE_BYTECODE" if unsafe_bytecode
                    else "CHECKOV_ENVIRONMENT_UNVERIFIABLE" if unverifiable
                    else "CHECKOV_ENVIRONMENT_INCOMPLETE"
                ),
                "detail": redact_detail(detail),
                "remediation": (
                    "Remove all __pycache__, .pyc and .pyo entries, then reinstall from pinned wheels."
                    if unsafe_bytecode else
                    "Reinstall Checkov 3.3.0 and its dependency closure from pinned wheels with valid RECORD hashes."
                ),
            }
    docker = shutil.which("docker")
    hardened = {
        "status": "INCONCLUSIVE",
        "reason_code": "HARDENED_CONTAINER_IMAGE_NOT_CONFIGURED",
        "docker_cli_present": docker is not None,
        "remediation": "Install and pin the Phase E hardened image before verifying hostile pull-request input.",
    }
    return DoctorReportV1(checkov, hardened)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iac-guard")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    verify_parser = subcommands.add_parser("verify")
    verify_parser.add_argument("--config", required=True, type=Path)
    verify_parser.add_argument("--format", choices=("json", "console"), default="console")
    doctor_parser = subcommands.add_parser("doctor")
    doctor_parser.add_argument("--format", choices=("json", "console"), default="console")
    demo_parser = subcommands.add_parser("demo")
    demo_parser.add_argument("--format", choices=("json", "console"), default="console")
    explain_parser = subcommands.add_parser("explain")
    explain_parser.add_argument("report", type=Path)
    explain_parser.add_argument("--format", choices=("json", "console"), default="console")
    return parser


def _read_report(path: Path) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DomainError(f"duplicate report JSON key: {key}")
            result[key] = value
        return result
    try:
        raw = path.read_bytes()
        if len(raw) > 25 * 1024 * 1024:
            raise DomainError("report exceeds the 25 MiB limit")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DomainError("report is not strict UTF-8 JSON") from exc
    if type(payload) is not dict:
        raise DomainError("report-v1 must be a JSON object")
    validate_report_payload(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "demo":
            result = OperationalReportV1(
                "OFFLINE_DEMO_ONLY",
                "This deterministic fixture demonstrates report-v1 without executing a scanner.",
                "Run verify with a trusted environment for production evidence.",
            )
            sys.stdout.write(
                result.canonical_json() if args.format == "json" else render_console(result)
            )
            return 0
        if args.command == "explain":
            value = _read_report(args.report)
            if args.format == "json":
                sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
            else:
                sys.stdout.write(
                    f"IaC-Guard-V report explanation\nkind: {value['result_kind']}\n"
                    f"verdict: {value['verdict']}\nexit_code: {value['exit_code']}\n"
                )
            return 0
        if args.command == "doctor":
            result = doctor()
            if args.format == "json":
                sys.stdout.write(result.canonical_json())
            else:
                value = result.canonical_dict()
                sys.stdout.write(
                    f"IaC-Guard-V doctor\nCheckov: {value['checkov']['status']} "
                    f"({value['checkov']['reason_code']})\nHardened container: "
                    f"{value['hardened_container']['status']} "
                    f"({value['hardened_container']['reason_code']})\n"
                )
            return 0 if (
                result.checkov["status"] == "PASS"
                and result.hardened_container["status"] == "PASS"
            ) else 3
        request = load_public_config(args.config)
        report = verify(request)
        sys.stdout.write(
            report.canonical_json() if args.format == "json" else render_console(report)
        )
        return report.exit_code
    except DomainError as exc:
        sys.stderr.write(json.dumps({
            "schema_version": "request-error-v1",
            "exit_code": 2,
            "reason_code": "INVALID_REQUEST",
            "detail": redact_detail(str(exc)),
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return 2
    except Exception:
        sys.stderr.write(json.dumps({
            "schema_version": "request-error-v1",
            "exit_code": 4,
            "reason_code": "UNEXPECTED_INTERNAL_ERROR",
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["DoctorReportV1", "doctor", "main"]
