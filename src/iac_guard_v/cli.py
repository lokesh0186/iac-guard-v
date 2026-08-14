"""Command-line boundary for report-v1 and deterministic environment diagnosis."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from . import __version__
from .adapters.checkov import CHECKOV_CONTRACT, checkov_distribution_identity
from .api import verify
from .config import (
    ExecutionIsolation, PublicTarget, PublicVerificationRequest, load_public_config,
)
from .models import DomainError
from .report import OperationalReportV1, render_console, validate_report_payload
from .redaction import redact_detail
from .reporters import render_junit, render_markdown, render_sarif
from .workflow import (
    WORKFLOW_LOCK_CONTRACT, canonical_json, changed_only_targets_are_bound,
    command_receipt, create_reduced_isolation_lock, public_config_payload,
    write_new_regular_file,
)


_REPORT_FORMATS = ("json", "console", "sarif", "markdown", "junit")


@dataclass(frozen=True, slots=True)
class DoctorReportV1:
    checkov: object
    hardened_container: object
    validator_registry: object = field(default_factory=lambda: {
        "status": "INCONCLUSIVE",
        "reason_code": "VALIDATOR_REGISTRY_NOT_EVALUATED",
        "remediation": "Run doctor in the protected bytecode-free product environment.",
    })

    def __post_init__(self) -> None:
        object.__setattr__(self, "checkov", _freeze(self.checkov))
        object.__setattr__(self, "hardened_container", _freeze(self.hardened_container))
        object.__setattr__(self, "validator_registry", _freeze(self.validator_registry))

    def canonical_dict(self) -> dict:
        return {
            "schema_version": "doctor-v1",
            "product_version": __version__,
            "checkov": _thaw(self.checkov),
            "hardened_container": _thaw(self.hardened_container),
            "validator_registry": _thaw(self.validator_registry),
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
                "reason_code": (
                    "CHECKOV_ENVIRONMENT_INTERNALLY_CONSISTENT"
                    if supported else "CHECKOV_VERSION_UNSUPPORTED"
                ),
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
    try:
        from .validators.registry import production_validator_registry
        registry = production_validator_registry()
        validator_registry = {
            "status": registry.integrity_status.value,
            "reason_code": registry.integrity_reason,
            "registry_identity": registry.identity,
            "remediation": registry.remediation or (
                "Run the bytecode-free installed product in its protected environment."
            ),
        }
    except DomainError as exc:
        validator_registry = {
            "status": "INCONCLUSIVE",
            "reason_code": "VALIDATOR_REGISTRY_INTEGRITY_UNAVAILABLE",
            "detail": redact_detail(str(exc)),
            "remediation": (
                "Reinstall from the protected wheel, remove executable caches, and set "
                "PYTHONDONTWRITEBYTECODE=1 before Python starts."
            ),
        }
    return DoctorReportV1(checkov, hardened, validator_registry)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iac-guard")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    verify_parser = subcommands.add_parser("verify")
    verify_parser.add_argument("--config", required=True, type=Path)
    verify_parser.add_argument("--format", choices=_REPORT_FORMATS, default="console")
    doctor_parser = subcommands.add_parser("doctor")
    doctor_parser.add_argument("--format", choices=("json", "console"), default="console")
    demo_parser = subcommands.add_parser("demo")
    demo_parser.add_argument("--format", choices=("json", "console"), default="console")
    explain_parser = subcommands.add_parser("explain")
    explain_parser.add_argument("report", type=Path)
    explain_parser.add_argument("--format", choices=_REPORT_FORMATS, default="console")
    for name in ("scan", "differential"):
        workflow_parser = subcommands.add_parser(name)
        workflow_parser.add_argument("--config", required=True, type=Path)
        workflow_parser.add_argument(
            "--format", choices=_REPORT_FORMATS, default="console"
        )
    lock_parser = subcommands.add_parser("lock")
    lock_parser.add_argument("--config", required=True, type=Path)
    lock_parser.add_argument("--output", required=True, type=Path)
    lock_parser.add_argument("--format", choices=("json", "console"), default="console")
    init_parser = subcommands.add_parser("init")
    init_parser.add_argument("--baseline", required=True, type=Path)
    init_parser.add_argument("--candidate", required=True, type=Path)
    init_parser.add_argument("--target", required=True, action="append")
    init_parser.add_argument(
        "--framework", choices=("terraform", "kubernetes"), action="append"
    )
    init_parser.add_argument(
        "--execution-mode",
        choices=("hardened-container", "reduced-isolation"),
        default="hardened-container",
    )
    init_parser.add_argument("--checkov-executable", type=Path)
    init_parser.add_argument("--output", required=True, type=Path)
    init_parser.add_argument("--format", choices=("json", "console"), default="console")
    pr_parser = subcommands.add_parser("pr")
    pr_parser.add_argument("--config", required=True, type=Path)
    pr_parser.add_argument("--changed-only", action="store_true", required=True)
    pr_parser.add_argument("--format", choices=_REPORT_FORMATS, default="console")
    return parser


def _parse_target_selector(value: str) -> PublicTarget:
    if type(value) is not str or "=" not in value:
        raise DomainError("target selector must use RULE_ID=RESOURCE_ADDRESS")
    rule_id, resource_address = value.split("=", 1)
    if not rule_id.strip() or not resource_address.strip():
        raise DomainError("target selector must contain a rule and resource")
    return PublicTarget(rule_id.strip(), resource_address.strip())


def _write_receipt(command: str, receipt: dict, output_format: str) -> None:
    if output_format == "json":
        sys.stdout.write(canonical_json(receipt).decode("utf-8"))
        return
    sys.stdout.write(
        f"IaC-Guard-V {command}\nstatus: {receipt['status']}\n"
        f"artifact_contract: {receipt['artifact_contract']}\n"
        f"artifact_sha256: {receipt['artifact_sha256']}\n"
    )


def _write_report(result, output_format: str) -> int:
    if output_format == "json":
        output = result.canonical_json()
    elif output_format == "console":
        output = render_console(result)
    else:
        output = _project_report(result.canonical_dict(), output_format)
    sys.stdout.write(output)
    return result.exit_code


def _project_report(payload: dict, output_format: str) -> str:
    renderers = {
        "sarif": render_sarif,
        "markdown": render_markdown,
        "junit": render_junit,
    }
    try:
        renderer = renderers[output_format]
    except KeyError as exc:
        raise DomainError("report output format is unsupported") from exc
    return renderer(payload)


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


def _explain_report(value: dict) -> str:
    lines = [
        "IaC-Guard-V report explanation",
        f"kind: {value['result_kind']}",
        f"verdict: {value['verdict']}",
        f"exit_code: {value['exit_code']}",
    ]
    if value["result_kind"] == "operational_uncertainty":
        diagnostic = value["diagnostic"]
        lines.extend((
            f"reason: {diagnostic['reason_code']}",
            f"detail: {diagnostic['detail']}",
            f"remediation: {diagnostic['remediation']}",
        ))
        return "\n".join(lines) + "\n"
    isolation = value["execution_isolation"]
    verification = value["verification"]
    policy = value["policy"]
    lines.append(f"isolation: {isolation['mode']}")
    if "failure_stage" in verification:
        lines.extend((
            f"artifact: {verification['artifact_kind']}",
            f"validator: {verification['validator_gate_id']} FAIL "
            f"({verification['failure_reason']})",
            "targets: unavailable because candidate syntax is invalid",
            "scanner integrity: not executed",
            "regression: not evaluated",
            "policy decisions: candidate artifact invalid",
            "remediation: correct the candidate artifact syntax and rerun verification",
        ))
        return "\n".join(lines) + "\n"
    lines.append(
        "scanner integrity: "
        f"{verification['scanner_integrity']['status']} "
        f"({verification['scanner_integrity']['reason_code']})"
    )
    lines.append("targets:")
    for target in verification["targets"]:
        identity = target["binding"]["identity"]
        lines.append(
            f"  {identity['rule_id']} {identity['scope']}: {target['outcome']} "
            f"({target['target_reason']})"
        )
    gates = [verification["preflight"], *verification["validators"], *verification["oracles"]]
    nonpassing = [item for item in gates if item["status"] != "PASS"]
    lines.append("failing/inconclusive gates:")
    lines.extend(
        f"  {item['gate_id']}: {item['status']} ({item['reason_code']})"
        for item in nonpassing
    )
    if not nonpassing:
        lines.append("  none")
    lines.append(
        f"regression: {verification['regression']['status']} "
        f"({verification['regression']['reason_code']})"
    )
    adverse_events = [
        item for item in verification["engine_events"] if item["status"] != "PASS"
    ]
    lines.append("regressions/destructive changes:")
    lines.extend(
        f"  {item['delta_class']}: {item['status']} ({item['reason_code']})"
        for item in adverse_events
    )
    if not adverse_events:
        lines.append("  none")
    lines.append("policy decisions:")
    for decision in policy["decisions"]:
        exception = decision["exception_id"] or "none"
        lines.append(
            f"  {decision['outcome']}: permitted={str(decision['policy_permitted']).lower()} "
            f"exception={exception}"
        )
    remediation = (
        "none; all required evidence passed"
        if value["verdict"] == "VERIFIED"
        else "review the listed target, gate, scanner, regression, and policy evidence"
    )
    lines.append(f"remediation: {remediation}")
    return "\n".join(lines) + "\n"


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
            elif args.format == "console":
                sys.stdout.write(_explain_report(value))
            else:
                sys.stdout.write(_project_report(value, args.format))
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
                    f"({value['hardened_container']['reason_code']})\nValidator registry: "
                    f"{value['validator_registry']['status']} "
                    f"({value['validator_registry']['reason_code']})\n"
                )
            return 0 if (
                result.checkov["status"] == "PASS"
                and result.hardened_container["status"] == "PASS"
                and result.validator_registry["status"] == "PASS"
            ) else 3
        if args.command == "init":
            targets = tuple(_parse_target_selector(item) for item in args.target)
            frameworks = tuple(args.framework or ("kubernetes", "terraform"))
            mode = ExecutionIsolation(args.execution_mode)
            request = PublicVerificationRequest(
                args.baseline,
                args.candidate,
                targets,
                mode,
                args.checkov_executable,
                frameworks,
            )
            payload = canonical_json(public_config_payload(request))
            digest = write_new_regular_file(args.output, payload)
            _write_receipt(
                "init", command_receipt("init", "config-v1", digest), args.format
            )
            return 0
        if args.command == "lock":
            request = load_public_config(args.config)
            if request.execution_isolation is ExecutionIsolation.HARDENED_CONTAINER:
                return _write_report(OperationalReportV1(
                    "HARDENED_CONTAINER_LOCK_UNAVAILABLE",
                    "The Phase-E hardened execution image has not been released, so its "
                    "runtime lock cannot be created.",
                    "Use an explicit verified reduced-isolation Checkov environment for "
                    "local alpha evaluation, or wait for the protected image release.",
                ), args.format)
            try:
                assert request.checkov_executable is not None
                version = _version(request.checkov_executable.resolve(strict=True))
                lock = create_reduced_isolation_lock(request, scanner_version=version)
            except (DomainError, OSError) as exc:
                return _write_report(OperationalReportV1(
                    "WORKFLOW_LOCK_ENVIRONMENT_UNAVAILABLE",
                    redact_detail(str(exc)),
                    "Run doctor and reinstall the exact Checkov 3.3.0 dependency closure "
                    "from pinned wheels before creating a lock.",
                ), args.format)
            payload = canonical_json(lock)
            digest = write_new_regular_file(args.output, payload)
            _write_receipt(
                "lock",
                command_receipt("lock", WORKFLOW_LOCK_CONTRACT, digest),
                args.format,
            )
            return 0
        if args.command in {"verify", "scan", "differential", "pr"}:
            request = load_public_config(args.config)
            if args.command == "pr":
                changed_only_targets_are_bound(request)
            report = verify(request)
            return _write_report(report, args.format)
        raise DomainError("unsupported command")
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
