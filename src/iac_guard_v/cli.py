"""Command-line boundary for report-v1 and deterministic environment diagnosis."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from importlib.resources import files as package_files
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

from . import __version__
from .adapters.checkov import CHECKOV_CONTRACT, checkov_distribution_identity
from .api import (
    BaselineDiscoveryUnavailable,
    _verify_git,
    discover_baseline_targets,
    verify,
)
from .config import (
    ExecutionIsolation, PublicTarget, PublicVerificationRequest, load_public_config,
)
from .models import DomainError
from .report import OperationalReportV1, render_console, validate_report_payload
from .redaction import redact_detail
from .reporters import render_junit, render_markdown, render_sarif
from .workflow import (
    WORKFLOW_LOCK_CONTRACT, canonical_json, changed_only_targets_are_bound,
    bind_inventory_targets, command_receipt, create_reduced_isolation_lock,
    materialize_git_comparison, public_config_payload, write_new_regular_file,
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
            text=True, timeout=30, env={
                "PATH": "", "LANG": "C", "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            },
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


def doctor(
    mode: str = "all", checkov_executable: Path | None = None,
) -> DoctorReportV1:
    if mode not in {"all", "local-trusted", "hardened-container"}:
        raise DomainError("doctor mode is unsupported")
    if checkov_executable is not None:
        if not isinstance(checkov_executable, Path):
            raise DomainError("doctor Checkov executable must be pathlib.Path")
        if mode == "hardened-container":
            raise DomainError(
                "--checkov-executable is valid only for local-trusted or all doctor mode"
            )
        discovered = str(checkov_executable)
    else:
        discovered = shutil.which("checkov")
    if discovered is None:
        checkov = {
            "status": "UNAVAILABLE",
            "reason_code": "CHECKOV_NOT_FOUND",
            "remediation": "python -m pip install --no-compile checkov==3.3.0",
        }
    else:
        try:
            executable = Path(discovered).resolve(strict=True)
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
                    "python -m pip install --force-reinstall --no-compile checkov==3.3.0"
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
    parser = argparse.ArgumentParser(
        prog="iac-guard",
        description="Fail-closed before/after verification for infrastructure-as-code repairs.",
        epilog=(
            "Canonical alpha command:\n"
            "  iac-guard verify --before BEFORE --after AFTER "
            "--all-baseline-findings --local-trusted\n\n"
            "Exit codes: 0 VERIFIED, 1 FAILED, 2 invalid request, "
            "3 INCONCLUSIVE, 4 internal error.\n"
            "The canonical alpha command is verify. Local trusted mode is reduced "
            "isolation for operator-controlled input only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    verify_parser = subcommands.add_parser(
        "verify",
        help="verify one before/after repair (canonical alpha command)",
        description=(
            "Verify explicit targets or every exact failed baseline finding. "
            "Target grammar: RULE_ID=RESOURCE_ADDRESS or RULE_ID=RESOURCE_ADDRESS@FILE."
        ),
        epilog=(
            "Example:\n  iac-guard verify --before ./before --after ./after "
            "--all-baseline-findings "
            "--local-trusted --output ./iac-guard-report.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    request_source = verify_parser.add_mutually_exclusive_group(required=True)
    request_source.add_argument("--config", type=Path)
    request_source.add_argument("--before", type=Path)
    verify_parser.add_argument("--after", type=Path)
    target_mode = verify_parser.add_mutually_exclusive_group()
    target_mode.add_argument("--target", action="append")
    target_mode.add_argument("--all-baseline-findings", action="store_true")
    verify_parser.add_argument(
        "--framework", choices=("terraform", "kubernetes"), action="append"
    )
    verify_parser.add_argument("--local-trusted", action="store_true")
    verify_parser.add_argument("--checkov-executable", type=Path)
    verify_parser.add_argument("--format", choices=_REPORT_FORMATS, default="console")
    verify_parser.add_argument("--output", type=Path)
    verify_parser.add_argument("--quiet", action="store_true")
    doctor_parser = subcommands.add_parser(
        "doctor", help="diagnose readiness for one selected isolation mode"
    )
    doctor_parser.add_argument(
        "--mode", choices=("local-trusted", "hardened-container", "all"), default="all"
    )
    doctor_parser.add_argument(
        "--checkov-executable", type=Path,
        help="exact Checkov 3.3.0 launcher for local-trusted diagnosis",
    )
    doctor_parser.add_argument("--format", choices=("json", "console"), default="console")
    demo_parser = subcommands.add_parser(
        "demo", help="show illustrative outcomes or run the real packaged Checkov example"
    )
    demo_parser.add_argument("--real", action="store_true")
    demo_parser.add_argument("--local-trusted", action="store_true")
    demo_parser.add_argument("--checkov-executable", type=Path)
    demo_parser.add_argument("--format", choices=_REPORT_FORMATS, default="console")
    demo_parser.add_argument("--output", type=Path)
    demo_parser.add_argument("--quiet", action="store_true")
    explain_parser = subcommands.add_parser(
        "explain", help="render and explain an existing validated report-v1"
    )
    explain_parser.add_argument("report", type=Path)
    explain_parser.add_argument("--format", choices=_REPORT_FORMATS, default="console")
    explain_parser.add_argument("--output", type=Path)
    explain_parser.add_argument("--quiet", action="store_true")
    for name in ("scan", "differential"):
        workflow_parser = subcommands.add_parser(
            name,
            help=f"advanced compatibility alias of verify --config ({name})",
        )
        workflow_parser.add_argument("--config", required=True, type=Path)
        workflow_parser.add_argument(
            "--format", choices=_REPORT_FORMATS, default="console"
        )
        workflow_parser.add_argument("--output", type=Path)
        workflow_parser.add_argument("--quiet", action="store_true")
    lock_parser = subcommands.add_parser(
        "lock", help="write a non-evidentiary reduced-isolation environment lock"
    )
    lock_parser.add_argument("--config", required=True, type=Path)
    lock_parser.add_argument("--output", required=True, type=Path)
    lock_parser.add_argument("--format", choices=("json", "console"), default="console")
    init_parser = subcommands.add_parser(
        "init", help="write an advanced reproducible config-v1 request"
    )
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
    pr_parser = subcommands.add_parser(
        "pr", help="verify exact Git base/head objects without changing the checkout"
    )
    pr_source = pr_parser.add_mutually_exclusive_group(required=True)
    pr_source.add_argument("--config", type=Path)
    pr_source.add_argument("--base-ref")
    pr_parser.add_argument("--head-ref")
    pr_parser.add_argument("--repository", type=Path, default=Path("."))
    pr_targets = pr_parser.add_mutually_exclusive_group()
    pr_targets.add_argument("--target", action="append")
    pr_targets.add_argument("--all-baseline-findings", action="store_true")
    pr_parser.add_argument(
        "--framework", choices=("terraform", "kubernetes"), action="append"
    )
    pr_parser.add_argument("--local-trusted", action="store_true")
    pr_parser.add_argument("--checkov-executable", type=Path)
    pr_parser.add_argument("--changed-only", action="store_true")
    pr_parser.add_argument("--format", choices=_REPORT_FORMATS, default="console")
    pr_parser.add_argument("--output", type=Path)
    pr_parser.add_argument("--quiet", action="store_true")
    return parser


def _parse_target_selector(value: str) -> PublicTarget:
    if type(value) is not str or "=" not in value:
        raise DomainError("target selector must use RULE_ID=RESOURCE_ADDRESS")
    rule_id, resource_address = value.split("=", 1)
    if not rule_id.strip() or not resource_address.strip():
        raise DomainError("target selector must contain a rule and resource")
    file_path = ""
    if "@" in resource_address:
        resource_address, file_path = resource_address.rsplit("@", 1)
        if not resource_address.strip() or not file_path.strip():
            raise DomainError(
                "file-qualified target selector must use RULE_ID=RESOURCE_ADDRESS@FILE"
            )
    return PublicTarget(rule_id.strip(), resource_address.strip(), file_path.strip())


def _direct_request(args) -> PublicVerificationRequest | OperationalReportV1:
    if args.after is None:
        raise DomainError("direct verification requires --after")
    if not args.target and not args.all_baseline_findings:
        raise DomainError(
            "direct verification requires --target or --all-baseline-findings"
        )
    frameworks = tuple(args.framework or ("kubernetes", "terraform"))
    if not args.local_trusted:
        if args.checkov_executable is not None:
            raise DomainError("--checkov-executable requires --local-trusted")
        return OperationalReportV1(
            "HARDENED_CONTAINER_UNAVAILABLE",
            "The hardened execution image is not released and local execution was not selected.",
            "Rerun with --local-trusted for operator-controlled local content.",
        )
    configured = args.checkov_executable
    if configured is None:
        discovered = shutil.which("checkov")
        if discovered is None:
            return OperationalReportV1(
                "CHECKOV_NOT_FOUND",
                "Local trusted mode could not find the locked Checkov executable.",
                "Install Checkov 3.3.0, then rerun with --local-trusted.",
            )
        configured = Path(discovered)
    selectors = tuple(
        (
            target.rule_id,
            target.resource_address,
            target.file_path,
        )
        for target in (_parse_target_selector(value) for value in (args.target or ()))
    )
    try:
        targets = discover_baseline_targets(
            args.before,
            configured,
            frameworks,
            selectors,
            all_findings=args.all_baseline_findings,
        )
    except BaselineDiscoveryUnavailable as exc:
        return OperationalReportV1(
            "BASELINE_TARGET_DISCOVERY_UNAVAILABLE",
            redact_detail(str(exc)),
            "Run doctor --mode local-trusted and repair the exact Checkov 3.3.0 environment.",
        )
    if not targets:
        return OperationalReportV1(
            "NO_BASELINE_TARGETS",
            "The complete locked baseline scan produced no selectable failed findings.",
            "Provide an explicit failing baseline or review the baseline scanner scope.",
        )
    return PublicVerificationRequest(
        args.before,
        args.after,
        targets,
        ExecutionIsolation.REDUCED_ISOLATION,
        configured,
        frameworks,
    )


def _pr_executable(args) -> Path | OperationalReportV1:
    if not args.local_trusted:
        if args.checkov_executable is not None:
            raise DomainError("--checkov-executable requires --local-trusted")
        return OperationalReportV1(
            "HARDENED_CONTAINER_UNAVAILABLE",
            "The hardened execution image is not released and local execution was not selected.",
            "Rerun with --local-trusted for operator-controlled local Git content.",
        )
    configured = args.checkov_executable
    if configured is None:
        discovered = shutil.which("checkov")
        if discovered is None:
            return OperationalReportV1(
                "CHECKOV_NOT_FOUND",
                "Local trusted mode could not find the locked Checkov executable.",
                "Install Checkov 3.3.0, then rerun with --local-trusted.",
            )
        configured = Path(discovered)
    return configured


def _git_pr_report(args):
    if args.head_ref is None:
        raise DomainError("Git-aware pr verification requires --head-ref")
    if not args.target and not args.all_baseline_findings:
        raise DomainError("Git-aware pr requires --target or --all-baseline-findings")
    executable = _pr_executable(args)
    if type(executable) is OperationalReportV1:
        return executable
    frameworks = tuple(args.framework or ("kubernetes", "terraform"))
    selectors = tuple(
        (target.rule_id, target.resource_address, target.file_path)
        for target in (_parse_target_selector(value) for value in (args.target or ()))
    )
    with materialize_git_comparison(
        args.repository, args.base_ref, args.head_ref
    ) as materialization:
        eligible = materialization.changed_paths if args.changed_only else None
        try:
            targets = discover_baseline_targets(
                materialization.baseline_root,
                executable,
                frameworks,
                selectors,
                all_findings=args.all_baseline_findings,
                eligible_paths=eligible,
            )
        except BaselineDiscoveryUnavailable as exc:
            return OperationalReportV1(
                "BASELINE_TARGET_DISCOVERY_UNAVAILABLE",
                redact_detail(str(exc)),
                "Run doctor --mode local-trusted and repair Checkov 3.3.0.",
            )
        if not targets:
            return OperationalReportV1(
                "NO_BASELINE_TARGETS",
                "No exact failing baseline target matched the protected Git selection.",
                "Review the changed paths or provide a file-qualified --target selector.",
            )
        request = PublicVerificationRequest(
            materialization.baseline_root,
            materialization.candidate_root,
            targets,
            ExecutionIsolation.REDUCED_ISOLATION,
            executable,
            frameworks,
        )
        return _verify_git(request, materialization)


def _write_receipt(command: str, receipt: dict, output_format: str) -> None:
    if output_format == "json":
        sys.stdout.write(canonical_json(receipt).decode("utf-8"))
        return
    sys.stdout.write(
        f"IaC-Guard-V {command}\nstatus: {receipt['status']}\n"
        f"artifact_contract: {receipt['artifact_contract']}\n"
        f"artifact_sha256: {receipt['artifact_sha256']}\n"
    )


def _write_report(
    result, output_format: str, output_path: Path | None = None, *, quiet: bool = False,
) -> int:
    if output_format == "json":
        output = result.canonical_json()
    elif output_format == "console":
        output = render_console(result)
    else:
        output = _project_report(result.canonical_dict(), output_format)
    if output_path is not None:
        artifact = result.canonical_json() if output_format == "console" else output
        write_new_regular_file(
            output_path, artifact.encode("utf-8"), max_bytes=25 * 1024 * 1024
        )
    if not quiet:
        sys.stdout.write(output)
    return result.exit_code


def _write_text_artifact(
    text: str, output_path: Path | None, *, quiet: bool = False,
) -> None:
    if output_path is not None:
        write_new_regular_file(
            output_path, text.encode("utf-8"), max_bytes=25 * 1024 * 1024
        )
    if not quiet:
        sys.stdout.write(text)


def _offline_demo(args) -> int:
    result = OperationalReportV1(
        "OFFLINE_DEMO_ONLY",
        "Illustrative non-evidentiary outcomes: VERIFIED, FAILED, SUPPRESSED, INCONCLUSIVE.",
        "Run demo --real --local-trusted or verify for scanner-backed evidence.",
    )
    if args.format != "console":
        _write_report(
            result, args.format, args.output, quiet=args.quiet
        )
        return 0
    text = (
        "IaC-Guard-V offline demo (illustrative; not verification evidence)\n"
        "VERIFIED     target FIXED; scanner integrity PASS; policy VERIFIED; exit 0\n"
        "FAILED       target STILL_PRESENT; policy FAILED; exit 1\n"
        "SUPPRESSED   suppression visible; policy FAILED; exit 1\n"
        "INCONCLUSIVE scanner or coverage evidence unavailable; exit 3\n"
        "Next: iac-guard demo --real --local-trusted\n"
    )
    _write_text_artifact(text, args.output, quiet=args.quiet)
    return 0


def _real_demo(args) -> int:
    if not args.local_trusted:
        raise DomainError("demo --real requires the explicit --local-trusted mode")
    temporary = Path(tempfile.mkdtemp(prefix="iacgv-real-demo-"))
    try:
        baseline = temporary / "before"
        candidate = temporary / "after"
        baseline.mkdir()
        candidate.mkdir()
        example = package_files("iac_guard_v").joinpath(
            "examples", "checkov-before-after"
        )
        (baseline / "main.tf").write_text(
            example.joinpath("before.tf").read_text(encoding="utf-8"), encoding="utf-8"
        )
        (candidate / "main.tf").write_text(
            example.joinpath("after.tf").read_text(encoding="utf-8"), encoding="utf-8"
        )
        request = _direct_request(SimpleNamespace(
            before=baseline,
            after=candidate,
            target=["CKV_AWS_53=aws_s3_bucket_public_access_block.example"],
            all_baseline_findings=False,
            framework=["terraform"],
            local_trusted=True,
            checkov_executable=args.checkov_executable,
        ))
        report = request if type(request) is OperationalReportV1 else verify(request)
        return _write_report(
            report, args.format, args.output, quiet=args.quiet
        )
    except (FileNotFoundError, OSError) as exc:
        raise DomainError("packaged real-demo fixture is unavailable") from exc
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


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
            return _real_demo(args) if args.real else _offline_demo(args)
        if args.command == "explain":
            value = _read_report(args.report)
            if args.format == "json":
                rendered = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
            elif args.format == "console":
                rendered = _explain_report(value)
            else:
                rendered = _project_report(value, args.format)
            _write_text_artifact(rendered, args.output, quiet=args.quiet)
            return 0
        if args.command == "doctor":
            result = (
                doctor()
                if args.mode == "all" and args.checkov_executable is None
                else doctor(args.mode, args.checkov_executable)
            )
            if args.format == "json":
                sys.stdout.write(result.canonical_json())
            else:
                value = result.canonical_dict()
                sys.stdout.write(
                    f"IaC-Guard-V doctor\nRequested mode: {args.mode}\n"
                    f"Checkov: {value['checkov']['status']} "
                    f"({value['checkov']['reason_code']})\nHardened container: "
                    f"{value['hardened_container']['status']} "
                    f"({value['hardened_container']['reason_code']})\nValidator registry: "
                    f"{value['validator_registry']['status']} "
                    f"({value['validator_registry']['reason_code']})\n"
                )
            local_ready = (
                result.checkov["status"] == "PASS"
                and result.validator_registry["status"] == "PASS"
            )
            hardened_ready = (
                result.hardened_container["status"] == "PASS"
                and result.validator_registry["status"] == "PASS"
            )
            ready = (
                local_ready if args.mode == "local-trusted"
                else hardened_ready if args.mode == "hardened-container"
                else local_ready and hardened_ready
            )
            return 0 if ready else 3
        if args.command == "init":
            targets = tuple(_parse_target_selector(item) for item in args.target)
            frameworks = tuple(args.framework or ("kubernetes", "terraform"))
            targets = bind_inventory_targets(args.baseline, targets, frameworks)
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
        if args.command == "verify":
            if args.config is not None:
                if any((
                    args.after is not None,
                    bool(args.target),
                    args.all_baseline_findings,
                    bool(args.framework),
                    args.local_trusted,
                    args.checkov_executable is not None,
                )):
                    raise DomainError(
                        "--config cannot be combined with direct request arguments"
                    )
                request = load_public_config(args.config)
            else:
                request = _direct_request(args)
                if type(request) is OperationalReportV1:
                    return _write_report(
                        request, args.format, args.output, quiet=args.quiet
                    )
            report = verify(request)
            return _write_report(report, args.format, args.output, quiet=args.quiet)
        if args.command == "pr":
            if args.config is not None:
                if any((
                    args.head_ref is not None,
                    bool(args.target),
                    args.all_baseline_findings,
                    bool(args.framework),
                    args.local_trusted,
                    args.checkov_executable is not None,
                    args.repository != Path("."),
                )):
                    raise DomainError(
                        "--config cannot be combined with direct Git request arguments"
                    )
                request = load_public_config(args.config)
                if args.changed_only:
                    changed_only_targets_are_bound(request)
                report = verify(request)
            else:
                report = _git_pr_report(args)
            return _write_report(
                report, args.format, args.output, quiet=args.quiet
            )
        if args.command in {"scan", "differential"}:
            request = load_public_config(args.config)
            report = verify(request)
            return _write_report(
                report, args.format, args.output, quiet=args.quiet
            )
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
