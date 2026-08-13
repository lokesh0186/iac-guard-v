#!/usr/bin/env python3
"""Run the E4 fixtures through the protected scanner locks and emit evidence JSON."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from iac_guard_v.adapters.checkov import (
    CheckovAdapter,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
    checkov_distribution_identity,
)
from iac_guard_v.adapters.kics import KicsAdapter, create_kics_scan_request
from iac_guard_v.adapters.phase_e_lock import (
    load_locked_container_identity,
    load_protected_checks_cache_identity,
    load_protected_phase_e_evidence,
)
from iac_guard_v.adapters.phase_e_runtime import attest_container_runtime
from iac_guard_v.adapters.trivy import TrivyAdapter, create_trivy_scan_request
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import BoundInputFile, ExpectedResource


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "controls/catalog-v1.yml"
CONTRACT = "phase-e-control-fixture-runtime-evidence-v2"
ATTESTATION_CONTRACT = "phase-e-control-fixture-execution-attestation-v1"


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


def _bound(path: Path) -> BoundInputFile:
    metadata = path.stat()
    return BoundInputFile(
        path.name, "regular_file", metadata.st_size,
        hashlib.sha256(path.read_bytes()).hexdigest(), metadata.st_dev, metadata.st_ino,
    )


def _observation(run, rule_id: str) -> tuple[str, str]:
    if run.status.value != "PASS":
        normalized = "ERROR" if run.status.value == "ERROR" else "INCONCLUSIVE"
        return run.diagnostics[0] if run.diagnostics else run.status.value, normalized
    failed = any(item.rule_id == rule_id for item in run.findings)
    passed = any(
        item.rule_id == rule_id and item.native_result.value == "PASSED"
        for item in run.evaluations
    )
    skipped = any(
        item.rule_id == rule_id and item.native_result.value == "SKIPPED"
        for item in run.evaluations
    )
    if failed:
        return "FAILED", "FINDING"
    if passed:
        return "PASSED", "NO_FINDING"
    if skipped:
        return "SKIPPED", "SUPPRESSED"
    return "ABSENT", "NO_FINDING"


def _record(
    *, relationship_id: str, fixture_kind: str, fixture_sha256: str,
    scanner: str, version: str, policy_identity: str, invocation_identity: str,
    environment_identity: str, native_result: str, normalized_result: str,
    raw_output_sha256: str, canonical_output_sha256: str,
    expected: str, execution_status: str, exit_code: int,
    diagnostics: tuple[str, ...], command_argv: tuple[tuple[str, ...], ...],
    stdout_sha256: str, stderr_sha256: str, duration_ms: int,
) -> dict:
    canonical_commands = _portable_argv(command_argv)
    return {
        "relationship_id": relationship_id,
        "fixture_kind": fixture_kind,
        "fixture_sha256": fixture_sha256,
        "scanner": scanner,
        "scanner_version": version,
        "policy_identity": policy_identity,
        "invocation_identity": invocation_identity,
        "environment_identity": environment_identity,
        "execution_status": execution_status,
        "exit_code": exit_code,
        "diagnostics": list(diagnostics),
        "command_argv": [list(command) for command in canonical_commands],
        "command_argv_sha256": _sha([list(command) for command in canonical_commands]),
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "duration_ms": duration_ms,
        "native_result": native_result,
        "normalized_result": normalized_result,
        "raw_output_sha256": raw_output_sha256,
        "canonical_output_sha256": canonical_output_sha256,
        "expected_relationship_observation": expected,
    }


def _portable_argv(commands: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
    """Retain the exact locked shape without publishing machine-local temp roots."""
    result = []
    for command in commands:
        normalized = []
        for index, value in enumerate(command):
            if index == 0:
                normalized.append(
                    "<trusted-container-runtime>" if Path(value).name == "docker"
                    else "<checkov-executable>"
                )
                continue
            if ":/iacgv-input:" in value:
                normalized.append("<materialized-input>:/iacgv-input:ro")
            elif ":/work:" in value:
                normalized.append("<materialized-input>:/work:ro")
            elif ":/iacgv-output:" in value:
                normalized.append("<bounded-output>:/iacgv-output:rw")
            elif ":/out:" in value:
                normalized.append("<bounded-output>:/out:rw")
            elif ":/iacgv-cache:" in value:
                normalized.append("<protected-cache>:/iacgv-cache:rw")
            elif ":/cache:" in value:
                normalized.append("<protected-cache>:/cache:rw")
            elif value.startswith(("/private/", "/tmp/", "/var/folders/")):
                normalized.append("<ephemeral-path>")
            else:
                normalized.append(value)
        result.append(tuple(normalized))
    return tuple(result)


def _execute_with_argv(module, operation):
    """Capture every actual process argv while retaining the production runner."""
    original = module.run_command
    commands = []

    def run(request):
        result = original(request)
        commands.append(tuple(result.argv))
        return result

    module.run_command = run
    try:
        return operation(), tuple(commands)
    finally:
        module.run_command = original


def generate(catalog: dict, cache: Path, checkov: Path, docker: Path) -> dict:
    import iac_guard_v.adapters.checkov as checkov_module
    import iac_guard_v.adapters.kics as kics_module
    import iac_guard_v.adapters.trivy as trivy_module

    architecture = "linux/arm64" if platform.machine() in {"arm64", "aarch64"} else "linux/amd64"
    protected = load_protected_phase_e_evidence(ROOT)
    kics_lock = load_locked_container_identity(protected, "kics", architecture)
    trivy_lock = load_locked_container_identity(protected, "trivy", architecture)
    checks = load_protected_checks_cache_identity(protected, cache)
    checkov_distribution = checkov_distribution_identity(checkov, "3.3.0")
    records = []
    with tempfile.TemporaryDirectory(prefix="iacgv-catalog-evidence-") as directory:
        workspace = Path(directory)
        roots = []
        jobs = []
        for relationship in catalog["relationships"]:
            for fixture_kind, fixture in sorted(relationship["fixtures"].items()):
                root = workspace / relationship["relationship_id"] / fixture_kind
                root.mkdir(parents=True)
                destination = root / "manifest.yaml"
                shutil.copyfile(ROOT / fixture, destination)
                roots.append(root)
                jobs.append((relationship, fixture_kind, destination, root))
        limit = int(os.environ.get("IACGV_CATALOG_EVIDENCE_LIMIT", "0"))
        if limit:
            jobs = jobs[:limit]
            roots = roots[:limit]
        runtime = attest_container_runtime(
            docker,
            protected_execution_context_identity=hashlib.sha256(
                b"phase-e-catalog-locked-fixture-execution-v1"
            ).hexdigest(),
            protected_evidence=protected,
            evaluated_workspaces=tuple(roots),
        )
        for relationship, fixture_kind, source, root in jobs:
            expected_by_scanner = relationship["expected_locked_observations"][fixture_kind]
            fixture_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            document = yaml.safe_load(source.read_text(encoding="utf-8"))
            name = document["metadata"]["name"]
            native_resource = f"Pod.default.{name}"
            resource_identity = f"v1/Pod/default/{name}"
            checkov_request = CheckovScanRequest(
                executable=checkov, scan_root=root, workspace_root=root,
                frameworks=("kubernetes",), files_eligible=("manifest.yaml",),
                expected_version="3.3.0",
                expected_executable_sha256=hashlib.sha256(checkov.read_bytes()).hexdigest(),
                expected_scanner_environment_sha256=(
                    checkov_distribution.scanner_environment_digest
                ),
                expected_policy_inventory_sha256=(
                    checkov_distribution.policy_inventory_digest
                ),
                kubernetes_identities=(CheckovKubernetesIdentity(
                    "manifest.yaml", native_resource, "v1", "Pod", "default", name,
                ),),
                expected_resources=(ExpectedResource(
                    "manifest.yaml", resource_identity,
                    ArtifactKind.KUBERNETES_YAML, native_resource,
                ),),
            )
            checkov_run, checkov_argv = _execute_with_argv(
                checkov_module, lambda: CheckovAdapter().scan(checkov_request),
            )
            print(
                relationship["relationship_id"], fixture_kind, "checkov",
                checkov_run.status.value, checkov_run.diagnostics,
                file=sys.stderr, flush=True,
            )
            native, normalized = _observation(checkov_run, relationship["checkov_rule_id"])
            records.append(_record(
                relationship_id=relationship["relationship_id"],
                fixture_kind=fixture_kind, fixture_sha256=fixture_sha256,
                scanner="checkov", version=checkov_run.scanner_version,
                policy_identity=checkov_run.policy_inventory_digest,
                invocation_identity=checkov_run.invocation_config_digest,
                environment_identity=checkov_run.scanner_environment_digest,
                native_result=native, normalized_result=normalized,
                raw_output_sha256=checkov_run.raw_output_sha256,
                canonical_output_sha256=_sha(checkov_run.canonical_dict()),
                expected=expected_by_scanner["checkov"],
                execution_status=checkov_run.status.value,
                exit_code=checkov_run.exit_code,
                diagnostics=checkov_run.diagnostics,
                command_argv=checkov_argv,
                stdout_sha256=checkov_run.stdout_sha256,
                stderr_sha256=checkov_run.stderr_sha256,
                duration_ms=checkov_run.duration_ms,
            ))
            bound = _bound(source)
            expected_resource = ExpectedResource(
                "manifest.yaml", resource_identity,
                ArtifactKind.KUBERNETES_YAML, native_resource,
            )
            kics, kics_argv = _execute_with_argv(
                kics_module,
                lambda: KicsAdapter().scan(create_kics_scan_request(
                    workspace_root=root, scan_root=root,
                    files_eligible=("manifest.yaml",), eligible_file_evidence=(bound,),
                    expected_resources=(expected_resource,), container_runtime=runtime,
                    locked_identity=kics_lock,
                )),
            )
            print(
                relationship["relationship_id"], fixture_kind, "kics",
                kics.scanner_run.status.value, kics.scanner_run.diagnostics,
                file=sys.stderr, flush=True,
            )
            native, normalized = _observation(kics.scanner_run, relationship["kics_query_id"])
            records.append(_record(
                relationship_id=relationship["relationship_id"],
                fixture_kind=fixture_kind, fixture_sha256=fixture_sha256,
                scanner="kics", version=kics.scanner_run.scanner_version,
                policy_identity=kics.scanner_run.policy_inventory_digest,
                invocation_identity=kics.invocation_identity,
                environment_identity=kics.scanner_run.scanner_environment_digest,
                native_result=native, normalized_result=normalized,
                raw_output_sha256=kics.native_output_bytes_sha256,
                canonical_output_sha256=kics.canonical_native_output_sha256,
                expected=expected_by_scanner["kics"],
                execution_status=kics.scanner_run.status.value,
                exit_code=kics.scanner_run.exit_code,
                diagnostics=kics.scanner_run.diagnostics,
                command_argv=kics_argv,
                stdout_sha256=kics.scanner_run.stdout_sha256,
                stderr_sha256=kics.scanner_run.stderr_sha256,
                duration_ms=kics.scanner_run.duration_ms,
            ))
            trivy, trivy_argv = _execute_with_argv(
                trivy_module,
                lambda: TrivyAdapter().scan(create_trivy_scan_request(
                    workspace_root=root, scan_root=root,
                    files_eligible=("manifest.yaml",), eligible_file_evidence=(bound,),
                    expected_resources=(expected_resource,), container_runtime=runtime,
                    protected_checks_cache=checks, locked_identity=trivy_lock,
                )),
            )
            print(
                relationship["relationship_id"], fixture_kind, "trivy",
                trivy.scanner_run.status.value, trivy.scanner_run.diagnostics,
                file=sys.stderr, flush=True,
            )
            native, normalized = _observation(
                trivy.scanner_run, relationship["trivy_check_id"],
            )
            records.append(_record(
                relationship_id=relationship["relationship_id"],
                fixture_kind=fixture_kind, fixture_sha256=fixture_sha256,
                scanner="trivy", version=trivy.scanner_run.scanner_version,
                policy_identity=trivy.scanner_run.policy_inventory_digest,
                invocation_identity=trivy.invocation_identity,
                environment_identity=trivy.scanner_run.scanner_environment_digest,
                native_result=native, normalized_result=normalized,
                raw_output_sha256=trivy.raw_results_file_sha256,
                canonical_output_sha256=trivy.canonical_output_sha256,
                expected=expected_by_scanner["trivy"],
                execution_status=trivy.scanner_run.status.value,
                exit_code=trivy.scanner_run.exit_code,
                diagnostics=trivy.scanner_run.diagnostics,
                command_argv=trivy_argv,
                stdout_sha256=trivy.raw_stdout_sha256,
                stderr_sha256=trivy.raw_stderr_sha256,
                duration_ms=trivy.scanner_run.duration_ms,
            ))
    records.sort(key=lambda item: (
        item["relationship_id"], item["fixture_kind"], item["scanner"],
    ))
    record_root = _sha(records)
    attestation = {
        "contract": ATTESTATION_CONTRACT,
        "status": "PROTECTED_LOCAL_EXECUTION",
        "creation_timestamp": datetime.now(timezone.utc).isoformat(),
        "architecture": architecture,
        "protected_evidence_identity": protected.identity,
        "protected_cache_manifest_root": checks.protected_manifest_root,
        "cache_attestation_identity": checks.cache_attestation_identity,
        "cache_attestation_record_sha256": checks.cache_attestation_record_sha256,
        "cache_attestation_signature_sha256": checks.cache_attestation_signature_sha256,
        "cache_attestation_public_key_sha256": checks.cache_attestation_public_key_sha256,
        "runtime_identity": runtime.identity,
        "runtime_executable_sha256": runtime.executable_sha256,
        "runtime_client_version": runtime.client_version,
        "runtime_server_version": runtime.server_version,
        "runtime_context_identity": runtime.context_identity,
        "runtime_daemon_identity": runtime.daemon_identity,
        "runner_implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "record_root_sha256": record_root,
    }
    attestation["attestation_identity"] = _sha(attestation)
    payload = {
        "contract": CONTRACT,
        "architecture": architecture,
        "protected_evidence_identity": protected.identity,
        "records": records,
        "execution_attestation": attestation,
    }
    payload["evidence_root_sha256"] = _sha(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=Path, default=Path(os.environ.get(
        "IACGV_PHASE_E_CACHE", "/nonexistent",
    )))
    parser.add_argument("--checkov", type=Path, required=True)
    parser.add_argument("--docker", type=Path, default=Path(shutil.which("docker") or "docker"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    payload = generate(
        catalog, args.cache.resolve(strict=True), args.checkov.resolve(strict=True),
        args.docker.resolve(strict=True),
    )
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
