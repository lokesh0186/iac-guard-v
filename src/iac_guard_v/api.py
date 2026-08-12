"""Small public API: paths and selectors in, report-v1 out."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .adapters.checkov import CheckovScanRequest, checkov_distribution_identity
from .config import ExecutionIsolation, PublicVerificationRequest
from .engine import (
    VerificationRequest,
    attest_checkov_scan_plan,
    load_operator_verification_config,
    run_checkov_verification,
)
from .models import RequiredGates
from .policy import (
    PolicyRequest,
    evaluate_policy,
    load_operator_execution_context,
    load_operator_policy,
)
from .report import OperationalReportV1, VerificationReportV1


def _launcher_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _untrusted_scan_request(
    root: Path,
    workspace: Path,
    executable: Path,
    frameworks: tuple,
) -> CheckovScanRequest:
    executable = executable.resolve(strict=True)
    distribution = checkov_distribution_identity(executable, "3.3.0")
    return CheckovScanRequest(
        executable=executable,
        scan_root=root,
        workspace_root=workspace,
        frameworks=frameworks,
        files_eligible=(),
        expected_version="3.3.0",
        expected_executable_sha256=_launcher_digest(executable),
        expected_scanner_environment_sha256=distribution.scanner_environment_digest,
        expected_policy_inventory_sha256=distribution.policy_inventory_digest,
    )


def verify(
    request: PublicVerificationRequest,
) -> VerificationReportV1 | OperationalReportV1:
    """Run one public verification without accepting precomputed or trusted evidence."""
    if type(request) is not PublicVerificationRequest:
        raise TypeError("verify requires an exact PublicVerificationRequest")
    if request.execution_isolation is ExecutionIsolation.HARDENED_CONTAINER:
        return OperationalReportV1(
            "HARDENED_CONTAINER_UNAVAILABLE",
            "Phase E container execution is not installed; native execution was not selected.",
            "Run doctor, install the pinned hardened image when available, or explicitly "
            "select reduced-isolation only for operator-controlled local content.",
        )
    executable = request.checkov_executable
    baseline_raw = _untrusted_scan_request(
        request.baseline_root, request.baseline_root, executable, request.frameworks
    )
    candidate_raw = _untrusted_scan_request(
        request.candidate_root, request.candidate_root, executable, request.frameworks
    )
    baseline = attest_checkov_scan_plan(baseline_raw)
    candidate = attest_checkov_scan_plan(candidate_raw)
    validators = tuple(sorted(
        f"{name}_hcl_parse" if name == "terraform" else "kubernetes_yaml_parse"
        for name in request.frameworks
    ))
    config = load_operator_verification_config(
        baseline.request,
        candidate.request,
        required_gates=RequiredGates(validators),
        frameworks=request.frameworks,
    )
    engine_request = VerificationRequest(
        baseline, candidate, tuple(item.to_domain() for item in request.targets), config
    )
    verification = run_checkov_verification(engine_request)
    context = load_operator_execution_context(config)
    policy = load_operator_policy(
        {"exceptions": [], "optional_gates": []}, context=context
    )
    return VerificationReportV1(
        verification, evaluate_policy(PolicyRequest(verification, policy))
    )


__all__ = ["verify"]
