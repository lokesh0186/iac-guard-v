"""Small public API: paths and selectors in, report-v1 out."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .adapters.checkov import (
    CheckovAdapter,
    CheckovScanRequest,
    checkov_distribution_identity,
)
from .config import ExecutionIsolation, PublicTarget, PublicVerificationRequest
from .enums import ArtifactKind, Status
from .engine import (
    VerificationRequest,
    attest_checkov_scan_plan,
    load_operator_verification_config,
    run_checkov_verification,
)
from .models import DomainError, RequiredGates, require_trusted_scanner_run
from .policy import (
    PolicyRequest,
    evaluate_policy,
    load_operator_execution_context,
    load_operator_policy,
)
from .report import (
    CandidateArtifactFailureReportV1, ExecutionIsolationEvidence,
    OperationalReportV1, VerificationReportV1,
)


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
    isolation = ExecutionIsolationEvidence.reduced_verified()
    try:
        baseline_raw = _untrusted_scan_request(
            request.baseline_root, request.baseline_root, executable, request.frameworks
        )
        baseline = attest_checkov_scan_plan(baseline_raw)
    except DomainError as exc:
        return OperationalReportV1(
            "TRUSTED_BASELINE_EVIDENCE_UNAVAILABLE", str(exc),
            "Repair or restore the trusted baseline and verified scanner environment.",
        )
    try:
        candidate_raw = _untrusted_scan_request(
            request.candidate_root, request.candidate_root, executable, request.frameworks
        )
        candidate = attest_checkov_scan_plan(candidate_raw)
    except DomainError as exc:
        detail = str(exc)
        definite_failure = any(marker in detail for marker in (
            "syntax is invalid", "syntax is malformed", "must be UTF-8",
            "unterminated", "duplicate Terraform", "duplicate Kubernetes",
            "duplicate YAML", "duplicate Kubernetes JSON",
        ))
        if definite_failure:
            if "Terraform" in detail:
                artifact_kind = ArtifactKind.TERRAFORM_HCL
                gate_id = "terraform_hcl_parse"
            elif "JSON" in detail:
                artifact_kind = ArtifactKind.KUBERNETES_JSON
                gate_id = "kubernetes_yaml_parse"
            else:
                artifact_kind = ArtifactKind.KUBERNETES_YAML
                gate_id = "kubernetes_yaml_parse"
            return CandidateArtifactFailureReportV1(
                artifact_kind, gate_id, "ARTIFACT_SYNTAX_INVALID", detail, isolation
            )
        return OperationalReportV1(
            "CANDIDATE_ARTIFACT_INDETERMINATE", detail,
            "Use a supported artifact representation and rerun verification.",
        )
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
        verification, evaluate_policy(PolicyRequest(verification, policy)), isolation
    )


def discover_baseline_targets(
    baseline_root: Path,
    executable: Path,
    frameworks: tuple,
    selectors: tuple[tuple[str, str, str], ...] = (),
    *,
    all_findings: bool = False,
    eligible_paths: tuple[str, ...] | None = None,
) -> tuple[PublicTarget, ...]:
    """Resolve baseline failures to exact public target selectors.

    This function executes the same locked Checkov adapter used by verification. It
    accepts only paths and plain selectors and returns only untrusted public request
    values; scanner evidence and adapter capabilities never cross this boundary.
    """
    if not isinstance(baseline_root, Path) or not isinstance(executable, Path):
        raise DomainError("target discovery requires pathlib baseline and executable paths")
    if type(frameworks) is not tuple or not frameworks:
        raise DomainError("target discovery requires a nonempty framework tuple")
    if type(selectors) is not tuple or any(
        type(item) is not tuple
        or len(item) != 3
        or any(type(value) is not str for value in item)
        for item in selectors
    ):
        raise DomainError("target selectors must be exact rule/resource/file tuples")
    if type(all_findings) is not bool:
        raise DomainError("all_findings must be a Boolean")
    if all_findings == bool(selectors):
        raise DomainError("select explicit targets or all baseline findings, not both")
    if eligible_paths is not None and (
        type(eligible_paths) is not tuple
        or any(type(item) is not str or not item for item in eligible_paths)
    ):
        raise DomainError("eligible target paths must be an exact nonblank string tuple")

    try:
        raw = _untrusted_scan_request(
            baseline_root, baseline_root, executable, frameworks
        )
        plan = attest_checkov_scan_plan(raw)
        run = require_trusted_scanner_run(CheckovAdapter().scan(plan.request))
    except (DomainError, OSError) as exc:
        raise BaselineDiscoveryUnavailable(str(exc)) from exc
    if run.status is not Status.PASS or run.ruleset_integrity is not Status.PASS:
        detail = "; ".join(run.diagnostics) or run.status.value
        raise BaselineDiscoveryUnavailable(
            f"baseline target discovery is not complete: {detail}"
        )

    allowed = None if eligible_paths is None else frozenset(eligible_paths)
    failures = tuple(
        item for item in run.findings
        if not item.suppressed
        and (allowed is None or item.location.file_path in allowed)
    )
    resources = {
        (item.file_path, item.resource_address, item.artifact_kind): item
        for item in plan.expected_resources
    }
    grouped: dict[tuple[str, str, str, ArtifactKind], list] = {}
    for finding in failures:
        key = (
            finding.rule_id,
            finding.resource_address,
            finding.location.file_path,
            finding.artifact_kind,
        )
        grouped.setdefault(key, []).append(finding)

    def public_target(key: tuple[str, str, str, ArtifactKind], count: int) -> PublicTarget:
        rule_id, resource_address, file_path, artifact_kind = key
        resource = resources.get((file_path, resource_address, artifact_kind))
        if resource is None:
            raise DomainError("baseline finding lacks independent resource binding")
        return PublicTarget(
            rule_id,
            resource_address,
            file_path,
            artifact_kind,
            resource.scanner_native_lookup,
            count,
        )

    if all_findings:
        return tuple(
            public_target(key, len(values))
            for key, values in sorted(
                grouped.items(),
                key=lambda item: (*item[0][:3], item[0][3].value),
            )
        )

    resolved: list[PublicTarget] = []
    for rule_id, resource_address, file_path in selectors:
        matches = [
            (key, values) for key, values in grouped.items()
            if key[0] == rule_id
            and key[1] == resource_address
            and (not file_path or key[2] == file_path)
        ]
        if not matches:
            raise DomainError(
                f"baseline has no failed finding for {rule_id}={resource_address}"
            )
        if len(matches) != 1:
            candidates = sorted(
                f"{key[0]}={key[1]}@{key[2]}" for key, _values in matches
            )
            raise DomainError(
                "target selector is ambiguous; choose one exact selector: "
                + ", ".join(candidates)
            )
        key, values = matches[0]
        resolved.append(public_target(key, len(values)))
    identities = [
        (item.rule_id, item.resource_address, item.file_path, item.artifact_kind.value)
        for item in resolved
    ]
    if len(identities) != len(set(identities)):
        raise DomainError("target selectors resolve to duplicate exact targets")
    return tuple(sorted(resolved, key=lambda item: (
        item.rule_id, item.resource_address, item.file_path, item.artifact_kind.value,
    )))


class BaselineDiscoveryUnavailable(DomainError):
    """The locked baseline scanner could not provide complete discovery evidence."""


__all__ = ["BaselineDiscoveryUnavailable", "discover_baseline_targets", "verify"]
