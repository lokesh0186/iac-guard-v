"""Small public API: paths and selectors in, report-v1 out."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .adapters.checkov import (
    CheckovAdapter,
    CheckovEvidenceAdapter,
    CheckovScanRequest,
    checkov_distribution_identity,
)
from .acceptance import CandidateEvidenceUniverses, build_candidate_evidence_universes
from .config import (
    ExecutionIsolation, PublicAcceptanceProperty,
    PublicCandidateAcceptanceRequest, PublicHelmAcceptanceRequest,
    PublicHelmVerificationRequest, PublicKustomizeAcceptanceRequest,
    PublicTarget, PublicVerificationRequest,
)
from .enums import ArtifactKind, CheckEvaluationResult, Status
from .engine import (
    VerificationRequest,
    attest_checkov_scan_plan,
    load_git_verification_config,
    load_operator_verification_config,
    run_checkov_verification,
)
from .helm import (
    HelmMaterializationError, materialize_helm_comparison,
    materialize_helm_universe,
)
from .kustomize import (
    KustomizeMaterializationError, materialize_kustomize_universe,
)
from .models import DomainError, RequiredGates, require_trusted_scanner_run
from .policy import (
    PolicyRequest,
    evaluate_policy,
    load_base_commit_policy,
    load_git_execution_context,
    load_operator_execution_context,
    load_operator_policy,
)
from .report import (
    CandidateAcceptancePropertyEvidence, CandidateAcceptanceReportV1,
    CandidateArtifactFailureReportV1, ExecutionIsolationEvidence,
    HelmVerificationReportV1, OperationalReportV1, VerificationReportV1,
)
from .scanner_core import (
    NativePropertyIdentity,
    PropertyCapability,
    ProtectedPropertyTarget,
    ScannerObservationResult,
    build_protected_scan_plan,
    execute_protected_scan,
    legacy_report_v1_property_capability,
    protect_scan_artifact,
)
from .workflow import GitVerificationMaterialization


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
    return _verify_request(request)


def _resolve_acceptance_property(
    property_: PublicAcceptanceProperty,
    plan,
    run,
    evidence_universes: CandidateEvidenceUniverses,
) -> CandidateAcceptancePropertyEvidence:
    resources = [
        item for item in plan.resources
        if item.resource_address == property_.resource_address
        and (not property_.file_path or item.file_path == property_.file_path)
        and (
            property_.artifact_kind is ArtifactKind.UNKNOWN
            or item.artifact_kind is property_.artifact_kind
        )
    ]
    if not resources:
        return CandidateAcceptancePropertyEvidence(
            property_.rule_id,
            None,
            property_.resource_address,
            property_.file_path,
            "INCONCLUSIVE",
            "CANDIDATE_TARGET_MISSING",
        )
    if len(resources) != 1:
        return CandidateAcceptancePropertyEvidence(
            property_.rule_id,
            None,
            property_.resource_address,
            property_.file_path,
            "INCONCLUSIVE",
            "CANDIDATE_TARGET_AMBIGUOUS",
        )
    resource = resources[0]
    target_universe = evidence_universes.target_for(property_)
    scanner_complete = (
        evidence_universes.status is Status.PASS
        and target_universe.status is Status.PASS
    )
    if not scanner_complete:
        return CandidateAcceptancePropertyEvidence(
            property_.rule_id,
            resource,
            property_.resource_address,
            property_.file_path,
            "INCONCLUSIVE",
            "SCANNER_EVIDENCE_INCOMPLETE",
        )
    evaluations = [
        item for item in run.evaluations
        if item.rule_id == property_.rule_id
        and item.file_path == resource.file_path
        and item.resource_address in {
            resource.resource_address,
            resource.scanner_native_lookup,
        }
    ]
    if len(evaluations) != 1:
        return CandidateAcceptancePropertyEvidence(
            property_.rule_id,
            resource,
            property_.resource_address,
            property_.file_path,
            "INCONCLUSIVE",
            (
                "CANDIDATE_EVALUATION_MISSING"
                if not evaluations
                else "CANDIDATE_EVALUATION_AMBIGUOUS"
            ),
        )
    evaluation = evaluations[0]
    relationship_required = (
        target_universe.query_identity_sha256 != "0" * 64
        or legacy_report_v1_property_capability(
            evaluation.scanner, property_.rule_id
        ) is PropertyCapability.RELATIONSHIP
    )
    if relationship_required and (
        evaluation.graph_evidence is None
        or evaluation.graph_evidence.status is not Status.PASS
    ):
        return CandidateAcceptancePropertyEvidence(
            property_.rule_id,
            resource,
            property_.resource_address,
            property_.file_path,
            "INCONCLUSIVE",
            "GRAPH_EVIDENCE_INCOMPLETE",
            evaluation,
        )
    if evaluation.native_result is CheckEvaluationResult.PASSED:
        outcome, reason = "SATISFIED", "CANDIDATE_PROPERTY_SATISFIED"
    elif evaluation.native_result is CheckEvaluationResult.FAILED:
        outcome, reason = "VIOLATED", "CANDIDATE_PROPERTY_VIOLATED"
    else:
        outcome, reason = "INCONCLUSIVE", "CANDIDATE_EVALUATION_UNDECIDED"
    return CandidateAcceptancePropertyEvidence(
        property_.rule_id,
        resource,
        property_.resource_address,
        property_.file_path,
        outcome,
        reason,
        evaluation,
    )


def _neutral_acceptance_evidence(
    request: PublicCandidateAcceptanceRequest,
    plan,
    run,
    *,
    materialized: bool,
):
    """Reconcile production Checkov evidence through the neutral a8 boundary.

    Missing or ambiguous requested resources remain ordinary candidate-acceptance
    uncertainty and therefore do not become protected scanner targets. Every target
    that resolves exactly once must, however, be observed through the complete
    independently protected file/resource universe.
    """
    adapter = CheckovEvidenceAdapter(plan.request, trusted_run=run)
    resolved = []
    for property_ in request.properties:
        resources = tuple(
            item for item in plan.resources
            if item.resource_address == property_.resource_address
            and (not property_.file_path or item.file_path == property_.file_path)
            and (
                property_.artifact_kind is ArtifactKind.UNKNOWN
                or item.artifact_kind is property_.artifact_kind
            )
        )
        if len(resources) == 1:
            resolved.append((property_, resources[0]))
    if not resolved:
        return None
    kinds = {item.artifact_kind for item in plan.resources}
    kubernetes_kinds = {ArtifactKind.KUBERNETES_YAML, ArtifactKind.KUBERNETES_JSON}
    if kinds and kinds <= kubernetes_kinds:
        artifact_class = (
            "kubernetes_rendered_yaml" if materialized
            else "kubernetes_source_manifest"
        )
    elif kinds == {ArtifactKind.TERRAFORM_HCL}:
        artifact_class = "terraform_hcl_source"
    else:
        artifact_class = "mixed_iac_source"
    artifact = protect_scan_artifact(
        plan.request.scan_root,
        artifact_class,
        tuple(sorted(
            (*plan.request.eligible_file_evidence,
             *plan.request.supporting_file_evidence),
            key=lambda item: item.canonical_key,
        )),
        plan.request.expected_resources,
    )
    targets = tuple(
        ProtectedPropertyTarget(
            NativePropertyIdentity(
                property_.scanner_name,
                property_.rule_id,
                adapter.descriptor.scanner_version,
                adapter.descriptor.policy_bundle_digest,
            ),
            resource.resource_address,
            resource.file_path,
            resource.scanner_native_lookup,
            legacy_report_v1_property_capability(
                property_.scanner_name, property_.rule_id
            ),
        )
        for property_, resource in resolved
    )
    neutral_plan = build_protected_scan_plan(adapter.descriptor, artifact, targets)
    return execute_protected_scan(neutral_plan, adapter)


def _reconcile_acceptance_with_neutral_evidence(properties, evidence) -> None:
    if evidence is None:
        return
    observations = {
        (
            item.target.property_identity.policy_id,
            item.target.protected_resource_identity,
            item.target.file_path,
        ): item.result
        for item in evidence.observations
    }
    expected = {
        "SATISFIED": ScannerObservationResult.PASS,
        "VIOLATED": ScannerObservationResult.FAIL,
    }
    for item in properties:
        if item.resource is None or item.outcome not in expected:
            continue
        key = (item.rule_id, item.resource.resource_address, item.resource.file_path)
        if observations.get(key) is not expected[item.outcome]:
            raise DomainError(
                "scanner-neutral and report-v1 target evidence disagree"
            )


def verify_candidate(
    request: PublicCandidateAcceptanceRequest,
) -> CandidateAcceptanceReportV1 | OperationalReportV1:
    """Verify selected candidate properties without asserting a repair occurred."""
    return _verify_candidate_request(request)


def _verify_candidate_request(
    request: PublicCandidateAcceptanceRequest,
    *,
    materialization: object | None = None,
) -> CandidateAcceptanceReportV1 | OperationalReportV1:
    if type(request) is not PublicCandidateAcceptanceRequest:
        raise TypeError("verify_candidate requires an exact acceptance request")
    if request.execution_isolation is ExecutionIsolation.HARDENED_CONTAINER:
        return OperationalReportV1(
            "HARDENED_CONTAINER_UNAVAILABLE",
            "Phase E container execution is not installed; native execution was not selected.",
            "Use explicit reduced isolation only for operator-controlled local content.",
        )
    try:
        raw = _untrusted_scan_request(
            request.candidate_root,
            request.candidate_root,
            request.checkov_executable,
            request.frameworks,
        )
        plan = attest_checkov_scan_plan(raw)
        run = require_trusted_scanner_run(CheckovAdapter().scan(plan.request))
        neutral_evidence = _neutral_acceptance_evidence(
            request, plan, run, materialized=materialization is not None
        )
    except (DomainError, OSError) as exc:
        return OperationalReportV1(
            "CANDIDATE_EVIDENCE_UNAVAILABLE",
            str(exc),
            "Repair the protected candidate input or scanner environment and rerun.",
        )
    evidence_universes = build_candidate_evidence_universes(
        plan=plan,
        run=run,
        properties=request.properties,
        executable=request.checkov_executable,
    )
    properties = tuple(
        _resolve_acceptance_property(item, plan, run, evidence_universes)
        for item in request.properties
    )
    try:
        _reconcile_acceptance_with_neutral_evidence(properties, neutral_evidence)
    except DomainError as exc:
        return OperationalReportV1(
            "CANDIDATE_EVIDENCE_UNAVAILABLE",
            str(exc),
            "Repair the protected scanner evidence discrepancy and rerun.",
        )
    return CandidateAcceptanceReportV1(
        plan,
        run,
        properties,
        ExecutionIsolationEvidence.reduced_verified(),
        materialization,
        evidence_universes,
    )


def verify_helm_candidate(
    request: PublicHelmAcceptanceRequest,
) -> CandidateAcceptanceReportV1 | OperationalReportV1:
    """Render one protected chart universe and verify selected candidate properties."""
    if type(request) is not PublicHelmAcceptanceRequest:
        raise TypeError("verify_helm_candidate requires an exact Helm acceptance request")
    try:
        with materialize_helm_universe(request.charts) as universe:
            result = _verify_candidate_request(
                PublicCandidateAcceptanceRequest(
                    universe.scanner_root,
                    request.properties,
                    request.execution_isolation,
                    request.checkov_executable,
                    ("kubernetes",),
                ),
                materialization=universe,
            )
            if type(result) is CandidateAcceptanceReportV1 and any(
                item.evaluation is not None
                and item.evaluation.graph_evidence is not None
                for item in result.properties
            ) and any(
                evidence.render_inputs["crds"] == "exclude"
                and any(file_["path"].startswith("crds/") for file_ in evidence.chart["files"])
                for _key, evidence in universe.charts
            ):
                return OperationalReportV1(
                    "INCOMPLETE_RENDERED_COVERAGE",
                    "Graph acceptance cannot exclude chart CRDs authoritatively.",
                    "Rerun every participating chart with CRDs included.",
                )
            return result
    except HelmMaterializationError as exc:
        return OperationalReportV1(
            exc.reason_code,
            exc.safe_detail,
            "Make the local Helm inputs deterministic and fully source-bound, then rerun.",
        )


def verify_kustomize_candidate(
    request: PublicKustomizeAcceptanceRequest,
) -> CandidateAcceptanceReportV1 | CandidateArtifactFailureReportV1:
    """Build one protected local Kustomize universe before scanner selection."""
    if type(request) is not PublicKustomizeAcceptanceRequest:
        raise TypeError(
            "verify_kustomize_candidate requires an exact Kustomize request"
        )
    try:
        with materialize_kustomize_universe(request.build) as universe:
            return _verify_candidate_request(
                PublicCandidateAcceptanceRequest(
                    universe.scanner_root,
                    request.properties,
                    request.execution_isolation,
                    request.checkov_executable,
                    ("kubernetes",),
                ),
                materialization=universe.evidence,
            )
    except KustomizeMaterializationError as exc:
        return CandidateArtifactFailureReportV1(
            ArtifactKind.KUBERNETES_YAML,
            "kustomize-materialization",
            exc.reason_code,
            exc.safe_detail,
            ExecutionIsolationEvidence.reduced_verified(),
        )


def _graph_verification_has_excluded_crds(
    result: VerificationReportV1, materialization: object
) -> bool:
    graph_evidence_present = any(
        evaluation.graph_evidence is not None
        for run in (
            result.verification.baseline_run,
            result.verification.candidate_run,
        )
        for evaluation in run.evaluations
    )
    return graph_evidence_present and any(
        evidence.render_inputs["crds"] == "exclude"
        and any(
            item["path"].startswith("crds/")
            for item in evidence.chart["files"]
        )
        for evidence in (
            materialization.baseline,
            materialization.candidate,
        )
    )


def verify_helm(
    request: PublicHelmVerificationRequest,
) -> VerificationReportV1 | HelmVerificationReportV1 | OperationalReportV1:
    """Render an exact local chart pair, then run the ordinary Kubernetes verifier."""
    if type(request) is not PublicHelmVerificationRequest:
        raise TypeError("verify_helm requires an exact PublicHelmVerificationRequest")
    try:
        with materialize_helm_comparison(
            request.baseline, request.candidate
        ) as materialization:
            try:
                targets = discover_baseline_targets(
                    materialization.baseline_root,
                    request.checkov_executable,
                    ("kubernetes",),
                    request.selectors,
                    all_findings=request.all_baseline_findings,
                )
            except BaselineDiscoveryUnavailable as exc:
                return OperationalReportV1(
                    "BASELINE_TARGET_DISCOVERY_UNAVAILABLE",
                    str(exc),
                    "Repair the protected Checkov environment or provide a failing chart.",
                )
            if not targets:
                return OperationalReportV1(
                    "NO_BASELINE_TARGETS",
                    "The deterministic baseline render produced no selectable failed findings.",
                    "Provide an explicit failing baseline chart or review scanner scope.",
                )
            result = _verify_request(PublicVerificationRequest(
                materialization.baseline_root,
                materialization.candidate_root,
                targets,
                request.execution_isolation,
                request.checkov_executable,
                ("kubernetes",),
            ))
            if type(result) is VerificationReportV1:
                if _graph_verification_has_excluded_crds(result, materialization):
                    return OperationalReportV1(
                        "INCOMPLETE_RENDERED_COVERAGE",
                        "Graph verification cannot exclude chart CRDs authoritatively.",
                        "Rerun with --helm-include-crds and review the complete graph.",
                    )
                return HelmVerificationReportV1(result, materialization)
            return result
    except HelmMaterializationError as exc:
        return OperationalReportV1(
            exc.reason_code,
            exc.safe_detail,
            "Make the local Helm inputs deterministic and fully source-bound, then rerun.",
        )


def _verify_git(
    request: PublicVerificationRequest,
    materialization: GitVerificationMaterialization,
) -> VerificationReportV1 | OperationalReportV1:
    """Internal PR path: bind exact materialized objects to Git provenance."""
    if type(materialization) is not GitVerificationMaterialization or not materialization._trusted:
        raise DomainError("Git verification requires protected materialization provenance")
    if (
        request.baseline_root != materialization.baseline_root.resolve(strict=True)
        or request.candidate_root != materialization.candidate_root.resolve(strict=True)
    ):
        raise DomainError("Git verification request roots disagree with materialized objects")
    return _verify_request(request, materialization)


def _verify_request(
    request: PublicVerificationRequest,
    git_materialization: GitVerificationMaterialization | None = None,
) -> VerificationReportV1 | OperationalReportV1:
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
    if git_materialization is None:
        config = load_operator_verification_config(
            baseline.request,
            candidate.request,
            required_gates=RequiredGates(validators),
            frameworks=request.frameworks,
        )
    else:
        config = load_git_verification_config(
            baseline.request,
            candidate.request,
            required_gates=RequiredGates(validators),
            repository_identity=git_materialization.repository_identity,
            base_commit=git_materialization.base_commit,
            head_commit=git_materialization.head_commit,
            context_identity=git_materialization.context_identity,
            frameworks=request.frameworks,
        )
    engine_request = VerificationRequest(
        baseline, candidate, tuple(item.to_domain() for item in request.targets), config
    )
    verification = run_checkov_verification(engine_request)
    if git_materialization is None:
        context = load_operator_execution_context(config)
        policy = load_operator_policy(
            {"exceptions": [], "optional_gates": []}, context=context
        )
    else:
        context = load_git_execution_context(config)
        policy = load_base_commit_policy(context)
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


__all__ = [
    "BaselineDiscoveryUnavailable",
    "discover_baseline_targets",
    "verify",
    "verify_candidate",
    "verify_helm",
    "verify_helm_candidate",
    "verify_kustomize_candidate",
]
