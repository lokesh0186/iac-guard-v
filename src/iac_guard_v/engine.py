"""Verification engine: trusted execution evidence to outcomes and gates.

The public request deliberately has no field for ``ScannerRun``, matching, delta, or
target-evaluation evidence.  Those values are obtained in this module by invoking the
adapter and the D3 factories.  The engine emits evidence and events; only ``policy.py``
may collapse them to a verdict.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Callable

from .adapters.checkov import (
    CheckovAdapter,
    CheckovScanRequest,
    evaluate_checkov_target,
)
from .diffing import FindingDiffResult, diff_findings, require_trusted_diff_result
from .enums import (
    CheckTargetReason,
    DeltaClass,
    Outcome,
    SEVERITY_ORDER,
    Severity,
    Status,
)
from .models import (
    DomainError,
    GateResult,
    RequiredGates,
    ScannerRun,
    Target,
    TargetIdentity,
    canonical_identifier,
    require_enum,
    require_exact_type,
    require_trusted_scanner_run,
)


_TRUSTED_ENGINE_CONTEXT = object()
_SHA256 = __import__("re").compile(r"^[0-9a-f]{64}$")


def _digest(value: object, name: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise DomainError(f"{name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class VerificationRequest:
    """Paths, targets, and protected configuration; never derived scan evidence."""

    baseline_scan: CheckovScanRequest
    candidate_scan: CheckovScanRequest
    targets: tuple
    required_gates: RequiredGates
    trusted_governed_config_sha256: str
    candidate_governed_config_sha256: str
    severity_floor: Severity = Severity.HIGH
    fail_on_location_change: bool = False

    def __post_init__(self) -> None:
        require_exact_type(self.baseline_scan, CheckovScanRequest, "baseline scan request")
        require_exact_type(self.candidate_scan, CheckovScanRequest, "candidate scan request")
        require_exact_type(self.required_gates, RequiredGates, "required gates")
        require_enum(self.severity_floor, Severity, "severity_floor")
        if type(self.fail_on_location_change) is not bool:
            raise DomainError("fail_on_location_change must be a bool")
        if type(self.targets) is not tuple or not self.targets:
            raise DomainError("targets must be a nonempty exact tuple")
        rebuilt: list[Target] = []
        for item in self.targets:
            require_exact_type(item, Target, "verification target")
            rebuilt.append(
                Target(
                    TargetIdentity(
                        item.identity.scanner,
                        item.identity.rule_id,
                        item.identity.scope,
                    ),
                    item.baseline_occurrences,
                )
            )
        keys = [item.identity.canonical_key for item in rebuilt]
        if len(keys) != len(set(keys)):
            raise DomainError("verification targets contain duplicate identities")
        if any(item.scanner != "checkov" for item in rebuilt):
            raise DomainError("D5 supports Checkov targets only")
        object.__setattr__(self, "targets", tuple(sorted(rebuilt, key=lambda x: x.identity.canonical_key)))
        object.__setattr__(
            self,
            "trusted_governed_config_sha256",
            _digest(self.trusted_governed_config_sha256, "trusted governed-config digest"),
        )
        object.__setattr__(
            self,
            "candidate_governed_config_sha256",
            _digest(self.candidate_governed_config_sha256, "candidate governed-config digest"),
        )


@dataclass(frozen=True, slots=True)
class TargetObservation:
    """Typed facts used by the total target classifier.

    ``PASS`` means the named positive property was established; ``FAIL`` means its
    specified contrary was established; every operational state remains uncertainty.
    """

    identity: TargetIdentity
    baseline_occurrences: int
    candidate_matches: int
    scanner_integrity: Status
    ruleset_integrity: Status
    artifact_eligibility: Status
    target_file_presence: Status
    target_resource_presence: Status
    suppression_absence: Status
    occurrence_evidence: Status
    affirmative_target_pass: Status

    def __post_init__(self) -> None:
        require_exact_type(self.identity, TargetIdentity, "target identity")
        for name in ("baseline_occurrences", "candidate_matches"):
            value = getattr(self, name)
            if type(value) is not int or value < (1 if name == "baseline_occurrences" else 0):
                raise DomainError(f"{name} is outside its valid count domain")
        for name in (
            "scanner_integrity", "ruleset_integrity", "artifact_eligibility",
            "target_file_presence", "target_resource_presence", "suppression_absence",
            "occurrence_evidence", "affirmative_target_pass",
        ):
            require_enum(getattr(self, name), Status, name)


def classify_target(observation: TargetObservation) -> Outcome:
    """Apply semantics section 4 in fail-closed order."""
    require_exact_type(observation, TargetObservation, "target observation")
    o = observation
    if o.scanner_integrity is not Status.PASS:
        return Outcome.SCANNER_ERROR
    if o.ruleset_integrity is Status.FAIL:
        return Outcome.RULE_OR_SCANNER_DRIFT
    if o.ruleset_integrity is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.artifact_eligibility is Status.FAIL:
        return Outcome.OUT_OF_SCOPE
    if o.artifact_eligibility is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.target_file_presence is Status.FAIL:
        return Outcome.FILE_DELETED_OR_RENAMED
    if o.target_file_presence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.target_resource_presence is Status.FAIL:
        return Outcome.RESOURCE_DELETED
    if o.target_resource_presence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.suppression_absence is Status.FAIL:
        return Outcome.SUPPRESSED
    if o.suppression_absence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.occurrence_evidence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.baseline_occurrences > 1 and 0 < o.candidate_matches < o.baseline_occurrences:
        return Outcome.PARTIALLY_FIXED
    if o.candidate_matches >= o.baseline_occurrences:
        return Outcome.STILL_PRESENT
    if o.candidate_matches == 0 and o.affirmative_target_pass is Status.PASS:
        return Outcome.FIXED
    return Outcome.INCONCLUSIVE


@dataclass(frozen=True, slots=True)
class TargetOutcomeEvidence:
    identity: TargetIdentity
    outcome: Outcome
    observation: TargetObservation
    target_reason: str
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_exact_type(self.identity, TargetIdentity, "target identity")
        require_enum(self.outcome, Outcome, "target outcome")
        require_exact_type(self.observation, TargetObservation, "target observation")
        if self.identity.canonical_key != self.observation.identity.canonical_key:
            raise DomainError("target outcome identity disagrees with its observation")
        if self.outcome is not classify_target(self.observation):
            raise DomainError("target outcome does not satisfy its classification predicate")
        object.__setattr__(self, "target_reason", canonical_identifier(self.target_reason, "target reason"))
        if _trusted_context is not _TRUSTED_ENGINE_CONTEXT:
            raise DomainError("target outcome evidence requires trusted engine execution")
        object.__setattr__(self, "_trusted", True)

    @property
    def canonical_key(self) -> tuple:
        return (*self.identity.canonical_key, self.outcome.value)

    def canonical_dict(self) -> dict:
        return {
            "identity": self.identity.canonical_dict(),
            "outcome": self.outcome.value,
            "target_reason": self.target_reason,
            "counts": {
                "baseline": self.observation.baseline_occurrences,
                "candidate": self.observation.candidate_matches,
            },
        }


GateExecutor = Callable[[str, str, Path], GateResult]


@dataclass(frozen=True, slots=True)
class VerificationResult:
    baseline_run: ScannerRun
    candidate_run: ScannerRun
    finding_diff: FindingDiffResult
    target_outcomes: tuple
    preflight: GateResult
    scanner_integrity: GateResult
    validator_results: tuple
    oracle_results: tuple
    regression: GateResult
    suppression: GateResult
    policy_drift: bool
    coverage_decreased_on_required_scanner: bool
    rule_substituted_on_required_target: bool
    required_gates: RequiredGates
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_trusted_scanner_run(self.baseline_run)
        require_trusted_scanner_run(self.candidate_run)
        require_trusted_diff_result(self.finding_diff)
        require_exact_type(self.required_gates, RequiredGates, "required gates")
        for name in ("preflight", "scanner_integrity", "regression", "suppression"):
            require_exact_type(getattr(self, name), GateResult, name)
        for name, expected_ids in (
            ("validator_results", self.required_gates.validator_ids),
            ("oracle_results", self.required_gates.oracle_ids),
        ):
            values = getattr(self, name)
            if type(values) is not tuple or any(type(item) is not GateResult for item in values):
                raise DomainError(f"{name} must be an exact tuple of GateResult")
            if tuple(item.gate_id for item in values) != expected_ids:
                raise DomainError(f"{name} do not exactly cover required gate identities")
        if type(self.target_outcomes) is not tuple or not self.target_outcomes:
            raise DomainError("target outcomes must be a nonempty exact tuple")
        if any(type(item) is not TargetOutcomeEvidence or not item._trusted for item in self.target_outcomes):
            raise DomainError("target outcomes contain caller-authored evidence")
        for name in (
            "policy_drift", "coverage_decreased_on_required_scanner",
            "rule_substituted_on_required_target",
        ):
            if type(getattr(self, name)) is not bool:
                raise DomainError(f"{name} must be a bool")
        if _trusted_context is not _TRUSTED_ENGINE_CONTEXT:
            raise DomainError("VerificationResult requires trusted engine execution")
        object.__setattr__(self, "target_outcomes", tuple(sorted(self.target_outcomes, key=lambda x: x.canonical_key)))
        object.__setattr__(self, "_trusted", True)

    def canonical_dict(self) -> dict:
        return {
            "preflight": self.preflight.canonical_dict(),
            "scanner_integrity": self.scanner_integrity.canonical_dict(),
            "validators": [item.canonical_dict() for item in self.validator_results],
            "oracles": [item.canonical_dict() for item in self.oracle_results],
            "targets": [item.canonical_dict() for item in self.target_outcomes],
            "finding_diff": self.finding_diff.canonical_dict(),
            "regression": self.regression.canonical_dict(),
            "suppression": self.suppression.canonical_dict(),
            "policy_drift": self.policy_drift,
            "coverage_decreased_on_required_scanner": self.coverage_decreased_on_required_scanner,
            "rule_substituted_on_required_target": self.rule_substituted_on_required_target,
            "baseline_run": self.baseline_run.canonical_dict(),
            "candidate_run": self.candidate_run.canonical_dict(),
        }


def require_trusted_verification_result(value: object) -> VerificationResult:
    require_exact_type(value, VerificationResult, "verification result")
    if not value._trusted:
        raise DomainError("verification result is caller-authored, not trusted engine evidence")
    return value


def _gate_results(
    ids: tuple,
    kind: str,
    root: Path,
    executor: GateExecutor | None,
) -> tuple[GateResult, ...]:
    results: list[GateResult] = []
    for gate_id in ids:
        if executor is None:
            result = GateResult(gate_id, Status.UNSUPPORTED, "GATE_EXECUTOR_UNAVAILABLE")
        else:
            result = executor(kind, gate_id, root)
            require_exact_type(result, GateResult, f"{kind} executor result")
            if result.gate_id != gate_id:
                raise DomainError(f"{kind} executor substituted {result.gate_id!r} for {gate_id!r}")
            result = GateResult(result.gate_id, result.status, result.reason_code, result.detail)
        results.append(result)
    return tuple(results)


def _target_paths(run: ScannerRun, target: Target) -> tuple[str, ...]:
    return tuple(sorted({
        finding.location.file_path
        for finding in run.findings
        if finding.scanner == target.scanner
        and finding.rule_id == target.rule_id
        and finding.resource_address == target.scope
    }))


def _target_observation(
    target: Target,
    baseline: ScannerRun,
    candidate: ScannerRun,
    diff: FindingDiffResult,
    request: VerificationRequest,
) -> tuple[TargetObservation, str]:
    run_ok = baseline.status is Status.PASS and candidate.status is Status.PASS
    stable = (
        baseline.scanner == candidate.scanner == target.scanner
        and baseline.scanner_version == candidate.scanner_version
        and baseline.ruleset_integrity is Status.PASS
        and candidate.ruleset_integrity is Status.PASS
        and baseline.scanner_environment_digest == candidate.scanner_environment_digest
        and baseline.policy_inventory_digest == candidate.policy_inventory_digest
    )
    baseline_findings = tuple(
        f for f in baseline.findings
        if f.rule_id == target.rule_id and f.resource_address == target.scope
    )
    candidate_findings = tuple(
        f for f in candidate.findings
        if f.rule_id == target.rule_id and f.resource_address == target.scope and not f.suppressed
    )
    baseline_paths = _target_paths(baseline, target)
    eligible = set(request.candidate_scan.files_eligible)
    expected_resources = {
        item.resource_address for item in request.candidate_scan.expected_resources
    }
    resource_present = target.scope in expected_resources
    path_present = resource_present or any(path in eligible for path in baseline_paths)
    physical_present = any((request.candidate_scan.scan_root / path).is_file() for path in baseline_paths)
    if resource_present or path_present:
        file_state = Status.PASS
        eligibility = Status.PASS
    elif baseline_paths and physical_present:
        file_state = Status.PASS
        eligibility = Status.FAIL
    elif baseline_paths:
        file_state = Status.FAIL
        eligibility = Status.PASS
    else:
        file_state = Status.INCONCLUSIVE
        eligibility = Status.INCONCLUSIVE
    resource_state = Status.PASS if resource_present else Status.FAIL
    ambiguity = any(
        any(f.rule_id == target.rule_id and f.resource_address == target.scope
            for f in (*item.baseline, *item.candidate))
        for item in diff.ambiguities
    )
    target_evidence = evaluate_checkov_target(
        candidate, target.rule_id, target.scope,
        baseline_paths[0] if len(baseline_paths) == 1 and baseline_paths[0] in eligible else None,
    )
    suppressed = (
        target_evidence.reason is CheckTargetReason.TARGET_SUPPRESSED
        or any(f.suppressed for f in candidate.findings
               if f.rule_id == target.rule_id and f.resource_address == target.scope)
    )
    baseline_count_ok = len(baseline_findings) == target.baseline_occurrences
    observation = TargetObservation(
        identity=target.identity,
        baseline_occurrences=target.baseline_occurrences,
        candidate_matches=len(candidate_findings),
        scanner_integrity=Status.PASS if run_ok else Status.ERROR,
        ruleset_integrity=Status.PASS if stable else Status.FAIL,
        artifact_eligibility=eligibility,
        target_file_presence=file_state,
        target_resource_presence=resource_state,
        suppression_absence=Status.FAIL if suppressed else Status.PASS,
        occurrence_evidence=(Status.PASS if baseline_count_ok and not ambiguity else Status.INCONCLUSIVE),
        affirmative_target_pass=target_evidence.status,
    )
    return observation, target_evidence.reason.value


def _regression_result(request: VerificationRequest, diff: FindingDiffResult) -> GateResult:
    if diff.ambiguities:
        return GateResult("regression", Status.INCONCLUSIVE, "MATCHING_INCONCLUSIVE")
    decisive = []
    floor = SEVERITY_ORDER.index(request.severity_floor)
    for delta in diff.deltas:
        if delta.delta_class is DeltaClass.NEW_FINDING:
            if SEVERITY_ORDER.index(delta.candidate.severity) >= floor:
                decisive.append(delta.delta_class.value)
        elif delta.delta_class in {
            DeltaClass.SEVERITY_INCREASED,
            DeltaClass.SCOPE_EXPANDED,
            DeltaClass.SUPPRESSION_ADDED,
        }:
            decisive.append(delta.delta_class.value)
        elif delta.delta_class is DeltaClass.LOCATION_CHANGED and request.fail_on_location_change:
            decisive.append(delta.delta_class.value)
    if decisive:
        return GateResult("regression", Status.FAIL, "REGRESSION_DETECTED", ",".join(sorted(set(decisive))))
    return GateResult("regression", Status.PASS, "NO_DECISIVE_REGRESSION")


def run_checkov_verification(
    request: VerificationRequest,
    *,
    _gate_executor: GateExecutor | None = None,
) -> VerificationResult:
    """Run both scans and derive all D5 evidence internally.

    ``_gate_executor`` is an in-process trusted dependency hook for validator/oracle
    implementations. It is deliberately absent from ``VerificationRequest`` and cannot
    be supplied through CLI/config/JSON.
    """
    require_exact_type(request, VerificationRequest, "verification request")
    adapter = CheckovAdapter()
    baseline = require_trusted_scanner_run(adapter.scan(request.baseline_scan))
    candidate = require_trusted_scanner_run(adapter.scan(request.candidate_scan))
    stable_run = (
        baseline.scanner == candidate.scanner
        and baseline.scanner_version == candidate.scanner_version
        and baseline.scanner_environment_digest == candidate.scanner_environment_digest
        and baseline.policy_inventory_digest == candidate.policy_inventory_digest
    )
    if stable_run:
        diff = diff_findings(baseline.findings, candidate.findings)
    else:
        diff = diff_findings((), ())
    outcomes = []
    for target in request.targets:
        observation, reason = _target_observation(target, baseline, candidate, diff, request)
        outcomes.append(
            TargetOutcomeEvidence(
                target.identity,
                classify_target(observation),
                observation,
                reason,
                _trusted_context=_TRUSTED_ENGINE_CONTEXT,
            )
        )
    candidate_root = request.candidate_scan.scan_root
    validators = _gate_results(
        request.required_gates.validator_ids, "validator", candidate_root, _gate_executor
    )
    oracles = _gate_results(
        request.required_gates.oracle_ids, "oracle", candidate_root, _gate_executor
    )
    scanner_status = (
        Status.PASS
        if baseline.status is Status.PASS and candidate.status is Status.PASS and stable_run
        else Status.INCONCLUSIVE
    )
    regression = _regression_result(request, diff)
    suppression_status = (
        Status.FAIL
        if any(item.outcome is Outcome.SUPPRESSED for item in outcomes)
        or any(d.delta_class is DeltaClass.SUPPRESSION_ADDED for d in diff.deltas)
        else Status.PASS
    )
    coverage_decreased = (
        candidate.status is Status.PARTIAL
        or candidate.coverage.files_parsed < candidate.coverage.files_eligible
        or candidate.resource_coverage.resources_observed
        < candidate.resource_coverage.resources_expected
    )
    return VerificationResult(
        baseline,
        candidate,
        diff,
        tuple(outcomes),
        GateResult("preflight", Status.PASS, "PATHS_AND_INPUTS_BOUND"),
        GateResult("scanner_integrity", scanner_status, "SCANNER_EVIDENCE_RECONCILED"),
        validators,
        oracles,
        regression,
        GateResult("suppression", suppression_status, "SUPPRESSION_POLICY_EVALUATED"),
        request.trusted_governed_config_sha256 != request.candidate_governed_config_sha256,
        coverage_decreased,
        False,
        request.required_gates,
        _trusted_context=_TRUSTED_ENGINE_CONTEXT,
    )


__all__ = [
    "TargetObservation", "TargetOutcomeEvidence", "VerificationRequest",
    "VerificationResult", "classify_target", "require_trusted_verification_result",
    "run_checkov_verification",
]
