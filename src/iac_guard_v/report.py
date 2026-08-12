"""Canonical report-v1 and projections derived only from canonical evidence."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

import jsonschema

from .enums import Verdict
from .engine import VerificationResult, require_trusted_verification_result
from .models import DomainError
from .policy import PolicyResult, require_trusted_policy_result


@dataclass(frozen=True, slots=True)
class ExecutionIsolationEvidence:
    mode: str
    hostile_input_support: bool
    network_isolation_state: str
    filesystem_isolation_state: str
    scanner_environment_integrity_state: str

    def __post_init__(self) -> None:
        if self.mode not in {"hardened-container", "reduced-isolation"}:
            raise DomainError("execution isolation mode is unsupported")
        if type(self.hostile_input_support) is not bool:
            raise DomainError("hostile_input_support must be an exact bool")
        for name in (
            "network_isolation_state", "filesystem_isolation_state",
            "scanner_environment_integrity_state",
        ):
            if getattr(self, name) not in {"PASS", "FAIL", "INCONCLUSIVE", "UNSUPPORTED"}:
                raise DomainError(f"execution isolation {name} is unsupported")
        if self.mode == "reduced-isolation" and self.hostile_input_support:
            raise DomainError("reduced-isolation cannot claim hostile-input support")

    @classmethod
    def reduced_verified(cls) -> "ExecutionIsolationEvidence":
        return cls("reduced-isolation", False, "UNSUPPORTED", "UNSUPPORTED", "PASS")

    def canonical_dict(self) -> dict:
        return {
            "mode": self.mode,
            "hostile_input_support": self.hostile_input_support,
            "network_isolation_state": self.network_isolation_state,
            "filesystem_isolation_state": self.filesystem_isolation_state,
            "scanner_environment_integrity_state": self.scanner_environment_integrity_state,
        }


def _schema() -> dict:
    path = files("iac_guard_v").joinpath("schemas/report-v1.schema.json")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_report_payload(payload: dict) -> None:
    try:
        jsonschema.Draft202012Validator(_schema(), format_checker=jsonschema.FormatChecker()).validate(payload)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"report-v1 contract violation: {exc.message}") from exc
    if payload["result_kind"] == "verification":
        policy = payload["policy"]
        if (payload["verdict"], payload["exit_code"]) != (
            policy["verdict"], policy["exit_code"]
        ):
            raise DomainError("report-v1 top-level and policy verdict/exit disagree")


@dataclass(frozen=True, slots=True)
class VerificationReportV1:
    verification: VerificationResult
    policy_result: PolicyResult
    execution_isolation: ExecutionIsolationEvidence = field(
        default_factory=ExecutionIsolationEvidence.reduced_verified
    )

    def __post_init__(self) -> None:
        require_trusted_verification_result(self.verification)
        require_trusted_policy_result(self.policy_result)
        if type(self.execution_isolation) is not ExecutionIsolationEvidence:
            raise DomainError("verification report requires typed execution isolation evidence")
        bundle = self.policy_result.policy_evidence.bundle
        if (
            bundle.verification_config_sha256
            != self.verification.verification_config.config_sha256
            or bundle.candidate_snapshot_sha256
            != self.verification.candidate_snapshot.snapshot_sha256
        ):
            raise DomainError("report policy and verification evidence do not share a snapshot")
        outcome_keys = {item.binding.canonical_key for item in self.verification.target_outcomes}
        decision_keys = {
            item.resolved_target.canonical_key
            for item in self.policy_result.decisions
            if item.resolved_target is not None
        }
        if outcome_keys != decision_keys:
            raise DomainError("report policy decisions do not cover verification targets")

    @property
    def verdict(self) -> Verdict:
        return self.policy_result.verdict

    @property
    def exit_code(self) -> int:
        return self.policy_result.exit_code

    def canonical_dict(self) -> dict:
        result = {
            "schema_version": "report-v1",
            "result_kind": "verification",
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "execution_isolation": self.execution_isolation.canonical_dict(),
            "verification": self.verification.canonical_dict(),
            "policy": self.policy_result.canonical_dict(),
        }
        validate_report_payload(result)
        return result

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n"

    @property
    def report_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class OperationalReportV1:
    reason_code: str
    detail: str
    remediation: str

    def __post_init__(self) -> None:
        for name in ("reason_code", "detail", "remediation"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip() or any(
                ord(char) < 32 and char not in "\t" for char in value
            ):
                raise DomainError(f"operational report {name} must be safe nonblank text")

    @property
    def verdict(self) -> Verdict:
        return Verdict.INCONCLUSIVE

    @property
    def exit_code(self) -> int:
        return 3

    def canonical_dict(self) -> dict:
        result = {
            "schema_version": "report-v1",
            "result_kind": "operational_uncertainty",
            "verdict": "INCONCLUSIVE",
            "exit_code": 3,
            "diagnostic": {
                "reason_code": self.reason_code,
                "detail": self.detail,
                "remediation": self.remediation,
            },
        }
        validate_report_payload(result)
        return result

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n"


@dataclass(frozen=True, slots=True)
class CandidateArtifactFailureReportV1:
    reason_code: str
    detail: str
    execution_isolation: ExecutionIsolationEvidence

    @property
    def verdict(self) -> Verdict:
        return Verdict.FAILED

    @property
    def exit_code(self) -> int:
        return 1

    def canonical_dict(self) -> dict:
        result = {
            "schema_version": "report-v1",
            "result_kind": "verification",
            "verdict": "FAILED",
            "exit_code": 1,
            "execution_isolation": self.execution_isolation.canonical_dict(),
            "verification": {
                "failure_stage": "V1",
                "preflight": {
                    "gate_id": "preflight", "status": "PASS",
                    "reason_code": "PUBLIC_REQUEST_BOUND", "detail": "",
                },
                "validators": [{
                    "gate_id": "terraform_hcl_parse", "status": "FAIL",
                    "reason_code": self.reason_code, "detail": self.detail,
                }],
            },
            "policy": {
                "verdict": "FAILED", "exit_code": 1, "decisions": [],
                "policy_evidence": {
                    "source_origin": "operator",
                    "reason_code": "CANDIDATE_ARTIFACT_INVALID",
                },
            },
        }
        validate_report_payload(result)
        return result

    def canonical_json(self) -> str:
        return json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")) + "\n"

def render_console(report: VerificationReportV1 | OperationalReportV1 | CandidateArtifactFailureReportV1) -> str:
    """Human projection of report-v1; it introduces no new evidence."""
    value = report.canonical_dict()
    lines = [
        f"IaC-Guard-V: {value['verdict']}",
        f"exit_code: {value['exit_code']}",
    ]
    if value["result_kind"] == "operational_uncertainty":
        diagnostic = value["diagnostic"]
        lines.extend((
            f"reason: {diagnostic['reason_code']}",
            f"detail: {diagnostic['detail']}",
            f"remediation: {diagnostic['remediation']}",
        ))
    else:
        targets = value["verification"].get("targets", [])
        lines.append("targets:")
        for target in targets:
            identity = target["binding"]["identity"]
            lines.append(
                f"  {identity['rule_id']} {identity['scope']}: {target['outcome']}"
            )
        if hasattr(report, "report_sha256"):
            lines.append(f"report_sha256: {report.report_sha256}")
    return "\n".join(lines) + "\n"


__all__ = [
    "CandidateArtifactFailureReportV1", "ExecutionIsolationEvidence",
    "OperationalReportV1", "VerificationReportV1", "render_console",
    "validate_report_payload",
]
