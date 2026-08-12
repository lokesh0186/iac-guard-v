"""Canonical report-v1 and projections derived only from canonical evidence."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .enums import Verdict
from .engine import VerificationResult, require_trusted_verification_result
from .models import DomainError
from .policy import PolicyResult, require_trusted_policy_result


@dataclass(frozen=True, slots=True)
class VerificationReportV1:
    verification: VerificationResult
    policy_result: PolicyResult

    def __post_init__(self) -> None:
        require_trusted_verification_result(self.verification)
        require_trusted_policy_result(self.policy_result)
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
        return {
            "schema_version": "report-v1",
            "result_kind": "verification",
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "verification": self.verification.canonical_dict(),
            "policy": self.policy_result.canonical_dict(),
        }

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
        return {
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

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n"


def render_console(report: VerificationReportV1 | OperationalReportV1) -> str:
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
        targets = value["verification"]["targets"]
        lines.append("targets:")
        for target in targets:
            identity = target["binding"]["identity"]
            lines.append(
                f"  {identity['rule_id']} {identity['scope']}: {target['outcome']}"
            )
        lines.append(f"report_sha256: {report.report_sha256}")
    return "\n".join(lines) + "\n"


__all__ = ["OperationalReportV1", "VerificationReportV1", "render_console"]
