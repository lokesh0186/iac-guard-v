"""Immutable validator evidence shared by the closed Phase-E registry."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import InitVar, dataclass, field
from enum import Enum
from typing import Any

from ..enums import Status
from ..models import BoundInputFile, DomainError, canonical_identifier, safe_report_text


_EVIDENCE_CONTEXT = object()
_SHA = re.compile(r"[0-9a-f]{64}")


class ValidationReason(str, Enum):
    COMPLETED = "COMPLETED"
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    NEEDS_INIT = "NEEDS_INIT"
    UNSUPPORTED_CONDITION = "UNSUPPORTED_CONDITION"
    PROCESS_ERROR = "PROCESS_ERROR"
    TIMEOUT = "TIMEOUT"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    DUPLICATE_JSON_KEY = "DUPLICATE_JSON_KEY"
    JSON_DEPTH_EXCEEDED = "JSON_DEPTH_EXCEEDED"
    OUTPUT_DIRECTORY_INTEGRITY_FAILED = "OUTPUT_DIRECTORY_INTEGRITY_FAILED"
    INPUT_CHANGED_DURING_VALIDATION = "INPUT_CHANGED_DURING_VALIDATION"
    RUNTIME_INTEGRITY_FAILED = "RUNTIME_INTEGRITY_FAILED"
    VERSION_OR_LOCK_DRIFT = "VERSION_OR_LOCK_DRIFT"
    DIAGNOSTIC_CONTRADICTION = "DIAGNOSTIC_CONTRADICTION"
    EMPTY_SCOPE = "EMPTY_SCOPE"
    MISSING_SCHEMA = "MISSING_SCHEMA"
    CRD_SCHEMA_UNAVAILABLE = "CRD_SCHEMA_UNAVAILABLE"
    SCHEMA_BUNDLE_CHANGED = "SCHEMA_BUNDLE_CHANGED"
    INCOMPLETE_COVERAGE = "INCOMPLETE_COVERAGE"
    ADVISORY_FINDINGS = "ADVISORY_FINDINGS"
    PLUGIN_INITIALIZATION_REQUIRED = "PLUGIN_INITIALIZATION_REQUIRED"
    BASELINE_EVIDENCE_INVALID = "BASELINE_EVIDENCE_INVALID"
    MATERIALIZED_VIEW_INTEGRITY_FAILED = "MATERIALIZED_VIEW_INTEGRITY_FAILED"


@dataclass(frozen=True, slots=True)
class ValidationDiagnostic:
    severity: str
    summary: str
    detail: str = ""
    file_path: str = ""
    line: int | None = None

    def __post_init__(self) -> None:
        if self.severity not in {"error", "warning", "info", "unknown"}:
            raise DomainError("validator diagnostic severity is unsupported")
        object.__setattr__(self, "summary", safe_report_text(self.summary, "summary", 4096))
        if self.detail:
            object.__setattr__(self, "detail", safe_report_text(self.detail, "detail", 16384))
        if type(self.file_path) is not str:
            raise DomainError("validator diagnostic file path must be a string")
        if self.line is not None and (type(self.line) is not int or self.line < 1):
            raise DomainError("validator diagnostic line must be >= 1 or absent")

    def canonical_dict(self) -> dict:
        return {
            "severity": self.severity, "summary": self.summary, "detail": self.detail,
            "file_path": self.file_path, "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class ValidatorExecutionEvidence:
    validator_id: str
    tool: str
    version: str
    status: Status
    reason: ValidationReason
    advisory_only: bool
    diagnostics: tuple
    resource_identities: tuple
    input_files: tuple
    files_eligible: int
    files_validated: int
    resources_expected: int
    resources_validated: int
    runtime_identity: str
    tool_environment_identity: str
    invocation_identity: str
    sealed_snapshot_identity: str
    materialized_view_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    native_output_bytes_sha256: str
    canonical_native_output_sha256: str
    output_directory_manifest_sha256: str
    exit_code: int | None
    duration_ms: int
    execution_controls: tuple
    _trusted_context: InitVar[object] = None
    _trusted_validator_evidence: bool = field(
        init=False, default=False, repr=False, compare=False
    )

    def __post_init__(self, _trusted_context: object) -> None:
        for name in ("validator_id", "tool", "version"):
            object.__setattr__(self, name, canonical_identifier(getattr(self, name), name))
        if type(self.status) is not Status or type(self.reason) is not ValidationReason:
            raise DomainError("validator status/reason must use the closed vocabulary")
        if type(self.advisory_only) is not bool:
            raise DomainError("advisory_only must be a bool")
        if type(self.diagnostics) is not tuple or any(
            type(item) is not ValidationDiagnostic for item in self.diagnostics
        ):
            raise DomainError("validator diagnostics must be an exact typed tuple")
        if type(self.input_files) is not tuple or any(
            type(item) is not BoundInputFile for item in self.input_files
        ):
            raise DomainError("validator inputs must be exact BoundInputFile evidence")
        if type(self.resource_identities) is not tuple or any(
            type(item) is not str or not item for item in self.resource_identities
        ):
            raise DomainError("validator resource identities must be an exact string tuple")
        if tuple(sorted(set(self.resource_identities))) != self.resource_identities:
            raise DomainError("validator resource identities must be sorted and unique")
        if len({item.file_path for item in self.input_files}) != len(self.input_files):
            raise DomainError("validator input paths must be unique")
        for name in (
            "files_eligible", "files_validated", "resources_expected",
            "resources_validated", "duration_ms",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise DomainError(f"{name} must be an integer >= 0")
        if self.files_validated > self.files_eligible:
            raise DomainError("files_validated cannot exceed files_eligible")
        if self.resources_validated > self.resources_expected:
            raise DomainError("resources_validated cannot exceed resources_expected")
        for name in (
            "runtime_identity", "tool_environment_identity", "invocation_identity",
            "sealed_snapshot_identity", "stdout_sha256", "stderr_sha256",
            "materialized_view_sha256",
            "native_output_bytes_sha256", "canonical_native_output_sha256",
            "output_directory_manifest_sha256",
        ):
            if type(getattr(self, name)) is not str or _SHA.fullmatch(getattr(self, name)) is None:
                raise DomainError(f"{name} must be a canonical SHA-256")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise DomainError("validator exit_code must be int or absent")
        controls = tuple(sorted(self.execution_controls))
        if len(controls) != len(set(controls)) or any(type(item) is not str for item in controls):
            raise DomainError("validator execution controls must be unique strings")
        object.__setattr__(self, "execution_controls", controls)
        object.__setattr__(self, "diagnostics", tuple(sorted(
            self.diagnostics,
            key=lambda item: (item.severity, item.file_path, item.line or 0, item.summary),
        )))
        object.__setattr__(self, "input_files", tuple(sorted(
            self.input_files, key=lambda item: item.canonical_key,
        )))
        if self.status is Status.PASS and self.reason is not ValidationReason.COMPLETED:
            raise DomainError("PASS validator evidence requires COMPLETED")
        if _trusted_context is _EVIDENCE_CONTEXT:
            object.__setattr__(self, "_trusted_validator_evidence", True)

    @classmethod
    def _from_execution(cls, **kwargs: Any) -> "ValidatorExecutionEvidence":
        return cls(_trusted_context=_EVIDENCE_CONTEXT, **kwargs)

    @property
    def identity(self) -> str:
        return hashlib.sha256(json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()

    def canonical_dict(self) -> dict:
        return {
            "validator_id": self.validator_id, "tool": self.tool, "version": self.version,
            "status": self.status.value, "reason": self.reason.value,
            "advisory_only": self.advisory_only,
            "diagnostics": [item.canonical_dict() for item in self.diagnostics],
            "resource_identities": list(self.resource_identities),
            "input_files": [item.canonical_dict() for item in self.input_files],
            "files_eligible": self.files_eligible, "files_validated": self.files_validated,
            "resources_expected": self.resources_expected,
            "resources_validated": self.resources_validated,
            "runtime_identity": self.runtime_identity,
            "tool_environment_identity": self.tool_environment_identity,
            "invocation_identity": self.invocation_identity,
            "sealed_snapshot_identity": self.sealed_snapshot_identity,
            "materialized_view_sha256": self.materialized_view_sha256,
            "stdout_sha256": self.stdout_sha256, "stderr_sha256": self.stderr_sha256,
            "native_output_bytes_sha256": self.native_output_bytes_sha256,
            "canonical_native_output_sha256": self.canonical_native_output_sha256,
            "output_directory_manifest_sha256": self.output_directory_manifest_sha256,
            "exit_code": self.exit_code, "duration_ms": self.duration_ms,
            "execution_controls": list(self.execution_controls),
        }


def require_trusted_validator_evidence(value: object) -> ValidatorExecutionEvidence:
    if type(value) is not ValidatorExecutionEvidence or not value._trusted_validator_evidence:
        raise DomainError("validator evidence was not produced by actual trusted execution")
    return value


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()).hexdigest()
