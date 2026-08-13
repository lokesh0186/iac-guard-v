"""Immutable evidence from protected deterministic oracles."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import InitVar, dataclass, field

from ..enums import ArtifactKind, ScanRole, Status
from ..models import (
    DomainError,
    canonical_identifier,
    canonical_repo_path,
    canonical_resource_scope,
    require_enum,
)


ORACLE_CONTRACT = "protected-deterministic-oracle-v1"
_SHA = re.compile(r"[0-9a-f]{64}")
_EVIDENCE_CONTEXT = object()


@dataclass(frozen=True, slots=True)
class OracleObservation:
    path: str
    result: str
    detail: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", canonical_resource_scope(self.path, "oracle path"))
        if self.result not in {"SATISFIED", "VIOLATED", "UNAVAILABLE"}:
            raise DomainError("oracle observation result is unsupported")
        if type(self.detail) is not str or len(self.detail) > 4096:
            raise DomainError("oracle observation detail is invalid")

    def canonical_dict(self) -> dict:
        return {"path": self.path, "result": self.result, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class OracleResult:
    oracle_id: str
    contract_version: str
    implementation_build_identity: str
    protected_policy_sha256: str
    sealed_snapshot_identity: str
    role: ScanRole
    file_path: str
    artifact_kind: ArtifactKind
    resource_identity: str
    status: Status
    reason: str
    observations: tuple
    raw_output_sha256: str
    canonical_output_sha256: str
    execution_controls: tuple
    authoritative_reference: str
    _trusted_context: InitVar[object] = None
    _trusted_oracle_evidence: bool = field(
        init=False, default=False, repr=False, compare=False,
    )

    def __post_init__(self, _trusted_context: object) -> None:
        object.__setattr__(self, "oracle_id", canonical_identifier(self.oracle_id, "oracle id"))
        object.__setattr__(
            self, "contract_version",
            canonical_identifier(self.contract_version, "oracle contract"),
        )
        for name in (
            "implementation_build_identity", "protected_policy_sha256",
            "sealed_snapshot_identity", "raw_output_sha256", "canonical_output_sha256",
        ):
            if type(getattr(self, name)) is not str or not _SHA.fullmatch(getattr(self, name)):
                raise DomainError(f"oracle {name} must be a canonical SHA-256")
        require_enum(self.role, ScanRole, "oracle role")
        if self.role is ScanRole.DISCOVERY:
            raise DomainError("oracle requires a role-bound snapshot")
        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        require_enum(self.artifact_kind, ArtifactKind, "oracle artifact kind")
        object.__setattr__(
            self, "resource_identity",
            canonical_resource_scope(self.resource_identity, "oracle resource identity"),
        )
        require_enum(self.status, Status, "oracle status")
        object.__setattr__(self, "reason", canonical_identifier(self.reason, "oracle reason"))
        if type(self.observations) is not tuple or any(
            type(item) is not OracleObservation for item in self.observations
        ):
            raise DomainError("oracle observations must be exact typed records")
        ordered = tuple(sorted(self.observations, key=lambda item: (item.path, item.result)))
        if len({item.path for item in ordered}) != len(ordered):
            raise DomainError("oracle observations contain duplicate paths")
        object.__setattr__(self, "observations", ordered)
        controls = tuple(sorted(self.execution_controls))
        if controls != tuple(sorted(set(controls))) or any(type(item) is not str for item in controls):
            raise DomainError("oracle controls must be unique strings")
        object.__setattr__(self, "execution_controls", controls)
        if type(self.authoritative_reference) is not str or not self.authoritative_reference.startswith("https://"):
            raise DomainError("oracle authoritative reference must be HTTPS")
        if self.status is Status.PASS and any(item.result != "SATISFIED" for item in ordered):
            raise DomainError("passing oracle evidence contains a non-satisfied observation")
        if self.status is Status.FAIL and not any(item.result == "VIOLATED" for item in ordered):
            raise DomainError("failing oracle evidence requires a violation")
        if _trusted_context is not _EVIDENCE_CONTEXT:
            raise DomainError("oracle evidence requires protected execution")
        object.__setattr__(self, "_trusted_oracle_evidence", True)

    @property
    def identity(self) -> str:
        return hashlib.sha256(json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()

    def canonical_dict(self) -> dict:
        return {
            "oracle_id": self.oracle_id,
            "contract_version": self.contract_version,
            "implementation_build_identity": self.implementation_build_identity,
            "protected_policy_sha256": self.protected_policy_sha256,
            "sealed_snapshot_identity": self.sealed_snapshot_identity,
            "role": self.role.value,
            "file_path": self.file_path,
            "artifact_kind": self.artifact_kind.value,
            "resource_identity": self.resource_identity,
            "status": self.status.value,
            "reason": self.reason,
            "observations": [item.canonical_dict() for item in self.observations],
            "raw_output_sha256": self.raw_output_sha256,
            "canonical_output_sha256": self.canonical_output_sha256,
            "execution_controls": list(self.execution_controls),
            "authoritative_reference": self.authoritative_reference,
        }


def create_oracle_result(**values) -> OracleResult:
    return OracleResult(_trusted_context=_EVIDENCE_CONTEXT, **values)


def require_trusted_oracle_evidence(value: object) -> OracleResult:
    if type(value) is not OracleResult or not value._trusted_oracle_evidence:
        raise DomainError("oracle evidence is not protected execution evidence")
    return value
