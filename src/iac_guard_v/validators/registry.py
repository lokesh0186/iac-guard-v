"""Closed production validator registry; executable callbacks are never accepted."""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from ..models import DomainError, canonical_identifier
from .base import ValidatorExecutionEvidence, canonical_sha256, require_trusted_validator_evidence
from .kubeconform import KubeconformValidationRequest, KubeconformValidator
from .terraform import TerraformValidationRequest, TerraformValidator
from .tflint import TflintValidationRequest, TflintValidator


_REGISTRY_CONTRACT = "phase-e-closed-validator-registry-v1"
_IMPLEMENTATIONS = {
    "opentofu_validate": (TerraformValidationRequest, TerraformValidator, "terraform.py", ("terraform_hcl",), False),
    "terraform_validate": (TerraformValidationRequest, TerraformValidator, "terraform.py", ("terraform_hcl",), False),
    "kubeconform_schema": (KubeconformValidationRequest, KubeconformValidator, "kubeconform.py", ("kubernetes_json", "kubernetes_yaml"), False),
    "tflint_advisory": (TflintValidationRequest, TflintValidator, "tflint.py", ("terraform_hcl",), True),
}


def _module_digest(filename: str) -> str:
    path = Path(__file__).with_name(filename)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DomainError("validator implementation module is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise DomainError("validator implementation changed during registry construction")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ValidatorImplementationRecord:
    gate_id: str
    contract_version: str
    implementation_sha256: str
    supported_artifact_kinds: tuple
    advisory_only: bool

    def __post_init__(self) -> None:
        canonical_identifier(self.gate_id, "gate_id")
        canonical_identifier(self.contract_version, "contract_version")
        if len(self.implementation_sha256) != 64:
            raise DomainError("validator implementation digest is invalid")
        if tuple(sorted(set(self.supported_artifact_kinds))) != self.supported_artifact_kinds:
            raise DomainError("validator artifact kinds must be sorted and unique")

    def canonical_dict(self) -> dict:
        return {
            "gate_id": self.gate_id, "contract_version": self.contract_version,
            "implementation_sha256": self.implementation_sha256,
            "supported_artifact_kinds": list(self.supported_artifact_kinds),
            "advisory_only": self.advisory_only,
        }


@dataclass(frozen=True, slots=True)
class TrustedValidatorRegistry:
    records: tuple
    contract: str

    def __post_init__(self) -> None:
        if self.contract != _REGISTRY_CONTRACT:
            raise DomainError("validator registry contract is unsupported")
        if type(self.records) is not tuple or any(
            type(item) is not ValidatorImplementationRecord for item in self.records
        ):
            raise DomainError("validator registry records are invalid")
        ids = tuple(item.gate_id for item in self.records)
        if ids != tuple(sorted(_IMPLEMENTATIONS)):
            raise DomainError("validator registry is not the complete closed production set")

    @property
    def identity(self) -> str:
        return canonical_sha256(self.canonical_dict())

    def canonical_dict(self) -> dict:
        return {"contract": self.contract, "records": [item.canonical_dict() for item in self.records]}

    def execute(self, gate_id: str, request: object) -> ValidatorExecutionEvidence:
        if gate_id not in _IMPLEMENTATIONS:
            raise DomainError("validator id is outside the closed production registry")
        request_type, validator_type, _, _, _ = _IMPLEMENTATIONS[gate_id]
        if type(request) is not request_type:
            raise DomainError("validator request type does not match the selected gate")
        if gate_id in {"opentofu_validate", "terraform_validate"}:
            expected_tool = gate_id.removesuffix("_validate")
            if request.locked_identity.tool != expected_tool:
                raise DomainError("Terraform-family validator identity was substituted")
        evidence = validator_type().validate(request)
        require_trusted_validator_evidence(evidence)
        if evidence.validator_id != gate_id:
            raise DomainError("validator returned evidence for a different gate")
        return evidence


def production_validator_registry() -> TrustedValidatorRegistry:
    records = tuple(
        ValidatorImplementationRecord(
            gate_id, _REGISTRY_CONTRACT, _module_digest(filename),
            tuple(sorted(artifacts)), advisory,
        )
        for gate_id, (_, _, filename, artifacts, advisory) in sorted(_IMPLEMENTATIONS.items())
    )
    return TrustedValidatorRegistry(records, _REGISTRY_CONTRACT)


__all__ = [
    "TrustedValidatorRegistry", "ValidatorImplementationRecord",
    "production_validator_registry",
]
