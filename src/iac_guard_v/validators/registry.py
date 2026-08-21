"""Closed production validator registry; executable callbacks are never accepted."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from ..enums import Status
from ..models import DomainError, canonical_identifier
from .base import ValidatorExecutionEvidence, canonical_sha256, require_trusted_validator_evidence
from .kubeconform import KubeconformValidationRequest, KubeconformValidator
from .terraform import TerraformValidationRequest, TerraformValidator
from .tflint import TflintValidationRequest, TflintValidator


_REGISTRY_CONTRACT = "phase-e-closed-validator-registry-v2"
_VALIDATOR_CONTRACTS = {
    "opentofu_validate": "opentofu-validate-contract-v3",
    "terraform_validate": "terraform-validate-contract-v3",
    "kubeconform_schema": "kubeconform-schema-contract-v3",
    "tflint_advisory": "tflint-advisory-contract-v3",
}
_IMPLEMENTATIONS = {
    "opentofu_validate": (TerraformValidationRequest, TerraformValidator, "terraform.py", ("terraform_hcl",), False),
    "terraform_validate": (TerraformValidationRequest, TerraformValidator, "terraform.py", ("terraform_hcl",), False),
    "kubeconform_schema": (KubeconformValidationRequest, KubeconformValidator, "kubeconform.py", ("kubernetes_json", "kubernetes_yaml"), False),
    "tflint_advisory": (TflintValidationRequest, TflintValidator, "tflint.py", ("terraform_hcl",), True),
}


_SHARED_IMPLEMENTATION_FILES = (
    "adapters/base.py", "adapters/phase_e_lock.py", "adapters/phase_e_runtime.py",
    "engine.py", "enums.py", "models.py", "process.py", "validators/base.py",
    "validators/materialization.py", "validators/registry.py", "validators/universe.py",
)
_SHA = re.compile(r"[0-9a-f]{64}")
_INTEGRITY_REASON_PASS = "BYTECODE_FREE_PRODUCT_BUILD"
_INTEGRITY_REASON_NATIVE = "WRITABLE_NATIVE_PACKAGE_HAS_EXECUTABLE_CACHE"
_INTEGRITY_REMEDIATION = (
    "Use the read-only bytecode-free hardened installation and set "
    "PYTHONDONTWRITEBYTECODE=1 before Python starts."
)


def _read_source_bytes(relative: str) -> bytes:
    root = Path(__file__).parents[1]
    path = root.joinpath(*relative.split("/"))
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DomainError("validator implementation module is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise DomainError("validator implementation changed during registry construction")
        content = bytearray()
        while chunk := os.read(descriptor, 64 * 1024):
            content.extend(chunk)
    finally:
        os.close(descriptor)
    return bytes(content)


def _source_digest(relative: str) -> str:
    return hashlib.sha256(_read_source_bytes(relative)).hexdigest()


def _product_source_inventory() -> tuple[tuple[str, ...], tuple[str, ...]]:
    root = Path(__file__).parents[1]
    records = []
    unsafe = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(metadata.st_mode):
                unsafe.append(f"SYMLINK:{relative}")
            if stat.S_ISDIR(metadata.st_mode):
                if entry.name == "__pycache__":
                    unsafe.append(f"BYTECODE_CACHE:{relative}")
                elif not stat.S_ISLNK(metadata.st_mode):
                    pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                if path.suffix.lower() in {".pyc", ".pyo"}:
                    unsafe.append(f"BYTECODE:{relative}")
                else:
                    records.append(relative)
            else:
                if not stat.S_ISLNK(metadata.st_mode):
                    unsafe.append(f"SPECIAL:{relative}")
    return tuple(sorted(records)), tuple(sorted(unsafe))


def _manifest_digest(paths: tuple[str, ...]) -> str:
    records = []
    for path in paths:
        content = _read_source_bytes(path)
        records.append({
            "path": path, "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        })
    return canonical_sha256(records)


def _parser_dependency_identity() -> str:
    # The Phase-D gate implementation already enforces complete RECORD-backed
    # installed-code identity for python-hcl2, PyYAML, and their closure.
    from ..engine import _verified_parser_environment
    return canonical_sha256(_verified_parser_environment())


def _runtime_contract_identity() -> str:
    from ..adapters.phase_e_runtime import REQUIRED_ISOLATION_CONTROLS, RUNTIME_CONTRACT
    return canonical_sha256({
        "contract": RUNTIME_CONTRACT,
        "required_controls": list(REQUIRED_ISOLATION_CONTROLS),
        "implementation": _source_digest("adapters/phase_e_runtime.py"),
    })


def _schema_contract_identity() -> str:
    return canonical_sha256({
        "contract": "protected-kubernetes-schema-e0.3-v1",
        "lock_implementation": _source_digest("adapters/phase_e_lock.py"),
        "discovery_implementation": _source_digest("engine.py"),
    })


@dataclass(frozen=True, slots=True)
class ValidatorImplementationRecord:
    gate_id: str
    contract_version: str
    implementation_sha256: str
    supported_artifact_kinds: tuple
    advisory_only: bool
    product_build_digest: str
    validator_module_sha256: str
    shared_code_manifest_root: str
    parser_dependency_identity: str
    schema_contract_identity: str
    runtime_contract_identity: str

    def __post_init__(self) -> None:
        canonical_identifier(self.gate_id, "gate_id")
        canonical_identifier(self.contract_version, "contract_version")
        for name in (
            "implementation_sha256", "product_build_digest",
            "validator_module_sha256", "shared_code_manifest_root",
            "parser_dependency_identity", "schema_contract_identity",
            "runtime_contract_identity",
        ):
            if type(getattr(self, name)) is not str or _SHA.fullmatch(getattr(self, name)) is None:
                raise DomainError(f"validator {name} digest is invalid")
        if tuple(sorted(set(self.supported_artifact_kinds))) != self.supported_artifact_kinds:
            raise DomainError("validator artifact kinds must be sorted and unique")
        if self.implementation_sha256 != canonical_sha256(self._implementation_children()):
            raise DomainError("validator implementation digest does not bind its children")

    def _implementation_children(self) -> dict:
        return {
            "gate_id": self.gate_id,
            "contract_version": self.contract_version,
            "product_build_digest": self.product_build_digest,
            "validator_module_sha256": self.validator_module_sha256,
            "shared_code_manifest_root": self.shared_code_manifest_root,
            "parser_dependency_identity": self.parser_dependency_identity,
            "schema_contract_identity": self.schema_contract_identity,
            "runtime_contract_identity": self.runtime_contract_identity,
        }

    def canonical_dict(self) -> dict:
        return {
            "gate_id": self.gate_id, "contract_version": self.contract_version,
            "implementation_sha256": self.implementation_sha256,
            "product_build_digest": self.product_build_digest,
            "validator_module_sha256": self.validator_module_sha256,
            "shared_code_manifest_root": self.shared_code_manifest_root,
            "parser_dependency_identity": self.parser_dependency_identity,
            "schema_contract_identity": self.schema_contract_identity,
            "runtime_contract_identity": self.runtime_contract_identity,
            "supported_artifact_kinds": list(self.supported_artifact_kinds),
            "advisory_only": self.advisory_only,
        }


@dataclass(frozen=True, slots=True)
class TrustedValidatorRegistry:
    records: tuple
    contract: str
    integrity_status: Status = Status.PASS
    integrity_reason: str = _INTEGRITY_REASON_PASS
    remediation: str = ""

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
        if self.integrity_status not in {Status.PASS, Status.INCONCLUSIVE}:
            raise DomainError("validator registry integrity status is invalid")
        if type(self.integrity_reason) is not str or not self.integrity_reason:
            raise DomainError("validator registry integrity reason is required")
        if type(self.remediation) is not str:
            raise DomainError("validator registry remediation must be a string")
        if self.integrity_status is Status.PASS and self.remediation:
            raise DomainError("passing validator registry cannot require remediation")

    @property
    def identity(self) -> str:
        return canonical_sha256(self.canonical_dict())

    def canonical_dict(self) -> dict:
        return {
            "contract": self.contract,
            "integrity_status": self.integrity_status.value,
            "integrity_reason": self.integrity_reason,
            "remediation": self.remediation,
            "records": [item.canonical_dict() for item in self.records],
        }

    def execute(self, gate_id: str, request: object) -> ValidatorExecutionEvidence:
        if self.integrity_status is not Status.PASS:
            raise DomainError("VALIDATOR_REGISTRY_INTEGRITY_INCONCLUSIVE")
        _paths, unsafe = _product_source_inventory()
        if unsafe:
            raise DomainError("VALIDATOR_REGISTRY_INTEGRITY_INCONCLUSIVE")
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
        _paths, unsafe = _product_source_inventory()
        if unsafe:
            raise DomainError("VALIDATOR_REGISTRY_INTEGRITY_INCONCLUSIVE")
        require_trusted_validator_evidence(evidence)
        if evidence.validator_id != gate_id:
            raise DomainError("validator returned evidence for a different gate")
        return evidence


def production_validator_registry() -> TrustedValidatorRegistry:
    product_paths, unsafe = _product_source_inventory()
    product_build = _manifest_digest(product_paths)
    shared_manifest = _manifest_digest(_SHARED_IMPLEMENTATION_FILES)
    parser_unsafe = ""
    try:
        parser_dependencies = _parser_dependency_identity()
    except DomainError as exc:
        parser_unsafe = str(exc)
        parser_dependencies = canonical_sha256({
            "integrity": "INCONCLUSIVE", "reason": parser_unsafe,
        })
    runtime_contract = _runtime_contract_identity()
    schema_contract = _schema_contract_identity()
    records = tuple(
        _implementation_record(
            gate_id, filename, artifacts, advisory, product_build, shared_manifest,
            parser_dependencies, schema_contract, runtime_contract,
        )
        for gate_id, (_, _, filename, artifacts, advisory) in sorted(_IMPLEMENTATIONS.items())
    )
    return TrustedValidatorRegistry(
        records, _REGISTRY_CONTRACT,
        Status.INCONCLUSIVE if unsafe or parser_unsafe else Status.PASS,
        (
            _INTEGRITY_REASON_NATIVE if unsafe
            else "PARSER_DEPENDENCY_INTEGRITY_INCONCLUSIVE" if parser_unsafe
            else _INTEGRITY_REASON_PASS
        ),
        _INTEGRITY_REMEDIATION if unsafe or parser_unsafe else "",
    )


def _implementation_record(
    gate_id: str, filename: str, artifacts: tuple, advisory: bool,
    product_build: str, shared_manifest: str, parser_dependencies: str,
    schema_contract: str, runtime_contract: str,
) -> ValidatorImplementationRecord:
    module_digest = _source_digest(f"validators/{filename}")
    children = {
        "gate_id": gate_id,
        "contract_version": _VALIDATOR_CONTRACTS[gate_id],
        "product_build_digest": product_build,
        "validator_module_sha256": module_digest,
        "shared_code_manifest_root": shared_manifest,
        "parser_dependency_identity": parser_dependencies,
        "schema_contract_identity": schema_contract,
        "runtime_contract_identity": runtime_contract,
    }
    return ValidatorImplementationRecord(
        gate_id=gate_id, contract_version=_VALIDATOR_CONTRACTS[gate_id],
        implementation_sha256=canonical_sha256(children),
        supported_artifact_kinds=tuple(sorted(artifacts)), advisory_only=advisory,
        product_build_digest=product_build, validator_module_sha256=module_digest,
        shared_code_manifest_root=shared_manifest,
        parser_dependency_identity=parser_dependencies,
        schema_contract_identity=schema_contract,
        runtime_contract_identity=runtime_contract,
    )


__all__ = [
    "TrustedValidatorRegistry", "ValidatorImplementationRecord",
    "production_validator_registry",
]
