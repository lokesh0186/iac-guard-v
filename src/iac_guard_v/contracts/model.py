"""Immutable closed vocabulary for a10 intent contracts."""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from enum import Enum
from importlib.resources import files
from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError, canonical_identifier, canonical_resource_scope
from ..native_properties.model import canonical_digest


CONTRACT_SCHEMA_VERSION = "infrastructure-contract-v1alpha1"
CONTRACT_REPORT_VERSION = "infrastructure-contract-report-v1alpha1"
_SAFE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,62}[a-z0-9])?$")


def contract_canonical_json(value: Any, label: str = "value") -> Any:
    """Freeze contract JSON, including finite decimal activation values.

    The a9 native-property boundary intentionally rejects floats.  Contracts need
    typed numeric activation without changing that released native semantic model.
    """
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise DomainError(f"{label} contains a non-finite number")
        return value
    if type(value) in (list, tuple):
        return tuple(contract_canonical_json(item, f"{label} item") for item in value)
    if type(value) in (dict, MappingProxyType):
        copied: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise DomainError(f"{label} keys must be nonempty exact strings")
            copied[key] = contract_canonical_json(item, f"{label}.{key}")
        return MappingProxyType(dict(sorted(copied.items())))
    raise DomainError(f"{label} contains unsupported JSON type {type(value).__name__}")


def contract_thaw(value: Any) -> Any:
    if type(value) is MappingProxyType:
        return {key: contract_thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [contract_thaw(item) for item in value]
    return value


def contract_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        contract_thaw(contract_canonical_json(value)), sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")).hexdigest()


class ContractProvenance(str, Enum):
    PROJECT_AUTHORED = "PROJECT_AUTHORED"
    USER_AUTHORED = "USER_AUTHORED"
    RESEARCH_HYPOTHESIS = "RESEARCH_HYPOTHESIS"
    SUGGESTED_CONTRACT = "SUGGESTED_CONTRACT"


class Responsibility(str, Enum):
    PROJECT_MANAGED = "PROJECT_MANAGED"
    USER_MANAGED = "USER_MANAGED"
    EXTERNAL_SYSTEM = "EXTERNAL_SYSTEM"
    OUT_OF_CONTRACT = "OUT_OF_CONTRACT"


class ActivationStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE_CONDITION_FALSE = "INACTIVE_CONDITION_FALSE"
    ACTIVATION_NOT_EVALUATED = "ACTIVATION_NOT_EVALUATED"
    ACTIVATION_ERROR = "ACTIVATION_ERROR"


class ContractResult(str, Enum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class ContractSourceIdentity:
    path: str
    raw_sha256: str
    source_commit: str
    project_root_identity: str
    provenance: ContractProvenance

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", canonical_resource_scope(self.path, "contract path"))
        for name in ("raw_sha256", "project_root_identity"):
            value = getattr(self, name)
            if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise DomainError(f"{name} must be a lowercase SHA-256")
        if (
            type(self.source_commit) is not str
            or (
                self.source_commit != "WORKTREE"
                and re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", self.source_commit) is None
            )
        ):
            raise DomainError("contract source commit must be WORKTREE or an exact lowercase Git commit")
        if type(self.provenance) is not ContractProvenance:
            raise DomainError("contract provenance is invalid")

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "raw_sha256": self.raw_sha256,
            "source_commit": self.source_commit,
            "project_root_identity": self.project_root_identity,
            "provenance": self.provenance.value,
        }


@dataclass(frozen=True, slots=True)
class InfrastructureContract:
    name: str
    artifact_class: str
    when: Mapping[str, Any] | None
    subjects: Mapping[str, Any]
    responsibility: Mapping[str, Any]
    clauses: tuple[Mapping[str, Any], ...]
    canonical_payload: Mapping[str, Any]
    canonical_digest: str
    source: ContractSourceIdentity

    def __post_init__(self) -> None:
        if type(self.name) is not str or _SAFE_NAME.fullmatch(self.name) is None:
            raise DomainError("contract name is invalid")
        if self.artifact_class not in {"kubernetes_rendered", "terraform_source"}:
            raise DomainError("contract artifact class is unsupported")
        for name in ("subjects", "responsibility", "canonical_payload"):
            object.__setattr__(self, name, contract_canonical_json(getattr(self, name), name))
        if self.when is not None:
            object.__setattr__(self, "when", contract_canonical_json(self.when, "activation"))
        object.__setattr__(
            self, "clauses", tuple(contract_canonical_json(item, "contract clause") for item in self.clauses)
        )
        if self.canonical_digest != contract_digest(self.canonical_payload):
            raise DomainError("contract canonical digest is contradictory")
        if type(self.source) is not ContractSourceIdentity:
            raise DomainError("contract source identity is invalid")

    @property
    def identity(self) -> str:
        return contract_digest({
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "name": self.name,
            "provenance": self.source.provenance.value,
            "source": self.source.canonical_dict(),
            "canonical_contract_digest": self.canonical_digest,
        })


@dataclass(frozen=True, slots=True)
class ActivationEvidence:
    status: ActivationStatus
    reason_code: str
    facts: tuple[Mapping[str, Any], ...]
    input_identity: str

    def __post_init__(self) -> None:
        if type(self.status) is not ActivationStatus:
            raise DomainError("activation status is invalid")
        object.__setattr__(self, "reason_code", canonical_identifier(self.reason_code, "activation reason"))
        object.__setattr__(self, "facts", tuple(contract_canonical_json(item) for item in self.facts))
        if type(self.input_identity) is not str or re.fullmatch(r"[0-9a-f]{64}", self.input_identity) is None:
            raise DomainError("activation input identity must be a SHA-256")

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason_code": self.reason_code,
            "facts": [contract_thaw(item) for item in self.facts],
            "input_identity": self.input_identity,
        }


def contract_implementation_identity() -> str:
    package = files("iac_guard_v").joinpath("contracts")
    names = (
        "activation.py", "evaluator.py", "helm_values.py", "historical.py",
        "model.py", "parser.py", "planner.py", "provenance.py", "public.py", "report.py",
    )
    records = []
    for name in names:
        item = package.joinpath(name)
        if item.is_file():
            records.append({"module": f"contracts.{name[:-3]}", "sha256": hashlib.sha256(item.read_bytes()).hexdigest()})
    # Activation consumes the reviewed Helm materializer's protected effective
    # values.  Bind that implementation separately instead of pretending the
    # contract layer independently implements Helm precedence.
    helm = files("iac_guard_v").joinpath("helm.py")
    records.append({"module": "helm", "sha256": hashlib.sha256(helm.read_bytes()).hexdigest()})
    for schema in (
        "infrastructure-contract-v1alpha1.schema.json",
        "infrastructure-contract-report-v1alpha1.schema.json",
    ):
        item = files("iac_guard_v").joinpath("schemas", schema)
        records.append({"module": f"schemas.{schema}", "sha256": hashlib.sha256(item.read_bytes()).hexdigest()})
    return canonical_digest(records)


def contract_schema_identity() -> str:
    payload = files("iac_guard_v").joinpath(
        "schemas/infrastructure-contract-v1alpha1.schema.json"
    ).read_bytes()
    return hashlib.sha256(payload).hexdigest()


def canonical_contract_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        contract_thaw(contract_canonical_json(payload)), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


__all__ = [
    "ActivationEvidence", "ActivationStatus", "CONTRACT_REPORT_VERSION",
    "CONTRACT_SCHEMA_VERSION", "ContractProvenance", "ContractResult",
    "ContractSourceIdentity", "InfrastructureContract", "Responsibility",
    "canonical_contract_bytes", "contract_implementation_identity",
    "contract_schema_identity", "contract_canonical_json", "contract_digest",
    "contract_thaw",
]
