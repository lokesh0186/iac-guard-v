"""Immutable native-property vocabulary and canonical evidence identities."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from ..models import DomainError, canonical_identifier, canonical_resource_scope


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class NativePropertyResult(str, Enum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


class NativeArtifactClass(str, Enum):
    KUBERNETES_RENDERED = "kubernetes_rendered"
    TERRAFORM_SOURCE = "terraform_source"
    OPENTOFU_SOURCE = "opentofu_source"


def canonical_json(value: Any, label: str = "value") -> Any:
    """Return an immutable, JSON-shaped copy with exact boundary types.

    Floats are intentionally rejected. Native property parameters and witnesses use
    exact integers, strings, booleans and null; accepting NaN or architecture-sensitive
    floating encodings would weaken canonical evidence identity.
    """
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) in (list, tuple):
        return tuple(canonical_json(item, f"{label} item") for item in value)
    if type(value) in (dict, MappingProxyType):
        copied: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise DomainError(f"{label} keys must be nonempty exact strings")
            copied[key] = canonical_json(item, f"{label}.{key}")
        return MappingProxyType(dict(sorted(copied.items())))
    raise DomainError(f"{label} contains unsupported JSON type {type(value).__name__}")


def thaw_json(value: Any) -> Any:
    if type(value) is MappingProxyType:
        return {key: thaw_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [thaw_json(item) for item in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        thaw_json(canonical_json(value)),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def require_digest(value: str, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise DomainError(f"{label} must be a lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class NativePropertyCapabilities:
    can_satisfy: bool
    can_violate: bool
    requires_complete_universe_for_violation: bool
    relationship_graph: bool
    source_span: bool

    def __post_init__(self) -> None:
        for name in self.__slots__:
            if type(getattr(self, name)) is not bool:
                raise DomainError(f"native capability {name} must be an exact bool")

    def canonical_dict(self) -> dict[str, bool]:
        return {name: getattr(self, name) for name in self.__slots__}


@dataclass(frozen=True, slots=True)
class NativeSemanticVersionBinding:
    system: str
    version: str
    contract_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "system", canonical_identifier(self.system, "semantic system"))
        object.__setattr__(self, "version", canonical_identifier(self.version, "semantic version"))
        require_digest(self.contract_digest, "semantic contract digest")

    def canonical_dict(self) -> dict[str, str]:
        return {
            "system": self.system,
            "version": self.version,
            "contract_digest": self.contract_digest,
        }


@dataclass(frozen=True, slots=True)
class NativePropertyImplementationIdentity:
    implementation_version: str
    implementation_digest: str
    module_digests: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "implementation_version",
            canonical_identifier(self.implementation_version, "native implementation version"),
        )
        require_digest(self.implementation_digest, "native implementation digest")
        if type(self.module_digests) is not tuple or not self.module_digests:
            raise DomainError("native implementation modules must be a nonempty exact tuple")
        rebuilt: list[tuple[str, str]] = []
        for entry in self.module_digests:
            if type(entry) is not tuple or len(entry) != 2:
                raise DomainError("native implementation module entry is malformed")
            module = canonical_identifier(entry[0], "native implementation module")
            rebuilt.append((module, require_digest(entry[1], "native module digest")))
        rebuilt.sort()
        if len(rebuilt) != len(set(rebuilt)):
            raise DomainError("duplicate native implementation module identity")
        object.__setattr__(self, "module_digests", tuple(rebuilt))
        expected = canonical_digest([
            {"module": module, "sha256": digest} for module, digest in rebuilt
        ])
        if self.implementation_digest != expected:
            raise DomainError("native implementation digest is not canonical")

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "implementation_version": self.implementation_version,
            "implementation_digest": self.implementation_digest,
            "modules": [
                {"module": module, "sha256": digest}
                for module, digest in self.module_digests
            ],
        }


@dataclass(frozen=True, slots=True)
class NativePropertyDefinition:
    property_namespace: str
    property_id: str
    property_version: str
    artifact_class: NativeArtifactClass
    subject_class: str
    parameter_schema: Mapping[str, Any]
    parameter_schema_digest: str
    semantic_definition_digest: str
    semantic_binding: NativeSemanticVersionBinding
    capabilities: NativePropertyCapabilities
    witness_type: str
    implementation: NativePropertyImplementationIdentity

    def __post_init__(self) -> None:
        if self.property_namespace != "iac_guard_v":
            raise DomainError("native property namespace must be iac_guard_v")
        for name in ("property_id", "property_version", "subject_class", "witness_type"):
            object.__setattr__(self, name, canonical_identifier(getattr(self, name), name))
        if type(self.artifact_class) is not NativeArtifactClass:
            raise DomainError("native property artifact class is invalid")
        schema = canonical_json(self.parameter_schema, "native parameter schema")
        object.__setattr__(self, "parameter_schema", schema)
        require_digest(self.parameter_schema_digest, "native parameter schema digest")
        if self.parameter_schema_digest != canonical_digest(schema):
            raise DomainError("native parameter schema digest is not canonical")
        require_digest(self.semantic_definition_digest, "native semantic definition digest")
        if type(self.semantic_binding) is not NativeSemanticVersionBinding:
            raise DomainError("native semantic binding must be exact")
        if type(self.capabilities) is not NativePropertyCapabilities:
            raise DomainError("native capabilities must be exact")
        if type(self.implementation) is not NativePropertyImplementationIdentity:
            raise DomainError("native implementation identity must be exact")

    @property
    def opaque_id(self) -> str:
        return f"{self.property_namespace}:{self.property_id}:{self.property_version}"

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "property_namespace": self.property_namespace,
            "property_id": self.property_id,
            "property_version": self.property_version,
            "artifact_class": self.artifact_class.value,
            "subject_class": self.subject_class,
            "parameter_schema": thaw_json(self.parameter_schema),
            "parameter_schema_digest": self.parameter_schema_digest,
            "semantic_definition_digest": self.semantic_definition_digest,
            "semantic_binding": self.semantic_binding.canonical_dict(),
            "capabilities": self.capabilities.canonical_dict(),
            "witness_type": self.witness_type,
            "implementation": self.implementation.canonical_dict(),
        }


@dataclass(frozen=True, slots=True)
class NativePropertyRequest:
    property_id: str
    property_version: str
    artifact_class: NativeArtifactClass
    subject_identity: str
    parameters: Mapping[str, Any]
    parameters_digest: str
    protected_universe_identity: str
    request_id: str

    def __post_init__(self) -> None:
        for name in ("property_id", "property_version", "request_id"):
            object.__setattr__(self, name, canonical_identifier(getattr(self, name), name))
        if type(self.artifact_class) is not NativeArtifactClass:
            raise DomainError("native request artifact class is invalid")
        object.__setattr__(
            self,
            "subject_identity",
            canonical_resource_scope(self.subject_identity, "native subject identity"),
        )
        parameters = canonical_json(self.parameters, "native request parameters")
        object.__setattr__(self, "parameters", parameters)
        require_digest(self.parameters_digest, "native request parameters digest")
        if self.parameters_digest != canonical_digest(parameters):
            raise DomainError("native request parameters digest is not canonical")
        require_digest(self.protected_universe_identity, "protected universe identity")

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        property_id: str,
        property_version: str,
        artifact_class: NativeArtifactClass,
        subject_identity: str,
        parameters: Mapping[str, Any],
        protected_universe_identity: str,
    ) -> "NativePropertyRequest":
        return cls(
            property_id,
            property_version,
            artifact_class,
            subject_identity,
            parameters,
            canonical_digest(parameters),
            protected_universe_identity,
            request_id,
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "property_id": self.property_id,
            "property_version": self.property_version,
            "artifact_class": self.artifact_class.value,
            "subject_identity": self.subject_identity,
            "parameters": thaw_json(self.parameters),
            "parameters_digest": self.parameters_digest,
            "protected_universe_identity": self.protected_universe_identity,
        }


@dataclass(frozen=True, slots=True)
class NativePropertyWitness:
    witness_type: str
    contents: Mapping[str, Any]
    witness_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "witness_type", canonical_identifier(self.witness_type, "witness type")
        )
        contents = canonical_json(self.contents, "native witness")
        object.__setattr__(self, "contents", contents)
        require_digest(self.witness_digest, "native witness digest")
        expected = canonical_digest({
            "witness_type": self.witness_type,
            "contents": thaw_json(contents),
        })
        if self.witness_digest != expected:
            raise DomainError("native witness digest is not canonical")

    @classmethod
    def build(cls, witness_type: str, contents: Mapping[str, Any]) -> "NativePropertyWitness":
        digest = canonical_digest({"witness_type": witness_type, "contents": contents})
        return cls(witness_type, contents, digest)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "witness_type": self.witness_type,
            "contents": thaw_json(self.contents),
            "witness_digest": self.witness_digest,
        }


@dataclass(frozen=True, slots=True)
class NativePropertyObservation:
    request: NativePropertyRequest
    definition: NativePropertyDefinition
    result: NativePropertyResult
    reason_code: str
    subject_provenance: Mapping[str, Any]
    witness: NativePropertyWitness
    observation_digest: str

    def __post_init__(self) -> None:
        if type(self.request) is not NativePropertyRequest:
            raise DomainError("native observation request must be exact")
        if type(self.definition) is not NativePropertyDefinition:
            raise DomainError("native observation definition must be exact")
        if type(self.result) is not NativePropertyResult:
            raise DomainError("native observation result must be exact")
        object.__setattr__(
            self, "reason_code", canonical_identifier(self.reason_code, "native reason code")
        )
        provenance = canonical_json(self.subject_provenance, "native subject provenance")
        object.__setattr__(self, "subject_provenance", provenance)
        if type(self.witness) is not NativePropertyWitness:
            raise DomainError("every native observation requires an exact witness")
        if self.witness.witness_type != self.definition.witness_type:
            raise DomainError("native witness type does not match the property definition")
        if (
            self.request.property_id != self.definition.property_id
            or self.request.property_version != self.definition.property_version
            or self.request.artifact_class is not self.definition.artifact_class
        ):
            raise DomainError("native request and definition identities disagree")
        require_digest(self.observation_digest, "native observation digest")
        if self.observation_digest != canonical_digest(self._body_dict()):
            raise DomainError("native observation digest is not canonical")

    def _body_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.canonical_dict(),
            "definition": self.definition.canonical_dict(),
            "result": self.result.value,
            "reason_code": self.reason_code,
            "subject_provenance": thaw_json(self.subject_provenance),
            "witness": self.witness.canonical_dict(),
        }

    @classmethod
    def build(
        cls,
        *,
        request: NativePropertyRequest,
        definition: NativePropertyDefinition,
        result: NativePropertyResult,
        reason_code: str,
        subject_provenance: Mapping[str, Any],
        witness: NativePropertyWitness,
    ) -> "NativePropertyObservation":
        body = {
            "request": request.canonical_dict(),
            "definition": definition.canonical_dict(),
            "result": result.value,
            "reason_code": reason_code,
            "subject_provenance": subject_provenance,
            "witness": witness.canonical_dict(),
        }
        return cls(
            request,
            definition,
            result,
            reason_code,
            subject_provenance,
            witness,
            canonical_digest(body),
        )

    def canonical_dict(self) -> dict[str, Any]:
        value = self._body_dict()
        value["observation_digest"] = self.observation_digest
        return value


__all__ = [
    "NativeArtifactClass",
    "NativePropertyCapabilities",
    "NativePropertyDefinition",
    "NativePropertyImplementationIdentity",
    "NativePropertyObservation",
    "NativePropertyRequest",
    "NativePropertyResult",
    "NativePropertyWitness",
    "NativeSemanticVersionBinding",
    "canonical_digest",
    "canonical_json",
    "canonical_json_bytes",
    "require_digest",
    "thaw_json",
]
