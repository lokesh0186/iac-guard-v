"""Scanner-neutral protected-universe and property-observation boundary.

Materializers and independent parsers establish the artifact and protected target
identities before an adapter is selected.  Adapters may report native observations;
they cannot select the universe, redefine a target, or turn absence into PASS.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from .models import (
    BoundInputFile,
    DomainError,
    ExpectedResource,
    canonical_identifier,
    canonical_repo_path,
    canonical_resource_scope,
    require_exact_type,
)
from .fingerprints import canonicalize_kubernetes_identity


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@runtime_checkable
class ProtectedAdapterRequest(Protocol):
    """Minimum protected request shape consumed by generic orchestration."""

    scanner_name: str
    scanner_version: str
    executable: Path
    scan_root: Path
    workspace_root: Path
    frameworks: tuple
    files_eligible: tuple
    expected_resources: tuple
    eligible_file_evidence: tuple
    source_snapshot_sha256: str


@dataclass(frozen=True, slots=True)
class ProtectedKubernetesIdentity:
    """Independent Kubernetes identity plus one adapter-native address."""

    file_path: str
    scanner_native_resource: str
    api_version: str
    kind: str
    namespace: str
    name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        object.__setattr__(self, "scanner_native_resource", canonical_identifier(
            self.scanner_native_resource, "scanner-native Kubernetes resource"
        ))
        canonical = canonicalize_kubernetes_identity(
            self.api_version, self.kind, self.namespace, self.name
        )
        api_version, kind, namespace, name = canonical.rsplit("/", 3)
        object.__setattr__(self, "api_version", api_version)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "namespace", namespace)
        object.__setattr__(self, "name", name)

    @property
    def checkov_resource(self) -> str:
        """Frozen adapter-v4 compatibility alias."""
        return self.scanner_native_resource

    @property
    def canonical_address(self) -> str:
        return canonicalize_kubernetes_identity(
            self.api_version, self.kind, self.namespace, self.name
        )


def _digest(value: object, label: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise DomainError(f"{label} must be a lowercase SHA-256")
    return value


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


class ScannerObservationResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


class PropertyCapability(str, Enum):
    ATTRIBUTE = "ATTRIBUTE"
    CONTAINER = "CONTAINER"
    RELATIONSHIP = "RELATIONSHIP"


def legacy_report_v1_property_capability(
    scanner_name: str, native_property_id: str
) -> PropertyCapability:
    """Interpret the frozen a7 report-v1 native-ID convention.

    New scans carry an explicit capability on ``ProtectedPropertyTarget``.  The
    historical schema did not serialize one, so old Checkov evidence requires a
    versioned compatibility reader.  This function must never construct a new plan.
    """
    scanner = canonical_identifier(scanner_name, "legacy scanner name")
    property_id = canonical_identifier(native_property_id, "legacy property id")
    if scanner == "checkov" and re.fullmatch(r"CKV2_[A-Za-z0-9_]+", property_id):
        return PropertyCapability.RELATIONSHIP
    return PropertyCapability.ATTRIBUTE


@dataclass(frozen=True, slots=True)
class ScannerCapabilities:
    artifact_classes: tuple[str, ...]
    property_capabilities: tuple[PropertyCapability, ...]
    affirmative_target_pass: bool
    advisory_only: bool

    def __post_init__(self) -> None:
        if type(self.artifact_classes) is not tuple or not self.artifact_classes:
            raise DomainError("scanner artifact classes must be a nonempty exact tuple")
        classes = tuple(sorted(
            canonical_identifier(item, "scanner artifact class")
            for item in self.artifact_classes
        ))
        if len(classes) != len(set(classes)):
            raise DomainError("scanner artifact classes must be unique")
        if type(self.property_capabilities) is not tuple:
            raise DomainError("scanner property capabilities must be an exact tuple")
        if any(type(item) is not PropertyCapability for item in self.property_capabilities):
            raise DomainError(
                "scanner property capabilities must contain exact enum members"
            )
        capabilities = tuple(sorted(
            self.property_capabilities, key=lambda item: item.value
        ))
        if len(capabilities) != len(set(capabilities)):
            raise DomainError("scanner property capabilities must be unique")
        if type(self.affirmative_target_pass) is not bool or type(self.advisory_only) is not bool:
            raise DomainError("scanner capability flags must be exact booleans")
        if self.advisory_only and self.affirmative_target_pass:
            raise DomainError("advisory scanner cannot claim authoritative target PASS")
        object.__setattr__(self, "artifact_classes", classes)
        object.__setattr__(self, "property_capabilities", capabilities)

    def canonical_dict(self) -> dict:
        return {
            "artifact_classes": list(self.artifact_classes),
            "property_capabilities": [item.value for item in self.property_capabilities],
            "affirmative_target_pass": self.affirmative_target_pass,
            "advisory_only": self.advisory_only,
        }


@dataclass(frozen=True, slots=True)
class ScannerDescriptor:
    scanner_name: str
    scanner_version: str
    scanner_binary_digest: str
    scanner_configuration_digest: str
    policy_bundle_digest: str
    capabilities: ScannerCapabilities

    def __post_init__(self) -> None:
        object.__setattr__(self, "scanner_name", canonical_identifier(
            self.scanner_name, "scanner name"
        ))
        object.__setattr__(self, "scanner_version", canonical_identifier(
            self.scanner_version, "scanner version"
        ))
        for name in (
            "scanner_binary_digest", "scanner_configuration_digest",
            "policy_bundle_digest",
        ):
            _digest(getattr(self, name), name)
        require_exact_type(self.capabilities, ScannerCapabilities, "scanner capabilities")

    @property
    def identity(self) -> str:
        return _canonical_digest(self.canonical_dict())

    def canonical_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "scanner_binary_digest": self.scanner_binary_digest,
            "scanner_configuration_digest": self.scanner_configuration_digest,
            "policy_bundle_digest": self.policy_bundle_digest,
            "capabilities": self.capabilities.canonical_dict(),
        }


@dataclass(frozen=True, slots=True)
class NativePropertyIdentity:
    scanner_name: str
    policy_id: str
    scanner_version: str
    policy_bundle_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scanner_name", canonical_identifier(
            self.scanner_name, "native property scanner"
        ))
        object.__setattr__(self, "policy_id", canonical_identifier(
            self.policy_id, "native policy id"
        ))
        object.__setattr__(self, "scanner_version", canonical_identifier(
            self.scanner_version, "native property scanner version"
        ))
        _digest(self.policy_bundle_digest, "native property bundle digest")

    @property
    def opaque_id(self) -> str:
        return f"{self.scanner_name}:{self.policy_id}"

    def canonical_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "policy_id": self.policy_id,
            "scanner_version": self.scanner_version,
            "policy_bundle_digest": self.policy_bundle_digest,
        }


@dataclass(frozen=True, slots=True)
class NormalizedPropertyIdentity:
    namespace: str
    property_id: str
    mapping_version: str
    mapping_digest: str

    def __post_init__(self) -> None:
        for name in ("namespace", "property_id", "mapping_version"):
            object.__setattr__(self, name, canonical_identifier(
                getattr(self, name), f"normalized property {name}"
            ))
        _digest(self.mapping_digest, "normalized property mapping digest")

    def canonical_dict(self) -> dict:
        return {
            "namespace": self.namespace,
            "property_id": self.property_id,
            "mapping_version": self.mapping_version,
            "mapping_digest": self.mapping_digest,
        }


@dataclass(frozen=True, slots=True)
class ProtectedPropertyTarget:
    property_identity: NativePropertyIdentity
    protected_resource_identity: str
    file_path: str
    scanner_native_target_identity: str
    capability: PropertyCapability

    def __post_init__(self) -> None:
        require_exact_type(
            self.property_identity, NativePropertyIdentity, "native property identity"
        )
        object.__setattr__(self, "protected_resource_identity", canonical_resource_scope(
            self.protected_resource_identity, "protected resource identity"
        ))
        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        object.__setattr__(self, "scanner_native_target_identity", canonical_resource_scope(
            self.scanner_native_target_identity, "scanner native target identity"
        ))
        if type(self.capability) is not PropertyCapability:
            raise DomainError("protected property capability must be an exact enum member")

    @property
    def canonical_key(self) -> tuple:
        return (
            self.property_identity.scanner_name,
            self.property_identity.policy_id,
            self.property_identity.scanner_version,
            self.property_identity.policy_bundle_digest,
            self.protected_resource_identity,
            self.file_path,
            self.scanner_native_target_identity,
            self.capability.value,
        )

    def canonical_dict(self) -> dict:
        return {
            "property_identity": self.property_identity.canonical_dict(),
            "protected_resource_identity": self.protected_resource_identity,
            "file_path": self.file_path,
            "scanner_native_target_identity": self.scanner_native_target_identity,
            "capability": self.capability.value,
        }


@dataclass(frozen=True, slots=True)
class ProtectedScanArtifact:
    root: Path
    artifact_class: str
    input_files: tuple[BoundInputFile, ...]
    expected_resources: tuple[ExpectedResource, ...]
    input_manifest_digest: str
    resource_inventory_digest: str
    artifact_identity: str

    def __post_init__(self) -> None:
        if not isinstance(self.root, Path):
            raise DomainError("protected scan root must be pathlib.Path")
        object.__setattr__(self, "root", self.root.resolve(strict=True))
        object.__setattr__(self, "artifact_class", canonical_identifier(
            self.artifact_class, "protected artifact class"
        ))
        if type(self.input_files) is not tuple or any(
            type(item) is not BoundInputFile for item in self.input_files
        ):
            raise DomainError("protected input files must be exact bound records")
        if not self.input_files:
            raise DomainError("protected scanner artifact cannot be empty")
        if type(self.expected_resources) is not tuple or any(
            type(item) is not ExpectedResource for item in self.expected_resources
        ):
            raise DomainError("protected resources must be exact expected records")
        paths = [item.file_path for item in self.input_files]
        if len(paths) != len(set(paths)):
            raise DomainError("protected scanner input paths must be unique")
        resource_keys = [item.canonical_key for item in self.expected_resources]
        if len(resource_keys) != len(set(resource_keys)):
            raise DomainError("protected scanner resources must be unique")
        input_payload = [item.canonical_dict() for item in self.input_files]
        resource_payload = [item.canonical_dict() for item in self.expected_resources]
        if self.input_manifest_digest != _canonical_digest(input_payload):
            raise DomainError("protected input manifest digest is not canonical")
        if self.resource_inventory_digest != _canonical_digest(resource_payload):
            raise DomainError("protected resource inventory digest is not canonical")
        payload = {
            "artifact_class": self.artifact_class,
            "input_manifest_digest": self.input_manifest_digest,
            "resource_inventory_digest": self.resource_inventory_digest,
        }
        if self.artifact_identity != _canonical_digest(payload):
            raise DomainError("protected scanner artifact identity is not canonical")

    def canonical_dict(self) -> dict:
        return {
            "artifact_class": self.artifact_class,
            "input_files": [item.canonical_dict() for item in self.input_files],
            "expected_resources": [item.canonical_dict() for item in self.expected_resources],
            "input_manifest_digest": self.input_manifest_digest,
            "resource_inventory_digest": self.resource_inventory_digest,
            "artifact_identity": self.artifact_identity,
        }


def protect_scan_artifact(
    root: Path,
    artifact_class: str,
    input_files: tuple[BoundInputFile, ...],
    expected_resources: tuple[ExpectedResource, ...],
) -> ProtectedScanArtifact:
    """Construct one immutable artifact only after re-reading every protected byte."""
    ordered_files = tuple(sorted(input_files, key=lambda item: item.canonical_key))
    ordered_resources = tuple(sorted(
        expected_resources, key=lambda item: item.canonical_key
    ))
    _revalidate_files(root.resolve(strict=True), ordered_files)
    input_digest = _canonical_digest([item.canonical_dict() for item in ordered_files])
    resource_digest = _canonical_digest([
        item.canonical_dict() for item in ordered_resources
    ])
    canonical_class = canonical_identifier(artifact_class, "protected artifact class")
    identity = _canonical_digest({
        "artifact_class": canonical_class,
        "input_manifest_digest": input_digest,
        "resource_inventory_digest": resource_digest,
    })
    return ProtectedScanArtifact(
        root.resolve(strict=True), canonical_class, ordered_files, ordered_resources,
        input_digest, resource_digest, identity,
    )


def _revalidate_files(root: Path, files: tuple[BoundInputFile, ...]) -> None:
    for item in files:
        path = root / item.file_path
        try:
            path.relative_to(root)
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise DomainError("protected scanner input is not a regular nonsymlink file")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(descriptor)
                digest = hashlib.sha256()
                size = 0
                while True:
                    block = os.read(descriptor, 64 * 1024)
                    if not block:
                        break
                    size += len(block)
                    digest.update(block)
            finally:
                os.close(descriptor)
        except (OSError, ValueError) as exc:
            raise DomainError("protected scanner input cannot be revalidated") from exc
        if (
            size != item.size
            or digest.hexdigest() != item.sha256
            or opened.st_dev != item.device
            or opened.st_ino != item.inode
        ):
            raise DomainError("protected scanner input changed")


@dataclass(frozen=True, slots=True)
class ProtectedScanPlan:
    descriptor: ScannerDescriptor
    artifact: ProtectedScanArtifact
    targets: tuple[ProtectedPropertyTarget, ...]
    plan_identity: str

    def __post_init__(self) -> None:
        require_exact_type(self.descriptor, ScannerDescriptor, "scanner descriptor")
        require_exact_type(self.artifact, ProtectedScanArtifact, "protected scan artifact")
        if type(self.targets) is not tuple or not self.targets or any(
            type(item) is not ProtectedPropertyTarget for item in self.targets
        ):
            raise DomainError("protected scan targets must be a nonempty exact tuple")
        keys = [item.canonical_key for item in self.targets]
        if len(keys) != len(set(keys)):
            raise DomainError("protected scan targets must be unique")
        if self.artifact.artifact_class not in self.descriptor.capabilities.artifact_classes:
            raise DomainError("scanner does not support the protected artifact class")
        for item in self.targets:
            if (
                item.property_identity.scanner_name != self.descriptor.scanner_name
                or item.property_identity.scanner_version != self.descriptor.scanner_version
                or item.property_identity.policy_bundle_digest
                != self.descriptor.policy_bundle_digest
            ):
                raise DomainError("target property identity disagrees with scanner descriptor")
            if item.capability not in self.descriptor.capabilities.property_capabilities:
                raise DomainError("scanner lacks a required property capability")
            matching_resources = tuple(
                resource for resource in self.artifact.expected_resources
                if resource.file_path == item.file_path
                and resource.resource_address == item.protected_resource_identity
                and resource.scanner_native_lookup == item.scanner_native_target_identity
            )
            if len(matching_resources) != 1:
                raise DomainError(
                    "protected target must resolve exactly once in the protected resource universe"
                )
        expected = _canonical_digest({
            "descriptor_identity": self.descriptor.identity,
            "artifact_identity": self.artifact.artifact_identity,
            "targets": [item.canonical_dict() for item in self.targets],
        })
        if self.plan_identity != expected:
            raise DomainError("protected scan plan identity is not canonical")

    def canonical_dict(self) -> dict:
        return {
            "descriptor": self.descriptor.canonical_dict(),
            "artifact": self.artifact.canonical_dict(),
            "targets": [item.canonical_dict() for item in self.targets],
            "plan_identity": self.plan_identity,
        }


def build_protected_scan_plan(
    descriptor: ScannerDescriptor,
    artifact: ProtectedScanArtifact,
    targets: tuple[ProtectedPropertyTarget, ...],
) -> ProtectedScanPlan:
    ordered = tuple(sorted(targets, key=lambda item: item.canonical_key))
    identity = _canonical_digest({
        "descriptor_identity": descriptor.identity,
        "artifact_identity": artifact.artifact_identity,
        "targets": [item.canonical_dict() for item in ordered],
    })
    return ProtectedScanPlan(descriptor, artifact, ordered, identity)


@dataclass(frozen=True, slots=True)
class RawPropertyObservation:
    property_identity: NativePropertyIdentity
    protected_resource_identity: str
    file_path: str
    scanner_native_target_identity: str
    result: ScannerObservationResult
    affirmative_evidence_digest: str = ""
    relationship_evidence_digest: str = ""
    native_reason: str = ""

    def __post_init__(self) -> None:
        require_exact_type(self.property_identity, NativePropertyIdentity, "raw property")
        object.__setattr__(self, "protected_resource_identity", canonical_resource_scope(
            self.protected_resource_identity, "raw protected target"
        ))
        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        object.__setattr__(self, "scanner_native_target_identity", canonical_resource_scope(
            self.scanner_native_target_identity, "raw scanner target"
        ))
        if type(self.result) is not ScannerObservationResult:
            raise DomainError("raw observation result must be an exact enum member")
        _digest(self.affirmative_evidence_digest, "affirmative evidence", optional=True)
        _digest(self.relationship_evidence_digest, "relationship evidence", optional=True)
        if type(self.native_reason) is not str:
            raise DomainError("native scanner reason must be a string")

    @property
    def target_key(self) -> tuple:
        return (
            self.property_identity.scanner_name,
            self.property_identity.policy_id,
            self.property_identity.scanner_version,
            self.property_identity.policy_bundle_digest,
            self.protected_resource_identity,
            self.file_path,
            self.scanner_native_target_identity,
        )


@dataclass(frozen=True, slots=True)
class RawScannerExecution:
    descriptor_identity: str
    scanner_input_artifact_identity: str
    consumed_input_paths: tuple[str, ...]
    observed_resource_identities: tuple[str, ...]
    observations: tuple[RawPropertyObservation, ...]
    raw_result_digest: str
    scanner_diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _digest(self.descriptor_identity, "raw descriptor identity")
        _digest(self.scanner_input_artifact_identity, "raw input artifact identity")
        _digest(self.raw_result_digest, "raw scanner result digest")
        if type(self.consumed_input_paths) is not tuple:
            raise DomainError("consumed scanner paths must be an exact tuple")
        paths = tuple(sorted(canonical_repo_path(item) for item in self.consumed_input_paths))
        if len(paths) != len(set(paths)):
            raise DomainError("consumed scanner paths must be unique")
        object.__setattr__(self, "consumed_input_paths", paths)
        if type(self.observed_resource_identities) is not tuple:
            raise DomainError("observed resource identities must be an exact tuple")
        resources = tuple(sorted(canonical_resource_scope(
            item, "observed resource identity"
        ) for item in self.observed_resource_identities))
        if len(resources) != len(set(resources)):
            raise DomainError("observed resource identities must be unique")
        object.__setattr__(self, "observed_resource_identities", resources)
        if type(self.observations) is not tuple or any(
            type(item) is not RawPropertyObservation for item in self.observations
        ):
            raise DomainError("raw observations must be exact typed records")
        if type(self.scanner_diagnostics) is not tuple or any(
            type(item) is not str for item in self.scanner_diagnostics
        ):
            raise DomainError("scanner diagnostics must be an exact string tuple")


@dataclass(frozen=True, slots=True)
class PropertyObservation:
    target: ProtectedPropertyTarget
    result: ScannerObservationResult
    raw_result_digest: str
    normalized_evidence_digest: str
    relationship_evidence_digest: str
    scanner_diagnostics: tuple[str, ...]

    def canonical_dict(self) -> dict:
        return {
            "target": self.target.canonical_dict(),
            "result": self.result.value,
            "raw_result_digest": self.raw_result_digest,
            "normalized_evidence_digest": self.normalized_evidence_digest,
            "relationship_evidence_digest": self.relationship_evidence_digest,
            "scanner_diagnostics": list(self.scanner_diagnostics),
        }


@dataclass(frozen=True, slots=True)
class ScannerEvidence:
    descriptor: ScannerDescriptor
    scanner_input_artifact_identity: str
    observations: tuple[PropertyObservation, ...]
    raw_result_digest: str
    normalized_evidence_digest: str

    def canonical_dict(self) -> dict:
        return {
            "descriptor": self.descriptor.canonical_dict(),
            "scanner_input_artifact_identity": self.scanner_input_artifact_identity,
            "observations": [item.canonical_dict() for item in self.observations],
            "raw_result_digest": self.raw_result_digest,
            "normalized_evidence_digest": self.normalized_evidence_digest,
        }


@runtime_checkable
class ScannerAdapter(Protocol):
    @property
    def descriptor(self) -> ScannerDescriptor: ...

    def scan(self, plan: ProtectedScanPlan) -> RawScannerExecution: ...


def execute_protected_scan(
    plan: ProtectedScanPlan, adapter: ScannerAdapter
) -> ScannerEvidence:
    """Validate adapter evidence against the independently protected scan plan."""
    require_exact_type(plan, ProtectedScanPlan, "protected scan plan")
    if not isinstance(adapter, ScannerAdapter):
        raise DomainError("scanner adapter does not satisfy the neutral protocol")
    if type(adapter.descriptor) is not ScannerDescriptor:
        raise DomainError("scanner adapter descriptor must be exact")
    if adapter.descriptor != plan.descriptor:
        raise DomainError("scanner adapter descriptor disagrees with protected plan")
    _revalidate_files(plan.artifact.root, plan.artifact.input_files)
    raw = adapter.scan(plan)
    require_exact_type(raw, RawScannerExecution, "raw scanner execution")
    _revalidate_files(plan.artifact.root, plan.artifact.input_files)
    if raw.descriptor_identity != plan.descriptor.identity:
        raise DomainError("scanner execution uses another descriptor identity")
    if raw.scanner_input_artifact_identity != plan.artifact.artifact_identity:
        raise DomainError("scanner execution uses another protected artifact")
    expected_paths = tuple(item.file_path for item in plan.artifact.input_files)
    if raw.consumed_input_paths != expected_paths:
        raise DomainError("scanner did not consume the complete protected file universe")
    expected_resources = tuple(sorted(
        item.resource_address for item in plan.artifact.expected_resources
    ))
    decisive = any(
        item.result in {ScannerObservationResult.PASS, ScannerObservationResult.FAIL}
        for item in raw.observations
    )
    if raw.observed_resource_identities != expected_resources:
        if decisive:
            raise DomainError("scanner did not prove complete protected resource coverage")
        if not set(raw.observed_resource_identities) <= set(expected_resources):
            raise DomainError("scanner reported a resource outside the protected universe")
    target_map = {
        (
            item.property_identity.scanner_name,
            item.property_identity.policy_id,
            item.property_identity.scanner_version,
            item.property_identity.policy_bundle_digest,
            item.protected_resource_identity,
            item.file_path,
            item.scanner_native_target_identity,
        ): item
        for item in plan.targets
    }
    if len(raw.observations) != len(target_map):
        raise DomainError("scanner must return exactly one observation per protected target")
    normalized: list[PropertyObservation] = []
    seen: set[tuple] = set()
    for observation in raw.observations:
        target = target_map.get(observation.target_key)
        if target is None or observation.target_key in seen:
            raise DomainError("scanner observation redefines or duplicates a protected target")
        seen.add(observation.target_key)
        if observation.result in {
            ScannerObservationResult.PASS, ScannerObservationResult.FAIL,
        } and not observation.affirmative_evidence_digest:
            raise DomainError("decisive scanner observation requires affirmative evidence")
        if observation.result is ScannerObservationResult.PASS and (
            plan.descriptor.capabilities.advisory_only
            or not plan.descriptor.capabilities.affirmative_target_pass
        ):
            raise DomainError("advisory scanner cannot produce authoritative target PASS")
        if (
            target.capability is PropertyCapability.RELATIONSHIP
            and observation.result in {
                ScannerObservationResult.PASS, ScannerObservationResult.FAIL,
            }
            and not observation.relationship_evidence_digest
        ):
            raise DomainError("relationship property lacks affirmative relationship evidence")
        payload = {
            "target": target.canonical_dict(),
            "result": observation.result.value,
            "affirmative_evidence_digest": observation.affirmative_evidence_digest,
            "relationship_evidence_digest": observation.relationship_evidence_digest,
            "native_reason": observation.native_reason,
            "raw_result_digest": raw.raw_result_digest,
        }
        normalized.append(PropertyObservation(
            target,
            observation.result,
            raw.raw_result_digest,
            _canonical_digest(payload),
            observation.relationship_evidence_digest,
            tuple(raw.scanner_diagnostics),
        ))
    ordered = tuple(sorted(normalized, key=lambda item: item.target.canonical_key))
    evidence_payload = {
        "descriptor": plan.descriptor.canonical_dict(),
        "scanner_input_artifact_identity": plan.artifact.artifact_identity,
        "observations": [item.canonical_dict() for item in ordered],
        "raw_result_digest": raw.raw_result_digest,
    }
    return ScannerEvidence(
        plan.descriptor,
        plan.artifact.artifact_identity,
        ordered,
        raw.raw_result_digest,
        _canonical_digest(evidence_payload),
    )


__all__ = [
    "NativePropertyIdentity",
    "NormalizedPropertyIdentity",
    "PropertyCapability",
    "PropertyObservation",
    "ProtectedPropertyTarget",
    "ProtectedAdapterRequest",
    "ProtectedKubernetesIdentity",
    "ProtectedScanArtifact",
    "ProtectedScanPlan",
    "RawPropertyObservation",
    "RawScannerExecution",
    "ScannerAdapter",
    "ScannerCapabilities",
    "ScannerDescriptor",
    "ScannerEvidence",
    "ScannerObservationResult",
    "build_protected_scan_plan",
    "execute_protected_scan",
    "protect_scan_artifact",
]
