"""Strict public config-v1 input; it carries requests, never trusted evidence."""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .enums import ArtifactKind
from .helm import HelmRenderSpec, HelmUniverseChart
from .kustomize import KustomizeBuildSpec
from .models import DomainError, Target, TargetIdentity, canonical_identifier


class ExecutionIsolation(Enum):
    HARDENED_CONTAINER = "hardened-container"
    REDUCED_ISOLATION = "reduced-isolation"


@dataclass(frozen=True, slots=True)
class PublicTarget:
    rule_id: str
    resource_address: str
    file_path: str = ""
    artifact_kind: ArtifactKind = ArtifactKind.UNKNOWN
    scanner_native_lookup: str = ""
    baseline_occurrences: int = 1
    scanner_name: str = "checkov"

    def __post_init__(self) -> None:
        if type(self.artifact_kind) is not ArtifactKind:
            raise DomainError("public target artifact_kind must be an ArtifactKind")
        if type(self.baseline_occurrences) is not int or self.baseline_occurrences <= 0:
            raise DomainError("baseline_occurrences must be a positive exact integer")
        # Target performs the full canonical path/scope validation without retaining it.
        Target(
            TargetIdentity(self.scanner_name, self.rule_id, self.resource_address),
            self.baseline_occurrences,
            self.file_path,
            self.artifact_kind,
            self.scanner_native_lookup,
        )

    def to_domain(self) -> Target:
        return Target(
            TargetIdentity(self.scanner_name, self.rule_id, self.resource_address),
            self.baseline_occurrences,
            self.file_path,
            self.artifact_kind,
            self.scanner_native_lookup,
        )


@dataclass(frozen=True, slots=True)
class PublicVerificationRequest:
    baseline_root: Path
    candidate_root: Path
    targets: tuple
    execution_isolation: ExecutionIsolation = ExecutionIsolation.HARDENED_CONTAINER
    checkov_executable: Path | None = None
    frameworks: tuple = ("kubernetes", "terraform")

    def __post_init__(self) -> None:
        if type(self.execution_isolation) is not ExecutionIsolation:
            raise DomainError("execution_isolation must be a closed enum value")
        for field_name in ("baseline_root", "candidate_root"):
            value = getattr(self, field_name)
            if not isinstance(value, Path):
                raise DomainError(f"{field_name} must be pathlib.Path")
            try:
                resolved = value.resolve(strict=True)
            except OSError as exc:
                raise DomainError(f"{field_name} does not exist") from exc
            if not resolved.is_dir():
                raise DomainError(f"{field_name} must be a directory")
            object.__setattr__(self, field_name, resolved)
        if self.baseline_root == self.candidate_root:
            raise DomainError("baseline and candidate roots must be distinct")
        if (
            self.baseline_root in self.candidate_root.parents
            or self.candidate_root in self.baseline_root.parents
        ):
            raise DomainError("baseline and candidate roots must not contain one another")
        if type(self.targets) is not tuple or not self.targets or any(
            type(item) is not PublicTarget for item in self.targets
        ):
            raise DomainError("targets must be a nonempty tuple of PublicTarget")
        if type(self.frameworks) is not tuple or not self.frameworks:
            raise DomainError("frameworks must be a nonempty exact tuple")
        frameworks = tuple(sorted(canonical_identifier(item, "framework") for item in self.frameworks))
        if len(frameworks) != len(set(frameworks)) or set(frameworks) - {"terraform", "kubernetes"}:
            raise DomainError("frameworks must be unique supported Checkov frameworks")
        object.__setattr__(self, "frameworks", frameworks)
        if self.execution_isolation is ExecutionIsolation.REDUCED_ISOLATION:
            if not isinstance(self.checkov_executable, Path):
                raise DomainError("reduced-isolation requires an explicit Checkov executable")
        elif self.checkov_executable is not None:
            raise DomainError("hardened-container input cannot provide a native executable")


@dataclass(frozen=True, slots=True)
class PublicHelmVerificationRequest:
    baseline: HelmRenderSpec
    candidate: HelmRenderSpec
    selectors: tuple[tuple[str, str, str], ...]
    all_baseline_findings: bool
    execution_isolation: ExecutionIsolation
    checkov_executable: Path

    def __post_init__(self) -> None:
        if type(self.baseline) is not HelmRenderSpec or type(self.candidate) is not HelmRenderSpec:
            raise DomainError("Helm verification requires exact render specifications")
        if type(self.selectors) is not tuple or any(
            type(item) is not tuple
            or len(item) != 3
            or any(type(value) is not str for value in item)
            for item in self.selectors
        ):
            raise DomainError("Helm selectors must be exact rule/resource/file tuples")
        if type(self.all_baseline_findings) is not bool:
            raise DomainError("Helm all-baseline-findings must be a Boolean")
        if self.all_baseline_findings == bool(self.selectors):
            raise DomainError("Helm verification requires explicit targets or all findings")
        if self.execution_isolation is not ExecutionIsolation.REDUCED_ISOLATION:
            raise DomainError("Helm alpha supports only explicit local-trusted execution")
        if not isinstance(self.checkov_executable, Path):
            raise DomainError("Helm verification requires an explicit Checkov executable")
        try:
            executable = self.checkov_executable.resolve(strict=True)
        except OSError as exc:
            raise DomainError("Helm Checkov executable is unavailable") from exc
        object.__setattr__(self, "checkov_executable", executable)


@dataclass(frozen=True, slots=True)
class PublicAcceptanceProperty:
    rule_id: str
    resource_address: str
    file_path: str = ""
    artifact_kind: ArtifactKind = ArtifactKind.UNKNOWN
    scanner_name: str = "checkov"

    def __post_init__(self) -> None:
        if type(self.artifact_kind) is not ArtifactKind:
            raise DomainError("acceptance property artifact_kind must be an ArtifactKind")
        Target(
            TargetIdentity(self.scanner_name, self.rule_id, self.resource_address),
            1,
            self.file_path,
            self.artifact_kind,
            "",
        )


@dataclass(frozen=True, slots=True)
class PublicCandidateAcceptanceRequest:
    candidate_root: Path
    properties: tuple[PublicAcceptanceProperty, ...]
    execution_isolation: ExecutionIsolation = ExecutionIsolation.HARDENED_CONTAINER
    checkov_executable: Path | None = None
    frameworks: tuple[str, ...] = ("kubernetes", "terraform")

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_root, Path):
            raise DomainError("candidate_root must be pathlib.Path")
        try:
            candidate = self.candidate_root.resolve(strict=True)
        except OSError as exc:
            raise DomainError("candidate_root does not exist") from exc
        if not candidate.is_dir():
            raise DomainError("candidate_root must be a directory")
        object.__setattr__(self, "candidate_root", candidate)
        if (
            type(self.properties) is not tuple
            or not self.properties
            or any(type(item) is not PublicAcceptanceProperty for item in self.properties)
        ):
            raise DomainError("properties must be a nonempty exact tuple")
        identities = [
            (item.rule_id, item.resource_address, item.file_path, item.artifact_kind.value)
            for item in self.properties
        ]
        if len(identities) != len(set(identities)):
            raise DomainError("candidate acceptance properties must be unique")
        if type(self.frameworks) is not tuple or not self.frameworks:
            raise DomainError("frameworks must be a nonempty exact tuple")
        frameworks = tuple(
            sorted(canonical_identifier(item, "framework") for item in self.frameworks)
        )
        if len(frameworks) != len(set(frameworks)) or set(frameworks) - {
            "terraform", "kubernetes"
        }:
            raise DomainError("frameworks must be unique supported Checkov frameworks")
        object.__setattr__(self, "frameworks", frameworks)
        if type(self.execution_isolation) is not ExecutionIsolation:
            raise DomainError("execution_isolation must be a closed enum value")
        if self.execution_isolation is ExecutionIsolation.REDUCED_ISOLATION:
            if not isinstance(self.checkov_executable, Path):
                raise DomainError("reduced-isolation requires an explicit Checkov executable")
            try:
                executable = self.checkov_executable.resolve(strict=True)
            except OSError as exc:
                raise DomainError("Checkov executable is unavailable") from exc
            object.__setattr__(self, "checkov_executable", executable)
        elif self.checkov_executable is not None:
            raise DomainError("hardened-container input cannot provide a native executable")


@dataclass(frozen=True, slots=True)
class PublicHelmAcceptanceRequest:
    charts: tuple[HelmUniverseChart, ...]
    properties: tuple[PublicAcceptanceProperty, ...]
    execution_isolation: ExecutionIsolation
    checkov_executable: Path

    def __post_init__(self) -> None:
        if (
            type(self.charts) is not tuple
            or not self.charts
            or any(type(item) is not HelmUniverseChart for item in self.charts)
        ):
            raise DomainError("Helm acceptance requires exact universe charts")
        if (
            type(self.properties) is not tuple
            or not self.properties
            or any(type(item) is not PublicAcceptanceProperty for item in self.properties)
        ):
            raise DomainError("Helm acceptance requires exact properties")
        chart_keys = [item.universe_key for item in self.charts]
        if len(chart_keys) != len(set(chart_keys)):
            raise DomainError("Helm acceptance chart keys must be unique")
        property_keys = [
            (item.rule_id, item.resource_address, item.file_path, item.artifact_kind.value)
            for item in self.properties
        ]
        if len(property_keys) != len(set(property_keys)):
            raise DomainError("Helm acceptance properties must be unique")
        if self.execution_isolation is not ExecutionIsolation.REDUCED_ISOLATION:
            raise DomainError("Helm alpha supports only explicit local-trusted execution")
        if not isinstance(self.checkov_executable, Path):
            raise DomainError("Helm acceptance requires an explicit Checkov executable")
        try:
            executable = self.checkov_executable.resolve(strict=True)
        except OSError as exc:
            raise DomainError("Helm Checkov executable is unavailable") from exc
        object.__setattr__(self, "checkov_executable", executable)


@dataclass(frozen=True, slots=True)
class PublicKustomizeAcceptanceRequest:
    build: KustomizeBuildSpec
    properties: tuple[PublicAcceptanceProperty, ...]
    execution_isolation: ExecutionIsolation
    checkov_executable: Path

    def __post_init__(self) -> None:
        if type(self.build) is not KustomizeBuildSpec:
            raise DomainError("Kustomize acceptance requires an exact build specification")
        if type(self.properties) is not tuple or not self.properties or any(
            type(item) is not PublicAcceptanceProperty for item in self.properties
        ):
            raise DomainError("Kustomize properties must be a nonempty exact tuple")
        if self.execution_isolation is not ExecutionIsolation.REDUCED_ISOLATION:
            raise DomainError("Kustomize a8 supports explicit local-trusted scanning only")
        if not isinstance(self.checkov_executable, Path):
            raise DomainError("Kustomize acceptance requires an explicit Checkov executable")
        try:
            executable = self.checkov_executable.resolve(strict=True)
        except OSError as exc:
            raise DomainError("Kustomize Checkov executable is unavailable") from exc
        object.__setattr__(self, "checkov_executable", executable)


_CONFIG_FIELDS = frozenset({
    "schema_version", "execution_mode", "baseline", "candidate", "targets",
    "checkov_executable", "frameworks",
})
_TARGET_FIELDS = frozenset({
    "rule_id", "resource_address", "file_path", "artifact_kind",
    "scanner_native_lookup", "baseline_occurrences",
})


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DomainError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _read_config(path: Path) -> dict:
    if not isinstance(path, Path):
        raise DomainError("config path must be pathlib.Path")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DomainError("config file cannot be inspected") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DomainError("config file must be a no-follow regular file")
    if metadata.st_size > 1024 * 1024:
        raise DomainError("config file exceeds the 1 MiB limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            raw = os.read(descriptor, 1024 * 1024 + 1)
        finally:
            os.close(descriptor)
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DomainError("config file is not strict UTF-8 JSON") from exc
    if type(payload) is not dict:
        raise DomainError("config-v1 top level must be an object")
    return payload


def load_public_config(path: Path) -> PublicVerificationRequest:
    payload = _read_config(path)
    unknown = set(payload) - _CONFIG_FIELDS
    if unknown:
        raise DomainError(f"config-v1 contains unknown fields: {sorted(unknown)}")
    if payload.get("schema_version") != "config-v1":
        raise DomainError("config schema_version must be config-v1")
    for name in ("baseline", "candidate", "targets"):
        if name not in payload:
            raise DomainError(f"config-v1 requires {name}")
    for name in ("baseline", "candidate"):
        if type(payload[name]) is not str or not payload[name].strip():
            raise DomainError(f"config-v1 {name} must be a nonblank string")
    raw_targets = payload["targets"]
    if type(raw_targets) is not list or not raw_targets:
        raise DomainError("targets must be a nonempty JSON array")
    targets = []
    for value in raw_targets:
        if type(value) is not dict or set(value) - _TARGET_FIELDS:
            raise DomainError("target contains unknown fields or is not an object")
        if "rule_id" not in value or "resource_address" not in value:
            raise DomainError("target requires rule_id and resource_address")
        for name in ("rule_id", "resource_address", "file_path", "scanner_native_lookup"):
            if name in value and type(value[name]) is not str:
                raise DomainError(f"target {name} must be a string")
        try:
            artifact = ArtifactKind(value.get("artifact_kind", "unknown"))
        except (TypeError, ValueError) as exc:
            raise DomainError("target artifact_kind is unsupported") from exc
        targets.append(PublicTarget(
            value["rule_id"], value["resource_address"], value.get("file_path", ""),
            artifact, value.get("scanner_native_lookup", ""),
            value.get("baseline_occurrences", 1),
        ))
    try:
        isolation = ExecutionIsolation(payload.get("execution_mode", "hardened-container"))
    except (TypeError, ValueError) as exc:
        raise DomainError("execution_mode is unsupported") from exc
    executable = payload.get("checkov_executable")
    if executable is not None and (type(executable) is not str or not executable.strip()):
        raise DomainError("checkov_executable must be a nonblank string")
    frameworks = payload.get("frameworks", ["kubernetes", "terraform"])
    if type(frameworks) is not list or any(type(item) is not str for item in frameworks):
        raise DomainError("frameworks must be a JSON array of strings")
    return PublicVerificationRequest(
        Path(payload["baseline"]), Path(payload["candidate"]), tuple(targets),
        isolation, None if executable is None else Path(executable), tuple(frameworks),
    )


_HELM_ACCEPTANCE_FIELDS = frozenset({
    "schema_version", "checkov_executable", "charts", "properties",
})
_HELM_CHART_FIELDS = frozenset({
    "universe_key", "chart_root", "helm_executable", "release_name", "namespace",
    "kube_version", "values_files", "set", "set_string", "api_versions",
    "include_crds", "include_tests",
    "protected_repository_root",
})
_ACCEPTANCE_PROPERTY_FIELDS = frozenset({
    "rule_id", "resource_address", "file_path", "artifact_kind",
})


def _acceptance_property(value: object) -> PublicAcceptanceProperty:
    if type(value) is not dict or set(value) - _ACCEPTANCE_PROPERTY_FIELDS:
        raise DomainError("acceptance property contains unknown fields")
    if "rule_id" not in value or "resource_address" not in value:
        raise DomainError("acceptance property requires rule_id and resource_address")
    for name in ("rule_id", "resource_address", "file_path", "artifact_kind"):
        if name in value and type(value[name]) is not str:
            raise DomainError(f"acceptance property {name} must be a string")
    try:
        kind = ArtifactKind(value.get("artifact_kind", "unknown"))
    except ValueError as exc:
        raise DomainError("acceptance property artifact_kind is unsupported") from exc
    return PublicAcceptanceProperty(
        value["rule_id"], value["resource_address"], value.get("file_path", ""), kind
    )


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise DomainError(f"{label} must be a JSON string array")
    return tuple(value)


def _overrides(value: object, label: str) -> tuple[tuple[str, str], ...]:
    if type(value) is not list:
        raise DomainError(f"{label} must be a JSON array")
    result = []
    for item in value:
        if type(item) is not dict or set(item) != {"key", "value"}:
            raise DomainError(f"{label} entries require only key and value")
        if type(item["key"]) is not str or type(item["value"]) is not str:
            raise DomainError(f"{label} key and value must be strings")
        result.append((item["key"], item["value"]))
    return tuple(result)


def load_public_helm_acceptance_config(path: Path) -> PublicHelmAcceptanceRequest:
    """Load one closed local Helm universe request from strict JSON."""
    payload = _read_config(path)
    if set(payload) - _HELM_ACCEPTANCE_FIELDS:
        raise DomainError("helm-acceptance-v1 contains unknown fields")
    if payload.get("schema_version") != "helm-acceptance-v1":
        raise DomainError("Helm acceptance schema_version must be helm-acceptance-v1")
    if type(payload.get("checkov_executable")) is not str:
        raise DomainError("Helm acceptance requires checkov_executable")
    raw_charts = payload.get("charts")
    if type(raw_charts) is not list or not raw_charts:
        raise DomainError("Helm acceptance charts must be a nonempty array")
    charts = []
    for value in raw_charts:
        if type(value) is not dict or set(value) - _HELM_CHART_FIELDS:
            raise DomainError("Helm acceptance chart contains unknown fields")
        required = {
            "universe_key", "chart_root", "helm_executable", "release_name",
            "namespace", "kube_version",
        }
        if not required <= set(value):
            raise DomainError("Helm acceptance chart is missing required fields")
        for name in required:
            if type(value[name]) is not str or not value[name]:
                raise DomainError(f"Helm acceptance chart {name} must be nonblank")
        if "protected_repository_root" in value and (
            type(value["protected_repository_root"]) is not str
            or not value["protected_repository_root"]
        ):
            raise DomainError(
                "Helm acceptance chart protected_repository_root must be nonblank"
            )
        for name in ("include_crds", "include_tests"):
            if name in value and type(value[name]) is not bool:
                raise DomainError(f"Helm acceptance chart {name} must be Boolean")
        charts.append(HelmUniverseChart(
            value["universe_key"],
            HelmRenderSpec(
                Path(value["chart_root"]),
                Path(value["helm_executable"]),
                value["release_name"],
                value["namespace"],
                value["kube_version"],
                _string_list(value.get("values_files", []), "values_files"),
                _overrides(value.get("set", []), "set"),
                _overrides(value.get("set_string", []), "set_string"),
                _string_list(value.get("api_versions", []), "api_versions"),
                value.get("include_crds", False),
                value.get("include_tests", False),
                None if "protected_repository_root" not in value
                else Path(value["protected_repository_root"]),
            ),
        ))
    raw_properties = payload.get("properties")
    if type(raw_properties) is not list or not raw_properties:
        raise DomainError("Helm acceptance properties must be a nonempty array")
    return PublicHelmAcceptanceRequest(
        tuple(charts),
        tuple(_acceptance_property(item) for item in raw_properties),
        ExecutionIsolation.REDUCED_ISOLATION,
        Path(payload["checkov_executable"]),
    )


_KUSTOMIZE_ACCEPTANCE_FIELDS = frozenset({
    "schema_version", "repository_root", "build_root", "kustomize_executable",
    "checkov_executable", "properties",
})


def load_public_kustomize_acceptance_config(
    path: Path,
) -> PublicKustomizeAcceptanceRequest:
    """Load the closed local-source Kustomize a8 acceptance request."""
    payload = _read_config(path)
    if set(payload) != _KUSTOMIZE_ACCEPTANCE_FIELDS:
        raise DomainError(
            "kustomize-acceptance-v1 requires exactly its closed field set"
        )
    if payload["schema_version"] != "kustomize-acceptance-v1":
        raise DomainError(
            "Kustomize acceptance schema_version must be kustomize-acceptance-v1"
        )
    for name in (
        "repository_root", "build_root", "kustomize_executable", "checkov_executable"
    ):
        if type(payload[name]) is not str or not payload[name]:
            raise DomainError(f"Kustomize acceptance {name} must be nonblank")
    raw_properties = payload["properties"]
    if type(raw_properties) is not list or not raw_properties:
        raise DomainError("Kustomize acceptance properties must be a nonempty array")
    return PublicKustomizeAcceptanceRequest(
        KustomizeBuildSpec(
            Path(payload["repository_root"]),
            Path(payload["build_root"]),
            Path(payload["kustomize_executable"]),
        ),
        tuple(_acceptance_property(item) for item in raw_properties),
        ExecutionIsolation.REDUCED_ISOLATION,
        Path(payload["checkov_executable"]),
    )


__all__ = [
    "ExecutionIsolation", "PublicAcceptanceProperty",
    "PublicCandidateAcceptanceRequest", "PublicHelmAcceptanceRequest",
    "PublicKustomizeAcceptanceRequest",
    "PublicHelmVerificationRequest", "PublicTarget", "PublicVerificationRequest",
    "load_public_config", "load_public_helm_acceptance_config",
    "load_public_kustomize_acceptance_config",
]
