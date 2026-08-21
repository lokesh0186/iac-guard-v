"""Strict public config-v1 input; it carries requests, never trusted evidence."""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .enums import ArtifactKind
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

    def __post_init__(self) -> None:
        if type(self.artifact_kind) is not ArtifactKind:
            raise DomainError("public target artifact_kind must be an ArtifactKind")
        if type(self.baseline_occurrences) is not int or self.baseline_occurrences <= 0:
            raise DomainError("baseline_occurrences must be a positive exact integer")
        # Target performs the full canonical path/scope validation without retaining it.
        Target(
            TargetIdentity("checkov", self.rule_id, self.resource_address),
            self.baseline_occurrences,
            self.file_path,
            self.artifact_kind,
            self.scanner_native_lookup,
        )

    def to_domain(self) -> Target:
        return Target(
            TargetIdentity("checkov", self.rule_id, self.resource_address),
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


__all__ = [
    "ExecutionIsolation", "PublicTarget", "PublicVerificationRequest",
    "load_public_config",
]
