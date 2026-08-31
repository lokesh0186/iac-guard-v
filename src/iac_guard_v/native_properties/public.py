"""Public local request loader for native-property verification."""
from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

import jsonschema

from ..models import DomainError, canonical_repo_path
from .engine import evaluate_native_requests
from .model import NativeArtifactClass, NativePropertyRequest, canonical_json
from .report import NativePropertyReportV1
from .universe import ProtectedNativeUniverse, load_protected_native_universe


@dataclass(frozen=True, slots=True)
class PublicNativePropertyRun:
    universe: ProtectedNativeUniverse
    requests: tuple[NativePropertyRequest, ...]


def _schema() -> dict:
    return json.loads(
        files("iac_guard_v").joinpath(
            "schemas/native-property-request-v1.schema.json"
        ).read_text(encoding="utf-8")
    )


def load_native_property_config(path: Path) -> PublicNativePropertyRun:
    if not isinstance(path, Path):
        raise DomainError("native property config path must be a Path")
    if path.is_symlink():
        raise DomainError("native property config must not be a symlink")
    config_path = path.resolve(strict=True)
    if not config_path.is_file():
        raise DomainError("native property config must be a regular non-symlink file")
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DomainError("native property config is not valid UTF-8 JSON") from exc
    try:
        jsonschema.Draft202012Validator(_schema()).validate(payload)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"native property request contract violation: {exc.message}") from exc
    relative_root = canonical_repo_path(payload["root"], "native protected root")
    root_candidate = config_path.parent / relative_root
    if root_candidate.is_symlink():
        raise DomainError("native protected root must not be a symlink")
    root = root_candidate.resolve(strict=True)
    try:
        root.relative_to(config_path.parent)
    except ValueError as exc:
        raise DomainError("native protected root escapes the config directory") from exc
    artifact = NativeArtifactClass(payload["artifact_class"])
    universe = load_protected_native_universe(
        root,
        artifact,
        default_namespace=payload.get("default_namespace", "default"),
    )
    requests = tuple(
        NativePropertyRequest.build(
            request_id=item["request_id"],
            property_id=item["property_id"],
            property_version=item.get("property_version", "1"),
            artifact_class=artifact,
            subject_identity=item["subject_identity"],
            parameters=item.get("parameters", {}),
            protected_universe_identity=universe.identity,
        )
        for item in payload["requests"]
    )
    return PublicNativePropertyRun(universe, requests)


def verify_native_properties(run: PublicNativePropertyRun) -> NativePropertyReportV1:
    if type(run) is not PublicNativePropertyRun:
        raise DomainError("native verification requires an exact public run")
    observations = evaluate_native_requests(run.universe, run.requests)
    return NativePropertyReportV1.build(run.universe, observations)


__all__ = [
    "PublicNativePropertyRun",
    "load_native_property_config",
    "verify_native_properties",
]
