"""Closed v1alpha1/stable-v1 schema compatibility bridge."""
from __future__ import annotations

import copy
import hashlib
import json
from importlib.resources import files
from typing import Any

from ..models import DomainError


CONTRACT_API_V1ALPHA1 = "iac-guard-v.io/v1alpha1"
CONTRACT_API_V1 = "iac-guard-v.io/v1"
CONTRACT_SCHEMA_V1ALPHA1 = "infrastructure-contract-v1alpha1"
CONTRACT_SCHEMA_V1 = "infrastructure-contract-v1"
CONTRACT_REPORT_V1ALPHA1 = "infrastructure-contract-report-v1alpha1"
CONTRACT_REPORT_V1 = "infrastructure-contract-report-v1"

_API_TO_SCHEMA = {
    CONTRACT_API_V1ALPHA1: CONTRACT_SCHEMA_V1ALPHA1,
    CONTRACT_API_V1: CONTRACT_SCHEMA_V1,
}
_SCHEMA_TO_API = {value: key for key, value in _API_TO_SCHEMA.items()}
_SCHEMA_TO_REPORT = {
    CONTRACT_SCHEMA_V1ALPHA1: CONTRACT_REPORT_V1ALPHA1,
    CONTRACT_SCHEMA_V1: CONTRACT_REPORT_V1,
}
_REPORT_TO_SCHEMA = {value: key for key, value in _SCHEMA_TO_REPORT.items()}


def _load(name: str) -> dict[str, Any]:
    return json.loads(files("iac_guard_v").joinpath("schemas", name).read_text(encoding="utf-8"))


def contract_schema_for_api_version(api_version: str) -> dict[str, Any]:
    if api_version not in _API_TO_SCHEMA:
        raise DomainError(f"unsupported infrastructure contract apiVersion: {api_version!r}")
    schema = _load("infrastructure-contract-v1alpha1.schema.json")
    if api_version == CONTRACT_API_V1:
        schema = copy.deepcopy(schema)
        schema["$id"] = "https://iac-guard-v.io/schemas/infrastructure-contract-v1.schema.json"
        schema["properties"]["apiVersion"]["const"] = CONTRACT_API_V1
    return schema


def contract_report_schema(report_version: str) -> dict[str, Any]:
    if report_version not in _REPORT_TO_SCHEMA:
        raise DomainError(f"unsupported infrastructure contract report version: {report_version!r}")
    schema = _load("infrastructure-contract-report-v1alpha1.schema.json")
    if report_version == CONTRACT_REPORT_V1:
        schema = copy.deepcopy(schema)
        schema["$id"] = "https://iac-guard-v.io/schemas/infrastructure-contract-report-v1.schema.json"
        schema["properties"]["schema_version"]["const"] = CONTRACT_REPORT_V1
    return schema


def schema_version_for_api_version(api_version: str) -> str:
    try:
        return _API_TO_SCHEMA[api_version]
    except KeyError as exc:
        raise DomainError(f"unsupported infrastructure contract apiVersion: {api_version!r}") from exc


def api_version_for_schema_version(schema_version: str) -> str:
    try:
        return _SCHEMA_TO_API[schema_version]
    except KeyError as exc:
        raise DomainError(f"unsupported infrastructure contract schema version: {schema_version!r}") from exc


def report_version_for_schema_version(schema_version: str) -> str:
    try:
        return _SCHEMA_TO_REPORT[schema_version]
    except KeyError as exc:
        raise DomainError(f"unsupported infrastructure contract schema version: {schema_version!r}") from exc


def schema_version_for_report_version(report_version: str) -> str:
    try:
        return _REPORT_TO_SCHEMA[report_version]
    except KeyError as exc:
        raise DomainError(f"unsupported infrastructure contract report version: {report_version!r}") from exc


def contract_schema_identity_for_version(schema_version: str) -> str:
    api_version = api_version_for_schema_version(schema_version)
    encoded = json.dumps(
        contract_schema_for_api_version(api_version),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if schema_version == CONTRACT_SCHEMA_V1ALPHA1:
        # Preserve the exact Beta1 file-byte identity for existing report consumers.
        encoded = files("iac_guard_v").joinpath(
            "schemas/infrastructure-contract-v1alpha1.schema.json"
        ).read_bytes()
    return hashlib.sha256(encoded).hexdigest()


def is_contract_report_version(value: object) -> bool:
    return type(value) is str and value in _REPORT_TO_SCHEMA


def convert_contract_api_version(payload: dict[str, Any], target_api_version: str) -> dict[str, Any]:
    """Explicitly convert only the schema discriminator after validating both ends."""
    import jsonschema

    if type(payload) is not dict:
        raise DomainError("infrastructure contract conversion input must be an object")
    source_api_version = payload.get("apiVersion")
    source_schema = contract_schema_for_api_version(source_api_version)
    try:
        jsonschema.Draft202012Validator(source_schema).validate(payload)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"source infrastructure contract is invalid: {exc.message}") from exc
    converted = copy.deepcopy(payload)
    converted["apiVersion"] = target_api_version
    target_schema = contract_schema_for_api_version(target_api_version)
    try:
        jsonschema.Draft202012Validator(target_schema).validate(converted)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"converted infrastructure contract is invalid: {exc.message}") from exc
    return converted


__all__ = [
    "CONTRACT_API_V1", "CONTRACT_API_V1ALPHA1", "CONTRACT_REPORT_V1",
    "CONTRACT_REPORT_V1ALPHA1", "CONTRACT_SCHEMA_V1", "CONTRACT_SCHEMA_V1ALPHA1",
    "api_version_for_schema_version", "contract_report_schema",
    "contract_schema_for_api_version", "contract_schema_identity_for_version",
    "convert_contract_api_version", "is_contract_report_version",
    "report_version_for_schema_version", "schema_version_for_api_version",
    "schema_version_for_report_version",
]
