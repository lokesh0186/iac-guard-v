"""Canonical native-property-report-v1 and semantic validation boundary."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from importlib.resources import files

import jsonschema

from ..models import DomainError, canonical_identifier, canonical_resource_scope
from .evidence import validate_native_observation, validate_native_witness_payload
from .model import (
    NativePropertyObservation, NativePropertyResult, canonical_digest, thaw_json,
)
from .registry import NATIVE_PROPERTY_REGISTRY, native_registry_identity
from .universe import ProtectedNativeUniverse


def _schema() -> dict:
    return json.loads(
        files("iac_guard_v").joinpath(
            "schemas/native-property-report-v1.schema.json"
        ).read_text(encoding="utf-8")
    )


@dataclass(frozen=True, slots=True)
class NativePropertyReportV1:
    protected_universe_identity: str
    artifact_class: str
    input_manifest_digest: str
    resource_inventory_digest: str
    registry_identity: str
    observations: tuple[NativePropertyObservation, ...]
    report_digest: str

    @classmethod
    def build(
        cls,
        universe: ProtectedNativeUniverse,
        observations: tuple[NativePropertyObservation, ...],
    ) -> "NativePropertyReportV1":
        if type(universe) is not ProtectedNativeUniverse:
            raise DomainError("native report requires an exact protected universe")
        if type(observations) is not tuple or any(
            type(item) is not NativePropertyObservation for item in observations
        ):
            raise DomainError("native report observations must be an exact tuple")
        if not observations:
            raise DomainError("native report requires at least one property observation")
        for observation in observations:
            if observation.request.protected_universe_identity != universe.identity:
                raise DomainError("native report observation belongs to another universe")
            validate_native_observation(observation)
        request_ids = [item.request.request_id for item in observations]
        if len(request_ids) != len(set(request_ids)):
            raise DomainError("native report request IDs must be unique")
        registry = native_registry_identity()
        body = {
            "schema_version": "native-property-report-v1",
            "product_semantics": "scanner-independent protected-manifest semantics",
            "protected_universe": {
                "identity": universe.identity,
                "artifact_class": universe.artifact_class.value,
                "input_manifest_digest": universe.input_manifest_digest,
                "resource_inventory_digest": universe.resource_inventory_digest,
            },
            "registry_identity": registry,
            "observations": [item.canonical_dict() for item in observations],
            "summary": _summary(observations),
        }
        return cls(
            universe.identity,
            universe.artifact_class.value,
            universe.input_manifest_digest,
            universe.resource_inventory_digest,
            registry,
            observations,
            canonical_digest(body),
        )

    @property
    def exit_code(self) -> int:
        results = {item.result for item in self.observations}
        if NativePropertyResult.ERROR in results:
            return 4
        if NativePropertyResult.VIOLATED in results:
            return 1
        if results.intersection({
            NativePropertyResult.NOT_EVALUATED, NativePropertyResult.UNSUPPORTED
        }):
            return 3
        return 0

    def canonical_dict(self) -> dict:
        return {
            "schema_version": "native-property-report-v1",
            "product_semantics": "scanner-independent protected-manifest semantics",
            "protected_universe": {
                "identity": self.protected_universe_identity,
                "artifact_class": self.artifact_class,
                "input_manifest_digest": self.input_manifest_digest,
                "resource_inventory_digest": self.resource_inventory_digest,
            },
            "registry_identity": self.registry_identity,
            "observations": [item.canonical_dict() for item in self.observations],
            "summary": _summary(self.observations),
            "exit_code": self.exit_code,
            "report_digest": self.report_digest,
        }

    def canonical_json(self) -> str:
        payload = self.canonical_dict()
        validate_native_report_payload(payload)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _summary(observations: tuple[NativePropertyObservation, ...]) -> dict[str, int]:
    counts = Counter(item.result.value for item in observations)
    return {
        result.value: counts[result.value]
        for result in NativePropertyResult
    } | {"TOTAL": len(observations)}


def validate_native_report_payload(payload: dict) -> None:
    try:
        jsonschema.Draft202012Validator(
            _schema(), format_checker=jsonschema.FormatChecker()
        ).validate(payload)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"native-property-report-v1 contract violation: {exc.message}") from exc
    body = dict(payload)
    report_digest = body.pop("report_digest")
    exit_code = body.pop("exit_code")
    if canonical_digest(body) != report_digest:
        raise DomainError("native-property-report-v1 digest is not canonical")
    if payload["registry_identity"] != native_registry_identity():
        raise DomainError("native-property-report-v1 registry identity is stale or forged")
    universe_identity = payload["protected_universe"]["identity"]
    request_ids = []
    for observation in payload["observations"]:
        request = observation["request"]
        definition = observation["definition"]
        witness = observation["witness"]
        property_id = request.get("property_id")
        packaged = NATIVE_PROPERTY_REGISTRY.get(property_id)
        if packaged is None or definition != packaged.canonical_dict():
            raise DomainError("native-property-report-v1 definition is not the packaged definition")
        if set(request) != {
            "request_id", "property_id", "property_version", "artifact_class",
            "subject_identity", "parameters", "parameters_digest",
            "protected_universe_identity",
        }:
            raise DomainError("native-property-report-v1 request shape is not closed")
        request_ids.append(canonical_identifier(request["request_id"], "native request ID"))
        canonical_resource_scope(request["subject_identity"], "native subject identity")
        if (
            request.get("property_version") != packaged.property_version
            or request.get("artifact_class") != packaged.artifact_class.value
            or request.get("protected_universe_identity") != universe_identity
        ):
            raise DomainError("native-property-report-v1 request binding is contradictory")
        if canonical_digest(request.get("parameters")) != request.get("parameters_digest"):
            raise DomainError("native-property-report-v1 parameter digest is not canonical")
        try:
            jsonschema.Draft202012Validator(
                thaw_json(packaged.parameter_schema)
            ).validate(request["parameters"])
        except jsonschema.ValidationError as exc:
            raise DomainError("native-property-report-v1 parameters violate the packaged definition") from exc
        canonical_identifier(observation["reason_code"], "native reason code")
        if witness.get("witness_type") != packaged.witness_type:
            raise DomainError("native-property-report-v1 witness type disagrees with the definition")
        expected_witness = canonical_digest({
            "witness_type": witness.get("witness_type"),
            "contents": witness.get("contents"),
        })
        if expected_witness != witness.get("witness_digest"):
            raise DomainError("native-property-report-v1 witness digest is not canonical")
        observation_body = dict(observation)
        observation_digest = observation_body.pop("observation_digest")
        if canonical_digest(observation_body) != observation_digest:
            raise DomainError("native-property-report-v1 observation digest is not canonical")
        try:
            result = NativePropertyResult(observation["result"])
        except ValueError as exc:
            raise DomainError("native-property-report-v1 result is invalid") from exc
        validate_native_witness_payload(
            witness_type=witness["witness_type"],
            result=result,
            contents=witness["contents"],
        )
    if len(request_ids) != len(set(request_ids)):
        raise DomainError("native-property-report-v1 request IDs must be unique")
    results = {item["result"] for item in payload["observations"]}
    expected_exit = (
        4 if "ERROR" in results else 1 if "VIOLATED" in results
        else 3 if results.intersection({"NOT_EVALUATED", "UNSUPPORTED"}) else 0
    )
    if exit_code != expected_exit:
        raise DomainError("native-property-report-v1 exit code disagrees with observations")
    expected_summary = _summary(tuple_payload_results(payload["observations"]))
    if payload["summary"] != expected_summary:
        raise DomainError("native-property-report-v1 summary disagrees with observations")


@dataclass(frozen=True, slots=True)
class _PayloadResult:
    result: NativePropertyResult


def tuple_payload_results(observations: list[dict]) -> tuple[_PayloadResult, ...]:
    return tuple(_PayloadResult(NativePropertyResult(item["result"])) for item in observations)


def render_native_console(report: NativePropertyReportV1) -> str:
    lines = [
        "IaC-Guard-V native property report",
        f"artifact: {report.artifact_class}",
        f"universe: {report.protected_universe_identity}",
    ]
    for observation in report.observations:
        lines.append(
            f"{observation.request.request_id}: {observation.definition.property_id} "
            f"{observation.result.value} ({observation.reason_code})"
        )
    summary = _summary(report.observations)
    lines.append(
        "summary: " + ", ".join(
            f"{key}={summary[key]}" for key in (
                "SATISFIED", "VIOLATED", "NOT_EVALUATED", "UNSUPPORTED", "ERROR"
            )
        )
    )
    lines.append("scope: protected manifest semantics only; no live-system or project-defect claim")
    return "\n".join(lines) + "\n"


__all__ = [
    "NativePropertyReportV1",
    "render_native_console",
    "validate_native_report_payload",
]
