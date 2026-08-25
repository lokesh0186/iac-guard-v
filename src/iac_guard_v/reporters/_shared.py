"""Shared, fail-closed helpers for deterministic report-v1 projections."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..models import DomainError
from ..redaction import redact_detail
from ..report import validate_report_payload


def validated_snapshot(payload: dict) -> dict:
    """Return an immutable-by-convention copy after full public validation.

    Serialising before validation prevents a reporter from retaining caller-owned
    containers.  Validation is deliberately performed on the exact copied graph that
    the projection consumes, not on a different object supplied by the caller.
    """
    if type(payload) is not dict:
        raise DomainError("reporter input must be an exact report-v1 dictionary")
    try:
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        )
        snapshot = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise DomainError("reporter input is not canonical JSON data") from exc
    validate_report_payload(snapshot)
    return snapshot


def canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ) + "\n"


def report_identity(payload: dict) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def safe_text(value: Any) -> str:
    """Redact unstructured report text before it enters a projection."""
    return redact_detail(value if type(value) is str else str(value))


def is_full_verification(payload: dict) -> bool:
    return payload["result_kind"] == "verification" and "targets" in payload["verification"]


def target_key(target: dict) -> tuple[str, ...]:
    binding = target["binding"]
    identity = target["identity"]
    return (
        identity["scanner"], identity["rule_id"], identity["scope"],
        binding["file_path"], binding["artifact_kind"],
        binding["scanner_native_lookup"],
    )


def sorted_targets(payload: dict) -> list[dict]:
    if not is_full_verification(payload):
        return []
    return sorted(payload["verification"]["targets"], key=target_key)


def decision_for(payload: dict, target: dict) -> dict:
    wanted = target_key(target)
    for decision in payload["policy"]["decisions"]:
        resolved = decision["resolved_target"]
        candidate = {
            "identity": decision["identity"],
            "binding": resolved,
        }
        if target_key(candidate) == wanted:
            return decision
    raise DomainError("validated report target lacks its policy decision")


def gate_records(payload: dict) -> list[tuple[str, str, str, str]]:
    if not is_full_verification(payload):
        if payload["result_kind"] == "candidate_acceptance":
            acceptance = payload["acceptance"]
            return [
                (
                    "scanner_integrity",
                    acceptance["scanner_integrity"]["gate_id"],
                    acceptance["scanner_integrity"]["status"],
                    acceptance["scanner_integrity"]["reason_code"],
                ),
                *[
                    ("validator", gate["gate_id"], gate["status"], gate["reason_code"])
                    for gate in acceptance["parser_gates"]
                ],
            ]
        if payload["result_kind"] != "verification":
            return []
        verification = payload["verification"]
        return [
            (
                "preflight", verification["preflight"]["gate_id"],
                verification["preflight"]["status"],
                verification["preflight"]["reason_code"],
            ),
            *[
                ("validator", gate["gate_id"], gate["status"], gate["reason_code"])
                for gate in verification["validators"]
            ],
        ]
    verification = payload["verification"]
    rows = [
        ("preflight", verification["preflight"]),
        ("scanner_integrity", verification["scanner_integrity"]),
        *[("validator", gate) for gate in verification["validators"]],
        *[("oracle", gate) for gate in verification["oracles"]],
        ("regression", verification["regression"]),
        ("suppression", verification["suppression"]),
    ]
    return [
        (kind, gate["gate_id"], gate["status"], gate["reason_code"])
        for kind, gate in rows
    ]


def target_delta_classes(payload: dict, target: dict) -> list[str]:
    """Select only finding deltas whose retained side binds the exact target."""
    if not is_full_verification(payload):
        return []
    binding = target["binding"]
    identity = target["identity"]
    classes: set[str] = set()
    for delta in payload["verification"]["finding_diff"]["deltas"]:
        for side in (delta["baseline"], delta["candidate"]):
            if side is not None and (
                side["scanner"] == identity["scanner"]
                and side["rule_id"] == identity["rule_id"]
                and side["resource_address"] == identity["scope"]
                and side["location"]["file_path"] == binding["file_path"]
                and side["artifact_kind"] == binding["artifact_kind"]
            ):
                classes.add(delta["delta_class"])
                break
    return sorted(classes)


def engine_events(payload: dict) -> list[dict]:
    if not is_full_verification(payload):
        return []
    return sorted(
        payload["verification"]["engine_events"],
        key=lambda item: item["delta_class"],
    )


def target_location(payload: dict, target: dict) -> tuple[int, int]:
    """Return a retained native line range, without inventing a location."""
    binding = target["binding"]
    identity = target["identity"]
    for role in ("candidate_run", "baseline_run"):
        findings = payload["verification"][role]["findings"]
        for finding in findings:
            if (
                finding["scanner"] == identity["scanner"]
                and finding["rule_id"] == identity["rule_id"]
                and finding["resource_address"] == identity["scope"]
                and finding["location"]["file_path"] == binding["file_path"]
                and finding["artifact_kind"] == binding["artifact_kind"]
            ):
                location = finding["location"]
                return location["start_line"], location["end_line"]
    return 0, 0


def remediation_for(payload: dict, target: dict | None = None) -> str:
    """Project remediation already present in report-v1; never synthesize policy."""
    if payload["result_kind"] == "operational_uncertainty":
        return safe_text(payload["diagnostic"]["remediation"])
    if target is not None and is_full_verification(payload):
        decision = decision_for(payload, target)
        return safe_text(decision["rejection_reason"])
    return ""
