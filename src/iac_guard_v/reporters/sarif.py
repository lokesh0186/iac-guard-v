"""Deterministic SARIF 2.1.0 projection of validated report-v1 evidence."""
from __future__ import annotations

from ._shared import (
    canonical_json, decision_for, engine_events, gate_records, is_full_verification,
    remediation_for, report_identity, safe_text, sorted_targets, target_delta_classes,
    target_location, validated_snapshot,
)

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _level(payload: dict, target: dict | None = None) -> str:
    if payload["result_kind"] == "operational_uncertainty":
        return "error"
    if payload["verdict"] == "INCONCLUSIVE":
        return "warning"
    if payload["verdict"] == "FAILED":
        return "error"
    if target is not None and target["outcome"] != "FIXED":
        return "warning"
    return "note"


def _kind(payload: dict, target: dict | None = None) -> str:
    if payload["result_kind"] == "operational_uncertainty":
        return "review"
    if payload["verdict"] == "FAILED":
        return "fail"
    if payload["verdict"] == "INCONCLUSIVE":
        return "review"
    if target is not None and target["outcome"] != "FIXED":
        return "review"
    return "pass"


def _target_result(payload: dict, target: dict) -> dict:
    identity = target["identity"]
    binding = target["binding"]
    decision = decision_for(payload, target)
    start, end = target_location(payload, target)
    location: dict = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": binding["file_path"], "uriBaseId": "%SRCROOT%",
            },
        }
    }
    if start:
        location["physicalLocation"]["region"] = {
            "startLine": start, "endLine": end,
        }
    remediation = remediation_for(payload, target)
    message = (
        f"{identity['scanner']} {identity['rule_id']} at {identity['scope']}: "
        f"{target['outcome']} ({target['target_reason']})"
    )
    events = engine_events(payload)
    return {
        "ruleId": f"{identity['scanner']}:{identity['rule_id']}",
        "level": _level(payload, target),
        "kind": _kind(payload, target),
        "message": {"text": message},
        "locations": [location],
        "properties": {
            "artifactKind": binding["artifact_kind"],
            "baselineOccurrences": target["counts"]["baseline"],
            "candidateOccurrences": target["counts"]["candidate"],
            "engineEvents": [
                {
                    "deltaClass": event["delta_class"],
                    "reasonCode": event["reason_code"],
                    "status": event["status"],
                }
                for event in events
            ],
            "exceptionId": decision["exception_id"],
            "findingDeltaClasses": target_delta_classes(payload, target),
            "finalVerdict": payload["verdict"],
            "policyPermitted": decision["policy_permitted"],
            "remediation": remediation,
            "resourceIdentity": binding["scanner_native_lookup"],
            "scanner": identity["scanner"],
            "targetIdentity": identity["opaque_id"],
            "targetOutcome": target["outcome"],
        },
    }


def _single_result(payload: dict) -> dict:
    if payload["result_kind"] == "operational_uncertainty":
        diagnostic = payload["diagnostic"]
        return {
            "ruleId": diagnostic["reason_code"],
            "level": _level(payload),
            "kind": _kind(payload),
            "message": {"text": safe_text(diagnostic["detail"])},
            "properties": {
                "finalVerdict": payload["verdict"],
                "remediation": remediation_for(payload),
                "resultKind": payload["result_kind"],
            },
        }
    failure = payload["verification"]
    gate = failure["validators"][0]
    return {
        "ruleId": failure["validator_gate_id"],
        "level": _level(payload),
        "kind": _kind(payload),
        "message": {"text": safe_text(gate["detail"])},
        "properties": {
            "artifactKind": failure["artifact_kind"],
            "failureReason": failure["failure_reason"],
            "finalVerdict": payload["verdict"],
            "remediation": "",
            "resultKind": payload["result_kind"],
        },
    }


def render_sarif(payload: dict) -> str:
    """Render SARIF only after the complete public report validator accepts input."""
    report = validated_snapshot(payload)
    targets = sorted_targets(report)
    results = (
        [_target_result(report, target) for target in targets]
        if is_full_verification(report)
        else [_single_result(report)]
    )
    rule_ids = sorted({result["ruleId"] for result in results})
    isolation = report.get("execution_isolation", {})
    run = {
        "automationDetails": {"id": f"iac-guard-v/{report_identity(report)}"},
        "invocations": [{
            "executionSuccessful": report["result_kind"] != "operational_uncertainty",
            "exitCode": report["exit_code"],
            "properties": {
                "executionIsolation": isolation,
                "finalVerdict": report["verdict"],
                "gates": [
                    {
                        "kind": kind, "gateId": gate_id,
                        "status": status, "reasonCode": reason,
                    }
                    for kind, gate_id, status, reason in gate_records(report)
                ],
                "resultKind": report["result_kind"],
            },
        }],
        "results": results,
        "tool": {"driver": {
            "name": "IaC-Guard-V",
            "rules": [{"id": rule_id, "name": rule_id} for rule_id in rule_ids],
            "semanticVersion": "0.1.0a1",
        }},
    }
    return canonical_json({"$schema": _SCHEMA, "runs": [run], "version": "2.1.0"})


__all__ = ["render_sarif"]
