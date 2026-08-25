"""Deterministic JUnit XML projection of validated report-v1 evidence."""
from __future__ import annotations

from xml.etree import ElementTree as ET

from ._shared import (
    decision_for, gate_records, is_full_verification, remediation_for,
    report_identity, safe_text, sorted_targets, validated_snapshot,
)


def _property(parent: ET.Element, name: str, value: object) -> None:
    """Emit only closed, schema-validated structured properties."""
    ET.SubElement(parent, "property", {"name": name, "value": str(value)})


def _mark(testcase: ET.Element, kind: str, message: str, detail: str) -> None:
    child = ET.SubElement(testcase, kind, {"message": safe_text(message)})
    child.text = safe_text(detail)


def render_junit(payload: dict) -> str:
    """Render JUnit where uncertainty is skipped/error, never a passing test."""
    report = validated_snapshot(payload)
    targets = sorted_targets(report)
    acceptance_properties = (
        report["acceptance"]["properties"]
        if report["result_kind"] == "candidate_acceptance"
        else []
    )
    total = 1 + len(targets) + len(acceptance_properties)
    failures = 1 if report["verdict"] == "FAILED" else 0
    errors = 1 if report["result_kind"] == "operational_uncertainty" else 0
    skipped = 1 if (
        report["verdict"] == "INCONCLUSIVE"
        and report["result_kind"] != "operational_uncertainty"
    ) else 0
    suite = ET.Element("testsuite", {
        "name": "IaC-Guard-V report-v1",
        "tests": str(total),
        "failures": str(failures),
        "errors": str(errors),
        "skipped": str(skipped),
    })
    properties = ET.SubElement(suite, "properties")
    _property(properties, "report.sha256", report_identity(report))
    _property(properties, "report.result_kind", report["result_kind"])
    _property(properties, "report.verdict", report["verdict"])
    _property(properties, "report.exit_code", report["exit_code"])
    isolation = report.get("execution_isolation")
    if isolation is not None:
        for name in sorted(isolation):
            _property(properties, f"isolation.{name}", isolation[name])
    for kind, gate_id, status, reason in gate_records(report):
        _property(properties, f"gate.{kind}.{gate_id}.status", status)
        _property(properties, f"gate.{kind}.{gate_id}.reason", reason)

    final = ET.SubElement(suite, "testcase", {
        "classname": "iac_guard_v.report",
        "name": "final-verdict",
    })
    if report["result_kind"] == "operational_uncertainty":
        diagnostic = report["diagnostic"]
        _mark(final, "error", diagnostic["reason_code"], diagnostic["detail"])
        output = ET.SubElement(final, "system-out")
        output.text = f"remediation: {remediation_for(report)}"
    elif report["verdict"] == "FAILED" and report["result_kind"] == "candidate_acceptance":
        _mark(
            final,
            "failure",
            "IaC-Guard-V candidate acceptance failed",
            "One or more explicitly requested candidate properties are violated.",
        )
    elif report["verdict"] == "FAILED":
        detail = (
            report["verification"].get("failure_reason", "POLICY_VERDICT_FAILED")
        )
        _mark(final, "failure", "IaC-Guard-V verification failed", detail)
    elif report["verdict"] == "INCONCLUSIVE":
        _mark(
            final, "skipped", "IaC-Guard-V verification is inconclusive",
            "Typed report-v1 uncertainty prevented an affirmative result.",
        )

    for target in targets:
        identity = target["identity"]
        decision = decision_for(report, target)
        case = ET.SubElement(suite, "testcase", {
            "classname": f"{identity['scanner']}.{identity['rule_id']}",
            "name": identity["scope"],
        })
        if target["outcome"] == "FIXED":
            continue
        detail = (
            f"outcome={target['outcome']}; reason={target['target_reason']}; "
            f"file={target['binding']['file_path']}; "
            f"exception={decision['exception_id']}; "
            f"remediation={remediation_for(report, target)}"
        )
        if report["verdict"] == "FAILED":
            _mark(case, "failure", target["outcome"], detail)
            failures += 1
        else:
            _mark(case, "skipped", target["outcome"], detail)
            skipped += 1
    for property_ in acceptance_properties:
        selector = property_["selector"]
        case = ET.SubElement(suite, "testcase", {
            "classname": f"checkov.{selector['rule_id']}",
            "name": selector["resource_address"],
        })
        if property_["outcome"] == "VIOLATED":
            _mark(case, "failure", property_["reason_code"], "VIOLATED")
            failures += 1
        elif property_["outcome"] == "INCONCLUSIVE":
            _mark(case, "skipped", property_["reason_code"], "INCONCLUSIVE")
            skipped += 1
    suite.set("failures", str(failures))
    suite.set("skipped", str(skipped))
    ET.indent(suite, space="  ")
    xml = ET.tostring(suite, encoding="unicode", short_empty_elements=True)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml + "\n"


__all__ = ["render_junit"]
