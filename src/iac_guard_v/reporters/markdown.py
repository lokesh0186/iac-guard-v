"""Deterministic Markdown projection of validated report-v1 evidence."""
from __future__ import annotations

from ._shared import (
    decision_for, engine_events, gate_records, is_full_verification,
    remediation_for, safe_text, sorted_targets, target_delta_classes,
    validated_snapshot,
)


def _cell(value: object) -> str:
    text = safe_text(value).replace("|", "\\|")
    return text.replace("\r", " ").replace("\n", "<br>")


def _structured_cell(value: object) -> str:
    """Escape schema-validated identity without treating its digest as a secret."""
    text = str(value).replace("|", "\\|")
    return text.replace("\r", " ").replace("\n", "<br>")


def _isolation(report: dict) -> list[str]:
    evidence = report.get("execution_isolation")
    if evidence is None:
        return []
    return [
        "## Execution isolation",
        "",
        f"- Mode: `{_structured_cell(evidence['mode'])}`",
        f"- Hostile-input support: `{str(evidence['hostile_input_support']).lower()}`",
        f"- Network isolation: `{evidence['network_isolation_state']}`",
        f"- Filesystem isolation: `{evidence['filesystem_isolation_state']}`",
        f"- Scanner environment integrity: `{evidence['scanner_environment_integrity_state']}`",
        "",
    ]


def _operational(report: dict) -> list[str]:
    diagnostic = report["diagnostic"]
    return [
        "## Operational uncertainty",
        "",
        f"- Reason: `{_cell(diagnostic['reason_code'])}`",
        f"- Detail: {_cell(diagnostic['detail'])}",
        f"- Remediation: {_cell(diagnostic['remediation'])}",
        "",
    ]


def _artifact_failure(report: dict) -> list[str]:
    verification = report["verification"]
    validator = verification["validators"][0]
    return [
        "## Candidate artifact failure",
        "",
        f"- Artifact kind: `{verification['artifact_kind']}`",
        f"- Validator: `{verification['validator_gate_id']}`",
        f"- Reason: `{verification['failure_reason']}`",
        f"- Detail: {_cell(validator['detail'])}",
        "",
    ]


def _full(report: dict) -> list[str]:
    verification = report["verification"]
    lines = [
        "## Evaluation scope",
        "",
        f"- Baseline snapshot: `{verification['baseline_snapshot']['snapshot_sha256']}`",
        f"- Candidate snapshot: `{verification['candidate_snapshot']['snapshot_sha256']}`",
        f"- Scanner: `{verification['candidate_run']['scanner']}` "
        f"`{verification['candidate_run']['scanner_version']}`",
        "",
        "## Targets and policy",
        "",
        "| Scanner/rule | Resource | File | Outcome | Evidence reason | Policy | Remediation |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for target in sorted_targets(report):
        identity = target["identity"]
        binding = target["binding"]
        decision = decision_for(report, target)
        policy = (
            f"exception `{_structured_cell(decision['exception_id'])}`"
            if decision["policy_permitted"]
            else ("permitted" if target["outcome"] == "FIXED" else "not permitted")
        )
        lines.append(
            f"| `{identity['scanner']}:{identity['rule_id']}` | "
            f"`{_structured_cell(identity['scope'])}` | "
            f"`{_structured_cell(binding['file_path'])}` | "
            f"`{target['outcome']}` | `{target['target_reason']}` | {policy} | "
            f"{_cell(remediation_for(report, target))} |"
        )
        deltas = target_delta_classes(report, target)
        if deltas:
            lines.append(
                f"|  |  |  | Finding deltas | `{', '.join(deltas)}` |  |  |"
            )
    lines.extend(("", "## Scanner and gate evidence", ""))
    for role in ("baseline_run", "candidate_run"):
        run = verification[role]
        coverage = run["coverage"]
        lines.append(
            f"- `{role}`: status `{run['status']}`, ruleset `{run['ruleset_integrity']}`, "
            f"files parsed `{coverage['files_parsed']}/{coverage['files_eligible']}`"
        )
    lines.extend((
        "",
        "| Gate kind | Gate | Status | Reason |",
        "| --- | --- | --- | --- |",
    ))
    for kind, gate_id, status, reason in gate_records(report):
        lines.append(f"| `{kind}` | `{gate_id}` | `{status}` | `{reason}` |")
    lines.extend((
        "",
        "## Regression, destructive, drift, and suppression evidence",
        "",
        "| Delta class | Status | Reason | Affected resources | Affected paths |",
        "| --- | --- | --- | --- | --- |",
    ))
    for event in engine_events(report):
        lines.append(
            f"| `{event['delta_class']}` | `{event['status']}` | `{event['reason_code']}` | "
            f"{_structured_cell(', '.join(event['affected_resources']))} | "
            f"{_structured_cell(', '.join(event['affected_paths']))} |"
        )
    lines.extend((
        "",
        "## Policy exceptions",
        "",
    ))
    applied = report["policy"]["policy_evidence"]["applied_exception_sources"]
    if not applied:
        lines.append("No trusted exception was applied.")
    else:
        for exception in sorted(applied, key=lambda item: item["exception_id"]):
            lines.append(
                f"- `{exception['exception_id']}` from `{exception['source_origin']}` "
                f"(`{exception['source_identity']}`)"
            )
    lines.extend(("", "## Remediation", ""))
    remediations = sorted({
        remediation_for(report, target)
        for target in sorted_targets(report)
        if remediation_for(report, target)
    })
    if remediations:
        lines.extend(f"- {_cell(item)}" for item in remediations)
    elif report["verdict"] == "VERIFIED":
        lines.append("No remediation is recorded in report-v1.")
    else:
        lines.append("Consult the typed target, gate, and policy reasons above.")
    lines.append("")
    return lines


def render_markdown(payload: dict) -> str:
    """Render a human explanation without changing report-v1 semantics."""
    report = validated_snapshot(payload)
    lines = [
        "# IaC-Guard-V report",
        "",
        f"- Verdict: **{report['verdict']}**",
        f"- Exit code: `{report['exit_code']}`",
        f"- Result kind: `{report['result_kind']}`",
        "",
    ]
    lines.extend(_isolation(report))
    if report["result_kind"] == "operational_uncertainty":
        lines.extend(_operational(report))
    elif is_full_verification(report):
        lines.extend(_full(report))
    else:
        lines.extend(_artifact_failure(report))
    return "\n".join(lines)


__all__ = ["render_markdown"]
