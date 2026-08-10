"""Normalisation helpers shared by scanner adapters.

Adapters receive findings in whatever order a scanner emitted them, which is not a
contract. `ScannerRun` rejects two findings with the same exact identity, because
`occurrence_index` exists precisely to disambiguate repeated findings — so the index has
to be assigned deterministically before construction, not left to chance.

The defect this prevents was measured: two findings sharing an exact key but differing in
severity and message serialised as `["one", "two"]` or `["two", "one"]` depending purely
on the order the adapter happened to pass them in.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from .models import DomainError, Finding, require_exact_type


def occurrence_group_key(finding: Finding) -> tuple:
    """Findings that compete for an occurrence index within one group."""
    return (finding.scanner, finding.rule_id, finding.location.file_path,
            finding.resource_address)


def canonical_sort_key(finding: Finding) -> tuple:
    """The documented canonical order for assigning occurrence indices.

    Ordering is by location, then by the content that distinguishes two findings at the
    same location. Every component is a stable property of the finding itself, so the
    result does not depend on the order the scanner emitted them.
    """
    return (
        finding.scanner,
        finding.rule_id,
        finding.location.file_path,
        finding.resource_address,
        finding.location.start_line,
        finding.location.end_line,
        finding.severity.value,
        finding.native_fingerprint,
        finding.message,
        finding.rule_name,
        finding.artifact_kind.value,
        finding.suppressed,
    )


def assign_occurrence_indices(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Return findings with deterministic `occurrence_index` values.

    Findings are canonically sorted, then indexed from 0 within each
    `(scanner, rule_id, file_path, resource_address)` group. Two adapters given the same
    set of native findings in different orders therefore produce identical output.

    Identical findings — same canonical sort key in every respect — are a genuine
    duplicate rather than two occurrences, and are rejected: silently indexing them 0 and
    1 would invent a second finding that the scanner never reported.
    """
    items = []
    for finding in findings:
        require_exact_type(finding, Finding, "finding")
        items.append(finding)

    ordered = sorted(items, key=canonical_sort_key)
    seen: dict[tuple, int] = {}
    for finding in ordered:
        key = canonical_sort_key(finding)
        if key in seen:
            raise DomainError(
                f"two findings are identical in every canonical field "
                f"({finding.scanner}:{finding.rule_id} at "
                f"{finding.location.file_path}:{finding.location.start_line} on "
                f"{finding.resource_address}); this is a duplicate, not a second "
                f"occurrence"
            )
        seen[key] = 1

    counters: dict[tuple, int] = {}
    result = []
    for finding in ordered:
        group = occurrence_group_key(finding)
        index = counters.get(group, 0)
        counters[group] = index + 1
        result.append(replace(finding, occurrence_index=index))
    return tuple(result)
