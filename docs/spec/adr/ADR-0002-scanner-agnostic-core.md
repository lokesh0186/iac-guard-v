# ADR-0002 — Scanner-agnostic core with a strict adapter boundary

- Status: Accepted
- Date: 2026-08-09

## Context

The research harness used Checkov as parser, security oracle, and truth
(`scripts/verify_patch.py:16`, `:27`, `:57`). Three consequences followed: results are
Checkov-specific (stated at `README.md:220`), a Checkov false negative becomes ground
truth, and a Checkov output-shape quirk becomes a verification bug — as it did in audit
findings F1 and F2.

## Decision

The verification engine never touches scanner-specific structures. Adapters translate
tool output into normalised `Finding` and `ScannerRun` objects. An adapter reports
capabilities, tool provenance, execution status, coverage counters, findings,
diagnostics, and raw-output references, and has no opinion about pass or fail.

Required scanners for 1.0: Checkov, KICS, Trivy misconfiguration. Independent
validators handle syntax and schema so that no security scanner is on the validity path.

## Consequences

- Adding a scanner is an adapter plus fixtures, not an engine change.
- Cross-scanner comparison needs an explicit mapping layer; raw rule IDs are not
  comparable. Handled by the control catalog with `EXACT` mappings only.
- Each adapter must be tested against the same twelve output shapes, which is more work
  per scanner and the reason the initial supported set is small.
- Users can require one scanner and treat others as advisory, so a flaky second scanner
  cannot block a pipeline.

## Alternatives considered

**Stay Checkov-only and ship sooner.** Rejected: the single-scanner limitation is the
first thing a reviewer of the paper flagged, and the product claim depends on not being
tied to one tool's semantics.

**Normalise everything into SARIF internally.** Rejected: SARIF is a good output format
but loses scanner-specific completeness counters (`files_failed_to_scan`,
`queries_failed_to_execute`) that the integrity gate depends on.
