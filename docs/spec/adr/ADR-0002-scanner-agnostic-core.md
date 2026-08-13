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

## Amendment, 2026-08-10: first concrete adapter

D4 implements Checkov only. The adapter translates both single-framework objects and
multi-framework lists into `ScannerRun`; it never imports policy or emits a verdict.
Every malformed/incomplete execution shape is represented by the closed `AdapterReason`
family and a non-`PASS` status when eligible inputs exist. KICS and Trivy remain
unimplemented at Review 2.

The adapter's scan directory is a private snapshot of independently eligible files.
This is necessary because Checkov discovers configuration under `-d` even when a trusted
`--config-file` is also present. It also makes the adapter boundary concrete: native
scanner structures and implicit configuration discovery cannot leak into the core.

## Amendment, 2026-08-10: affirmative evaluation evidence

`ScannerRun` now carries scanner-neutral `CheckEvaluation` records for native passed,
failed, skipped, and unknown results. Checkov is still the only D4 adapter, but positive
target evidence no longer disappears into aggregate summary counts. A target absent from
failed findings remains inconclusive unless its exact rule/resource evaluation is
affirmatively passed. Coverage is derived from evaluation paths/resources rather than
invented from the requested eligible count.

## Amendment, 2026-08-11: independent resource coverage

File eligibility alone cannot establish resource coverage. Scanner requests now receive
scanner-neutral `ExpectedResource` records from the independent detector/parser and
report typed resource counters separately from file counters. Adapters map native lookup
identity to canonical resource identity, retain every native evaluation category, and
fail or become partial on missing, unexpected, count-inconsistent, or contradictory
resource evidence. An empty independent scope is `SKIPPED`, not scanner success.

## Amendment, 2026-08-11: complete parser-backed artifact classification

The independent inventory is trustworthy only if supported syntax cannot evade it.
Terraform `.tf` discovery uses `python-hcl2`. YAML classification inspects bounded syntax
nodes before constructing only Kubernetes-like documents, so ordinary workflow and
CloudFormation YAML remains visible but non-Kubernetes. Strict JSON classification adds
`KUBERNETES_JSON` object/List support. Every inspected supported-extension file retains
a digest-bound classification. Duplicate keys, Kubernetes custom tags, aliases,
excessive structure, incomplete identity, malformed bytes, and unsupported `.tf.json`
fail closed.

## Amendment, 2026-08-11: mixed-repository classification

D4.6 applies Kubernetes-only tag and alias restrictions only after bounded root identity
inspection. Workflow, OpenAPI, and CloudFormation YAML with anchors, domain tags, or
nested `kind` fields remains classified non-Kubernetes evidence. Unsupported nested
complete Kubernetes identity and unsafe Kubernetes roots still fail closed.

## Amendment, 2026-08-11: shared no-follow source inventory

D4.7 makes one typed filesystem inventory the input to artifact detectors, scan plans,
governed comparison, snapshot identity and final revalidation. Scanner-specific parsers
receive only digest-bound regular bytes. Symlinks and supported special files remain
scanner-agnostic rejected evidence and are never silently dropped.

## Amendment, 2026-08-12: E1 KICS adapter

KICS v2.1.20 now translates its official summary/query/file JSON into scanner-neutral
`ScannerRun`, `Finding`, evaluation, and coverage evidence. It preserves native
`similarity_id` and fails closed on all three native completeness counters. This is an
adapter boundary only: no cross-scanner agreement or policy consequence was added.

## Amendment, 2026-08-12: E2 Trivy adapter

Trivy v0.73.0 plus the external checks v2.2.0 lock now translates strict native JSON
into scanner-neutral findings, PASS/FAIL evaluations, and file/resource coverage.
Binary and checks drift remain independent. Global positive aggregates cannot prove a
sealed file/resource was evaluated. This remains an evidence adapter only; no
multi-scanner agreement or policy consequence was added.

## Amendment, 2026-08-12: E1.1 complete KICS contract

All official result exits are output-bearing; native types/arithmetic fail closed;
TRACE is separate BOM evidence; optional metadata remains optional; and `--pull never`
keeps locked execution offline. KICS supplies no affirmative target PASS.

## Amendment, 2026-08-12: E2.1 protected Trivy evidence

Cache provenance is factory-bound to the signed E0.3 physical inventory. Contradictory
native evaluation identities fail closed, and volatile report metadata is separated
from exact native-byte identity.

## Amendment, 2026-08-12: E1/E2 private normalization

Production evidence is constructed only after adapter-owned locked execution. Public
normalization rejects caller process/JSON combinations; private unit helpers are
unexported and cannot enter the public adapter or future consensus surface.

## Amendment, 2026-08-12: E1.2 KICS native coherence

KICS result exits must agree with the highest ordinary native severity. The complete
required v2.1.20 query/file shape and standard counters are validated; BOM/TRACE stays
separate; similarity-ID failure is typed identity uncertainty. KICS remains advisory.

## Amendment, 2026-08-12: E2.2 Trivy status and provenance

Official `EXCEPTION` records are visible skipped evidence. Documented omitted native
fields are retained conservatively. The portable execution record carries the full
E0.3 cache attestation and equal pre/post subtree roots.
