# ADR-0006 — One canonical report, versioned, with all formats derived

- Status: Accepted
- Date: 2026-08-09

## Context

Consumers are different: a maintainer reads a PR summary, an agent parses JSON, GitHub
code scanning ingests SARIF, a CI dashboard wants JUnit. Producing each independently
guarantees they will eventually disagree, and disagreement about a verdict is worse than
no report.

## Decision

There is exactly one canonical JSON report with a `schema_version`, published as
`schemas/report-v1.schema.json`. Console, SARIF 2.1.0, Markdown, and JUnit outputs are
projections of it. Nothing may appear in a projection that is not in the canonical
report.

The report separates evidence from judgement: raw output references and coverage
counters, then normalised findings, then classifications, then policy decisions, then
the verdict with reason codes. A reader can always answer "why".

Determinism is a requirement: identical inputs and tool lock produce byte-equal reports
except `run.started_at`, `run.duration_ms`, and a non-deterministic `run.id` if
selected. Ordering keys are documented.

## Consequences

- Adding an output format cannot change semantics.
- Schema evolution needs a policy: additive changes bump the minor version; removals or
  meaning changes bump the major version and are documented in the changelog.
- Snapshot tests can compare whole reports, which makes accidental semantic drift loud.
- Report size grows with evidence. Raw outputs are referenced by digest and retained
  only when `keep_raw_outputs` is set.

## Alternatives considered

**SARIF as the internal model.** Rejected: it cannot carry the completeness counters
(`files_parsed`, `evaluations_reported`, `queries_failed_to_execute`) that the integrity gate
requires, so the primary signal would live in vendor extensions.

**Per-format renderers reading engine state directly.** Rejected: that is how formats
drift apart.

## Amendment, 2026-08-11: portable input and resource coverage evidence

D4.2 defines portable scanner-input identity as path, artifact type, size, and SHA-256.
Device and inode remain private runtime race checks and do not serialize. Scanner reports
also carry `resource_coverage` separately from file/evaluation counters. These are
pre-release schema corrections: host filesystem allocation must not make otherwise
identical canonical reports differ.

## Amendment, 2026-08-11: deterministic scanner-JSON depth

Checkov result JSON is rejected above a fixed nesting depth of 128 before CPython's JSON
decoder runs. The report diagnostic is `JSON_DEPTH_EXCEEDED`, not whichever parser error
or top-level shape happens to result on a particular interpreter. Structural brackets
inside strings are ignored by the depth counter; syntax and duplicate-key checks remain
the strict decoder's responsibility.
