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

## Amendment, 2026-08-11: sealed snapshot evidence

D5.4 requires canonical verification evidence to include baseline and candidate sealed
snapshot identities, portable repository-relative subpaths, complete artifact
classifications, expected resources, governed-entry types/digests, resource inventory
roots, and gate implementation identities. Local absolute source roots are private
runtime diagnostics and do not contribute to canonical configuration or report hashes.
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

## Amendment, 2026-08-11: schema-ready provenance

Before report-v1 is frozen, D5.5 requires complete ordered gate implementation records
and full role filesystem inventories in canonical results. Rejected symlinks and special
entries remain report evidence. Portable repository/snapshot/subpath identities replace
host-root paths, so equivalent runs in different temporary directories serialize alike.

## Amendment, 2026-08-11: report-v1 public boundary

D7 publishes `config-v1` and `report-v1` from the package. JSON is canonical UTF-8 with
sorted keys and compact separators; console is derived from that same dictionary. A
verification report binds the exact trusted engine and policy results and rejects a
policy result from another snapshot. Operational container unavailability is also a
typed report-v1 result with verdict `INCONCLUSIVE` and exit 3. Request errors remain a
separate `request-error-v1` diagnostic and exit 2.

## Amendment, 2026-08-12: portable symlink and gate evidence

Canonical report-v1 never emits raw symlink target text. It emits target kind and a
SHA-256 so snapshot mutation remains bound without leaking machine-local paths. Gate
records separately expose contract, product-build, parser-distribution, and loader/schema
identities.

## Amendment, 2026-08-12: closed report-v1 branches

D7.1 replaces permissive conditionals with closed verdict/exit branches and closed
nested definitions. Runtime output is schema-validated and top-level policy agreement is
mandatory. Execution isolation is first-class canonical evidence. Operational and
verification payload members are mutually exclusive.

## Amendment, 2026-08-12: semantic state table

Shape validation is followed by a mandatory semantic state-table validation. JSON
Schema alone cannot prove that a `VERIFIED` label agrees with scanner integrity,
required gates, target outcomes, engine events and policy decisions. The
full-verification/full-policy and artifact-failure/artifact-policy pairs are closed and
cannot be crossed.
