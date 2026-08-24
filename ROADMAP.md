# Roadmap

This roadmap records intent, not a delivery commitment.

## `0.1.0a1` - Checkov-focused alpha

- Hardened differential core and closed `report-v1` evidence graph.
- Checkov 3.3.0 integration with explicit reduced-isolation semantics.
- Offline deterministic demo, environment doctor, report validation, and explain.
- Deterministic SARIF 2.1.0, Markdown, and JUnit report-v1 projections.
- Closed scan, differential, initialization, lock, and changed-only PR workflows.
- Clean Python 3.10–3.13 wheel and source distribution.
- Experimental Phase-E adapters and validators remain advisory.

## `0.1.0a2` - Evidence correctness

- Parse Terraform resource inventory with the protected native HCL2 parser so
  comment-like text inside strings and heredocs cannot alter structural inventory.
- Bind supported Checkov CKV2 connection-graph findings to exact participants,
  relationships, files, policy definitions, scanner identity, and snapshots.
- Keep missing, ambiguous, unsupported, or contradictory graph evidence
  `INCONCLUSIVE`.
- Design protected deterministic Helm materialization; implementation remains
  deferred pending owner review.

## `0.1.0a3` - Terraform coverage correctness

- Route initialization, direct and Git verification, validation planning, and scanner
  preparation through one protected Terraform structural parser.
- Classify Terraform files from parsed content rather than support-file names.
- Keep resource-free support files byte-bound, parser-governed, and in scope without
  inventing scanner resource identities.
- Preserve fail-closed handling for unsupported or ambiguous structure.

## `0.1.0a4` - Workload identity and bounded Helm materialization

- Bind supported controller-derived synthetic Pods through exact structural workload
  identity without fuzzy or label-only matching.
- Render local charts twice in fresh, client-only Helm environments and require exact
  byte, document, identity, source-provenance, and semantic agreement.
- Consume only frozen local dependencies and reject cluster state, plugins,
  post-renderers, remote charts, dependency negotiation, and arbitrary command tails.
- Extend the closed alpha `report-v1` schema with optional Helm materialization
  evidence while retaining compatibility for non-Helm reports.

## Candidate next-alpha work

These candidates are prioritized by real-world compatibility findings, not
promised release dates:

- Stabilize protected-oracle implementation identity across fresh Python processes.
- Improve diagnostics and performance for large Git materializations.
- Evaluate a candidate-only/new-IaC review mode that reports introduced findings
  without mislabelling a new module as a `FIXED` repair.
- Evaluate OpenTofu `.tofu` support after a trusted Checkov release supports it
  and additional external demand justifies the complete parser/evidence surface.
- Complete the native-Linux UID/GID 65532 bind-mount portability proof.

Private scanner-case screening remains limited to `observation`,
`semantic-difference`, `blocked`, and `not-reproducible` until each path has
decisive evidence.

## Before production container or Action release

- Pass the native-Linux read-only input/protected mount and writable output test with
  no root fallback.
- Resolve every redistribution licence, including the kubeconform schema bundle
  currently recorded as `NOASSERTION`.
- Complete full offline image, signature, architecture, and protected-cache review.

## Explicitly deferred

- Authoritative V7 multi-scanner consensus.
- Automated public validated-discrepancy claims.
- Public Phase-F scanner cases and upstream submissions without owner review.
- Model refresh.

The submitted manuscript's arXiv link will be added when the public identifier exists.
The Springer Version of Record and DOI will be linked when published. Neither pending
publication record blocks the software alpha.
