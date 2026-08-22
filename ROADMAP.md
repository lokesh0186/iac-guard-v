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

## Candidate next-alpha work

These candidates are prioritized by real-world compatibility findings, not
promised release dates:

- Stabilize protected-oracle implementation identity across fresh Python processes.
- Improve diagnostics and performance for large Git materializations.
- Evaluate a candidate-only/new-IaC review mode that reports introduced findings
  without mislabelling a new module as a `FIXED` repair.
- Evaluate OpenTofu `.tofu` support after a trusted Checkov release supports it
  and additional external demand justifies the complete parser/evidence surface.
- Investigate reproducible Helm materialization only with version, chart, values,
  dependency, command, rendered-output, and source-identity provenance.
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
