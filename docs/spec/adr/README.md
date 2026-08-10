# Architecture Decision Records

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](ADR-0001-research-in-same-repo.md) | Keep the research artifact in this repository | Accepted |
| [0002](ADR-0002-scanner-agnostic-core.md) | Scanner-agnostic core with adapter boundary | Accepted |
| [0003](ADR-0003-finding-identity.md) | Four-tier finding identity, not rule IDs | Accepted |
| [0004](ADR-0004-fail-closed-process-model.md) | Fail-closed process model and typed statuses | Accepted |
| [0005](ADR-0005-oracle-strategy.md) | Deterministic, scanner-independent oracles only | Accepted |
| [0006](ADR-0006-report-schema-versioning.md) | One canonical report, versioned; all formats derived | Accepted |
| [0007](ADR-0007-composite-action.md) | Composite GitHub Action, not a Docker container action | Accepted |
| [0008](ADR-0008-plugin-discovery.md) | Entry-point adapter discovery, trusted-config activation | Accepted |
| [0009](ADR-0009-no-telemetry.md) | No telemetry of any kind | Accepted |
| [0010](ADR-0010-version-lock.md) | Version and digest locking with `--locked` | Accepted |
| [0011](ADR-0011-paper-hosting.md) | Hosting of `paper.pdf` | Interim: `KEEP_UNCHANGED_PENDING_RIGHTS_CONFIRMATION` |
| [0012](ADR-0012-byte-vs-semantic-freeze.md) | Two freeze mechanisms: byte-exact and semantic | Accepted |
| [0013](ADR-0013-trusted-policy-source.md) | Policy loads from the trusted base, never the candidate | Accepted |

Format: context, decision, consequences, alternatives considered. An ADR is amended by
a new ADR, not by rewriting history.
