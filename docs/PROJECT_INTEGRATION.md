# Project integration

Begin with one existing project invariant or one exact repair target. Compare the project's native test first. If a small maintained native test covers the need, use that option. IaC-Guard-V is useful when the project needs its bounded identity binding, typed uncertainty, protected evidence and retained reports.

For an early integration, a project-owned manual `workflow_dispatch` job can run one selected case before the project decides whether to require it in CI. Pin the verifier, dependencies and actions; use `contents: read`, no secrets and trusted local source. Upload raw reports and logs even when verification fails. Require both the expected typed verdict and process exit; a missing report is an operational error.

For native invariants, [intent contracts](INTENT_CONTRACTS.md) compile to the declared 18 properties. Only a project can adopt a contract as project-authored intent. Verification does not upgrade a suggested contract's provenance. See [CI trust boundary](CI_TRUST_BOUNDARY.md) before choosing a runner or trigger.

[Independent rerun packets](../adoption/README.md) and the [existing CI guide](CI.md) provide starting points. No external project should add a dependency merely to demonstrate use.
