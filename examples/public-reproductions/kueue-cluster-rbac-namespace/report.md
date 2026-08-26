# IaC-Guard-V report

- Verdict: **INCONCLUSIVE**
- Exit code: `3`
- Result kind: `operational_uncertainty`

## Operational uncertainty

- Reason: `CONTRADICTORY_NAMESPACE_PROVENANCE`
- Detail: cluster-scoped rendered resource contains metadata.namespace
- Remediation: Make the local Helm inputs deterministic and fully source-bound, then rerun.
