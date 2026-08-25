# IaC-Guard-V report

- Verdict: **VERIFIED**
- Exit code: `0`
- Result kind: `candidate_acceptance`

## Execution isolation

- Mode: `reduced-isolation`
- Hostile-input support: `false`
- Network isolation: `UNSUPPORTED`
- Filesystem isolation: `UNSUPPORTED`
- Scanner environment integrity: `PASS`

## Candidate acceptance scope

This report evaluates only the explicitly requested candidate properties. 
It does not assert that a baseline defect was fixed.

- Candidate snapshot: `7cd7cf84fda08bb0352eedf6cf6c535b7269bee4bf86b33d1a6a5fb37daf5b36`
- Scanner: `checkov` `3.3.0`
- Scanner integrity: `PASS`

| Rule | Resource | File | Outcome | Evidence reason |
| --- | --- | --- | --- | --- |
| `CKV_AWS_24` | `aws_security_group.instance` | `main.tf` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |

## Scope accounting

- Requested properties: `1`
- Selected resources: `1`
- Unselected failed findings remain accounted for by count and digest.
