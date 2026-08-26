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

- Candidate snapshot: `e729214743af78a6955048aebd18883cb3e1c35fbd0c23980996e500ce7eee64`
- Scanner: `checkov` `3.3.0`
- Scanner integrity: `PASS`

| Rule | Resource | File | Outcome | Evidence reason |
| --- | --- | --- | --- | --- |
| `CKV2_K8S_6` | `apps/v1/Deployment/default/supabase-supabase-auth` | `rendered.yaml` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |
| `CKV2_K8S_6` | `apps/v1/Deployment/default/supabase-supabase-kong` | `rendered.yaml` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |
| `CKV2_K8S_6` | `apps/v1/Deployment/default/supabase-supabase-rest` | `rendered.yaml` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |

## Scope accounting

- Requested properties: `3`
- Selected resources: `3`
- Unselected failed findings remain accounted for by count and digest.
