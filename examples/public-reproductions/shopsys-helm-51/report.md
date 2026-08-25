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

- Candidate snapshot: `f442564b492b5c85cc3265bfbbdb023f1753b2e76d04b508a28bd7f73f9ce61c`
- Scanner: `checkov` `3.3.0`
- Scanner integrity: `PASS`

| Rule | Resource | File | Outcome | Evidence reason |
| --- | --- | --- | --- | --- |
| `CKV2_K8S_6` | `apps/v1/Deployment/default/webserver-php-fpm` | `rendered.yaml` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |
| `CKV2_K8S_6` | `apps/v1/Deployment/default/storefront` | `rendered.yaml` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |
| `CKV2_K8S_6` | `apps/v1/Deployment/default/cron` | `rendered.yaml` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |
| `CKV2_K8S_6` | `apps/v1/Deployment/default/redis` | `rendered.yaml` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |
| `CKV2_K8S_6` | `apps/v1/StatefulSet/default/rabbitmq` | `rendered.yaml` | `SATISFIED` | `CANDIDATE_PROPERTY_SATISFIED` |

## Scope accounting

- Requested properties: `5`
- Selected resources: `5`
- Unselected failed findings remain accounted for by count and digest.
