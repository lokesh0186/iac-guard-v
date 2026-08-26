# IaC-Guard-V report

- Verdict: **INCONCLUSIVE**
- Exit code: `3`
- Result kind: `verification`

## Execution isolation

- Mode: `reduced-isolation`
- Hostile-input support: `false`
- Network isolation: `UNSUPPORTED`
- Filesystem isolation: `UNSUPPORTED`
- Scanner environment integrity: `PASS`

## Evaluation scope

- Baseline snapshot: `52a4681b9088f149359ffb065e252ba9c6ec011128e0a0211c58aa48004ed11f`
- Candidate snapshot: `9fa89e025050eca709c9c25be87706c4a47eb4c844d536fb902ae1b9d44fd4d3`
- Scanner: `checkov` `3.3.0`

## Targets and policy

| Scanner/rule | Resource | File | Outcome | Evidence reason | Policy | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| `checkov:CKV_K8S_20` | `apps/v1/Deployment/default/supabase-supabase-storage` | `storage-deployment.yaml` | `STILL_PRESENT` | `TARGET_FAILED` | not permitted | no trusted target-scoped exception authorises this outcome |
|  |  |  | Finding deltas | `NEW_FINDING, RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_22` | `apps/v1/Deployment/default/supabase-supabase-storage` | `storage-deployment.yaml` | `STILL_PRESENT` | `TARGET_FAILED` | not permitted | no trusted target-scoped exception authorises this outcome |
|  |  |  | Finding deltas | `NEW_FINDING, RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_30` | `apps/v1/Deployment/default/supabase-supabase-storage` | `storage-deployment.yaml` | `STILL_PRESENT` | `TARGET_FAILED` | not permitted | no trusted target-scoped exception authorises this outcome |
|  |  |  | Finding deltas | `NEW_FINDING, RESOLVED_FINDING` |  |  |

## Scanner and gate evidence

- `baseline_run`: status `PASS`, ruleset `PASS`, files parsed `1/1`
- `candidate_run`: status `PASS`, ruleset `PASS`, files parsed `1/1`

| Gate kind | Gate | Status | Reason |
| --- | --- | --- | --- |
| `preflight` | `preflight` | `PASS` | `BOUND_SCAN_PLAN_VALIDATED` |
| `scanner_integrity` | `scanner_integrity` | `PASS` | `SCANNER_EVIDENCE_RECONCILED` |
| `validator` | `kubernetes_yaml_parse` | `PASS` | `VALIDATOR_COMPLETED` |
| `regression` | `regression` | `INCONCLUSIVE` | `NEW_FINDING_SEVERITY_UNKNOWN` |
| `suppression` | `suppression` | `PASS` | `SUPPRESSION_DETECTOR_COMPLETED` |

## Regression, destructive, drift, and suppression evidence

| Delta class | Status | Reason | Affected resources | Affected paths |
| --- | --- | --- | --- | --- |
| `COVERAGE_DECREASED` | `PASS` | `COVERAGE_COMPLETE` |  |  |
| `DESTRUCTIVE_CHANGE` | `PASS` | `NO_RESOURCES_DELETED` |  |  |
| `DIAGNOSTIC_ADDED` | `PASS` | `NO_DIAGNOSTICS_ADDED` |  |  |
| `POLICY_DRIFT` | `PASS` | `GOVERNED_CONFIG_STABLE` |  |  |
| `RULE_SUBSTITUTED` | `PASS` | `RULE_IDENTITY_STABLE` |  |  |

## Policy exceptions

No trusted exception was applied.

## Remediation

- no trusted target-scoped exception authorises this outcome
