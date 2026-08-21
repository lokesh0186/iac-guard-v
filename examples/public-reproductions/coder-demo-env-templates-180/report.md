# IaC-Guard-V report

- Verdict: **VERIFIED**
- Exit code: `0`
- Result kind: `verification`

## Execution isolation

- Mode: `reduced-isolation`
- Hostile-input support: `false`
- Network isolation: `UNSUPPORTED`
- Filesystem isolation: `UNSUPPORTED`
- Scanner environment integrity: `PASS`

## Evaluation scope

- Baseline snapshot: `a236bee71cfbfaa4c6f40c4f595350ef35ad6e70f1d204200f1c744e3e5b99cc`
- Candidate snapshot: `6547344be265057f8e9e99d1eec2c26faa0ae805b08d668fd4930cb03f04a936`
- Scanner: `checkov` `3.3.0`

## Targets and policy

| Scanner/rule | Resource | File | Outcome | Evidence reason | Policy | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| `checkov:CKV_K8S_16` | `kubernetes_deployment_v1.this` | `workspace.tf` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_20` | `kubernetes_deployment_v1.this` | `workspace.tf` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |

## Scanner and gate evidence

- `baseline_run`: status `PASS`, ruleset `PASS`, files parsed `1/1`
- `candidate_run`: status `PASS`, ruleset `PASS`, files parsed `1/1`

| Gate kind | Gate | Status | Reason |
| --- | --- | --- | --- |
| `preflight` | `preflight` | `PASS` | `BOUND_SCAN_PLAN_VALIDATED` |
| `scanner_integrity` | `scanner_integrity` | `PASS` | `SCANNER_EVIDENCE_RECONCILED` |
| `validator` | `terraform_hcl_parse` | `PASS` | `VALIDATOR_COMPLETED` |
| `regression` | `regression` | `PASS` | `NO_DECISIVE_REGRESSION` |
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

No remediation is recorded in report-v1.
