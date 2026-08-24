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

- Baseline snapshot: `73223a6364a1878ad5e30d3e3d614af8c30521919c48add2c859dc59946e8de4`
- Candidate snapshot: `93802be800a0111ca6373937cc0034a0467de884554d782e34d25ae3ebc6386d`
- Scanner: `checkov` `3.3.0`

## Targets and policy

| Scanner/rule | Resource | File | Outcome | Evidence reason | Policy | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| `checkov:CKV2_K8S_6` | `apps/v1/Deployment/default/kafka-shared` | `kafka-shared-deployment.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |

## Scanner and gate evidence

- `baseline_run`: status `PASS`, ruleset `PASS`, files parsed `2/2`
- `candidate_run`: status `PASS`, ruleset `PASS`, files parsed `3/3`

| Gate kind | Gate | Status | Reason |
| --- | --- | --- | --- |
| `preflight` | `preflight` | `PASS` | `BOUND_SCAN_PLAN_VALIDATED` |
| `scanner_integrity` | `scanner_integrity` | `PASS` | `SCANNER_EVIDENCE_RECONCILED` |
| `validator` | `kubernetes_yaml_parse` | `PASS` | `VALIDATOR_COMPLETED` |
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
