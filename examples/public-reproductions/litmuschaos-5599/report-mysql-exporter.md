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

- Baseline snapshot: `85770abd9643870d13587dfae799a26e7b5dace4ee0614bda73e84006b7f94a8`
- Candidate snapshot: `951fdc07824e14d39cea804ffa1468b2491d950e04491100209541a9681c350f`
- Scanner: `checkov` `3.3.0`

## Targets and policy

| Scanner/rule | Resource | File | Outcome | Evidence reason | Policy | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| `checkov:CKV_K8S_10` | `apps/v1/Deployment/monitoring/mysql-exporter` | `deployment.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_11` | `apps/v1/Deployment/monitoring/mysql-exporter` | `deployment.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_12` | `apps/v1/Deployment/monitoring/mysql-exporter` | `deployment.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_13` | `apps/v1/Deployment/monitoring/mysql-exporter` | `deployment.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_22` | `apps/v1/Deployment/monitoring/mysql-exporter` | `deployment.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_23` | `apps/v1/Deployment/monitoring/mysql-exporter` | `deployment.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_30` | `apps/v1/Deployment/monitoring/mysql-exporter` | `deployment.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |

## Scanner and gate evidence

- `baseline_run`: status `PASS`, ruleset `PASS`, files parsed `2/2`
- `candidate_run`: status `PASS`, ruleset `PASS`, files parsed `2/2`

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
