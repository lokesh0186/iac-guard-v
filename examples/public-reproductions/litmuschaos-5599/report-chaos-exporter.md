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

- Baseline snapshot: `054c85cedb28c1beb8e4bfb8e510568c6f37aeb7488728d8944fcb34e36da9d1`
- Candidate snapshot: `31f5487bcf99b5e84f6b6a7e2bb18b52e4a002eab426b0e079c63852ce3a80f6`
- Scanner: `checkov` `3.3.0`

## Targets and policy

| Scanner/rule | Resource | File | Outcome | Evidence reason | Policy | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| `checkov:CKV_K8S_10` | `apps/v1/Deployment/litmus/chaos-exporter` | `chaos-exporter.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_11` | `apps/v1/Deployment/litmus/chaos-exporter` | `chaos-exporter.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_12` | `apps/v1/Deployment/litmus/chaos-exporter` | `chaos-exporter.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_13` | `apps/v1/Deployment/litmus/chaos-exporter` | `chaos-exporter.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_22` | `apps/v1/Deployment/litmus/chaos-exporter` | `chaos-exporter.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_23` | `apps/v1/Deployment/litmus/chaos-exporter` | `chaos-exporter.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |
| `checkov:CKV_K8S_30` | `apps/v1/Deployment/litmus/chaos-exporter` | `chaos-exporter.yaml` | `FIXED` | `AFFIRMATIVE_TARGET_PASS` | permitted |  |
|  |  |  | Finding deltas | `RESOLVED_FINDING` |  |  |

## Scanner and gate evidence

- `baseline_run`: status `PASS`, ruleset `PASS`, files parsed `1/1`
- `candidate_run`: status `PASS`, ruleset `PASS`, files parsed `1/1`

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
