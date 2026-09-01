# Claim ledger

| Claim | Evidence | Boundary |
|---|---|---|
| `coredns-1.47.0` is the exact released source under review. | `SOURCE_IDENTITY.json`; release commit and tree | Released chart only. |
| Monitor `true`, service `false` renders a ServiceMonitor with zero matching Services. | `A_B_EXECUTION.json`; `RESOURCE_INVENTORY.json`; `REPORT_CASE_A.json` | Protected rendered-manifest semantics. |
| The ordinary DNS Service is not an alternative match. | Case A selector witness | It lacks `app.kubernetes.io/component=metrics`. |
| Monitor `true`, service `true` renders the expected metrics Service. | `A_B_EXECUTION.json`; `RESOURCE_INVENTORY.json`; `REPORT_CASE_B.json` | Positive control. |
| The positive relationship resolves to TCP 9153. | Case B native witness and resource inventory | Service -> workload/container-port configuration, not live traffic. |
| IaC-Guard-V independently establishes both relationship verdicts. | Native reports from public `iac-guard-v==0.1.0a9` | Scanner-independent native property; no scanner voting. |
| Both render pairs were byte-identical. | `A_B_EXECUTION.json`; `AB_COMPARISON.json` | Deterministic local Helm rendering. |
| Existing chart tests and lint pass but do not assert the relationship. | `REGRESSION_DESCRIPTION.md` | Factual test comparison, not criticism. |
| Live Prometheus scraping fails in every environment. | Not claimed | No Kubernetes, Prometheus, or traffic execution occurred. |
| The observation is a security vulnerability or outage. | Not claimed | Classification is a released feature-composition defect. |

External classification: `TIER_A_RELEASE_DEFECT / NATIVE_A9_DISCOVERY /
PUBLIC_DEFECT_REPORT / EXTERNAL_TECHNICAL_OUTREACH`.

No acknowledgement, reliance, adoption, or remediation is claimed without an
independent maintainer response or change.
