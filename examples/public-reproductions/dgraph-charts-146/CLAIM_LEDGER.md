# Claim ledger

| Claim | Classification | Evidence | Boundary |
| --- | --- | --- | --- |
| The rendered NetworkPolicy selects the rendered Zero StatefulSet pod template. | Authoritative IaC-Guard-V result | `REPORT.json`, `SELECTED_PROPERTY.json`: `CKV2_K8S_6`, `SATISFIED`, complete graph edge | Exact PR head, release, namespace, and selected property only |
| The selected policy explicitly has `policyTypes: [Ingress]`. | Exact rendered-policy observation | `REPORT.json`, `rendered/networkpolicy.yaml` | Isolation consequence uses standard Kubernetes semantics |
| The ServiceMonitor selects the Zero ClusterIP Service and names endpoint `http-zero`. | Corroborating configuration semantics | `rendered/servicemonitor.yaml`, `rendered/zero-service.yaml`, `RELATIONSHIP_EVIDENCE.json` | IaC-Guard-V a8 does not model ServiceMonitor CRD endpoint resolution |
| `http-zero` resolves Service TCP 6080 to targetPort 6080 and the selected Zero container exposes TCP 6080. | Corroborating configuration semantics | `rendered/zero-service.yaml`, `rendered/zero-statefulset.yaml` | Declared static configuration path, not live traffic |
| Exactly one chart-rendered NetworkPolicy selects Zero, and its only rendered ingress rule admits same-namespace, same-release Dgraph pods on all ports. | Corroborating configuration semantics | `RESOURCE_INVENTORY.json`, `RELATIONSHIP_EVIDENCE.json`, `rendered/networkpolicy.yaml` | Covers this chart render; cannot exclude policies installed separately |
| With `extraIngress: []`, no chart-rendered applicable rule admits an ordinary Prometheus source to Zero TCP 6080. | Corroborating configuration semantics | `CONFIGURATION.yaml`, `RELATIONSHIP_EVIDENCE.json` | Prometheus identity is external to the chart; runtime CNI and node-origin behavior are not tested |
| The source's optional client rule is for Alpha client ports 8080/9080 and is absent when `clientPodLabels: {}`. | Exact source/render observation | `source/networkpolicy.yaml`, `rendered/networkpolicy.yaml` | It is not described as an incorrect substitute for 6080 |
| Both optional features default to false; the result requires enabling both without an added ingress rule. | Conditional configuration fact | `source/values-observability.yaml`, `CONFIGURATION.yaml` | Not a default-install failure |
| Two render pairs were byte-identical and Helm lint passed. | Local deterministic verification | `MATERIALIZATION.json` | Syntax/determinism does not itself prove the relationship correct |
| Existing CI does not establish the complete ServiceMonitor-to-Zero-policy relationship. | Native-test-scope observation | Exact-head repository workflow and test inspection | No criticism of the project's CI strategy |
| No public duplicate of the exact 6080 monitoring-policy omission was found at final recheck. | Public search result | PR commits/comments/reviews and repository issue/PR searches | Cannot exclude private trackers or later activity |

## Explicitly unclaimed

- No vulnerability, exploitability, severity, outage, or universal monitoring
  failure is claimed.
- No default-chart breakage is claimed.
- No live cluster, packet drop, or deployed-service behavior was tested.
- IaC-Guard-V is not claimed to model the ServiceMonitor CRD or to have
  experimentally proved Prometheus traffic was dropped.
- No particular Prometheus pod or namespace selector is prescribed.
- No whole-PR, whole-chart, whole-namespace, or whole-cluster correctness is
  claimed.
- No acknowledgement, reliance, adoption, or remediation is claimed without
  independent maintainer action.
