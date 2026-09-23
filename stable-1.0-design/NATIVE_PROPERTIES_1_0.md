# Native properties for 1.0

## Decision

Freeze the 18 public Beta1 V1 properties. Do not expand the semantic surface
while simultaneously making a 1.0 compatibility commitment.

| Requested family | 1.0 decision | Stable property or boundary |
| --- | --- | --- |
| PodMonitor resolves container port | include | `IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1` |
| ServiceMonitor resolves Service port | include | `IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1` |
| Service selects workload | include | `IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1` |
| Service port resolves container port | include | `IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1` |
| RBAC subject resolves | include only exact existing scope | `IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1`; generic User/Group subjects are not implied |
| RBAC roleRef resolves | include | `IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1` |
| NetworkPolicy selects workload | include | `IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1` |
| Bounded network path | include | existing ingress, egress, Pod path, monitoring ingress, isolation, closure, and rendered-policy-denial V1 properties |
| Container security-context properties | defer | existing scanner/oracle evidence is not promoted to a new native-property promise without separate definitions and complete fixtures |
| Terraform/OpenTofu reference resolves | include | `IACGV_TF_REFERENCE_RESOLVES_V1` and `IACGV_OPENTOFU_REFERENCE_RESOLVES_V1` |
| `ATTRIBUTE_EQUALS` | defer | no current public native property |
| `ATTRIBUTE_PRESENT` | defer | no current public native property |
| Bounded nested-block existence | defer | no current public native property |

## Complete frozen property set

1. `IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1`
2. `IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1`
3. `IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1`
4. `IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1`
5. `IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1`
6. `IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1`
7. `IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1`
8. `IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1`
9. `IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1`
10. `IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1`
11. `IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1`
12. `IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1`
13. `IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1`
14. `IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1`
15. `IACGV_OPENTOFU_REFERENCE_RESOLVES_V1`
16. `IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1`
17. `IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1`
18. `IACGV_TF_REFERENCE_RESOLVES_V1`

## Per-property release gate

Each property requires a traceability row binding:

- exact semantic definition and semantic-version dependency;
- versioned property ID and closed parameter schema;
- witness schema and reason-code vocabulary;
- `SATISFIED`, `VIOLATED`, `NOT_EVALUATED`, `UNSUPPORTED`, and `ERROR`
  coverage where reachable;
- positive, negative, ambiguous, incomplete-universe, and adversarial fixtures;
- deterministic witness and result identity;
- real-world demand or an existing public Beta1 use;
- replay of every external case that exercised the property.

A property with a missing fixture class blocks 1.0 or is removed only through an
explicit compatibility decision. It may not silently become scanner-backed.
