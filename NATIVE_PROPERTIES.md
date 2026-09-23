# Native properties in IaC-Guard-V 1.0

The following 18 property IDs are the complete stable 1.0 native surface. Every
property has version `1`, a closed parameter schema, a mechanically validated witness,
and one of five results: `SATISFIED`, `VIOLATED`, `NOT_EVALUATED`, `UNSUPPORTED`, or
`ERROR`.

`SATISFIED` proves the selected predicate over the protected artifact universe.
`VIOLATED` proves it false. `NOT_EVALUATED` means required evidence is missing,
ambiguous, incomplete, or inapplicable. `UNSUPPORTED` means the request is outside the
declared semantics. `ERROR` means evaluation could not complete safely. Uncertainty is
never converted to success.

Use `iac-guard properties describe PROPERTY_ID` for the packaged canonical parameter
schema, semantic digest, implementation identity, capabilities, and witness type.

## Kubernetes policy and path properties

| Stable property ID | Subject | Parameters | Exact bounded question | Witness |
| --- | --- | --- | --- | --- |
| `IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1` | workload | optional `policy_identity` | Does at least one rendered NetworkPolicy, or the named policy, select the workload? | `k8s_network_policy_selection_v1` |
| `IACGV_K8S_WORKLOAD_INGRESS_ISOLATED_V1` | workload | none | Is the workload selected by a policy governing ingress? | `k8s_network_policy_isolation_v1` |
| `IACGV_K8S_WORKLOAD_EGRESS_ISOLATED_V1` | workload | none | Is the workload selected by a policy governing egress? | `k8s_network_policy_isolation_v1` |
| `IACGV_K8S_NETWORK_INGRESS_PATH_ALLOWED_V1` | workload | required `source`, `port`; optional protocol | Do the complete rendered policies allow the bounded source-to-workload ingress path? | `k8s_network_path_v1` |
| `IACGV_K8S_NETWORK_EGRESS_PATH_ALLOWED_V1` | workload | required `destination`, `port`; optional protocol | Do the complete rendered policies allow the bounded workload-to-destination egress path? | `k8s_network_path_v1` |
| `IACGV_K8S_POD_NETWORK_PATH_ALLOWED_V1` | workload | optional destination workload/service, service port, port, protocol | Does the bounded rendered source-to-destination Pod path remain allowed through selection, service, and policy semantics? | `k8s_pod_network_path_v1` |
| `IACGV_K8S_TRAFFIC_PATH_DENIED_BY_RENDERED_POLICY_SET_V1` | workload | required direction and port; bounded source/destination and protocol | Does the complete rendered policy set deny the selected bounded path? | `k8s_denied_path_v1` |
| `IACGV_K8S_COMPONENT_POLICY_CLOSURE_V1` | component | required workload identities, policy identities, membership digest | Does a caller-bound component contain the declared workloads and complete policy closure? | `k8s_component_policy_closure_v1` |
| `IACGV_K8S_MONITORING_INGRESS_PATH_ALLOWED_V1` | ServiceMonitor or PodMonitor | required source; optional endpoint index | Does the selected monitoring source have an allowed ingress path to the resolved metrics target? | `prometheus_monitoring_ingress_v1` |

Path results describe Kubernetes manifest NetworkPolicy semantics only. They do not
prove CNI enforcement, routing, DNS, service-mesh, readiness, firewall, NAT, or live
packet behavior. Unknown selectors, incomplete policy universes, and unresolved IP or
port evidence fail closed.

## Kubernetes Service and monitoring relationships

| Stable property ID | Subject | Parameters | Exact bounded question | Witness |
| --- | --- | --- | --- | --- |
| `IACGV_K8S_SERVICE_SELECTS_WORKLOAD_V1` | Service | optional expectation and expected workload set | Does the Service selector resolve to the requested nonempty, exact-one, exact-set, or all-expected workload set? | `k8s_service_selection_v1` |
| `IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1` | Service | required service-port selector; optional expected numeric port | Does the selected Service port and targetPort resolve unambiguously to a matching workload container port? | `k8s_service_port_resolution_v1` |
| `IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1` | ServiceMonitor | optional endpoint index and expected Service | Does the selected endpoint resolve through namespace and selector semantics to the intended Service port? | `prometheus_monitor_resolution_v1` |
| `IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1` | PodMonitor | optional endpoint index | Does the selected endpoint resolve through Pod selection to an unambiguous matching container port? | `prometheus_monitor_resolution_v1` |

Resolution is identity- and namespace-aware. Missing ports, ambiguous selectors,
unknown monitor semantics, duplicate identities, and unresolved named target ports do
not become `SATISFIED`.

## Kubernetes RBAC relationships

| Stable property ID | Subject | Parameters | Exact bounded question | Witness |
| --- | --- | --- | --- | --- |
| `IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1` | RoleBinding or ClusterRoleBinding | optional `complete_expected_domain` | Does the binding's roleRef resolve with the correct Role or ClusterRole scope? | `k8s_rbac_role_ref_v1` |
| `IACGV_K8S_RBAC_SERVICEACCOUNT_SUBJECT_RESOLVES_V1` | RoleBinding or ClusterRoleBinding | optional `complete_expected_domain` | Do ServiceAccount subjects resolve under Kubernetes namespace-defaulting rules? | `k8s_rbac_subject_v1` |
| `IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1` | RoleBinding or ClusterRoleBinding | none | Are binding kind, roleRef kind, subject kind, and namespaces scope-consistent? | `k8s_rbac_scope_v1` |

These properties resolve declared references and scope. They do not simulate
authorization or prove that a principal can perform an action.

## Terraform and OpenTofu references

| Stable property ID | Artifact | Subject | Required parameters | Exact bounded question | Witness |
| --- | --- | --- | --- | --- | --- |
| `IACGV_TF_REFERENCE_RESOLVES_V1` | `terraform_source` | Terraform resource | `attribute_path`, `expected_target`; optional direct/transitive mode and completeness evidence | Does the selected `.tf` source attribute resolve to the declared source-local target under the Terraform V1 boundary? | `terraform_reference_v1` |
| `IACGV_OPENTOFU_REFERENCE_RESOLVES_V1` | `opentofu_source` | OpenTofu resource | same closed reference parameters | Does the effective OpenTofu file-set attribute resolve to the declared bounded local target after `.tofu` and JSON precedence? | `opentofu_reference_v1` |

When `complete_expected_domain` is true, a 64-character
`reference_contract_digest` is required. Provider evaluation, remote modules, dynamic
expressions outside the reviewed subset, plans, `init`, and `apply` are not inferred.

## Examples and limitations

The packaged `examples/quickstart` directory contains positive, violated, and
not-evaluated Kubernetes fixtures plus a positive Terraform reference. These examples
show the result model; they do not expand the supported semantics. Full executable
positive, negative, ambiguous, incomplete, and adversarial coverage is bound to the
stable property freeze tests.
