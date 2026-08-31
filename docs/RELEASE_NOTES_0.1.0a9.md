# IaC-Guard-V 0.1.0a9 release notes

IaC-Guard-V 0.1.0a9 is a bounded native semantic verification release. It adds
scanner-independent verification contracts for selected infrastructure properties over
protected deterministic artifacts. It does not turn IaC-Guard-V into a general policy
engine or replace infrastructure scanners.

## Added in alpha 9

- A witness-first native property framework with versioned definitions, requests,
  observations, implementation identities, semantic-version bindings, and validated
  evidence schemas.
- Exact protected Kubernetes workload, pod-template, namespace, label-selector, and
  container-occurrence identities for the reviewed controller set.
- NetworkPolicy selection and direction-specific isolation properties, additive-rule
  evaluation, and caller-bounded component/workload policy closure.
- Service-to-workload and ServicePort-to-container-port resolution with exact selector,
  name, port, protocol, and ambiguity witnesses.
- Bounded NetworkPolicy plus Service path composition over the protected rendered
  policy set.
- Bounded ServiceMonitor and PodMonitor composition under the allowlisted
  `monitoring.coreos.com/v1` contract; this
  is not a general custom-resource interpreter.
- RBAC binding identity and scope relationships for the reviewed RoleBinding,
  ClusterRoleBinding, roleRef, and ServiceAccount-subject contracts. A RoleBinding may
  validly bind a ServiceAccount from another namespace while granting permissions in
  the RoleBinding namespace.
- Exact source-local Terraform resource-reference relationships when the protected
  source identities and expression are uniquely resolvable without runtime, provider,
  module, `count`, or `for_each` evaluation.
- Structured fail-closed diagnostics for `NOT_EVALUATED`, `UNSUPPORTED`, and `ERROR`
  outcomes as well as mechanical witnesses for `SATISFIED` and `VIOLATED`.

## Authority and interpretation

- Checkov 3.3.0 remains supported and authoritative for its existing reviewed scanner
  paths. Its alpha 8 semantics are unchanged.
- KICS and Trivy remain advisory. Alpha 9 does not infer selected-target PASS from
  absence, promote either scanner to authority, or use scanner voting.
- Native IaC-Guard-V properties have independent semantic identities; they are not
  silently equated to Checkov, KICS, or Trivy checks.
- Mechanical property violations do not automatically establish project defects,
  vulnerabilities, outages, or project intent. Contextual defect classification remains
  a separate review activity.

## Deliberate boundaries

- Network-path observations concern only the modeled Kubernetes manifest semantics.
  They do not prove live CNI enforcement, packet delivery, routing, DNS, service-mesh,
  NAT, cloud-firewall, readiness, or other runtime behavior.
- Alpha 9 does not claim general Kubernetes network reachability, arbitrary custom-
  resource interpretation, an authorization simulator, arbitrary Terraform evaluation,
  or general infrastructure security verification.
- General Helm interpretation, remote dependency acquisition, live Kubernetes/cloud
  state, arbitrary Kustomize transformers, and unsupported dynamic semantics remain
  outside scope and fail closed.
- New generic container security-context checks and generic Terraform attribute checks
  are deliberately excluded; existing reviewed Checkov paths remain available for
  those property classes.
- Native execution remains reduced isolation for operator-controlled input only; the
  hostile-input container and GitHub Action are not released.

Every supported native verdict is bound to exact protected input, resource-universe,
property-definition, implementation, and witness identities. Uncertainty remains an
explicit result rather than being converted into success.

## Public release identities

- GitHub prerelease: [v0.1.0-alpha.9](https://github.com/lokesh0186/iac-guard-v/releases/tag/v0.1.0-alpha.9)
- PyPI: [iac-guard-v 0.1.0a9](https://pypi.org/project/iac-guard-v/0.1.0a9/)
- Version DOI: [`10.5281/zenodo.22216372`](https://doi.org/10.5281/zenodo.22216372)
- Concept DOI: [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272)
