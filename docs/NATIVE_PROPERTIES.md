# Native semantic properties

IaC-Guard-V native properties are scanner-independent verification contracts over one
content-bound, deterministic infrastructure artifact. They do not replace Checkov,
KICS, or Trivy, and they do not change the authority of any a8 scanner path.

The `0.1.0a9` native boundary is additive and versioned separately:

- request: `native-property-request-v1`;
- evidence: `native-property-report-v1`;
- property namespace: `iac_guard_v`;
- results: `SATISFIED`, `VIOLATED`, `NOT_EVALUATED`, `UNSUPPORTED`, `ERROR`.

`SATISFIED` and `VIOLATED` are mechanical property results. They are not automatic
claims of a project bug, vulnerability, outage, or runtime behavior.

## Invocation

The native command accepts operator-controlled local configuration only:

```console
python -m iac_guard_v.native_properties --config native-request.json --format json
```

A minimal request is:

```json
{
  "schema_version": "native-property-request-v1",
  "root": "rendered",
  "artifact_class": "kubernetes_rendered",
  "requests": [
    {
      "request_id": "policy-selection",
      "property_id": "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1",
      "property_version": "1",
      "subject_identity": "apps/v1/Deployment/default/example",
      "parameters": {}
    }
  ]
}
```

The root is relative to the configuration file and cannot escape its directory. Native
evaluation reads exact local bytes, rejects duplicate canonical identities, and binds
every observation to the complete input and resource-inventory digests.

## Authorized property inventory

The a9 implementation contains only the final authorized families:

- workload selection and direction-specific NetworkPolicy isolation;
- caller-bound component/policy closure;
- Service selector and ServicePort/container-port relationships;
- bounded ingress, egress, Pod-to-Pod, and rendered-policy-denial semantics;
- allowlisted `monitoring.coreos.com/v1` ServiceMonitor and PodMonitor target graphs;
- RBAC roleRef, ServiceAccount subject, and scope relationships;
- direct source-local Terraform resource references.

The packaged registry records every property version, parameter-schema digest,
semantic-contract digest, implementation/module digest, semantic version binding,
capability declaration, and witness type.

## Witness and uncertainty boundary

Every result, including uncertainty, has a structured witness. Authoritative results
are rejected unless their property-specific witness mechanically agrees with the
result. Serialized reports are revalidated against the packaged definition registry,
parameter, witness, observation, report, input-universe, and implementation identities.

Unresolved named ports, incomplete policy sets, unknown Pod IPs against `ipBlock`,
ambiguous selectors or identities, unsupported monitor contracts, external RBAC
identities, Terraform dynamic/module/provider semantics, and other material uncertainty
fail closed.

Network-path results describe Kubernetes manifest NetworkPolicy semantics only. They do
not establish CNI enforcement, packet delivery, DNS, service-mesh behavior, cloud
firewalls, NAT, routing, readiness, or live state.

RBAC relationship results keep three questions separate: roleRef resolution,
ServiceAccount subject resolution, and binding scope consistency. A RoleBinding grants
permissions in its own namespace but may name a ServiceAccount in another namespace.
When a RoleBinding ServiceAccount subject omits `namespace`, Kubernetes matches it in
the RoleBinding namespace; ClusterRoleBinding ServiceAccount subjects require an
explicit namespace. User and Group subjects are non-namespaced, and any serialized
subject `namespace` field does not become a ServiceAccount-style identity.

## Explicit boundaries

There are no new generic security-context checks or public Terraform attribute checks.
KICS and Trivy remain advisory; Checkov 3.3.0 retains its existing a8 authority. There
is no voting, inferred scanner PASS, arbitrary CRD interpreter, authorization simulator,
general Terraform evaluator, remote dependency resolver, cloud API, or live cluster
path.
