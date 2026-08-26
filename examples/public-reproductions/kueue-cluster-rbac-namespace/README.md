# Kueue cluster-scoped RBAC namespace reproduction

This packet records a narrow, pre-existing Helm chart correctness defect at Kueue
revision `09560ad1624f75cb26cdd440281160f0b4cec776`.

With KueueViz enabled and the Helm release namespace set to `default`, the chart
deterministically renders these cluster-scoped RBAC resources with a top-level
`metadata.namespace: default`:

- `ClusterRole/kueue-kueueviz-backend-read-access`
- `ClusterRoleBinding/kueue-kueueviz-backend-read-access-binding`

Kubernetes defines both resource kinds as cluster-scoped. Kubernetes v1.36.3
validation rejects their non-empty `metadata.namespace` with `Forbidden: not allowed
on this type`. The namespace on the `ServiceAccount` subject inside the
`ClusterRoleBinding` is valid and is not part of this finding.

IaC-Guard-V `0.1.0a6`, installed from public PyPI, independently stops the protected
Helm materialization with `CONTRADICTORY_NAMESPACE_PROVENANCE`. The final result is
fail-closed `INCONCLUSIVE`; this packet does not reinterpret that operational result as
`VERIFIED`.

## Scope and provenance

- Kueue source: <https://github.com/kubernetes-sigs/kueue/tree/09560ad1624f75cb26cdd440281160f0b4cec776>
- Kueue chart tree: `charts/kueue` Git tree `7efec26f36dffc96279e9fa5bd310d8228ca04e5`
- ClusterRole source: `charts/kueue/templates/kueueviz/clusterrole.yaml`
  - SHA-256: `67b3c10f6abb84a73dbf6a46e20aca0e1224bc6407cad11b24988cf2c2f189e7`
- ClusterRoleBinding source: `charts/kueue/templates/kueueviz/cluster-role-binding.yaml`
  - SHA-256: `a93ce667e25757c3f374cb9f68dfcc4dd3db00b1b7deef43af7234e158c345d3`
- Rendered manifest SHA-256, identical across two fresh Helm environments:
  `8b9f39e5b10871cdc53901c874eb2c9d5411849a7670e5b58cde8b56dc1e4106`
- Helm: `v4.2.4+g3900f43`
  - executable SHA-256: `ebf04b3606784d48568cf386483ac2b81fc747ed77859da4ba4f77df4c5e81d3`
- Checkov: `3.3.0`
- Verifier: IaC-Guard-V `0.1.0a6`
- PyPI: `iac-guard-v==0.1.0a6`
- Software DOI: <https://doi.org/10.5281/zenodo.22105295>
- Concept DOI: <https://doi.org/10.5281/zenodo.22088272>
- Canonical report SHA-256:
  `2c3ae74c60d696da63bd61ba4e6c43822bdddfb1319c93bf065eee37b9e262eb`

The metadata existed before and independently of Kueue PR #14142; this packet does
not attribute the defect to that PR. This is not a security-vulnerability or
whole-chart claim. It establishes a manifest/API correctness and portability defect
for two exact RBAC objects.

## Authoritative references

- Kubernetes RBAC documentation identifies `ClusterRole` as non-namespaced and
  `ClusterRoleBinding` as cluster-wide:
  <https://kubernetes.io/docs/reference/access-authn-authz/rbac/>
- Kubernetes v1.36.3 validates both types with non-namespaced object metadata:
  <https://github.com/kubernetes/kubernetes/blob/v1.36.3/pkg/apis/rbac/validation/validation.go>
- Kubernetes object-metadata validation forbids a namespace when the type is not
  namespaced:
  <https://github.com/kubernetes/apimachinery/blob/v0.36.3/pkg/api/validation/objectmeta.go>

See [REPRODUCE.md](REPRODUCE.md) for the exact public-package reproduction and the
isolated generic fixture.
