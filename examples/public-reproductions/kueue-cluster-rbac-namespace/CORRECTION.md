# Correction to the Kueue namespace interpretation

The immutable evidence commit recorded the exact behavior of public IaC-Guard-V
`0.1.0a6` and a direct RBAC object-validation result. Its conclusion that the
Kubernetes API server rejects these objects was incomplete.

In the full API server create path, Kubernetes clears `metadata.namespace` for a
cluster-scoped request before object validation. The rendered namespace on the KueueViz
`ClusterRole` and `ClusterRoleBinding` is therefore normalized away rather than rejected.
The upstream change remains a useful manifest cleanup that aligns the YAML with the
scope of those resources and preserves the valid namespace on the `ServiceAccount`
subject.

The original report remains unchanged as an immutable record of `0.1.0a6` behavior.
Current product work corrects the namespace-provenance model so the emitted value stays
governed while the effective Kubernetes namespace is recorded as absent.

Authoritative implementation references:

- [Kubernetes generic REST create handling](https://github.com/kubernetes/kubernetes/blob/v1.36.3/staging/src/k8s.io/apiserver/pkg/registry/rest/create.go)
- [Kubernetes request-namespace normalization](https://github.com/kubernetes/kubernetes/blob/v1.36.3/staging/src/k8s.io/apiserver/pkg/registry/rest/meta.go)
