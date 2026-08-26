# Helm namespace provenance

IaC-Guard-V binds three distinct namespace facts for each protected Helm render:

- the requested Helm release namespace;
- the namespace text emitted in `metadata.namespace`, if any;
- the effective namespace used by the Kubernetes API identity.

For a known namespaced kind, an omitted namespace defaults to the protected release
namespace. An explicit namespace remains source-bound, and unsupported dynamic
construction or contradictory protected evidence fails closed.

For a known cluster-scoped kind, the Kubernetes API server clears namespace before
object validation. IaC-Guard-V therefore records the effective namespace as absent.
If the rendered manifest contains `metadata.namespace`, that exact value remains in
the governed provenance and in the Checkov-facing address because Checkov 3.3.0 reports
the emitted value. The metadata is redundant, but it is not classified as
`CONTRADICTORY_NAMESPACE_PROVENANCE` solely for being present.

Two cluster-scoped objects with the same API version, kind, and name collide even if
their rendered namespace strings differ. IaC-Guard-V rejects that normalized duplicate
identity. Unknown custom-resource scope remains inconclusive unless an exact local CRD
proves it.

This model follows the API server create path, where namespace normalization occurs
before strategy validation. It does not claim live-cluster admission or runtime
verification.

Authoritative implementation references:

- [Kubernetes generic REST create handling](https://github.com/kubernetes/kubernetes/blob/v1.36.3/staging/src/k8s.io/apiserver/pkg/registry/rest/create.go)
- [Kubernetes request-namespace normalization](https://github.com/kubernetes/kubernetes/blob/v1.36.3/staging/src/k8s.io/apiserver/pkg/registry/rest/meta.go)
