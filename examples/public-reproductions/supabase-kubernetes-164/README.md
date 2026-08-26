# Supabase Kubernetes PR #164: NetworkPolicy relationship evidence

Third-party pull request:
[supabase-community/supabase-kubernetes#164](https://github.com/supabase-community/supabase-kubernetes/pull/164)

Verified repository identities:

- Base: `b6b399f1cc994e609cbaff4e1652a6c4a79381ee`
- Candidate head: `8d23520955879cb06c020d6dfe6f975a372f2ee6`

Verifier:

- IaC-Guard-V `0.1.0a6`
- PyPI: `iac-guard-v==0.1.0a6`
- Public wheel SHA-256: `5f39e41478fc30c5f2a7af1e2008059178d7eaadeb91dea67ac9446fd472b256`
- Software DOI: [10.5281/zenodo.22105295](https://doi.org/10.5281/zenodo.22105295)
- Concept DOI: [10.5281/zenodo.22088272](https://doi.org/10.5281/zenodo.22088272)
- Checkov `3.3.0`
- Helm `4.2.4`, Darwin arm64 executable SHA-256 `ebf04b3606784d48568cf386483ac2b81fc747ed77859da4ba4f77df4c5e81d3`

## Protected result

The candidate chart was rendered twice with these exact protected inputs:

- Chart: `charts/supabase`
- Release: `supabase`
- Namespace: `default`
- Kubernetes version: `1.31.0`
- Values files: none
- Typed override: `networkPolicies.enabled=true`
- CRDs: excluded
- Helm tests: excluded

The renders were byte-identical. IaC-Guard-V retained all `63/63` rendered
resources in the governed universe and returned `VERIFIED` in
`candidate_acceptance` mode for three selected Checkov `CKV2_K8S_6`
properties:

1. `apps/v1/Deployment/default/supabase-supabase-auth` is selected by
   `networking.k8s.io/v1/NetworkPolicy/default/supabase-supabase-auth-netpol`.
2. `apps/v1/Deployment/default/supabase-supabase-kong` is selected by
   `networking.k8s.io/v1/NetworkPolicy/default/supabase-supabase-kong-netpol`.
3. `apps/v1/Deployment/default/supabase-supabase-rest` is selected by
   `networking.k8s.io/v1/NetworkPolicy/default/supabase-supabase-rest-netpol`.

Each selected outcome is `SATISFIED`; none is labelled `FIXED`. Scanner
integrity and Kubernetes parsing pass. The raw Checkov run remains `PARTIAL`,
and all `282` unselected failed findings are preserved and digest-bound rather
than hidden.

This evidence establishes the exact policy-to-workload relationships and the
protected rendered universe. It does **not** formally certify every egress peer.

## Peer-semantics review finding

Reviewing the exact governed Auth and REST policies against Kubernetes
NetworkPolicy semantics exposed two proposed-policy correctness problems:

1. Auth's SMTP ports `465`/`587` and HTTPS/OAuth port `443` use
   `namespaceSelector: {}`. That peer selects Pods across Kubernetes
   namespaces; it does not represent ordinary external SMTP or OAuth Internet
   destinations. Once Auth is egress-isolated, those rules alone do not allow
   ordinary external destinations.
2. Auth and REST use `namespaceSelector: {}` on PostgreSQL port `5432`. This
   permits matching Pod destinations across every namespace instead of
   restricting egress to the intended Supabase database workload.

These are respectively a NetworkPolicy functional/correctness defect and a
least-privilege policy-scoping defect. This packet does not characterize either
as a security vulnerability.

See [FINDING.md](FINDING.md) for the Kubernetes semantics and runtime caveats,
[policy-inventory.json](policy-inventory.json) for the bounded policy inventory,
and [REPRODUCE.md](REPRODUCE.md) for the public-package replay.

## Evidence identities

- Chart inventory root: `da192d2a3cff83064a014f84ffe046ca2751161a391fcf35f2852a524a82b7b4`
- Helm materialization: `9300217b112b86aeb2b5d6aff170b3d2d484a3bb837b8d7bb6403e04d5f12804`
- Combined universe: `49de8c5c4a789ae0671dfcf258605ffbc11fb0858fd0394667c6d4c986977564`
- Rendered bundle: `5737e5db441957893490cf7fae857b7641a194d35ba4ec3182b2c1bf52e17715`
- Rendered document inventory: `fefd260746bf7b90275b8e153cfd9ff9743d7f22490bd97fb0783f97ae1e9d24`
- Source snapshot: `e729214743af78a6955048aebd18883cb3e1c35fbd0c23980996e500ce7eee64`
- Unselected failed findings: `282`
- Unselected-finding digest: `4155567b7665bf9a85d44f56834f884e72c396fdde92df02c3686c38ad32bbc5`

Canonical report SHA-256:

```text
d12cb5e92978ea66170a16d605402171014987083498ad821c0b28c5af34f314  report.json
```

## Scope and product boundary

This is candidate-property acceptance, not baseline repair verification and not
a whole-chart or whole-PR security claim. It does not establish CNI enforcement,
runtime connectivity, application security, or correctness of unselected
findings.

A separate protected request using a non-default namespace failed closed with
`INVALID_REQUEST` because its graph evidence escaped the rendered universe.
That public-a6 product boundary is separate from—and does not invalidate—the
canonical default-namespace result above. No product change was made for this
packet.

