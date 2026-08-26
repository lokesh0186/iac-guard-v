# NetworkPolicy egress peer review

## Authoritative Kubernetes semantics

The current Kubernetes NetworkPolicy documentation establishes that:

- an egress rule allows traffic that matches both its `to` and `ports`
  sections;
- `namespaceSelector` selects namespaces by labels, and without a combined
  `podSelector` it allows all Pods in those selected namespaces;
- an empty label selector matches all labels, so `namespaceSelector: {}`
  selects all namespaces;
- `namespaceSelector` describes namespace/Pod peers, not arbitrary Internet or
  FQDN destinations;
- `ipBlock` selects CIDR ranges and is typically used for cluster-external IP
  ranges.

Authoritative reference:
[Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

The generated Kubernetes API definition also states explicitly that an empty
label selector matches all objects:
[Kubernetes LabelSelector](https://kubernetes.io/docs/reference/kubernetes-api/definitions/label-selector-v1-meta/)

The standard NetworkPolicy API does not provide DNS/FQDN peer selectors.

## Finding A: Auth external egress

The PR commit states that Auth egress permits DB, DNS, SMTP, and HTTPS. The
governed rendered Auth policy uses:

- `namespaceSelector: {}` for TCP `587` and `465`;
- `namespaceSelector: {}` for TCP `443`.

Those peers consist of Pods across all Kubernetes namespaces. They do not
describe ordinary external SMTP or OAuth/HTTPS Internet destinations. Because
the policy selects Auth and includes `Egress` in `policyTypes`, Auth becomes
egress-isolated. These rules by themselves therefore do not authorize ordinary
external SMTP/OAuth destinations.

Narrow characterization: **NetworkPolicy functional/correctness defect**.

## Finding B: PostgreSQL peer scope

The governed Auth and REST policies both render:

- `namespaceSelector: {}`
- TCP `5432`

This allows matching Pod destinations across every namespace on TCP `5432`.
It does not restrict the peer to the intended Supabase database workload.

Narrow characterization: **least-privilege / policy-scoping defect**.

This finding does not claim that the rules authorize arbitrary Internet
PostgreSQL endpoints.

## Runtime caveats

- NetworkPolicy enforcement requires a networking plugin that implements the
  API. Merely creating a NetworkPolicy has no effect without one.
- Kubernetes documents that source/destination address rewriting can occur
  before or after policy processing depending on the network plugin, cloud
  provider, and Service implementation.
- This packet makes no claim about a particular CNI or live cluster.

## Why this is new review information

The PR adds no native policy test. Its default value leaves
`networkPolicies.enabled=false`, so ordinary default chart checks do not render
the three policies. At evidence publication time, the PR had no CI checks,
reviews, or comments addressing these egress-peer semantics. The separate
merged database NetworkPolicy PR #167 concerns database ingress and does not
correct these Auth/REST egress rules.

The likely repair depends on maintainer intent: the database may be in-chart or
external, while SMTP/OAuth endpoints may need deployment-specific CIDR peers or
a separately documented network mechanism. This packet intentionally does not
guess that contract.
