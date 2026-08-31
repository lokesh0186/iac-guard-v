# Dgraph charts PR #146: conditional Zero monitoring ingress omission

Third-party pull request:
[`dgraph-io/charts#146`](https://github.com/dgraph-io/charts/pull/146)

Classification: `TIER_A_PR_DEFECT / PUBLIC_APPLICATION /
EXTERNAL_TECHNICAL_OUTREACH`

## Verifier

IaC-Guard-V `0.1.0a8`

PyPI: [`iac-guard-v==0.1.0a8`](https://pypi.org/project/iac-guard-v/0.1.0a8/)

Software DOI: https://doi.org/10.5281/zenodo.22167878

- IaC-Guard-V source: `aa82d1879786986a5e62dad55fa0fea8b8bbbcea`
- Public wheel SHA256:
  `ef62cfedd3c4f8a3fa2bbdf4bad241a17c0f2c076a37cd6fc7bb008a0476015c`
- Checkov: `3.3.0` (authoritative scanner path)
- Helm: `v4.2.4+g3900f43` (A8 materialization and native-render
  corroboration)

## Exact upstream identity

- Pull-request state at final recheck: open
- Base: `794d90eed9d480932a5c9e08323c0bd795fc8e6a`
- Head: `fe013a6d24ef21b6812cd2f55f28246f444ef563`
- Head tree: `fd770dd5f0f22fab92dfea78f69ed9308b903711`
- Dgraph chart tree: `b374ebf4227ff9bd281ab70866074c868e67ad93`
- The head remained the previously confirmed single commit.
- Final recheck found the same four review comments and no issue comments. No
  comment, review, issue, or related PR raised or fixed the exact Zero 6080
  ServiceMonitor/NetworkPolicy relationship.

[SOURCE_IDENTITY.json](SOURCE_IDENTITY.json) binds the retained sources and
[CHART_TREE.txt](CHART_TREE.txt) inventories every Git object under
`charts/dgraph` at the head.

## Conditional configuration

This is not a default-install finding. Both features default to `false`. The
finding concerns the supported combination in [CONFIGURATION.yaml](CONFIGURATION.yaml):

```yaml
serviceMonitor:
  enabled: true
networkPolicy:
  enabled: true
  clientPodLabels: {}
  extraIngress: []
```

In words: the chart's built-in ServiceMonitor and NetworkPolicy are enabled
together without an additional user-provided ingress rule.

## Narrow configuration relationship

The exact native render establishes this declared path:

```text
Prometheus or PrometheusAgent source external to this chart
  -> ServiceMonitor dgraph-system/adjudicate-dgraph endpoint http-zero
  -> Service dgraph-system/adjudicate-dgraph-zero
  -> TCP 6080 / targetPort 6080
  -> StatefulSet Zero pod container adjudicate-dgraph-zero TCP 6080
```

The ServiceMonitor selector matches the Alpha and Zero ClusterIP Services. The
Zero Service selects the Zero pod-template labels
`app=dgraph`, `release=adjudicate`, and `component=zero`; its `http-zero` port
resolves `6080 -> 6080`, and the Zero container exposes named TCP port
`http-zero` on 6080.

The only rendered NetworkPolicy is
`networking.k8s.io/v1 NetworkPolicy
dgraph-system/adjudicate-dgraph`. Its selector `app=dgraph,
release=adjudicate` matches the Zero pods, and `policyTypes: [Ingress]`
establishes ingress isolation under standard Kubernetes NetworkPolicy
semantics.

The complete applicable rendered ingress-rule union contains one rule: all
destination ports from same-namespace pods carrying this release's Dgraph
labels. It does not match an ordinary Prometheus workload. Because
`clientPodLabels` is empty, the optional client rule is not rendered. If
configured, that source contract is explicitly for Alpha clients and contains
TCP 8080/9080, not Zero 6080. `extraIngress` is empty, and there is no separate
chart-rendered monitoring policy.

Therefore the chart-rendered policy set contains no rule permitting an ordinary
monitoring source to the declared Zero TCP 6080 endpoint in this exact
configuration. Under standard semantics, this appears to prevent the declared
scrape unless a user-provided `extraIngress` rule or another applicable
NetworkPolicy permits it.

[RELATIONSHIP_EVIDENCE.json](RELATIONSHIP_EVIDENCE.json) records every identity,
selector, port, policy type, and applicable rule used in that conclusion.

## Authoritative IaC-Guard-V result

[REPORT.json](REPORT.json) is IaC-Guard-V 0.1.0a8 candidate-acceptance evidence
over the exact chart head with `networkPolicy.enabled=true`. The selected
property is `CKV2_K8S_6` for
`apps/v1/StatefulSet/dgraph-system/adjudicate-dgraph-zero`.

- Verdict: `VERIFIED`
- Property: `SATISFIED / CANDIDATE_PROPERTY_SATISFIED`
- Graph evidence: `PASS / GRAPH_EVIDENCE_COMPLETE`
- Exact graph edge:
  `NetworkPolicy/dgraph-system/adjudicate-dgraph` ->
  `StatefulSet/dgraph-system/adjudicate-dgraph-zero`
- Relation: `kubernetes_network_policy_selector`
- Evidence universe: 12/12 expected resources observed, none missing or
  unexpected
- Candidate snapshot SHA256:
  `43fa2e4ed69cca59b99e8d1e577976b15b68a50eaaa7ebdf15defeaf6dd6e9cd`
- Report SHA256:
  `b0697e23858a7b542cda4ebd0e20fbef13bcfa31e4d2cf97e079364fef89b57a`

This authoritatively establishes and source-binds the rendered
NetworkPolicy-to-Zero selection relationship. The report also retains the exact
rendered policy and target evidence. See [A8_EXECUTION.json](A8_EXECUTION.json)
and [SELECTED_PROPERTY.json](SELECTED_PROPERTY.json).

## Corroborating configuration semantics

IaC-Guard-V 0.1.0a8 does not model ServiceMonitor CRD endpoint resolution or
live packet reachability. The authoritative A8 universe therefore leaves
`serviceMonitor.enabled` at its default `false`; admitting that external CRD
without local CRD namespace-provenance evidence would exceed a8's supported
claim scope.

The two-feature Helm render is retained separately in [MATERIALIZATION.json](MATERIALIZATION.json),
[RESOURCE_INVENTORY.json](RESOURCE_INVENTORY.json), and `rendered/`. Those
committed resources corroborate the ServiceMonitor -> Service -> Zero TCP 6080
resolution and the complete applicable ingress-rule comparison.

The combined claim is deliberately bounded: IaC-Guard-V establishes the
protected policy-to-Zero relationship; deterministic configuration analysis of
the same chart head resolves the monitoring path and finds no chart-rendered
ordinary-monitoring-source allowance to 6080.

No live cluster or packet test was used. This packet does not say IaC-Guard-V
experimentally observed dropped Prometheus traffic.

## Native render and CI context

Two native Helm renders of the conditional configuration were byte-identical.
Their full rendered file-set digest is
`6864c5f3a72c8fa7ec77209addce481e842d25194f1223b90ebfa234a0672420`.
`helm lint` passed with `1 chart(s) linted, 0 chart(s) failed`.

PR #146 adds no tests. The repository's sole workflow is a main-branch release
workflow, and the exact head has no check runs or commit statuses. Existing
repository test material does not establish the ServiceMonitor -> Service ->
Zero 6080 -> NetworkPolicy relationship. This is a factual description of the
property exercised, not criticism of the project's testing choices.

## Scope limits

- This is a conditional feature-composition gap, monitoring-specific ingress
  omission, and NetworkPolicy/ServiceMonitor configuration mismatch.
- It is not characterized as a vulnerability, outage, exploit, severity result,
  or default-chart breakage.
- NetworkPolicy enforcement requires a supporting network implementation.
- Another independently installed additive NetworkPolicy, a user-provided
  `extraIngress` rule, node-origin semantics, or implementation-specific source
  handling can change runtime reachability.
- The chart does not define the Prometheus deployment's exact pod labels or
  namespace, so this packet does not prescribe those selectors.
- The claim covers only resources rendered by the exact PR/configuration and is
  not whole-PR or whole-cluster verification.
- No acknowledgement, reliance, adoption, or remediation is claimed without
  independent maintainer action.

See [REPRODUCE.md](REPRODUCE.md) for replay commands and
[CLAIM_LEDGER.md](CLAIM_LEDGER.md) for the claim/boundary ledger. Every retained
file is bound by [SHA256SUMS](SHA256SUMS).
