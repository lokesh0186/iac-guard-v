# Quay Operator PR #1322: upgrade-workload NetworkPolicy relationships

Third-party pull request:
[quay/quay-operator#1322](https://github.com/quay/quay-operator/pull/1322)

## Verifier

IaC-Guard-V `0.1.0a8`

PyPI: [`iac-guard-v==0.1.0a8`](https://pypi.org/project/iac-guard-v/0.1.0a8/)

Software DOI: https://doi.org/10.5281/zenodo.22167878

- IaC-Guard-V source: `aa82d1879786986a5e62dad55fa0fea8b8bbbcea`
- Public wheel SHA256:
  `ef62cfedd3c4f8a3fa2bbdf4bad241a17c0f2c076a37cd6fc7bb008a0476015c`
- Checkov: `3.3.0` (authoritative scanner path)
- Kustomize: `v5.7.1` (native-render corroboration only)

## Exact upstream identity

- Pull-request state at final recheck: open
- Base: `bff5e1b5315f02bfc2373cb2e7039fb7e653a783`
- Head: `1340fe9cdae651a0e36fc27a4322b2a2f5872223`
- Head tree: `4527f67d7f4a258ac84c64ccccd42fc737db0a93`
- Complete head source-manifest SHA256:
  `81da943bca7568cb28ff8fea827c6c38f8fcc8cff7fc8bcae2d1e7dbeaace77f`
- Final recheck: no later commit, review, comment, or public duplicate addressing the
  exact upgrade-workload selector gap was found.

See [SOURCE_IDENTITY.json](SOURCE_IDENTITY.json) for the bound source paths and hashes.

## Narrow finding

PR #1322 adds default NetworkPolicies for managed components. The Clair PostgreSQL
upgrade closure contains two additional workloads that are selector-disjoint from all
three policies in that closure:

1. Deployment `clair-postgres-old`
2. Job `clair-postgres-upgrade`

The old Deployment's pod template has:

```yaml
quay-component: clair-postgres-old
```

The new ordinary Clair PostgreSQL policy selects:

```yaml
quay-component: clair-postgres
```

The migration Job's committed manifest puts `quay-component: clair-postgres-upgrade`
on the Job object, not on `spec.template.metadata.labels`. The native render adds the
operator-wide label `quay-operator/quayregistry: a8` to its pod template. None of the
three applicable policies selects that label set.

For both rendered targets:

- property: `CKV2_K8S_6`
- outcome: `VIOLATED`
- reason: `CANDIDATE_PROPERTY_VIOLATED`
- applicable NetworkPolicies: 3
- selecting NetworkPolicies: 0
- relationship classifications: 3 × `SELECTOR_DISJOINT`
- graph evidence: `PASS / TARGET_RELEVANT_GRAPH_EVIDENCE_COMPLETE`
- scanner integrity: `PASS / SCANNER_EVIDENCE_COMPLETE`
- files parsed: 8/8
- expected resources observed: 8/8
- parse errors, failed files, missing resources, and unexpected resources: 0

Kubernetes NetworkPolicy is selector-based: a pod is isolated in a direction only when
a policy selecting that pod establishes that isolation. This packet therefore describes
an upgrade-path policy-coverage gap. It does not characterize the finding as a
vulnerability and does not prescribe the required migration traffic.

## Authoritative primary claim

[REPORT.json](REPORT.json) is IaC-Guard-V candidate-acceptance evidence over eight exact
committed Kubernetes resources copied byte-for-byte from the PR head. It authoritatively
establishes for `apps/v1/Deployment/default/clair-postgres-old`:

- `CKV2_K8S_6: VIOLATED`
- `CANDIDATE_PROPERTY_VIOLATED`
- complete target-relevant scanner and graph evidence
- all three governed NetworkPolicies proven selector-disjoint

The exact-source snapshot SHA256 is
`d4fe01c56a542df7652234ee7cba9a7b99e205f24362674e7fcadae4ed072519`.
The report SHA256 is
`ba7e311c54e4026b7678786f21d81e57ce9a6e4c10cd3d87c7c86106743998ee`.

Checkov's raw-source `CKV2_K8S_6` semantics do not address the Job before a pod-template
label exists. The primary report therefore governs the committed Job but classifies it
`CHECK_SEMANTICS_EXCLUDES_RESOURCE_TYPE`; it does not silently turn that boundary into
an exact-source pass or failure.

## Native-render corroboration

The operator assembly test identifies the relevant component closure as `redis`,
`clairpostgres`, and `clairpgupgrade/base` when `NeedsClairPgUpgrade` is true and Clair
is unmanaged. Native Kustomize `v5.7.1` was used to reproduce that closure with an
explicit namespace, prefix, and common registry label.

[REPORT-rendered.json](REPORT-rendered.json) evaluates the eight relationship-relevant
rendered resources. It establishes `VIOLATED` for both the old Deployment and migration
Job, with complete target-relevant evidence and zero selecting policies.

This is corroboration of the selector relationship. It is not a claim that IaC-Guard-V
authoritatively supports the repository's complete generated Kustomization. That
generated control uses legacy `vars`, which remains outside a8's bounded
`kustomize-accept` contract. The native transformations preserve the relevant disjoint
`quay-component` values.

See [MATERIALIZATION.json](MATERIALIZATION.json) for the exact render identities and
[SELECTED_PROPERTIES.json](SELECTED_PROPERTIES.json) for both target records.

## Why this adds information beyond existing checks

Substantive CI at the exact head was green. The existing Chainsaw assertion verifies
the presence of seven named NetworkPolicy objects. It does not assert these two
selector-to-workload relationships. The standard E2E path does not exercise
`NeedsClairPgUpgrade`, while unit coverage verifies the component assembly rather than
the resulting policy selection.

This is a factual statement about the property currently exercised, not criticism of
the project's CI strategy.

## Scope limits

This packet is limited to the exact PR head, the Clair PostgreSQL upgrade closure, and
`CKV2_K8S_6`. It does not claim whole-PR correctness, whole-namespace policy coverage,
runtime CNI behavior, exploitability, severity, or a particular allowed-connectivity
design. Target-scoped evidence is not whole-change verification.

See [REPRODUCE.md](REPRODUCE.md) for public replay commands and
[CLAIM_LEDGER.md](CLAIM_LEDGER.md) for the claim/boundary ledger. Every retained file is
bound by [SHA256SUMS](SHA256SUMS).
