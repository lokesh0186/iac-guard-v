# Teranode PR #1617: NetworkPolicy relationship verification

This directory preserves independent IaC-Guard-V evidence for the
NetworkPolicy hardening portion of
[bsv-blockchain `teranode` PR #1617](https://github.com/bsv-blockchain/teranode/pull/1617).

## Exact reviewed identity

- Pull request: <https://github.com/bsv-blockchain/teranode/pull/1617>
- State at final recheck: open
- Base: `e01f7bca875225b14142c8068d799ec1d722c395`
- Head: `4b25d8289645324b7eb556782f46e5c7b1d26b45`
- IaC-Guard-V: public PyPI `0.1.0a3`
- Published wheel SHA-256: `7de633ff85595052c04a9fad2aa156a2e3f77062ba7d118f5a35fb15fd08405b`
- Checkov: `3.3.0`
- Python: `3.11.6`

The installed distribution records `INSTALLER = pip` and has no
`direct_url.json`, consistent with an index installation rather than a local
source or editable install.

## Verified scope

This verifies only the `CKV2_K8S_6` workload-to-NetworkPolicy relationship for
`kafka-shared`.

Only this relationship is verified:

```text
CKV2_K8S_6
apps/v1/Deployment/default/kafka-shared
    <- kubernetes_network_policy_selector -
networking.k8s.io/v1/NetworkPolicy/default/kafka-shared
```

Native Checkov behavior on the exact module snapshot:

| Revision | CKV2_K8S_6 | Resource |
| --- | --- | --- |
| base | fail | `Pod.default.kafka-shared.io.kompose.service-kafka-shared` |
| head | pass | `Pod.default.kafka-shared.io.kompose.service-kafka-shared` |

IaC-Guard-V canonicalizes the target as
`apps/v1/Deployment/default/kafka-shared`, binds the candidate NetworkPolicy
participant and selector edge, and reports:

```text
target: FIXED
scanner integrity: PASS
Kubernetes YAML parsing: PASS
regressions: none
verdict: VERIFIED
exit: 0
```

The base accounts for 2/2 parsed files. The candidate accounts for 3/3 parsed
files. Both graph-evidence records are complete; the candidate adds the exact
NetworkPolicy participant and relationship edge.

## Scope limits

This is not whole-PR verification. It does not verify CNI enforcement, Kafka
authentication, Kafka TLS, unrelated Go changes, or whole-PR correctness. It
establishes only the exact `CKV2_K8S_6` workload-to-NetworkPolicy repair on the
recorded base/head.

An all-baseline-findings diagnostic also observed pre-existing, unrelated
Kubernetes hardening findings on the workload. Those findings remain present
on both revisions and are outside the PR's stated NetworkPolicy repair. The
public evidence packet therefore uses the exact target selector rather than
making a whole-module claim.

## Evidence hashes

- `report.json`: `a0f5b839e370430e2904096220c4d420e80e7e6d49b5c11096d7f3a02e5b8283`
- `report.md`: `bfbcf95cbfacb6d0d376e8d4c64b02f3bcbd8b026ea2c6a32299a07c4b15cb7c`
- base deployment YAML: `4157059f683b26b58b9d72d8b45259bff9c8fcfab4d9121b7bb19ad852021ec5`
- base/head service YAML: `93332f7984980aeeee8eff773f4d95fac8d34e9c1bf9f3a9487a9cc6b259990e`
- head NetworkPolicy YAML: `10a603615f13e5387a7c87a8b74634bda3a41d69c88ad76e9dfc933eb49cbcf9`

The canonical report and Markdown rendering contain no local/private
filesystem paths.
