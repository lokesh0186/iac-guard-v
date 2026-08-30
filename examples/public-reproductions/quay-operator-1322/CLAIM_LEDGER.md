# Claim ledger

| Claim | Classification | Evidence | Boundary |
| --- | --- | --- | --- |
| The committed `clair-postgres-old` pod-template label is disjoint from all three policies in the exact upgrade closure. | Authoritative primary claim | `REPORT.json`; exact source files | Exact PR head and `CKV2_K8S_6` only |
| `clair-postgres-old` has `CKV2_K8S_6: VIOLATED`. | Authoritative primary claim | `REPORT.json`: `CANDIDATE_PROPERTY_VIOLATED`; complete graph evidence | Target-scoped, not whole-change verification |
| The committed Job places its component label on Job metadata rather than pod-template metadata. | Exact-source observation | `source/clair-pg-upgrade.job.yaml` | Does not itself assert Checkov addressability |
| Native rendering gives the Job pod template only the common registry label, and no applicable policy selects it. | Corroborated relationship claim | `rendered/`; `REPORT-rendered.json` | Native render, not a8 `kustomize-accept` |
| Both rendered upgrade workloads have `CKV2_K8S_6: VIOLATED`. | IaC-Guard-V rendered-universe evidence | `REPORT-rendered.json`; complete graph evidence for both targets | Materialization provenance is corroborative |
| Existing substantive CI was green at the exact head. | Public CI observation | PR head check rollup at final recheck | Does not imply every property was tested |
| Chainsaw asserts NetworkPolicy object presence. | Native-test observation | `test/chainsaw/reconcile/00-assert-networkpolicies.yaml` at the exact head | It does not assert these selector relationships |
| Standard E2E does not enter `NeedsClairPgUpgrade`; unit coverage binds component assembly. | Native-test-scope observation | `chainsaw-test.yaml`, `pkg/kustomize/kustomize_test.go` at the exact head | No criticism of the project's CI strategy |
| No public duplicate addressing this exact gap was found. | Search result | Final commits/comments/reviews and exact GitHub issue/PR searches | Cannot exclude private trackers or later activity |

## Explicitly unclaimed

- This packet does not call the finding a vulnerability or assign severity.
- It does not claim exploitation, whole-PR failure, or whole-namespace security.
- It does not prescribe exact migration connectivity.
- It does not claim general or legacy-`vars` Kustomize support in IaC-Guard-V a8.
- It does not claim acknowledgement, external reliance, adoption, or a resulting code
  change.
