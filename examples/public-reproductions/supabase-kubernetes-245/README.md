# Supabase Kubernetes PR #245: init-container propagation evidence

Third-party pull request:
[supabase-community/supabase-kubernetes#245](https://github.com/supabase-community/supabase-kubernetes/pull/245)

## Live pull request identity

- Pull request: https://github.com/supabase-community/supabase-kubernetes/pull/245
- State: open, non-draft, mergeable
- Base: `d04a3133af93cc12af000b15f88c22507be5354f`
- Head: `36ab1fc6e1bbb60597148b726a05bd842888f570`
- Author: `hsahmed`, association `NONE`
- Human reviews: none
- Inline review comments: none
- Head checks: none reported by GitHub
- Duplicate search: no issue, pull request, or current fix was found for the exact
  `init-bucket` security-context omission

## Public verifier identity

- IaC-Guard-V `0.1.0a6`
- PyPI: `iac-guard-v==0.1.0a6`
- Public wheel SHA256:
  `5f39e41478fc30c5f2a7af1e2008059178d7eaadeb91dea67ac9446fd472b256`
- Version DOI: https://doi.org/10.5281/zenodo.22105295
- Checkov `3.3.0`
- Python `3.12.4`
- Helm `v4.2.4+g3900f43`
- Helm executable SHA256:
  `ebf04b3606784d48568cf386483ac2b81fc747ed77859da4ba4f77df4c5e81d3`

## Finding

The pull request says each component's configured `securityContext` is applied to its
init containers. In the MinIO-enabled Storage branch, the rendered Storage Deployment
contains two built-in init containers:

1. `init-db`
2. `init-bucket`

The head applies `deployment.storage.securityContext` to `init-db` but not to
`init-bucket`.

With an explicit protected Storage security context, Checkov reports the selected
failures at `initContainers[0]` on the base and at `initContainers[1]` on the head:

| Rule | Base evaluated key | Head evaluated key | IaC-Guard-V outcome |
| --- | --- | --- | --- |
| `CKV_K8S_20` | `initContainers/[0]/securityContext/allowPrivilegeEscalation` | `initContainers/[1]/securityContext/allowPrivilegeEscalation` | `STILL_PRESENT` |
| `CKV_K8S_22` | `initContainers/[0]/securityContext/readOnlyRootFilesystem` | `initContainers/[1]/securityContext/readOnlyRootFilesystem` | `STILL_PRESENT` |
| `CKV_K8S_30` | `initContainers/[0]/securityContext` | `initContainers/[1]/securityContext` | `STILL_PRESENT` |

This means the proposed change repairs `init-db` but leaves the second built-in init
container outside the same public values contract. The report is correctly
`INCONCLUSIVE`, not `VERIFIED`, because each selected target is still failing at the
candidate revision.

## Protected materialization

Both revisions were rendered twice in independently recreated Helm state directories
with byte-identical output. The exact protected configuration uses release `supabase`,
namespace `default`, Kubernetes `1.31.0`, Helm tests excluded, MinIO enabled, Storage
enabled, Storage database initialization enabled, Kong disabled as unrelated to the
selected Storage property, and these Storage security-context values:

- `allowPrivilegeEscalation=false`
- `privileged=false`
- `readOnlyRootFilesystem=true`
- `runAsNonRoot=true`
- `runAsUser=10001`
- `seccompProfile.type=RuntimeDefault`

| Evidence | Base | Head |
| --- | --- | --- |
| Governed rendered resources | 51 | 51 |
| Chart inventory root | `0af7f48857270817e792e1ff06316217cb9e31f2d390aa69e91ad52ffd37a660` | `b0ab6d3d431c442ba0bf002df5a10421bdc1ea6d213ecd4eacc64b9de64f1b15` |
| Materialization identity | `ad4af46d744a15997e2645da2b896852df87701aa1a779f83acbb0d6c2b9bd65` | `8fdb746bf6808b43baa52ec17d5dff3e4c86ba292d6e7f22c4eddca24a13e72a` |
| Rendered bundle SHA256 | `7bc372a62d4181357cb2db2a1686617a74896e10a38c613ac9cf9eb886360673` | `5813fbfa9b0cbd34e46271cbbe11c95d2cc2ae5367a32e30cb26f75b9786faa9` |
| Document inventory SHA256 | `ab77993ca2e0856af1397da45ea0327f0beb6ee4c86f21e6715c9211a5465deb` | `e4ee253e8bcebe93e08cdfe2d1463003420515573a7390a5ef9fd70828fa3419` |

Bounded Helm action reachability passes for both revisions with identity
`2e4715759fc3b336809995d9c33e933b926a5de2c054f83c15ce92df1522951d`.

## Authoritative target result

- Target: `apps/v1/Deployment/default/supabase-supabase-storage`
- Selected controls: `CKV_K8S_20`, `CKV_K8S_22`, `CKV_K8S_30`
- Baseline scanner run: `PASS`, 1/1 files parsed
- Candidate scanner run: `PASS`, 1/1 files parsed
- Scanner integrity: `PASS / SCANNER_EVIDENCE_RECONCILED`
- Kubernetes parsing: `PASS / VALIDATOR_COMPLETED`
- Three selected outcomes: `STILL_PRESENT`
- Final report: `INCONCLUSIVE`, as required for still-failing selected targets
- Semantic report validation: `PASS`
- Canonical report SHA256:
  `d1c4b0c5336d7a484fdace2600be8ff0a6513e50599269aeb01743e413eebbcc`
- Private-path leakage: none in canonical report or materialization evidence

The hashes for every retained packet file are recorded in
[SHA256SUMS](SHA256SUMS).

## What the maintainer would learn

The five edited templates do add the requested context to their `init-db` containers,
but the MinIO-enabled Storage branch has another built-in init container that remains
uncovered. The repository's lint and chart-install workflows do not assert this
property, and its Storage and MinIO Helm test hooks check service health rather than
rendered init-container security contexts. The pull request adds no native regression
test and currently has no human review or GitHub checks.

See [FINDING.md](FINDING.md) for the narrow characterization and
[REPRODUCE.md](REPRODUCE.md) for the exact public-package replay.

## Scope limits

This evidence is limited to the exact MinIO-enabled Storage branch and three selected
manifest controls. It does not claim whole-chart security, Restricted Pod Security
Standards compliance, runtime admission, image behavior, or whole-PR correctness.

This evidence does not assert that the entire chart or PR is insecure.

The full-chart `helm-accept` request also encountered a separate a6
scanner-addressability semantic boundary after successful materialization. The packet
therefore retains protected Helm materialization evidence and uses the supported direct
Kubernetes before/after verifier for the exact rendered Storage Deployment. No product
change was made.
