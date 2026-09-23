# External compatibility manifest for 1.0

## Hard release rule

Every public IaC-Guard-V-dependent issue, pull request, reproduction, contract,
workflow, command, and report consumer must replay under the 1.0 release
candidate. Changing only `iac-guard-v==0.1.0b1` to the candidate pin is allowed.
Editing a contract, provenance token, property ID, command, parser, expected exit
code, or result interpretation to make it work is a compatibility failure.

This manifest was seeded from an authenticated GitHub author search and the
private adoption ledger on `2026-09-22`. A fresh search is mandatory at release
candidate freeze. Unrelated public work is inventoried but does not become a
product-compatibility dependency merely because Lokesh authored it.

## Highest-risk direct consumers

| Public case | Beta1 dependency | Required 1.0 proof | Pre-implementation classification |
| --- | --- | --- | --- |
| K8sGPT operator #846 | Installs Beta1; v1alpha1 contract; `PROJECT_AUTHORED`; `contract lint`, `plan`, `verify`, `explain`; ServiceMonitor V1 property | Exact workflow replay on preserved head; baseline `SATISFIED`; all published mutation categories unchanged; JSON and exit codes compatible | `REPLAY_REQUIRED`; predicted unchanged |
| IaCSecBench #86/#88 | Optional external `iac-guard` subprocess; `verify` and `accept`; report-v1 parsing; target identities; Checkov 3.3.0; normalized result categories | Replay all eligible pairs and stored controls; verify report validator, exit mapping, target continuity, and unsupported mappings | `REPLAY_REQUIRED`; highest report-consumer risk |
| Argo Helm #4075 | Installs Beta1; v1alpha1 research-hypothesis contract; five ServiceMonitor paths | Replay baseline, one-sided mutations, coordinated renames, workflow and provenance | `REPLAY_REQUIRED` |
| CloudNativePG charts #1025 | Beta1 PodMonitor contract and mutation evidence | Replay exact current preserved contract and controls | `REPLAY_REQUIRED` |
| Prometheus helm-charts #7308 | Closed unmerged workflow proposal using two native families | Replay preserved contract/workflow privately even though declined; no outreach or reopening | `REPLAY_REQUIRED`; archival compatibility only |
| K8s direct-integration proposals: Kueue #14978, Thanos Operator #630, KAITO #2313, vehagn/homelab #564, Hetzner #1353 | Public commands/contracts from alpha/Beta generations | Preserve the documented exact historical package path and separately verify any Beta1-compatible fixture; do not rewrite public history | `REPLAY_REQUIRED_WHERE_BETA1_USED` |

## Native-method and defect chains

These projects do not necessarily depend on the package at runtime. Their
preserved IaC-Guard-V evidence must nevertheless keep the same mechanical result
under 1.0:

| Case group | Cases | Compatibility expectation |
| --- | --- | --- |
| Monitoring relationships | cert-manager #9366/#9367, CoreDNS Helm #274, Falco Helm #1053, KubeLinter #1256, External Secrets #6987 | Same baseline and negative-control result classes for the exact frozen manifests. Native project tests may differ and are not falsely called tool adoption. |
| Service/workload resolution | Kubescape #805 and merged/released fix chain | Unresolved named targetPort remains fail-closed; corrected control remains satisfied. |
| RBAC | KubeLinter #1255, Kueue #14816 and backports, Polaris #1240 | Role/ClusterRole identity, namespace, subject, and scope results remain unchanged on frozen fixtures. |
| OpenTofu/Terraform discovery | pre-commit-terraform #1013/#1014, tofu-ls #187, terraform-docs #960, Terramate #2386, Trivy #11181/#11192/#11193, dflook advisory/release | Protected file-set and precedence cases remain reproducible; scanner findings are not substituted for native source-discovery evidence. |
| Scanner discrepancy | Checkov #7668, KICS #8107 and related controls | Same-predicate comparisons and non-equivalence boundaries remain unchanged. |
| Deterministic materialization | Checkov #7655 and its Kustomize renderer-selection path | Preserve the bounded renderer-selection and materialization behavior used by the public contribution; a 1.0 verification must not depend on implicit or nondeterministic renderer choice. |
| Network policy and earlier public reproductions | Quay #1322, Dgraph #146, Supabase #253, and preserved alpha/a10 cases | Replay using the exact historical release when needed, then run a 1.0 semantic-equivalence fixture. Historical hashes remain immutable. |

## Authored but product-unrelated items

The authenticated author inventory also includes FastMCP #5160, ARD/OpenARD
issues, Nevermined and AgentField proposals, Hugging Face hf-discover #47, and an
arXiv endorsement PR. These must be recorded as `OUT_OF_SCOPE_NO_IAC_GUARD_V_DEPENDENCY`
after a final body/diff audit. They are not permitted to inflate the 1.0 replay
count.

## Replay record required per case

Each row in the executable manifest must contain:

- repository, issue/PR URL, immutable source/head, and public package version;
- exact command array and environment/tool identities;
- input and contract hashes;
- property IDs, provenance, schema, expected result, reason category, and exit;
- positive, negative, ambiguous, and coordinated-change controls where public;
- Beta1 output hashes and 1.0 release-candidate output hashes;
- classification: `UNCHANGED`, `STRICTER_BUT_COMPATIBLE`, `BREAKING`, or
  `UNSUPPORTED`;
- reviewed explanation for every non-`UNCHANGED` result.

For any public alpha or Beta command that was presented as a reusable workflow,
installing 1.0 in its place must either work without source edits or exercise a
documented compatibility alias included in 1.0. Merely noting that the old wheel
remains downloadable is not sufficient for the user's no-breakage requirement.

## Release decision rule

The goal is zero `BREAKING` and zero newly `UNSUPPORTED` rows. A
`STRICTER_BUT_COMPATIBLE` row is allowed only when all existing contracts and
consumers still run unchanged and the stricter result closes a documented
correctness defect without converting certainty into success. Otherwise 1.0 is
blocked.

Current aggregate state as of 2026-09-23: `REPLAY_PASS`. The executable manifest
contains 32 cases: 32 `UNCHANGED`, zero `STRICTER_BUT_COMPATIBLE`, zero `BREAKING`,
zero `NEWLY_UNSUPPORTED`, and zero `BLOCKED_BY_EXTERNAL_DRIFT`. The implementation
and validation record is in `CORE_STABILIZATION_PHASES_1_4.md`.
