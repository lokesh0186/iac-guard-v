# Checkov authority qualification surface

This local sprint starts from released 1.0.1. Adapter compatibility is distinct
from policy authority. No version is promoted by a successful CLI or JSON parse.
Native properties have no scanner dependency and retain their existing semantics.

| Product path | Required scanner behavior | Policy/identity dependency | Positive / negative / uncertainty |
| --- | --- | --- | --- |
| Terraform direct CKV; baseline discovery | Complete eligible HCL file/resource coverage; one exact address per evaluation | CKV_AWS_3, 18, 19, 23, 24 and corpus-observed rules; Terraform address, exact source path; installed Python check class | `check_result.result=PASSED` / `FAILED` / SKIPPED, UNKNOWN, absent resource/rule, parsing errors stay inconclusive |
| Terraform CKV2 | Exact primary plus independently reconstructed source participants, edges and supported graph query | CKV2_AWS_6; bucket-to-access-block reference; graph JSON policy definition and query digests | Both affirmative scanner result and independently reconciled graph required; unresolved/ambiguous graph never passes |
| Kubernetes direct CKV | Manifest identity reconciled with protected source and exact file | API group/version, kind, namespace, name; canonical `apiVersion/kind/namespace/name`; CKV_K8S_10–13, 20, 22, 23, 30 and corpus-observed rules | Typed affirmative pass / explicit fail / suppression, unknown, duplicate or absent identity stay inconclusive |
| Kubernetes CKV2 | Exact source relationship with NetworkPolicy selector and namespace | CKV2_K8S_6, source graph, policy JSON, graph-participant identities | Scanner graph result must agree with independent graph reconstruction |
| Synthetic workload Pods | Controller template resolves to the exact source workload; no broad alias equivalence | Deployment, DeploymentConfig, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job; explicit template name or parent-plus-label spelling; CronJob exclusion | Complete identity and graph binding / explicit failed evaluation / ambiguous or unsupported synthetic spelling remains inconclusive |
| Candidate acceptance (`accept`, API) | Property-specific affirmative evidence over complete protected candidate universe | Same direct/graph identities and exact property definition; no before/after repair assumption | SATISFIED / VIOLATED / NOT_EVALUATED; zero findings alone is not success |
| Before/after repair (`verify`, API, Git workflow) | Baseline target is independently observed, candidate affirmatively passes, scope and policy remain bound | Same scanner/runtime/policy identity for both roles; selectors bind exact rule/resource/file | VERIFIED exit 0 / still-failing property exit 1 / absent/deleted/unknown target exit 3 |
| Helm/Kustomize scanner-backed entry points | Scan only independently materialized, protected Kubernetes output; maintain rendering/namespace provenance | Same Kubernetes CKV/CKV2 surface; existing rendering gates remain unchanged | Render/identity/coverage uncertainty cannot become an affirmative scanner result |
| Suppression and candidate configuration | Candidate config cannot choose policy; inline skips retained as suppression evidence | CKV_AWS_3/23, CKV_K8S_20; protected explicit scanner config | SKIPPED is not PASS; candidate `.checkov.yml` does not govern invocation |
| Rename/move and deletion | Canonical exact path and resource binding survive only permitted correspondence | Same resource at another path is not automatically the original target; selected deletion remains uncertain | Existing policy decides allowed moves; missing evaluation never proves repair |
| Parser failure, crash, partial output | Exit 0 is insufficient; summary/errors, output bounds, process result and complete resource coverage must reconcile | Existing adapter/process contracts; HCL/YAML parsers and Checkov dependencies identity-bound | Parsing error, crash, bad output or missing coverage never passes |
| Doctor and provenance | Report version, authority profile, installation integrity and remediation independently | Exact released-version set, source/distribution digest, dependencies, policy inventory, interpreter and invocation | Unsupported version/property is explicit; native mode remains available |

Every row depends on the reviewed JSON fields `check_type`, `results`,
`passed_checks`, `failed_checks`, `skipped_checks`, `parsing_errors`, and summary
coverage. Incidental ordering, timing, absolute scratch paths and version text are
not semantic equivalence criteria. Executed check classes, resource spelling,
result categories, source path and graph participants are semantic criteria.

## Observed policy difference

The canonical Pod `uid_namespace.json` has `hostUsers: false` and a container UID
of zero. Checkov 3.3.0 reports CKV_K8S_40 FAILED; 3.3.30 reports PASSED. The newer
definition intentionally exempts a private user namespace. These are different
policy semantics, not an adapter defect. Equal check IDs do not establish
equivalence. This check must not enter an unchanged-semantics authority profile
for the newer version without a separate, explicit policy review.

Qualification artifacts and classifications must distinguish raw-scanner
comparison, adapter normalization, property authority, full public workflow and
environment integrity. This document does not itself promote a version.

## Shared helper changes and qualification bounds

Endpoint source review also found changes outside individual check definitions:
Markdown/SCA reporting, parallel result draining, POSIX/Windows path helpers,
Kubernetes suppression-prefix recognition, and indexed Terraform graph lookup.
Matching check-definition hashes alone therefore does not establish whole-program
equivalence. The runtime corpus separately compares semantic JSON, exact resource
identities, suppression, parsing errors and independently reconciled graph evidence.
Results are compared without order; the parallelizer's changed drain order is not
an authority criterion. Markdown/SCA output and Checkov's Helm/Kustomize runners
are outside the requested Terraform/Kubernetes JSON invocation surface.

Additional Kubernetes suppression prefixes can produce SKIPPED rather than FAIL
in later releases. Neither is affirmative repair evidence: suppressed requested
targets remain inconclusive. The profile does not equate suppression with passing
or broaden supported graph/index/module resolution beyond the product's existing
independent protected-resource and graph proofs. A raw scanner graph result that
disagrees with that proof remains inconclusive on every qualified version.

The claimed surface uses built-in checks and protected explicit configuration.
External plugins and ambient site startup hooks are not promoted by matching
built-in registration. Native properties, rendering, contracts and independent
parsers retain their separate existing release gates.
