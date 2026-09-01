# Changelog

All notable product changes will be documented here. The frozen QRS 2026 research
artifact has its own immutable provenance and is not rewritten by this changelog.

## [0.1.0b1] - 2026-09-01

### Archive

- Archived IaC-Guard-V `0.1.0b1` under Version DOI
  [`10.5281/zenodo.22239516`](https://doi.org/10.5281/zenodo.22239516). The evolving
  software project continues to use Concept DOI
  [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272).

### Added

- A distinct protected OpenTofu source mode for `.tofu`, `.tofu.json`, `.tf`, and
  `.tf.json`, including reviewed same-basename precedence, effective/shadowed source
  evidence, bounded override ordering, and contained local-module closure.
- `IACGV_OPENTOFU_REFERENCE_RESOLVES_V1` for exact witness-backed direct source-local
  OpenTofu references under the bounded protected file-set contract.
- Deterministic property/support discovery, native-mode doctor diagnostics, safe
  `SUGGESTED_CONTRACT` initialization, tested CI guidance, and a generated support
  matrix that separates native, authoritative scanner, advisory, and fail-closed
  capabilities.

### Compatibility

- All 17 existing native property IDs, versions, meanings, and witness obligations are
  unchanged. `IACGV_TF_REFERENCE_RESOLVES_V1` remains `.tf`-only and does not acquire
  OpenTofu precedence behavior.
- Contract `iac-guard-v.io/v1alpha1` and report
  `infrastructure-contract-report-v1alpha1` retain their a10 meanings. The exact
  retained KAITO, Kueue, and Thanos contracts require no edits or migration warning.

### Hardened

- Added public API/CLI/schema snapshots, historical-report compatibility checks,
  content-bound compatibility corpora, deterministic evidence checks, narrow package
  allowlists, sensitive-path rejection, and artifact-only installation validation.
- Preserved the clean Python 3.10-3.13, packaging, supply-chain, and frozen QRS release
  gates without lowering coverage thresholds.

### Scanner policy

- Checkov 3.3.0 authority is unchanged and remains limited to previously reviewed
  supported paths. KICS and Trivy retain their advisory boundaries. Zero findings do
  not establish target pass, and scanner voting is not used.

### Limitations

- OpenTofu and Terraform evaluation remains source-local and bounded. Remote modules,
  provider/cloud/runtime state, `init`/`plan`/`apply`, live Kubernetes, arbitrary CRD
  semantics, and general Helm interpretation remain unsupported or fail closed.
- Project intent is authoritative only through an explicit protected contract with the
  corresponding provenance. A mechanical violation is not automatically a project
  defect, vulnerability, outage, or runtime claim.

## [0.1.0a10] - 2026-09-01

### Archive

- Archived IaC-Guard-V `0.1.0a10` under Version DOI
  [`10.5281/zenodo.22226912`](https://doi.org/10.5281/zenodo.22226912). The evolving
  software project continues to use Concept DOI
  [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272).

### Added

- A closed declared-intent contract layer using one
  `.iac-guard-v/contracts.yaml` convention, strict schema/canonical identity, and
  deterministic compilation to immutable a9 native property requests.
- Verifier-derived project, user, research-hypothesis, and suggested-contract
  provenance; protected typed activation evidence; explicit include/exclude
  denominators; non-vacuous cardinality; and responsibility metadata.
- Witness-first clause aggregation, semantically validated JSON contract reports,
  deterministic contract exit codes, and `contract lint`, `contract plan`,
  `verify --contract`, and contract-aware `explain` CLI paths.
- Protected effective Helm-value activation evidence bound to the same deterministic
  materialization semantics, including defaults, values files, supported overrides,
  and local dependency contexts where provenance is exact.
- Typed historical reproducibility reasons for missing scanner, bundle, render-input,
  materialization, baseline, and candidate identities without environment emulation.

### Security

- Contract uncertainty, ambiguous subject identity, unknown activation, zero subject
  matches, unsupported properties, and incomplete native evidence remain fail closed.
- A project-authored contract requires exact canonical bytes in the declared local Git
  commit; user/research contracts cannot self-promote through YAML contents or paths.
- Checkov 3.3.0 and all a9 native semantics are unchanged. KICS and Trivy remain
  advisory; no voting, PASS-from-absence, cloud/runtime lookup, arbitrary CRD
  interpretation, or general Terraform evaluation was added.
- Contract violations establish only the supplied declared invariant. They do not
  automatically establish a project defect, vulnerability, outage, runtime behavior,
  or project-author intent.

## [0.1.0a9] - 2026-08-31

### Archive

- Archived IaC-Guard-V `0.1.0a9` under Version DOI
  [`10.5281/zenodo.22216372`](https://doi.org/10.5281/zenodo.22216372). The evolving
  software project continues to use Concept DOI
  [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272).

### Added

- A witness-first native semantic property framework with independent property,
  request, implementation, evidence, and semantic-version identities over protected
  deterministic artifacts.
- Bounded Kubernetes identity/selector semantics, NetworkPolicy selection and
  direction-specific isolation, caller-supplied workload closure, Service/workload and
  ServicePort/container-port resolution, and additive NetworkPolicy path composition.
- Reviewed `monitoring.coreos.com/v1` ServiceMonitor and PodMonitor composition without
  introducing a general custom-resource interpreter.
- RBAC binding identity and scope relationships, including valid cross-namespace
  ServiceAccount subjects, plus exact source-local Terraform resource-reference
  relationships.

### Security

- Every native outcome carries a validated mechanical witness and fails closed on
  incomplete identity, unsupported semantics, or ambiguity.
- Checkov 3.3.0 authority is unchanged; KICS and Trivy remain advisory; no scanner
  voting or PASS-from-absence inference is used.
- Native properties establish configuration semantics, not project intent, live
  Kubernetes/cloud behavior, vulnerabilities, outages, or general security.

## [0.1.0a8] - 2026-08-29

### Archive

- Archived IaC-Guard-V `0.1.0a8` under Version DOI
  [`10.5281/zenodo.22167878`](https://doi.org/10.5281/zenodo.22167878). The evolving
  software project continues to use Concept DOI
  [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272).

### Added

- Scanner-neutral protected-artifact, target-identity, property-observation, and
  evidence contracts. Checkov remains the sole authoritative adapter; KICS and Trivy
  remain advisory and cannot establish target `PASS`.
- Bounded Helm logical dependency instances for aliases, activation/import metadata,
  globals, repeated physical sources, nested local directory closure, and contained
  `file://` dependencies with strict source/lock/byte binding.
- Structural, output-sensitive equivalence for duplicate named templates, including
  all-member source/span provenance and consumer-specific namespace-value equality.
- The closed a8 namespace-helper grammar for literal `include`/`template` calls,
  exact root contexts, direct Release/Values forms, and the reviewed default/trunc/
  trimSuffix chain.
- A locked, local-only Kustomize `v5.7.1` materializer with closed control grammar,
  complete transitive input inventory, sealed offline double builds, conservative
  full-closure provenance, and exact rendered/scanner-universe identity.

### Fixed

- Completed the frozen local Helm dependency contract for nested closure inside a
  protected vendored archive and Helm-compatible declared-version constraints bound
  to exact protected lock, nested `Chart.yaml`, physical, and logical identities.
- Bound archive-backed and directory-backed logical dependency instances to the same
  protected effective-Values model across defaults, parent/alias overrides, globals,
  imports, action analysis, namespace provenance, and rendered target identity.

### Security

- Scanner adapters cannot select or prune protected inputs, redefine protected target
  identity, infer `PASS` from absence, omit required coverage, or bypass relationship
  evidence.
- Remote dependencies/resources, cluster-state lookup, plugins/exec, Helm inflation
  through Kustomize, nondeterministic template functions, unsupported dynamic template
  names, unknown Kustomize keys, path/symlink escapes, and unequal fresh builds remain
  typed fail-closed boundaries.

## [0.1.0a7] - 2026-08-26

### Archive

- Archived IaC-Guard-V `0.1.0a7` under Version DOI
  [`10.5281/zenodo.22118759`](https://doi.org/10.5281/zenodo.22118759). The evolving
  software project continues to use Concept DOI
  [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272).

### Fixed

- Known cluster-scoped Kubernetes resources now retain any rendered
  `metadata.namespace` as governed scanner-facing evidence while recording the API
  server-normalized effective namespace as absent. Such metadata is redundant cleanup,
  not an API rejection condition. Duplicate objects that collide after normalization
  still fail closed.
- Unknown custom-resource scope and contradictory namespaced-resource provenance remain
  inconclusive; existing Terraform, Kubernetes, Helm, graph, and candidate-acceptance
  behavior is otherwise unchanged.

## [0.1.0a6] - 2026-08-25

### Archive

- Archived IaC-Guard-V `0.1.0a6` under Version DOI
  [`10.5281/zenodo.22105295`](https://doi.org/10.5281/zenodo.22105295). The evolving
  software project continues to use Concept DOI
  [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272).

### Added

- Protected namespace provenance for default and non-default Helm releases, including
  exact release, emitted, values-derived, static-helper, resource-scope, source, and
  materialization identities.
- Bounded Helm action-reachability evidence for exact protected `if`/`else`, `with`,
  `range`, and static named-template paths.
- Digest-only bounded `tpl` evidence for exact literal and protected-values template
  strings, including nested analysis, recursion/resource limits, and redacted values.
- Exact bounded dynamic `include`/`template` resolution for restricted literal and
  `.Template.BasePath` `print`/`printf` expressions, with protected target hashes,
  call-graph edges, and strict recursion/resource limits.

### Security

- Reachable lookup remains `CLUSTER_STATE_REQUIRED`; reachable random, password,
  UUID, or time generation remains `NONDETERMINISTIC_RENDER`; unknown or dynamic
  reachability remains `AMBIGUOUS_TEMPLATE_ACTION_GRAPH`.
- Computed or unsupported `tpl` arguments remain ambiguous; deterministic rendered
  bytes cannot override dangerous nested `tpl` actions.
- Missing, duplicate, escaped, cyclic, or unsupported dynamic include targets remain
  ambiguous. Dangerous actions reached through an exact target retain their stronger
  typed fail-closed outcome.
- In `0.1.0a6`, cluster-scoped resources carrying `metadata.namespace` were treated as
  contradictory. The correction released in `0.1.0a7` above aligns this with the API
  server create path. Custom-resource scope still requires exact local CRD evidence,
  and unproven scope remains fail closed.

## [0.1.0a5] - 2026-08-25

### Archive

- Archived IaC-Guard-V `0.1.0a5` under Version DOI
  [`10.5281/zenodo.22099303`](https://doi.org/10.5281/zenodo.22099303). The evolving
  software project continues to use Concept DOI
  [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272).

### Added

- Candidate/head-only acceptance for explicitly requested properties, with separate
  `SATISFIED`, `VIOLATED`, and `INCONCLUSIVE` outcomes that never imply a baseline
  repair.
- Ordered multi-chart Helm verification universes with per-chart materialization,
  rendered-resource ownership, and cross-chart graph relationship evidence.
- Closed `accept` and `helm-accept` command surfaces and the additive
  `candidate_acceptance` report-v1 branch.
- Target-relevant scanner-addressability accounting that keeps every resource governed
  while distinguishing primary scanner addresses, graph participants, structurally
  irrelevant relationship resources, and unresolved evidence.

### Fixed

- Dependency relevance now follows declared or physically vendored chart dependencies.
  A stray lock remains byte-bound but cannot create a dependency-resolution failure
  when the chart has no dependency state.

### Security

- Candidate acceptance requires complete scanner, parser, target, and requested-property
  evidence. Duplicate cross-chart resources and incomplete participating charts fail
  closed.
- A raw partial scanner run is accepted only for the bounded selected-property gate
  when exact diagnostics identify only independently proven non-target standalone
  omissions; unsupported checks retain complete-resource coverage.

## [0.1.0a4] - 2026-08-24

### Archive

- Archived IaC-Guard-V `0.1.0a4` under Version DOI
  [`10.5281/zenodo.22088273`](https://doi.org/10.5281/zenodo.22088273). The evolving
  software project uses Concept DOI
  [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272).

### Added

- Bounded local, client-side Helm materialization with byte-bound charts, frozen local
  dependencies, protected render inputs, isolated double rendering, exact source
  markers, rendered-resource identities, and closed `report-v1` evidence.
- A separate `helm-verify` command for deterministic before/after chart verification.

### Fixed

- Kubernetes controller findings now bind Checkov synthetic Pods through exact source
  workload name, namespace, and file identity rather than requiring label-derived
  suffixes.

### Security

- Helm lookup, reachable random/time helpers, mutable or unresolved dependencies,
  render drift, duplicate identities, ambiguous source markers, cluster state,
  plugins, post-renderers, and remote charts fail closed.

## [0.1.0a3] - 2026-08-24

### Added

- A parsed Terraform file-coverage contract that distinguishes scanner-evidence-bearing
  files from structural-only support files without relying on filenames.
- Byte-bound, parser-governed handling for resource-free variable, output,
  terraform/version, locals, empty, and comments-only Terraform files.

### Fixed

- `init`, direct verification, Git verification, validation planning, and adapter
  preparation now share the same protected native Terraform structural parser.
- Resource, module, data, or provider constructs cannot be downgraded to support-only
  coverage by placing them in files named `variables.tf`, `outputs.tf`, or `versions.tf`.

## [0.1.0a2] - 2026-08-23

### Added

- Bounded Checkov CKV2 connection-graph evidence binding primary targets,
  participating resources, relationships, file identities, policy definitions,
  scanner identity, and sealed snapshots.
- Fail-closed graph evidence outcomes for missing nodes, ambiguous identities,
  unsupported query shapes, and scanner/evidence contradictions.

### Fixed

- Terraform resource inventory now uses the protected native HCL2 parser, so valid
  comment-like text inside quoted strings, escaped strings, interpolations, and
  heredocs cannot change structural resource discovery.
- The copied-file Checkov doctor probe keeps a bounded 30-second ceiling so a cold
  Checkov 3.3.0 import is not misclassified by the former 10-second limit.

### Changed

- Reorganized the README around value, installation, a real verification command,
  and the public Coder #180 reproduction.
- Moved detailed installation, scope, and trust-boundary material into focused public
  documentation without weakening any alpha limitation.
- Clarified contribution priorities and made the roadmap evidence-driven.
- Added target-scoped DeepSec #112 evidence for Kubernetes privileged-workload
  matcher boundaries.
- Exact operator-controlled verification roots remain portable when they are nested
  beneath an unrelated Git worktree.
- Retained `report-v1` for the alpha while extending its closed schema with optional
  graph evidence and inventory-completion data. Consumers with a vendored `0.1.0a1`
  schema must update before validating a2 graph reports; non-graph a1 reports remain
  valid under the a2 schema.

## [0.1.0a1] - 2026-08-20

### Added

- Typed differential verification and fail-closed policy semantics.
- Closed JSON configuration and `report-v1` contracts with semantic graph validation.
- Checkov 3.3.0 environment verification and reduced-isolation execution mode.
- Offline `demo`, `doctor`, `verify`, and `explain` commands.
- Deterministic SARIF 2.1.0, Markdown, and JUnit projections derived only from
  semantically valid `report-v1` evidence.
- Closed `scan`, `differential`, `init`, `lock`, and `pr --changed-only` workflow
  commands; alpha lock records are explicitly non-evidentiary.
- Experimental lock-bound KICS and Trivy adapters.
- Experimental OpenTofu/Terraform, kubeconform, and TFLint validators.
- Protected structural Kubernetes oracles and complete validation-universe planning.
- Source-attested advisory control catalog with zero exact mappings.

### Security

- Unsupported, partial, malformed, contradictory, or operationally uncertain evidence
  cannot become `VERIFIED`.
- Public inputs cannot inject trusted scanner, validator, oracle, or policy evidence.
- Symlinks, special files, bytecode caches, environment drift, and incomplete artifact
  coverage fail closed at their protected boundaries.

### Known limitations

- The production hardened container and GitHub Action are not released.
- Native execution is reduced isolation and intended only for trusted local input.
- Experimental multi-scanner agreement is advisory and disconnected from final policy.
- The current catalog is not ready for validated-discrepancy screening.
- `.tf.json` is unsupported/inconclusive.
