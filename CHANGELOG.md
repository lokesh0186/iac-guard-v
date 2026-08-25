# Changelog

All notable product changes will be documented here. The frozen QRS 2026 research
artifact has its own immutable provenance and is not rewritten by this changelog.

## [Unreleased]

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
