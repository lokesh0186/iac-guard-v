# Changelog

All notable product changes will be documented here. The frozen QRS 2026 research
artifact has its own immutable provenance and is not rewritten by this changelog.

## [Unreleased]

### Changed

- Reorganized the README around value, installation, a real verification command,
  and the public Coder #180 reproduction.
- Moved detailed installation, scope, and trust-boundary material into focused public
  documentation without weakening any alpha limitation.
- Clarified contribution priorities and made the roadmap evidence-driven.
- Added target-scoped DeepSec #112 evidence for Kubernetes privileged-workload
  matcher boundaries.

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
