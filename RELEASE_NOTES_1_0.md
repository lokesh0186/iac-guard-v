# IaC-Guard-V 1.0.0

IaC-Guard-V 1.0 is a stability release for a bounded fail-closed verification
contract. It is not a claim of universal IaC verification.

## Stable surface

- the existing 18 native V1 properties;
- the Beta1 CLI commands, options, public Python exports, result enums, provenance
  tokens, and exit-code meanings;
- existing v1alpha1 contracts and reports plus an explicit equivalent stable-v1
  bridge;
- rendered Kubernetes, deterministic local Helm, bounded local Kustomize,
  source-local Terraform, and bounded OpenTofu support;
- Python 3.10, 3.11, 3.12, and 3.13.

## Security and supply chain

The release gate adds deterministic repeat-build comparison, exact wheel and sdist
smoke tests, a source manifest, SHA-256 checksums, CycloneDX SBOM, dependency and
license inventories, provenance statements, package-content and private-path audits,
and a protected Trusted Publishing workflow with GitHub artifact attestations.

## Compatibility result

The final external replay contains 32 cases: 32 unchanged, zero breaking, zero newly
unsupported, zero stricter-but-compatible, and zero blocked by external drift. The
frozen QRS replay remains unchanged.

## Migration

Existing supported consumers change only the package pin from `0.1.0b1` to `1.0.0`.
See [MIGRATION_0_1_0B1_TO_1_0.md](MIGRATION_0_1_0B1_TO_1_0.md).

## Known limits

Python 3.14, universal container-security checks, a generic Terraform attribute
engine, generic nested-block predicates, arbitrary CRD semantics, remote
materialization, hostile-input sandboxing, and scanner consensus are not in 1.0.
Trivy and KICS remain advisory by default. IaC-Guard-V results prove only the selected
mechanical predicate over protected evidence.

The software DOI remains the concept DOI until the authorized 1.0 Zenodo version
archive is created. No version DOI is invented in this candidate.
