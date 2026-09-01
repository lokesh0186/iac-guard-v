# IaC-Guard-V 0.1.0b1

IaC-Guard-V 0.1.0b1 is the first beta in the 0.1.0 line. The core verifier,
native-property, evidence, and intent-contract architectures remain compatible with
0.1.0a10. Beta1 concentrates on bounded OpenTofu support, adoption ergonomics, public
API visibility, and release reliability.

## Main addition: bounded OpenTofu source verification

Beta1 adds a distinct protected OpenTofu source mode and the native property
`IACGV_OPENTOFU_REFERENCE_RESOLVES_V1`.

The source mode protects `.tofu`, `.tofu.json`, `.tf`, and `.tf.json` files and records
which files are effective or shadowed under the reviewed same-basename precedence
rules. It also records bounded override ordering and local-module closure. Malformed
winning files do not fall back to valid shadowed files. Missing, remote, dynamic,
cyclic, escaping, and symlinked module relationships fail closed.

The new property verifies exact direct source-local references with witness-backed
results. It does not run `tofu init`, `plan`, or `apply`, fetch remote modules, evaluate
providers, expand `count` or `for_each`, or claim deployed cloud state.

## Compatibility

- All 17 native properties present in 0.1.0a10 retain their IDs, versions, semantic
  meanings, and witness obligations.
- `IACGV_TF_REFERENCE_RESOLVES_V1` remains `.tf`-only and does not inherit OpenTofu
  precedence or shadowing behavior.
- The contract API remains `iac-guard-v.io/v1alpha1`.
- The contract report remains `infrastructure-contract-report-v1alpha1`.
- Existing a10 contracts require no migration. Retained KAITO, Kueue, and Thanos
  contracts execute from the same bytes with unchanged provenance and clause
  interpretation.
- Historical reports remain interpreted under their declared historical schema and
  property identities. Beta1 does not regenerate or relabel old evidence.

## Adoption hardening

- Native property listing and description expose exact versions and evidence
  contracts.
- `doctor --mode native` and the generated support matrix distinguish native,
  contract, authoritative scanner, advisory scanner, and fail-closed capabilities.
- `contract init` creates reviewed `SUGGESTED_CONTRACT` templates and refuses to
  overwrite an existing file.
- Tested GitHub Actions and generic CLI guidance document a read-only CI path without
  cluster or cloud credentials.

## Reliability and release engineering

- Public CLI/API/schema snapshots protect documented Beta surfaces.
- Scanner adapter diagnostics retain exact capability and identity boundaries.
- Distribution tests use a narrow sdist allowlist plus sensitive-path rejection and
  prevent bytecode, private evidence, recursive README/LICENSE, local-path, and test
  capability leakage.
- Determinism, clean artifact-only installation, Python 3.10-3.13 compatibility,
  packaging, and frozen QRS preservation are release gates.

## Scanner policy

Checkov 3.3.0 remains authoritative only on its previously reviewed supported paths.
KICS and Trivy remain advisory under their documented target-binding and bundle/query
boundaries. Zero findings are not inferred to be a selected-target pass, and scanner
agreement does not vote a result into authority.

## Important limitations

IaC-Guard-V is a fail-closed static verifier for protected IaC artifacts. Beta1 does
not provide complete OpenTofu or Terraform language evaluation, remote module
acquisition, provider or cloud-state evaluation, live Kubernetes queries, runtime
network verification, arbitrary CRD interpretation, general Helm execution, hidden
telemetry, or model-provider integration. Project intent is authoritative only when it
is supplied through an explicit protected contract with the corresponding provenance.

The package is for trusted local input. A hardened hostile-input container and a
turnkey GitHub Action are not part of Beta1.
