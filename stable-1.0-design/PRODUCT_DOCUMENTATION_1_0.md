# Stable product documentation plan

The following documents must exist in release-facing form before the 1.0 release
candidate. This file records their required content; it does not alter the live
product documentation yet.

## `README.md`

Explain in one page: what IaC-Guard-V verifies, what it does not verify, a
Kubernetes quickstart, a Terraform/OpenTofu quickstart, a CI example, the five
native result states, scanner-authority boundaries, and links to the detailed
support and security documents. A user must not need the paper to understand a
result.

## `SUPPORTED_SCOPE.md`

List supported artifact classes, materializers, exact exclusions, Python
versions, scanner versions and authority, deterministic-input requirements, and
the difference between manifest semantics and runtime behavior.

## `SECURITY_MODEL.md`

Document protected versus candidate-controlled inputs, fail-closed behavior,
process isolation, filesystem and network assumptions, secret redaction,
materializer trust, scanner integrity, hostile-input limits, and the absence of
telemetry or automatic cloud credentials.

## `COMPATIBILITY.md`

Publish the 1.x rules for CLI, Python exports, schemas, property IDs, witness and
reason semantics, provenance, exit codes, deprecation, and the v1alpha1 reader.
State clearly that implementation digests can change while stable semantics may
not.

## `MIGRATION_0_1_B1_TO_1_0.md`

The normal path must be a package-pin change only. Document the optional stable
v1 contract conversion, changed implementation/product identities, unchanged
commands and exit codes, and how to compare reports without expecting their
whole-file hashes to match across versions.

## `NATIVE_PROPERTIES.md`

For every one of the 18 V1 IDs, provide artifact class, subject class,
parameters, semantic definition, completeness requirement, result meanings,
witness example, limitations, and a positive/negative example.

## `SCANNER_AUTHORITY.md`

Publish the rules in `SCANNER_AUTHORITY_1_0.md` in user language. Separate
authoritative paths, advisory evidence, and independent validators. Include the
no-empty-output-pass and no-majority-vote rules.

## `RELEASE_NOTES_1_0.md`

Describe 1.0 as a compatibility commitment over bounded support, not universal
IaC verification. List frozen surfaces, security and supply-chain additions,
Python support, external replay result, known limitations, and migrations. Do
not present declined proposals as adoption.

## Quickstarts

The Kubernetes quickstart uses a small rendered relationship contract. The
Terraform/OpenTofu quickstart uses a bounded source reference. The CI example
uses an explicit Python version and exact `iac-guard-v==1.0.0` pin, read-only
permissions, no secrets, no cluster, and archived machine-readable output. A
first useful contract should take under 15 minutes for the recorded
non-implementer test.
