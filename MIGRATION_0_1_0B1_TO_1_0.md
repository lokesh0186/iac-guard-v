# Migrating from 0.1.0b1 to 1.0.0

For supported Beta1 consumers, migration is a package-pin change:

```text
iac-guard-v==0.1.0b1  ->  iac-guard-v==1.0.0
```

No substantive rewrite is required for existing commands, v1alpha1 contracts,
property IDs, provenance values, JSON result handling, or exit-code handling. The
32-case external compatibility replay completed with 32 unchanged cases, zero
breaking cases, and zero newly unsupported cases.

## Contracts and reports

Existing `iac-guard-v.io/v1alpha1` files remain valid. Keeping them as v1alpha1 is
supported throughout 1.x. A caller may explicitly convert to `iac-guard-v.io/v1`; the
semantic content is unchanged. An alpha input continues to produce an alpha-compatible
report unless conversion is explicitly requested.

Product-version fields, implementation digests, registry implementation identities,
build metadata, and whole-report hashes change across releases. Compare property ID,
property version, result, reason class, witness facts, schema-required fields, and exit
code rather than expecting whole-file hashes to match.

## Python and installation

Python 3.10 through 3.13 remain supported. Python 3.14 is not supported by 1.0.
Checkov remains separately installed when a reviewed scanner-authoritative workflow
needs it. Native-property and contract workflows do not gain a hidden scanner or
network dependency.

## Stable additions

Version 1.0 adds an explicit stable schema bridge, executable API and CLI freeze,
published compatibility and support policies, a bounded scanner-authority statement,
SBOM and provenance release evidence, and clean-wheel quickstarts. These additions do
not reinterpret Beta1 evidence.
