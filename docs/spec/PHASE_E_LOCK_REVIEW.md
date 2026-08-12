# Phase E immutable dependency lock review

## Scope and decision

E0 is dependency research only. It does not implement or execute KICS, Trivy,
OpenTofu, Terraform, kubeconform, TFLint, a hardened container, or a composite
GitHub Action. The machine-readable decision is
`tools/locks/phase-e-locks.json`; `tools/validate_phase_e_locks.py` rejects a
missing field, malformed digest, floating selection, architecture omission, or
change to a security-role decision.

| Component | Selected identity | E0 compatibility result | Intended role |
| --- | --- | --- | --- |
| KICS | v2.1.20, commit `e1f23cad9640f55b963f22a116b04906b8c16ac6` | Static contract review only | Future scanner |
| Trivy | v0.73.0, commit `40c73e5d6166dcc0346a1ab4e94499d1572854e4` | Static contract review only | Future scanner |
| trivy-checks | v2.2.0 OCI manifest `sha256:b63166ca02aa09e30a5127320384d7bd0d2760dc19bab3ab7041a6070114ba45` | Manifest/schema review only | Future external check bundle |
| OpenTofu | v1.12.5, commit `230349e959a44fb8eb7b83754f9d9b012f3bdb42` | Static invocation review only | Future external validator |
| Terraform | v1.15.8, commit `b9e178d44488db4e9a93543b2d4ba34104314e29` | Static invocation review only | User-supplied validator; never bundled |
| kubeconform | v0.8.0, commit `02374f3ae471475995e20c529694c0e5092f79ac` | Static formatter review only | Future external validator |
| TFLint | v0.64.0, commit `15c65c5aa4ba90acc92dd8d36fb199b5b2714d20` | Static formatter review only | Optional, non-security lint |

The recorded compatibility result “static contract review passed; runtime not
executed” means release identity,
archive checksums, OCI indexes, supported architectures, and an upstream output
fixture were reviewed. It is not a scanner or compatibility execution result.
Phase-E implementation remains unauthorized at this gate.

## KICS selection

The initial v2.1.21 candidate has a source tag and commit but no official release
archives and no `checkmarx/kics` v2.1.21 container tag. E0 therefore selects
v2.1.20, the newest release for which the review found signed archive checksums
and immutable linux/amd64 and linux/arm64 OCI identities. A later switch to
v2.1.21 requires a new lock review; the source tag alone is not a substitute for
the runtime artifact identity.

## Trivy check identity

The Trivy executable and policy bundle are separate identities. The selected
external bundle is `ghcr.io/aquasecurity/trivy-checks:2.2.0` at manifest
`sha256:b63166ca02aa09e30a5127320384d7bd0d2760dc19bab3ab7041a6070114ba45`.
The moving `:2` tag is prohibited. Trivy v0.73.0 embeds
`trivy-checks@v1.12.2-0.20251219190323-79d27547baf5`; that identity is recorded
but not selected. External versus embedded source and whether fallback occurred
are part of execution identity. E0 sets `fallback_used` to false.

Future offline execution must preload and verify the exact external bundle in a
private cache before networking is disabled. Missing external checks may not
silently select the embedded copy. Such a switch needs a new identity and a
typed non-PASS result unless protected configuration authorizes it.

## Artifact and provenance records

Every tool record binds a version, upstream repository, release tag and commit,
per-architecture archive SHA-256, OCI multi-platform manifest and selected
architecture digest, signature or attestation availability, licence identity,
architectures, invocation contract, upstream output-fixture digest, offline
requirements, upgrade policy, and the scope of E0 compatibility review.

Signature records describe what upstream published; E0 did not claim that a
signature was cryptographically verified. A future build gate must verify the
selected archive or image against the protected keys/identity policy before it
can contribute to a verified environment.

No execution or example configuration may use `latest`, a moving major tag, or
an unqualified image tag. Terraform is locked for interoperability but remains
user-supplied and is never copied into an IaC-Guard-V image. TFLint remains
optional and cannot satisfy a security validator gate.

## Hardened-container base

The base was selected only after the full prospective tool set showed common
linux/amd64 and linux/arm64 availability. The research lock records
`docker.io/library/debian:bookworm-slim` at index
`sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241`,
plus both platform-manifest digests. This is a dependency decision, not a
container implementation or authorization to execute scanners.

## Upgrade and compatibility policy

An upgrade is an atomic lock change. It refreshes the release commit, archives,
image indexes and platform manifests, signatures, licence, output fixture,
invocation contract, offline material, and compatibility result. A Trivy upgrade
also refreshes external and embedded checks and cache identities. The hardened
base changes only after architecture and tool compatibility are reassessed.

Runtime compatibility, output-schema validation, signature verification,
network isolation, and multi-scanner semantic integration are future Phase-E
implementation gates. Nothing in E0 weakens accepted Phase-D contracts.

## E0 validation evidence

```text
PHASE_E_LOCKS: PASS (6 tools, 2 architectures, immutable digests)
```

Mutation tests cover missing fields, malformed OCI digests, moving Trivy check
tags, prohibited Terraform bundling, Trivy fallback, and a floating base tag.

NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED

NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V

MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
