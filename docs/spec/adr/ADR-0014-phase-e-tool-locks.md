# ADR-0014: Phase-E tool locks are immutable execution identities

## E0.3 physical-cache and current-runtime amendment

The protected cache is one signed complete lstat inventory. It records real
directories and regular files, forbids symlinks and all special entries, hashes files
through no-follow descriptors, and rejects every unlisted path. Source verification
revalidates that inventory before runtime; runtime verification revalidates it before
and after every network-disabled process.

Current Trivy verification is byte-bound, not inferred from a lock-authored Boolean.
The exact network, mount, environment, architecture, image, external manifest, policy
layer, cache, and fallback contract are retained. Trivy report IDs and timestamps are
normalized by a versioned script inside the locked image; normalized stdout, normalized
stderr, canonical JSON, exit code, and external-check diagnostics must reproduce the
lock. A different schema-valid output is a runtime failure. Version-only smoke records
remain explicitly non-authoritative for future adapters. The kubeconform schema bundle
continues to carry `NOASSERTION`; redistribution remains blocked.

## Status

Accepted for E0.2 dependency-lock verification. Scanner, validator, production
container, and action implementation remain deferred pending review.

## Context

Phase E will combine independently released executables and policy bundles. A
version string or floating tag does not bind executable bytes, architecture,
bundled policy, output structure, or offline behavior. Trivy also has external
and embedded policy sources. Terraform must not be silently bundled.

## Decision

`tools/locks/phase-e-locks.json` is the reviewed, canonically sealed lock graph.
Each prospective tool binds its repository, release tag and full commit,
version-pinned archive URLs and bytes, checksum manifest, structured signature
evidence, licence and output-fixture bytes, OCI index, both supported platform
children, canonical digest-qualified execution references, invocation, offline
inputs, runtime-smoke evidence, and upgrade rule. The Markdown review is
generated from that JSON rather than maintained as a competing source.

KICS v2.1.21 is rejected as a runtime selection because its release lacks
official binary archives and the official image repository lacks that tag.
v2.1.20 is selected instead.

Trivy v0.73.0 is locked independently from `trivy-checks` v2.2.0. The external
check manifest, embedded-check commit, cache identity, selected source, and
fallback flag form check execution identity. The moving `:2` reference is not
an execution lock.

OpenTofu v1.12.5 is the prospective bundled Terraform validator. Terraform
v1.15.8 is interoperability-locked but user-supplied only. kubeconform v0.8.0
is the prospective Kubernetes validator. TFLint v0.64.0 is optional,
non-security evidence.

The prospective hardened base is selected only after tool and architecture
review. Both the multi-platform index and linux/amd64 and linux/arm64 manifests
are pinned. Execution must use a recorded `repository@sha256:digest` reference.

kubeconform is also bound to an offline Kubernetes 1.34.0 strict and non-strict
schema subset at one full `kubernetes-json-schema` commit. Its extracted tree
roots and combined content digest are verified. Network schema fallback and
unlocked CRD schemas are prohibited. The generated schema repository has no
root licence file, so its licence remains `NOASSERTION` pending redistribution
review.

The structural validator reports `PHASE_E_LOCK_SCHEMA`; this proves shape,
cross-field consistency, and the canonical lock seal only. A distinct protected
cache mode reports `PHASE_E_LOCK_SOURCE` after hashing actual archives,
reconciling checksum manifests, rerunning the three verified OpenPGP checks,
verifying OCI child membership, and checking fixture, licence, schema, and Trivy
checks bytes. Sigstore material that was cached but not identity-policy verified
is explicitly `AVAILABLE_NOT_VERIFIED`; absent signatures are `UNAVAILABLE`.

The lock graph itself records source/runtime verification requirements, not
self-authored PASS claims. Cached tag evidence is parsed as an exact ref map:
annotated tags must peel to the locked commit and lightweight tags must equal it.
Source PASS requires the signed complete protected-cache manifest and every real
cached byte. Runtime PASS requires re-executing both-architecture version smokes
and both Trivy external-check scans.

## Consequences

- E0.2 creates no adapter, validator integration, production container, or
  GitHub Action.
- Static compatibility records remain `STATIC_REVIEW`. Version-only offline
  image smoke does not claim output compatibility.
- KICS, OpenTofu, and Terraform checksum signatures are reproducibly verified;
  other signature states remain narrower and explicit.
- External-versus-embedded Trivy fallback changes execution identity.
- Trivy's exact external bundle was loaded from the bound cache with networking
  disabled and `fallback_used=false`; this smoke does not authorize an adapter.
- Runtime records bind argv, environment allowlist, network and filesystem
  modes, exact image/index/platform identities, exit and output hashes,
  architecture, duration, and verifier build identity. A version smoke never
  establishes an adapter output contract.
- Upgrades rerun contract, architecture, fixture, signature, licence, and
  offline reviews and update the complete lock atomically.
- An absent or mismatched artifact cannot be replaced by a nearby version or
  floating tag.
- Phase-D and frozen QRS evidence are unchanged.

## Alternatives rejected

Floating tags and version-only selections do not bind bytes. KICS v2.1.21 from
source alone leaves runtime identity unspecified. Invisible Trivy embedded
fallback changes the policy universe. Bundling Terraform violates the approved
user-supplied-only distribution contract.

## Validation

`python tools/validate_phase_e_locks.py` enforces the selected tool set, fields,
canonical seal, architectures, digest-qualified references, security roles,
schema lock, structured signature states, and Trivy source/fallback decision.
`--verify-cached-artifacts --artifact-cache <protected-cache>` verifies the real
cached source evidence. Mutation tests reject valid-looking substituted commits,
archive and OCI digests, prose verification claims, missing architecture or
schema locks, and embedded-check fallback.

## E1 execution amendment

The reviewed E0.3 KICS v2.1.20 lock is now consumed by a fail-closed adapter. Its first
offline contract execution uses the exact platform digest with networking disabled and
preserves official JSON and native similarity evidence. This amendment authorizes only
KICS typed scanner evidence; it does not authorize Trivy, validators, consensus,
production containers, or Actions.

## E2 execution amendment

The reviewed E0.3 Trivy v0.73.0 platform image and external checks v2.2.0 cache are now
consumed by a fail-closed adapter. Runtime diagnostics, current cache metadata/content,
checks manifest/layer, fallback state, network/update state, and canonical native JSON
are bound separately. The finding fixture is a complete PASS; a live finding-free shape
with only repository-global positives remains `PARTIAL` because it cannot affirm file
or resource coverage. This authorizes typed Trivy evidence only, not consensus,
validators, production containers, or Actions.

## E1.1 contract amendment

The E0.3 KICS image now runs with `--pull never` and the complete severity/result exit
family. Summary arithmetic, TRACE/BOM separation, and optional native fields are bound
without authorizing consensus.

## E2.1 physical-cache amendment

Raw cache paths are not trusted scanner configuration. The signed cache verifier must
construct the immutable capability, and E2.1 verifies its exact Trivy subtree before
and after scanning. Metadata-only substitution and pass/fail contradictions are
integrity failures.

## E1/E2.1 execution-boundary amendment

The lock is exercised only through adapter-owned execution. Exact argv, process streams,
native output, sealed inputs, and cache checks form one chain. Unit normalizers are
private and are not adapter authorization.
