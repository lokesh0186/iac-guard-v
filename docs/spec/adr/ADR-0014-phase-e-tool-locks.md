# ADR-0014: Phase-E tool locks are immutable execution identities

## Status

Accepted for E0 dependency research. Scanner, validator, container, and action
implementation are deferred pending review.

## Context

Phase E will combine independently released executables and policy bundles. A
version string or floating tag does not bind executable bytes, architecture,
bundled policy, output structure, or offline behavior. Trivy also has external
and embedded policy sources. Terraform must not be silently bundled.

## Decision

`tools/locks/phase-e-locks.json` is the reviewed executable lock contract. Each
prospective tool binds its repository, release tag and commit, archive hashes,
multi-platform image manifest, selected architecture digest, signature or
attestation status, licence, invocation, output fixture, offline inputs, upgrade
rule, and compatibility-review result.

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
are pinned. Execution must use a digest.

## Consequences

- E0 creates no adapter, validator, container, or GitHub Action.
- Static review does not claim runtime compatibility or signature verification.
- External-versus-embedded Trivy fallback changes execution identity.
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
digest forms, architectures, non-floating references, security roles, and Trivy
source/fallback decision. Mutation tests prove the material guards.
