# ADR-0010 — Version and digest locking, with `--locked` making drift an error

- Status: Accepted
- Date: 2026-08-09

## Context

Scanner behaviour is version-dependent. Rules are added, renamed, retired, and
re-scoped; Trivy's checks bundle evolves independently of its binary. A comparison
between a baseline scanned with one version and a candidate scanned with another is not
a comparison of the change — it is a comparison of two tools.

This is live on the development machine: the research pin is Checkov 3.2.517 and the
installed version is 3.3.0.

## Decision

`iac-guard.lock.yml` records scanner versions, container image digests, the Trivy
checks-bundle digest, schema-bundle versions, and policy hashes. The lock digest appears
in every report.

- Default mode: drift is detected, reported, and compatibility-checked.
- `--locked`: any drift is an error, exit 3.
- Baseline and candidate must be scanned by the same version; a difference is
  `RULE_OR_SCANNER_DRIFT`, never a finding delta.
- A locally built container image is identified by image ID. A registry digest is used
  only after a push. Verified locally: a never-pushed image reported a `RepoDigests`
  entry equal to its own image ID and bound to no registry, so treating that value as
  provenance would record a meaningless digest.

## Consequences

- Reproducible verdicts across machines and over time.
- A nightly job tests current stable scanner releases and may open an issue, but never
  silently widens the support matrix.
- Users must regenerate the lock to upgrade a scanner, which is the intended friction.
- Air-gapped users get a lock they can audit against their internal mirror.

## Alternatives considered

**Track "latest".** Rejected: verdicts change under users without any change to their
code.

**Pin only the binary, not the checks bundle.** Rejected: for Trivy the bundle is where
the policies live, so an unpinned bundle is an unpinned policy set.

## Amendment, 2026-08-10: D4 native Checkov evidence

The D4 Checkov request requires an expected version and SHA-256 of the strictly resolved
native launcher. The digest is verified at construction and immediately before probe and
spawn; the probe, every `summary.checkov_version`, and the trusted expected version must
agree. The launcher digest is recorded separately from process-output and raw-JSON
digests.

This does not pretend that hashing a Python console script binds its full dependency
environment. Product Checkov 3.3.0 has a pinned live integration job. Research 3.2.517
has a D4 parser fixture and frozen replay evidence, while its current executable/image
integration remains Phase E and is not labelled supported native execution.
