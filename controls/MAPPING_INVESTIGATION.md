# Phase E control relationship investigation

## Decision

Catalog v2 (retained at the stable `catalog-v1.yml` path) publishes **zero `EXACT`
mappings**. It records two useful `OVERLAPPING` Kubernetes relationships without
treating scanner agreement as ground truth. A target count was deliberately not used.

The machine-readable source is [`catalog-v1.yml`](catalog-v1.yml). The checker
rejects unknown relationship classes, unapproved repositories, tag/commit drift,
non-commit source URLs, source-byte drift, missing locked fixture evidence, duplicate
scanner IDs, and any `EXACT` entry without mechanically verified review evidence.

## Method

The investigation compared implementation semantics at the versions and policy
identities pinned by Phase E:

| Scanner | Reviewed identity |
| --- | --- |
| Checkov | 3.3.0, source commit `5b5ce3e65339c78ca9977e06beb504240db95fdc` |
| KICS | 2.1.20, source commit `e1f23cad9640f55b963f22a116b04906b8c16ac6` |
| Trivy checks | 2.2.0, source commit `d7c9302130a9b7e614a5c5d32854f6a08b4bc52e`, external manifest `sha256:b63166ca…` |

For each candidate, the review retained a positive, negative, and boundary
fixture; compared explicit/default values; recorded resource selectors and
known differences; and checked the actual rule/query source rather than names or
descriptions alone. Each source record binds the exact reviewed repository, release
tag and commit, commit-pinned URL, relative path, byte digest, and canonical
source-attestation identity. `tools/check_catalog.py --verify-sources` re-resolves the
official tag refs and verifies the six source files.

## Locked execution evidence

`runtime-evidence-v1.json` records all 18 scanner/fixture cells from the protected
arm64 execution environment. The preserved E4.1 matrix contained 11 `PASS` and seven
`ERROR` records; all six Trivy cells and one KICS boundary cell were errors. E4.2 reran
the matrix with complete expected resource bindings. Its current distribution is six
`PASS`, five KICS `PARTIAL/COVERAGE_MISMATCH`, and seven typed `ERROR` records. All six
Trivy cells remain `ERROR/INVALID_RESULTS_STRUCTURE`, while Checkov completes all six.
These are bound execution records, not 18 successful behavioral demonstrations.

The v2 runtime evidence closes its top-level architecture and protected-evidence
identity, retains exit code, diagnostics, portable locked argv, duration and raw/canonical
output hashes, and binds every record to one reviewed protected execution attestation.
The checker will not accept a locally re-sealed substitute. A future `EXACT` mapping
also requires definitive non-error results for all nine cells plus a referenced,
byte-verified and signature-verified independent sign-off. Typed errors and partial
coverage remain explicit blockers rather than being rewritten as agreement.

## Findings

### Privileged containers

`CKV_K8S_16`, KICS `dd29336b-fe57-445b-a26e-e6aa867ae609`, and Trivy
`AVD-KSV-0017` all detect an explicitly privileged container. They remain
`OVERLAPPING`: the scanners use different workload selectors, normalization
libraries, locations, and occurrence identities. Exact equality over every
supported workload and malformed-input boundary has not been independently
reviewed and signed.

### Privilege escalation

`CKV_K8S_20`, KICS `5572cc5e-1e4c-4113-92a6-7a8a3bd25e6d`, and Trivy
`AVD-KSV-0001` all require `allowPrivilegeEscalation: false` in their selected
container scope. They remain `OVERLAPPING` for the same selector and
normalization boundaries. The omission fixture is retained because default and
missing-field behavior is part of the relationship, not incidental test data.

## Use boundary

This catalog is advisory research evidence. It cannot prove target resolution,
override a protected oracle, or change a final policy verdict. Promotion to
`EXACT` requires a new catalog version and the complete evidence package
enforced by `tools/check_catalog.py`.
