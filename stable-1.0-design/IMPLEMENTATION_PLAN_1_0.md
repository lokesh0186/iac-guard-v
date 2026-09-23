# IaC-Guard-V 1.0 phased implementation plan

No phase begins until the support contract and compatibility policy are approved.
No pull request, release, or public announcement is authorized by this plan.

## Phase 1: native-property core freeze

1. Generate a traceability record for all 18 public V1 properties.
2. Fill any missing positive, negative, ambiguous, incomplete-universe, and
   adversarial fixture class.
3. Freeze property IDs, versions, schemas, semantic definitions, witness types,
   result meanings, and reason-code classes.
4. Mark container-security and generic Terraform attribute/block properties as
   post-1.0 work rather than expanding the release.

Exit gate: every property has deterministic, complete, reviewed evidence and no
known correctness defect.

## Phase 2: scanner-authority cleanup

1. Encode the Checkov authoritative-path allowlist explicitly.
2. Make Trivy and KICS advisory status unambiguous in API, reports, and docs.
3. Add assertions preventing pass-from-absence, majority voting, predicate
   collapsing, and adapter-owned universe changes.
4. Re-run exact same-predicate and discrepancy fixtures.

Exit gate: no scanner can create authoritative success outside an approved
property/target evidence contract.

## Phase 3: API and schema freeze

1. Turn `beta-public-api-v1` into an executable 1.x compatibility golden.
2. Golden-test every CLI command, option, enum, output mode, and exit code.
3. Implement the v1alpha1 compatibility reader and stable-v1 bridge without
   changing existing inputs or reports.
4. Document public versus private Python modules and the deprecation policy.

Exit gate: every Beta1 public-surface fixture passes unchanged.

## Phase 4: external compatibility replay

1. Refresh authenticated GitHub issue, PR, and Discussion inventory.
2. Materialize an executable manifest for every IaC-Guard-V-dependent public
   artifact.
3. Replay K8sGPT, IaCSecBench, Argo, CloudNativePG, Prometheus archival,
   cert-manager, dflook, pre-commit-terraform, Kubescape, KubeLinter, Trivy,
   Checkov, tofu-ls, Kueue, and every other public case in the manifest.
4. Compare Beta1 and 1.0 RC semantics, structure, result, reason class, exit,
   witness facts, and consumer parsing.
5. Reject release on any unexplained `BREAKING` or newly `UNSUPPORTED` row.

Exit gate: all relevant rows are `UNCHANGED` or explicitly reviewed
`STRICTER_BUT_COMPATIBLE`; existing public workflows need only a package-pin
change.

## Phase 5: stable documentation and adoption experience

1. Prepare the eight release-facing documents in the documentation plan.
2. Add Kubernetes and Terraform/OpenTofu quickstarts.
3. Add one read-only pip-based GitHub Actions example without a bespoke Action.
4. Run the recorded non-implementer workflow and fix every documentation defect.

Exit gate: a new user completes install through machine-readable interpretation
without implementer assistance and within the declared time target.

## Phase 6: security and adversarial review

1. Threat-model the final stable surfaces.
2. Run every process, parser, materializer, schema, integrity, suppression,
   partial-output, ambiguity, and resource-limit adversarial test.
3. Audit wheel/sdist contents, licenses, dependency bounds, redaction, and
   temporary-file behavior.
4. Confirm no inference/model-provider or live deployment action occurs.

Exit gate: zero known correctness defect within supported scope and no open
security release blocker.

## Phase 7: release candidate validation

1. Produce `1.0.0rc1` only after Phases 1-6 pass.
2. Run `focused` and `dev` during work, one `pr` profile on the final candidate,
   then the owner-authorized clean `release` profile.
3. Run Python 3.10-3.13, exact-wheel, exact-sdist, QRS replay, external replay,
   repeat-build, SBOM, and attestation gates.
4. Freeze release notes, migration, hashes, source identity, and known limits.

Exit gate: the RC is release-equivalent except for the version label and has no
unresolved blocker.

## Phase 8: final 1.0 release gate

1. Create the exact source tag from the validated commit.
2. Build once through the protected trusted workflow.
3. Verify artifacts, SBOMs, attestations, and hashes before publishing.
4. Publish PyPI, GitHub release, and Zenodo archive.
5. Reinstall the exact public wheel and repeat smoke and compatibility checks.
6. Record immutable evidence and only then update the version-facing docs.

Estimated scope: medium-to-large hardening program, approximately 4-8 focused
engineering weeks depending on compatibility replay automation and schema-bridge
findings. This estimate excludes new property families and a Marketplace Action.
