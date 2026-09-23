# IaC-Guard-V 1.0 release-quality gate

Every item is mandatory unless explicitly marked optional.

## Correctness and compatibility

- zero known correctness defects in the declared support contract;
- all 18 native-property traceability rows complete;
- all positive, negative, ambiguous, incomplete, and adversarial suites green;
- every external compatibility row adjudicated with zero breaking consumers;
- frozen QRS artifact replay unchanged in the fields governed by the research
  contract;
- Beta1 CLI, schemas, Python exports, provenance, exit codes, and report-reader
  goldens green;
- stable-v1/v1alpha1 bridge and migration tests green.

## Test profiles

- follow `docs/TESTING.md` without manually recreating compatibility environments;
- Python 3.10-3.13 full matrix;
- current coverage threshold or higher, never reduced to pass;
- `pr` profile once on the final candidate;
- owner-authorized clean `release` profile on the exact release commit;
- exact-wheel and exact-sdist clean-install smoke;
- no source-checkout import leakage;
- repeat-build comparison with explained platform metadata and identical package
  contents;
- offline and failure-path tests for supported modes.

Python 3.14 is not required for 1.0. The explicit `<3.14` bound remains until
the complete matrix, packaging, dependency, and adversarial profiles pass. It may
be added in a backward-compatible 1.x release.

## Supply chain and publication

- PyPI Trusted Publishing from the protected release workflow;
- wheel and sdist hashes verified before and after publication;
- SPDX or CycloneDX SBOMs for release artifacts;
- GitHub artifact attestations or equivalent build provenance;
- signed or otherwise cryptographically attributable annotated source tag;
- immutable GitHub release with hashes, SBOMs, attestations, and migration notes;
- PyPI `1.0.0` publication;
- Zenodo version archive linked to the concept DOI;
- updated `CITATION.cff`;
- `SECURITY.md`, support policy, compatibility policy, and vulnerability-reporting
  route verified.

## Usability

A non-implementer must complete, without live help:

1. clean install;
2. `doctor`;
3. illustrative demo;
4. a real Kubernetes or Terraform/OpenTofu verification;
5. a copyable GitHub Actions workflow using `pip install iac-guard-v==1.0.0`;
6. a deliberate failure and interpretation of the non-success result;
7. machine-readable report consumption.

A bespoke Marketplace Action or maintained container is not a 1.0 requirement.
The older product specification that assumes an Action must be revised before
implementation. A pip-based GitHub Actions example meets the onboarding need
without creating another support surface. A first-party Action may be added later
when adopter demand justifies its maintenance burden.

## Release artifacts and evidence

The final release packet records UTC timestamps, commit/tree/tag, workflow run,
test counts, coverage, package manifests, hashes, SBOM hashes, attestation links,
PyPI files, GitHub release, Zenodo record, and the external replay manifest. No
release claim is made from a reusable development environment.
