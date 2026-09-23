# IaC-Guard-V 1.0 finalization implementation

Status: private release-candidate engineering. This record does not authorize a tag,
push, GitHub Release, PyPI publication, or Zenodo deposit.

## Phase 5: stable documentation

The candidate contains release-facing README, scope, security, compatibility,
native-property, scanner-authority, migration, release-note, and support documents.
The README provides copyable Kubernetes, Terraform, and read-only CI quickstarts. The
documentation names all 18 stable native V1 properties, separates native and contract
exit codes, preserves v1alpha1 compatibility, and does not claim universal IaC or
hostile-input verification.

## Phase 6: security and supply chain

The build backend and frontend are exact candidate dependencies. Candidate tooling
performs two isolated-output builds under one source epoch and rejects non-identical
wheel or sdist bytes. The packet includes an exact source manifest, SHA-256 manifest,
CycloneDX SBOM, dependency inventory, license inventory, SLSA-format local provenance
statement, security audit, and attestation identities. Distribution inspection rejects
private paths, immigration material, and private-evidence directory markers.

The protected release workflow remains manual, requires the exact reviewed commit and
artifact hashes, downloads rather than rebuilds the reviewed GitHub Release artifacts,
verifies the whole evidence packet, creates GitHub/Sigstore build provenance, and then
uses PyPI Trusted Publishing. It executes from `main`, matching the live `pypi`
environment branch policy, while independently requiring the reviewed `v1.0.0` release
to target the exact authorized source commit. The workflow is prepared only; it is not
executed by this program.

## Phase 7: clean-user usability

`tools/usability_1_0.py` creates a fresh Python 3.12 environment, installs the candidate
wheel without the source checkout, runs native doctor, runs Kubernetes satisfied,
violated, and not-evaluated cases, runs a Terraform satisfied case, and confirms that
the JSON report exposes result, reason, request, definition, witness, and semantic
boundary fields. The gate fails above 15 minutes.

## Phase 8: private candidate gate

The candidate version is `1.0.0` only on the local private candidate branch. The final
source identity must pass the repository `pr` profile once, the owner-authorized fresh
`release` profile once, Python 3.10-3.13, the 32-case external replay, QRS replay,
coverage, package, exact-wheel, quickstart, repeat-build, and private-path gates.

The resulting artifacts remain local. Actual Sigstore attestations, an annotated source
tag, a GitHub Release, PyPI files, and a Zenodo version archive are publication actions
and remain prohibited until separate explicit owner authorization.
