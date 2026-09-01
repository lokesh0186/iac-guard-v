# IaC-Guard-V 0.1.0b1 release checklist

This public checklist records the Beta1 release boundary. It does not itself authorize
a tag, upload, publication, or announcement. Run it only from the exact owner-approved
release candidate and preserve every failed gate as evidence.

## Source and version

- [ ] Record the exact clean source commit and Git tree.
- [ ] Confirm package version `0.1.0b1` and Beta classifier in built metadata.
- [ ] Confirm the project-standard tag is `v0.1.0-beta.1` before creating it.
- [ ] Confirm the complete staged file inventory contains only reviewed product,
      public documentation/tests, and intentional public evidence.
- [ ] Confirm no frozen QRS, historical report, adoption record, screening packet,
      private evidence, or unrelated worktree file changed.
- [ ] Confirm `paper.pdf`, credentials, private absolute paths, `.pyc`,
      `__pycache__`, and temporary build/test files are absent from release inputs.

## Public interfaces and compatibility

- [ ] API, CLI help, exit-code, public-export, property-registry, and schema snapshots
      match the reviewed Beta1 identities.
- [ ] Contract API remains `iac-guard-v.io/v1alpha1`.
- [ ] Contract report remains `infrastructure-contract-report-v1alpha1`.
- [ ] All 17 historical native properties retain their frozen semantic definitions.
- [ ] `IACGV_TF_REFERENCE_RESOLVES_V1` produces unchanged Terraform V1 semantics.
- [ ] Exact KAITO, Kueue, and Thanos contract bytes lint, plan, and verify without
      migration, provenance, clause, or selection changes.

## OpenTofu

- [ ] `IACGV_OPENTOFU_REFERENCE_RESOLVES_V1` is the only new property.
- [ ] `.tofu`, `.tofu.json`, `.tf`, and `.tf.json` effective-source rules pass.
- [ ] Same-basename precedence and shadowed-file witnesses pass.
- [ ] Bounded override and contained local-module tests pass.
- [ ] Malformed effective files never fall back to shadowed files.
- [ ] Missing, remote, dynamic, cyclic, escaping, symlinked, duplicate, and ambiguous
      inputs retain typed fail-closed behavior.
- [ ] The content-bound real-world compatibility corpus matches its frozen manifest.

## Scanners and tools

- [ ] Checkov 3.3.0 reviewed authoritative paths and policy identity pass unchanged.
- [ ] KICS remains advisory; zero findings do not become target pass.
- [ ] Trivy remains advisory; exact bundle/cache diagnostics remain visible.
- [ ] Scanner voting remains disabled.
- [ ] Helm and Kustomize identities and bounded local materialization tests pass.
- [ ] No remote module/dependency fetch, live cluster/cloud query, hidden update, or
      model-provider call occurs in authoritative native/contract verification.

## Complete release profile

- [ ] Run the owner-authorized clean `release` profile exactly once from the beginning.
- [ ] Python 3.10, 3.11, 3.12, and 3.13 pass with no unexpected skip.
- [ ] All functional tests pass with zero failures and errors.
- [ ] Branch coverage is at least the unchanged 90% threshold.
- [ ] Documentation, links, examples, API/schema snapshots, scanner boundaries,
      compatibility corpora, determinism, and dependency checks pass.
- [ ] Frozen QRS is exactly 4,842/4,842 files, 630/630 replay records,
      10,080/10,080 fields, and 7/7 `SEMANTIC_MATCH`, with root
      `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`.

## Build and package contents

- [ ] Build one wheel and one sdist from the exact approved source in a fresh output
      directory; never reuse prior development artifacts.
- [ ] Record the build backend, source commit/tree, filenames, sizes, and SHA-256s.
- [ ] Audit the complete wheel and sdist inventories against the narrow allowlist.
- [ ] Confirm both artifacts exclude private/research/design/release-working evidence,
      arbitrary nested README/LICENSE files, local paths, secrets, tests, bytecode,
      caches, `.git`, and temporary files.
- [ ] Confirm required code, schemas, policies, locks, public docs, root README,
      license, notice, changelog, citation, Beta1 notes, and this checklist are present.
- [ ] Build/install from the sdist and install the wheel in separate clean environments.
- [ ] Run artifact-only version, doctor, property/support discovery, contract
      init/lint/plan/verify, Terraform/OpenTofu, Checkov, report validation, and explain
      smokes without source-checkout fallback.
- [ ] Record repeated-build determinism truthfully; do not claim reproducibility unless
      byte equality is proven under the reviewed build contract.

## Documentation and citation

- [ ] README, installation, security, support matrix, OpenTofu, CI, changelog, release
      notes, package description, and help text describe Beta1 consistently.
- [ ] Historical a10 release records and DOI references remain unchanged.
- [ ] `CITATION.cff` names `0.1.0b1`, retains the Concept DOI, and does not invent a
      version DOI or release date before publication.
- [ ] The software citation remains distinct from the QRS paper citation.
- [ ] Limitations reject full Terraform/OpenTofu, cloud/runtime/live-cluster, scanner
      replacement, and universal security claims.

## Publication, only after separate owner authorization

- [ ] Create the exact reviewed release commit and project-standard tag.
- [ ] Create a GitHub prerelease containing the audited wheel and sdist bytes.
- [ ] Bind the Trusted Publishing workflow to the exact tag, source, filenames, and
      SHA-256s; publish without rebuilding.
- [ ] Verify PyPI version, artifact hashes, OIDC provenance, and attestations.
- [ ] Run a PyPI-only fresh installation smoke without local-source fallback.
- [ ] Create the Zenodo Beta1 version record and preserve Concept DOI
      `10.5281/zenodo.22088272`.
- [ ] Verify GitHub, PyPI, Zenodo, tag, source, artifact, and citation identities agree.
- [ ] Publish an immutable Beta1 release record after every public identity is known.

Publication items above remain unchecked until separately authorized and completed.
