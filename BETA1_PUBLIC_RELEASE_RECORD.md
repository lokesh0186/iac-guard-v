# IaC-Guard-V 0.1.0b1 public release record

Disposition: `BETA1_PUBLIC_RELEASE_VERIFIED`

IaC-Guard-V `0.1.0b1` was published from the reviewed Beta1 candidate. Beta1 adds
bounded first-class OpenTofu effective-source verification and adoption-facing API/UX
hardening while preserving the existing 17 native property definitions, Terraform V1,
the contract and report v1alpha1 formats, and scanner-authority boundaries.

## Release source identity

- Release source commit: `b538ad931f193aa7786694080a0beca2a04bbd76`
- Release source tree: `7af1e3f0a2c9803e91e880db3188d6a73724402c`
- Signed annotated tag: `v0.1.0-beta.1`
- Tag object: `cdcc8b699f2281768b416b97b1eb4033f87b1588`
- Tag target: `b538ad931f193aa7786694080a0beca2a04bbd76`
- Commit and tag signing-key fingerprint:
  `SHA256:FyTyV+ggDICMoTYTFC0AJxD0UsZk7AYuHavqCFVsBkk`
- Local `git verify-commit` and `git verify-tag`: `PASS`
- GitHub signature state at publication: `unknown_key`. GitHub preserved both SSH
  signatures but did not associate this release key with the account; this is the same
  externally reported signature state as the established alpha10 release practice.

The tag remains fixed on the release source. A later signed main-branch commit,
`dcbf18caa0939c759d489376b2424e0e80909238`, bound Trusted Publishing to the exact
tag, source commit, artifact names, and artifact hashes. Its tree is
`65c890aaf6070d0a6bcca47a71e4cec96ccd07fe`; it did not alter the tagged release or
artifact bytes.

## Validation lineage

The release-engineering record preserves the complete chronology rather than treating
the first attempt as successful:

1. The compatibility design retained contract/report v1alpha1 and Terraform V1.
2. The first implementation PR profile exposed 89.16% branch coverage against an
   unchanged 90% threshold.
3. Genuine uncovered Beta1 behavior received meaningful behavioral tests.
4. One newly added schema-test expectation was adjudicated as incorrect; the schema
   and implementation remained unchanged.
5. Focused coverage reached 90.64% without exclusions or threshold changes.
6. A replacement profile was blocked by restricted PyPI resolution and Unix-domain
   socket creation; environment adjudication found no product-semantic defect.
7. The environment-capable replacement PR profile passed 16,138 / 16,138.
8. Owner release review identified only bounded wording, allowlist, and help
   discoverability work.
9. Two release-readiness test oracles were corrected for argparse wrapping and
   semantically equivalent checklist prose; no product behavior changed.
10. The canonical release profile and fresh final-candidate Python matrix below passed.

## Final validation evidence

The canonical release profile ran in a fresh CPython 3.12 environment against the
final candidate:

- Run: `.test-results/20260901T201748Z-release`
- Result: `PASS`
- Executions: 6,346 / 6,346
- Failures/errors/skips: 0 / 0 / 0
- Native-property branch coverage: 90.63841201716738%
- Required threshold: 90%, unchanged
- Checkov integration: 9 / 9
- Packaging: 14 / 14
- Installed-wheel golden workflow: 1 / 1
- Summary SHA256:
  `e445d4d780a2a43198959b6eae0c321e20127b03990e15cfa2854179f82da6be`

A separately authorized fresh final-candidate matrix preserved the repository's
intentional separation between its Python 3.12 release profile and compatibility
matrix:

- Run: `.test-results/20260901T224111Z-matrix`
- Result: `PASS`
- Total: 13,056 / 13,056
- Python 3.10.20: 3,264 / 3,264
- Python 3.11.6: 3,264 / 3,264
- Python 3.12.4: 3,264 / 3,264
- Python 3.13.15: 3,264 / 3,264
- Failures/errors/skips: 0 / 0 / 0
- Summary SHA256:
  `1e28e1f2a28268839a6f8c94378f21a57063701bc4917fdf3445cc071d512d5d`

Both profiles recorded the pre-commit candidate base
`dec4feb073e99b465d59c5c8cb435fbefd3dc42a` with the same reviewed dirty candidate
files. Those exact reviewed files were committed without substantive changes as the
release source and tree above.

## Frozen QRS preservation

- QRS primary replay: 4,842 / 4,842
- QRS extended replay: 630 / 630
- QRS evidence assertions: 10,080 / 10,080
- Semantic matches: 7 / 7 `SEMANTIC_MATCH`
- Frozen QRS root:
  `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`

No QRS content was regenerated or modified.

## Published artifacts

- Wheel: `iac_guard_v-0.1.0b1-py3-none-any.whl`
  - Size: 467,901 bytes
  - SHA256: `4d5418ba9b4bb1cb9306eeb857732da19de37d896d9a932c4a54a5cb5a751244`
- Source distribution: `iac_guard_v-0.1.0b1.tar.gz`
  - Size: 457,709 bytes
  - SHA256: `7be64ff19d16b58e434737c0369ca0d300bdd195f2141c260e984851dbf90c37`

The reviewed artifacts were built once from an archive of the release commit with
`SOURCE_DATE_EPOCH=0`. The wheel contains 98 entries and the sdist 124 entries. The
sdist rebuilt to a byte-identical wheel. Complete inventory and extraction audits
found no bytecode, private adoption/research/screening evidence, test-result data,
local path, credential-shaped content, or Git metadata. GitHub and PyPI expose the
exact audited bytes.

## Public identities

- GitHub prerelease:
  <https://github.com/lokesh0186/iac-guard-v/releases/tag/v0.1.0-beta.1>
- PyPI project version: <https://pypi.org/project/iac-guard-v/0.1.0b1/>
- Trusted Publishing workflow:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33570066728>
- Trusted Publishing job:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33570066728/job/100061876198>
- Wheel provenance:
  <https://pypi.org/integrity/iac-guard-v/0.1.0b1/iac_guard_v-0.1.0b1-py3-none-any.whl/provenance>
- Sdist provenance:
  <https://pypi.org/integrity/iac-guard-v/0.1.0b1/iac_guard_v-0.1.0b1.tar.gz/provenance>
- Zenodo record: <https://zenodo.org/records/22239516>
- Version DOI: <https://doi.org/10.5281/zenodo.22239516>
- Unchanged concept DOI: <https://doi.org/10.5281/zenodo.22088272>

The GitHub prerelease was published at `2026-09-01T23:12:10Z`. PyPI received the
wheel at `2026-09-01T23:14:19.123879Z` and sdist at
`2026-09-01T23:14:21.103787Z`. Zenodo created the linked public version record at
`2026-09-01T23:12:26.981004Z` and records version `v0.1.0-beta.1` in the existing
concept lineage.

PyPI records digital publish attestations from GitHub repository
`lokesh0186/iac-guard-v`, workflow `release.yml`, and environment `pypi`. The official
`pypi-attestations` verifier validated both artifact subjects and SHA256 digests using
the system trust bundle.

## PyPI-only smoke

A fresh environment installed `iac-guard-v==0.1.0b1` solely from
`https://pypi.org/simple`, after normal Simple-index propagation, with no editable
checkout or local-wheel fallback. It passed:

- import and version;
- native doctor diagnostics;
- native property discovery, including the OpenTofu property;
- top-level contract and `contract init` discovery;
- creation and linting of a v1alpha1 contract;
- representative native Kubernetes relationship evaluation; and
- authoritative v1alpha1 report validation.

The representative contract returned `SATISFIED`; its report digest is
`775e305e3c0675a70485a864b0a58f7cc3cec35f62eacc33eab7da7eef525214`
and file SHA256 is
`78e98cdb49eb3011aba761c29d012e077c2cdc825d658071d80bb701efcd9f33`.
No local repository or temporary path appeared in the report.

Result: `PYPI_ONLY_BETA1_SMOKE_PASS`.

## Post-publication contract compatibility

The exact existing suggested-contract bytes were privately re-executed with the
public PyPI Beta1 installation and their exact retained upstream source snapshots.
No upstream record was changed.

| Contract | Raw SHA256 | Selected bindings | Native observations | Result | Provenance |
| --- | --- | ---: | ---: | --- | --- |
| KAITO | `4b840ef27e14c1b71524b17778b724242a22e08fa721058e5e23862ba2399b4f` | 7 | 21 | `SATISFIED` | `SUGGESTED_CONTRACT` |
| Kueue | `847f5b02baa4cc22968db1a4d9dd366d131b42defb08e38a0e6dc9935b50aaca` | 5 | 15 | `SATISFIED` | `SUGGESTED_CONTRACT` |
| Thanos Operator | `4de59016a5a76302a399704c0a9d29e7c0b2a9162fc6c0ccb1cea903be46ffaf` | 3 | 9 | `SATISFIED` | `SUGGESTED_CONTRACT` |

All three contracts linted, planned, and verified with their original v1alpha1 bytes,
same selected relationship semantics, no migration warning, no provenance change, and
no false `SATISFIED`. Their rendered-source hashes exactly matched the retained a10
records.

## Public metadata evidence hashes

- PyPI release JSON SHA256:
  `679cb2fa037c62b4df3d13b836e0a2600c5b7854c277d023494ddc9916e58f5c`
- Wheel provenance response SHA256:
  `3edbf120dd17e65d9fac90c41a03b1e24275a080bb8146b6feced04390413aaa`
- Sdist provenance response SHA256:
  `bbd65f4f0e7fb9b527dc1adafc9e79112260e5ac45391d98d86cea04cabd9c87`
- Zenodo record API response SHA256:
  `9dffb4460d8e5dc8d003351e1b354da8c75ee4f0bee0ab6d8daa2e8c9b61ce2b`

These hashes seal the publication-time service responses. Mutable service statistics
may change future response bytes; the immutable source, tag, artifact digests,
attestation subjects, and DOI identities above remain authoritative.

## Released scope and limitations

Beta1 adds `IACGV_OPENTOFU_REFERENCE_RESOLVES_V1` and a protected OpenTofu source
mode with reviewed effective/shadowed file semantics. It does not reinterpret
`IACGV_TF_REFERENCE_RESOLVES_V1`, any of the other existing native properties, or the
v1alpha1 contract/report formats. Checkov authority is unchanged; KICS and Trivy
remain advisory under their documented boundaries, and scanner voting is not used.

Remote module fetching, provider/cloud/runtime evaluation, live Kubernetes state,
arbitrary CRD interpretation, and complete OpenTofu/Terraform language execution are
not supported. Unsupported or ambiguous semantics remain fail closed.

`BETA1_PUBLIC_RELEASE_VERIFIED`
