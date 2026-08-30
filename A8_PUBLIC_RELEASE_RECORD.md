# IaC-Guard-V 0.1.0a8 public release record

Disposition: `A8_PUBLIC_RELEASE_COMPLETE`

IaC-Guard-V `0.1.0a8` was validated, packaged, and published from the reviewed a8
implementation. No product semantics were added during release validation. No frozen
research path was modified, no benchmark inference or model-provider call occurred,
and no external-project outreach was performed.

## Release source identity

- Release source commit: `aa82d1879786986a5e62dad55fa0fea8b8bbbcea`
- Release source tree: `3f3a23a7d0039a19eb3ea2c2144a90f4be2398a3`
- Signed annotated tag: `v0.1.0-alpha.8`
- Tag object: `c5c8774da8682e74129e8fdddfb0cd86e0c8f00c`
- Tag target: `aa82d1879786986a5e62dad55fa0fea8b8bbbcea`
- Commit and tag signing-key fingerprint:
  `SHA256:FyTyV+ggDICMoTYTFC0AJxD0UsZk7AYuHavqCFVsBkk`
- Complete Git tree manifest: 5,240 files; SHA256
  `5170c43ffd84104ee58ac8704b82e25354771363816ec993d0723c1b2ff7316e`
- Product-source manifest: 54 files; SHA256
  `6c5587c4a06fc9e7c12a5e6d545e3ca3b34118b0985c033962ff85532aff530f`

The exact release commit was verified in a separate clean checkout before tagging.
The release tag remains fixed on that commit. A later signed main-branch commit,
`9321d6fa0fe7dcf978a73ff680a909c7627e4bdf`, bound the trusted-publication workflow
to the exact tag, release commit, and artifact hashes; it did not change the release
source or artifacts.

## Clean release-profile result

The owner-authorized `release` profile ran once to completion in a fresh environment:

- Run ID: `20260830T010337Z-release`
- Result: PASS
- Aggregate tests: 5,880
- Failures: 0
- Errors: 0
- Skips: 0
- Duration: 1,418.029 seconds
- Environment fingerprint:
  `8abfb5fa2b63675f2083260dd506deaf4443dadc6a22b7f858cfcac75ec3f7a1`

The passing gates comprised the 3,033-test release suite; D3 fingerprinting,
matching, and diffing; D4, D5, D6, and D7; scanner-neutral public-boundary tests;
539 Helm tests; 62 Kustomize tests; packaging and report/schema validation; clean
Checkov integration; the installed-wheel golden workflow; frozen QRS preservation;
and permanent 55-surface corpus validation.

All configured coverage thresholds were retained. The D7 coverage gate reported
89.854767% with zero-decimal display precision against the unchanged 90% threshold;
pytest-cov returned success and the release harness recorded the gate as PASS. This
rounding behavior is disclosed here rather than obscured or changed.

The first sandboxed bootstrap attempt could not install the declared build backend
because outbound package-index access was unavailable. It stopped before any release
test or gate ran. The authorized network-enabled run above is the sole completed
release-profile execution.

## Frozen preservation gates

- QRS primary replay: 4,842 / 4,842
- QRS extended replay: 630 / 630
- QRS evidence assertions: 10,080 / 10,080
- Semantic matches: 7 / 7 `SEMANTIC_MATCH`
- Permanent corpus: 9 `SUPPORTED`, 5 `PARTIALLY_REACHABLE`, 41 `FAIL_CLOSED`
- Corpus manifest SHA256:
  `b189031477e990cf70188adabf740b73cddf0ad7c3477ee4eb1c7b6a33c6292a`
- Corpus content-lock SHA256:
  `84e9c5cceb9e517658f61725696d94f77954b30c1a7888d33ad43aa0851152e5`
- Corpus replay-driver SHA256:
  `c4803877f17b7c5fcacbd8578385e0f270e599c9c56b5892ff21b739380321f5`
- Corpus final-result SHA256:
  `6f798f406257fa546c6fb52d135db4f192f733073c8a04a572213ff61817d785`

## Tool identities

- Git: 2.50.1 (Apple Git-155)
- Nox: 2026.8.17
- Release Python: CPython 3.12.4 arm64
- build: 1.6.0
- pytest: 9.1.1
- coverage.py: 7.16.0
- Hatchling isolated build backend: 1.32.0
- Checkov: 3.3.0
- Helm: v4.2.4+g3900f43; binary SHA256
  `ebf04b3606784d48568cf386483ac2b81fc747ed77859da4ba4f77df4c5e81d3`
- Kustomize: v5.7.1; binary SHA256
  `c7b2b13703ff6d8f06d88f22f7737bea7f7c072a151b39440875e3e046a13899`

## Reviewed artifacts

- Wheel: `iac_guard_v-0.1.0a8-py3-none-any.whl`
  - Size: 370,252 bytes
  - SHA256: `ef62cfedd3c4f8a3fa2bbdf4bad241a17c0f2c076a37cd6fc7bb008a0476015c`
- Source distribution: `iac_guard_v-0.1.0a8.tar.gz`
  - Size: 393,130 bytes
  - SHA256: `41a1b999e3945b50c8d08f29c6f9f05467468734515ef042f7a8af5dc6f3f45b`

The artifacts built cleanly with their package metadata and public documentation,
then passed an exact-wheel fresh copied-file smoke. After publication, a clean
PyPI-only installation fetched the same wheel from `pypi.org`, passed `pip check`,
reported `0.1.0a8`, completed the offline demo workflow, and produced no bytecode.

## Public identities

- GitHub prerelease:
  <https://github.com/lokesh0186/iac-guard-v/releases/tag/v0.1.0-alpha.8>
- PyPI project version: <https://pypi.org/project/iac-guard-v/0.1.0a8/>
- Trusted Publishing workflow:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33286324570>
- Trusted Publishing job:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33286324570/job/99190035606>
- PyPI attestation identity: GitHub publisher, repository
  `lokesh0186/iac-guard-v`, workflow `release.yml`, environment `pypi`, workflow
  source `.github/workflows/release.yml@refs/heads/main`, binding commit
  `9321d6fa0fe7dcf978a73ff680a909c7627e4bdf`
- Zenodo record: <https://zenodo.org/records/22167878>
- Version DOI: <https://doi.org/10.5281/zenodo.22167878>
- Unchanged concept DOI: <https://doi.org/10.5281/zenodo.22088272>

GitHub and PyPI expose the exact reviewed wheel and sdist hashes. PyPI provenance
contains one digital attestation per artifact with the identity above. Zenodo records
version `v0.1.0-alpha.8` in the existing concept-DOI relationship. The GitHub, PyPI,
and Zenodo version identities agree.

## Evidence hashes

- Completed release raw log SHA256:
  `e8d657d19888e35328ab8d0e0ad79e1c868b4c6052e6e87a24cb84d56cf87fb7`
- Release summary SHA256:
  `72afede107dc8c6eb0aece979cb899a03c6967c8a7aa9009d5103aa63b3f6bd2`
- Pre-gate sandbox-bootstrap log SHA256:
  `bbb65587e951dc2dc9e2d39d9dea81a68271cb0eb7ad1675ea2d72cf0615c414`
- Authoritative artifact-build log SHA256:
  `82b26da0326be7ac7dd56358721e5fbe3e0f4c9366ba9964b12cceda20c3f8e4`
- Focused packaging/public-documentation summary SHA256:
  `6f818fb2eaf1e40fb87cb67e58789961e71bc4586ceda81cdbbc684d0eb98742`
- GitHub release API evidence SHA256:
  `f569558a69d2f7d57034d5fc11f311f0ae92f3021a9532554688833bceb24350`
- Trusted Publishing run API evidence SHA256:
  `7905246c33f818695ee80fcb684d0c2650fa24e16da4a3cd5bdea1ce33b4caa5`
- Trusted Publishing raw log SHA256:
  `64096981b9b179e4488728df43a297fbf26b716670f8ab7125a8d55775ff02c0`
- PyPI JSON evidence SHA256:
  `e6010e3d5fdfdce562e281b4560103c764a6042e9a741f333900a9d5b3bf9270`
- Wheel provenance evidence SHA256:
  `a96d87d7436f79ab99fc29272bda92778825ffa00e33aa4f2378671cab18776a`
- Sdist provenance evidence SHA256:
  `11279bd4fbf2836e04d2ed0599e2024d4119b08cf4aba9fb21ce1cc9509ab9a2`
- PyPI-only install report SHA256:
  `60baa2c5e9235e0243972b8e8abaea0b94309f8bcbc7087c43c7c65f454f1b95`
- Zenodo record evidence SHA256:
  `fa43b37591dfde8e9f37c5699a9f3bce0340e1cc411b5eae408a4577ab532d5e`

## Released support contract

Alpha 8 adds the scanner-neutral verifier/evidence architecture; bounded Helm
dependency aliases and nested local dependency closure; Helm-compatible
dependency-version binding; equivalent duplicate named-template handling; bounded
namespace-provenance improvements; bounded deterministic local Kustomize
materialization; and stronger permanent real-world coverage/replay preservation.

Checkov remains the authoritative scanner path. KICS and Trivy remain advisory and
future adapter work. General Helm interpretation and broad Kustomize support are not
claimed. Remote dependency resolution is not supported. Helm `lookup` and other live
cluster state remain fail closed, and unsupported dynamic semantics remain fail
closed.

TerraRepair and all other external-project outreach remain deliberately deferred.
