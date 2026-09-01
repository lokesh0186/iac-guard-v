# IaC-Guard-V 0.1.0a10 public release record

Disposition: `A10_PUBLIC_RELEASE_COMPLETE`

IaC-Guard-V `0.1.0a10` was validated, packaged, and published from the reviewed a10
declared-intent implementation. It adds a closed intent-contract layer over the
unchanged 17-property a9 native registry. Checkov's reviewed authority is unchanged;
KICS and Trivy remain advisory. No scanner voting, model-provider call, benchmark
inference, external-project outreach, or live Kubernetes/cloud evaluation occurred.

## Release source identity

- Release source commit: `038bf38256706ffc83485bf5f33eb3c4992e3857`
- Release source tree: `228ddf20d2dcbf188abe90934ce86d5077bbb793`
- Signed annotated tag: `v0.1.0-alpha.10`
- Tag object: `337c7e7987a004138c7007d5d744805327c7bc69`
- Tag target: `038bf38256706ffc83485bf5f33eb3c4992e3857`
- Commit and tag signing-key fingerprint:
  `SHA256:FyTyV+ggDICMoTYTFC0AJxD0UsZk7AYuHavqCFVsBkk`
- Complete Git tree manifest: 5,356 files; SHA256
  `729d60ce69cb4d960e367ee64f8dbce436770061e7634aaaa3d3f8a930870f2b`
- Product-source manifest: 86 files; SHA256
  `49735a93a4a63c96397f121509208d961b6eeaa59a029aa285c7e74da56e4ce1`

The tag remains fixed on the release source. A later signed main-branch commit,
`29a7084f3b57c4abe0601e6bb42dd1d7686001e5`, bound Trusted Publishing to the exact
tag, source commit, artifact names, and artifact hashes. It did not alter release-source
or artifact bytes.

## Validation profiles

The implementation PR profile ran once before release preparation:

- Run: `20260901T062618Z-pr`
- Result: PASS
- Aggregate gate executions: 15,877
- Failures/errors/skips: 0 / 0 / 0
- Python matrix: 3.10, 3.11, 3.12, and 3.13; 3,215 tests per interpreter
- Checkov integration: 9 / 9
- Package tests: 14 / 14
- Installed-wheel golden workflow: 1 / 1
- QRS gate: 29 / 29
- Summary SHA256:
  `6530b319259bc5a2c4112fe892018a164bb7c2df6983290490866981b1b5f2a5`

The first clean release-profile invocation completed its local suite, coverage, QRS,
and package gates, then encountered a transient DNS failure while provisioning the
disposable Checkov environment. No test or semantic gate failed. After independent
network-health confirmation, the owner-authorized replacement ran once from a fresh,
clean, non-reused CPython 3.12.4 arm64 environment at the exact release source:

- Run: `20260901T071707Z-release`
- Result: PASS
- Aggregate gate executions: 6,204
- Failures/errors/skips: 0 / 0 / 0
- Duration: 1,448.380 seconds
- Environment fingerprint:
  `5c6c5ce5a064d5614717699794cd091cd6149771c079df3972e841ac1bea0b00`
- Native-property tests: 91 / 91
- Intent-contract tests: 68 / 68
- Helm tests: 539 / 539
- Kustomize tests: 62 / 62
- Clean Checkov integration: 9 / 9
- Package tests: 14 / 14
- Installed-wheel golden workflow: 1 / 1
- Summary SHA256:
  `edd5fc5da1dd2b6085823f5f3d38063b7424dc8c7f9847d3ccb3168af46d70b1`

All unchanged coverage thresholds remained at or above 90%. Intent-contract coverage
was 90.34003091190108%; native-property coverage remained 90.29126213592232%.

The exact source and tag also passed every GitHub Python 3.10-3.13 warnings-as-errors
job, pinned Checkov 3.3.0 integration, and installed-wheel golden workflow:

- Exact-source workflow:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33483798011>
- Exact-tag workflow:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33483800649>
- Post-tag publication-binding workflow:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33485024139>

## Published artifacts

- Wheel: `iac_guard_v-0.1.0a10-py3-none-any.whl`
  - Size: 451,300 bytes
  - SHA256: `6ff89229083c88b3d9c35b9be21646e722dfccaf2e6b2ccf3d215bb4c2a3b57e`
- Source distribution: `iac_guard_v-0.1.0a10.tar.gz`
  - Size: 440,135 bytes
  - SHA256: `0df0104985e202c176d3f66cd1231334b03585c72b6870dc5db3379c3b932b47`

The reviewed artifacts were built once. The sdist-to-wheel rebuild produced the same
wheel SHA256. Complete extraction audits found 93 wheel files and 115 sdist files,
limited to reviewed runtime/source/public-documentation families, with no bytecode,
private research/design/screening material, local paths, release workspace, or
credential-shaped content. GitHub and PyPI expose the exact same artifact bytes.

## Public identities

- GitHub prerelease:
  <https://github.com/lokesh0186/iac-guard-v/releases/tag/v0.1.0-alpha.10>
- PyPI project version: <https://pypi.org/project/iac-guard-v/0.1.0a10/>
- Trusted Publishing workflow:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33485916491>
- Trusted Publishing job:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33485916491/job/99785835391>
- Wheel provenance:
  <https://pypi.org/integrity/iac-guard-v/0.1.0a10/iac_guard_v-0.1.0a10-py3-none-any.whl/provenance>
- Sdist provenance:
  <https://pypi.org/integrity/iac-guard-v/0.1.0a10/iac_guard_v-0.1.0a10.tar.gz/provenance>
- Zenodo record: <https://zenodo.org/records/22226912>
- Version DOI: <https://doi.org/10.5281/zenodo.22226912>
- Unchanged concept DOI: <https://doi.org/10.5281/zenodo.22088272>

PyPI records one digital publish attestation per artifact from GitHub repository
`lokesh0186/iac-guard-v`, workflow `release.yml`, environment `pypi`, at binding commit
`29a7084f3b57c4abe0601e6bb42dd1d7686001e5`. Both public provenance bundles were also
verified with the official `pypi-attestations` verifier and the system's trusted CA
bundle; both artifact subjects and SHA256 digests matched.

Zenodo records version `v0.1.0-alpha.10`, links the immutable GitHub tag, assigns
Version DOI `10.5281/zenodo.22226912`, and retains Concept DOI
`10.5281/zenodo.22088272`.

## PyPI-only smoke

A fresh CPython 3.12 environment installed `iac-guard-v==0.1.0a10` solely from
`https://pypi.org/simple`, with no editable/local-source fallback. It passed import,
version, CLI help, strict contract lint, package doctor, Checkov 3.3.0 compatibility,
the unchanged 17-property native registry, and a deterministic Dgraph contract replay.

That replay produced one native `SATISFIED` clause for ServiceMonitor-to-Zero port
resolution and one native `VIOLATED` clause for the declared monitoring ingress path,
with aggregate exit code 10. Repeated reports were byte-identical with SHA256
`eaa833d2ba4d4dbb50a30dac3db88220db2f831cb574f7ed269adc4d11418009`.
The report bound native registry
`de9a293ea2d3da8dbdbbbe3b12aa5b5d212ba789af225ea714b18d91dc501f90`
and compiler
`7990eeae19c6e93b7a6cee68ef3c2c582c2f85ef86d88029c50bfa48905daff7`.

Doctor's closed validator-registry identity is intentionally environment-bound. Two
isolated installations produced different registry identities only because
`python-hcl2`'s generated console launcher contains the isolated environment path in
its shebang. Product bytes, parser versions, semantic identities, integrity status,
and native registry were identical; both validator registries independently reported
`BYTECODE_FREE_PRODUCT_BUILD` and `PASS`.

## Semantic and schema identities

- Native property count: 17 (unchanged from a9)
- Native property registry:
  `de9a293ea2d3da8dbdbbbe3b12aa5b5d212ba789af225ea714b18d91dc501f90`
- Contract compiler identity:
  `7990eeae19c6e93b7a6cee68ef3c2c582c2f85ef86d88029c50bfa48905daff7`
- Infrastructure contract schema SHA256:
  `c6baff537d854c2cea8204a5fc740d88bee79e9abb91b2aa5389dafbee4a65cc`
- Infrastructure contract report schema SHA256:
  `89a629df641fa1d467167869147327e449c63d22e198484f40962f2c0fa8c2ed`
- Native property report schema SHA256:
  `4c3ce24772746ce786fe8b2f77f18b47db29f0b7008faf2cfab605bcae2430f1`
- Native property request schema SHA256:
  `5a9fbcd3fd2c24649f9b6e60d07985745c61f433517cfa55c3d0a30629c0409c`
- Frozen-30 manifest SHA256:
  `abda127f7278f5972d03e7d2fb7e04b58bc2d5ce3ce44d260ac9383ce2a84a61`
- Defect-discovery corpus manifest SHA256:
  `8ae1c3640118562a6f5dfeb4cfa5a85e6e8be48294685f9b7d894d3ebe982742`

The frozen-30 result remains 9 decisive and 20 operationally inconclusive
target-bearing cases. It is not generalized beyond that frozen cohort.

## Frozen QRS preservation

- QRS primary replay: 4,842 / 4,842
- QRS extended replay: 630 / 630
- QRS evidence assertions: 10,080 / 10,080
- Semantic matches: 7 / 7 `SEMANTIC_MATCH`
- QRS root:
  `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`

## Public metadata evidence hashes

- PyPI release JSON SHA256:
  `0005bf4f5074570a9a71db7144a68f63590314443bb5e8f4464ab070b9454a1e`
- Wheel provenance response SHA256:
  `5ee672842a17ea8ba5f2f4387e63cf24fc7cf98868f16adfae9caf64124db4c8`
- Sdist provenance response SHA256:
  `8ad4cbc68de0cc1bd195f37ac3e87e6056a0f5f898a50808af6c9c59bc95a41f`
- Zenodo record API response SHA256:
  `e6389d85edcdaa8ef34502da1e4d717b4dceed95568c9eaefe00d27b13484554`

These response hashes record the verified publication-time payloads; service-side
statistics or metadata revisions may legitimately change future response bytes. The
immutable artifact, source, tag, DOI, and attested subject identities above are the
release authority.

## Released contract and intentional limitations

Alpha 10 verifies strict, versioned declared infrastructure contracts against
protected deterministic evidence. It provides verifier-derived provenance classes,
typed activation (including protected effective Helm values), explicit inclusion and
exclusion denominators, non-vacuous cardinality, responsibility metadata,
deterministic compilation to immutable native properties, witness-first aggregation,
typed exit codes, and lint/plan/verify/explain CLI paths.

The release does not infer project intent, promote user/research contracts to project
authorship, treat a contract violation as an automatic bug/vulnerability/outage, claim
runtime network or cloud behavior, or evaluate arbitrary CRDs/Terraform/provider state.
Unsupported and ambiguous semantics remain fail closed.

The historical dispositions remain `A9_SCANNER_AUTHORITY_NOT_JUSTIFIED` and
`TABLE6_PROVENANCE_BLOCKED`. Checkov 3.3.0 retains its reviewed authoritative paths;
KICS and Trivy remain advisory. No scanner voting or PASS-from-absence inference was
introduced, and no a9 native semantic identity changed.
