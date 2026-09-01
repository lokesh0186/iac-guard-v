# IaC-Guard-V 0.1.0b1 preimplementation freeze

Status: owner-authorized implementation baseline

## Development checkout

- Branch: `beta1/implementation`
- Starting HEAD: `dec4feb073e99b465d59c5c8cb435fbefd3dc42a`
- Starting tree: `cd2fa40bb53592314ab2075b5c02d1b27e7ee899`
- Tracked staged changes: 0
- Tracked unstaged changes: 0
- Worktree state: dirty only because retained untracked design, implementation,
  adoption, research, and local test artifacts are present.
- Complete `git status --porcelain=v1 -uall` at freeze: 84,086 rows; SHA256
  `73fa276a97d5005069180c3b946b181f4c563004e28b1a3e865dd29807196c8d`.

The untracked material predates Beta1 implementation and remains user-owned. Beta1
must not delete, rewrite, package, or treat it as product source.

## Public a10 authority

- Version: `0.1.0a10`
- Release commit: `038bf38256706ffc83485bf5f33eb3c4992e3857`
- Release tree: `228ddf20d2dcbf188abe90934ce86d5077bbb793`
- Tag: `v0.1.0-alpha.10`
- Product-source manifest: 86 paths; path-list SHA256
  `5afe8c9ca7d9f40d1576393d0d55992cea7cdcbf79c9510363e5599ec72551d1`;
  Git-entry SHA256
  `49735a93a4a63c96397f121509208d961b6eeaa59a029aa285c7e74da56e4ce1`.
- Native property count: 17
- Native registry identity:
  `de9a293ea2d3da8dbdbbbe3b12aa5b5d212ba789af225ea714b18d91dc501f90`
- Contract schema: `iac-guard-v.io/v1alpha1`; SHA256
  `c6baff537d854c2cea8204a5fc740d88bee79e9abb91b2aa5389dafbee4a65cc`
- Contract report schema: `infrastructure-contract-report-v1alpha1`; SHA256
  `89a629df641fa1d467167869147327e449c63d22e198484f40962f2c0fa8c2ed`
- Native request/report schemas:
  `5a9fbcd3fd2c24649f9b6e60d07985745c61f433517cfa55c3d0a30629c0409c` /
  `4c3ce24772746ce786fe8b2f77f18b47db29f0b7008faf2cfab605bcae2430f1`.

## Last public a10 validation of record

- PR profile: `20260901T062618Z-pr`, PASS
- Aggregate gate executions: 15,877
- Failures/errors/skips: 0 / 0 / 0
- Matrix: 3,215 tests on each of Python 3.10, 3.11, 3.12, and 3.13
- Checkov: 9 / 9
- Packaging: 14 / 14
- Installed-wheel golden: 1 / 1
- QRS gate: 29 / 29
- Summary SHA256:
  `6530b319259bc5a2c4112fe892018a164bb7c2df6983290490866981b1b5f2a5`

The owner-authorized Beta1 implementation will use focused and dev profiles during
development and exactly one PR profile at the final implementation gate.

## Frozen Beta1 design identities

| Artifact | SHA256 |
| --- | --- |
| `BETA1_MATURITY_ASSESSMENT.md` | `0db9652501464eea2920d3c161edf7436461013addd2adf2d5f6616885293f80` |
| `BETA1_PUBLIC_API_FREEZE.md` | `cd6ef9f77a2005a332a8470f742379a9e55f978b8e877069a2fce86271746051` |
| `BETA1_OPENTOFU_SUPPORT_DESIGN.md` | `a50fd1848a95bb8bfb1e1409e8503f853fa3c8daf8024f05900fbd97393da341` |
| `BETA1_SCANNER_INTEROP_DESIGN.md` | `c2e5ce97ede098aec420cb82b6514cc3bcd7a3f8d8aa68da3613b714e9254e22` |
| `BETA1_ADOPTION_UX_DESIGN.md` | `1ebc159c370f9bc33a8b241f0e13cf2b062e2f53e3f2da9d9cd2733cc112fd97` |
| `BETA1_COMPATIBILITY_CORPUS.md` | `3423bf64049ad15ce8a364f5ef0e77e1dca825fddfe6ee2eb45759ddbc774305` |
| `BETA1_SUPPLY_CHAIN_THREAT_MODEL.md` | `0909835faeb4803435d48507665b5b861e404125c00083510f1caf6bb6300cc5` |
| `BETA1_TEST_AND_RELEASE_PLAN.md` | `76de4d1d26b22b3506c7d1c3833c98366ad85c4bbdd06f104d487033b6b2cc17` |
| `BETA1_FINAL_IMPLEMENTATION_DESIGN.md` | `285e8193ad9de40ef85012e3b567ef738418c99cb6211e497f2ed7f53a78f4e2` |

Disposition: `BETA1_DESIGN_REVISED_KEEP_V1ALPHA1`.

## Frozen QRS boundary

- 4,842 / 4,842 files
- Root: `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`
- 630 / 630 replay records
- 10,080 / 10,080 fields
- 7 / 7 `SEMANTIC_MATCH`

No benchmark inference, model-provider call, frozen-corpus regeneration, release,
tagging, publication, or external outreach is authorized by this implementation task.
