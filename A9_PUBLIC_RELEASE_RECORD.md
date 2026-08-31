# IaC-Guard-V 0.1.0a9 public release record

Disposition: `A9_PUBLIC_RELEASE_COMPLETE`

IaC-Guard-V `0.1.0a9` was validated, packaged, and published from the reviewed a9
native-property implementation. The release corrected only the prepublication sdist
selection boundary after the original candidate accidentally included untracked local
research files. No native semantics changed during that correction. Frozen research
paths were not modified, no benchmark inference or model-provider call occurred, and
no external-project outreach was performed.

## Release source identity

- Release source commit: `b4045c1e25e1abb10d55912698ea7130f13d54db`
- Release source tree: `84d59a54917221c0192222265cadfb6f525d6d4e`
- Signed annotated tag: `v0.1.0-alpha.9`
- Tag object: `c117e4c5b0f91b973bca411a914f9dcabce3876c`
- Tag target: `b4045c1e25e1abb10d55912698ea7130f13d54db`
- Commit and tag signing-key fingerprint:
  `SHA256:FyTyV+ggDICMoTYTFC0AJxD0UsZk7AYuHavqCFVsBkk`
- Complete Git tree manifest: 5,320 files; SHA256
  `c25761ccb7cca686df8adbc4cb502ed2391ae43f3bb7becb02fc03d31de425b0`
- Product-source manifest: 73 files; SHA256
  `07589abf543001eab79301f131e461876fc248fdf37ddeee97d3d7839b4e949f`

The release tag remains fixed on the release source commit. A later signed main-branch
commit, `d88d82f9063f7505d8b3859f7a84255615527c40`, bound the Trusted Publishing workflow
to the exact tag, release commit, and reviewed artifact hashes; it did not change the
release source or artifact bytes.

## Final clean release-profile result

The owner-authorized packaging-integrity replacement `release` profile ran once to
completion in a fresh, non-reused CPython 3.12.4 arm64 environment:

- Run ID: `20260831T221302Z-release`
- Result: PASS
- Aggregate gate executions: 6,090
- Failures: 0
- Errors: 0
- Skips: 0
- Duration: 1,582.231 seconds
- Environment fingerprint:
  `c7eb50679238746163a8ba74f458158c5efc6584f36e0b5e52402c995e75bb1b`
- Summary SHA256:
  `d7dbd0cb77da08086d383eafe018e8e7aaae03c1baccc623d4c0d465236403b8`

The passing gates included 3,147 main-suite tests; 94 D3 fingerprinting, matching,
and diffing tests in each partition; D4, D5, D6, and D7; 539 Helm tests; 62
Kustomize tests; 91 native-property tests; 14 packaging tests; nine clean Checkov
integration tests; one installed-wheel golden workflow; report/schema validation;
the frozen QRS gate; and all unchanged coverage thresholds. Native-property coverage
was 90.291262%.

This run was justified because the previously clean profile preceded a tracked Hatch
sdist-selection correction. It validated the exact publishable tree and was not a retry
of a product-semantic failure.

## Sdist publication-integrity correction

The rejected sdist proved that Hatch's bare `README.md` and `LICENSE` `include`
patterns matched those basenames recursively. All 22 leaked files were untracked local
research, screening, design, or implementation-evidence files. The release replaced
that broad traversal with exact `only-include` roots, added a closed public inventory,
a nested README/LICENSE decoy regression, and a defense-in-depth sensitive-path audit.

Rejected artifacts, never published:

- Wheel SHA256:
  `9f63be6390e6f72d06b9f59f4184334b050f46ef637832f4e056e87164b15e99`
- Sdist SHA256:
  `fe8eb74a6ba10823de0565b25b3c45f10bd8ea1da6995792ae221f5f12b5fd26`

The exact published pair passed a complete 80-file wheel and 101-file sdist inventory,
private/sensitive-path rejection, local-path and credential-shape scans, bytecode
rejection, wheel and sdist installs, representative native Kubernetes/RBAC/Terraform
properties, Checkov compatibility, and deterministic report validation.

## Published artifacts

- Wheel: `iac_guard_v-0.1.0a9-py3-none-any.whl`
  - Size: 418,121 bytes
  - SHA256: `64727745b787fdb473712eed1c4cd332ee27b12553ab3edc34194045f637ee00`
- Source distribution: `iac_guard_v-0.1.0a9.tar.gz`
  - Size: 412,730 bytes
  - SHA256: `c13c20886cf86ab6f86b98b0d3c7de6a3995c12536ef31633cb45029207a8d2e`

GitHub and PyPI independently expose these exact hashes. No rebuild occurred after the
final leakage scan.

## Public identities

- GitHub prerelease:
  <https://github.com/lokesh0186/iac-guard-v/releases/tag/v0.1.0-alpha.9>
- PyPI project version: <https://pypi.org/project/iac-guard-v/0.1.0a9/>
- Trusted Publishing workflow:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33447744870>
- Trusted Publishing job:
  <https://github.com/lokesh0186/iac-guard-v/actions/runs/33447744870/job/99670519384>
- Wheel provenance:
  <https://pypi.org/integrity/iac-guard-v/0.1.0a9/iac_guard_v-0.1.0a9-py3-none-any.whl/provenance>
- Sdist provenance:
  <https://pypi.org/integrity/iac-guard-v/0.1.0a9/iac_guard_v-0.1.0a9.tar.gz/provenance>
- Zenodo record: <https://zenodo.org/records/22216372>
- Version DOI: <https://doi.org/10.5281/zenodo.22216372>
- Unchanged concept DOI: <https://doi.org/10.5281/zenodo.22088272>

PyPI records one digital attestation per artifact from the GitHub publisher for
repository `lokesh0186/iac-guard-v`, workflow `release.yml`, environment `pypi`, and
workflow source `.github/workflows/release.yml@refs/heads/main`. The attested binding
commit is `d88d82f9063f7505d8b3859f7a84255615527c40`. Zenodo records version
`v0.1.0-alpha.9`, links the exact GitHub tag, and retains concept DOI
`10.5281/zenodo.22088272`.

## PyPI-only smoke

A fresh CPython 3.12 environment installed `iac-guard-v==0.1.0a9` solely from
`https://pypi.org/simple`, with bytecode disabled and no local-source fallback. It
passed import, version, CLI help, doctor product-registry validation, dependency check,
representative native Kubernetes verification, and native report validation. The
loaded package path was inside the isolated environment, and the environment contained
zero `.pyc` files. The host's Python 3.14 correctly rejected the declared
`Requires-Python >=3.10,<3.14` boundary before the supported-environment smoke.

## Native and frozen identities

- Native property count: 17
- Native property registry identity:
  `de9a293ea2d3da8dbdbbbe3b12aa5b5d212ba789af225ea714b18d91dc501f90`
- Native registry source SHA256:
  `3915310f26f15be5f40e821e848db47cc29b80f4ee9ef48a0940873dfe9fe870`
- Native report schema SHA256:
  `4c3ce24772746ce786fe8b2f77f18b47db29f0b7008faf2cfab605bcae2430f1`
- Native request schema SHA256:
  `5a9fbcd3fd2c24649f9b6e60d07985745c61f433517cfa55c3d0a30629c0409c`
- Frozen-30 manifest SHA256:
  `abda127f7278f5972d03e7d2fb7e04b58bc2d5ce3ce44d260ac9383ce2a84a61`
- Defect-discovery corpus manifest SHA256:
  `8ae1c3640118562a6f5dfeb4cfa5a85e6e8be48294685f9b7d894d3ebe982742`

Frozen-30 replay remains 9 decisive and 20 operationally inconclusive target-bearing
cases. This result is not generalized beyond the frozen cohort.

## Frozen QRS preservation

- QRS primary replay: 4,842 / 4,842
- QRS extended replay: 630 / 630
- QRS evidence assertions: 10,080 / 10,080
- Semantic matches: 7 / 7 `SEMANTIC_MATCH`
- QRS root:
  `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`

## Evidence hashes

- Final artifact inventory SHA256:
  `3bf0a7b53a3d9de79f4e4db8db812f0f4da95ec914a3b4953537dadbc88ae619`
- Artifact-only smoke record SHA256:
  `dfafa182ba642f1ea4c57370d6b90b12643a9002e4b0278dcd129f49f28313e3`
- Wheel provenance document SHA256:
  `22a2dea78549361343a6cc684425e2fffd7b872125c88116538aea9e0e310dec`
- Sdist provenance document SHA256:
  `53f69eabe4ef295f7cb65cd861c200916a9276a67d3be9f147ff6c47f120a6e7`
- Zenodo record API evidence SHA256:
  `171c1fea09c44acf8271cc32feb7c8f8bdc6b83214977927fe1b83ccf3b0169a`

## Released support contract and intentional limitations

Alpha 9 adds witness-first, scanner-independent semantic contracts for the bounded
Kubernetes identity/selector, NetworkPolicy, workload-closure, Service/port,
monitoring-composition, and RBAC relationships, plus exact source-local Terraform
references documented in the release notes.

Checkov 3.3.0 authority on its reviewed paths is unchanged. KICS and Trivy remain
advisory; there is no scanner voting or PASS inference from absence. Mechanical native
property verdicts do not infer project intent or automatically establish a defect,
vulnerability, outage, or runtime behavior. General Kubernetes reachability, arbitrary
CRD or Terraform evaluation, live Kubernetes/cloud state, and unsupported dynamic
semantics remain outside scope and fail closed.

The preserved research conclusions remain `A9_SCANNER_AUTHORITY_NOT_JUSTIFIED` and
`TABLE6_PROVENANCE_BLOCKED`. The independent 1,190/1,190 L3 result remains separate.
