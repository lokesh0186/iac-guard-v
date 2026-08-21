# Phase E verified dependency lock review

## Scope and decision

E0.3 separates structural, source, and runtime verification and performs only
lock-verification smoke tests.
It does not implement a scanner adapter, validator integration, production
container, composite Action, or control catalog. The canonical graph is
`tools/locks/phase-e-locks.json`; this document is generated from that graph by
`tools/render_phase_e_lock_review.py`.

Lock contract: `phase-e-verified-tool-locks-v4`

Canonical lock seal: `6a945cd22b117283825bd12724dc29b7dcc406bf014b61af41c6cd2efae4e0a6`

Artifact-cache contract: `phase-e-protected-artifact-cache-v3`

Protected-cache manifest root: `cb53a2f9ac0e2648418e72e37fffa1aa972315f14545c814542809410c115e74`

The lock itself records requirements, not self-authored PASS claims:

```text
schema:  REQUIRES_SCHEMA_VALIDATION
source:  REQUIRES_PROTECTED_CACHE_VERIFICATION
runtime: REQUIRES_REEXECUTION_OR_SIGNED_ATTESTATION
```

| Component | Tag | Full selected commit | Review result | Intended role |
| --- | --- | --- | --- | --- |
| kics | v2.1.20 | `e1f23cad9640f55b963f22a116b04906b8c16ac6` | STATIC_REVIEW | Future scanner |
| trivy | v0.73.0 | `40c73e5d6166dcc0346a1ab4e94499d1572854e4` | STATIC_REVIEW | Future scanner |
| opentofu | v1.12.5 | `230349e959a44fb8eb7b83754f9d9b012f3bdb42` | STATIC_REVIEW | Future external validator |
| terraform | v1.15.8 | `b9e178decf87d274d25ed36bc5a4dbc857e00420` | STATIC_REVIEW_USER_SUPPLIED_ONLY | User-supplied validator; never bundled |
| kubeconform | v0.8.0 | `02374e583d700721f57300fae78e11acd27ee539` | STATIC_REVIEW | Future external validator |
| tflint | v0.64.0 | `15c65a33b322750f6131e286cd9597896299ba32` | STATIC_REVIEW_OPTIONAL_NON_SECURITY | Optional non-security lint |

KICS 2.1.21 remains rejected because its source release lacks the selected
official archives and runtime image. Terraform remains
`USER_SUPPLIED_ONLY_NEVER_BUNDLED`; TFLint remains `OPTIONAL_NON_SECURITY`.

## Reproducible acquisition and signature evidence

Every Linux archive has a version-pinned HTTPS URL, retrieval date, archive
SHA-256, cached checksum-manifest URL and SHA-256, and structured signature
evidence. A status of `AVAILABLE_NOT_VERIFIED` does not claim signer-policy
verification. `UNAVAILABLE` records the upstream absence explicitly.

| Component | Method | Status | Signer/key identity |
| --- | --- | --- | --- |
| kics | OPENPGP | VERIFIED | 8F94F30BF6B3FC6085C42590F856854108973D6C |
| kubeconform | NONE | UNAVAILABLE | none |
| opentofu | OPENPGP | VERIFIED | E3E6E43D84CB852EADB0051D0C0AF313E5FD9F80 |
| terraform | OPENPGP | VERIFIED | 374EC75B485913604A831CC7C820C6D5CD27AB87 |
| tflint | SIGSTORE | AVAILABLE_NOT_VERIFIED | UNVERIFIED_GITHUB_ACTIONS_IDENTITY |
| trivy | SIGSTORE | AVAILABLE_NOT_VERIFIED | UNVERIFIED_UPSTREAM_SIGSTORE_IDENTITY |

KICS, OpenTofu, and Terraform checksum signatures were reproduced with GnuPG
against the cached upstream keys. Trivy and TFLint Sigstore material was cached
but its signer policy was not verified. kubeconform publishes checksums without
a detached archive signature. The source-verification command rehashes the real
archives, verifies checksum membership, reruns the verified OpenPGP proofs, and
checks licence and output-fixture bytes.

## Container architecture binding

Execution references are stored directly as `repository@sha256:digest`; no
execution consumer constructs a reference from a floating tag. Each recorded
amd64 and arm64 child was found in the cached multi-platform index.

| Component | Index digest | linux/amd64 child | linux/arm64 child |
| --- | --- | --- | --- |
| kics | `sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602` | `sha256:643071cf0c1657eaea695a48b49d2d61b7e625bb87c51505530e624e0c0a1ad1` | `sha256:d6d12f269db55d9ca59e2886248997c0613f8d1855f0380716795b6b9cedce90` |
| kubeconform | `sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e` | `sha256:5103f6f5e89061728aad4ad5a250627dd0fc9b2a92eb876f3762677a4222f9e0` | `sha256:5ec810f20ae7b78696499089a767c348802d70bc5d1afabd87b87143395b223d` |
| opentofu | `sha256:ba827d1af675c3f522eb78e2b8098cc87daefb9ceb9d3c4b69d0a1bb6d272463` | `sha256:181e070709e9f38cc0acaddc0fa1eb9939976481c76f9aae2657581de7821dc4` | `sha256:57dc209eed201f36a6a202cb01fe49ede303677be171b2ece3ec2ee24564965a` |
| terraform | `sha256:7ae513256f7ce67879e218ae8593d6fbe216ec9e123abe6c94e4e10704857963` | `sha256:8207a3cae11633e1182b94698adf46fdaf55a848e3d0ff151139729773568494` | `sha256:728102b238128667d3f13c43d746978c2c48b025d2fccf404bc71d819dc26fd7` |
| tflint | `sha256:1c595f42d794c32c45a6ea8b58655fd66433d4ca3b1bc631c574a48d120bd19f` | `sha256:85c63179e53e69f48fb5d1e22fb6c2b4941049c7f906f30625defa6ffcc3f834` | `sha256:80b051005568a11339948abc9f06f4919f2aa3b4ef451b0d69bb43bb01be878c` |
| trivy | `sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c` | `sha256:4bbf3824d974b70f27631005e2e6194d4d8fbd6e72c4a9e04cf521e25c5cb07f` | `sha256:3c135a0270fe7f19a677eabb3f7eca95c96ae78b52b81697de736670fc6e66c8` |

The prospective Debian base is also bound by its index and both platform
children. Selection remains research evidence, not authorization to build the
production hardened container.

## kubeconform offline schema bundle

The schema source is `https://github.com/yannh/kubernetes-json-schema` at commit `c8f4e61c63bc529749125ac566bccc6986e08d45`.
E0.1 selects Kubernetes 1.34.0
standalone schemas. The non-strict tree contains
1304 files with manifest root
`44cfe82a61d37191417037bc5954cb497424b4a7b9f18baef4dce051638c246f`; the strict tree contains
1304 files with manifest root
`0c8b0cd8155344ac4cc95d5c9a4c56898be5956e715f1fc597b4fab41e552828`. Their combined content digest is
`f1e0b62f3bedbaf0d190bd9724bb67448496dfc859f035bac3a409d34101bb67`.

The generated schema repository has no root licence file, so the lock records
`NOASSERTION`; redistribution requires a later licence decision. Network schema
fallback is forbidden. CRDs require a separately protected local schema lock or
produce unsupported evidence.

## Trivy checks offline proof

Trivy's binary and checks are distinct identities. The selected external checks
manifest is `sha256:b63166ca02aa09e30a5127320384d7bd0d2760dc19bab3ab7041a6070114ba45` and its policy layer is
`sha256:40a47ef8eb262c8e41d44f25c266463fff4dba9adcba12d33b93da88cbc7c80f`. The cached offline smoke used Trivy 0.73.0,
`--skip-check-update`, Docker network mode `none`, and the exact cache metadata.
It parsed schema version 2 with `fallback_used=false`. Any external/embedded
switch, missing bundle, moving tag, cache mismatch, or fallback changes the
execution identity and is non-PASS.

## Runtime-smoke scope

All six selected images executed their version command for both linux/amd64 and
linux/arm64 with Docker networking disabled, a read-only root, tmpfs `/tmp`, and
no host mounts. The source/runtime verifier re-executes those exact digest-pinned
commands. This proves only the recorded platform child starts and emits the
recorded version bytes; it does not authorize an adapter or establish its output
contract. Trivy alone also executed an output-producing offline scan on both
architectures with the exact external checks cache and `fallback_used=false`.

| Component | Architecture | Execution digest | Scope |
| --- | --- | --- | --- |
| kics | linux/amd64 | `27a7b8451ba3ac20848fb0b9aca5fbd6d8dfed1e9483b3281597d6883aa48977` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| kics | linux/arm64 | `501c6f5572c843122b6e3e21b2600f34b10ff84a0211d0fa77c57fd3f9770f4c` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| kubeconform | linux/amd64 | `37b6004afc56f14df9a040af574600f5d59941c3cc871cfd63e3eebb69d74fc0` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| kubeconform | linux/arm64 | `745a80fa788c7499aa4bd9fe43767d027b4efc41458cb8462885daca566a2434` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| opentofu | linux/amd64 | `e3ac9a97b3cf7e3cac1cc7866311d6cc5127a92c1a0546085502bcec7f44fad7` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| opentofu | linux/arm64 | `87bd0c299ddf4a0164f3d6b966ad264abe385b2dbf31ce330a955848cc3650e0` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| terraform | linux/amd64 | `31af6d4c9ad0af7eeb1082c45e2121e35692f30362b741414e459ad989a5cbf3` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| terraform | linux/arm64 | `4feb785d229300b3ad486ff5b7143e39994235454b50129d8f4853651a588e7e` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| tflint | linux/amd64 | `78d1a0a119cc2648e278b767cb5418dca4f8b6814f398151197f720b46af0358` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| tflint | linux/arm64 | `48ab4414d654bd18c1b1d4c04c0c7e11c5f1efa43de6f60fdba828ba741aea2d` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| trivy | linux/amd64 | `fc9afcc6cdac0e47e60b1e5685fef75b10ba019d059dd021837476a36daca3e1` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |
| trivy | linux/arm64 | `c292544feba897de33e8804aaefe62573512965611f529bfa188ed690d72f6f2` | VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION |

## Validation commands

```text
python tools/validate_phase_e_locks.py
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: NOT_RUN
PHASE_E_LOCK_RUNTIME: NOT_RUN

python tools/validate_phase_e_locks.py --verify-cached-artifacts \
  --artifact-cache <protected-cache>
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)
PHASE_E_LOCK_RUNTIME: NOT_RUN

python tools/validate_phase_e_locks.py --verify-runtime \
  --artifact-cache <protected-cache>
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)
PHASE_E_LOCK_RUNTIME: PASS (both architectures and Trivy offline checks)
```

Source mode consumes real cached bytes and verifies the signed complete lstat-based
cache inventory before interpreting individual records. Symlinks and non-regular
entries are forbidden, and the inventory is checked before and after every runtime
process. It verifies tag relations, archives,
checksum/signature evidence, OCI indexes and architecture children, licence and
fixture bytes, both schema trees, and the Trivy external checks layer/cache.
Runtime mode re-executes both platform version smokes and both Trivy offline
checks. Trivy's normalized canonical output plus raw stdout/stderr are compared to
the lock, and the current cache and diagnostic evidence proves the external checks
manifest with fallback disabled. Structural validation alone is never called source
or runtime proof.

NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED

NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V

MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
