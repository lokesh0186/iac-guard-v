# Validation Log

## 2026-08-12 — E1/E2.2 hardened runtime and output boundary

Failing-before, both scanners ignored extra output files; KICS lacked capability,
no-new-privileges, PID, memory and CPU guards; Trivy lacked memory and CPU guards; and
product modules shipped explicit test evidence factories. Passing-after applies the
complete non-root guard set, twice inventories an exact bounded output allowlist, binds
the portable output manifest, and moves all test capabilities outside `src/`.
Focused adapter/boundary tests: 176 passed; combined branch coverage: 91% (KICS 93%,
Trivy 90%). Exact locked KICS offline integration: 1 passed. Fresh wheel and sdist each
contain 28 entries, no tests tree, and none of the removed capability markers. Trivy
live integration requires the protected cache through `IACGV_PHASE_E_CACHE`.

## 2026-08-12 — E2.2 Trivy status and cache provenance closure

Failing-before, `EXCEPTION` disappeared as an unknown category, documented omitted
fields were rejected, and portable execution evidence exposed only selected checks
digests. Passing-after preserves skipped evidence, handles omissions conservatively,
retains experimental detail, and binds the signed manifest, subtree, metadata,
attestation and pre/post roots. Focused unit tests: 65 passed; branch coverage: 90%.

## 2026-08-12 — E1.2 KICS native contract closure

Failing-before, a CRITICAL report with exit 20 and an empty report with exit 60 both
normalized successfully. Required v2.1.20 query/file fields, complete severity
counters, and native BOM records were incomplete. Passing-after adds exact exit/report
reconciliation, full required-field probes, RFC 3339 ordering, separate BOM/TRACE
preservation, and conservative similarity-identity integrity. Focused tests: 95 passed.

## 2026-08-12 — E1/E2.1 private execution boundary

Failing-before, public KICS and Trivy normalization accepted a sealed request plus a
caller-built `CommandResult` and arbitrary JSON. Passing-after, both public methods
reject that combination; adapter-owned `scan` checks result argv against the locked
invocation. Fixture normalizers/cache factories are absent from package exports. Trivy
integration now requires `IACGV_PHASE_E_CACHE` and verifies signed E0.3 evidence.

```text
KICS and Trivy unit/boundary tests: 140 passed
exact locked offline adapter integrations: 2 passed
```

No benchmark inference, model-provider call, consensus implementation, or model refresh
was executed.

## 2026-08-12 — E2.1 protected Trivy cache and native consistency

Failing-before probes accepted correct `metadata.json` beside arbitrary Rego, accepted
one exact evaluation as both PASS and FAIL, and changed semantic hashes when only
`ReportID`/`CreatedAt` changed. Passing-after results: arbitrary cache rejected by the
signed E0.3 physical inventory; contradictory evaluation returned
`ERROR / CONTRADICTORY_EVALUATION_EVIDENCE` with ruleset integrity `FAIL`; volatile
metadata produced equal semantic hashes and different raw-byte hashes.

```text
Trivy unit tests: 56 passed
Trivy branch coverage: 90%
E2.1 plus E0.2 cache-lock tests: 70 passed
```

The protected cache identity binds the signed manifest root, Trivy subtree root,
external OCI manifest and layer, metadata digest, and cache-attestation identity. No
benchmark inference, model-provider call, consensus implementation, or model refresh
was executed.

## 2026-08-12 — E1.1 complete KICS contract

Failing-before at `6da9073d`: exits were `(0, 40)`, locked argv omitted `--pull never`,
top-level type/arithmetic contradictions were not all checked, TRACE/BOM was conflated,
and official optional fields were required or unknown. Passing-after:

```text
result exits: (0, 20, 30, 40, 50, 60)
HIGH/50 and CRITICAL/60: parsed PASS scanner evidence
type/arithmetic mutations: INVALID_RESULTS_STRUCTURE
TRACE=1, total_counter=0, total_bom_resources=1: BOM-only evidence
locked argv: --pull never
focused tests: 80 passed
branch coverage: 94%
```

KICS remains advisory. No benchmark inference or provider call occurred.

## 2026-08-12 — E2 externally locked Trivy adapter

Failing-before E2 evidence was literal absence: no `adapters/trivy.py`, no Trivy adapter
suite, and the support matrix said `adapter unsupported`. Passing-after evidence:

```text
Trivy unit tests: 53 passed
Trivy exact locked offline integrations: 2 passed
Trivy branch coverage: 91.75%
locked image (local linux/arm64): docker.io/aquasec/trivy@sha256:3c135a0270fe7f19a677eabb3f7eca95c96ae78b52b81697de736670fc6e66c8
external checks manifest: sha256:b63166ca02aa09e30a5127320384d7bd0d2760dc19bab3ab7041a6070114ba45
network mode: none
updates: disabled
finding result: PASS with exact file/resource coverage
finding-free global-only result: PARTIAL / COVERAGE_MISMATCH
embedded fallback: INCONCLUSIVE / EMBEDDED_CHECKS_FALLBACK
cache mutation: ERROR / CACHE_CHANGED_DURING_EXECUTION
```

Malformed and duplicate-key output, missing native records, unknown categories,
timeouts, partial coverage, binary-only drift, and checks-only drift are permanent
mutation probes. The adapter emits typed evidence only; it does not alter final policy
or implement multi-scanner consensus. No benchmark inference or provider call occurred.

## 2026-08-12 — E1 locked KICS adapter

The prerequisite checkpoint ran from pristine clone `7caa1ce2`. D7.5 security probes
were `20 passed`; Python 3.10, 3.11, 3.12, and 3.13 each reported `1493 passed`; the
isolated Checkov 3.3.0 integration reported `6 passed`; and the real E0.3 protected
cache reported all three independent results `PASS` before any Phase-E code changed.

Failing-before E1 evidence was literal absence: no `adapters/kics.py`, no KICS adapter
tests, and the support matrix said `adapter unsupported`. Passing-after evidence:

```text
KICS unit plus exact locked offline integration: 59 passed
KICS branch coverage: 94.21%
locked image: docker.io/checkmarx/kics@sha256:d6d12f269db55d9ca59e2886248997c0613f8d1855f0380716795b6b9cedce90
network mode: none
native finding similarity_id retained: PASS
files_failed_to_scan=1: PARTIAL / KICS_FAILED_TO_SCAN
queries_failed_to_execute=1: PARTIAL / KICS_QUERY_EXECUTION_FAILED
queries_failed_to_compute_similarity_id=1: PARTIAL / KICS_SIMILARITY_ID_FAILED
```

The adapter emits typed evidence only and does not alter final policy or implement
multi-scanner consensus. No benchmark inference or model-provider call occurred.

## 2026-08-12 — E0.3 physical cache and current Trivy execution evidence

Failing-before probes against `5b29d702` produced these literal values:

```text
OLD_UNLISTED_SYMLINK: ACCEPTED
OLD_TRIVY_DIFFERENT_OUTPUT: ACCEPTED
```

The first probe added `unlisted-symlink -> /etc/hosts` beside an otherwise signed cache
inventory. The old source attestation ignored it. The second supplied a current,
schema-valid Trivy 0.73.0 JSON result with different stdout/stderr; the old runtime
check accepted the version, schema, and log phrase without comparing current bytes.

E0.3 replaces that behavior with cache manifest contract
`phase-e-cache-manifest-v2`: 3,500 entries, including 3,381 regular files and 119 real
directories, are lstat-bound and signed. Symlinks, FIFOs, sockets, devices, other entry
types, path escapes, and unlisted paths are rejected before runtime. The complete
manifest is revalidated before runtime and after every process.

Both digest-pinned Trivy platform children were re-executed with network mode `none`,
read-only root/cache/input mounts, update disabled, and the exact external checks
manifest `sha256:b63166ca02aa09e30a5127320384d7bd0d2760dc19bab3ab7041a6070114ba45`.
The versioned normalizer removes only generated `ReportID` and `CreatedAt` values.
Both platforms produced normalized output SHA-256
`aaef90dbaaf7f7e18d78e8d6b8e09c913b04728b7a5b54b068f4d6281c39801e`,
stderr SHA-256
`1083b6d76634974f9dbcc8a5b0a0f7f684ceef33549fdf0fcf8052527a487029`, and
canonical JSON SHA-256
`011764692304749941ac6578e3cbe9479446c898671475a704e41401bf20dbe0`.
`fallback_used=false` is re-derived from current cache metadata, bound manifest/layer
identities, update-disabled invocation, network isolation, and current diagnostics.

```text
36 passed (E0/E0.2/E0.3 lock tests)
1493 passed (complete non-integration suite)
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)
PHASE_E_LOCK_RUNTIME: PASS (both architectures and Trivy offline checks)
```

No scanner adapter, validator integration, container build, benchmark inference, or
model-provider call was performed.

## 2026-08-12 — E0.2 reproducible source and runtime lock attestation

E0.2 separates three claims that the preceding lock conflated. The static lock
records requirements rather than source/runtime PASS. Literal schema-only output is:

```text
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: NOT_RUN
PHASE_E_LOCK_RUNTIME: NOT_RUN
```

The protected-cache source verifier consumed the complete signed cache manifest,
verified exact tag/ref maps and official repositories, rehashed release archives,
checksum/signature records, OCI indexes and both architecture children, verified
the kubeconform schema Git object/tree and all 2,608 extracted schemas, and bound
the external Trivy checks tag and bundle:

```text
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)
PHASE_E_LOCK_RUNTIME: NOT_RUN
```

Runtime verification then re-executed the exact digest-pinned version smoke for
all six tools on linux/amd64 and linux/arm64. It also re-executed Trivy's external
checks scan on both architectures with network disabled, update disabled, and
`fallback_used=false`:

```text
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)
PHASE_E_LOCK_RUNTIME: PASS (both architectures and Trivy offline checks)
```

Version-only smoke remains explicitly insufficient to authorize KICS,
kubeconform, OpenTofu, Terraform, or TFLint adapters. No Phase-E adapter,
validator integration, production container, Action, or control catalog was
implemented.

NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED

NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V

MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED

## 2026-08-12 — D7.3 complete canonical report-graph validation

- Failing-before: `tests/unit/test_public_d73.py` produced 30 failures. The old
  validator accepted 29 contradictory verified-report mutations, and `explain`
  returned exit 0 while printing both `STILL_PRESENT` and `FIXED` for the same binding.
- Passing-after: duplicate target, decision, gate, engine-event, finding, evaluation,
  snapshot-file, and scanner-input identities fail before lookup construction.
- Role snapshots, gate implementations, scanner inputs, file/resource coverage,
  target evidence, policy decisions, and isolation evidence are reconciled as one graph.
- Source snapshot, artifact-manifest, resource-inventory, and target derived identities
  are recomputed from canonical child evidence.
- Mutation guards run for verified, failed, and inconclusive verdict branches.

## 2026-08-12 — E0.1 verified Phase-E dependency locks

E0.1 preserved E0's static version decisions but replaced digest-shaped trust
with a sealed evidence graph and an independent protected-cache verification
mode. Literal pre-change probes were accepted by E0's structural validator:

```text
random release commit: ACCEPTED
random archive sha: ACCEPTED
random OCI digest: ACCEPTED
prose crypto claim: ACCEPTED
prose runtime pass: ACCEPTED
kube schema absent: ACCEPTED
```

After E0.1 the permanent mutations are rejected, the human table is rendered
from canonical JSON, and the real cache produced:

```text
PHASE_E_LOCK_SCHEMA: PASS (6 tools, 2 architectures, sealed graph)
PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)
22 passed
```

The cache check rehashed twelve selected Linux archives; matched them to the
six upstream checksum manifests; reran valid KICS, OpenTofu, and Terraform
OpenPGP signatures; checked all six OCI indexes and their amd64/arm64 children;
checked licence and output fixtures; verified 2,608 pinned kubeconform schema
files; and proved Trivy 0.73.0 loaded external checks manifest
`sha256:b63166ca02aa09e30a5127320384d7bd0d2760dc19bab3ab7041a6070114ba45`
offline with no embedded fallback. Trivy and TFLint Sigstore evidence remains
`AVAILABLE_NOT_VERIFIED`, and kubeconform's absent detached signature remains
`UNAVAILABLE`. No adapter, validator integration, production container, or
Action was implemented.

NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED

NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V

MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED

## 2026-08-12 — E0 immutable Phase-E dependency lock research

- Added `tools/locks/phase-e-locks.json` and its fail-closed validator.
- Reviewed official release/tag, archive checksum, OCI manifest, architecture,
  licence, signing/attestation availability, invocation, offline, and output
  fixture evidence for KICS, Trivy and trivy-checks, OpenTofu, Terraform,
  kubeconform, and TFLint.
- Selected KICS v2.1.20 because proposed v2.1.21 lacked official runtime
  archives and an official image tag at review time.
- Locked Trivy v0.73.0 separately from external trivy-checks v2.2.0; embedded
  fallback is recorded and prohibited for the selected identity.
- Selected a digest-pinned Debian bookworm-slim base after linux/amd64 and
  linux/arm64 review of the prospective tool set.
- Compatibility result is static contract review only. No Phase-E executable,
  scanner, validator, container, or action was implemented or run.
- Lock validator: `PHASE_E_LOCKS: PASS (6 tools, 2 architectures, immutable digests)`.
- No benchmark inference, provider call, or model refresh was executed.

Unedited command output for every gate. Paths are repository-relative or use
`$REPO_ROOT` / `$TEMP_ROOT`; absolute local paths, usernames, and hostnames are never
recorded here.

Conventions:
- Commands are shown exactly as run, from `$REPO_ROOT`.
- Output is pasted unedited except for the path substitution noted above.
- A gate is only "passed" when its recorded output says so.

Revision note: this log was rewritten after adversarial review found four attacks that
the first byte-freeze verifier **passed**. The superseded claims are listed in §
"Corrections to the previous log" so the record shows what was wrong, not only what is
right now.

---

## Environment of record

| Item | Value |
| --- | --- |
| Frozen snapshot commit | `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5` |
| Branch | `adoption/p1-research-and-spec` |
| Verified at commit | see "Test counts of record" below; the final gate run is from a clean clone of the last commit on this branch |
| Python | 3.11.5 |
| git | 2.50.1 |
| Docker | 29.6.2 |
| checkov available locally | 3.3.0 — **differs from the research pin 3.2.517** |
| Not installed | kics, tflint, terraform, tofu, kubeconform, gh, pipx, uv |

Phases A–C perform no model calls. One local Checkov invocation occurs, only to prove
that the legacy-semantics wrapper refuses to run on scanner drift.

---

## Gate A — workspace and audit

```console
$ test "$(git rev-parse --abbrev-ref HEAD)" = "adoption/p1-research-and-spec" && echo OK
OK

$ python3 tools/check_audit_citations.py docs/spec/CURRENT_STATE_AUDIT.md --min 15
distinct valid citations: 34 (minimum 15)
PASS
```

Every cited file exists and every line number is in range. Quoted text was
spot-checked at `scripts/verify_patch.py:161-165`,
`docs/VERIFICATION_PROCEDURE.md:15,22`, and `README.md:220`.

**Gate A: PASS.**

---

## Gate B — research freeze and reproduction lock

All output below was produced from a **clean checkout**: a fresh non-local clone of the
branch at `e636b4f`, `0` modified files, with the freeze tag fetched.

### B.1 Freeze tag

No signing key is configured, so the unsigned annotated path ran. `git tag -v` verifies
signatures, not existence, and therefore fails on this tag by design:

```console
$ git cat-file -t qrs-2026-replication-v1
tag
$ git rev-parse qrs-2026-replication-v1^{commit}
7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5
$ git tag -v qrs-2026-replication-v1
error: no signature found
exit=1
$ git ls-remote --tags origin
(no output — the tag exists locally only, pending the ADR-0011 decision)
```

### B.2 Byte freeze, bound to the tag

`--tag` is mandatory. Without it the verifier refuses, because a manifest that is not
bound to the tag can be regenerated over changed data and still verify against itself:

```console
$ python3 research/verify_byte_manifest.py --manifest research/qrs2026-byte-manifest.jsonl \
    --root . --expect-entries 4842 --strict
FAIL: TAG_BINDING_REQUIRED: pass --tag <freeze tag>, or --allow-unbound for a
development check that does not prove the freeze
```

```console
$ python3 research/verify_byte_manifest.py \
    --manifest research/qrs2026-byte-manifest.jsonl \
    --root . --tag qrs-2026-replication-v1 \
    --expect-entries 4842 --strict
files checked:          4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
PASS
```

Tag-binding detail, printed independently of the verifier:

```console
tag object type          : tag
tag peels to             : 7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5
sidecar frozen_snapshot  : 7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5
sidecar MANIFEST_ROOT    : a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
tag annotation root match: True
frozen blobs in tag tree : 4842
manifest entries         : 4842
```

The verifier checks ten things: manifest schema and canonical ordering,
`MANIFEST_ROOT`, tag object type, peeled commit, the tag annotation's `MANIFEST_ROOT`,
every path/mode/blob id against `git ls-tree -r <tag>`, working-tree bytes, physical
executable bits, symlink-free parent components with resolved paths inside the
repository, and full physical enumeration under frozen prefixes.

### B.3 The four attacks that previously passed

Each was run against the current verifier, then reverted; the clean state re-verified
`PASS` after every one. All four are now permanent tests in
`tests/research/test_freeze_adversarial.py`.

**A — `chmod +x` on a frozen file, unstaged.** Previously `PASS, exit 0`, because mode
was read from `git ls-files -s`, which reports the index rather than the filesystem.

```console
  FAIL PHYSICAL_MODE_CHANGED: scripts/verify_patch.py recorded git mode 100644 but
       working-tree exec bit is set (st_mode 0o755)
FAIL
```

**B — git-ignored `scripts/__pycache__/evil.pyc`.** Previously `PASS, exit 0`, because
untracked files came from `git ls-files --others --exclude-standard`, which omits
ignored files. This was not hypothetical: the delivered tree contained
`scripts/__pycache__/verify_patch.cpython-311.pyc`, created when the legacy wrapper
imported the frozen harness. It has been removed.

```console
  FAIL UNLISTED_PHYSICAL_FILE_UNDER_FROZEN_PREFIX: scripts/__pycache__/evil.pyc
FAIL
```

**C — `scripts/` replaced by a symlink to an outside directory with identical files.**
Previously `PASS, exit 0`, because only the final path component was tested. Note the
content is byte-identical, so hashing alone could never have caught it.

```console
  FAIL SYMLINKED_DIRECTORY_UNDER_FROZEN_PREFIX: scripts is a symlink; a frozen
       directory must be a real directory
  FAIL MISSING_FILE: scripts/analyze_part1.py
  FAIL MISSING_FILE: scripts/analyze_part2.py
FAIL
```

**D — edit a frozen file, regenerate the manifest, hand-preserve
`frozen_snapshot_commit`.** Previously the verifier **and all 24 tests passed** while
the sidecar root no longer matched the tag. The builder now refuses outright when the
frozen scope differs from the claimed snapshot; forcing the manifest through the
unbound development path and hand-editing the sidecar is caught by tag binding:

```console
  FAIL TAG_ROOT_MISMATCH: tag annotation MANIFEST_ROOT a42cf0184aa345e5060...4dd4
       != sidecar 5c079f6c53286493245d13ea2459c93f96c30bf15f7be7272ae1f0c00e762fc6
FAIL
```

Builder binding rules:

```console
$ python3 research/build_byte_manifest.py --root . --output-dir /tmp/mb
FAIL: SNAPSHOT_BINDING_REQUIRED: pass --frozen-snapshot-commit <sha> to write the
canonical manifest, or --unbound-development-output <stem> to write a non-canonical
development copy.

$ python3 research/build_byte_manifest.py ... --unbound-development-output qrs2026-byte-manifest
FAIL: refusing to write an unbound manifest under the canonical name

$ python3 research/build_byte_manifest.py ... --frozen-snapshot-commit 7646d593...
entries:       4842
MANIFEST_ROOT: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
# manifest byte-identical to the committed one
```

Other detections, each induced and reverted: staged content edit
(`GIT_BLOB_CHANGED` + `SHA256_CHANGED` + `SIZE_CHANGED`), unstaged content edit
(`SHA256_CHANGED … unstaged working-tree edit`), CRLF rewrite
(`WORKING_TREE_BYTES_DIFFER_EOL_ONLY`), index mode change (`INDEX_MODE_CHANGED`),
symlink replacing a listed file (`SYMLINK_APPEARED`), deletion (`MISSING_FILE`),
tampered manifest record (`SIZE_CHANGED` + `MANIFEST_ROOT_MISMATCH`), wrong
`--expect-entries` (`ENTRY_COUNT`).

### B.4 Semantic reproduction, with corrected counts

```console
$ python3 research/replay_from_frozen_runs.py --check
== 1. exact reconstruction of results/tables/all_runs.csv ==
frozen run records:        630/630
committed rows matched:    True (630 rows, 0 unmatched)
field comparisons:         10080/10080 equal (expected 10080)
duplicate CSV keys:        0
duplicate run keys:        0
missing JSON fields:       0

-- stored verification values (ast.literal_eval is a compatibility path) --
attempts_total:            762
verification_dicts:        759
verification_repr_strings: 0  <- ast.literal_eval exercised this many times
verification_missing:      3
verification_unexpected:   0
verification_parse_failures: 0

final_verdicts_checked:     627
final_verdicts_unavailable: 3
    BM-0276_claude-opus-4.6_verify_loop.json: final attempt error='empty_extraction', record verdict=False, known and explained
    BM-0276_claude-sonnet-4.6_verify_loop.json: final attempt error='empty_extraction', record verdict=False, known and explained
    BM-0279_claude-sonnet-4.6_verify_loop.json: final attempt error='empty_extraction', record verdict=False, known and explained
final_verdict_mismatches:   0

== 2. semantic reproduction of derived tables (CRLF->LF canonicalised) ==
files copied into the workspace: 642 via git-ls-files
analyze_part1.py     exit=0
analyze_part2.py     exit=0
analyze_part3.py     exit=0
  SEMANTIC_MATCH  main_results_with_ci.csv           rows=18  [content equal; line endings differed]
  SEMANTIC_MATCH  results_by_violation_class.csv     rows=42  [content equal; line endings differed]
  SEMANTIC_MATCH  cost_effectiveness.csv             rows=9  [content equal; line endings differed]
  SEMANTIC_MATCH  statistical_tests.csv              rows=18  [content equal; line endings differed]
  SEMANTIC_MATCH  convergence.csv                    rows=6  [content equal; line endings differed]
  SEMANTIC_MATCH  difficulty_terraform.csv           rows=50  [content equal; line endings differed]
  SEMANTIC_MATCH  difficulty_kubernetes.csv          rows=20  [content equal; line endings differed]

figures: not regenerated (no frozen analysis script calls savefig)
all_runs.csv: input to the analysis scripts, not an output
PASS
```

All seven tables report `byte_identical: false` with
`eol_canonicalisation_applied: true`: content equal, bytes not, because `csv.writer`
emits CRLF while git stores LF under `* text=auto`.

### B.5 Reproduction lock, completed

Base image digest resolved from the registry:

```console
$ docker buildx imagetools inspect python:3.11.5-slim-bookworm
Digest: sha256:edaf703dce209d774af3ff768fc92b1e3b60261e7602126276f9ceb0e3a96874
  linux/amd64: sha256:a28fdf3bde6c0c97b656841669f6b4cc8164d0f34067c6ce6b5532effe94f8a7
```

Dependency hashes resolved **inside the target image**, because wheel selection and
therefore hashes are platform-specific:

```console
$ docker run --rm --platform linux/amd64 python@sha256:edaf7...874 \
    sh -c 'pip download --no-cache-dir -d /tmp/d numpy==1.26.4 scipy==1.11.1 \
           && cd /tmp/d && sha256sum *'
numpy-1.26.4-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
scipy-1.11.1-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
---HASHES---
666dbfb6ec68962c033a450943ded891bed2d54e6755e35e5835d63f4f6931d5  numpy-1.26.4-...whl
b4bb943010203465ac81efa392e4645265077b4d9e99b66cf3ed33ae12254173  scipy-1.11.1-...whl
```

The dependency set is `numpy` and `scipy` only, derived by AST import analysis of the
three frozen analysis scripts rather than from `requirements.txt`. `pandas` and
`matplotlib` are declared in `requirements.txt` but imported by no analysis script, so
they are not replay dependencies. `numpy` has no runtime dependencies and `scipy`
depends only on `numpy`, so the closure is complete with two entries.

Build and offline run:

```console
$ docker build --platform linux/amd64 -f research/Dockerfile.reproduction -t iac-guard-v-repro:qrs2026 .
$ docker image inspect --format '{{.Id}}' iac-guard-v-repro:qrs2026
sha256:338db8953db19fb91662ac459cce7c442c9f97771e88678f10adaf4cb1a45361

$ docker run --rm --platform linux/amd64 --network=none --read-only \
    --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=256 --memory=2g --cpus=2 \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,noexec,nosuid,size=256m -e HOME=/tmp \
    -v "$PWD:/src:ro" -w /src iac-guard-v-repro:qrs2026 \
    research/replay_from_frozen_runs.py --check
...
files copied into the workspace: 642 via filesystem-walk-with-exclusions
  SEMANTIC_MATCH  ... (7/7)
PASS
container exit=0
```

The container has no `git`, so the workspace copy fell back to a filesystem walk with
an explicit exclusion list. Both methods copied 642 files and produced identical
results. The local image ID is recorded; `registry_digest` stays `null` because the
image has not been pushed, and a local build's `RepoDigests` value is bound to no
registry.

### B.6 Environment records: historical facts stay separate from replay facts

```console
$ python3 research/verify_reproduction_env.py \
    --original research/ORIGINAL_EXPERIMENT_METADATA.json \
    --replay research/VALIDATED_REPLAY_ENVIRONMENT.json
evidenced fields:     18
not_recorded fields:  10
  NOTE A/run_count: source is a directory (runs/raw); hash check skipped
PASS
```

Path-escape and malicious-glob attempts, all rejected:

```console
absolute     ->  FAIL A/aws_region: unsafe source path '/etc/passwd' (absolute path)
traversal    ->  FAIL A/aws_region: unsafe source path '../../../etc/passwd' (relative traversal component)
backslash    ->  FAIL A/aws_region: unsafe source path 'scripts\\call_bedrock.py' (backslash separator)
outside      ->  FAIL A/aws_region: unsafe source path 'README.md' (outside the frozen scope)
glob escape  ->  FAIL A/checkov_version: unsafe corroboration glob '../*.json' (relative traversal component)
```

Commented-out pins no longer satisfy the lock check:

```console
$ printf '# pandas==2.0.3\n# numpy==1.26.4\n' > /tmp/fake.lock
  FAIL E/lock: numpy==1.26.4 is not an active pin in fake.lock (parsed: None)
  FAIL E/lock: numpy is declared hash-pinned but no --hash=sha256 entry was parsed
```

Contamination attempts, all rejected:

```console
  FAIL A/experiment_host_python_version: value '3.11.5' not supported by excerpt '#!/usr/bin/env python3'
  FAIL C/experiment_host_python_version: host or library facts must never be evidenced in the historical record
  FAIL D/experiment_host_python_version: value '3.11.5' also appears in the replay record
  FAIL A/aws_region: value 'us-west-2' not supported by excerpt "client = boto3.client('bedrock-runtime', region_name='us-east-1')"
  FAIL E/result: derived tables are not byte-identical (line endings differ); claiming otherwise would conflate byte and semantic equality
```

### B.7 Legacy semantics quarantine

```console
# (1) no acknowledgement
REFUSED: legacy semantics require --acknowledge-legacy-non-production-semantics.
exit=2

# (2) acknowledged, installed scanner is 3.3.0 rather than the pinned 3.2.517
REFUSED: installed checkov '3.3.0' != pinned '3.2.517'.
exit=3

# (3) explicit untrusted inspection run
{'result_label': 'LEGACY_REPLAY_RESULT', 'is_production_verdict': False,
 'trust': 'UNTRUSTED_VERSION_DRIFT', 'checkov_version_installed': '3.3.0'}
exit=4
```

Exit code is 2, 3, or 4 — never 0 — so the legacy harness cannot be wired in as a
passing CI gate.

### B.8 Tests

```console
$ python3 -m pytest tests -q
536 passed
```

### Test counts of record

| Suite | Count |
| --- | --- |
| `tests/spec/test_semantics_truth_table.py` | 121 |
| `tests/spec/test_domain_boundaries.py` | 84 |
| `tests/spec/test_domain_immutability.py` | 62 |
| `tests/spec/test_event_binding.py` | 36 |
| `tests/unit/test_models_immutability.py` | 94 |
| `tests/unit/test_domain_consistency.py` | 38 |
| `tests/unit/test_process.py` | 46 |
| `tests/research/test_qrs_regression.py` | 29 |
| `tests/research/test_freeze_adversarial.py` | 19 |
| **total** | **536** |

Progression across review rounds, so the record shows what each one added: 24 at the
first freeze commit, 76 after the first adversarial remediation, 108 after the
semantic-consistency commit, 169 after the exception-scoping commit, 243 after the D0
boundary-hardening commit, 299 after D0.1, 305 after the identifier-hazard follow-up, 445 after the D1 domain-closure commit, and 536 after D1.1 plus the D2 process runner.
Only the current figures are the gate result.

### D1 domain closure

Seven further fail-open behaviours were independently reproduced in the conformance
oracle and are now closed. Measured before, then after:

| Probe | Before | After |
| --- | --- | --- |
| `RunObservation.__dict__["policy_drift"] = True` | `VERIFIED` became `FAILED` | `AttributeError`; no `__dict__` exists |
| `ExceptionRecord.__dict__["scope"] = ...` on a caller-held record | `VERIFIED` became `FAILED` | `AttributeError`; the stored record is a deep copy |
| `TargetDecision` subclass reporting `FIXED` while storing `STILL_PRESENT` | `VERIFIED` | `SpecDomainError` at every boundary |
| `tuple` subclass swapping its `__iter__` after construction | `VERIFIED` became `FAILED` | verdict unchanged; an exact built-in tuple is stored |
| one exception used for `SUPPRESSED`, `RESOURCE_DELETED` and `FILE_DELETED_OR_RENAMED` | all three `VERIFIED` | only the named event verifies; the others `FAILED` |
| `TargetObservation.__dict__["candidate_matches"] = -1` | `FIXED` from an impossible state | `AttributeError`; `M` stays 0 |
| `FindingLocation.__dict__["start_line"] = -100` | invalid object retained | `AttributeError`; `start_line` stays 10 |

The rejection message names both sides of an event mismatch:

```
exception EX-1 authorises ['SUPPRESSED'], not RESOURCE_DELETED: approving one event
does not approve another
```

The 3×3 event matrix is exhaustive: for each of the three eligible outcomes as the
authorised event, each of the three as the attempted event, only the diagonal verifies.

Phase D1 also lands the production package `src/iac_guard_v/` with `enums.py` and
`models.py` under the same rules, and `tests/unit/test_models_immutability.py` applies one
matrix to **both** the oracle and the production models, so the production code cannot
inherit a weakness the oracle has shed.

**Gate B: PASS.**

---

## Gate C — specification package

```console
$ python3 tools/spec_lint.py docs/spec/
documents inspected:  23
enum values defined:  41
PASS

$ python3 tools/spec_lint.py --require-section trusted-configuration \
    docs/spec/VERIFICATION_SEMANTICS.md docs/spec/THREAT_MODEL.md
PASS
```

The linter fails on a real gap. Removing one enum definition:

```console
  FAIL ENUM_COMPLETE: DeltaClass member `LOCATION_CHANGED` is not defined in VERIFICATION_SEMANTICS.md
FAIL
```

The final Gate C run reports **zero warnings**: verifier diagnostic codes such as
`INDEX_MODE_CHANGED` are now declared in a named `DIAGNOSTIC_CODES` set, since they
describe how a tool failed rather than what a verification outcome means.

### C.1 Semantic consistency corrections
Review 1 found four places where the document and the executable reference model
disagreed. All four are corrected, and each correction has tests:

| Contradiction | Correction |
| --- | --- |
| V5 treated `files_parsed` or `checks_loaded` below the **baseline** as `PARTIAL`, contradicting §5.1 | V5 now compares against the independently computed eligible candidate set; `checks_loaded` only signals drift when it contradicts the locked ruleset inventory |
| the written ordering evaluated counts before evidence sufficiency, while the model evaluated evidence first | evidence sufficiency is now documented as a prerequisite for every count-based outcome, ahead of `PARTIALLY_FIXED`, `STILL_PRESENT` and `FIXED` |
| `LOCATION_CHANGED` was "matches `RELOCATED` but not `EXACT`", which a line-only move can never satisfy because lines are excluded from the `EXACT` key | it is now a metadata delta over matched findings: `file_path`, `start_line` or `end_line` changed (§5.2) |
| oracle state was inside the `FIXED` predicate **and** the whole-run rule claimed a failing oracle yields `FAILED`, which is unreachable | oracles are gates, not classifiers (§4.3). Target classification uses structural and scanner evidence only; typed validator and oracle states are applied at verdict time |

Validators and oracles now carry the full `Status` vocabulary. `FAIL` means the
artifact or repair is demonstrably wrong and yields `FAILED`; `ERROR`, `TIMEOUT`,
`UNSUPPORTED`, `PARTIAL`, `INCONCLUSIVE` and `SKIPPED` mean the check did not complete
and yield `INCONCLUSIVE`.

### C.2 Domain and policy-boundary hardening

Review probes of the conformance oracle itself found nine unsafe behaviours. The
oracle is the model Phase D's engine will be written against, so each would have been
implemented into the product. Measured before, then after:

| Probe | Before | After |
| --- | --- | --- |
| verification request with zero targets | `VERIFIED` | `InvalidVerificationRequest`, exit code 2 |
| `STILL_PRESENT` waived by permission | `VERIFIED` | `FAILED` — never exception-eligible |
| `PARTIALLY_FIXED` waived by permission | `VERIFIED` | `FAILED` — never exception-eligible |
| two deletions, one blanket permission | `VERIFIED` | `FAILED` — the exception binds one `target_id` |
| regression policy `ERROR` | `FAILED` | `INCONCLUSIVE` |
| suppression policy `TIMEOUT` | `FAILED` | `INCONCLUSIVE` |
| empty required-validator list | `VERIFIED` | `InvalidVerificationRequest` |
| target counts `N=0, M=0` | `STILL_PRESENT` | `SpecDomainError` |
| target counts `N=1, M=-1` | `FIXED` | `SpecDomainError` |
| target counts `N=-1, M=0` | `STILL_PRESENT` | `SpecDomainError` |

The global `permitted_outcomes` set was replaced by per-target `TargetDecision` records
bound to `ExceptionRecord`s. A permission now holds only when the outcome is in the
closed eligible set, the record names that exact target, its scope matches, its origin
is trusted rather than the evaluated change, it carries a reason and an owner, and it
has not expired. Each clause has a test that fails when it is removed, and the
rejection reason is reported rather than the claim being silently dropped:

```
exception EX-1 binds target 'T-A', not 'T-B'
STILL_PRESENT is never exception-eligible
exception EX-1 originates in the evaluated change; a self-granted approval is not an approval
exception EX-1 expired on 2026-01-01
```

The `MANIFEST_ROOT` parser was also unanchored, so decorated labels counted as
declarations. Measured:

| Annotation line | Before | After |
| --- | --- | --- |
| `MANIFEST_ROOT: <root>` | 1 match | 1 match |
| `    MANIFEST_ROOT:     <root>   ` | 1 match | 1 match (alignment is fine) |
| `NOT_MANIFEST_ROOT: <root>` | **1 match** | 0 matches → `TAG_ROOT_ABSENT` |
| `XMANIFEST_ROOT: <root>` | **1 match** | 0 matches → `TAG_ROOT_ABSENT` |
| `MANIFEST_ROOT: <root> trailing-text` | **1 match** | 0 matches → `TAG_ROOT_ABSENT` |
| two exact declarations | 2 | 2 → `TAG_ROOT_AMBIGUOUS` |

And one test was tautological: `assert all(...) or excluded_artifacts` passes whether
the list is empty or not. It is replaced by a test that plants a `.pyc`, a `.pyo` and a
`.DS_Store` in a synthetic tree and asserts none is copied. Verified to fail when the
exclusion list is removed:

```console
E  assert not ['scripts/stray.pyo', 'scripts/__pycache__/analyze_part1.cpython-311.pyc',
               'runs/raw/.DS_Store']
FAILED tests/research/test_qrs_regression.py::test_replay_workspace_copy_rejects_artifacts_that_exist
```

### C.3 D0 boundary hardening: malformed and omitted input

Review probes of the conformance oracle found a further fail-open class: Python
annotations are not runtime validation, so an unknown value is neither in the undecided
set nor equal to `FAIL` and falls through to the pass branch. Measured before, then
after, using the review's A–L labels:

| Probe | Before | After |
| --- | --- | --- |
| A no gate evidence supplied | `VERIFIED` | `InvalidVerificationRequest`, naming the missing field |
| B `required_validator_states=("PASS",)` | `VERIFIED` | `SpecDomainError`: must be a `Status` member |
| C `required_validator_states=("BOGUS",)` | `VERIFIED` | `SpecDomainError` |
| D `required_oracle_states=("BOGUS",)` | `VERIFIED` | `SpecDomainError` |
| E `regression_policy="BOGUS"` | `VERIFIED` | `SpecDomainError` |
| F `scanner_integrity_ok="false"` | classified as if integrity held (a non-empty string is truthy) | `SpecDomainError` |
| F2 `scanner_integrity_ok=1` | `SCANNER_ERROR` by accident of falsiness | `SpecDomainError` |
| G blank `target_id` | accepted | `SpecDomainError` |
| H blank exception scope | accepted | `SpecDomainError` |
| I mapping key `EX-1` pointing at a record whose id is something else | `VERIFIED` | `SpecDomainError`: key does not match record id |
| J default `evaluation_date` of 2026-08-09 | expired records stayed valid indefinitely | required input; a 2026-12-31 record is `expired` when evaluated on 2028-01-01 |
| K clearing the caller's exception dict | verdict changed `VERIFIED` → `FAILED` | verdict unchanged; the policy is copied and frozen |
| L `FindingLocation("main.tf", 5, 2)` | accepted | `SpecDomainError` |

Trusted provenance is now stamped by the loader rather than read from the record. A
payload declaring `origin: trusted_base` while being read from the candidate is stamped
`candidate_head`, and the resulting permission is rejected with `origin
'candidate_head' is not trusted; a self-granted approval is not an approval`.

Exception windows are inclusive on both bounds, and a record whose `created` date has
not arrived is rejected as `not yet in force`.

`tests/spec/test_domain_boundaries.py` holds 74 probes covering each row above plus
`datetime` rejected where a `date` is required, unknown exception fields, duplicate
exception ids, non-`TargetDecision` entries, unknown optional-gate names, and optional
gates whose optionality did not come from a trusted source.

### C.3.1 D1.1 domain consistency

Four further defects were reproduced against the production models and are now closed:

| Probe | Before | After |
| --- | --- | --- |
| `Target("checkov","RULE@X","scope")` vs `("checkov","RULE","X@scope")` | same `target_id`, so one exception could authorise both | structurally distinct; the spoofed decision is rejected with `binds a different target` |
| `Target("foo:bar","baz","scope")` vs `("foo","bar:baz","scope")` | same `target_id` | structurally distinct |
| a Trivy finding inside a Checkov run at version 9.9 | accepted | `DomainError`; provenance is never silently rewritten |
| two findings sharing an exact key | canonical JSON depended on input order (`["one","two"]` vs `["two","one"]`) | `DomainError`; `assign_occurrence_indices` produces identical output from either order |
| a `Mapping` whose `items()` and `values()` disagree | built a policy containing the smuggled record | `DomainError`; only exact built-in containers are accepted, snapshotted once |

Target identity now has four forms with distinct jobs: the authoritative
`canonical_key`; a lossless `reference` grammar (`scanner=<v>;rule=<v>;scope=<v>` with
`%`, `;` and `=` escaped) proven to round-trip under delimiter-laden values; a versioned
`opaque_id` over a length-prefixed encoding; and a human `display_ref` that is
deliberately ambiguous and cannot be parsed back.

### C.3.3 D2.1 secure-runner closure

Nine defects independently reproduced against `584eb3a` are closed. Measured before and
after:

| # | Defect | Before | After |
| --- | --- | --- | --- |
| 1 | HOME exposes `~/.aws/credentials` | child HOME = real HOME | child HOME = private scratch |
| 2 | PATH="." fake executable | PASS, ran "FAKE" | `ProcessPolicyError: cannot override protected 'PATH'` |
| 3 | 1 MiB stderr, 64 KiB cap | PASS, 1,048,576 bytes | PARTIAL, 65,536 bytes |
| 4 | closed streams + sleep, timeout=1 | ERROR after 3.07s | TIMEOUT after 1.06s |
| 5 | leader exits, grandchild survives | grandchild wrote marker | marker never appears; group killed |
| 6 | mutable env_extra | mutation succeeded | `TypeError` (MappingProxyType frozen) |
| 7 | `BAD=KEY` / NUL value | raw `ValueError` | `ProcessPolicyError` |
| 8 | malformed CommandResult | accepted | `ProcessPolicyError` |
| 9 | no redaction | absent | `redaction.py` with credential/token/path redaction |

30 new acceptance probes in `tests/unit/test_process_d21.py`. Suite total: 566.

### C.3.2 D2 secure process runner

`src/iac_guard_v/process.py` with 46 tests that run real subprocesses. Three guards were
mutation-checked — the test suite must fail when the guard is removed:

| Guard removed | Result |
| --- | --- |
| credential denylist | 16 failures, including `test_credential_denial_reaches_the_actual_child` |
| process-group termination replaced by child-only `terminate()` | `test_the_whole_process_group_is_terminated_not_just_the_child` fails: a grandchild outlived the deadline |
| truncated output classified `PASS` instead of `PARTIAL` | `test_oversized_output_is_partial_not_pass` fails |

Verified behaviours include: a shell metacharacter in an argument stays data and creates
no file; a hanging child times out as `TIMEOUT` and its grandchild does not survive; a
`SIGKILL`ed child is `ERROR` with the signal recorded; oversized output is `PARTIAL` with
the process group signalled; the scratch directory is `0o700` and removed; a declared
non-zero exit code (Checkov's 1) is within contract while an undeclared one is `ERROR`; a
missing executable is `UNSUPPORTED`; and evidence records digests rather than the child's
output.

### C.4 Executable semantic truth tables
Enum names existing is not the same as outcome predicates being coherent. The
specification's predicates are transcribed into `tests/spec/spec_reference.py` and
exercised by `tests/spec/test_semantics_truth_table.py`:

```console
$ python3 -m pytest tests/spec -q
...................................................................      [100%]
67 passed in 0.19s
```

Proven properties: every one of the ten target outcomes is reachable; insufficient
occurrence evidence outranks the count rules for `M == 0`, `0 < M < N` and `M >= N`
alike, while still yielding to stronger structural signals; a line-only move is
observable as `LOCATION_CHANGED` even though the stable identity is unchanged; every
undecided gate state yields `INCONCLUSIVE` for both validators and oracles; an
undecided gate dominates a definite defect; target classification takes no oracle
input, so the previously impossible test state cannot be constructed; the count
predicates for `PARTIALLY_FIXED`, `STILL_PRESENT`, and `FIXED` are disjoint and total
across a 5x7 grid of `(N, M)`; classification is total across all 128 combinations of
the seven observation flags, evaluated against five `(N, M)` pairs for 640 total
classifications; `SUPPRESSED` and `OUT_OF_SCOPE` cannot collide; `M == 0`
alone never yields `FIXED`; every verdict is reachable; and operational failure yields
`INCONCLUSIVE` rather than `VERIFIED` or `FAILED`, including when a real defect is
also present.

**Gate C: PASS.**

---

## No frozen research file changed

```console
$ git diff --stat qrs-2026-replication-v1 \
    -- benchmark runs results prompts scanners scripts requirements.txt
(no output)
```

---

## Corrections to the previous log

| Previous claim | Status | Correction |
| --- | --- | --- |
| "the strict verifier proves no unlisted file under frozen prefixes" | **wrong** | it used `git ls-files --others --exclude-standard`, which omits ignored files. Now the physical filesystem is walked |
| "mode change on `scripts/verify_patch.py` → `MODE_CHANGED`" | **incomplete** | only an *index* mode change was detected. Physical `lstat` bits are now compared |
| "frozen file replaced by a symlink → `SYMLINK_APPEARED`" | **incomplete** | only the final component was checked; a symlinked parent directory passed |
| "759 attempt blobs parsed via `ast.literal_eval`" | **wrong** | 759 values are JSON objects, 0 are repr strings, 3 are missing, and `ast.literal_eval` was invoked 0 times |
| "verdict consistency: 0 failures" | **incomplete** | 627 of 630 were checkable; 3 were unavailable and are now classified rather than skipped |
| audit finding F10, "`verification` is stored as a Python repr" | **wrong** | corrected in the audit; a printed `str(dict)` was misread as the stored encoding |
| `requirements-reproduction.lock` presented as the exact environment | **PARTIAL at the time** | replaced by a hash-pinned replay lock plus a separate Checkov lock, with a digest-pinned base image |
| `MODEL_REFRESH_PROTOCOL_PREPARED_BUT_NOT_EXECUTED` | **wrong wording** | the protocol was never written; see the statement below |

---

## Inference statements

```
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Final Phase-D gate — D4.7, D5.5, D7, and D9

The final core remediation and public-boundary work was committed independently:

```text
D4.7 3ff310b  complete filesystem and scanner-environment identity
D5.5 45e5ed2  complete gate and canonical-result provenance
D7   91f48e4  closed public API, CLI, config-v1, and report-v1 schemas
D9   731c295  offline frozen legacy-versus-hardened comparison
```

Literal old-to-new security probes:

```text
external directory symlink:
  old: omitted from artifact universe; validator files=0; VERIFIED possible
  new: recorded as SYMLINK / UNSAFE_SYMLINK_ENTRY; preflight ERROR; never VERIFIED

supported FIFO evil.tf:
  old: omitted from classifications; VERIFIED possible
  new: recorded as FIFO / UNSUPPORTED_ARTIFACT_PATH_TYPE; preflight ERROR; never VERIFIED

Checkov dependency.py changed without metadata change:
  old: scanner_environment_digest unchanged
  new: verified installed-file digest changes (or unsafe environment is rejected)

gate helper source changed:
  old: selected-dispatcher digest unchanged
  new: gate implementation manifest digest changes for YAML node validation,
       duplicate-key construction, root Kubernetes classification, JSON depth,
       HCL discovery, and bounded file reading

canonical verification result:
  old: gate_registry_identity without complete implementation/artifact records
  new: ordered gate implementation records plus baseline/candidate sealed snapshot,
       complete filesystem/artifact classifications, resource digest, and governed evidence
```

Supported Python matrix, using the declared dependencies and warning-as-error imports:

```text
Python 3.10.20: import PASS; 1248 passed in 163.37s
Python 3.11.5:  import PASS; 1248 passed in 111.69s
Python 3.12:    import PASS; 1248 passed in 162.97s
Python 3.13.14: import PASS; 1248 passed in 157.83s
```

Focused coverage and live integration gates:

```text
D4 adapter branch coverage: base 100%, checkov 91%, total 92%; 138 passed
D5 engine branch coverage: 90%; 208 passed
D6 policy branch coverage: 92%; 199 passed
Checkov 3.3.0 isolated live integration: 6 passed in 59.37s
D7 public-boundary tests: 12 passed
D9 frozen offline comparison tests: 3 passed
```

D9 used only stored frozen run, patch, and baseline scanner files. It executed no
scanner, benchmark inference, or model-provider operation. The deterministic analysis
reported 407 legacy `VERIFIED` records and 223 legacy `FAILED` records as hardened
`INCONCLUSIVE`, because the historical evidence lacks the affirmative candidate,
sealed-snapshot, execution-identity, coverage, and trusted-policy evidence required by
the hardened verifier. It did not reinterpret those missing records as production
verdicts or modify historical results.

```text
D9 frozen run-input digest:       d9ef4318911bc70fba2c2c0286626978bf3376b0de95a2d22f63a3e6ff51aef8
D9 frozen patch-input digest:     c081e50b40657980666141dac524ab2062f5e5cb5ebd7a21b92cc8eef516577a
D9 frozen baseline-input digest:  6027ae079029e5907bb69c15392775edc75758256cc8ab5058358c0a2d9d4ff3
local syntax evidence:            577 PASS, 53 FAIL
hardened analysis classification: 630 INCONCLUSIVE, 0 VERIFIED
scanner executions:               0
model-provider calls:             0
```

Final specification, packaging, research, and freeze gates:

```text
spec_lint: PASS; 23 documents; 111 enum values; zero warnings
wheel/sdist build: PASS; schemas included; frozen/research inputs excluded
manifest files checked: 4842/4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
manifest result: PASS
frozen run records: 630/630
field comparisons: 10080/10080 equal
final verdict mismatches: 0
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
freeze tag type: annotated tag
freeze tag commit: 7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5
```

Phase E was not started. No branch or tag was pushed, and no PR, release,
publication, outreach, model refresh, benchmark inference, or provider call occurred.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Gate D9 — Frozen legacy-versus-hardened comparison

```text
stored run records: 630
stored patch records: 630
stored baseline Checkov records: 70
legacy VERIFIED -> hardened INCONCLUSIVE: 407
legacy FAILED -> hardened INCONCLUSIVE: 223
local candidate syntax PASS: 577
local candidate syntax FAIL: 53
hardened VERIFIED claims: 0
new scanner executions: 0
new benchmark inference runs: 0
model-provider calls: 0
focused D9 tests: 3 passed
stored runs manifest: d9ef4318911bc70fba2c2c0286626978bf3376b0de95a2d22f63a3e6ff51aef8
stored patches manifest: c081e50b40657980666141dac524ab2062f5e5cb5ebd7a21b92cc8eef516577a
stored baselines manifest: 6027ae079029e5907bb69c15392775edc75758256cc8ab5058358c0a2d9d4ff3
```

All 630 hardened classifications remain inconclusive because the historical record does
not retain affirmative candidate target evaluations, candidate execution/coverage
identity, a historical sealed snapshot, or trusted policy provenance. This is a
deliberate typed limitation, not a retroactive rewrite of the paper results.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Gate D9.1 — Reproducible historical evidence-sufficiency report

The canonical offline comparison now uses the exact label
`HISTORICAL_HARDENED_EVIDENCE_SUFFICIENCY_COMPARISON`, distinguishes local parser
`PASS`, `FAIL`, `UNSUPPORTED`, and `ERROR`, binds parser-distribution and IaC-Guard-V
implementation digests, and renders `LEGACY_VS_HARDENED.md`. Results remain 407 legacy
`VERIFIED` and 223 legacy `FAILED` to hardened-evidence `INCONCLUSIVE`, with zero
hardened `VERIFIED`, scanner executions, inference runs, or provider calls.

## Final Phase-D public-boundary gate (2026-08-12)

The final executable gate used copied-file Python environments and real declared
dependencies. After removing generated bytecode, clean warning-as-error imports and the
complete non-integration suite passed on Python 3.10.20, 3.11.6, 3.12.4, and 3.13.15.

```text
Python 3.10.20: clean import PASS; 1310 passed
Python 3.11.6:  clean import PASS; 1310 passed
Python 3.12.4:  clean import PASS; 1310 passed
Python 3.13.15: clean import PASS; 1310 passed
D4 adapter branch coverage: 90.32% (141 passed)
D5 engine branch coverage: 90.32% (216 passed)
D7 public-boundary branch coverage: 97.12% (61 passed)
Checkov 3.3.0 copied-file isolated integration: 6 passed
spec_lint: 24 documents; 111 enums; PASS with zero warnings
manifest: 4842/4842 PASS
MANIFEST_ROOT: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
replay: 630/630 runs; 10080/10080 fields; zero verdict mismatches
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
```

The first clean-wheel integration attempt exposed pip-generated, unhashed bytecode rows
in installed `RECORD` files. Old final result: six integration failures because absent
purged bytecode was treated as missing source. The corrected contract excludes those
rows from the source manifest while still rejecting any actual `__pycache__`, `.pyc`, or
`.pyo` entry before and after execution. New final result: six of six live Checkov 3.3.0
integrations pass in a copied-file, bytecode-disabled environment.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

## Gate D9.2 — Hash-pinned historical analysis (2026-08-12)

Failing-before, canonical Markdown byte equality required a test monkeypatch that
substituted two parser digests, and the `407`/`223` labels were duplicated as literals
beside computed values. No standalone pinned analysis environment or canonical JSON was
present.

Passing-after, `requirements-d9.lock` hash-pins eleven direct/transitive distributions;
`Dockerfile.d9` pins Python 3.11.14 by linux/amd64 image manifest; and
`D9_ENVIRONMENT.json` records the multi-platform index, selected manifest, versions,
wheel hashes and installed-code digests. The image build ran environment verification
and byte-equality assertions successfully. Canonical output contains 630 records,
computed transitions `407` and `223`, zero hardened `VERIFIED`, zero scanner executions,
zero provider calls and zero new benchmark inference runs.

## Gate D7.1 — Closed public API, CLI, and schema contract

Failing-before probes accepted operational `VERIFIED/0`, allowed reduced mode without
an executable in JSON Schema, exposed no `--version`, `demo`, or `explain`, accepted
nested roots, and mapped invalid candidate HCL to request exit 2. Passing-after probes
reject every contradictory branch, enforce config isolation conditions and disjoint
roots, emit candidate V1 `FAILED/1`, retain literal `reduced-isolation`, validate real
outputs, and prove deeply immutable doctor evidence.

## Gate D7.2 — Semantic public report closure (2026-08-12)

Failing-before: six schema-valid forged `VERIFIED` reports independently retained
scanner-integrity `FAIL`, preflight `ERROR`, required-validator `FAIL`, target
`STILL_PRESENT`, policy-decision `STILL_PRESENT`, or regression `FAIL`; all six passed
`validate_report_payload`. Full verification could also pair with artifact-failure
policy. The permanent D7.2 suite initially reported nine failures.

Passing-after: schema and runtime validation reject every forged state and crossed
branch, and `explain` rejects the same bytes as invalid input. Candidate failure evidence
now binds artifact kind, actual validator id and typed reason. Console explanation
projects isolation, target reasons, nonpassing gates, scanner integrity, regression and
destructive events, policy decisions/exceptions and remediation without adding evidence.

## Gate D5.7 — Physical parser implementation closure (2026-08-12)

Failing-before, adding unlisted
`parser_pkg/__pycache__/evil.cpython-313.pyc` left the parser distribution digest
unchanged. Unlisted `.py`, `.pyi`, `.so`, `.pyd`, `.dylib`, a symlinked helper and an
escaping `RECORD` path were also accepted: eight focused failures.

Passing-after, the no-follow installed-tree inventory rejects all eight mutations. The
active parser dependency closure is rechecked before and after validation while
`PYTHONDONTWRITEBYTECODE=1` and the interpreter bytecode switch are active. Unavailable,
unverifiable or changed evidence returns typed gate `INCONCLUSIVE`; it cannot reach
`VERIFIED`. Doctor calls successful native Checkov evidence
`CHECKOV_ENVIRONMENT_INTERNALLY_CONSISTENT`, reserving provenance for protected locks.

## Gate D7 — CLI, API, config-v1 and report-v1

```text
default public execution mode: hardened-container
Phase E image absent: INCONCLUSIVE / HARDENED_CONTAINER_UNAVAILABLE / exit 3
native mode without explicit executable: invalid request / exit 2
raw scanner_run, policy, callback or trusted_origin config key: invalid request / exit 2
duplicate JSON config key or symlinked config file: invalid request / exit 2
explicit reduced-isolation: internal scan-plan -> adapter -> engine -> policy pipeline
report-v1: complete gate implementations and baseline/candidate filesystem inventories
doctor: deterministic Checkov/container status and remediation
focused D7 tests: 12 passed
```

No hostile input was run natively, and no callback, raw policy, precomputed evidence or
candidate trust assertion was accepted. No benchmark inference, provider call, or model
refresh occurred.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Gate D5.6 — Validator implementation and portable snapshot provenance

Literal failing-before probes on D4.8:

```text
HCL2_OLD_IDENTITY_UNCHANGED True
SYMLINK_CANONICAL_OLD ... '/Users/alice/private/project' ...
```

Passing-after mutation tests show an active `hcl2.loads` behavior replacement changes
the verified parser dependency identity while leaving the product build and loader
contract identities separate. Canonical symlink evidence contains only `absolute` or
`relative`, the target-text SHA-256, and rejection evidence; the raw target is absent and
a target change still changes the snapshot identity.

## Gate D5.5 — Complete gate and canonical-result provenance

Literal failing-before probes on D4.7:

```text
mutate YAML node validator source: gate implementation identity unchanged
mutate duplicate-key constructor source: gate implementation identity unchanged
mutate root Kubernetes classifier source: gate implementation identity unchanged
mutate bounded file reader source: gate implementation identity unchanged
TrustedVerificationConfigBundle canonical keys: gate_registry_identity only
VerificationResult canonical keys: no top-level gate_implementations
```

Literal passing-after probes:

```text
YAML node validator mutation: implementation digest changed
duplicate-key constructor mutation: implementation digest changed
root Kubernetes classifier mutation: implementation digest changed
JSON depth checker mutation: implementation digest changed
HCL discovery wrapper mutation: implementation digest changed
bounded file reader mutation: implementation digest changed
configuration and result: ordered gate_id/kind/version/code_sha256/dependency_identity/artifact_kinds records
baseline/candidate canonical snapshots: complete filesystem_entries present
focused D5.5 probes: 7 passed
```

No benchmark inference, provider call, or model refresh occurred.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Gate D4.8 — Executable scanner-environment closure

Literal failing-before probe on `8e97146a142a0194b5446fe6603612671b8723cd`:

```text
PYC_OLD True True True
```

The three values show that adding executable bytecode left scanner-environment,
installed-distribution, and policy-inventory identity unchanged. Passing-after probes
reject timestamp-valid malicious bytecode, reject missing/extra/hash-mismatched RECORD
content, set `PYTHONDONTWRITEBYTECODE=1` for probe and scan, and turn bytecode created
during execution into `ERROR / SCANNER_ENVIRONMENT_MISMATCH`.

## Gate D4.7 — Complete filesystem artifact and scanner-environment identity

Literal failing-before probes on `ed9d77f39c14cacc17ba46fb7c94bfb97b0daaa6`:

```text
external directory symlink linked -> outside/pod.yaml: absent from snapshot; preflight PASS; VERIFIED
FIFO evil.tf: absent from classifications; preflight PASS; VERIFIED
dependency.py VALUE=1 -> VALUE=2 with unchanged dist-info: dependency digest unchanged
candidate snapshot canonical keys: no filesystem_entries
```

Literal passing-after probes:

```text
external/internal/broken/cyclic directory symlink: SYMLINK / UNSAFE_SYMLINK_ENTRY
FIFO evil.tf: FIFO / UNSUPPORTED_ARTIFACT_PATH_TYPE
socket manifest.yaml: SOCKET / UNSUPPORTED_ARTIFACT_PATH_TYPE
directory config.json: REAL_DIRECTORY / UNSUPPORTED_ARTIFACT_PATH_TYPE
symlink or broken-symlink supported input: UNSAFE_SYMLINK_ENTRY
all unsafe cases: ERROR / ARTIFACT_UNIVERSE_UNRESOLVED; never VERIFIED
dependency.py VALUE=1 -> VALUE=2: dependency digest changed; environment digest changed
focused D4.7 security probes: 10 passed
existing engine/Checkov unit tests excluding the pending D5.5 probes: 317 passed
```

The shared inventory never follows directory symlinks and retains rejected entries in
the sealed snapshot. No benchmark inference, provider call, or model refresh occurred.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

## D6.4 — Candidate tree and governed directory attestation (2026-08-11)

Parent: `230c0cec23b1a662b7a7f98b24ae370e3b27f6fd`. D6.4 did not alter the
frozen QRS scope and did not begin D7, D9, or Phase E. Literal parent behavior reproduced
before modification:

```text
OLD_CONTEXT_CANDIDATE_COMMIT <candidate commit SHA>
OLD_WORKTREE_EQUALS_BASE True
OLD_POLICY_DRIFT False
OLD_CANDIDATE_ROOT_IDENTITY git_candidate_<candidate commit SHA>
OLD_GOVERNED_SYMLINK_EVIDENCE []
```

Passing-after focused evidence:

```text
candidate commit/worktree mismatch -> DomainError: candidate checkout differs from authorized commit
mutation after context attestation -> rejected again immediately before policy loading
ignored untracked ignored.tf -> rejected as ignored supported or governed input
.iac-guard symlink directory -> candidate_kind SYMLINK; state type_changed
custom_checks symlink directory -> candidate_kind SYMLINK; state type_changed
monorepo prefix -> services/team-a on base and candidate Git-object reads
policy snapshot digest substitution -> PolicyRequest rejected as unauthorized
focused D6.4 regression file -> 17 passed
focused D6 suite -> 187 passed; policy branch coverage 92%
```

Candidate policy and governed evidence now come from the authorized candidate Git object.
The protected checkout is clean and commit-bound, D5/D6 snapshot and subpath identities
must agree, and canonical source evidence does not include local absolute roots.

Final gate evidence at `66d700c2323fb8a0f13637bdd9fc4357f5ea51ad` plus the
test-only cross-version assertion correction:

```text
host Python 3.11 non-integration -> 1216 passed
container Python 3.10 real declared dependencies -> 1216 passed
container Python 3.12 real declared dependencies -> 1216 passed
container Python 3.13 real declared dependencies -> 1216 passed
clean-bytecode warning-as-error import -> PASS on 3.10, 3.11, 3.12, 3.13
pinned Checkov 3.3.0 isolated venv --copies -> 6 passed
D4 adapter branch coverage -> 91%
D5 engine branch coverage -> 91%
D6 policy branch coverage -> 92%
spec_lint -> 23 documents; 111 enums; PASS; zero warnings
manifest -> 4842/4842; a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3; PASS
tag -> annotated tag; peeled commit 7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5
replay -> 630/630 runs; 10080/10080 fields; zero verdict mismatches
derived tables -> 7/7 SEMANTIC_MATCH
frozen-scope diff -> empty
```

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

## Gate D4.4 — Strict independent artifact discovery

Literal failing-before probes on `f9fe391b88b07676dbbab68124da04ac15bd13e3`:

```text
quoted-key Kubernetes pod.yaml -> files_eligible ('main.tf',); resource omitted
invalid HCL: resource "aws_x" "r" { invalid = } -> accepted; no exception
focused reproduction -> 2 failed
```

Passing-after behavior binds quoted/flow/JSON YAML, multi-document resources, and
Kubernetes List items; rejects duplicate keys, custom tags, aliases, excessive depth,
malformed/incomplete identity, and invalid HCL; and rejects `.tf.json` explicitly rather
than ignoring it. Exact executable gate output is recorded after the D4.4 test run.

```text
focused adapter/engine suites: 186 passed
clean-bytecode warning-as-error import: PASS (Python 3.11)
spec_lint: documents inspected 23; enum values defined 102; PASS
```

---

## Gate D4.5 — Complete Kubernetes artifact classification (2026-08-11)

Parent: `c23c5c0115d2a0b0018b5ee38e4d423e7cbf4420`. D4.5 did not alter the
frozen QRS scope and did not begin D5.3, D6.3, D7, D9, or Phase E.

Literal failing-before evidence from an archive of the parent:

```text
pod.json eligible files -> ('main.tf', 'pod.yaml')
pod.json present -> False
GitHub Actions workflow -> DomainError: Kubernetes YAML rejected: unsafe/custom YAML tag
```

Literal passing-after evidence:

```text
pod.json -> KUBERNETES_RESOURCES / KUBERNETES_JSON
pod.json eligible and copied to private scan view -> True
Kubernetes List JSON -> each item retained as an exact expected resource
ordinary JSON -> NON_KUBERNETES_JSON
GitHub Actions workflow -> NON_KUBERNETES_YAML
CloudFormation custom-tag document without Kubernetes identity -> NON_KUBERNETES_YAML
duplicate/deep/malformed/Kubernetes-looking unsupported JSON -> typed DomainError before scan
unsafe, nested, incomplete, or unsupported Kubernetes YAML -> typed DomainError before scan
every inspected Terraform/YAML/JSON file -> digest-bound ArtifactClassification
```

Executable gates:

```console
$ PYTHONPATH=src pytest -q tests -m 'not integration'
1117 passed in 167.28s (0:02:47)

$ PYTHONPATH=src pytest -q tests/integration/test_checkov_integration.py
6 passed in 98.82s (0:01:38)

$ COVERAGE_FILE=/tmp/iacgv-d45-adapter-final.coverage PYTHONPATH=src pytest -q \
    tests/unit/test_checkov_adapter.py tests/unit/test_checkov_adapter_d41.py \
    tests/unit/test_checkov_adapter_d42.py tests/unit/test_checkov_adapter_d45.py \
    --cov=iac_guard_v.adapters.base --cov=iac_guard_v.adapters.checkov \
    --cov-branch --cov-report=term --cov-fail-under=90
116 passed; combined adapter branch coverage 90.83%

$ COVERAGE_FILE=/tmp/iacgv-d45-engine.coverage PYTHONPATH=src pytest -q \
    tests/unit/test_engine.py tests/unit/test_engine_d44.py \
    tests/unit/test_engine_d45.py tests/unit/test_engine_d51.py \
    tests/unit/test_engine_d52.py --cov=iac_guard_v.engine --cov-branch \
    --cov-fail-under=90
124 passed; engine branch coverage 90.65%

$ python tools/spec_lint.py docs/spec/
documents inspected: 23
enum values defined: 105
PASS
```

Python 3.11 clean-bytecode warning-as-error import passed in the declared dependency
environment. Python 3.12 is installed locally but its environment lacks the declared
`python-hcl2` dependency; Python 3.10 and 3.13 are not installed locally. Those three
local compatibility legs are therefore **BLOCKED**; the 3.10–3.13 CI matrix and full
dependency installation remain mandatory.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Gate D5.2 — Protected configuration and exact evidence binding

Literal failing-before probes on D4.4 with D5.1 unchanged:

```text
VerificationRequest caller policy fields present -> True
run_checkov_verification _gate_executor parameter present -> True
two PASSED evaluated_keys unrelated-a/unrelated-b -> target FIXED
repeated aws_x.r selector across roots -> accepted, no ambiguity
candidate .checkov.yml plus equal caller digests -> POLICY_DRIFT PASS
a/main.tf target deletion + b/main.tf same-address deletion -> regression PASS
focused reproduction -> 6 failed
```

Passing-after values:

```text
caller policy/config fields in VerificationRequest -> none
arbitrary production gate callback parameter -> absent
unrelated positive keys -> INCONCLUSIVE / OCCURRENCE_PASS_COVERAGE_INCOMPLETE
repeated coarse selector -> rejected as ambiguous
candidate .checkov.yml -> POLICY_DRIFT FAIL; affected_paths ['.checkov.yml']
same-address b/main.tf deletion -> exact DESTRUCTIVE_CHANGE; regression FAIL
trusted HIGH floor + caller CRITICAL override -> rejected; new HIGH -> regression FAIL
protected terraform+kubernetes universe + caller terraform-only request ->
  pod.yaml included as v1/Pod/default/p
engine branch coverage -> 90.36% (103 passed)
```

---

## Gate D4.6 — Scanner environment and mixed-repository classification (2026-08-11)

Parent: `26cc75a0b10eb2a7c0878cd6b6d8d8f73da34696`. D4.6 did not alter the
frozen QRS scope and did not begin D5.4, D6.4, D7, D9, or Phase E.

Literal failing-before evidence:

```text
OLD_SYMLINK_ENV_UNCHANGED True
OLD_SYMLINK_POLICY_UNCHANGED True
OLD_ADAPTER_LABEL_IN_SOURCE True
OLD_YAML alias DomainError Kubernetes YAML aliases are unsupported
OLD_YAML nested_kind DomainError unsupported Kubernetes YAML document shape
```

Passing-after properties:

```text
external package/check/policy symlink -> DomainError before identity acceptance
installed distribution / dependency lock / policy / custom checks -> distinct digests
bytecode cache addition -> distribution identity unchanged
adapter contract -> checkov-adapter-contract-v3
ordinary alias/custom-tag/nested-kind YAML -> NON_KUBERNETES_YAML
root Kubernetes alias or unsupported nested complete identity -> typed failure
focused D4 regression set -> 146 passed
```

No benchmark inference, model-provider call, model refresh, tag/branch push, release,
or external publication occurred.

## Gate D5.3 — Role-bound configuration and closed gate registry (2026-08-11)

Parent: `d8f1ec29fe05d5c466cc942a6ac3af1d980795c6`. Literal archived-parent
reproductions before modification:

```text
swapped request -> OLD_SWAP_ACCEPTED candidate baseline
production loader callback parameter -> True
candidate .iac-guard.json -> policy drift paths ()
same root on both sides -> OLD_SAME_ROOT_ACCEPTED True
failed native token -> checkov-eval-v1:<sha256>
positive occurrence evidence -> raw evaluated_keys tuple (different domain)
```

Passing-after evidence:

```text
swapped roots -> DomainError: baseline scan root does not match protected baseline role
same roots -> DomainError: baseline and candidate roots must be distinct
opposite role-bound plan reuse -> rejected before adapter execution
role plan -> role + snapshot_sha256 + config_sha256
production loader callback parameter -> absent; supplied callback raises TypeError
production registry -> packaged id/version/code digest/artifact-kind evidence
candidate .iac-guard.json -> POLICY_DRIFT path ('.iac-guard.json',), state added
failed and positive evidence -> identical checkov-occurrence-v1 token domain
two exact token-covered occurrences -> FIXED
two unrelated positive keys -> OCCURRENCE_PASS_COVERAGE_INCOMPLETE
policy source authorization -> factory-bound EXPLICIT_OPERATOR for operator mode
```

Executable focused gate:

```console
$ COVERAGE_FILE=/tmp/iacgv-d53-engine2.coverage PYTHONPATH=src pytest -q \
    tests/unit/test_engine.py tests/unit/test_engine_d44.py \
    tests/unit/test_engine_d45.py tests/unit/test_engine_d51.py \
    tests/unit/test_engine_d52.py tests/unit/test_engine_d53.py \
    --cov=iac_guard_v.engine --cov-branch --cov-fail-under=90
145 passed; engine branch coverage 90.21%

$ python tools/spec_lint.py docs/spec/
documents inspected: 23
enum values defined: 111
PASS
```

No D6.3, D7, D9, Phase E, benchmark inference, provider call, or model refresh occurred
in this commit.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## D6.2 — Git-object policy provenance and exact event permission (2026-08-11)

Parent: `2c35692143077aaf58a95a05b725700a23a8f547`. D6.2 did not alter the
frozen QRS scope and did not begin D7, D9, or Phase E.

Literal failing-before evidence on the D6.1 parent:

```text
load_base_commit_policy parameters -> trusted_path, candidate_path, source_identity
candidate policy passed as trusted_path and candidate_path -> origin trusted_base
candidate-as-base policy drift -> False
candidate suppression exception policy_permitted -> True
candidate-as-base final verdict -> VERIFIED
same scanner/rule/address exception in another file -> policy_permitted True
focused source/exact-binding mutations -> 3 failed
```

Literal passing-after evidence:

```text
old arbitrary-path call -> TypeError: load_base_commit_policy() got an unexpected keyword argument 'source_identity'
base source identity -> git_commit_<mechanically-resolved-commit-sha>
trusted policy bytes -> Git commit tree object, not candidate working-tree bytes
candidate exception absent from base object -> trusted records 0
candidate policy differs from base object -> policy_drift True
same scanner/rule/address but other/main.tf -> policy_permitted False; verdict FAILED
candidate-only .checkov.yml -> governed state added; differing path .checkov.yml
committed policy symlink -> rejected: Git policy object must be a regular repository file
protected repository inside workspace -> rejected
protected repository unpinned commit -> rejected
```

Executable focused gates:

```console
$ PYTHONPATH=src pytest -q tests/unit/test_policy.py tests/unit/test_policy_d61.py \
    tests/unit/test_policy_d62.py tests/unit/test_engine_d51.py
149 passed

$ COVERAGE_FILE=/tmp/iacgv-d62.coverage PYTHONPATH=src pytest \
    tests/unit/test_policy.py tests/unit/test_policy_d61.py \
    tests/unit/test_policy_d62.py tests/unit/test_engine_d51.py \
    --cov=iac_guard_v.policy --cov-branch --cov-report=term-missing \
    --cov-fail-under=90 -q
149 passed
policy.py: 548 statements, 216 branches, 90.84% branch coverage
Required test coverage of 90% reached
```

Final D6.2 gate values:

```text
Python 3.11 clean-bytecode warning-as-error import: PASS
Python 3.11 non-integration suite: 1079 passed
Python 3.12 clean-bytecode warning-as-error import: PASS
Python 3.12 non-integration suite: 1079 passed
Python 3.10 local leg: BLOCKED (interpreter not installed)
Python 3.13 local leg: BLOCKED (interpreter not installed)
CI matrix retained: 3.10, 3.11, 3.12, 3.13
live Checkov 3.3.0 integration: 5 passed
D3 fingerprints/matching/diffing coverage: 100.00% / 90.32% / 91.58%
D4 adapter coverage: 90.50%
D5 engine branch coverage: 90.36%
D6 policy branch coverage: 90.84%
spec_lint: 23 documents, 102 enum values, PASS, zero warnings
manifest files checked: 4842/4842 PASS
MANIFEST_ROOT computed/recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
frozen runs: 630/630
field comparisons: 10080/10080 equal
final-verdict mismatches: 0
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
```

The compatibility workflow installs the full replay-test dependencies for each declared
interpreter. Python 3.13 uses NumPy 2 because NumPy 1 has no Python 3.13 wheel; the frozen
research environment and `requirements.txt` remain unchanged and continue to govern the
research replay. No benchmark inference, provider call, model refresh, D7, D9, or Phase E
work occurred.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## D5.4 — Sealed verification snapshot and portable evidence (2026-08-11)

Parent: `d1aa89b`. D5.4 did not alter the frozen QRS scope and did not begin D6.4,
D7, D9, or Phase E.

Literal failing-before evidence:

```text
OLD_CHANGED_CURRENT_DIFFERS_BOUND True
OLD_CHANGED_PREFLIGHT PASS BOUND_SCAN_PLAN_VALIDATED
OLD_CHANGED_VALIDATOR PASS VALIDATOR_COMPLETED
OLD_CHANGED_TARGET FIXED AFFIRMATIVE_TARGET_PASS
OLD_CHANGED_VERDICT VERIFIED
OLD_LATE_IN_PLAN False
OLD_LATE_EXISTS True
OLD_LATE_PREFLIGHT PASS BOUND_SCAN_PLAN_VALIDATED
OLD_LATE_VERDICT VERIFIED
OLD_CONFIG_SHA_EQUAL False
OLD_CONFIG_CANONICAL_EQUAL False
OLD_GATE_DIGEST_IS_DISPATCHER_ONLY True
OLD_RESULT_CANONICAL_HAS_SNAPSHOTS False
```

Passing-after evidence:

```text
NEW_CHANGED_PREFLIGHT ERROR SNAPSHOT_CHANGED_DURING_VERIFICATION
NEW_CHANGED_VALIDATOR PASS VALIDATOR_COMPLETED
NEW_CHANGED_VERDICT INCONCLUSIVE
NEW_RESULT_SNAPSHOT_KEYS ['baseline_snapshot', 'candidate_snapshot']
late Kubernetes YAML/JSON -> ERROR SNAPSHOT_CHANGED_DURING_VERIFICATION
equivalent roots + identical scanner -> equal config_sha256 and canonical config
parser helper source mutation -> gate implementation digest changes
focused D5 suite -> 179 passed; engine branch coverage 91%
```

All validator and oracle inputs are now sealed plan bytes. Target presence and metrics
use the sealed inventories; final P0 revalidation covers supported and governed entries.
No benchmark inference, model-provider call, model refresh, tag/branch push, release,
or external publication occurred.

## D6.3 — Authorized source context and trusted clock (2026-08-11)

Parent: `fd33c53a036a184cd6a27c2fdcc281be75ec8657`. Literal archived-parent
reproduction:

```text
actual base commit -> 86ead68edcb432ae7a4d653a89296ca5e8a8783c
caller-selected candidate commit -> bb9a6c178b65431f1d5c55dfe6c787db465cc062
stamped source origin -> trusted_base
trusted permissive records -> 1
policy drift -> False
base loader exposes _clock -> True
operator loader exposes _clock -> True
```

Passing-after evidence:

```text
base loader input -> exact TrustedExecutionContext, not caller-selected TrustedGitSource
authorized actual base -> source_commit equals actual base; candidate exception records 0
candidate policy differs from actual base -> policy_drift True; final suppression FAILED
caller-selected low-level candidate source -> rejected as not a trusted execution context
foreign repository bundle -> PolicyRequest rejected: repository/commit unauthorized
public base/operator loader _clock parameter -> absent
expired exception under system UTC context -> FAILED; caller _clock argument TypeError
operator context -> EXPLICIT_OPERATOR only; cannot claim PR/protected Git roles
policy source identity -> portable git_repo_v1 object identity, no local path hash
candidate policy with symlinked parent -> rejected before read
```

Executable focused gate:

```console
$ COVERAGE_FILE=/tmp/iacgv-d63-policy3.coverage PYTHONPATH=src pytest -q \
    tests/unit/test_policy.py tests/unit/test_policy_d61.py \
    tests/unit/test_policy_d62.py tests/unit/test_policy_d63.py \
    tests/unit/test_engine_d51.py --cov=iac_guard_v.policy --cov-branch \
    --cov-fail-under=90
165 passed; policy branch coverage 90.25%
```

PR/protected context construction is intentionally unavailable to ordinary production
callers until protected D7 workflow plumbing exists. That limitation is fail-closed and
is not represented as a completed D7 interface.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

## D4.3 — Cross-version strict JSON depth (2026-08-11)

The Review-3 reproduction on the D6 parent was stored before implementation:

```text
deeply nested JSON expected JSON_DEPTH_EXCEEDED
actual diagnostic on Python 3.11: MALFORMED_JSON
focused regression: 1 failed
independent Python 3.13 review result: UNEXPECTED_TOP_LEVEL
```

After D4.3, a string-aware structural pass enforces the same limit before `json.loads`:

```text
maximum nesting depth: 128
depth 128: accepted by the depth guard
depth 129: JSON_DEPTH_EXCEEDED
depth 2001: ERROR / JSON_DEPTH_EXCEEDED
brackets and escaped quotes inside JSON strings: do not consume depth
focused depth tests: 3 passed
raw RecursionError: still contained, never escapes the adapter
```

The Python 3.10--3.13 workflow retains clean warning-as-error import and full
non-integration test jobs. Locally available interpreter legs and the final D4.3 suite,
coverage, lint, freeze, and replay gates are recorded at the commit gate.

```text
adapter-focused suite: 105 passed; adapter coverage 90.50%
Python 3.11 non-integration: 943 passed in 60.12s
Python 3.12 clean warning-as-error import: PASS
Python 3.12 non-integration: 943 passed in 75.81s
Python 3.10 local leg: BLOCKED (interpreter not installed)
Python 3.13 local leg: BLOCKED (interpreter not installed)
CI matrix retained: 3.10, 3.11, 3.12, 3.13
spec_lint: 23 documents, 98 enum values, PASS, zero warnings
```

## D5 — Verification engine (2026-08-11)

The production verification module did not exist before D5. The literal clean import
result was:

```text
from iac_guard_v.engine import run_checkov_verification
ModuleNotFoundError: No module named 'iac_guard_v.engine'
```

After implementation, the focused executable properties reported:

```text
PYTHONPATH=src pytest -q tests/unit/test_engine.py
31 passed

all ten target outcomes produced: 10/10
zero findings + non-PASS affirmative evidence: INCONCLUSIVE (7/7 states)
adapter invocations: [baseline, candidate]
target outcome: FIXED
finding delta: RESOLVED_FINDING
validator/oracle identities: PASS/PASS
caller evidence fields in VerificationRequest: none
substituted gate id: DomainError
```

The engine request contains paths/scan plans, targets, required identities, and
protected configuration digests. Checkov runs, target evaluations, comparisons, deltas,
and target outcomes are invoked or derived internally and factory-bound. D5 emits no
verdict. Full-suite, coverage, specification, freeze, replay, and frozen-diff values are
recorded at the D5 commit gate.

Exact D5 gate values:

```text
engine coverage: 90.23% (31 passed)
full suite: 897 passed in 151.81s
spec_lint: 23 documents, 97 enum values, PASS, zero warnings
manifest: 4842/4842 PASS
MANIFEST_ROOT: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
replay: 630/630; 10080/10080 fields equal
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
```

## D6 — Policy and verdict (2026-08-11)

The production policy module did not exist before D6:

```text
from iac_guard_v.policy import evaluate_policy
ModuleNotFoundError: No module named 'iac_guard_v.policy'
```

Literal passing-after focused evidence:

```text
clean fully evidenced result -> VERIFIED / 0
definite unpermitted target outcomes -> FAILED (6/6)
uncertain target outcomes -> INCONCLUSIVE (3/3)
event-specific trusted exceptions -> VERIFIED, original event retained (3/3)
suppression exception applied to deletion -> FAILED
candidate, expired, and not-yet-valid exceptions -> FAILED (3/3)
validator statuses -> PASS/FAILED/INCONCLUSIVE mapping (8/8)
oracle statuses -> PASS/FAILED/INCONCLUSIVE mapping (8/8)
regression/suppression policy states -> specified mapping (8/8)
trusted optional SKIPPED regression -> VERIFIED
oracle ERROR plus STILL_PRESENT -> INCONCLUSIVE
policy drift -> FAILED
coverage/rule-substitution uncertainty -> INCONCLUSIVE
reversed exception input order -> byte-identical canonical policy output
candidate-authored optionality -> DomainError
caller-constructed PolicyResult -> DomainError

PYTHONPATH=src pytest -q tests/unit/test_policy.py
49 passed
policy coverage: 91.21%
```

D6 accepts only factory-proven D5 evidence, derives permissions rather than believing a
caller flag, applies the normative uncertainty-first verdict table, and binds each
verdict to its closed exit code. Complete Review-3 suite, lint, research, and frozen
scope gates are recorded after both D5 and D6.

```text
focused engine+policy: 80 passed; combined coverage 90.49%
  engine.py: 90%
  policy.py: 91%
complete suite: 946 passed in 154.86s
spec_lint: 23 documents, 97 enum values, PASS, zero warnings
manifest: 4842/4842 PASS
MANIFEST_ROOT computed/recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
replay: 630/630; 10080/10080 fields equal
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
```

## D5.1 — Affirmative target completeness and engine events (2026-08-11)

All Review-3 fail-open probes were first stored against the unmodified D6 parent. The
literal failing-before result was:

```text
7 failed
UNKNOWN new finding: regression PASS / NO_DECISIVE_REGRESSION
two baseline occurrences + one generic PASSED evaluation: target FIXED
launcher digest drift: scanner integrity PASS
invocation/config digest drift: scanner integrity PASS
real target suppression: suppression gate FAIL despite event-specific permission
unrelated resource deletion: no DESTRUCTIVE_CHANGE engine event
rule substitution: no typed engine event; Boolean default was false
```

After D5.1, the corresponding permanent properties report:

```text
UNKNOWN new finding: INCONCLUSIVE / NEW_FINDING_SEVERITY_UNKNOWN
two baseline occurrences + one generic PASSED evaluation:
  INCONCLUSIVE / OCCURRENCE_PASS_COVERAGE_INCOMPLETE
complete native occurrence tokens: FIXED
launcher or invocation/config digest drift: scanner integrity INCONCLUSIVE
target suppression: detector PASS; SUPPRESSED event remains visible for D6
unrelated resource deletion: DESTRUCTIVE_CHANGE / regression FAIL
rule substitution: typed PASS, FAIL, UNSUPPORTED, or INCONCLUSIVE evaluation
caller expected_resources: ignored and independently rebuilt from bound bytes
P0: BOUND_SCAN_PLAN_VALIDATED with canonical plan digest
V4: immutable line/file/resource metrics; unavailable fields named
all eleven delta classes: six D3-owned plus five D5-owned typed evaluations
focused D5 tests: 68 passed
engine branch coverage: 90.66%
Python 3.11 non-integration: 980 passed in 60.61s
spec_lint: 23 documents, 98 enum values, PASS, zero warnings
```

The scan-plan factory uses bounded no-follow reads and independently extracts supported
Terraform/Kubernetes resource identities. The adapter still revalidates and copies the
same digest-bound inputs immediately before Checkov execution, so this attestation
reduces TOCTOU exposure without claiming native execution is a sandbox. Final suite,
specification, research-freeze, replay, and frozen-diff values are recorded at the D5.1
commit gate.

## D6.1 — Loader-attested policy and integrated exceptions (2026-08-11)

The old production boundary was exercised before modification. Literal results were:

```text
self-constructed ExceptionRecord(origin=TRUSTED_BASE): PolicyRequest accepted
self-declared RESOURCE_DELETED exception: policy_permitted true / VERIFIED
PolicyRequest fields controlled by caller: evaluation_date, exceptions,
  optional_gates, optional_gates_origin
production loader functions present: none
new D6.1 boundary probes: 4 failed
real D5 suppression flow before D5.1:
  target SUPPRESSED; policy_permitted true; suppression gate FAIL; verdict FAILED
```

After D6.1:

```text
PolicyRequest fields: verification, policy_bundle
raw ExceptionRecord/ExceptionPolicy/candidate policy: rejected as TrustedPolicyBundle
serialized origin=trusted_base through candidate loader: CANDIDATE_HEAD
base/protected-repository/operator loaders: loader-stamped trusted origin
evaluation date: UTC trusted_execution_clock; no request/payload date field
optional gates: loaded only from the trusted policy document
real D5 SUPPRESSED event + active exact trusted exception: VERIFIED
candidate/expired/not-yet-active/wrong-event/wrong-target: not permitted
loader-observed policy drift: FAILED with source, both digests, and governed path
applied exception: id plus exact loader source retained
strict policy JSON: duplicate keys, excessive depth, malformed shape rejected
focused D6 integration tests: 124 passed
policy branch coverage: 91.33%
Python 3.11 non-integration: 1018 passed in 60.62s
Python 3.12 clean warning-as-error import: PASS
Python 3.12 non-integration: 1018 passed in 62.03s
Python 3.10 local leg: BLOCKED (interpreter not installed)
Python 3.13 local leg: BLOCKED (interpreter not installed)
CI matrix retained: 3.10, 3.11, 3.12, 3.13
spec_lint: 23 documents, 102 enum values, PASS, zero warnings
manifest: 4842/4842 PASS
MANIFEST_ROOT computed/recorded:
  a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
replay: 630/630; 10080/10080 fields equal; 0 final-verdict mismatches
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff against qrs-2026-replication-v1: empty
```

Final full-suite, specification, research-freeze, replay, and frozen-scope values are
recorded at the D6.1 commit gate.

---

## Gate D3.2 — Conservative occurrence ambiguity and multi-domain matching

D3.2 started from clean parent
`f3f08afe16e0249b59c90d05bf86b849a53431b1`; D3.1 and D4.1 were not rewritten.
The matching, diffing, model, adapter-evidence boundary, D3 specifications, and existing
security tests were independently reread before modification. D5/D6 were not started.

Literal failing-before evidence on the parent implementation:

```text
reused-location matches: [('occ-B', 'occ-A', 'EXACT')]
reused-location ambiguities: 0
reused-location deltas: [('RESOLVED_FINDING', 'occ-A', None)]
mixed Terraform/Kubernetes: DomainError baseline contains multiple versions or scanner/artifact match domains
caller NEW_FINDING: ACCEPTED
focused regression: 5 failed, 5 passed
```

Literal passing-after evidence:

```text
reused-location matches: []
reused-location ambiguities: 1 MATCHING_INCONCLUSIVE
reused-location deltas: []
native retained pairing: [('occ-A', 'occ-A', 'EXACT')]
native deltas: ['LOCATION_CHANGED', 'RESOLVED_FINDING', 'SEVERITY_INCREASED', 'SUPPRESSION_ADDED']
mixed domains: 2 exact matches ['kubernetes_yaml', 'terraform_hcl']
one-sided kubernetes domain: canonical unmatched baseline evidence
scanner/version drift: REJECTED
caller NEW_FINDING: REJECTED complete trusted comparison context
caller ScannerRun/CheckovTargetEvidence: REJECTED caller-authored
input-order canonical equality: True
```

The three earlier dense-compaction tests remain present but now assert the stronger
D3.2 property: no-native multiplicity/cardinality churn is typed ambiguity rather than
an exact same-location pairing. No security test was deleted, skipped, or xfailed.

Executable gates:

```console
$ COVERAGE_FILE=$TMPDIR/iacgv-d32.coverage PYTHONPATH=src:tests/unit \
    pytest tests/unit/test_fingerprints.py tests/unit/test_matching.py \
    tests/unit/test_matching_d32.py tests/unit/test_diffing.py \
    --cov=iac_guard_v.fingerprints --cov=iac_guard_v.matching \
    --cov=iac_guard_v.diffing --cov-report=term-missing --cov-fail-under=90 -q
94 passed in 0.55s
src/iac_guard_v/diffing.py          190     16    92%
src/iac_guard_v/fingerprints.py      69      0   100%
src/iac_guard_v/matching.py         217     12    94%
TOTAL                               476     28    94%
Required test coverage of 90% reached. Total coverage: 94.12%

$ PYTHONPATH=src:tests/unit pytest tests -q
845 passed in 152.04s (0:02:32)

$ python3 tools/spec_lint.py docs/spec/
documents inspected:  23
enum values defined:  90
PASS
```

Research gates:

```text
manifest files checked: 4842/4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
manifest result: PASS
frozen run records: 630/630
field comparisons: 10080/10080 equal
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
```

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Gate D3.1 — Occurrence identity and trusted-delta closure

D3.1 started from clean parent
`b8c0cbaa41427dbf33fc74565726997cf4a3224b` after independently rereading finding
semantics §§3 and 5, architecture §13, product §14, ADR-0003, implementation, and tests.
The preserved D2.3, D3, and D4 commits were not rewritten.

Literal failing-before values on the parent commit:

```text
A matches [(10, 20, 'EXACT')] unmatched baseline [20]
B deltas [('LOCATION_CHANGED', 10, 20), ('RESOLVED_FINDING', 20, None)]
C deltas [('LOCATION_CHANGED', 10, 20), ('RESOLVED_FINDING', 20, None)]
forged LOCATION_CHANGED ACCEPTED
forged SEVERITY_INCREASED ACCEPTED
forged SUPPRESSION_ADDED ACCEPTED
cross scanner comparison: ordinary unmatched baseline plus unmatched candidate
cross version exact EXACT
cross artifact exact EXACT
```

The permanent regression tests failed on the preserved implementation: 18 failures and
62 passes in the initial focused run. The failed properties included display-ordinal
compaction, native occurrence binding, typed ambiguity, domain consistency, and each
forged-delta predicate.

Literal passing-after values:

```text
A matches [(20, 20, 'EXACT')] unmatched baseline [10]
B deltas [('RESOLVED_FINDING', 10, None), ('SEVERITY_INCREASED', 20, 20)]
C deltas [('RESOLVED_FINDING', 10, None), ('SUPPRESSION_ADDED', 20, 20)]
forged LOCATION_CHANGED REJECTED LOCATION_CHANGED requires different file/start/end location
forged SEVERITY_INCREASED REJECTED SEVERITY_INCREASED requires a strictly higher candidate severity
forged SUPPRESSION_ADDED REJECTED SUPPRESSION_ADDED requires an unsuppressed-to-suppressed transition
scope REJECTED SCOPE_EXPANDED requires complete resource-set evidence
scanner REJECTED FindingMatch requires one scanner/version/artifact match domain
version REJECTED FindingMatch requires one scanner/version/artifact match domain
artifact REJECTED FindingMatch requires one scanner/version/artifact match domain
```

The successor primary fingerprint is visibly versioned:

```text
old: iacgv1:103a16c9e7eb2ed6a76a8acb10a3cc6aefeb0e1e9693999c0d0e403cde508871
new: iacgv2:fe6442319649d2827b7334576a8eee3222bc466fe3d5fcad2546d96402b41b02
```

Focused executable evidence:

```console
$ PYTHONPATH=src pytest tests/unit/test_fingerprints.py \
    tests/unit/test_matching.py tests/unit/test_diffing.py \
    --cov=iac_guard_v.fingerprints --cov=iac_guard_v.matching \
    --cov=iac_guard_v.diffing --cov-report=term-missing --cov-fail-under=90 -q
83 passed in 0.39s
src/iac_guard_v/diffing.py          169     14    92%
src/iac_guard_v/fingerprints.py      69      0   100%
src/iac_guard_v/matching.py         187     11    94%
TOTAL                               425     25    94%
Required test coverage of 90% reached. Total coverage: 94.12%

$ PYTHONPATH=src pytest tests -q
810 passed in 71.32s (0:01:11)

$ python tools/spec_lint.py docs/spec/
documents inspected:  23
enum values defined:  75
PASS
```

Research gates at the D3.1 boundary:

```text
manifest files checked: 4842/4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
manifest result: PASS
frozen run records: 630/630
field comparisons: 10080/10080 equal
final verdict mismatches: 0
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
```

D3.1 modifies no frozen QRS artifact and performs no benchmark inference, model-provider
call, or model refresh.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

The third statement is now accurate: the model-refresh protocol is a Phase I
deliverable and has not been written. "Prepared but not executed" will only be correct
once Phase I actually creates it.

---

## Gate D2.2 — Execution Layer Hardening

### Test run

```console
$ PYTHONPATH=src python3 -m pytest tests -q
593 passed in ~57s
```

All 566 pre-existing tests continue to pass. 27 new tests in
`tests/unit/test_process_d22.py` verify each defect fix:

| Defect | Tests | Result |
| --- | --- | --- |
| A: Process group termination | 3 (leader exits/timeout/both ignore TERM) | PASS |
| B: Combined output cap | 1 (50k+50k under 65536) | PASS |
| C: Redaction in canonical_dict | 5 (token, path, detail, display_command, URLs) | PASS |
| D: Cleanup as typed gate | 2 (monkeypatched rmtree) | PASS |
| E: CommandResult consistency | 7 (each contradiction) | PASS |
| F: Stop inheriting parent PATH | 4 (attacker dir, minimal, helpers, blocked vars) | PASS |
| G: Mandatory workspace boundary | 2 (cwd rejected, scratch as default) | PASS |
| H: Resolved executable | 3 (populated, in canonical_dict, path redacted) | PASS |

### Files modified

- `src/iac_guard_v/process.py` — all execution-layer fixes
- `src/iac_guard_v/redaction.py` — option-value redaction, improved path patterns, display_command
- `tests/unit/test_process_d22.py` — 27 acceptance probes
- `tests/unit/test_process.py` — 2 existing tests adapted to new constraints
- `tests/unit/test_process_d21.py` — 1 existing test adapted to new consistency rule
- `docs/spec/ARCHITECTURE.md` — §11 D2.2 execution layer hardening
- `docs/spec/THREAT_MODEL.md` — §7 D2.2 threat mitigations
- `docs/spec/PRODUCT_SPEC.md` — §12 D2.2 specification
- `docs/spec/VALIDATION_LOG.md` — this entry
- `docs/spec/adr/ADR-0004-fail-closed-process-model.md` — D2.2 amendment

### Existing test compatibility

No tests were weakened, deleted, xfailed, or skipped. Three tests required minor
adjustments to match the new security constraints:
1. `test_display_command_is_for_reports_only` — updated assertion for shlex-quoted output
2. `test_the_working_directory_is_honoured` — added mandatory workspace_root parameter
3. `test_scratch_cleanup_field_exists_on_result` — uses ERROR status (PASS+cleanup=False is now rejected)

---

## Gate D2.3 — Process-boundary closure

Validated on branch `adoption/p2-hardened-core`, starting from
`eba9b73baebcac689b69500da8e178f2fdca0815`. The starting working tree was clean.

### D2.3.1 Literal failing-before and passing-after values

All “before” values below were captured against the untouched starting commit before an
implementation file was edited. All “after” values were captured from the D2.3 working
tree only after the corresponding regression test passed.

| Probe | Before (`eba9b73`) | After (D2.3) |
| --- | --- | --- |
| clean import, warnings as errors | `SyntaxError: "\\." is an invalid escape sequence` in `redaction.py` | Python 3.11, 3.12, and 3.14 each printed `PASS clean import` |
| custom sensitive option: display | `option display contains secret: True` | `option display contains secret: False` |
| custom sensitive option: canonical | `option canonical contains secret: True` | `option canonical contains secret: False` |
| sensitive argument index: display | `index display contains secret: True` | `index display contains secret: False` |
| sensitive argument index: canonical | `index canonical contains secret: True` | `index canonical contains secret: False` |
| malformed indices `('x',)`, `(-1,)`, `(999,)`, `(1, 1)`, `(True,)` | each `ACCEPTED` | each `REJECTED ProcessPolicyError` |
| malformed options `('',)`, `('token',)`, newline, NUL, bidi | each `ACCEPTED` | each `REJECTED ProcessPolicyError` |
| `/opt/company/secret/file.tf` | original remained `True` | `[PATH]`, original remained `False` |
| `/root/.aws/credentials` | original remained `True` | `[PATH]`, original remained `False` |
| `/workspace/repo/main.tf` | original remained `True` | `[PATH]`, original remained `False` |
| `C:/Users/Alice/secret.tf` | `C:[PATH]` (partial transformation) | `[PATH]`, original remained `False` |
| `C:\\Users\\Alice\\secret.tf` | `[PATH]` | `[PATH]` |
| absolute private executable in canonical argv | `canonical contains '/Users/person/private-venv/bin/checkov': True` | `False`; reported identity `checkov` |
| spawn failure plus cleanup failure | `ERROR SPAWN_FAILED`, `scratch_cleanup_success: None`, cleanup absent from canonical | `ERROR SPAWN_FAILED False ['SCRATCH_CLEANUP_FAILED']`; canonical has both events `True` |
| cleanup log path | `raw scratch path in logs: True` | `raw scratch path in canonical/logs: False` |
| `PARTIAL/OUTPUT_LIMIT_EXCEEDED/truncated=False` | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| `ERROR/OUTPUT_LIMIT_EXCEEDED/truncated=False` | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| `TIMEOUT` with unrelated reason | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| blank/control reason | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| signal 0, negative, or outside platform set | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| signal without matching negative exit | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| negative exit without matching signal | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| `PASS` without resolved executable | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| deadline reason under `ERROR` | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| group-cleanup reason without failed cleanup | `ACCEPTED` | `REJECTED ProcessPolicyError` |
| `PermissionError` during group probe | `False` (misreported absent) | `UNKNOWN` |
| timeout plus unconfirmed cleanup | `TIMEOUT DEADLINE_EXCEEDED` | `ERROR PROCESS_GROUP_CLEANUP_FAILED DEADLINE_EXCEEDED False` |
| truncation plus unconfirmed cleanup | `PARTIAL OUTPUT_LIMIT_EXCEEDED` | `ERROR PROCESS_GROUP_CLEANUP_FAILED OUTPUT_LIMIT_EXCEEDED False` |
| absolute workspace executable | `PASS WORKSPACE_EXECUTED` | `ProcessPolicyError before spawn` |
| cwd replaced by outside symlink | `PASS`, child cwd was the outside directory | `ProcessPolicyError before spawn` |
| helper replaced by workspace symlink | `PASS HELPER_REPLACED_INTO_WORKSPACE` | `ProcessPolicyError before spawn` |
| truncated byte evidence | only `stdout_bytes` / `stderr_bytes`; no hash-scope statement | `stdout_observed_bytes=5000`, `stdout_retained_bytes=1024`, `output_hashes_cover=retained_bytes_only` |

Python 3.13 is not installed on this validation host, so the required local 3.13 command
is **BLOCKED**, not passed. `.github/workflows/python-compat.yml` adds 3.10, 3.11, 3.12,
and 3.13 jobs; every job deletes `__pycache__`, imports with `-W error`, then runs the
suite. Local clean-bytecode imports passed under every installed relevant interpreter:

```console
== python3.11 ==
PASS clean import
== python3.12 ==
PASS clean import
== python3.14 ==
PASS clean import
```

### D2.3.2 Tests and mutation-sensitive probes

```console
$ PYTHONPATH=src pytest tests -q
660 passed in 58.65s
```

| Suite | Tests |
| --- | ---: |
| `tests/spec/test_semantics_truth_table.py` | 121 |
| `tests/spec/test_domain_boundaries.py` | 84 |
| `tests/spec/test_domain_immutability.py` | 62 |
| `tests/spec/test_event_binding.py` | 36 |
| `tests/unit/test_models_immutability.py` | 101 |
| `tests/unit/test_domain_consistency.py` | 38 |
| `tests/unit/test_process.py` | 46 |
| `tests/unit/test_process_d21.py` | 30 |
| `tests/unit/test_process_d22.py` | 27 |
| `tests/unit/test_process_d23.py` | 67 |
| `tests/research/test_qrs_regression.py` | 29 |
| `tests/research/test_freeze_adversarial.py` | 19 |
| **Total** | **660** |

The 67 D2.3 tests are additive; all 593 tests present at the starting commit still pass.
The D2.3 tests are mutation-sensitive at each material guard: they force custom metadata,
each path family, simultaneous spawn/cleanup exceptions, every forbidden result state,
`EPERM` and non-`ESRCH` inspection errors, typed cleanup failure overriding deadline and
output-limit events, candidate executable resolution, cwd/helper replacement, and output
overflow. Spawn-boundary tests patch `Popen` and assert it was never called; removing the
corresponding guard therefore turns the assertion into a failure rather than merely
changing an implementation detail.

### D2.3.3 Specification gate

```console
$ python tools/spec_lint.py docs/spec/
documents inspected:  23
enum values defined:  54
PASS

$ python tools/spec_lint.py --require-section trusted-configuration \
    docs/spec/VERIFICATION_SEMANTICS.md docs/spec/THREAT_MODEL.md
documents inspected:  2
enum values defined:  54
PASS
```

Zero warnings were emitted. `spec_lint` now includes the closed process-reason and
process-group-state families in its completeness gate.

### D2.3.4 Research invariants and frozen scope

```console
$ git cat-file -t qrs-2026-replication-v1
tag
$ git rev-parse qrs-2026-replication-v1^{commit}
7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5

$ python research/verify_byte_manifest.py \
    --manifest research/qrs2026-byte-manifest.jsonl --root . \
    --tag qrs-2026-replication-v1 --expect-entries 4842 --strict
files checked:          4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
PASS
```

Replay output:

```console
frozen run records:        630/630
committed rows matched:    True (630 rows, 0 unmatched)
field comparisons:         10080/10080 equal (expected 10080)
final_verdict_mismatches:   0
SEMANTIC_MATCH main_results_with_ci.csv
SEMANTIC_MATCH results_by_violation_class.csv
SEMANTIC_MATCH cost_effectiveness.csv
SEMANTIC_MATCH statistical_tests.csv
SEMANTIC_MATCH convergence.csv
SEMANTIC_MATCH difficulty_terraform.csv
SEMANTIC_MATCH difficulty_kubernetes.csv
PASS
```

Frozen-scope diff:

```console
$ git diff --stat qrs-2026-replication-v1 -- \
    benchmark runs results prompts scanners scripts requirements.txt paper.pdf
(no output)
```

No benchmark inference, provider call, model refresh, tag mutation, or frozen artifact
write was performed.

### D2.3.5 Changed-file inventory

- `.github/workflows/python-compat.yml`
- `docs/spec/ARCHITECTURE.md`
- `docs/spec/PRODUCT_SPEC.md`
- `docs/spec/THREAT_MODEL.md`
- `docs/spec/VALIDATION_LOG.md`
- `docs/spec/VERIFICATION_SEMANTICS.md`
- `docs/spec/adr/ADR-0004-fail-closed-process-model.md`
- `src/iac_guard_v/process.py`
- `src/iac_guard_v/redaction.py`
- `tests/unit/test_process.py`
- `tests/unit/test_process_d21.py`
- `tests/unit/test_process_d23.py`
- `tools/spec_lint.py`

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Gate D3 — Versioned fingerprints and multiset matching

D3 began only after D2.3 commit
`70739cb068211876b0264f91d046adc568e8046c` passed its mandatory gates. Before
implementation, verification semantics §§3 and 5, ADR-0003, architecture boundaries,
the domain model, and occurrence normalisation were reread.

Implemented evidence:

- golden `iacgv1` fingerprint:
  `iacgv1:103a16c9e7eb2ed6a76a8acb10a3cc6aefeb0e1e9693999c0d0e403cde508871`;
- line, message, severity, scanner-version, suppression-state, and temp-root changes keep
  that identity stable;
- scanner, rule, path, resource, occurrence, or artifact-kind changes alter it;
- exact matching precedes relocation; occurrences never collapse;
- a resource move is `NEW_FINDING` plus `RESOLVED_FINDING`, not relocation;
- forged fingerprints, duplicate exact keys, version drift, ambiguous relocation,
  collection subclasses, and engine-only delta claims are rejected.

Focused test and coverage output:

```console
$ PYTHONPATH=src pytest tests/unit/test_fingerprints.py \
    tests/unit/test_matching.py tests/unit/test_diffing.py \
    --cov=iac_guard_v.fingerprints --cov=iac_guard_v.matching \
    --cov=iac_guard_v.diffing --cov-report=term-missing --cov-fail-under=90 -q
64 passed in 0.19s
src/iac_guard_v/diffing.py           92      3    97%
src/iac_guard_v/fingerprints.py      69      0   100%
src/iac_guard_v/matching.py         131      1    99%
TOTAL                               292      4    99%
Required test coverage of 90% reached. Total coverage: 98.63%
```

Complete suite:

```console
$ PYTHONPATH=src pytest tests -q
724 passed in 58.88s
```

D3 adds 64 tests; the 660 tests at the D2.3 commit remain green.

---

## Gate D4 — Checkov-only adapter / Review 2

D4 began only after D3 commit
`8be0c7886554cee964a66f30545261b1ff271f36`. The Checkov contract, V5 integrity
semantics, threat model, architecture adapter boundary, ADR-0002, ADR-0010, and
ADR-0013 were reread before implementation. No Trivy implementation was started.

### D4.1 Literal failing-before evidence

The D3 commit had no adapter package:

```console
$ PYTHONPATH=src python -W error -c 'import iac_guard_v.adapters.checkov'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'iac_guard_v.adapters'
```

A live Checkov 3.3.0 mutation probe then established that private cwd plus an explicit
trusted config was insufficient. With candidate `.checkov.yml` containing
`skip-check: CKV_AWS_23`, direct `-d <candidate>` output contained:

```text
finding rule ids: {'CKV_AWS_24'}
CKV_AWS_23 present: False
```

Checkov merges default config discovered below `-d`. After switching to the private
eligible-file view, the identical candidate mutation produces:

```text
finding rule ids include: {'CKV_AWS_23', 'CKV_AWS_24'}
CKV_AWS_23 present: True
```

### D4.2 Executable contract evidence

- the twelve common scanner shapes and Checkov summary-only shape are automated;
- object and multi-framework-list JSON are both consumed completely;
- research 3.2.517 and product 3.3.0 parser fixtures pass;
- installed product Checkov 3.3.0 passes live Terraform and Kubernetes scans;
- candidate config/custom-check inputs are absent, and the live skip-check mutation is
  inert;
- the resolved launcher version and digest are revalidated before use;
- raw JSON is a single bounded nonsymlink file with its own digest;
- suppressions remain findings with `suppressed=True`;
- malformed structures, partial coverage, timeout/signal/truncation, unsupported or
  mismatched versions, path replacement, check-inventory mismatch, and cleanup failure
  remain non-`PASS`.

Focused suite and executable coverage:

```console
$ PYTHONPATH=src pytest tests/unit/test_checkov_adapter.py -q
65 passed in 0.27s

$ PYTHONPATH=src pytest tests/unit/test_checkov_adapter.py \
    --cov=iac_guard_v.adapters.base --cov=iac_guard_v.adapters.checkov \
    --cov-report=term-missing --cov-fail-under=90 -q
src/iac_guard_v/adapters/base.py         51      0   100%
src/iac_guard_v/adapters/checkov.py     492     44    91%
TOTAL                                   543     44    92%
Required test coverage of 90% reached. Total coverage: 91.90%
65 passed in 0.34s

$ PYTHONPATH=src pytest tests/integration/test_checkov_integration.py -q
2 passed in 13.66s
```

The current non-integration total is 789 tests (724 at D3 plus 65 D4 contract tests).
The separate pinned integration suite adds two live checks. A current executable
integration for research Checkov 3.2.517 is **BLOCKED/deferred to Phase E**; D4 does not
claim it as a supported native product path.

```console
$ PYTHONPATH=src pytest tests -q
791 passed in 69.95s (0:01:09)
```

No benchmark tree, frozen scanner output, model provider, Trivy executable, or model
refresh path was invoked by D4.

### D4.3 Review 2 research and specification gates

```console
$ python tools/spec_lint.py docs/spec/
documents inspected:  23
enum values defined:  74
PASS

$ python research/verify_byte_manifest.py \
    --manifest research/qrs2026-byte-manifest.jsonl --root . \
    --tag qrs-2026-replication-v1 --expect-entries 4842 --strict
files checked:          4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
PASS
```

Replay remained 630/630 frozen records, 10,080/10,080 field comparisons, zero verdict
mismatches, and seven of seven `SEMANTIC_MATCH` tables. The frozen-scope diff against
`qrs-2026-replication-v1` was empty; the tag still resolves to annotated tag object and
commit `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5`.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

### D4.4 Changed-file inventory

- `.github/workflows/python-compat.yml`
- `docs/spec/ARCHITECTURE.md`
- `docs/spec/PRODUCT_SPEC.md`
- `docs/spec/SCANNER_CONTRACTS.md`
- `docs/spec/THREAT_MODEL.md`
- `docs/spec/VALIDATION_LOG.md`
- `docs/spec/VERIFICATION_SEMANTICS.md`
- `docs/spec/adr/ADR-0002-scanner-agnostic-core.md`
- `docs/spec/adr/ADR-0010-version-lock.md`
- `docs/spec/adr/ADR-0013-trusted-policy-source.md`
- `src/iac_guard_v/__init__.py`
- `src/iac_guard_v/models.py`
- `src/iac_guard_v/adapters/__init__.py`
- `src/iac_guard_v/adapters/base.py`
- `src/iac_guard_v/adapters/checkov.py`
- `tests/integration/test_checkov_integration.py`
- `tests/unit/test_checkov_adapter.py`
- `tools/spec_lint.py`

---

## Gate D4.1 — Affirmative Checkov evidence and coverage closure

D4.1 started only after standalone D3.1 commit
`f3f0581b88ced473f5e1a6d9f017c15b06c83fd7`. Checkov contracts, V5, target
semantics, architecture, threat model, adapter ADRs, implementation, fixtures, and live
tests were reread before modification. D5/D6 were not started.

Literal failing-before values on the D3.1 parent:

```text
race inode retained True view bytes CHANGED-IN-PLACE
two files one evidence PASS 2 2 ('COMPLETED',)
aggregate target absence PASS findings 0 checks_loaded 7
failed bucket PASSED native PASS ('COMPLETED',)
duplicate results malicious-first PASS ('COMPLETED',) findings 0
same ruleset eval count 1 PASS eval count 2 ERROR ('CHECK_INVENTORY_MISMATCH',)
machine scan argv contained --quiet: True
report identity represented launcher only as executable_or_image_digest
```

The dedicated permanent D4.1 suite initially produced `16 failed in 0.23s`. Its
failures covered byte replacement, absent byte bindings, invented file coverage,
aggregate-only pass, missing positive evaluations, target absence/unknown states,
suppression evidence, bucket contradictions, duplicate keys, unknown buckets, false
ruleset inventory terminology, collapsed identities, quiet output, and untyped scan-view
failure.

Literal passing-after values:

```text
race ERROR ('INPUT_CHANGED_DURING_SCAN_PREPARATION',) inode retained True spawn calls 0
coverage PARTIAL 1 2 ('COVERAGE_MISMATCH', 'missing evaluation file: other.tf')
aggregate PARTIAL 7 0 ('AGGREGATE_ONLY_EVIDENCE', 'COVERAGE_MISMATCH', 'missing evaluation file: main.tf')
bucket contradiction ERROR ('INVALID_RESULTS_STRUCTURE',)
duplicate keys ERROR ('INVALID_RESULTS_STRUCTURE',)
same policy PASS 1 PASS 2 True
affirmative PASS AFFIRMATIVE_TARGET_PASS
absent INCONCLUSIVE RESOURCE_NOT_OBSERVED
unknown INCONCLUSIVE TARGET_EVALUATION_UNKNOWN
machine scan argv contained --quiet: False
```

The request now records each input's path/type/size/SHA-256 and secondary device/inode,
and the final `ScannerRun` retains those records. Checkov results retain native passed,
failed, skipped, and supported unknown evaluations. Installed non-policy environment and
policy/check tree manifests are hashed separately from the launcher and invocation.

Focused unit and coverage evidence:

```console
$ PYTHONPATH=src:tests/unit pytest tests/unit/test_checkov_adapter.py \
    tests/unit/test_checkov_adapter_d41.py \
    --cov=iac_guard_v.adapters.base --cov=iac_guard_v.adapters.checkov \
    --cov-report=term-missing --cov-fail-under=90 -q
84 passed in 1.02s
src/iac_guard_v/adapters/base.py         57      0   100%
src/iac_guard_v/adapters/checkov.py     721     68    91%
TOTAL                                   778     68    91%
Required test coverage of 90% reached. Total coverage: 91.26%

$ PYTHONPATH=src pytest tests/integration/test_checkov_integration.py -q
5 passed in 57.35s

$ PYTHONPATH=src:tests/unit pytest tests -q
834 passed in 141.76s (0:02:21)

$ python tools/spec_lint.py docs/spec/
documents inspected:  23
enum values defined:  90
PASS
```

The five live Checkov 3.3.0 tests cover Terraform affirmative pass plus absent
rule/resource target evidence, Kubernetes affirmative pass, inline suppression, two
eligible files with one lacking native evaluation, in-place byte replacement, and inert
candidate `.checkov.yml`. The 3.2.517 parser fixture remains; no native 3.2.517
integration is claimed.

Research and freeze gates:

```text
manifest files checked: 4842/4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
manifest result: PASS
frozen run records: 630/630
field comparisons: 10080/10080 equal
final verdict mismatches: 0
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
tag type: tag
tag commit: 7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5
```

No benchmark inference, model-provider call, Trivy implementation, D5/D6 work, or model
refresh was performed.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```

---

## Gate D4.2 — Resource coverage and evidence-consistency closure

D4.2 started from standalone D3.2 commit
`c8f814d8c6fd3d85dea06ac316c7d8d7eafa1a70`. The named D4 specifications,
ADRs, request/model boundaries, normalizer, scan-view preparation, and all existing
adapter tests were reread before modification. D5/D6 were not started.

Literal failing-before evidence on the D3.2 parent:

```text
summary resource_count=2, observed resources=1 -> PASS ('COMPLETED',)
summary resource_count=1, observed resources=2 -> PASS ('COMPLETED',)
same evaluation PASSED+FAILED -> PASS ('COMPLETED',)
policy inventory mismatch -> ERROR ('POLICY_INVENTORY_MISMATCH',) ruleset_integrity PASS
portable input keys -> ['device', 'file_path', 'file_type', 'inode', 'sha256', 'size']
empty eligible scope -> PASS ('NO_RESULTS_STRUCTURE',)
deep JSON -> raw RecursionError
focused regression -> 7 failed
```

Literal passing-after evidence:

```text
summary resource_count=2, observed resources=1 -> PARTIAL ('RESOURCE_COUNT_MISMATCH', ...)
summary resource_count=1, observed resources=2 -> ERROR ('INVALID_RESULTS_STRUCTURE',)
same evaluation PASSED+FAILED -> ERROR ('CONTRADICTORY_EVALUATION_EVIDENCE',)
missing expected resource -> PARTIAL ('COVERAGE_MISMATCH', ...)
unexpected observed resource -> PARTIAL ('COVERAGE_MISMATCH', ...)
nonempty scan without expected inventory -> PARTIAL ('RESOURCE_INVENTORY_MISSING', ...)
policy inventory mismatch -> ERROR ('POLICY_INVENTORY_MISMATCH',) ruleset_integrity FAIL
scanner environment mismatch -> ERROR ('SCANNER_ENVIRONMENT_MISMATCH',) ruleset_integrity FAIL
version mismatch -> ERROR ('VERSION_MISMATCH',) ruleset_integrity INCONCLUSIVE
portable input keys -> ['file_path', 'file_type', 'sha256', 'size']
different runtime device/inode canonical equality -> True
empty eligible scope -> SKIPPED ('EMPTY_ELIGIBLE_SCOPE',) spawn calls 0
file-count cap -> INPUT_FILE_COUNT_EXCEEDED before spawn
per-file cap -> INPUT_FILE_BYTES_EXCEEDED before spawn
total cap -> INPUT_TOTAL_BYTES_EXCEEDED before spawn
deep JSON -> ERROR ('MALFORMED_JSON',)
```

Scan-view preparation now streams bounded no-follow descriptor bytes directly to the
private view and verifies the copied digest; it does not join an unbounded eligible file
in memory. Input limits are included in `invocation_config_digest`. File and resource
coverage remain separate typed evidence.

Executable gates:

```console
$ COVERAGE_FILE=$TMPDIR/iacgv-d42.coverage PYTHONPATH=src:tests/unit \
    pytest tests/unit/test_checkov_adapter.py tests/unit/test_checkov_adapter_d41.py \
    tests/unit/test_checkov_adapter_d42.py --cov=iac_guard_v.adapters.base \
    --cov=iac_guard_v.adapters.checkov --cov-report=term-missing \
    --cov-fail-under=90 -q
103 passed in 1.71s
src/iac_guard_v/adapters/base.py         64      0   100%
src/iac_guard_v/adapters/checkov.py     807     84    90%
TOTAL                                   871     84    90%
Required test coverage of 90% reached. Total coverage: 90.36%

$ PYTHONPATH=src pytest tests/integration/test_checkov_integration.py -q
5 passed in 81.74s (0:01:21)

$ PYTHONPATH=src:tests/unit pytest tests -q
866 passed in 151.06s (0:02:31)

$ python3 tools/spec_lint.py docs/spec/
documents inspected:  23
enum values defined:  97
PASS
```

Research gates:

```text
manifest files checked: 4842/4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
manifest result: PASS
frozen run records: 630/630
field comparisons: 10080/10080 equal
derived tables: 7/7 SEMANTIC_MATCH
frozen-scope diff: empty
```

No benchmark inference, model-provider call, Trivy implementation, or model refresh was
performed.

```text
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```
## 2026-08-12 — D7.4 complete evidence-graph reconstruction

Failing-before probes against `69ce2e3` returned these literal old values:

- protected `severity_floor`, framework, source, and policy-authorization mutations:
  `validate_report_payload = ACCEPTED` with unchanged `config_sha256`;
- candidate critical-severity finding with unchanged diff/regression:
  `regression = PASS`, public validation `ACCEPTED`;
- `DESTRUCTIVE_CHANGE PASS` with affected paths and governed drift reported as
  stable: public validation `ACCEPTED`;
- a permitted decision without its exact applied exception source: public validation
  `ACCEPTED`;
- a `PASS` scanner run carrying an adverse diagnostic: public validation `ACCEPTED`;
- private test registry provenance: `iac-guard explain = VERIFIED`.

Passing-after values are: every mutation raises `DomainError`; the candidate critical
finding makes `iac-guard explain` return exit `2`; exact public-registry evidence remains
accepted; and private test registry provenance returns exit `2`. The permanent D7.4
regression suite records `51 passed`. The complete public-boundary suite under a clean
Python 3.13 declared-dependency environment records `174 passed` and 90.55% combined
branch-aware coverage.

## 2026-08-12 — D7.5 derived targets and snapshot/artifact provenance

Failing-before probes against `5b29d702` returned these literal old values:

- `SUPPRESSED` plus trusted exception with only `PASSED` native evaluation:
  public validation `ACCEPTED`;
- `RESOURCE_DELETED` while the exact resource remained in the candidate snapshot:
  public validation `ACCEPTED`;
- `FILE_DELETED_OR_RENAMED` while the exact candidate file remained:
  public validation `ACCEPTED`;
- identical baseline/candidate snapshot SHA values with failed-versus-passed scanner
  evidence: public validation `ACCEPTED`;
- supported FIFO `evil.tf` omitted from classifications with preflight `PASS`: public
  validation `ACCEPTED`;
- private-test provenance disguised by changing only the registry id: public
  validation `ACCEPTED`;
- installed-distribution, dependency-lock, and custom-check child hashes changed under
  an unchanged scanner-environment digest: public validation `ACCEPTED`.

Passing-after values are: every forged report raises `DomainError`; role-identical
differential scan plans are rejected; every rejected supported entry is bound into the
snapshot graph and prevents preflight `PASS`; and scanner-environment child evidence
recomputes one canonical aggregate digest. The permanent D7.5 focused regression file
records `20 passed`; the combined D7.4/D7.5 regression set records `71 passed`. The
complete D7 public-boundary suite in a clean Python 3.11 wheel environment records
`194 passed` and 91.22% combined branch-aware coverage. The complete non-integration
suite in that environment records `1489 passed`.
## 2026-08-12 — E1E2.3 protected container-runtime authority

KICS and Trivy requests no longer accept `docker_executable`. A portable protected
Phase-E evidence bundle replaces source-relative `__file__` discovery, and an opaque
runtime capability binds the no-follow Docker client digest to live client/server,
daemon, context, platform, architecture, isolation-control, and protected execution
identities. The runtime is revalidated immediately before spawn. Permanent probes
reject fake KICS/Trivy-producing executables, binary and context drift, and local-path
dependence; 183 focused adapter/runtime/boundary tests passed.

## 2026-08-12 — E1.3 KICS evidence coherence

Permanent probes now reject retained LOW evidence paired with HIGH counters/exit,
native paths outside `/iacgv-input`, BOM queries outside `queries_total`, duplicate
ordinary/BOM query IDs, and unknown issue types. Compact/pretty JSON has distinct raw
and physical identities but one semantic identity. The exact E0.3 KICS integration
passed after the contract update.

## 2026-08-12 — E2.3 Trivy locked integration and provenance

The retained cache passed its signed E0.3 physical inventory with protected manifest
root `cb53a2f9ac0e2648418e72e37fffa1aa972315f14545c814542809410c115e74`
and Trivy subtree root
`df87dc55b37a550d45d5591b6c974bbc681bb6798eacabf9bcb45a52632f405e`.
Both exact locked Trivy integrations passed. Canonical evidence now records protected
runtime/image/invocation identities, signed cache and attestation identities, full and
subtree pre/post roots, derived external/nonfallback evidence, raw stdout/stderr/results
hashes, canonical semantic output, and the physical output-directory manifest.

## 2026-08-12 — E3 authorization checkpoint and E3.1 validators

The checkpoint used a pristine detached clone at `14d0978b903259a99fd37155d7a4c3cbeb1505e2`.
The 175 focused probes and three exact locked KICS/Trivy integrations passed. Wheel and
sdist contained no test capability; an installed wheel loaded external protected
evidence. Python 3.10–3.13 each recorded `1682 passed`. Spec lint, 4,842-file manifest,
630/630 replay, 10,080/10,080 fields, and 7/7 tables passed.

E3.1 adds distinct locked OpenTofu 1.12.5 and protected user-supplied Terraform 1.15.8
validation. Focused probes cover valid, invalid, `NEEDS_INIT`, malformed/duplicate JSON,
timeout, diagnostic contradiction, transient-state rejection, mutation, and trust. Both
exact arm64 integrations returned `PASS/COMPLETED` for a self-contained module.

## 2026-08-12 — E3.2 pinned offline kubeconform validation

The E0.3 protected cache authenticated 1,304 strict schema files totaling 56,498,213
bytes under tree root `0c8bd99e642e35c975be957a7520cd29977446711aed9c56f8c099bb4a1abbc5`.
The exact locked kubeconform 0.8.0 integration validated a sealed Pod without network
access. Permanent tests cover YAML, JSON, multiple documents, `List`, definite invalidity,
baseline uncertainty, missing schemas, protected/unprotected CRDs, schema mutation,
malformed and duplicate JSON, exact resource coverage, native ordering, runtime/input
mutation, hardened argv, and the private trusted-evidence boundary. The schema licence
remains `NOASSERTION`; no public redistribution occurred.

## 2026-08-12 — E3.3 optional TFLint and shared trust boundary

The exact locked TFLint 0.64.0 arm64 integration completed offline with the closed
built-in-rules configuration. Permanent probes cover ordinary diagnostics, clean
results, plugin initialization, candidate-config rejection, malformed and duplicate
JSON, timeout, exit contradictions, input/runtime mutation, extra output entries,
native-order determinism, and advisory-only semantics. The shared registry rejects
callbacks, wrong request types, tool/gate substitution, and mismatched returned evidence.
Focused branch-aware coverage recorded 96% for `tflint.py` and 91% for `registry.py`.

## 2026-08-13 — E3.4 sealed validator materialization

Failing-before probes accepted external parent-directory links in all three E3
validators and allowed a one-shot partial write to place fewer bytes in the private
view than the evidence described. The shared no-follow subsystem now rejects
external, internal, broken, and cyclic parent links, detects parent replacement,
retries partial/EINTR writes, rejects zero progress, and verifies destination bytes.
The materialized-view identity is present in canonical validator and invocation
evidence. The focused E3.4 and preserved E3 test set recorded 105 passing tests.

## 2026-08-13 — E3.5 exact module and kubeconform coverage

Failing-before probes reported root and nested Terraform/TFLint files validated by one
nonrecursive root invocation and converted kubeconform `resources=[]` plus `valid=2`
into exact two-resource PASS. The new module plan rejects mixed directories and runs a
sole nested module at its exact path. Kubeconform now uses verbose output and requires
one-to-one native identity and status reconciliation; aggregate-only output is
`AFFIRMATIVE_RESOURCE_COVERAGE_UNAVAILABLE`. The preserved E3/E3.4 set plus permanent
E3.5 probes recorded 110 passing tests.

## 2026-08-13 — E3.6 complete validator implementation provenance

The old selected-module registry digest remained unchanged when shared validator code
changed. The new product/build and shared-code manifests bind validator base semantics,
sealed materialization, process execution, Phase-E runtime/lock verification, artifact
discovery, leaf parsers, physical parser dependency code, and schema contracts.
Permanent source-evidence mutations across all required helper classes, plus a parser
distribution identity mutation, change the registry identity. Registry-focused tests
recorded 46 passes. The combined E3.1–E3.6 focused set recorded 129 passes with
branch-aware coverage of 91% Terraform/OpenTofu, 91% kubeconform, 95% TFLint, and
90% registry before the final matrix.

## 2026-08-13 — E3.7 Linux-readable immutable views

The old materializer produced host-owner-only `0700` directories and `0400` files for
containers fixed to UID/GID 65532. The v2 materialization contract uses `0555` mounted
directories, `0444` inputs/configuration, and a checked `0733` output directory while
retaining a private outer workspace. Permanent tests prove the POSIX other-read/traverse
bits, absence of every write bit on trusted files, exact mode revalidation, and
post-execution checks across all three validators. The focused preserved set records
131 passes.

## 2026-08-13 — E3.8 complete validation scopes

Failing-before probes allowed an ordinary request to omit `bad.tf`, add `late.tf`, or
add a late Kubernetes YAML file while the selected subset still returned PASS. The
trusted scope factory now proves exact module membership or the complete independently
classified Kubernetes universe. Each validator re-derives that universe before and
after execution. Permanent probes reject omitted Terraform/TFLint siblings and type
late Terraform or Kubernetes additions as `SNAPSHOT_CHANGED_DURING_VALIDATION`.

## 2026-08-13 — E3.9 kubeconform and registry runtime closure

The old kubeconform parser accepted `statusValid` alongside native validation errors
and mapped `/totally-other/manifest.yaml` by suffix to the sealed input. Permanent
probes now return `DIAGNOSTIC_CONTRADICTION` and `INCOMPLETE_COVERAGE`, respectively.
The registry's writable-environment bytecode failure is now a canonical integrity
state instead of an unexpected construction exception. It refuses authoritative
execution while inconclusive, checks for caches before and after calls, and exposes
pre-start `PYTHONDONTWRITEBYTECODE=1` remediation through doctor. A clean installed
wheel is invoked twice under that package contract without generating cache entries.

## 2026-08-13 — E5.1 protected deterministic oracles

The first oracle implementation is deliberately closed and narrow. Two bundled
Kubernetes structural assertions consume exact resource bytes from a role-bound sealed
snapshot. Tests cover positive and negative predicates, missing or unknown protected
policy, unbound targets, caller-authored result rejection, deterministic identities,
and wheel inclusion of the policy bytes. No scanner-agreement input or verdict
aggregation was added.

## 2026-08-13 — E5.2 complete repository validation universe

The selected-module validators are now orchestrated by a private-factory universe
derived from the complete role-bound snapshot. Permanent probes cover multiple module
directories, missing module evidence, conservative FAIL/INCONCLUSIVE aggregation, late
Terraform modules, late Kubernetes JSON, unforgeable plan provenance, and explicit
Terraform JSON uncertainty. The orchestrator revalidates the complete relevant
physical inventory around each execution; TFLint remains advisory and no V7 or final
policy behavior was added.

The final declared-dependency matrix recorded `1871 passed` independently on Python
3.10, 3.11, 3.12, and 3.13 with bytecode disabled before interpreter startup. Focused
branch coverage was 99% for both the validation-universe and protected-oracle modules.
The exact arm64 locked integration set recorded 14 passes and one macOS skip for the
native-Linux UID/bind-mount portability probe; the six Checkov 3.3.0 cases ran from a
fresh bytecode-free wheel installation. Specification lint reported 26 documents and
164 enum values with zero warnings. The frozen manifest remained 4,842/4,842 at root
`a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`; replay remained
630/630 and 10,080/10,080 with zero verdict mismatches; all seven derived tables were
`SEMANTIC_MATCH`; and the frozen-scope diff was empty.

## 2026-08-13 — E4.1 source-attested advisory catalog

The catalog retains zero `EXACT` mappings. Its v2 contract binds the three reviewed
upstream repositories, exact release tag-to-commit relations, six commit-pinned source
URLs and file digests, and an 18-cell protected scanner/fixture execution matrix.
Online source verification re-resolved all three official tag refs and all six source
files. Runtime errors from the strict KICS init-container and Trivy Kubernetes contracts
remain visible as `ERROR`; they are not converted into scanner agreement.

## 2026-08-13 — E5.3 protected oracle semantic closure

Failing-before probes showed that ephemeral containers were omitted, malformed Boolean
fields could be coerced to safe values, Windows Pods were treated as Linux violations,
duplicate container paths could escape as an exception, a caller-visible factory could
mint trusted empty-observation PASS evidence, and helper changes did not alter the
implementation identity. The v2 closed registry covers all three Kubernetes container
classes, enforces exact field types, types Windows non-applicability and ambiguous
identity, requires affirmative PASS observations, and owns the only trusted-result
construction path. Its implementation identity binds all oracle helpers, models,
loaders, parser dependency bytes, registry code, and policy bytes. The focused permanent
probe set records 21 passes.

## 2026-08-13 — E5.4 validation-universe evidence closure

Failing-before probes constructed internally marked module and kubeconform `PASS`
records with zero validated files/resources, baseline role, or unrelated scope hashes;
the E5.2 aggregator accepted them. The v2 universe plan now proves its repository,
subpath, artifact, physical-inventory, module, and Kubernetes contents directly against
the sealed snapshot. Both aggregation and the immutable result reconcile exact child
validator/tool/role/scope identities, sealed inputs, coverage counts, resources, and
closed status/reason pairs. The focused permanent set records 19 passes, including
missing/duplicate module, wrong-role, fake-snapshot, zero-coverage, and resource-set
mutations.

The final declared-dependency non-integration matrix recorded `1927 passed` on each of
Python 3.10, 3.11, 3.12, and 3.13 with bytecode disabled before interpreter startup.
Focused branch coverage was 95% for the source-attested catalog checker, 94% for the
protected-oracle modules, and 93% for validation-universe orchestration. The exact
locked integration set recorded 14 passes and the expected macOS skip for the
native-Linux UID/bind-mount portability probe. Specification lint inspected 26 documents
and 164 enum values with zero warnings. The frozen manifest remained 4,842/4,842 at
root `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`;
replay remained 630/630 and 10,080/10,080 with zero verdict mismatches; all seven
derived tables were `SEMANTIC_MATCH`; and the frozen-scope diff was empty.
