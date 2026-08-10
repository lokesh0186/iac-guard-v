# Validation Log

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
445 passed
```

### Test counts of record

| Suite | Count |
| --- | --- |
| `tests/spec/test_semantics_truth_table.py` | 121 |
| `tests/spec/test_domain_boundaries.py` | 84 |
| `tests/spec/test_domain_immutability.py` | 62 |
| `tests/spec/test_event_binding.py` | 36 |
| `tests/unit/test_models_immutability.py` | 94 |
| `tests/research/test_qrs_regression.py` | 29 |
| `tests/research/test_freeze_adversarial.py` | 19 |
| **total** | **445** |

Progression across review rounds, so the record shows what each one added: 24 at the
first freeze commit, 76 after the first adversarial remediation, 108 after the
semantic-consistency commit, 169 after the exception-scoping commit, 243 after the D0
boundary-hardening commit, 299 after D0.1, 305 after the identifier-hazard follow-up, and
445 after the D1 domain-closure commit. Only the current figures are the gate result.

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

The third statement is now accurate: the model-refresh protocol is a Phase I
deliverable and has not been written. "Prepared but not executed" will only be correct
once Phase I actually creates it.
