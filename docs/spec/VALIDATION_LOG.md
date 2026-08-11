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
$ COVERAGE_FILE=/private/tmp/iacgv-d32.coverage PYTHONPATH=src:tests/unit \
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
$ COVERAGE_FILE=/private/tmp/iacgv-d42.coverage PYTHONPATH=src:tests/unit \
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
