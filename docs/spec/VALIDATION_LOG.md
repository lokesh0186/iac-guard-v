# Validation Log

Unedited command output for every gate in the adoption programme. Paths are
repository-relative or use `$REPO_ROOT` / `$TEMP_ROOT`; absolute local paths,
usernames, and hostnames are never recorded here.

Conventions:
- Commands are shown exactly as run, from `$REPO_ROOT`.
- Output is pasted unedited except for path substitution noted above.
- A gate is only "passed" when its recorded output says so.

---

## Environment of record

| Item | Value |
| --- | --- |
| Audited commit | `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5` |
| Branch | `adoption/p1-research-and-spec` |
| Python | 3.11.5 |
| git | 2.50.1 |
| Docker | 29.6.2 (present; not used in Phases A–C) |
| checkov available locally | 3.3.0 — **differs from the research pin 3.2.517** |
| trivy / conftest available | 0.71.1 / OPA 1.15.2 (not used in Phases A–C) |
| Not installed | kics, tflint, terraform, tofu, kubeconform, gh, pipx, uv |

Phases A–C perform no scanner execution and no model calls.

---

## Gate A — workspace and audit

### A.1 Branch

```console
$ test "$(git rev-parse --abbrev-ref HEAD)" = "adoption/p1-research-and-spec" && echo OK
OK
```

### A.2 Audit citations

```console
$ python3 tools/check_audit_citations.py docs/spec/CURRENT_STATE_AUDIT.md --min 15
distinct valid citations: 34 (minimum 15)
  OK  README.md:220
  OK  README.md:23
  OK  README.md:57
  OK  README.md:92
  OK  docs/VERIFICATION_PROCEDURE.md:15
  OK  docs/VERIFICATION_PROCEDURE.md:22
  OK  requirements.txt:4
  OK  requirements.txt:5
  OK  scripts/analyze_part1.py:13
  OK  scripts/analyze_part1.py:65
  OK  scripts/call_bedrock.py:12
  OK  scripts/call_bedrock.py:25
  OK  scripts/call_bedrock.py:28
  OK  scripts/call_bedrock.py:38
  OK  scripts/call_bedrock.py:62
  OK  scripts/run_baseline_checkov.py:38
  OK  scripts/run_experiment.py:132
  OK  scripts/run_experiment.py:172
  OK  scripts/run_experiment.py:26
  OK  scripts/run_experiment.py:34
  OK  scripts/run_k8s_baseline.py:26
  OK  scripts/verify_patch.py:16
  OK  scripts/verify_patch.py:161
  OK  scripts/verify_patch.py:164
  OK  scripts/verify_patch.py:25
  OK  scripts/verify_patch.py:27
  OK  scripts/verify_patch.py:41
  OK  scripts/verify_patch.py:57
  OK  scripts/verify_patch.py:66
  OK  scripts/verify_patch.py:80
  OK  scripts/verify_patch.py:82
  OK  scripts/verify_patch.py:90
  OK  scripts/verify_patch.py:93
  OK  scripts/verify_patch.py:95
PASS
```

### A.3 Semantic spot-check of quoted lines

```console
$ sed -n '15p;22p' docs/VERIFICATION_PROCEDURE.md
- A verified fix `A'` — a repaired artifact that passes all three binary gates (V1, V2, V3), or
Run Checkov on the original artifact `A` and record the set of failed rule IDs as `B`. This baseline is the reference point for V3 (regression detection): any rule that appears in `B'` (the repaired file's failed rules) but not in `B` is a regression.

$ sed -n '161,165p' scripts/verify_patch.py
    results['overall_verified_fix'] = (
        results['v1_syntax_valid']
        and results['v2_target_resolved']
        and results['v3_new_issues_count'] == 0
    )

$ sed -n '220p' README.md
- **Single scanner**: Results are Checkov-specific; multi-scanner consensus untested.
```

**Gate A: PASS.**

---

## Gate B — research freeze and reproduction lock

All Gate B and Gate C output below was produced from a **clean checkout** — a fresh
non-local clone of the branch at commit `af47894`, `0` modified files — so nothing
depends on the working tree used during development.

### B.1 Freeze tag (mutually exclusive paths, non-destructive)

No signing key is configured on this machine, so the unsigned annotated path ran.

```console
$ TAG=qrs-2026-replication-v1
$ COMMIT=7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5
$ if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
>   echo "TAG_EXISTS: verifying only, not modifying"
>   test "$(git cat-file -t "$TAG")" = "tag"
>   test "$(git rev-parse "$TAG^{commit}")" = "$COMMIT"
> elif git tag -s "$TAG" "$COMMIT" -m "Frozen QRS 2026 replication snapshot"; then
>   git tag -v "$TAG"
> else
>   git tag -a "$TAG" "$COMMIT" -m "Frozen QRS 2026 replication snapshot ..."
>   test "$(git cat-file -t "$TAG")" = "tag"
>   test "$(git rev-parse "$TAG^{commit}")" = "$COMMIT"
> fi
no signing key available -> unsigned annotated tag
  type: tag OK
  peels to expected commit OK
tag qrs-2026-replication-v1
Tagger: lokesh0186 <lokesh0186@gmail.com>
Date:   Sun Aug 9 13:18:09 2026 -0500

Frozen QRS 2026 replication snapshot
```

`git tag -v` on this tag fails, as documented — it verifies signatures, not existence:

```console
$ git tag -v qrs-2026-replication-v1
error: no signature found
exit=1
```

The tag exists **locally only** and is not pushed, pending the ADR-0011 decision.

```console
$ git ls-remote --tags origin
(no output)
```

### B.2 Byte freeze — no normalisation

```console
$ python3 research/verify_byte_manifest.py \
    --manifest research/qrs2026-byte-manifest.jsonl \
    --root . --expect-entries 4842 --strict
files checked:          4842
MANIFEST_ROOT computed: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
MANIFEST_ROOT recorded: a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3
PASS
```

`MANIFEST_ROOT = a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`
over 4,842 records. The root digest lives in
`research/qrs2026-byte-manifest.root`, a typed sidecar, so `entry_count` means file
count and nothing else.

#### B.2.1 Detections proven to fire, not assumed to

Each was induced in a scratch state and then reverted; the clean state re-verified
`PASS` after every one.

| Induced condition | Reported |
| --- | --- |
| staged content edit of a frozen file | `GIT_BLOB_CHANGED`, `SHA256_CHANGED`, `SIZE_CHANGED` |
| unstaged content edit | `SHA256_CHANGED: … (unstaged working-tree edit; git index still holds the original blob, so this is a content change, not an encoding difference)` |
| CRLF rewrite of a frozen file | `WORKING_TREE_BYTES_DIFFER_EOL_ONLY: … (stored blob content identical; only line endings differ)` |
| new untracked file under `runs/` | `ADDED_UNTRACKED_FILE_UNDER_FROZEN_PREFIX: runs/extra.json` |
| mode change on `scripts/verify_patch.py` | `MODE_CHANGED: scripts/verify_patch.py 100644 -> 100755` |
| frozen file replaced by a symlink | `SYMLINK_APPEARED: prompts/plain_v1.txt` |
| frozen file deleted | `MISSING_FILE: prompts/retry_v1.txt` |
| manifest record tampered | `SIZE_CHANGED` + `MANIFEST_ROOT_MISMATCH` |
| wrong `--expect-entries` | `ENTRY_COUNT: manifest has 4842, expected 4841` |

The unstaged-edit and CRLF rows are distinct on purpose: an earlier revision of the
verifier reported both as a line-ending difference, which would have let an unstaged
edit of research data pass as benign. The test suite caught it.

### B.3 Semantic reproduction — canonicalised, never called byte equality

```console
$ python3 research/replay_from_frozen_runs.py --check
== 1. exact reconstruction of results/tables/all_runs.csv ==
frozen run records:      630/630
committed rows matched:  630/630
field comparisons:       10080/10080 equal (expected 10080)
attempt blobs parsed:    759 via ast.literal_eval, 0 failure(s)
verdict consistency:     0 failure(s)

== 2. semantic reproduction of derived tables (CRLF->LF canonicalised) ==
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
`eol_canonicalisation_applied: true`. That is the honest result: content is equal,
bytes are not, because `csv.writer` emits CRLF while git stores LF under
`* text=auto`.

### B.4 Environment records — historical facts separated from replay facts

```console
$ python3 research/verify_reproduction_env.py \
    --original research/ORIGINAL_EXPERIMENT_METADATA.json \
    --replay research/VALIDATED_REPLAY_ENVIRONMENT.json \
    --lock research/requirements-reproduction.lock
evidenced fields:     18
not_recorded fields:  10
  NOTE A/run_count: source is a directory (runs/raw); hash check skipped
PASS
```

Contamination attempts, each rejected:

```console
# back-fill the never-recorded host Python version from the replay environment
  FAIL A/experiment_host_python_version: value '3.11.5' not supported by excerpt '#!/usr/bin/env python3'
  FAIL C/experiment_host_python_version: host or library facts must never be evidenced in the historical record (the experiment host was not captured)
  FAIL D/experiment_host_python_version: value '3.11.5' also appears in the replay record; a replay fact must not be presented as a historical fact

# change an evidenced value away from its cited excerpt
  FAIL A/aws_region: value 'us-west-2' not supported by excerpt "client = boto3.client('bedrock-runtime', region_name='us-east-1')"

# claim the derived tables were byte-identical
  FAIL E/result: derived tables are not byte-identical (line endings differ); claiming otherwise would conflate byte and semantic equality
```

### B.5 Legacy semantics quarantine

```console
# (1) no acknowledgement
$ python3 research/compat/legacy_verify.py --before … --after … --target-rule CKV_AWS_233 --baseline …
REFUSED: legacy semantics require --acknowledge-legacy-non-production-semantics.
         For real verification use the hardened profile instead.
exit=2

# (2) acknowledged, but the installed scanner is 3.3.0 rather than the pinned 3.2.517
REFUSED: installed checkov '3.3.0' != pinned '3.2.517'.
         Replication requires the pinned scanner. Install it in an isolated
         environment, or pass --allow-version-drift-for-inspection to obtain an
         explicitly UNTRUSTED result.
exit=3

# (3) explicit untrusted inspection run
{'result_label': 'LEGACY_REPLAY_RESULT', 'is_production_verdict': False,
 'trust': 'UNTRUSTED_VERSION_DRIFT', 'checkov_version_installed': '3.3.0'}
exit=4
```

Exit code is 2, 3, or 4 — never 0 — so the legacy harness cannot be wired in as a
passing CI gate.

### B.6 Research regression tests

```console
$ python3 -m pytest tests/research -q
........................                                                 [100%]
24 passed in 3.10s
```

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
documents inspected:  2
enum values defined:  41
PASS
```

The linter fails on a real gap rather than only reporting success. Removing one enum
definition from the semantics document:

```console
$ python3 tools/spec_lint.py "$TEMP/spec"
  FAIL ENUM_COMPLETE: DeltaClass member `MOVED_FINDING` is not defined in VERIFICATION_SEMANTICS.md
FAIL
```

41 enum values are defined across seven families: 8 statuses, 3 verdicts, 10 target
outcomes, 11 delta classes, 4 identity tiers, 4 agreement states, 5 mapping
confidence levels, plus exit codes 0–4 (families overlap where values are shared).

**Gate C: PASS.**

---

## No frozen research file changed

```console
$ git diff --stat 7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5 \
    -- benchmark runs results prompts scanners scripts requirements.txt
(no output)
```

## Inference statements

```
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_PREPARED_BUT_NOT_EXECUTED
```

The third statement is scoped precisely: no model-refresh study was executed, and the
protocol document itself is a Phase I deliverable that has not been written yet, since
Phases A–C are the authorised scope.
