# Research Snapshot — QRS 2026 Replication

This document freezes what the accepted paper was produced from, and states exactly
how much of it can be re-derived offline.

| Field | Value |
| --- | --- |
| Snapshot commit | `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5` |
| Snapshot tag | `qrs-2026-replication-v1` (annotated, unsigned, local only) |
| Frozen files | 4,842 |
| `MANIFEST_ROOT` | `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3` |
| Manifest | `research/qrs2026-byte-manifest.jsonl` + `.root` sidecar |
| Scanner of record | Checkov **3.2.517** |
| Benchmark | 70 items (50 Terraform, 20 Kubernetes) |
| Runs | 630 = 70 items × 3 models × 3 methods |
| New model calls required to reproduce the tables | **none** |

## Manuscript availability

The pre-peer-review manuscript has been submitted to arXiv, but no public identifier is
available yet. This repository does not publish a placeholder arXiv identifier. When the
submission becomes public, its abstract record will be linked here. When Springer
publishes the Version of Record, this document will also link its DOI and publisher page.
The current repository tip does not distribute `paper.pdf`.

An ordinary deletion does not remove prior Git objects. The previously published history
and the separate rights/history question are documented in ADR-0011 and ADR-0014. The
local-only freeze tag remains unpublished.

## What is frozen

`benchmark/**`, `runs/**`, `results/**`, `prompts/**`, `scanners/**`, `scripts/**`,
and `requirements.txt` — 4,842 files, bit-for-bit. Everything else in the repository
(README, `docs/EXAMPLE_WALKTHROUGH.md`, `docs/VERIFICATION_PROCEDURE.md`,
`CITATION.cff`, `LICENSE`, `.gitignore`, and `.gitattributes`) is mutable product
documentation and is deliberately **not** covered by the byte manifest, so that ordinary
documentation work cannot trip the freeze. The formerly tracked `paper.pdf` was also
outside the byte manifest and its removal does not change the frozen research scope.

## Two different guarantees, deliberately not merged

**Byte preservation.** `research/verify_byte_manifest.py` hashes the raw bytes of
every frozen file with no normalisation and also checks git mode, git blob identity,
byte size, absence of symlinks, absence of unlisted files under frozen prefixes, and
`MANIFEST_ROOT`.

```bash
python research/verify_byte_manifest.py \
  --manifest research/qrs2026-byte-manifest.jsonl \
  --root . --tag qrs-2026-replication-v1 \
  --expect-entries 4842 --strict
```

`--tag` is mandatory. Without it the tool refuses to run, because a manifest that is
not bound to the tag can be regenerated over changed data and still verify against
itself. Tag binding checks the tag object type, its peeled commit, the
`MANIFEST_ROOT` recorded in the tag annotation, and every path, mode, and blob id in
`git ls-tree -r` for the tag.

**Semantic reproduction.** `research/replay_from_frozen_runs.py` rebuilds
`results/tables/all_runs.csv` from the 630 frozen run records and re-runs the three
analysis scripts, comparing the seven derived tables after a declared
canonicalisation (CRLF→LF, one trailing newline).

```bash
python research/replay_from_frozen_runs.py --check
```

The regenerated tables are **not** byte-identical to the committed ones — Python's
`csv` writer emits CRLF while git stores LF under `* text=auto`. The tool reports
`SEMANTIC_MATCH` and records `byte_identical: false`. It never claims byte equality;
that is the manifest's job.

## Verified results of the 2026-08-09 replay

```
frozen run records:          630/630
committed rows matched:      630/630, 0 unmatched, 0 duplicate keys
field comparisons:           10080/10080 equal      (630 rows x 16 columns)

stored verification values:
  attempts_total:            762
  verification_dicts:        759
  verification_repr_strings: 0     <- ast.literal_eval is a compatibility path and
                                      is NOT exercised by this artifact
  verification_missing:      3
  parse failures:            0

final verdicts:
  checked:                   627
  unavailable:               3     (final attempt error 'empty_extraction')
  mismatches:                0

derived tables:              7/7 SEMANTIC_MATCH, 0/7 byte-identical
figures:                     not regenerated (no frozen script calls savefig)
```

The three unavailable final verdicts are
`BM-0276_claude-opus-4.6_verify_loop.json`,
`BM-0276_claude-sonnet-4.6_verify_loop.json`, and
`BM-0279_claude-sonnet-4.6_verify_loop.json`. In each, the last verify-loop attempt
recorded `error: empty_extraction` and produced no verification object; all three
records carry `overall_verified_fix = false`. They are reported as unavailable
evidence, not silently skipped.

Environment: `research/VALIDATED_REPLAY_ENVIRONMENT.json`.

## Environment: two records, not one

- `research/ORIGINAL_EXPERIMENT_METADATA.json` — 18 fields evidenced by frozen
  artifacts, each citing a source file, a line where applicable, and that file's
  SHA-256; and **10 fields explicitly `not_recorded`**.
- `research/VALIDATED_REPLAY_ENVIRONMENT.json` — the environment that replayed the
  data on 2026-08-09. The interpreter was CPython 3.11.5, and the **hash-locked replay
  dependency closure is `numpy==1.26.4` and `scipy==1.11.1`**. The host also had pandas
  2.0.3 and matplotlib 3.7.2 installed, but no analysis script imports them, so they
  are recorded as present-on-host rather than as replay dependencies.

`research/verify_reproduction_env.py` enforces the separation: a value that appears
in the replay record cannot be presented as a historical fact, and no host,
interpreter, or library fact may ever be marked `evidenced` in the historical file.

### Evidenced (18)

AWS region `us-east-1`; the three Bedrock inference-profile identifiers
(`us.anthropic.claude-sonnet-4-6`, `us.meta.llama4-maverick-17b-instruct-v1:0`,
`us.anthropic.claude-opus-4-6-v1`); temperature `0.0` for both model families;
default output cap 4,096 tokens; `anthropic_version: bedrock-2023-05-31`; retry cap
2; Checkov `3.2.517` — corroborated by the `checkov_version` field embedded in all
70 frozen baseline outputs, not only by the dependency pin; the two Checkov
frameworks (`terraform`, `kubernetes`); the three prompt-template digests; the
50/20 item split; and the 630-run count.

### Not recorded (10)

Experiment start and end timestamps; Bedrock request identifiers; provider-side
model build or snapshot; stop reason, refusal, and truncation state; cached token
counts; provider-reported per-call cost; and the experiment host's Python version,
operating system, architecture, and resolved library versions.

These are absent from the artifact and must stay absent. The 2026-08-09 replay
environment is not a substitute for them.

## Reproducing

```bash
# 1. confirm nothing moved
python research/verify_byte_manifest.py --manifest research/qrs2026-byte-manifest.jsonl \
  --root . --expect-entries 4842 --strict

# 2. rebuild all_runs.csv and the seven derived tables from frozen records
python research/replay_from_frozen_runs.py --check

# 3. run both assertions as tests
python -m pytest tests/research -q

# 4. confirm the environment records are provenance-bound and separate
python research/verify_reproduction_env.py \
  --original research/ORIGINAL_EXPERIMENT_METADATA.json \
  --replay   research/VALIDATED_REPLAY_ENVIRONMENT.json
```

Pinned environment:

- `research/requirements-replay.lock` — hash-pinned and transitively complete for the
  replay: `numpy==1.26.4` and `scipy==1.11.1`, each with a `--hash=sha256`, resolved
  inside the target image because wheel selection is platform-specific. Install with
  `pip install --require-hashes --no-deps -r research/requirements-replay.lock`.
- `research/requirements-checkov-3.2.517.lock` — separate, for re-executing the
  scanner rather than replaying results. Version-pinned only; hash pinning of
  Checkov's large dependency tree is deferred to the Phase E integration workflow and
  is stated as such in the file.
- `research/Dockerfile.reproduction` — base image pinned by digest
  `python:3.11.5-slim-bookworm@sha256:edaf703dce209d774af3ff768fc92b1e3b60261e7602126276f9ceb0e3a96874`.

The dependency set was derived by AST import analysis of the frozen analysis scripts,
not from `requirements.txt`: they import only `numpy` and `scipy` beyond the standard
library. `pandas` and `matplotlib` appear in `requirements.txt` but are imported by no
analysis script, so they are not replay dependencies and are absent from the lock.

Verified: the replay runs to completion inside that container with
`--network=none --read-only --cap-drop=ALL --user $(id -u):$(id -g)` and a tmpfs for
`/tmp`, producing the same 630/630, 10080/10080, and 7/7 results as the host.

## Re-executing the original experiment

Steps 1–4 need no credentials and no model access. Re-running the *experiment*
additionally requires AWS Bedrock access to the three inference profiles above and
Checkov 3.2.517, and will not reproduce the raw responses byte-for-byte: hosted
inference at temperature 0 reduces sampling variance but is not a determinism
guarantee. The frozen responses in `runs/raw/` are the authoritative record.

## Legacy verification semantics

`scripts/verify_patch.py` is preserved unchanged and remains the harness that
produced the published `overall_verified_fix` column. It has four unsafe behaviours
for general use (audit F1–F4, plus F6), so it is quarantined:

- described in `research/compat/qrs2026.yml`, outside the product profile directory;
- reachable only via `research/compat/legacy_verify.py`, which requires
  `--acknowledge-legacy-non-production-semantics`, refuses to run unless Checkov is
  exactly 3.2.517 (or the caller explicitly requests an `UNTRUSTED_VERSION_DRIFT`
  inspection run), labels output `LEGACY_REPLAY_RESULT`, and never returns exit
  code 0 — so it cannot be used as a passing CI gate.

## Known limitations of the artifact

1. Results are Checkov-specific; multi-scanner behaviour was not evaluated. The
   current product boundary is documented in
   [`docs/SUPPORTED_SCOPE.md`](docs/SUPPORTED_SCOPE.md).
2. The 70 items derive from Checkov's own test suite and are not a random sample of
   production infrastructure code.
3. Repair quality was assessed only by automated gates; there was no human review.
4. The retry cap was 2, so convergence beyond three attempts is unmeasured.
5. Cost figures are computed from token counts and prices at the time, not from
   billing records.
6. The verification harness that produced these numbers can, in principle, report a
   silent scanner failure as a verified fix (F1). Nothing indicates this occurred in
   the 630 runs — every record carries a parsed Checkov result and the replay found
   zero inconsistencies between per-run verdicts and their final attempt — but the
   possibility is a property of the harness and is stated rather than hidden.

## Statements

```
NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED
NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V
MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
```
