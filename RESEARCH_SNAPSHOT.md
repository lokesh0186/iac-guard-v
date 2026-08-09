# Research Snapshot — QRS 2026 Replication

This document freezes what the accepted paper was produced from, and states exactly
how much of it can be re-derived offline.

| Field | Value |
| --- | --- |
| Snapshot commit | `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5` |
| Snapshot tag | `qrs-2026-replication-v1` (annotated) |
| Frozen files | 4,842 |
| `MANIFEST_ROOT` | `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3` |
| Manifest | `research/qrs2026-byte-manifest.jsonl` + `.root` sidecar |
| Scanner of record | Checkov **3.2.517** |
| Benchmark | 70 items (50 Terraform, 20 Kubernetes) |
| Runs | 630 = 70 items × 3 models × 3 methods |
| New model calls required to reproduce the tables | **none** |

## What is frozen

`benchmark/**`, `runs/**`, `results/**`, `prompts/**`, `scanners/**`, `scripts/**`,
and `requirements.txt` — 4,842 files, bit-for-bit. Everything else in the repository
(README, `docs/EXAMPLE_WALKTHROUGH.md`, `docs/VERIFICATION_PROCEDURE.md`,
`CITATION.cff`, `LICENSE`, `.gitignore`, `.gitattributes`, `paper.pdf`) is mutable
product documentation and is deliberately **not** covered by the byte manifest, so
that ordinary documentation work cannot trip the freeze.

## Two different guarantees, deliberately not merged

**Byte preservation.** `research/verify_byte_manifest.py` hashes the raw bytes of
every frozen file with no normalisation and also checks git mode, git blob identity,
byte size, absence of symlinks, absence of unlisted files under frozen prefixes, and
`MANIFEST_ROOT`.

```bash
python research/verify_byte_manifest.py \
  --manifest research/qrs2026-byte-manifest.jsonl \
  --root . --expect-entries 4842 --strict
```

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
frozen run records:      630/630
committed rows matched:  630/630
field comparisons:       10080/10080 equal        (630 rows × 16 columns)
attempt blobs parsed:    759 via ast.literal_eval, 0 failures
verdict consistency:     0 failures
derived tables:          7/7 SEMANTIC_MATCH, 0/7 byte-identical
figures:                 not regenerated (no frozen script calls savefig)
```

Environment: `research/VALIDATED_REPLAY_ENVIRONMENT.json`.

## Environment: two records, not one

- `research/ORIGINAL_EXPERIMENT_METADATA.json` — 18 fields evidenced by frozen
  artifacts, each citing a source file, a line where applicable, and that file's
  SHA-256; and **10 fields explicitly `not_recorded`**.
- `research/VALIDATED_REPLAY_ENVIRONMENT.json` — the environment that replayed the
  data on 2026-08-09 (CPython 3.11.5, pandas 2.0.3, numpy 1.26.4, scipy 1.11.1).

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

Pinned environment: `research/requirements-reproduction.lock` (exact versions;
artifact hash pinning is a deferred networked step, stated in the file itself) and
`research/Dockerfile.reproduction`.

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

1. Results are Checkov-specific; multi-scanner behaviour was not evaluated
   (`README.md:220`).
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
MODEL_REFRESH_PROTOCOL_PREPARED_BUT_NOT_EXECUTED
```
