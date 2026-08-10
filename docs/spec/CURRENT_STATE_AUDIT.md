# Current-State Audit

Audit of `lokesh0186/iac-guard-v` at the pre-productization HEAD, performed before
any repository modification.

| Field | Value |
| --- | --- |
| Audited commit | `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5` (`main`) |
| Commit date | 2026-07-08 11:54:10 -0500 |
| Commits in history | 15 (all created through the GitHub web uploader; no pull-request history) |
| Tracked files | 4,850 |
| Tags / releases | 0 / 0 |
| Licence | Apache-2.0 |
| Audit date | 2026-08-09 |
| Audit branch | `adoption/p1-research-and-spec` |

Every finding below cites a file and line in this repository. Findings are ranked by
severity in §6. This audit describes the artifact as it exists; it does not revise
the accepted paper, and nothing in the frozen research data is changed as a result
of it.

---

## 1. Inventory

### 1.1 Root

| Path | Size | Role | Freeze class |
| --- | --- | --- | --- |
| `README.md` | 14,105 B | Public entry point, results summary | mutable |
| `LICENSE` | 11,324 B | Apache-2.0 | mutable |
| `CITATION.cff` | 1,698 B | Citation metadata | mutable |
| `requirements.txt` | 220 B | Experiment dependency pins | **frozen** |
| `paper.pdf` | 393,284 B | Author-compiled LNCS build | mutable, decision pending (ADR-0011) |
| `.gitignore` | 10 B at audit time | Ignored `.DS_Store` only | mutable |
| `.gitattributes` | 66 B | `* text=auto` line-ending normalisation | mutable |

### 1.2 Directories

| Path | Contents | Role | Freeze class |
| --- | --- | --- | --- |
| `benchmark/raw/` | 3,481 item directories | Corpus derived from Checkov's test suite | **frozen** |
| `benchmark/*.csv` | 5 manifests | Corpus and selection records; `selected_manifest_enriched.csv` has 50 Terraform rows, `k8s_selected_manifest_enriched.csv` has 20 | **frozen** |
| `runs/raw/` | 630 JSON | Per-run records including full model responses | **frozen** |
| `runs/patches/` | 630 files | Extracted candidate patches | **frozen** |
| `results/tables/` | 8 CSV | `all_runs.csv` (input) + 7 derived tables | **frozen** |
| `results/figures/` | 3 PNG | Paper figures | **frozen** |
| `scanners/outputs/baseline/` | 70 JSON | Checkov baselines, one per benchmark item | **frozen** |
| `prompts/` | 3 templates | `plain_v1.txt`, `structured_v1.txt`, `retry_v1.txt` | **frozen** |
| `scripts/` | 11 Python files | Benchmark construction, experiment runner, verifier, analysis | **frozen** |
| `docs/` | 2 Markdown files | `VERIFICATION_PROCEDURE.md`, `EXAMPLE_WALKTHROUGH.md` | mutable |

630 runs = 70 items × 3 models × 3 methods. Frozen scope totals **4,842** of the
4,850 tracked files; the 8 mutable files are the six listed above plus the two
`docs/` files.

### 1.3 Absent

No `pyproject.toml`, `setup.py`, `src/`, `tests/`, `action.yml`, `Dockerfile`,
`.github/`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`,
`GOVERNANCE.md`, `ROADMAP.md`, `CHANGELOG.md`, `ADOPTERS.md`, `NOTICE`, or
`.pre-commit-hooks.yaml`. There is no packaged distribution, no test suite, no
continuous integration, and no release.

---

## 2. Verification-correctness findings

These concern `scripts/verify_patch.py`, the harness that produced the
`overall_verified_fix` column in `results/tables/all_runs.csv`.

### F1 — An empty scanner result is indistinguishable from a clean scan (critical)

`scripts/verify_patch.py:66` returns an empty dict when Checkov produced no stdout.
The caller at `scripts/verify_patch.py:80` builds `failed_ids` from that empty
structure, and `scripts/verify_patch.py:82` concludes the target is resolved because
its rule ID is not present. A scanner that crashed, timed out, was killed, or
produced nothing therefore yields the same evidence as a scanner that found nothing
wrong. Combined with the verdict expression at `scripts/verify_patch.py:161`, a
silent scanner failure can be reported as a verified fix.

### F2 — Syntactic validity is inferred from the absence of output (critical)

`scripts/verify_patch.py:41` returns `True, "No output but no errors"`. Validity is
asserted when Checkov printed nothing and did not obviously error. The comment at
`scripts/verify_patch.py:25` states the design intent — Checkov's parser is used as
the syntax oracle — so an artifact Checkov declines to parse for any unrelated
reason can still be recorded as syntactically valid. There is no independent HCL or
YAML parser anywhere in the repository.

### F3 — Finding identity is a bare rule ID (critical)

Regression detection compares two sets of `check_id` values,
`scripts/verify_patch.py:90` and `scripts/verify_patch.py:93`, and takes the
difference at `scripts/verify_patch.py:95`. Consequences that follow directly from
this representation:

- A finding that moves from one resource to another is invisible: the rule ID is
  present before and after, so the set difference is empty.
- Multiple occurrences of one rule collapse into a single set member, so fixing one
  of three violations of the same rule looks complete.
- A finding that changes file or resource but keeps its rule ID is neither "new" nor
  "resolved".

`scripts/verify_patch.py:80` uses a list rather than a set for the target check, but
identity is still the rule ID alone; no resource address, file path, or occurrence
index participates.

### F4 — Target resolution cannot distinguish a fix from an evasion (critical)

`scripts/verify_patch.py:82` treats "rule ID no longer in the failed list" as
resolution. All of the following produce that same observation and are therefore
reported identically to a genuine repair: adding a `checkov:skip` annotation;
deleting the offending resource; deleting or renaming the file; changing the file
extension so the framework no longer selects it; a scanner version or ruleset change
that renames or withdraws the rule; and a parser failure covered by F1. The harness
contains no suppression detection, no resource-deletion detection, and no
scanner-version contract.

### F5 — Single scanner, self-referential oracle (high)

`scripts/verify_patch.py:27` and `scripts/verify_patch.py:57` invoke the same
Checkov binary named at `scripts/verify_patch.py:16` for both parsing and security
judgement. The baseline scripts do the same:
`scripts/run_baseline_checkov.py:38` for Terraform and
`scripts/run_k8s_baseline.py:26` for Kubernetes. There is no independent oracle, so
any Checkov false negative silently becomes ground truth. `README.md:220` states
this limitation honestly.

### F6 — Operational failure is encoded in the same booleans as security outcomes (high)

`verify_patch` returns `v1_syntax_valid` and `v2_target_resolved` as booleans and
`v3_new_issues_count` initialised to `-1`. A timeout, a JSON decode failure, and a
genuine policy failure all collapse into `False`, so a consumer cannot separate "the
change is bad" from "we could not tell". The verdict at
`scripts/verify_patch.py:161`–`scripts/verify_patch.py:164` is a conjunction of
those booleans, with no error state.

---

## 3. Reproducibility findings

### F7 — The primary results table has no offline regeneration path (critical)

`results/tables/all_runs.csv` is written only by the experiment runner, which
requires live Bedrock calls: `scripts/run_experiment.py:26` defines the output path,
and `scripts/run_experiment.py:132` and `scripts/run_experiment.py:172` invoke the
verifier inside the model loop. All three analysis scripts consume that file rather
than producing it, for example `scripts/analyze_part1.py:13`. As shipped, a third
party cannot reconstruct the table from the artifact without paying for inference.

Measured during this audit: the data needed to reconstruct it **is** present. The
630 `runs/raw/*.json` records map 1:1 onto the 630 CSV rows, and all 16 CSV columns
exist as keys in every record — 10,080 field comparisons, zero mismatches. The gap
is tooling, not data. Remediated by `research/replay_from_frozen_runs.py`.

### F8 — Derived tables reproduce in content but not in bytes (medium)

Running the three analysis scripts against the committed `all_runs.csv` in a
disposable copy regenerated all 7 derived tables with no content differences. The
bootstrap is seeded at `scripts/analyze_part1.py:65`, so confidence intervals are
deterministic. The only difference is line endings: Python's `csv` writer emits
CRLF while git stores LF under the `* text=auto` rule in `.gitattributes`. Any
regression test that compares raw bytes of regenerated CSVs will fail for a reason
unrelated to research correctness. This is why the freeze uses two distinct
mechanisms (byte manifest vs. canonicalised semantic comparison).

### F9 — Per-run provenance is thin (medium)

Each `runs/raw/*.json` record contains `artifact_id`, `model`, `method`,
`checkov_rule_id`, `violation_class`, the four gate outcomes, `num_attempts`,
`input_tokens`, `output_tokens`, `latency_seconds`, `error`, and an `attempts` list
holding `attempt`, `response`, `fixed_text`, and `verification`. It contains **no
timestamp, no request identifier, no region, no model version string, no stop
reason, and no truncation or refusal state.** Experiment settings are recoverable
only from the frozen scripts — region at `scripts/call_bedrock.py:25`, model
identifiers at `scripts/call_bedrock.py:12`, `:16`, and `:20`, temperature at
`scripts/call_bedrock.py:38` and `scripts/call_bedrock.py:62`, output cap at
`scripts/call_bedrock.py:28`, retry cap at `scripts/run_experiment.py:34` — and the
Checkov version from `requirements.txt:4` corroborated by the
`"checkov_version": "3.2.517"` field embedded in all 70 baseline JSON files. Fields
that were never recorded must remain explicitly unknown rather than being
back-filled from a later environment.

### F10 — `verification` encoding was mis-stated in the first audit (corrected)

**Original claim, now known to be wrong:** that each `attempts[].verification` value is
the Python `repr` of a dict and therefore not JSON-parseable.

**Verified 2026-08-09, over all 630 records and 762 attempts:**

| Encoding | Count |
| --- | --- |
| `verification` stored as a JSON object | 759 |
| `verification` stored as a `repr` string | **0** |
| `verification` absent | 3 |

The first audit misread a printed `str(dict)` — which renders with single quotes and
looks exactly like a repr — as evidence of how the value was stored. Every present
value is a JSON object and parses with `json.loads`.

The engineering consequence stands but for a different reason: replay tooling keeps
`ast.literal_eval` as a **defensive compatibility path** for repr-encoded values, and
must never use `eval`, because these blobs contain model-generated text. That path
is not exercised by this artifact, and the replay reports its invocation count as 0
rather than implying it did the work.

The three absent values are a real, separate observation:

| File | Final attempt |
| --- | --- |
| `runs/raw/BM-0276_claude-opus-4.6_verify_loop.json` | `error: empty_extraction`, no verification object |
| `runs/raw/BM-0276_claude-sonnet-4.6_verify_loop.json` | same |
| `runs/raw/BM-0279_claude-sonnet-4.6_verify_loop.json` | same |

In each case the final verify-loop attempt produced no extractable patch, so no
verification was recorded for that attempt. All three records carry
`overall_verified_fix = false`, consistent with a failed final attempt. They are
classified as unavailable evidence, not skipped: 627 of 630 final verdicts are
independently checkable, and all 627 agree with their final attempt.

---

## 4. Security findings

### F11 — Unbounded trust in scanner invocation surface (high)

The harness writes candidate content to a temporary file and shells out
(`scripts/verify_patch.py:27`, `:57`) with a 30- and 60-second timeout respectively.
There is no process-group termination, no output-size bound, no environment
allowlist, no working-directory isolation, and no restriction on Checkov's external
Python checks. For a research harness operating on its own corpus this is
acceptable; for a tool that will scan untrusted pull-request content it is not.

### F12 — No policy-integrity boundary (high)

Nothing distinguishes the artifact under evaluation from the configuration that
governs the evaluation. A candidate that edits scanner configuration, ignore files,
or verifier settings would simply be evaluated under its own rules. This is the
threat that the hardened design addresses with base-commit-sourced policy and
`POLICY_DRIFT` classification.

### F13 — No security reporting path (medium)

No `SECURITY.md`, no private vulnerability reporting instructions, and no supported
version statement exist.

---

## 5. Adoption and documentation findings

### F14 — Documentation contradicts the repository contents (medium)

`README.md:23` states that the paper is not hosted in this repository, while
`paper.pdf` is present in the root. The file is byte-identical to the author's
compiled LNCS build, so redistribution rights need confirmation before either the
file or the sentence is changed. Recorded as ADR-0011; the file is left untouched
in this phase.

### F15 — Historical claims are worded as present-tense competitive claims (medium)

`README.md:19` says the conference is "to be held July 22–25, 2026", a date now
past. `README.md:57` calls Llama 4 Maverick "open-source" and Claude Opus 4.6 "the
strongest commercial model"; `README.md:92` repeats "open-source model". These
should become a historical, bounded statement ("the highest-performing commercial
model evaluated in the QRS 2026 study") using "open-weight" consistently.

### F16 — Determinism is overstated (medium)

`README.md:169` states that temperature 0 gives "deterministic, reproducible
outputs". Temperature 0 reduces sampling variance; it does not make a hosted
inference service bit-for-bit reproducible. The honest formulation is that raw
responses are preserved in the artifact.

### F17 — No installable or runnable product surface (high)

Normal use requires cloning the whole 28 MB artifact and running research scripts
with experiment-pinned dependencies. There is no packaged CLI, no public API, no
container, no GitHub Action, and no pre-commit hook. `requirements.txt:5` pulls
`boto3` into the dependency set, so even a user who never calls a model inherits an
AWS SDK requirement.

### F18 — No contribution or community surface (medium)

No contribution guide, code of conduct, issue templates, pull-request template,
governance statement, or changelog. Issues are enabled at the repository level, so
the barrier is missing guidance rather than a disabled tracker.

### F19 — Legacy procedure documentation describes only the old semantics (low)

`docs/VERIFICATION_PROCEDURE.md:15` defines a verified fix as passing the three
binary gates, and `docs/VERIFICATION_PROCEDURE.md:22` defines regression as a rule
appearing in the repaired set but not the baseline set — an accurate description of
F3's set-of-rule-IDs comparison. The document is correct about the research harness
and must be labelled as legacy semantics rather than silently rewritten.

---

## 6. Severity-ranked remediation backlog

| Rank | ID | Finding | Severity | Remediation | Phase |
| --- | --- | --- | --- | --- | --- |
| 1 | F1 | Empty scanner output can pass | Critical | Scanner-integrity gate; typed `SCANNER_ERROR`; fail closed | D |
| 2 | F4 | Fix indistinguishable from evasion | Critical | 10-outcome target classifier + suppression/deletion detectors | D |
| 3 | F3 | Rule-ID-only identity | Critical | Resource-level identity tiers, multiset deltas | D |
| 4 | F2 | Validity inferred from silence | Critical | Independent HCL/YAML parsers, separate schema state | D |
| 5 | F7 | No offline table regeneration | Critical | `research/replay_from_frozen_runs.py` + regression test | **B** |
| 6 | F6 | Errors encoded as security booleans | High | Typed status enums, exit codes 0–4 | D |
| 7 | F12 | No policy-integrity boundary | High | Base-commit policy source, `POLICY_DRIFT` | C spec, D |
| 8 | F11 | Unsafe process execution surface | High | Hardened runner: arg arrays, process-group kill, output caps, env allowlist | D |
| 9 | F5 | Single self-referential oracle | High | KICS/Trivy adapters, independent oracles | E |
| 10 | F17 | No installable product | High | Package, CLI, container, composite Action | D, E |
| 11 | F9 | Thin per-run provenance | Medium | Record what is evidenced; mark the rest `not_recorded` | **B** |
| 12 | F8 | Byte vs. content reproduction | Medium | Two-mechanism freeze | **B** |
| 13 | F14 | README contradicts `paper.pdf` | Medium | ADR-0011 then a single consistent statement | B decision, G text |
| 14 | F15 | Historical claims mis-worded | Medium | Bounded historical wording | G |
| 15 | F16 | Determinism overstated | Medium | Restate as variance reduction | G |
| 16 | F13 | No security reporting path | Medium | `SECURITY.md` + private reporting | G |
| 17 | F18 | No community surface | Medium | Contribution and template set | G |
| 18 | F10 | `repr`-encoded verification blob | Low | `ast.literal_eval` in replay tooling | **B** |
| 19 | F19 | Legacy docs unlabelled | Low | Legacy-semantics banner | G |

---

## 7. Hypotheses from the master prompt that this audit disproves

| Claimed | Actual |
| --- | --- |
| The verifier shells out to a hard-coded absolute Checkov path | `scripts/verify_patch.py:16` is `CHECKOV_BIN = "checkov"`, a PATH lookup. The absolute `/Users/…` path exists only in a stale local copy outside this repository |
| Issue creation is restricted | Issues are enabled on the repository; what is missing is contribution guidance and templates |
| There is no `requirements.txt` | It exists and pins `checkov==3.2.517` at `requirements.txt:4` |
| The paper is not in the repository | `paper.pdf` is in the root; it is `README.md:23` that is out of date |

## 8. What this audit deliberately does not do

It does not modify any frozen file, re-run any model, alter any published number, or
delete `paper.pdf`. F1–F6 describe the research harness accurately for its original
purpose: it measured a consistent signal across 630 runs under one scanner version.
The productization work replaces that harness for CI use while keeping it available,
byte-unchanged, for replication.
