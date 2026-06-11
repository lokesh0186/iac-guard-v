# Verification Procedure

This document is a plain-English description of the verification harness, mirroring Algorithm 1 from the paper.

## Inputs

- `A` — The original misconfigured IaC artifact (a Terraform `.tf` file or Kubernetes `.yaml` file).
- `v` — The Checkov rule ID that must be resolved (e.g., `CKV_AWS_338`).
- `M` — The LLM used for repair, accessed via API.
- `k` — Maximum number of retries (we use `k = 2`, giving 3 total attempts).

## Output

Either:
- A verified fix `A'` — a repaired artifact that passes all three binary gates (V1, V2, V3), or
- `FAIL` — if no verified fix is produced within `k` retries.

## Procedure

### Step 0: Establish the baseline

Run Checkov on the original artifact `A` and record the set of failed rule IDs as `B`. This baseline is the reference point for V3 (regression detection): any rule that appears in `B'` (the repaired file's failed rules) but not in `B` is a regression.

### Step 1: First repair attempt

Construct a structured prompt containing:
- The original artifact `A`.
- The target Checkov rule ID `v`, its description, the violation class, the affected resource, and the line range.

Send the prompt to `M` and parse the JSON response to extract the candidate repair `A'`.

### Step 2: Evaluate gates

For each of the four gates:

#### V1 — Syntactic Validity

Run Checkov on `A'`. If Checkov can parse the file and produce structured output (no parser error), `V1` passes.

#### V2 — Target-Issue Resolution

From Checkov's output on `A'`, extract the set of failed rule IDs `B'`. If `v` is **not** in `B'`, `V2` passes.

Note: this is a file-level check. In multi-resource files where the same rule is violated by multiple resources, every violating resource must be addressed for `V2` to pass.

#### V3 — Regression Safety

Compute `B' \ B` (set difference). If this set is empty, `V3` passes. Otherwise, the repair has introduced one or more new findings.

#### V4 — Patch Minimality (informational)

Compute the unified diff between `A` and `A'`. Record:
- Lines added.
- Lines removed.
- Total lines changed (added + removed).
- Diff ratio = total lines changed / lines in original file.

`V4` is reported but does not gate the verdict.

### Step 3: Decide

If `V1 ∧ V2 ∧ V3` all pass: return `A'` as a verified fix.

Otherwise:
1. Construct a retry prompt that conveys to the model:
   - The original artifact `A` and the failed attempt `A'`.
   - Which gates failed.
   - The relevant excerpt of Checkov's output (e.g., for V2: the rule still failing; for V3: the new findings).
2. Send the retry prompt to `M`, parse the response, and obtain a new candidate `A'`.
3. Return to Step 2.

If `k` retries have been exhausted without a verified fix, return `FAIL`.

## Implementation Files

- `scripts/run_experiment.py` — Main runner; coordinates attempts and retries.
- `scripts/verify_patch.py` — Implements V1, V2, V3, V4 against Checkov's JSON output.
- `scripts/call_bedrock.py` — Sends prompts to AWS Bedrock and parses responses.
- `prompts/structured_v1.txt`, `prompts/retry_v1.txt`, `prompts/plain_v1.txt` — Prompt templates.

## Why Automation Matters

Every gate (V1–V3) is computed by deterministic comparison of scanner outputs. There is no manual judgment in the verification path. This means:

- Results are reproducible given fixed model temperature (we use `temperature = 0`).
- The pipeline can be integrated into CI/CD as a mandatory gate.
- Independent replication does not require multiple human annotators or cross-checking.
