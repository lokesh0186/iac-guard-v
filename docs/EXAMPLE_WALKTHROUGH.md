# Worked Example: BM-0075 (CKV_AWS_338)

This document walks through the canonical example from Section 7 of the paper, using actual experimental data from this repository.

## Benchmark Item

- **ID**: BM-0075
- **Source**: `benchmark/raw/BM-0075.tf`
- **Rule**: CKV_AWS_338 — *"Ensure CloudWatch log groups retain logs for at least 1 year"*
- **Violation class**: `weak_observability`
- **Source directory**: Checkov's test suite, `example_CloudWatchRetentionDays`

## Original Artifact

```hcl
resource "aws_cloudwatch_log_group" "pass" {
  retention_in_days = 3
}

resource "aws_cloudwatch_log_group" "fail" {}
```

Both resources violate CKV_AWS_338:
- The first resource sets `retention_in_days = 3` (less than the required 365).
- The second resource omits `retention_in_days` entirely.

## Walkthrough: Sonnet with Verify-Loop

Raw run output: `runs/raw/BM-0075_claude-sonnet-4.6_verify_loop.json`

### Attempt 1 (structured prompt)

The model returns:

```hcl
resource "aws_cloudwatch_log_group" "pass" {
  retention_in_days = 365
}

resource "aws_cloudwatch_log_group" "fail" {}
```

**Gate evaluation:**

| Gate | Verdict | Reason |
|------|---------|--------|
| V1 — Syntax | ✅ PASS | Checkov parses the file successfully. |
| V2 — Resolution | ❌ **FAIL** | CKV_AWS_338 still appears in Checkov's failed-checks list because `aws_cloudwatch_log_group.fail` has no `retention_in_days`. |
| V3 — No regression | ✅ PASS | No new findings introduced. |
| V4 — Minimality | ℹ️ 6 lines changed, diff ratio = 0.107. |
| **Verdict** | ❌ **NOT a verified fix** | |

### Verification feedback (constructed automatically by the harness)

The retry prompt summarises:
- Gate V2 failed because CKV_AWS_338 is still in the Checkov failed-checks list.
- The rule requires every CloudWatch log group to set `retention_in_days` ≥ 365.
- Modifying only the first resource does not satisfy the rule for the second.

This feedback is constructed from the actual Checkov JSON output and the gate verdicts — no human intervention.

### Attempt 2 (retry with feedback)

```hcl
resource "aws_cloudwatch_log_group" "pass" {
  retention_in_days = 365
}

resource "aws_cloudwatch_log_group" "fail" {
  retention_in_days = 365
}
```

**Gate evaluation:**

| Gate | Verdict | Reason |
|------|---------|--------|
| V1 — Syntax | ✅ PASS | Valid HCL. |
| V2 — Resolution | ✅ **PASS** | CKV_AWS_338 no longer in Checkov output. |
| V3 — No regression | ✅ PASS | No new findings. |
| V4 — Minimality | ℹ️ 22 lines changed, diff ratio = 0.393. |
| **Verdict** | ✅ **VERIFIED FIX** (achieved on attempt 2) | |

## Why This Example Matters

Two properties on display:

1. **Syntactic validity is a poor proxy for correctness.** Attempt 1 produced perfectly valid HCL, but the rule remained violated by the untouched second resource.

2. **Verification feedback enables targeted self-correction.** The harness identifies *which* gate failed and *why*, and the model uses that feedback to produce a complete fix.

## Reproducing This Walkthrough

```bash
# Reproduce just this one run
python scripts/run_experiment.py \
  --item BM-0075 \
  --model claude-sonnet-4.6 \
  --method verify_loop

# Inspect the output
cat runs/raw/BM-0075_claude-sonnet-4.6_verify_loop.json | jq '.attempts[].verification'
```

Note: results are deterministic (`temperature=0`); your run should produce identical output to the JSON in this repo.
