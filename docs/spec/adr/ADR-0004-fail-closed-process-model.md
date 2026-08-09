# ADR-0004 — Fail-closed process model and typed statuses

- Status: Accepted
- Date: 2026-08-09

## Context

`scripts/verify_patch.py:66` returns `{}` when Checkov produces no stdout, and
`scripts/verify_patch.py:41` returns valid when there is no output and no recognised
error. Downstream, `:82` reads "rule ID not in the failed list" as resolution, and
`:161` combines three booleans into `overall_verified_fix`. A crashed scanner therefore
produces the same evidence as a clean scan (audit F1, F2, F6).

This is not hypothetical for current versions either. Verified on Checkov 3.3.0: an
empty scope returns a summary-only object with **no `results` key** and exit code 0.

## Decision

1. Every operation reports one of `PASS FAIL ERROR TIMEOUT UNSUPPORTED SKIPPED PARTIAL
   INCONCLUSIVE`. A boolean may never encode an operational failure.
2. Scanner integrity (V5) is evaluated **before** target classification. Absence of a
   finding is never sufficient evidence on its own.
3. An empty, unparseable, truncated, or structurally unexpected output is `ERROR`.
4. Verdicts are `VERIFIED`, `FAILED`, or `INCONCLUSIVE`, with exit codes 0, 1, 3.
   Usage errors are 2; internal errors are 4.
5. Success is never inferred from an exit code, and failure is never inferred from the
   presence of findings.

## Consequences

- A broken environment yields exit 3, so users see "we could not tell" rather than a
  green tick or a misleading red one.
- More states for consumers to handle. Mitigated by documenting that 1 is a real
  negative result while 3 and 4 mean the verifier failed.
- Adapters must report coverage counters even on failure, because those counters are
  what separate `PARTIAL` from `ERROR`.
- Some legitimately unusual repositories will land on `INCONCLUSIVE` until an adapter
  learns their shape. That is the intended direction of error.

## Alternatives considered

**Retry on empty output and pass if the retry is clean.** Rejected: it converts an
unexplained failure into a pass, which is precisely the defect being fixed.

**Treat `INCONCLUSIVE` as failure and drop the state.** Rejected: it destroys the
distinction between "your change is bad" and "our tooling is broken", and teams would
learn to ignore the resulting noise.
