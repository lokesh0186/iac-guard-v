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

## Amendment, 2026-08-09: malformed and omitted input

Fail-closed has to cover the input boundary too, not only scanner behaviour. Measured in
the specification reference model before this amendment:

| Input | Result |
| --- | --- |
| no gate evidence supplied at all | `VERIFIED` |
| `required_validator_states=("PASS",)` as a string | `VERIFIED` |
| `required_validator_states=("BOGUS",)` | `VERIFIED` |
| `regression_policy="BOGUS"` | `VERIFIED` |
| `scanner_integrity_ok="false"` | classified as if integrity held |

The mechanism is the same in each case: an unknown value is neither in the undecided set
nor equal to `FAIL`, so it falls through the checks into the pass branch. Type
annotations do not prevent this, because they are not runtime validation.

Therefore, added to this decision:

6. Required gate evidence is supplied explicitly and never defaulted to `PASS`.
7. Statuses and outcomes must be enum members, structural flags must be booleans, dates
   must be dates, identities and scopes must be non-blank and canonical.
8. Malformed input is a usage error with exit code 2. It is never reinterpreted as a
   verdict of any kind.

## Amendment, 2026-08-09 (second): frozen must mean frozen

Fail-closed also has to survive the object graph. Measured before this amendment, with a
verdict already computed:

| Mutation | Effect |
| --- | --- |
| `RunObservation.__dict__["policy_drift"] = True` | `VERIFIED` became `FAILED` |
| `ExceptionRecord.__dict__["scope"] = ...` on a caller-held record | `VERIFIED` became `FAILED` |
| `TargetObservation.__dict__["candidate_matches"] = -1` | `FIXED` from an impossible state |
| a `tuple` subclass swapping its `__iter__` | `VERIFIED` became `FAILED` |
| a `TargetDecision` subclass reporting `FIXED` while storing `STILL_PRESENT` | reached `VERIFIED` |

Added to this decision:

9. Every persistent domain value is a frozen **and** slotted dataclass, so no instance
   has a `__dict__`.
10. Nested records, findings and decisions are reconstructed from copied values;
    collections are rebuilt into exact built-in types and canonically ordered.
11. Security boundaries require exact types. `isinstance` accepts behaviour-overriding
    subclasses and is therefore not used for domain values.

## Amendment, 2026-08-10: D2.1 secure-runner closure

Nine further fail-open behaviours were independently reproduced in the process runner and
are now closed, each with a before/after probe:

| Defect | Before | After |
| --- | --- | --- |
| child inherits real HOME and reads `~/.aws/credentials` | credential file readable | private HOME under scratch; no real home exposure |
| PATH="." + untrusted cwd executes fake `checkov` | ran the fake binary | `ProcessPolicyError`: cannot override protected `PATH` |
| 1 MiB stderr under 64 KiB cap | PASS with all 1 MiB retained | PARTIAL; stderr bounded to configured cap |
| closed streams + sleep bypasses deadline | returned after ~3.9s as ERROR | TIMEOUT at the configured 1s deadline |
| leader os._exit(0), grandchild survives | grandchild wrote its marker | process GROUP killed; marker never appears |
| mutable env_extra after construction | mutation changed child output | `TypeError` (frozen MappingProxyType) |
| `BAD=KEY` environment name | raw `ValueError` from Popen | `ProcessPolicyError` before spawn |
| NUL in environment value | raw `ValueError` from Popen | `ProcessPolicyError` before spawn |
| malformed CommandResult constructed | accepted without validation | `ProcessPolicyError` |

Additionally: `redaction.py` strips credentials, tokens and local paths from report-facing
output; workspace-root confinement rejects cwd outside a declared root or through symlink
escapes; scratch cleanup success/failure is recorded rather than silently ignored.

The host process runner is explicitly NOT a sandbox. It reduces credential discovery and
bounds resource usage, but cannot prevent arbitrary host-filesystem reads. Full isolation
requires the container mode.

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

## Amendment, 2026-08-10: D2.2 hardened process model

Ten additional fail-open behaviours were independently reproduced and are now closed:

| Defect | Before | After |
| --- | --- | --- |
| A: leader exits, descendants survive (group not checked) | PASS; orphaned processes remain | ERROR/LINGERING_DESCENDANTS_TERMINATED; group killed |
| B: combined output cap not enforced (100k retained under 65536 cap) | stdout+stderr independently capped only | combined cap enforced; total ≤ max_output_bytes |
| C: canonical_dict returns raw argv and detail | secrets and local paths leak into reports | redact_argv and redact_detail applied; display_command shlex-quoted |
| D: cleanup failure records boolean but status stays PASS | PASS despite failed scratch cleanup | ERROR/SCRATCH_CLEANUP_FAILED when command otherwise succeeded |
| E: contradictory CommandResult states accepted | PASS with timed_out=True accepted | ProcessPolicyError on construction |
| F: child inherits parent PATH | attacker's absolute dir reachable | MINIMAL_SYSTEM_PATH + trusted_helper_dirs only; parent PATH never inherited |
| G: cwd without workspace_root accepted | arbitrary directory traversal | ProcessPolicyError: workspace_root required when cwd supplied |
| H: resolved executable not recorded | no audit trail of which binary ran | resolved_executable in CommandResult and canonical_dict |
| LD_PRELOAD/DYLD_*/PYTHONPATH reach child | preload injection possible | added to credential denylist; stripped before spawn |
| sensitive option values visible in display | --token value visible in logs | redact_option_values strips values after --token, --password, etc. |

Added to this decision:

12. Process group termination always verifies the **group** is gone (os.killpg(pgid, 0)),
    not just that the leader exited.
13. Output caps enforce a combined invariant: stdout_retained + stderr_retained ≤ max_output_bytes.
14. All report-facing output (canonical_dict, display_command) passes through redaction.
15. Scratch cleanup failure is a typed gate: it cannot coexist with PASS.
16. CommandResult rejects contradictory state combinations at construction time.
17. Child PATH is constructed from a fixed minimal set plus explicit trusted_helper_dirs;
    the parent process's PATH is never consulted.
18. workspace_root is mandatory when cwd is supplied; if neither is supplied, the private
    scratch directory is used as cwd.
19. The resolved executable path is recorded for auditability.

## Amendment, 2026-08-10: D2.3 process-boundary closure

Further independent probes showed that the D2.2 controls did not yet establish the
complete properties recorded above. The decision is amended as follows:

20. `ProcessReason` is closed, and an explicit status/reason table plus field invariants
    rejects contradictory public `CommandResult` evidence.
21. Adapter sensitivity metadata is exact-type validated, canonicalized, frozen, carried
    into the result, and used by both display and canonical report rendering.
22. Process-group existence is three-valued. `EPERM` and arbitrary inspection errors are
    uncertainty, never proof of absence. Unconfirmed cleanup overrides timeout or output
    truncation with `ERROR/PROCESS_GROUP_CLEANUP_FAILED`, preserving the original event.
23. The final result is constructed only after scratch cleanup, so execution and cleanup
    failures remain simultaneously visible.
24. Absolute executables inside the evaluated workspace, including symlinks resolving
    there, are refused. Workspace, cwd, helper directories, and executable identity are
    revalidated immediately before spawn.
25. Canonical evidence separates observed and retained bytes, and labels output hashes as
    retained-byte hashes.
26. Local path redaction covers the specified POSIX roots and both Windows separator
    forms; absolute `argv[0]` becomes a basename/tool identity; cleanup logs pass through
    the same redaction boundary.

Spawn-time revalidation is defence in depth, not an atomic filesystem sandbox. The final
check and `Popen` still form a native TOCTOU interval, and container isolation remains the
required hostile-PR boundary.
