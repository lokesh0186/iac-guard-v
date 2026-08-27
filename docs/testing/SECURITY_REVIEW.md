# Local test harness security review

Status: PASS for the persistent harness and shared public-CI gate migration, subject
to the complete PR and release profiles recorded in run summaries or published CI.

## Review boundary

The review covers `noxfile.py`, `tools/testing/`, the harness dependency inputs,
generated local summaries, and the documented operator commands. It does not promote
reusable state to release evidence and does not change product verification semantics.

## Findings and controls

| Risk | Control and result |
| --- | --- |
| Shell injection | Gate definitions are argv lists. No test selector is evaluated by a shell. PASS. |
| Unsafe deletion | Cleanup has fixed managed roots, lexical containment guards, and top-level/nested symlink refusal. Adversarial sentinels survive. PASS. |
| Unsafe focused passthrough | Only test paths under `tests/`, `-k`, `--lf`, and `--ff` are accepted. Destructive pytest path/config/plugin options are refused. PASS. |
| Credential forwarding | Test and scanner processes receive closed environments, isolated homes, and no token/key/password/proxy/auth variables. Package installation may use the invoking machine's configured index credentials, but test execution cannot. PASS. |
| Wrong interpreter | Exact CPython minor, executable identity/hash, host architecture, and copied-venv contract are fingerprinted and checked. Missing or Rosetta/mixed interpreters fail. PASS. |
| Stale environment reuse | Dependency, Python, architecture, Nox, and install-contract changes invalidate the fingerprint before suite execution. PASS. |
| Package contamination | `pip check`, project RECORD hashes/sizes, editable install presence, and prohibited product bytecode are checked before large suites. PASS. |
| Scanner contamination | Checkov 3.3.0 has an independent lock, fingerprint, doctor/RECORD/closure identity, and bounded managed rebuild. PASS. |
| Result-path escape or falsification | Run identifiers are bounded; result roots and run directories refuse symlinks and must remain in `.test-results`. JUnit counts are parsed, not supplied as arbitrary summary text. PASS. |
| Coverage bypass | Eight declarative gates retain their exact module selections, branch settings, and 90 percent thresholds. Each has an isolated coverage database. PASS. |
| Silent matrix reduction | Nox never downloads Python and missing 3.10 through 3.13 interpreters fail the matrix. PASS. |
| Release cache reuse | The release session declares `reuse_venv=False`, checks Nox's actual reuse flag, and retains a freshness marker. `--reuse-venv=always` is proven to fail before installation/tests. PASS. |
| Shared-path concurrency | Parallelism is across isolated interpreter environments. xdist is limited to two workers in the non-research development phase; QRS, coverage, scanners, matrix workers, and release stay serial within each session. PASS. |
| Docker exposure | The bounded experiment used no socket, credentials, cluster access, or runtime network. No Docker path or image is retained. PASS. |
| Mutable GitHub CI state | Shared coverage definitions do not change environment construction. GitHub Actions continues to create clean copied venvs without caching populated correctness environments. PASS. |
| Frozen research mutation | The manifest/root and replay semantics remain unchanged; the harness only invokes existing checks. PASS. |

## Corrections made during review

The first cleanup implementation resolved managed paths before checking whether a
managed root was a symlink. That could have authorized deletion through a crafted
symlink. Cleanup now uses lexical absolute containment, refuses symlinks at every
managed path component, and has adversarial top-level and nested escape tests.

The review also added direct Nox reuse detection, exact project RECORD verification,
strict credential isolation, safe result-directory construction, architecture mismatch
refusal, and a bounded focused-selector grammar.

## Verdict

No unresolved fail-open condition was found in the local harness. Reusable results are
explicitly diagnostic only. Clean GitHub CI and the fresh release profile remain the
authoritative proof boundaries.
