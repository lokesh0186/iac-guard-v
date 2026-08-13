# Architecture

## D7.5 derived target and artifact boundary

Public `report-v1` acceptance derives every target outcome from scanner evidence and
the two sealed snapshots. An exception can permit a proven non-fix event, but cannot
manufacture suppression, resource deletion, file deletion, scope loss, scanner drift,
or uncertainty. Ordinary differential reports require distinct role snapshot
identities.

The public validator also reconstructs the supported/governed filesystem scope from
the protected product catalog. Every supported or governed entry has exactly one
classification or governed record; unsafe entries and rejection reasons prevent a
passing preflight. Scanner identity is a canonical manifest of package, installed
distribution, dependency closure, custom-check, policy, and interpreter components,
not an independently asserted digest.

## D7.3 canonical report graph boundary

`report-v1` validation is a graph validation, not independent validation of JSON
fragments. JSON Schema first closes representation shape. The executable semantic
validator then rejects duplicate authoritative identities before constructing maps,
requires the complete five-class engine-event set, reconstructs target identities,
and reconciles target bindings with policy decisions.

The same pass reconciles protected configuration with role-bound snapshots and gate
implementations; recomputes source, artifact-manifest, and resource-inventory hashes;
and verifies that scanner inputs and evaluation evidence are members of the relevant
sealed snapshot. Scanner status, exit, coverage, resource, digest, ruleset, and
scanner-domain invariants are evaluated before verdict logic. A fixed target requires
an exact-domain affirmative passed evaluation and, for multiple occurrences, complete
canonical occurrence-token coverage.

Every report consumer starts with `validate_report_payload`. `explain` therefore
cannot project a forged graph that would be rejected by the verifier. Future report
comparison, conversion, and signature layers inherit the same requirement rather than
implementing a second semantic path.

Seven layers with one rule: raw scanner-specific structures exist only inside
adapters, and verdicts exist only in the policy layer. Everything between them
traffics in normalised evidence.

---

## 1. Layers

```
interface     CLI · Python API · composite GitHub Action · pre-commit
                     |
policy        exception records, severity floor, drift decisions -> Verdict
                     |
verification  preflight · validity · target classification · deltas · integrity
              · oracles · agreement          (emits events + evidence, no verdict)
                     |
adapter       checkov · kics · trivy · validators   (only place raw shapes live)
                     |
execution     subprocess runner: arg arrays, deadlines, process-group kill,
              env allowlist, output caps, isolated tmpdir
                     |
domain        immutable typed models, stable sort keys, schema versions
                     |
research      frozen artifact + byte manifest + replay + quarantined legacy profile
```

Dependency direction is strictly downward. The verification layer cannot import an
adapter module; it receives `ScannerRun` objects. The adapter layer cannot import the
policy layer; it has no opinion about pass or fail.

## 2. Package layout

```
src/iac_guard_v/
  __init__.py  api.py  cli.py  config.py  enums.py  models.py
  engine.py            # verification layer: gates P0, V1-V7
  policy.py            # policy layer: events -> decisions -> Verdict
  matching.py          # identity tiers
  fingerprints.py      # versioned fingerprint algorithm
  diffing.py           # multiset deltas
  process.py           # execution layer
  redaction.py  provenance.py  paths.py
  adapters/  base.py registry.py checkov.py kics.py trivy.py tflint.py
             terraform_validate.py opentofu_validate.py kubeconform.py
  oracles/   base.py assertions.py conftest.py
  reporters/ console.py json_report.py sarif.py markdown.py junit.py
  cases/     schema.py loader.py validator.py exporter.py
  schemas/   config-v1.schema.json report-v1.schema.json case-v1.schema.json
  profiles/  hardened.yml
research/
  compat/qrs2026.yml   # NOT under src/profiles: not selectable by the product
  compat/legacy_verify.py
```

`research/compat/` sits outside the package's profile directory deliberately. If the
legacy profile lived in `src/iac_guard_v/profiles/`, a `--profile qrs2026` flag would
eventually work, and the known-unsafe semantics would be one typo away from a
production pipeline.

Existing research paths (`benchmark/`, `runs/`, `results/`, `prompts/`, `scanners/`,
`scripts/`) stay exactly where they are. Relocating them would break external links
and citations for no functional gain, and they are byte-frozen regardless.

## 3. Data flow, repair mode

```
CLI/API args + trusted config
        |
     [P0 preflight]  path safety, artifact kind detection, hashes, config/lock digests
        |
   Artifact(baseline)            Artifact(candidate)
        |                                |
   adapters.scan() -> ScannerRun    adapters.scan() -> ScannerRun
        |         (raw refs + normalised Findings + coverage counters)
        +----------------+---------------+
                         |
                  [V1 validity]  independent parsers, not the scanner
                  [V5 integrity] before any classification is attempted
                  [V2 targets]   ordered classifier, ten outcomes
                  [V3 deltas]    multiset comparison, eleven classes
                  [V4 metrics]   change-risk numbers
                  [V6 oracles]   deterministic, scanner-independent
                  [V7 agreement] EXACT mappings only, advisory
                         |
                    Event stream + Evidence
                         |
                    [policy layer]  exceptions, floors, drift decisions
                         |
                    Report -> reporters -> exit code
```

V5 runs **before** V2 by construction. A classifier that runs first can conclude
"finding absent" from a broken scan; that ordering is exactly audit finding F1.

## 4. Domain objects

| Object | Purpose | Notes |
| --- | --- | --- |
| `Artifact` | a tree plus its detected kind, hashes, file and byte counts, role | immutable |
| `Finding` | normalised finding with the fields in semantics §3.1 | immutable |
| `ScannerRun` | tool provenance, execution status, coverage counters, findings, diagnostics, raw refs | no verdict field |
| `Target` | `(scanner, rule_id, scope)` plus expected occurrence count | |
| `Event` | a classification with evidence references | no pass/fail |
| `Decision` | policy outcome for an event, with the rule that produced it | |
| `GateResult` | gate id, `Status`, reason code, evidence refs | |
| `Report` | schema version, inputs, tools, coverage, targets, deltas, gates, oracles, verdict | deterministic serialisation |

Every model carries a schema version. Reports sort scanners, files, findings, deltas,
gates, and diagnostics by documented stable keys so that two identical runs produce
byte-equal output (semantics §10).

**Deep immutability is a requirement, not a decoration.** A frozen dataclass holding a
caller's `dict` is not immutable: in the reference model, clearing that dictionary after
construction changed an existing verdict from `VERIFIED` to `FAILED`. Every collection
inside a domain object is copied and frozen at construction — tuples of records plus a
read-only index — so a verdict depends only on what was observed when the object was
built.

**Statuses stay typed all the way to the report.** `ScannerRun`, `GateResult`, validator
results, and integrity results carry the full `Status` value through report generation.
Collapsing `ERROR`, `TIMEOUT`, `PARTIAL`, `UNSUPPORTED`, and `INCONCLUSIVE` into one
boolean is what made audit finding F6 possible, and the boolean flags in the
specification reference model are a scenario-writing convenience that product code must
not imitate.

**Immutability must be tested, not asserted.** Two designs that looked immutable were
not: a frozen dataclass holding the caller's `dict`, and a `__slots__` class exposing a
`MappingProxyType` whose *object* was still assignable. Domain collections are frozen
slotted dataclasses whose fields are set only during construction, records are
canonically sorted, and public constructors rebuild rather than alias what the caller
passed. Subclasses and lookalikes are rejected at the boundary, because `isinstance`
would accept an override of `get`.

**Public loaders construct domain types; they never accept preconstructed objects as
evidence of trust.** Configuration and case bundles are parsed into `ExceptionRecord`,
`GateResult`, `RequiredGates` and friends by loaders that stamp provenance themselves.
An `ExceptionRecord` arriving from a candidate is stamped `candidate_head` whatever its
serialised `origin` says, and it must additionally name the event it authorises before it
can permit anything.

**Malformed input is rejected at the boundary.** Configuration, case bundles, and API
arguments are validated against their schemas before anything runs; unknown enum values,
unknown keys, non-boolean flags, and blank identities are usage errors (exit code 2).
Nothing malformed is ever reinterpreted as `PASS`.

## 5. Adapter boundary

```python
class ScannerAdapter(Protocol):
    name: str
    def probe(self, ctx: ExecutionContext) -> ToolInfo: ...
    def supports(self, artifact: Artifact) -> SupportDecision: ...
    def scan(self, req: ScanRequest, ctx: ExecutionContext) -> ScannerRun: ...
    def normalize(self, raw: RawScanResult, req: ScanRequest) -> tuple[Finding, ...]: ...
    def contract(self) -> ScannerContract: ...
```

Rules: an adapter never decides a verdict; never reads global configuration; never
retrieves anything from the network in locked mode; returns `UNSUPPORTED` rather than
guessing an artifact kind; and reports coverage counters even when it fails, because a
failed run's counters are what make `PARTIAL` distinguishable from `ERROR`.

Discovery is via Python entry points (`iac_guard_v.adapters`), so third-party adapters
need no core change. A third-party adapter is untrusted code: it is loaded only when
named in trusted configuration.

## 6. Execution layer

`src/iac_guard_v/process.py`. Argument arrays only, never `shell=True`, so a path, rule
id, or config value cannot become a command. Per-call deadline; on expiry the entire
**process group** is signalled, confirmed dead, then killed — terminating only the direct
child leaves grandchildren holding the workspace, which a test proves by having a child
spawn a helper that would outlive it.

The environment is an allowlist (`PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ`, plus explicit
additions), and a credential denylist is applied **after** the allowlist and after any
caller additions, so a credential cannot be re-admitted by naming it. Output is capped
(default 25 MiB); exceeding the cap terminates the process and yields `PARTIAL` rather
than parsing a truncated document as complete. Each call gets a private `0o700` temporary
directory, exported as `TMPDIR` and removed afterwards.

Every ending is a typed result rather than an exception: `PASS` within a declared exit
contract, `TIMEOUT`, `PARTIAL`, `UNSUPPORTED` for a missing executable, `ERROR` for a
signal death or an exit code outside the adapter's contract. An adapter must declare its
expected exit codes, because success is never inferred from an exit code alone. Evidence
records the command, exit code, duration, and SHA-256 digests of stdout and stderr — never
the output itself, which can contain source and secrets.

Filesystem paths are the one deliberate exception to the exact-type rule: `Path("x")`
returns `PosixPath`, so `type(x) is Path` is never true. Paths use `isinstance` and are
then resolved and checked.

**The host process runner is not a sandbox.** It reduces default credential discovery by
providing an isolated `HOME`, `TMPDIR`, and `XDG_*` hierarchy under a per-command private
scratch root, strips credential-shaped environment variables, resolves executables to
absolute paths from trusted configuration rather than an attacker-controlled `PATH`, and
bounds both stdout and stderr so a hostile child cannot exhaust memory. But it cannot
prevent a child from reading arbitrary absolute host paths, and it cannot enforce network
denial or resource limits without kernel support.

**Native execution is explicitly reduced isolation.** The later container layer
(`--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
`--pids-limit`, `--memory`, `--cpus`, `--user`, `--tmpfs`) is what supplies mount,
network, and resource-limit isolation. Default hostile-PR execution requires the hardened
container mode; host-native execution is appropriate only for local developer use where
the operator is also the author.

D2 includes `process.py` (the secure runner), `redaction.py` (credential/token/path
scrubbing for report-facing output), and workspace-root confinement (cwd must resolve
inside a declared root without symlink escapes).

## 7. Configuration and locking

`.iac-guard.yml` validated against `schemas/config-v1.schema.json` before anything
runs. In PR mode it is loaded from the trusted source (semantics §2); the candidate's
copy is compared and reported as `POLICY_DRIFT` if different. `iac-guard.lock.yml`
records scanner versions, image digests, checks-bundle digest, schema-bundle versions,
and policy hashes; `--locked` makes any drift an error rather than a warning.

## 8. Interfaces

- **CLI**: `verify`, `pr`, `differential`, `scan`, `doctor`, `demo`, `init`, `lock`,
  `explain`, `case …`, and `research replay-qrs2026`. Every command emits the same
  canonical report; formats are projections of it.
- **API**: `verify(VerificationRequest) -> Report`. Explicit configuration in, typed
  report out, no hidden global state.
- **Action**: composite, not a Docker container action, because container actions
  cannot set network, mount, user, or resource options (threat model §4). Docker
  isolation is the default and only supported mode for untrusted content; a native
  mode exists as opt-in `reduced-isolation` and never auto-substitutes.
- **Pre-commit**: fast changed-path profile; the heavy multi-scanner profile is for
  pre-push and CI.
- **MCP server**: deliberately deferred. Not a v1 concern.

## 9. Research compatibility layer

The frozen artifact is protected by `research/verify_byte_manifest.py` (4,842 files,
no normalisation) and reproduced by `research/replay_from_frozen_runs.py` (630 records,
10,080 field comparisons, then a canonicalised comparison of seven derived tables).
Legacy semantics are reachable only through `research/compat/legacy_verify.py`, which
requires an explicit acknowledgement, refuses to run on scanner drift, labels output
`LEGACY_REPLAY_RESULT`, and never exits 0.

## 10. What is deliberately not here

No model SDK anywhere in the runtime dependency set; no telemetry; no network calls in
locked mode; no policy engine of our own beyond exceptions and floors; no attempt to
re-implement scanner rules; and no web UI, IDE extension, or MCP server before the
core, CLI, reports, tests, and Action are dependable.

## 11. D2.2 Execution Layer Hardening

Ten security defects in the execution layer were independently reproduced and closed
in phase D2.2:

### Process group lifecycle (Defect A)
After the command completes (normally OR by timeout), the runner always verifies the
process group is gone using `os.killpg(pgid, 0)`. If the group persists:
1. SIGTERM → wait for group disappearance → SIGKILL → wait → reap leader.
2. If the group cannot be eliminated: status=ERROR, reason=PROCESS_GROUP_CLEANUP_FAILED.
3. If leader exited cleanly but descendants were found: status=ERROR,
   reason=LINGERING_DESCENDANTS_TERMINATED.

### Combined output cap (Defect B)
The combined invariant is enforced: `stdout_retained + stderr_retained ≤ max_output_bytes`.
When the combined cap is reached, the larger stream is trimmed first.

### Redaction (Defect C)
`canonical_dict()` calls `redact_argv` and `redact_detail`. Sensitive option values
(after --token, --password, --secret, --api-key, --header) are fully redacted.
POSIX absolute paths (/Users, /home, /mnt, /private, /tmp, /var) and Windows paths
(C:\...) are redacted but URLs are preserved. `display_command` is shlex-quoted and
redacted.

### Cleanup gate (Defect D)
If scratch cleanup fails and the command otherwise succeeded: status=ERROR,
reason=SCRATCH_CLEANUP_FAILED. If already non-PASS, a diagnostic is appended.

### Consistency (Defect E)
`CommandResult.__post_init__` rejects: PASS+timed_out, PASS+truncated, PASS+killed_signal,
PASS+scratch_cleanup_success=False, TIMEOUT+timed_out=False,
COMPLETED_WITHIN_CONTRACT+non-PASS, DEADLINE_EXCEEDED+timed_out=False.

### Isolated PATH (Defect F)
Child PATH = `/usr/bin:/bin:/usr/sbin:/sbin` + `trusted_helper_dirs`. Parent PATH is
never inherited. LD_PRELOAD, LD_LIBRARY_PATH, DYLD_*, PYTHONPATH, PYTHONHOME, BASH_ENV,
ENV, NODE_OPTIONS, RUBYOPT, PERL5LIB are blocked.

### Workspace boundary (Defect G)
`workspace_root` is mandatory when `cwd` is supplied. If neither is supplied, the
private scratch is used as cwd.

### Resolved executable (Defect H)
`resolved_executable` field on CommandResult. `canonical_dict` includes it with machine
paths redacted but binary name preserved.

The D2.2 statements above are the historical gate record. D2.3 supersedes their
incomplete redaction, cleanup-finalisation, process-group uncertainty, result-invariant,
and path-validation details.

## 12. D2.3 Process-boundary closure

`CommandRequest` accepts adapter-supplied sensitive option names and argument indices
only after exact-type, bounds, duplicate, syntax, control-character, line-break, and bidi
validation. Both forms are copied into `CommandResult`; `display_command()` and
`canonical_dict()` use the same redaction metadata. Absolute executable arguments are
reported as a basename/tool identity, never as an absolute `argv[0]`.

The runner resolves the executable strictly to an executable regular file outside the
evaluated workspace. Immediately before `Popen`, it re-resolves and identity-checks the
workspace root, cwd, every trusted helper directory, and the executable. A changed path,
cwd escape, helper moved into the workspace, workspace-contained executable, or symlink
resolution into the workspace raises `ProcessPolicyError` before spawn.

This revalidation reduces the interval and straightforward exploitability of TOCTOU path
replacement. It does **not** make native execution a complete sandbox or remove the race
between the final check and the kernel's path lookup. Hardened container execution remains
required for hostile pull requests.

One `CommandResult` is finalized after scratch cleanup. It carries a closed
`ProcessReason`, the primary execution event, typed cleanup diagnostics, explicit
process-group cleanup attempted/success fields, scratch cleanup success, and separate
observed/retained byte counts. Output digests cover retained bytes only. The invariant
table permits only executable status/reason combinations and rejects contradictory
timeout, truncation, cleanup, signal, exit-code, and executable evidence.

Process-group inspection has three values: `ABSENT` only for `ESRCH` /
`ProcessLookupError`, `ALIVE` after a successful existence probe, and `UNKNOWN` for
`EPERM` / `PermissionError` or any other inspection error. A timeout or output-limit
event whose group cleanup is unconfirmed becomes
`ERROR/PROCESS_GROUP_CLEANUP_FAILED`; the original event remains in
`primary_execution_event`.

## 13. D3 fingerprints, matching, and finding deltas

`fingerprints.py` owns the current `iacgv2` algorithm, scan-root path canonicalisation, Terraform resource
address validation, and Kubernetes object identity construction. Temporary scan roots
are removed before a finding is built. Deterministic occurrence indices remain display
ordinals only and are excluded from authority. `iacgv2` binds stable native occurrence
evidence when available, and that native fingerprint is also retained in its own field.

`matching.py` accepts exact built-in finding collections, reconstructs their values, and
rejects duplicate full evidence records, forged stored fingerprints, and scanner/version
run-identity drift. A Checkov run may contain several artifact domains; each equal domain
is matched independently and a one-sided domain remains unmatched. Stable native
occurrence evidence is consumed first. Remaining no-native multiplicities use location
only when equal cardinality and an identical unique location multiset prove the pairing;
cardinality/location churn makes the whole group `MATCHING_INCONCLUSIVE`, even if one old
location is reused.

`diffing.py` projects proven matches into the six delta classes established by finding
evidence alone and carries matching ambiguities beside the deltas. Each public delta
constructor proves its semantic predicate, including complete resource-set evidence for
scope expansion. The five classes needing engine, coverage, plan, diagnostic,
control-map, or policy inputs remain unavailable at this boundary and are deferred to
D5. Different resource addresses never relocate.

Derived matching/diffing objects carry noncanonical factory provenance, and adapter-owned
scanner/target evidence is marked separately from caller-created model objects. The D5
production API must accept paths, target identities, and protected policy/configuration,
then invoke adapters and comparison internally; it has no field for caller-precomputed
scanner runs, matches, ambiguities, deltas, or target evidence.

## 14. D4 Checkov adapter

`adapters/base.py` owns the immutable scanner contract and closed adapter-reason family;
`adapters/checkov.py` is the only module that interprets Checkov JSON. D4 deliberately
contains no Trivy implementation.

The trusted Checkov request pins the resolved launcher digest, installed environment and
policy-inventory digests, supported version, framework set, independently eligible
paths/resources, and—for Kubernetes—the canonical object identities established outside
Checkov. Expected resources bind file, canonical address, artifact kind, and native
lookup identity. Every eligible file is portably bound by relative path, type, size, and
SHA-256; device/inode remain private runtime checks. Immediately before execution, the
adapter revalidates all identities and streams the bounded descriptor bytes to the
private view.

Checkov discovers `.checkov.yml` in the directory passed with `-d` even when an explicit
config file and private process cwd are used. The adapter therefore builds a private
eligible-file view, preserving repository-relative paths but excluding candidate policy,
custom checks, and unrelated content. It supplies an adapter-owned config, disables
downloads/uploads, and uses the D2 process runner. The view narrows policy injection and
read races; native execution remains reduced isolation.

Normalization uses strict duplicate-key JSON parsing and retains passed, failed, skipped,
and supported unknown records as typed `CheckEvaluation` evidence. Bucket/result
contradictions are errors; unknown future buckets and aggregate-only counts are partial.
Coverage comes from observed evaluation paths/resources, not the eligible count. The
machine invocation omits `--quiet`, because target absence is not proof: only an
affirmative native pass can support resolution. Reports separate launcher, installed
environment, policy inventory, invocation/config, process-output, and raw-JSON digests.
File and resource coverage have distinct typed counters. Missing/unexpected resources,
resource-count disagreement, absent independent inventory, or contradictory evaluation
claims cannot pass. Empty independent scope is skipped. Trusted input count/byte limits
are part of invocation identity and enforced through streaming preparation.

D4.3 makes strict JSON depth a byte-level adapter contract: a string-aware structural
scan rejects nesting beyond 128 with `JSON_DEPTH_EXCEEDED` before `json.loads`. This
removes dependence on CPython's version-specific recursion behavior while retaining the
decoder for syntax, balance, and duplicate-key validation.

## 15. D5 verification engine

`engine.py` owns the executable P0/V1--V7 orchestration boundary. Its request contains
two independently discovered Checkov plans, target selectors, and one loader-attested
`TrustedVerificationConfigBundle`. Required gates, framework/scanner locks, limits,
severity/location policy, governed configuration, and gate-registry identity exist only
inside that bundle. A public Checkov request is only an untrusted discovery input: the factory
ignores its resource inventory, performs bounded no-follow reads, detects supported
Terraform and Kubernetes resource identities from those bytes, and binds the resulting
inventory to a digest. It has no
field for a scanner run, finding match, multiset comparison, matching ambiguity, delta,
diff result, target evaluation, target outcome, or verdict.

The engine invokes the adapter twice and invokes `evaluate_checkov_target` and
`diff_findings` itself. Adapter, matching, diffing, target-outcome, and aggregate engine
objects must all carry their private in-process factory provenance before aggregation.
Validator and oracle implementations are invoked as trusted in-process gate executors
selected by the execution layer; their identity must equal the requested gate id. They
are dependencies, not JSON/config fields. Without an executor, the named gate is
explicitly `UNSUPPORTED`, never defaulted to `PASS`.

Target classification uses typed statuses for integrity, ruleset stability, structural
eligibility, file/resource presence, suppression absence, occurrence sufficiency, and
affirmative target-pass evidence. It follows verification semantics section 4. A zero
candidate count reaches `FIXED` only with affirmative native pass evidence bound to the
target file and artifact domain. More than one baseline occurrence requires complete
native occurrence-token coverage or an independent complete-target oracle; arbitrary
positive-key counts never suffice. Matching ambiguity, a
mismatched baseline occurrence count, or an unknown structural predicate yields
`INCONCLUSIVE`.

Baseline/candidate scanner execution identity compares scanner, scanner version,
launcher, installed environment, policy inventory, and invocation/config digests. D5
derives a real P0 record from its bound plan, immutable V4 metrics, and typed evaluations
for all five engine-owned delta classes. Unknown new-finding severity is uncertainty,
not a value below the severity floor. Resource inventory loss is a visible destructive
event. Suppression detector completion is separate from a target suppression event so
that D6 can apply an exact protected exception. D5 emits evidence and events only; it
cannot emit a verdict.

D5.2 resolves every target to file, artifact kind, and scanner-native resource identity
before scanning. Repeated addresses across roots are ambiguous without an explicit
selector. Destructive events retain full `ExpectedResource` keys, so a permitted target
deletion cannot erase an unrelated same-address deletion. Governed paths are hashed
mechanically, and the production runner calls only the versioned Terraform/Kubernetes
gate registry; no arbitrary callback is exposed.

D5.3 makes comparison direction part of the evidence. The configuration binds distinct
baseline/candidate roots; role-specific re-attestation binds each `TrustedScanPlan` to
its role, byte-manifest digest, and configuration digest. Swaps and same-root requests
are rejected before adapter execution. The production registry is a closed table of
packaged gates with implementation version/code digests and artifact support; callable
injection exists only in test code. Checkov failed and positive evaluations use the same
context-bound `checkov-occurrence-v1` token. The configuration also carries a
factory-attested policy-source authorization that D6 must match.

## 16. D6 policy layer

`policy.py` is the only layer that constructs `Verdict`. Its request requires a
factory-proven D5 `VerificationResult` and a private-loader-attested
`TrustedPolicyBundle`. It has no fields for a caller evaluation date, raw exception
record or policy, optional gates, optional-gate origin, target outcomes, deltas, or
scanner evidence.

The base-commit loader binds bytes from a mechanically resolved Git commit object, not
an arbitrary path bearing a caller-written label. The protected-policy-repository loader
requires an exact pinned commit and a repository outside the evaluated workspace.
Explicit operator loading remains a distinct `OPERATOR` mode and is never auto-selected
for PR verification. These loaders stamp source origin independently of serialized
claims, capture the current UTC date from a trusted execution clock, and load optionality
from that same protected document. Candidate loading always stamps `CANDIDATE_HEAD` and
returns no trusted bundle. The bundle records commit/repository identity, trusted digest,
candidate state/digest, and path-by-path governed evidence. Candidate file reads are
bounded and no-follow; Git policy entries must be regular files; JSON is duplicate-free
and depth-bounded.

The policy layer independently rebuilds decisions from engine classifications. It finds
an exact file/artifact/native-resource-bound target, event-specific, loader-stamped,
in-force exception; permission is
never copied from a caller-authored decision. A permitted event remains in the result
with its outcome and exception id. Missing, wrong-event, wrong-target, untrusted,
not-yet-valid, and expired records remain visible as unpermitted decisions.

The report retains the trusted source identity/origin, trusted digest, candidate
presence/digest evidence, differing
governed paths, UTC evaluation-time evidence, and the exact source of each applied
exception. Loader-observed policy drift is a definite failure even when an earlier
caller-supplied digest claimed stability. A completed suppression detector does not fail
merely because it emitted `SUPPRESSED`; D6 applies the exact event-specific disposition.

D6.3 inserts `TrustedExecutionContext` above the Git-object reader. It is the authority
for execution mode, evaluated repository identity, exact base/candidate commits,
governed paths, protected-repository pin, verification-config identity, and UTC clock.
The base loader no longer accepts `TrustedGitSource`; that type proves object existence
only. Policy aggregation cross-checks the D6 context/repository/commit against D5's
factory-bound authorization. Repository identity is portable Git-object evidence, not a
hash of a local absolute path, and candidate policy reads inspect every parent component
for symlinks.

The section-7 order is executable: any operational uncertainty dominates a definite
negative result and yields `INCONCLUSIVE`; validators/oracles that affirmatively fail,
policy drift, unresolved targets, and failed regression/suppression gates yield
`FAILED`; only the remaining fully evidenced state is `VERIFIED`. `PolicyResult` binds
the closed verdict to exit code 0, 1, or 3 and carries private policy-factory provenance.

## 17. D4.5 parser-backed discovery

The trusted scan-plan factory uses `python-hcl2` for every required `.tf` file. YAML is
first inspected as bounded syntax nodes so ordinary workflows and CloudFormation tags
can be classified without Kubernetes-only construction; Kubernetes-like documents then
receive duplicate-key, safe-tag, alias, depth/document/node, UTF-8, and identity checks.
Generic JSON is strict, duplicate-free, depth-bounded, and expands Kubernetes `List`
items. `.tf.json` remains explicitly unsupported. `TrustedScanPlan` records the digest,
syntax, classification, and resource set of every inspected supported-extension file,
including non-Kubernetes YAML/JSON that is not copied to the scan view.

## 18. D4.6 scanner installation and mixed-repository closure

The Checkov adapter rejects symlinks anywhere under the installed `checkov` package,
including checks and policies, instead of silently omitting them from an asserted-complete
identity. Mutable bytecode caches are excluded. Reports separate launcher, installed
distribution, dependency-lock/runtime, built-in policy, disabled custom-check, and
invocation-contract digests. The invocation contract is named
`checkov-adapter-contract-v3`; parser, coverage, policy-input, artifact, invocation, or
normalisation changes require a version increment.

YAML classification is two-stage. A bounded syntax-node pass checks structure and
duplicate keys but applies Kubernetes-only tag and alias restrictions only to a root
document carrying Kubernetes identity. Ordinary workflow, OpenAPI, and CloudFormation
documents therefore remain classified evidence even when they use aliases, custom tags,
or nested fields named `kind`. Nested complete Kubernetes identity outside a supported
root shape and unsafe Kubernetes roots still fail closed.

## 19. D5.4 sealed verification snapshots

Each role has one factory-proven `SealedVerificationSnapshot`. It contains the portable
source-state root, all inspected supported-file bytes and classifications, expected
resources, governed-entry types/digests, role, repository identity/subpath, resource
inventory, and protected configuration identity. Checkov revalidates and copies exactly
the plan-bound eligible bytes; packaged validators and oracles consume the same in-memory
sealed bytes and never reread the mutable source root. Target presence and V4 metrics use
the sealed inventories.

Immediately before `VerificationResult` construction, P0 re-enumerates the live role
roots. Any added, removed, changed, type-replaced, or symlinked supported/governed entry
produces `ERROR/SNAPSHOT_CHANGED_DURING_VERIFICATION`. Canonical configuration and
snapshot evidence use portable repository/snapshot/subpath identities, not local
absolute paths. The result retains both complete role snapshots. Gate implementation
identity hashes the dispatcher, parser/classifier helpers, contract version, and parser
dependency versions rather than one dispatcher function.

## 20. D6.4 candidate-tree and governed-directory attestation

Protected policy evaluation now binds the mutable candidate checkout to the authorized
Git candidate before context creation and revalidates it immediately before loading
policy. The checkout must have the authorized `HEAD`, no staged or unstaged changes, no
untracked input, and no ignored supported or governed input. Candidate policy and
governed bytes are then read from the authorized candidate Git object, not the live
working tree. The policy bundle's candidate snapshot digest and repository-relative
prefix must equal D5's sealed candidate snapshot.

`repository_relative_candidate_prefix` is explicit for monorepos and prefixes both base
and candidate object reads. Governed Git entries are typed as absent, regular file, real
directory, symlink, or other. Directory identity binds a bounded deterministic recursive
manifest; a symlinked governed directory remains visible drift rather than disappearing.
Canonical policy evidence records portable repository, commit/tree, prefix, governed
digest, configuration, and sealed-snapshot identities; absolute checkout paths remain
runtime-only.

## 21. D4.7 shared filesystem and scanner-environment inventory

One bounded `lstat`/no-follow inventory now supplies snapshot state, artifact discovery,
scan-plan construction, governed-path evidence, and final revalidation. It records every
symlink and every supported or governed entry with an exact path type; only regular files
are parsed. Directory symlinks are recorded but never traversed, and unsafe or special
entries make P0 `ERROR/ARTIFACT_UNIVERSE_UNRESOLVED`. Sealed snapshots and canonical
results bind successful classifications and rejected entries alike.

The native Checkov identity separately binds launcher bytes, installed Checkov bytes,
built-in policy bytes, custom-check state, interpreter bytes, and the actual installed
dependency-tree bytes. Mutable bytecode/cache entries are rejected rather than excluded.
Symlinks or non-regular
content in the verified package/dependency tree are rejected. Native execution remains
reduced isolation; a native environment whose complete identity cannot be established
cannot support `VERIFIED`.

## 26. D4.8 executable scanner environment

The native scanner boundary verifies installed executable files against wheel `RECORD`
SHA-256 and size evidence, binds the verified RECORD closure, and rejects missing,
extra, escaping, symlinked, or bytecode/cache code. Checkov runs with
`PYTHONDONTWRITEBYTECODE=1`; a post-process identity check detects runtime mutation.
Failure is typed scanner-environment uncertainty and reduced-isolation cannot upgrade it.

## 27. D5.6 validator and portable snapshot provenance

Gate evidence separates the gate contract version, IaC-Guard-V implementation digest,
verified parser-distribution/code digest, and schema/loader contract digest. The parser
digest verifies installed `python-hcl2` and PyYAML RECORD-backed bytes and also binds the
active parser callable behavior. Canonical filesystem evidence never contains raw link
target text: it records only absolute/relative kind and a SHA-256, while private runtime
state retains the text for revalidation.

## 22. D5.5 complete gate and result provenance

The production gate registry binds a canonical manifest of the dispatcher, Terraform
wrapper, Kubernetes YAML/JSON classifiers, bounded loaders, duplicate-key/depth/alias
guards, source reader, and shared inventory helpers. It separately binds parser
dependency names and versions. Canonical configuration and results expose every ordered
gate implementation record rather than only a registry label. Role snapshots expose the
complete filesystem inventory, including rejected entries, without absolute host paths.

## 23. D7 public boundary and report-v1

`config-v1` accepts only baseline/candidate paths, exact target selectors, the closed
framework set, and an execution-isolation choice. It cannot carry scanner runs,
resource inventories, deltas, callbacks, policy records, provenance assertions, locks,
or evaluation time. The Python API rebuilds scanner/config/policy evidence internally.

The default is `hardened-container`. Because the Phase E image is not implemented, that
mode returns `INCONCLUSIVE/HARDENED_CONTAINER_UNAVAILABLE` (exit 3) and never falls back
to native execution. `reduced-isolation` requires an explicit operator-selected Checkov
executable and is labelled accordingly. `report-v1` is the sole canonical result;
console output is a projection. It retains complete gate, scanner, snapshot, artifact,
policy and decision evidence.

## 24. D9 frozen legacy-versus-hardened analysis

`research/compat/compare_legacy_hardened.py` reads the 630 frozen stored run records,
patches and 70 stored baseline Checkov documents. It executes no scanner and no model.
It locally recomputes only deterministic Phase-D parser/resource evidence, binds every
input set by a manifest digest, and leaves all frozen bytes unchanged.

Historical candidate outputs lack affirmative per-target evaluations, execution and
coverage identities, sealed snapshots, and trusted policy provenance. D9 therefore
classifies all hardened results as `INCONCLUSIVE`; it never manufactures `VERIFIED`
from legacy booleans. Its output is an analysis record, not report-v1 or a production
verdict.

D9.1 names this a historical hardened-evidence sufficiency comparison, records the
actual installed parser-code and IaC-Guard-V implementation digests, and distinguishes
local parser `PASS`, `FAIL`, `UNSUPPORTED`, and `ERROR`. The canonical analysis renders
the committed `LEGACY_VS_HARDENED.md` deliverable; neither is a production verdict.

D9.2 fixes that analysis to a digest-selected Python 3.11.14 linux/amd64 image and a
fully hash-pinned dependency closure. `D9_ENVIRONMENT.json` binds every wheel and
installed-code digest. The image build verifies the physical environment and asserts
byte equality for canonical `D9_ANALYSIS.json` and its generated Markdown. Transition
labels are rendered only from computed counts; no scanner, model or benchmark inference
is invoked.

## 28. D7.1 closed public contract

`report-v1` is a closed four-branch state machine: verification `VERIFIED/0`,
`FAILED/1`, `INCONCLUSIVE/3`, or operational uncertainty `INCONCLUSIVE/3`. Runtime
validation uses the shipped schema and additionally enforces top-level/policy agreement.
Verification reports carry explicit execution-isolation evidence. `config-v1` encodes
the native-executable condition and rejects same or nested role roots. The offline
`demo` and read-only `explain` commands introduce no verification evidence.

## 29. D7.2 semantic report contract

JSON Schema establishes closed shape and branch pairing; a mandatory semantic validator
then replays the report state table. A `VERIFIED` report requires passing preflight,
scanner/run/ruleset integrity, every configured validator and oracle, regression and
suppression gates, no ambiguity or adverse engine event, and exact target-to-policy
decision agreement. `FAILED` requires decisive negative evidence without operational
uncertainty. `INCONCLUSIVE` requires typed uncertainty. Full verification evidence may
only pair with full policy evidence; definite candidate-artifact failure evidence may
only pair with its restricted artifact-failure policy branch.

## 30. D5.7 physical parser implementation identity

The packaged validators contribute `PASS` only when python-hcl2, PyYAML, packaging and
their active runtime dependency closure have complete, hash-valid wheel `RECORD`
evidence. A no-follow physical inventory rejects bytecode/cache entries, unlisted
content, missing or mismatched files, unsafe file types, symlinks and path escapes.

Validator execution disables bytecode writing through both the interpreter switch and
`PYTHONDONTWRITEBYTECODE=1`, then recomputes the environment identity. Missing or
changed implementation evidence is typed `INCONCLUSIVE` and cannot support `VERIFIED`.
This proves installed-manifest consistency; protected locks bind vendor provenance.
## D7.4 reconstructible public evidence graph

Public `report-v1` validation reconstructs the protected verification configuration
identity from its complete canonical children: role snapshots and repository subpaths,
scanner and framework locks, invocation limits, severity and location policy, required
gates, governed configuration, source authorization, and gate implementation records.
It also re-derives finding deltas, regression, the five engine events, governed drift,
resource metrics, and exception application from their authoritative child evidence.
Repeated digest strings are never accepted as proof of those relationships.

The packaged public validator rejects private synthetic gate registries. A private
test-only path remains available to exercise trusted factories without making that
provenance acceptable to `explain` or another public report consumer.

## E1 locked KICS evidence adapter

The KICS adapter is a scanner-evidence producer only. Its request is factory-bound to
the exact E0.3 lock seal and one digest-qualified architecture child. It builds a
private byte-bound input view, executes v2.1.20 with no network and a read-only root,
strictly parses the native JSON, retains `similarity_id`, and reconciles native file and
resource coverage with the independent inventory. KICS does not yet participate in
multi-scanner consensus or verdict formation.

E1.1 completes the native contract: all six result exits are parsed, `--pull never`
prevents registry access, summary types/arithmetic are closed, TRACE/BOM is separate,
and official optional fields remain optional. Clean KICS output remains negative
scanner evidence, not affirmative per-resource target-pass evidence.

E1.2 additionally requires result-exit/highest-severity agreement, validates every
required v2.1.20 query/file field, preserves official BOM records, and makes failed
similarity-ID computation explicit matching-identity uncertainty.

## E2 externally locked Trivy evidence adapter

Trivy executes only the E0.3 digest-qualified v0.73.0 platform child with the external
v2.2.0 checks cache mounted read-only, networking disabled, updates disabled, and the
sealed input view mounted read-only. Binary/image and external-policy identities remain
separate. The adapter hashes the complete no-follow checks cache immediately before and
after execution and derives fallback state from current diagnostics and cache evidence.

Strict native JSON parsing retains both FAIL and `--include-non-failures` PASS records.
Only exact per-file/resource records establish coverage; repository-global positives
remain aggregate evidence. Missing or changed cache, embedded fallback, malformed or
unknown output, and incomplete coverage are typed non-PASS. E2 does not alter the final
policy verdict or implement multi-scanner consensus.

E2.1 replaces a caller-selected cache directory with a signed-cache identity created by
the E0.3 physical verifier. The complete Trivy subtree is compared before and after

## E1E2.3 protected runtime authority

Protected operator/workflow plumbing constructs the portable Phase-E evidence bundle
and live-attested container runtime. Scanner requests contain those opaque capabilities
and cannot select `docker` or another executable. The process runner executes the exact
capability path with the locked argument vector; request bytes, runtime identity,
process evidence, and bounded output evidence form one execution chain.
execution. Contradictory pass/fail records for one evaluation identity fail closed.
Validated volatile report metadata is omitted from the semantic digest while exact
native bytes retain a separate hash.

E2.2 preserves official `EXCEPTION` as skipped/suppressed evidence, handles documented
omitted fields conservatively, and carries the complete signed E0.3 cache capability
into portable execution evidence without exposing its filesystem path.

## E1/E2 trusted execution boundary

Production adapters expose sealed request construction and `scan`; native normalization
is not a public evidence factory. A trusted scan binds the locked argv to the actual
`CommandResult`, private scan view and output bytes, plus pre/post source and cache
revalidation. Test fixture capabilities live only under `tests/` and are excluded from
wheel and sdist contents; no product module contains a test evidence factory.

E1/E2.2 applies one hardened Docker contract to both adapters: no pull, no network,
read-only root, all capabilities dropped, no-new-privileges, PID/CPU/memory limits,
and explicit non-root UID/GID. The complete writable output directory is inventoried
twice with no-follow reads; only the expected regular JSON file is allowed and its
portable semantic manifest is retained.

## E1.3 KICS coherent native evidence

The KICS boundary now returns `KicsExecutionEvidence`: its trusted scanner run plus
the runtime/image/invocation identities and separate raw, semantic, and physical output
identities. Query/file severities, summary counters, exit, scan path, ordinary/BOM
query totals, and pinned issue-type vocabulary form one validated evidence graph.

## E2.3 Trivy locked execution provenance

The Trivy execution object binds one protected runtime, platform image, external checks
bundle, complete signed cache, invocation, process streams, results file, semantic JSON,
and physical output directory. Full-cache and scanner-subtree inventories are checked
before and after the process. Fallback/source state is recomputed from current evidence.

## E3.1 offline Terraform-family validation

The closed validator package produces immutable `ValidatorExecutionEvidence`; only its
internal execution constructor marks evidence trusted. OpenTofu and Terraform have
separate gate and E0.3 environment identities. OpenTofu uses locked 1.12.5. Terraform
is a protected preloaded 1.15.8 operator runtime and is never acquired or shipped.

Each invocation consumes a private materialization of sealed input evidence and
revalidates source bytes and the live runtime around execution. Candidate transient
state and configuration cannot enter the view. Provider/module initialization need is
`INCONCLUSIVE`, not a fabricated validation result.
