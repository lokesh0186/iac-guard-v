# Architecture

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

Argument arrays only, never `shell=True`. Per-call deadline; on expiry the entire
process group is terminated and termination is confirmed. Environment is an allowlist
(`PATH`, `HOME`, plus explicit additions); cloud, Kubernetes, and GitHub credentials
are stripped. Output is capped (default 25 MB) and exceeding the cap yields `PARTIAL`,
not truncated-and-parsed. Each scanner gets an isolated temporary directory with
restrictive permissions, removed on exit. Every command, its exit code, and stdout and
stderr digests are recorded as evidence.

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
