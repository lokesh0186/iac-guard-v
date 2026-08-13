# Product Specification

## D7.5 public outcome release condition

All ten target outcomes in a public report are derived from exact rule, resource,
file, artifact, scanner-version, snapshot, and evaluation evidence. Policy exceptions
may change the disposition of a proven event only. They cannot create a suppression or
deletion event. Identical role snapshots cannot claim a differential repair.

Every supported or governed filesystem entry, including rejected non-regular entries,
is represented in the sealed artifact graph. A public `PASS` preflight is impossible
when that graph contains unresolved or rejected input. Native scanner execution
identity is recomputed from a complete canonical component manifest.

## D7.3 report-graph release condition

A public verification report is accepted only when its complete canonical evidence
graph is internally consistent. Arrays carrying targets, decisions, gates, scanner
evidence, snapshot files, and inputs reject duplicate authoritative identities before
lookup. Full reports contain exactly one evaluation for each engine-owned delta class.

Protected configuration, gate records, role snapshots, scanner inputs, resource
coverage, target outcomes, and policy decisions must describe the same sealed bytes and
identities. Snapshot-derived hashes are recomputed from child evidence. Fixed outcomes
require affirmative scanner or explicitly complete oracle evidence; exception metadata
cannot be attached to a fixed outcome. Isolation evidence must satisfy the selected
execution mode before a verified verdict is valid.

## 1. Problem

Scanners report what they observe at a point in time. They do not answer the question a
reviewer actually has about a proposed infrastructure change: **did this change fix the
thing it claimed to fix, without hiding findings, deleting the resource, losing scanner
coverage, or turning a scanner failure into a pass?**

Answering that requires comparing two states with resource-level identity, verifying
that the scanner actually ran properly, and distinguishing a repair from an evasion.
The research harness in this repository demonstrated the value of asking the question
and, as the audit records, could itself be fooled by an empty scanner result
(F1), a suppression comment (F4), or a finding that moved to another resource (F3).

## 2. What this product is and is not

**Is**: a scanner-agnostic differential verifier. It runs scanners, normalises their
findings, classifies what happened to specific targets, detects regressions and
evasions, verifies the scan itself was trustworthy, and emits a deterministic report
with a typed verdict and stable exit codes.

**Is not**: another scanner. It ships no policy catalogue of its own beyond a small,
evidence-backed cross-scanner control map. It does not need AWS, Bedrock, an LLM API,
or any cloud credential. It does not phone home.

## 3. Personas and their requirements

### A — IaC repository maintainer
One workflow step produces a PR summary showing what was resolved, what appeared, what
suppressions changed, whether the scan was trustworthy, and a verdict. The same command
runs locally with no account. One required scanner, others advisory. Severity floors and
exceptions with reasons and expiry. A scanner crash **cannot** pass the pipeline.

### B — AI coding-agent or repair-system developer
A stable API and CLI taking before and after trees plus targets, returning a versioned
JSON report. Feedback distinguishes unresolved target, new finding, suppression,
resource deletion, scanner error, and oracle failure, so a retry loop can act on the
difference. The verifier calls no model itself.

### C — Scanner maintainer
A reported discrepancy reproduces from a tiny fixture using native scanner commands
only — no IaC-Guard-V install required. Exact versions, an independent oracle, raw
output digests, and a proposed project-native regression test are included.
Suppression, partial scan, unsupported syntax, and version drift are excluded before
the report exists.

### D — Researcher
The QRS 2026 artifact reproduces from an immutable tag with no model calls. The case
format and report schema are reusable. Provenance and limitations are documented,
including which historical facts were never recorded.

### E — Enterprise or regulated team
Offline operation with pinned digests, no telemetry, no source upload, no inherited
cloud credentials, deterministic reports, published threat model, SBOM, and signed
artifacts.

## 4. Functional requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| F-01 | Compare baseline and candidate trees for Terraform HCL and Kubernetes YAML | P0 |
| F-02 | Classify each target into exactly one of the ten outcomes | P0 |
| F-03 | Compute the eleven delta classes over finding multisets | P0 |
| F-04 | Verify scanner execution integrity before classification | P0 |
| F-05 | Establish syntax and schema validity independently of the security scanner | P0 |
| F-06 | Detect suppressions, deletions, scope loss, and policy drift as distinct events | P0 |
| F-07 | Load policy and exceptions from a trusted source, never from the candidate | P0 |
| F-08 | Emit a versioned canonical JSON report plus a human console report | P0 |
| F-09 | Exit 0/1/2/3/4 per semantics §9 | P0 |
| F-09a | Validate every input at the boundary: enum membership, boolean types, date types, non-blank canonical identity and scope, valid line ranges, closed optional-gate names. Malformed input is exit code 2, never `PASS` | P0 |
| F-09b | Require explicit gate evidence: preflight, integrity, at least one validator, regression policy, suppression policy. No gate result is ever defaulted to `PASS` | P0 |
| F-09c | Take evaluation time from the execution context, record it in the report, and treat exception windows as inclusive on both bounds | P0 |
| F-09d | Deeply immutable domain objects: collections copied and frozen at construction, canonically ordered, rebuilt rather than aliased, with subclasses and lookalikes rejected, so no later external mutation can change a verdict | P0 |
| F-09e | Separate validators for identifiers, resource scopes, and repository paths; reserved placeholders rejected; `target_scope` mandatory with no default; identifiers Unicode-normalised before duplicate detection | P0 |
| F-09f | Required gates are named identities: observed gate results must cover exactly the required set, and missing, duplicate, or substituted gates are invalid requests | P0 |
| F-09g | Every exception names the events it authorises (`permitted_outcomes`, no default). Approving suppression does not approve resource deletion or file renaming | P0 |
| F-09i | Target identity is the structured `(scanner, rule_id, scope)` tuple; authorisation never binds a concatenated display string | P0 |
| F-09j | A `ScannerRun` constrains its findings' scanner and version, and rejects duplicate exact finding identities; adapters assign occurrence indices after a documented canonical sort | P0 |
| F-09k | The policy boundary accepts only exact built-in containers, snapshotted once | P0 |
| F-09l | Validate report semantics after schema validation: verdict, exit, gate, scanner, target, event and policy evidence must satisfy one closed state-table branch | P0 |
| F-09m | Bind the complete physical parser dependency closure, reject executable bytecode/unlisted/symlinked/escaping content, and revalidate it around packaged validator execution | P0 |
| F-10 | Process runner provides isolated HOME/TMPDIR/XDG (no real home credential exposure), absolute executable resolution (no PATH=. injection), bounded stdout AND stderr, wall-clock deadline enforcement even after streams close, process-group termination (no surviving descendants), and scratch cleanup diagnostics | P0 |
| F-11 | Report-facing command text is redacted: credential-shaped values, authorisation tokens, and machine-specific paths never enter canonical report data | P0 |
| F-12 | Working directory must resolve inside a declared workspace root without symlink-component escapes; traversal and outside-root cwd are rejected | P0 |
| F-13 | Process execution objects (CommandRequest, CommandResult) are frozen, slotted, and runtime-validated: environment names/values checked before spawn, no raw ValueError escapes, no caller-owned mutable dicts retained | P0 |
| F-09h | Domain objects are frozen and slotted with no `__dict__`; nested records and collections are reconstructed into exact built-in types and canonically ordered; subclasses are rejected at security boundaries | P0 |
| F-10 | `doctor` reports detected tools, versions, support, and exact install guidance | P0 |
| F-11 | `demo` shows verified, failed, suppressed, and inconclusive on bundled fixtures | P0 |
| F-12 | Checkov adapter with contract fixtures for the research and product versions | P0 |
| F-13 | Reproduce the QRS 2026 tables offline, with no model calls | P0 (done in Phase B) |
| F-14 | KICS and Trivy adapters with completeness semantics | P1 |
| F-15 | Independent validators: HCL, terraform/tofu validate, kubeconform, optional tflint | P1 |
| F-16 | SARIF 2.1.0, Markdown summary, JUnit reporters | P1 |
| F-17 | Composite GitHub Action with Docker isolation by default | P1 |
| F-18 | Container images: core and full-offline, non-root, digest-pinned | P1 |
| F-19 | Tool lock file and `--locked` mode | P1 |
| F-20 | Cross-scanner control catalog, `EXACT` mappings only for agreement | P1 |
| F-21 | Deterministic oracles: declarative assertions and trusted Rego | P1 |
| F-22 | Case bundles: init, validate, reproduce, export, summarize | P1 |
| F-23 | `pr` mode with changed-path scoping | P1 |
| F-24 | Pre-commit hook with a fast profile | P2 |
| F-25 | MCP server, additional artifact kinds, additional scanners | P2 |

E5.1 implements the declarative portion of F-21 as a closed, package-bound structural
oracle registry. Candidate-authored policy, callbacks, arbitrary Python or shell,
network access, and caller-supplied result evidence are outside the contract. Oracle
uncertainty remains a typed non-PASS state and scanner consensus remains advisory.
E5.3 requires exact Kubernetes field types, covers ordinary/init/ephemeral containers,
types non-applicable Windows assertions separately, and permits trusted result creation
only inside closed-registry execution. Empty-observation `PASS` evidence is invalid.
E5.4 requires repository-universe aggregation to reconcile exact role, snapshot, scope,
module, input-file, resource, validator/tool, count, and status/reason evidence before a
child `PASS` can contribute to a universe `PASS`.
E5.5 rejects unknown Kubernetes OS identities and requires exact passing Kubernetes
universe evidence before structural-oracle output can support an authoritative claim.
E5.6 makes aggregate universe status a derived value and closes each validator's
status/reason combinations; TFLint remains advisory.
E5.7 requires decisive `PASS`/`FAIL` oracle evidence for authoritative use and evaluates
Windows HostProcess under the no-privileged baseline assertion. The separate
allow-privilege-escalation oracle proves only explicit Boolean field state, not effective
runtime privilege semantics involving `privileged` or `CAP_SYS_ADMIN`.
E5.8 prohibits PASS whenever the sealed validation plan contains unsupported Terraform
JSON or unresolved entries. Required empty Kubernetes and Terraform domains remain
typed non-PASS states rather than affirmative evidence; protected policy owns whether a
gate is optional.

## 5. Non-functional requirements

| ID | Requirement |
| --- | --- |
| N-01 | Deterministic reports for identical inputs and tool lock |
| N-02 | No network access required for verification; `--network=none` proven in CI |
| N-03 | No telemetry, ever; no opt-out needed because there is nothing to opt out of |
| N-04 | No cloud credential required or inherited |
| N-05 | Fail closed: no error path, and no malformed or omitted input, may yield `VERIFIED` |
| N-06 | Core install small; scanners are external binaries or bundled images, not Python deps |
| N-07 | Python 3.10–3.13 for the thin CLI; the replay environment is pinned separately |
| N-08 | Research data excluded from wheel and sdist, enforced by a packaging test |
| N-09 | Coverage ≥90% on engine, policy, matching, fingerprints, and adapter normalisation |
| N-10 | Every bug fix ships with a regression test |

## 6. Release criteria

| Version | Gate |
| --- | --- |
| `0.1.0a1` | F-01…F-13; all ten outcomes and eleven delta classes covered by tests; twelve adapter contract shapes plus the two verified adapter-specific shapes; twelve adversarial fixtures including a forged exception; empty-output fixture yields exit 3; replay still green |
| `0.2.0b1` | F-14…F-23; pinned-image integration tests; offline container run; clean-venv install; wheel contains no research data; Action self-test produces a PR summary; a deliberately broken scanner yields exit 3 |
| `0.9.0rc1` | Case tooling, complete docs, community files; interfaces declared unstable |
| `1.0.0` | A non-implementer completes install → demo → real before/after → Action → deliberate failure → report interpretation, and their feedback is incorporated; interfaces frozen |

An external adopter is **not** required to publish `1.0.0`. No claim of external
adoption may be made unless an unaffiliated third party actually installs, integrates,
uses, or relies on the project.

## 7. Out of scope for 1.0

Re-implementing scanner rules; a policy language of our own; CloudFormation, ARM,
Bicep, Pulumi, or CDK adapters; Terrascan; a web UI; an IDE extension; an MCP server;
automated upstream submission of any kind; and any new benchmark inference run.

## 8. Success measures

Engineering: no known path from scanner error or empty output to `VERIFIED`; every
outcome and delta class test-covered; deterministic reports; the QRS tables still
reproduce; five-minute quickstart passes in a fresh repository.

Adoption: time to first successful result; install failure rate and how `doctor`
resolves it; whether an integration survives 30 and 60 days; external issues,
contributions, or case submissions; substantive upstream changes accepted by
independent projects. Stars, forks, and downloads are context, not evidence.

## 12. D2.2 — Execution Layer Hardening

Phase D2.2 closes ten independently reproduced security defects in the process runner:

1. **Process group termination**: After command completion, the runner verifies that the
   entire process group is gone. Lingering descendants are terminated (SIGTERM→SIGKILL).
2. **Combined output cap**: `stdout + stderr ≤ max_output_bytes` is enforced during
   reading. Exceeding the combined cap terminates the process and reports PARTIAL.
3. **Report redaction**: `canonical_dict()`, `display_command`, and all report-facing
   strings have secrets, option values, and local paths stripped.
4. **Cleanup gate**: Scratch cleanup failure changes a would-be PASS into
   ERROR/SCRATCH_CLEANUP_FAILED.
5. **State consistency**: CommandResult rejects contradictory fields at construction
   (e.g., PASS with timed_out=True).
6. **Isolated PATH**: The child gets only `/usr/bin:/bin:/usr/sbin:/sbin` plus explicitly
   configured `trusted_helper_dirs`. Parent PATH is never inherited. Preload injection
   variables (LD_PRELOAD, DYLD_*, PYTHONPATH, etc.) are blocked.
7. **Mandatory workspace**: `workspace_root` is required when `cwd` is supplied.
8. **Resolved executable audit**: The resolved binary path is recorded and included in
   canonical output (with machine paths redacted).

## 13. D2.3 — Process-boundary closure requirements

1. The Python 3.10–3.13 CI matrix performs a clean-bytecode import with warnings as
   errors before running tests.
2. Adapter-supplied sensitive option names and argument indices are validated,
   canonicalized, frozen, transferred into execution evidence, and applied on every
   command report surface.
3. Complete tested POSIX and Windows local absolute paths, including absolute
   executable arguments, are removed from canonical and logger-facing text without
   corrupting URLs.
4. A result is finalized once, after scratch cleanup, so spawn and cleanup failures can
   coexist as typed evidence.
5. `CommandResult` uses a closed reason vocabulary and an executable status/reason table;
   malformed public constructions are rejected.
6. Process-group absence is proven only by `ESRCH`; permission or inspection errors are
   uncertainty. Unconfirmed cleanup overrides timeout/partial status while retaining the
   original event as a typed secondary field.
7. Executables must strictly resolve to executable regular files outside the evaluated
   workspace. Symlinks resolving into the workspace are rejected.
8. Workspace root, cwd, trusted helper directories, and executable identity are
   revalidated immediately before spawn. This reduces TOCTOU exposure but does not make
   native execution a sandbox.
9. Reports record observed and retained byte counts per stream. Retained counts obey the
   individual and combined caps, observed counts are never lower, and truncated-output
   hashes are labelled as retained-byte hashes.

## 14. D3 — Fingerprints and multiset matching

1. `iacgv2` fingerprints are deterministic, visibly versioned, stable across line,
   message, severity, scanner-version, suppression-state, display-ordinal compaction,
   and temporary-root drift. They bind stable native occurrence evidence when present.
2. Scanner-native and IaC-Guard-V fingerprints coexist; a forged stored IaC-Guard-V
   fingerprint is rejected before matching or delta generation.
3. Matching preserves every occurrence, is independent of caller order, rejects
   scanner/version drift, partitions valid multi-artifact runs, matches stable identity
   before constrained relocation, and types equally supported pairings as
   `MATCHING_INCONCLUSIVE`. Reused no-native locations cannot defeat multiplicity-churn
   ambiguity.
4. Line-only and file moves remain observable as `LOCATION_CHANGED`; moving a rule to a
   different resource produces `RESOLVED_FINDING` plus `NEW_FINDING`.
5. Finding-only delta constructors cannot claim events that require later engine or
   trusted-policy evidence, and must prove the predicate of every delta they do expose.
6. Fingerprint, matching, and diffing modules each maintain at least 90% executable test
   coverage in CI.
7. D5-facing evidence is factory-bound: public requests contain paths, targets, and
   protected configuration/policy, never caller-authored scanner runs, matches,
   ambiguities, deltas, diff results, or target-evaluation evidence.

## 15. D4 — Checkov-only adapter

1. Checkov is the sole D4 scanner adapter; Trivy remains deferred.
2. Contract fixtures cover the twelve common scanner shapes plus Checkov's
   summary-only/no-results shape for research 3.2.517 and product 3.3.0 output.
3. Product 3.3.0 has pinned live Terraform and Kubernetes integration tests. The
   research 3.2.517 executable integration remains honestly deferred to Phase E; frozen
   output and a parser fixture do not impersonate a native run.
4. Version probe, summary version, trusted expected version, and trusted resolved-launcher
   digest must agree. Exit code 1 is valid finding evidence, not process failure.
5. Candidate Checkov config, custom checks, downloads, and uploads cannot govern a scan.
   The adapter scans only a private view of independently eligible files and uses an
   adapter-owned config.
6. Empty, malformed, truncated, structurally incomplete, unsupported-version,
   mismatched-version, partial, zero-resource, and cleanup-failed evidence cannot become
   `PASS` when eligible inputs exist.
7. Skipped checks remain typed suppression findings. Kubernetes normalization requires
   independently established canonical object identities rather than guessing an API
   version from Checkov's abbreviated resource string.
8. Raw JSON is bounded and no-follow read, and has a digest distinct from process stdout.
   Adapter base and Checkov modules maintain at least 90% executable test coverage.
9. Eligible files are portably bound by canonical path, type, size, and SHA-256;
   secondary device/inode evidence remains a private runtime race check. Changed bytes
   or scan-view copy uncertainty are typed errors.
10. Passed, failed, skipped, and unknown native evaluations are retained per
    rule/resource/file. Missing file/resource evaluation, aggregate-only evidence, and
    target absence cannot return `PASS` or establish `FIXED`.
11. Strict JSON rejects duplicate keys at every depth and enforces bucket/native-result
    consistency. Unknown result buckets remain visible as `PARTIAL`.
12. Evaluation count is `evaluations_reported`, never ruleset identity. Launcher,
    scanner environment, policy inventory, and invocation/config digests are distinct.
13. Nonempty verification requires an independent typed resource inventory. Native
    resource evidence is reconciled separately from file coverage; missing, unexpected,
    or count-mismatched resources cannot pass.
14. Contradictory native evaluations fail closed, and ruleset-integrity status reflects
    policy/environment/version evidence rather than overall run status.
15. Portable input JSON excludes device/inode; empty scope is typed `SKIPPED`; and
    trusted file-count/per-file/total-byte limits are enforced by streaming preparation
    and bound into invocation identity.
16. Checkov JSON nesting is capped deterministically before parsing. Depth above 128 is
    `ERROR/JSON_DEPTH_EXCEEDED` on every supported Python version; brackets inside JSON
    strings do not consume the depth budget.

## 16. D5 — Verification engine

1. The production request accepts factory-attested scan plans, structured targets,
   protected governed-configuration evidence, required gate identities, and regression
   settings; it cannot accept precomputed scanner, matching, delta, target, resource
   inventory, or verdict evidence. The scan-plan factory re-reads bounded regular-file
   bytes with no-follow safeguards and independently detects Terraform and Kubernetes
   resources; caller-supplied `expected_resources` is ignored.
2. Checkov execution, affirmative target lookup, and multiset comparison occur inside
   the engine, and every derived object is factory-proven before aggregation.
3. All ten target outcomes are executable in the documented fail-closed order.
   `FIXED` requires a zero retained finding count plus affirmative native target-pass
   evidence bound to the target file and artifact domain. Multiple baseline occurrences
   require occurrence-complete native tokens or distinct positive evaluation scopes;
   one generic pass is insufficient. Absence, ambiguity, incomplete coverage, and
   integrity uncertainty do not pass.
4. Required validator and oracle identities are executed through trusted in-process
   gate implementations. Missing implementation is `UNSUPPORTED`, and a substituted
   gate identity is rejected.
5. Stable scanner execution requires equal scanner, version, launcher digest,
   environment digest, policy-inventory digest, and invocation/config digest.
6. D5 reports derived preflight evidence and immutable V4 change metrics. It evaluates
   the five engine-owned event classes `RULE_SUBSTITUTED`, `COVERAGE_DECREASED`,
   `DIAGNOSTIC_ADDED`, `DESTRUCTIVE_CHANGE`, and `POLICY_DRIFT` as typed statuses rather
   than default booleans. A new finding with unknown severity is inconclusive, and an
   unrelated resource deletion is a destructive regression.
7. Suppression detection success is operational evidence, while each `SUPPRESSED`
   target remains a separate visible event for D6 policy disposition. D5 has no verdict
   field; verdict construction belongs exclusively to D6.

## 17. D6 — Policy and verdict

1. The policy request requires a factory-proven D5 result and an immutable
   `TrustedPolicyBundle` carrying private loader provenance. It rejects raw records,
   record collections, caller-created `ExceptionPolicy`, candidate-policy parses,
   caller evaluation dates, and caller gate optionality.
2. The base-commit loader resolves a real Git commit and reads the governed policy from
   that tree object; it accepts neither arbitrary trusted paths nor a caller-written
   source identity. A protected-policy repository requires an exact pinned commit and a
   repository outside the evaluated workspace. Explicit operator loading remains a
   separately reported local mode. Candidate loading always stamps `CANDIDATE_HEAD` and
   can never create an authoritative bundle.
3. Exceptions may permit only the exact scanner/rule/resource/file/artifact/native
   target binding and exact eligible outcome
   named by an in-force loader-stamped record. The inclusive evaluation date is captured
   from a trusted timezone-aware execution clock, and optional gates come from the same
   trusted policy document. Permission is derived by the policy layer, never believed
   from input.
4. Every classification stays visible. Permission changes its consequence and records
   the exception id; it never rewrites the event to `FIXED`.
5. Operational uncertainty, incomplete evidence, required-scanner coverage loss, and
   rule substitution produce `INCONCLUSIVE` before definite-negative evaluation.
   Validator/oracle failure, policy drift, unresolved targets, and regression or
   suppression failure then produce `FAILED`; otherwise the result is `VERIFIED`.
6. Policy evidence records the resolved source commit/repository, trusted source identity
   and origin, trusted digest, candidate presence/digest and path-by-path governed state,
   UTC evaluation-time provenance, and the exact
   loader source for every applied exception. Candidate policy drift is decisive even
   if a caller-supplied upstream digest claimed equality.
7. Verdicts and exit codes are closed and inseparable: `VERIFIED/0`, `FAILED/1`, and
   `INCONCLUSIVE/3`. Usage and internal error exits are outside `PolicyResult`.
8. A protected execution context, not a caller-selected existing Git object, authorizes
   PR-base and protected-repository policy. It binds repository/base/candidate roles,
   governed paths, verification configuration, and current UTC clock. Policy from a
   different context, repository, commit, mode, or clock is rejected before disposition.
   Explicit operator mode remains separately labelled and cannot masquerade as PR mode.

9. Phase-D artifact discovery is affirmative and parser-backed. Terraform `.tf`,
   Kubernetes YAML, and Kubernetes JSON—including quoted/flow YAML, multiple documents,
   and Kubernetes Lists—cannot be silently removed from coverage by representation.
   Ordinary YAML/JSON is classified without entering the Kubernetes scan. Unsafe or
   ambiguous Kubernetes evidence, duplicate JSON keys, invalid HCL, and unsupported
   `.tf.json` stop preflight rather than permitting `VERIFIED`.

   Phase-E validator orchestration preserves that boundary: `.tf.json` is explicit
   `UNSUPPORTED`/`INCONCLUSIVE`, not advertised as validator support. A protected
   repository-universe factory enumerates every `.tf` module and every Kubernetes
   artifact/resource before any whole-repository validation claim.

10. Protected verification configuration is one immutable factory-attested bundle, not
   ordinary request fields. It binds scanner/framework locks, limits, severity/location
   policy, validator/oracle ids, the gate registry, governed paths, and provenance.
   Targets resolve uniquely to file/artifact/native identity; same-address resources in
   other roots remain separate destructive events.

11. Differential direction is protected evidence: baseline and candidate roots are
    distinct and role-bound, and every role-specific plan carries a file-manifest and
    configuration digest. Reversed, same-root, cross-role, or stale-snapshot plans are
    usage errors before execution.
12. Production gate selection uses only packaged implementations with recorded version,
    code digest, and artifact support. The operator loader has no callback parameter.
13. `.iac-guard.json` and the complete protected scanner/ignore/custom-check/oracle/
    catalog/severity/exception/gate catalog participate in path-specific policy drift.
    Positive and failed Checkov evidence share one context-bound occurrence token.
14. Checkov execution identity separately binds launcher bytes, the installed package
    manifest, dependency/runtime lock evidence, built-in policy inventory, custom-check
    state, and `checkov-adapter-contract-v3`. Installed Checkov package/policy symlinks
    are rejected. Kubernetes classification applies strict Kubernetes semantics only
    after root identity evidence; clearly non-Kubernetes aliases, custom tags, and
    nested `kind` properties remain visible non-Kubernetes classifications.
15. One immutable, role-bound sealed snapshot supplies Checkov input binding, validators,
    oracles, target/resource presence, V4 metrics, policy-drift evidence, and the final
    canonical report. The mutable source roots are fully revalidated immediately before
    result construction; late additions/removals/changes/type or symlink replacements
    are `SNAPSHOT_CHANGED_DURING_VERIFICATION`, never `VERIFIED`. Canonical identities
    use repository/snapshot/subpath evidence and exclude local absolute roots.
16. Protected PR policy is accepted only when the candidate checkout is the exact clean
    authorized Git commit and D6's candidate snapshot/subpath equals D5's sealed evidence.
    Candidate policy comes from that Git tree. Monorepo prefixes apply symmetrically to
    base and candidate paths; governed directories have typed entries and bounded
    recursive digests, so symlink replacements are never treated as absent.
17. One no-follow inventory is authoritative for source state, artifact discovery,
    governed paths, scan planning and final revalidation. Every symlink and every
    supported/governed entry is reported with its exact filesystem type. Only regular
    files are parsed; an unsafe directory link or supported special file prevents
    `VERIFIED`. Native scanner integrity binds actual dependency code bytes as well as
    package, policy, launcher, interpreter and configuration evidence.
18. Canonical configuration and result evidence records each required gate's id, kind,
    contract version, complete implementation-manifest digest, parser dependency
    identity, and supported artifact kinds. The result also retains each role's full
    sealed filesystem inventory. Equivalent snapshots in different host directories
    remain byte-identical canonically.
19. The D7 CLI/API accepts only paths, target selectors and closed operator settings.
    Hostile-input execution defaults to the hardened container and returns exit 3 while
    that Phase E runtime is unavailable; native execution requires the explicit name
    `reduced-isolation`. Canonical JSON is `report-v1`; `VERIFIED`, `FAILED`, invalid
    request and operational uncertainty map to exit codes 0, 1, 2 and 3 respectively.
20. D9 compares all 630 frozen legacy records with locally recomputed deterministic
    parser evidence without scanner execution, model inference, provider calls, paper
    changes, or historical-result rewrites. Missing historical hardened evidence is
    explicit uncertainty. The comparison is labelled research analysis and cannot emit
    a production `VERIFIED` verdict.
21. Validator provenance separates the Phase-D gate contract, IaC-Guard-V build/source
    digest, verified parser-distribution code digest, and schema/loader contract. Raw
    symlink target text is private; canonical evidence records target kind and SHA-256.
22. Report-v1 has four closed verdict/exit branches and closed nested evidence.
    Config-v1 enforces isolation-specific executable fields and disjoint role roots.
    `--version`, offline `demo`, read-only `explain`, `verify`, and `doctor` are tested.
23. D9.1 publishes `LEGACY_VS_HARDENED.md` from canonical offline analysis, types local
    parser outcomes, binds installed parser/build provenance, and makes no production
    hardened verdict claim for evidence the historical runs did not retain.
24. D9.2 reproduces the canonical JSON and Markdown in a digest-pinned Python image with
    hash-pinned transitive dependencies and verified installed-code digests. Legacy
    transition labels come only from computed canonical counts.
## D7.4 public report acceptance

A public report is accepted only when its protected configuration hash is recomputed
from every protected scanner, framework, gate, limit, policy, source-authorization, and
snapshot input, and when its evidence graph can be re-derived. In particular, scanner
findings must produce the reported finding deltas and regression result; sealed
resources and governed paths must produce the reported engine events and change
metrics; and an exception-permitted decision must have exactly one active, trusted,
exact-target exception source record. Private test registry provenance is never valid
public evidence.

## E1 KICS adapter acceptance

KICS v2.1.20 is supported as typed adapter evidence only when executed through the
exact E0.3 digest lock. Native `similarity_id` is retained. Nonzero failed-file,
query-execution, or similarity-ID-computation counts, incomplete file/resource
coverage, version or environment drift, and unknown/malformed output cannot become
`PASS`. E1 does not change final policy or implement multi-scanner consensus.

E1.1 also requires official `0/20/30/40/50/60` result exits, `--pull never`, exact
summary types/arithmetic, separate TRACE/BOM accounting, optional native metadata
compatibility, and reason-specific integrity. KICS remains advisory.

E1.2 requires exit/report severity agreement, every required KICS v2.1.20 query/file
field, the complete standard severity-counter set, ordered native timestamps, and
separate BOM/TRACE preservation. Contradiction is typed and non-PASS.

## E2 Trivy adapter acceptance

Trivy v0.73.0 is supported as typed evidence only through the exact E0.3 image and
external checks v2.2.0 identities. The current cache, checks manifest/layer, invocation,
network/update state, stdout/stderr, and canonical native output are independently
bound. Embedded fallback, cache mutation, binary/check drift, malformed/duplicate JSON,
unknown categories, and incomplete file/resource coverage cannot become `PASS`.
Per-file native PASS records can establish positive evidence; global aggregate PASS
counts cannot. E2 has no policy or consensus consequence.

E2.1 requires E0.3-signed physical cache provenance. Correct metadata beside arbitrary
policy bytes is insufficient. Missing external evidence is inconclusive; manifest,
layer, subtree, or evaluation contradiction fails integrity. Native semantic and exact
byte hashes remain distinct.

E2.2 requires visible `EXCEPTION` evidence, conservative omitted-field behavior,
explicit experimental-modification evidence, and the complete signed cache attestation
with equal pre/post subtree roots.

E1/E2.1 production evidence requires actual locked execution. Public callers cannot
combine a sealed request, caller-authored process result, and arbitrary JSON to obtain
adapter evidence. Trivy obtains `IACGV_PHASE_E_CACHE` and verifies its E0.3 signature

## E1E2.3 shared runtime acceptance

Phase-E locked execution requires a portable protected evidence bundle and a
`TrustedContainerRuntime`. Missing, fake, workspace-local, symlinked, byte-drifted, or
daemon/context-drifted runtimes fail closed before scanner evidence is authoritative.

## E1.3 KICS coherence acceptance

KICS evidence is accepted only when retained severities, counters, result exit, locked
container scan path, ordinary/BOM query totals, unique query IDs, and issue types agree.
Raw bytes, canonical native semantics, and the physical output directory are bound by
three independent identities. KICS remains advisory.

## E2.3 Trivy provenance acceptance

Authoritative Trivy adapter evidence requires the exact E0.3 signed cache, external
checks identity, protected runtime, locked image/invocation, current nonfallback proof,
pre/post full and subtree roots, and independent raw/semantic/physical output hashes.
Missing cache remains an explicit blocked integration prerequisite, never a PASS.

## E3.1 Terraform-family validator acceptance

OpenTofu 1.12.5 and Terraform 1.15.8 are separate protected validator identities.
Terraform remains `USER_SUPPLIED_ONLY_NEVER_BUNDLED`. Only `validate -json` is
permitted. Init, plan, apply, provider/module acquisition, network use, candidate CLI
config, credentials, and candidate `.terraform` state are forbidden.

Definite invalidity is `FAIL`. Missing dependencies, unsupported states, timeouts,
malformed evidence, and operational failures are `INCONCLUSIVE`. `PASS` binds the
sealed snapshot, exact tool/runtime/argv, controls, output inventory, and coherent JSON.

## E3.2 kubeconform acceptance

kubeconform 0.8.0 is accepted only with the exact E0.3 image and signed offline
schema-tree identity. Valid complete resource coverage is `PASS`; definite
candidate schema or syntax invalidity is `FAIL`; unavailable schemas, unsupported
CRDs, incomplete coverage, malformed output, and trusted-baseline defects are
typed `INCONCLUSIVE`. The validator never enables network schema retrieval or
`ignore-missing-schemas`, and it never converts missing schema evidence to success.

Every expected Kubernetes resource from the sealed YAML/JSON, multi-document, or
`List` input is counted. CRD schemas must be protected and digest-bound. The
`NOASSERTION` schema-bundle licence is retained in validator evidence and blocks
public redistribution.

## E3.3 TFLint and shared-registry acceptance

TFLint 0.64.0 is `OPTIONAL_NON_SECURITY`. Clean and finding-bearing runs retain
deterministic advisory evidence, but neither independently proves security
correctness or a final `VERIFIED` verdict. Missing plugin initialization is
`INCONCLUSIVE`; diagnostics remain visible.

Only the protected built-in-rules configuration is authorized in E3.3. No plugin
download or initialization, candidate `.tflint.hcl`, network access, or candidate
plugin/cache state is accepted. All production validators execute through the
closed packaged registry with sealed requests and trusted runtime evidence.

## E3.5 exact validation coverage acceptance

Terraform/OpenTofu and TFLint PASS covers one explicitly sealed module directory, not
recursive paths. A mixed-root input is rejected until partitioned into separate module
requests. Kubeconform PASS requires verbose affirmative native evidence for the exact
sealed resource set; matching aggregate counts without identities are inconclusive.

## E3.6 implementation provenance acceptance

An authoritative validator record must bind the complete product build, its leaf
module, shared security implementation, parser dependency code, schema contract, and
runtime contract. The aggregate implementation digest is recomputed from these child
identities. Changes to shared evidence or materialization behavior must change the
closed registry identity.

## E3.7 Linux non-root acceptance

Validator mounts must work under a native Linux Docker engine without root fallback.
The locked UID/GID reads every sealed input and protected configuration, cannot modify
either mount, and writes only to the bounded output mount. Permission and content drift
before or after execution makes the result non-PASS.

## E3.8 complete scope acceptance

An authoritative validator request must be built from the complete factory-attested
role scope. A caller-selected subset is rejected when another top-level Terraform file
exists in the module or another Kubernetes-classified YAML/JSON artifact exists in the
snapshot. The same scope is revalidated at every process boundary. Late additions,
removals, byte changes, type changes, and governed/transient module state are non-PASS.
TFLint's clean output proves only that the complete module invocation ran; it does not
invent file-level affirmative evidence.

## E3.9 native and registry integrity acceptance

Kubeconform PASS requires coherent per-resource status, message, validation-error, and
exact locked-path evidence. `statusValid` plus adverse validation errors and an
unrelated absolute path are non-PASS. The closed validator registry is authoritative
only in a bytecode-free protected product installation whose parser dependencies also
pass physical integrity checks. An ordinary writable environment that has generated
`__pycache__`, `.pyc`, or `.pyo` content is explicitly `INCONCLUSIVE`; doctor reports
how to use the protected pre-start bytecode-disabled mode.
and inventory before use.

E1/E2.2 requires the complete hardened Docker restriction set, an exact no-follow
writable-output allowlist with per-file/total caps, and removal of all test evidence
factories from distributable product modules.
