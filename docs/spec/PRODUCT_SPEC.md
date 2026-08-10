# Product Specification

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
