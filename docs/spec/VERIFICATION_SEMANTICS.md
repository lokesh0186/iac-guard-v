# Verification Semantics

Normative specification of what IaC-Guard-V decides and how. Phase D implements this
document; where code and this document disagree, this document is the defect report.

Scope: the `hardened` profile. The `qrs2026` profile is a reproduction-only artifact
described in `research/compat/qrs2026.yml` and is out of scope here.

---

## 0. Defined terms

Every term below is defined because the word alone is ambiguous. No other part of the
specification may use these words in a normative sentence without pointing here.

| Term | Definition in this system |
| --- | --- |
| **successful** | Not used normatively. Replaced by an explicit `Status` value and, for a whole run, by `Verdict`. |
| **fixed** | Only as the target outcome `FIXED`, defined in §4. It requires target scope still present, scanner integrity intact, no new suppression, the finding absent, and any required oracle passing. |
| **resolved** | Synonym of `FIXED`; used only in prose that immediately cites §4. |
| **safe** | Not used normatively. The system makes no safety claim; it reports gate results and a `Verdict`. |
| **supported** | A `(scanner, version range, artifact kind)` triple that has both contract fixtures and a pinned integration test (`SCANNER_CONTRACTS.md`). Absent either, the adapter reports `UNSUPPORTED`. |
| **consensus** | Agreement between scanners **only** through an `EXACT` mapping in the control catalog (§8). Advisory always. Never ground truth. |
| **verified** | The single `Verdict` value `VERIFIED`, defined in §10. |
| **evidence** | A recorded, re-readable fact: a raw scanner output reference, a hash, a coverage counter, an oracle result, or a diff. Verdicts cite evidence; evidence never contains a verdict. |
| **baseline** | The artifact tree designated as the "before" state, plus its scan results. |
| **candidate** | The artifact tree designated as the "after" state, plus its scan results. |
| **target** | A `(scanner, rule_id, scope)` triple the change is expected to fix, where scope is a resource address or an artifact path (§3). |
| **trusted configuration** | Configuration loaded from the trusted source defined in §2, never from the evaluated change. |

---

## 1. Status and result vocabulary

### 1.1 `Status` — the outcome of any single operation

`PASS` `FAIL` `ERROR` `TIMEOUT` `UNSUPPORTED` `SKIPPED` `PARTIAL` `INCONCLUSIVE`

| Value | Meaning | May contribute to `VERIFIED`? |
| --- | --- | --- |
| `PASS` | Operation completed; its criterion held | yes |
| `FAIL` | Operation completed; its criterion did not hold | no |
| `ERROR` | Operation did not complete (crash, malformed output, unreadable input) | no |
| `TIMEOUT` | Operation exceeded its deadline and was terminated | no |
| `UNSUPPORTED` | The tool cannot handle this artifact kind or version | no |
| `SKIPPED` | Not run by explicit configuration; must name the configuration key | no |
| `PARTIAL` | Ran but did not cover everything it was asked to cover | no |
| `INCONCLUSIVE` | Ran, covered its input, and the evidence does not decide the question | no |

A boolean must never encode any of `ERROR`, `TIMEOUT`, `UNSUPPORTED`, `PARTIAL`, or
`INCONCLUSIVE`. This is the direct remedy for audit finding F6.

### 1.2 `Verdict` — the outcome of a whole verification

`VERIFIED` `FAILED` `INCONCLUSIVE`

There is no fourth value. "Passed with warnings" is `VERIFIED` plus advisory
findings; "probably fine" is `INCONCLUSIVE`.

---

## 2. Trusted configuration and policy provenance

The artifact under evaluation must never govern its own evaluation.

### 2.1 Trusted sources, in precedence order

1. `--policy-from` explicit path supplied by the invoking operator.
2. A protected workflow input or protected policy repository reference.
3. The **base commit** of the comparison in PR mode.
4. The working tree, **only** in local `repair` mode where operator and author are
   the same person.

### 2.2 Governed files

`.iac-guard.yml`, exception records, severity policy, the control catalog, oracle
policies, scanner configuration (`.checkov.yml`, KICS config, Trivy config,
`.tflint.hcl`), ignore files (`.trivyignore`, `.checkovignore`, equivalent), and any
custom-check directory.

### 2.3 `POLICY_DRIFT`

If any governed file differs between the trusted source and the candidate, the engine
MUST:

1. emit a `POLICY_DRIFT` event naming each differing file and the nature of the
   change (added, removed, broadened, narrowed, reordered);
2. evaluate using the **trusted** version only;
3. record both digests as evidence;
4. apply the configured `policy_drift` decision, whose default is `FAIL`.

### 2.4 Exception records

An exception suppresses a *policy decision*, never an *event*. Each record requires a
stable `id`, `scope`, `reason`, `owner`, `created`, and `expires`.

- An expired exception is `FAIL`, not ignored.
- An exception appearing or broadening in the candidate is `POLICY_DRIFT`.
- An `owner` string is not proof of approval. Approval is established only by the
  record residing in the trusted source, and optionally by a configured
  `approval_binding`: a protected file path, a signed commit, or a required review.
- A suppressed event remains in the report with `policy_permitted: true`.

---

## 3. Finding identity

A finding is not a rule ID. That representation is audit finding F3.

### 3.1 Fields

`scanner`, `scanner_version`, `rule_id`, `rule_name`, `severity`, `artifact_kind`,
`file_path` (canonical, scan-root relative), `resource_address`, `occurrence_index`,
`start_line`, `end_line`, `message`, `native_fingerprint`, `iacgv_fingerprint`,
`suppression_state`, `raw_ref`.

### 3.2 Identity tiers

| Tier | Key | Used for |
| --- | --- | --- |
| `EXACT` | scanner + rule_id + file_path + resource_address + occurrence_index | same-scanner before/after matching |
| `RELOCATED` | scanner + rule_id + resource_address, allowing file move and line drift | detecting a moved finding instead of one resolved plus one new |
| `SEMANTIC` | control_id + resource_address + artifact_kind | cross-scanner comparison, `EXACT` mappings only |
| `OCCURRENCE` | all of the above, preserving duplicates | never collapsing N violations of one rule into one |

### 3.3 Fingerprint rules

- Algorithm identifier is part of the fingerprint, so a change of algorithm is
  visible rather than silent.
- Line numbers are excluded from the primary fingerprint; they are location evidence.
- Temporary directories are excluded; paths are canonicalised to the scan root and
  a path escaping the root is `ERROR`, never a finding.
- Terraform addresses are canonicalised as `type.name[index]`; Kubernetes objects as
  `apiVersion/kind/namespace/name`.
- Both `native_fingerprint` and `iacgv_fingerprint` are stored. Neither replaces the
  other.

---

## 4. Target outcomes

Exactly one value per target. Only `FIXED` can contribute to `VERIFIED`.

For one target `(scanner, rule_id, scope)` define:

```
N = baseline occurrence count for the target        (N >= 1 by construction)
M = candidate occurrence count matching the target at EXACT or RELOCATED tier
```

`RELOCATED` means the **same resource address** with a changed file path or line
range. A finding on a *different* resource address is a different finding; see §5.

| Outcome | Predicate |
| --- | --- |
| `SCANNER_ERROR` | the required scanner did not produce a trustworthy result for the candidate (§6 V5) |
| `RULE_OR_SCANNER_DRIFT` | scanner version, ruleset, check bundle, or rule id differs between the baseline and candidate runs |
| `OUT_OF_SCOPE` | the target artifact ceased to be **structurally** eligible: artifact kind, framework, file extension, or generated-file marker changed so that no configured scanner selects it |
| `FILE_DELETED_OR_RENAMED` | the target file is absent and no rename mapping preserves scope |
| `RESOURCE_DELETED` | the target file exists and is eligible, but the target resource address does not exist in the candidate |
| `SUPPRESSED` | scope exists and is eligible, `M == 0`, and a suppression covering the scope appeared: inline skip annotation, ignore-file entry, scanner-config exclusion including path exclusion, baseline-suppression file, or custom-policy override |
| `PARTIALLY_FIXED` | `N > 1` and `0 < M < N` |
| `STILL_PRESENT` | `M >= N`, or (`N == 1` and `M == 1`) |
| `FIXED` | `M == 0`, scope present and eligible, integrity `PASS`, and no suppression covering the scope appeared. **Oracle results are deliberately not part of this predicate**; see §4.3 |
| `INCONCLUSIVE` | none of the above can be established from the available evidence |

### 4.1 Ordering rule

Evaluate in this order and stop at the first match:

```
SCANNER_ERROR
RULE_OR_SCANNER_DRIFT
OUT_OF_SCOPE
FILE_DELETED_OR_RENAMED
RESOURCE_DELETED
SUPPRESSED
INCONCLUSIVE             <- if occurrence evidence is insufficient
PARTIALLY_FIXED          <- before STILL_PRESENT
STILL_PRESENT
FIXED
```

Evidence sufficiency is a **prerequisite for every count-based outcome**. If the
occurrence counts `N` or `M` cannot be established with confidence — a partially
parsed file, an adapter that cannot express occurrence identity for this rule, an
ambiguous rename — the outcome is `INCONCLUSIVE` regardless of what the counts appear
to be. A count-based classification computed from counts we do not trust would be a
guess wearing a label.

Two properties this must satisfy, both covered by executable truth-table tests:

- **Reachability.** Every outcome is produced by at least one scenario. An earlier
  draft evaluated `STILL_PRESENT` first and defined it as "a finding remains", which
  made `PARTIALLY_FIXED` unreachable, because a partially fixed target always has a
  remaining finding. The count predicates above are disjoint, so the order affects
  efficiency only, not classification.
- **Disjointness.** `SUPPRESSED` and `OUT_OF_SCOPE` no longer overlap. Path exclusion
  through scanner configuration is a **suppression**: the artifact is still
  structurally eligible and a configuration change hid it. `OUT_OF_SCOPE` is reserved
  for the artifact itself ceasing to be eligible. A candidate-authored configuration
  or ignore-file change additionally emits `POLICY_DRIFT` (§2.3), so the two signals
  stack rather than compete.

Absence of a finding is never sufficient on its own: `M == 0` holds for `SUPPRESSED`,
`RESOURCE_DELETED`, `OUT_OF_SCOPE`, and `FIXED`, and only the last passes. That is
what stops audit findings F1 and F4 from recurring.

### 4.2 Classification is not policy, and not every failure is `FAILED`

The classifier emits the outcome. A separate policy layer decides the consequence, and
the consequence is not always "fail": some outcomes mean the verifier could not
establish anything, which is `INCONCLUSIVE`, not a negative result about the change.

| Outcome | Meaning | Default decision | Contributes to |
| --- | --- | --- | --- |
| `FIXED` | the target was repaired | pass | `VERIFIED` |
| `STILL_PRESENT` | the defect remains | fail | `FAILED` |
| `PARTIALLY_FIXED` | some occurrences remain | fail | `FAILED` |
| `SUPPRESSED` | the finding was hidden, not fixed | fail | `FAILED` |
| `RESOURCE_DELETED` | the resource is gone | fail unless `allow_resource_deletion` | `FAILED` |
| `FILE_DELETED_OR_RENAMED` | the file is gone | fail unless policy permits | `FAILED` |
| `OUT_OF_SCOPE` | the artifact left scanner selection | fail | `FAILED` |
| `RULE_OR_SCANNER_DRIFT` | the comparison is not valid | inconclusive | `INCONCLUSIVE` |
| `SCANNER_ERROR` | the scan is not trustworthy | inconclusive | `INCONCLUSIVE` |
| `INCONCLUSIVE` | evidence does not decide | inconclusive | `INCONCLUSIVE` |

The whole-run decision table, which §7 formalises:

| Condition | Overall |
| --- | --- |
| a defect remains, or the candidate evaded verification | `FAILED` |
| the candidate modified protected policy or configuration | `FAILED` with `POLICY_DRIFT` |
| a scanner crashed, timed out, returned partial data, or could not cover the input | `INCONCLUSIVE` |
| ruleset or version drift makes the comparison invalid | `INCONCLUSIVE` |
| trusted policy permits an event | per policy; the event stays reported |
| every required gate proves the fix and no regression | `VERIFIED` |

`allow_resource_deletion` and `allow_suppression` exist, default `false`, and when
enabled require an exception record per §2.4. A permitted outcome remains visible in
the report with `policy_permitted: true`; permission changes the decision, never the
classification.

---

### 4.3 Oracles are gates, not classifiers

An earlier draft put "every required oracle `PASS`" inside the `FIXED` predicate and
also asserted, at whole-run level, that a failing required oracle yields `FAILED`.
Those cannot both hold: if the classifier refuses to emit `FIXED` when the oracle
failed, the whole-run rule can never see the combination it claims to handle, and the
test that exercised it was constructing an impossible state.

The separation is therefore strict:

- **Target outcomes** are derived from structural and scanner evidence only: scope
  existence, eligibility, suppression, deletion, integrity, and occurrence counts.
- **Oracle results** are typed gate results evaluated at whole-run verdict time
  (§7), alongside validators, integrity, regression, and policy.

This also keeps the project's own rule intact: classification describes what happened,
gates decide what it means.

## 5. Regression delta classes

Computed over finding **multisets**, never sets of rule IDs.

A finding's resource address is part of its identity. Two cases an earlier draft
conflated:

- **Same resource, different file or line.** The same finding, in a new location. This
  is `LOCATION_CHANGED` and is **advisory by default**: reformatting, moving a resource
  between files, or inserting lines above it are ordinary refactors, not security
  regressions.
- **Rule disappears from resource A and appears on resource B.** Two different
  findings, reported as `RESOLVED_FINDING` on A **plus** `NEW_FINDING` on B. Not a
  relocation, because the resource address changed.

| Class | Definition | Default |
| --- | --- | --- |
| `NEW_FINDING` | candidate finding with no baseline match at `EXACT` or `RELOCATED` | fail at or above `severity_floor` |
| `LOCATION_CHANGED` | a matched finding whose `file_path`, `start_line`, or `end_line` changed (§5.2) | advisory |
| `SEVERITY_INCREASED` | same identity, higher severity | fail |
| `SCOPE_EXPANDED` | the same rule now matches additional resource addresses | fail |
| `RULE_SUBSTITUTED` | the same `EXACT` control now fails under a different native rule id after drift | inconclusive |
| `SUPPRESSION_ADDED` | new or broadened scanner-native suppression | fail |
| `COVERAGE_DECREASED` | see §5.1 | inconclusive |
| `DIAGNOSTIC_ADDED` | new parser or validator diagnostic | advisory, unless it indicates an unparsed eligible file |
| `DESTRUCTIVE_CHANGE` | resource deletion or replacement, when plan data is supplied | fail unless permitted |
| `POLICY_DRIFT` | §2.3 | fail |
| `RESOLVED_FINDING` | a baseline finding is absent in the candidate and not explained by suppression, deletion, or scope loss | positive |

Default gate: no `NEW_FINDING` at or above `severity_floor`, no `SEVERITY_INCREASED`,
no `SCOPE_EXPANDED`, no `SUPPRESSION_ADDED`, no `POLICY_DRIFT`. `LOCATION_CHANGED` is
reported and does not fail unless trusted policy sets
`regressions.fail_on_location_change: true`.

### 5.1 Coverage is measured against the candidate's own eligible set

An earlier draft compared the candidate's parsed-file count against the **baseline**
count. That misclassifies a legitimate deletion: removing one Terraform file lowers the
candidate count with no loss of scanner coverage.

Coverage is therefore evaluated within the candidate:

```
eligible_candidate = files the independent artifact-kind detector says the scanner
                     should select, computed without the scanner
parsed_candidate   = files the scanner reports it actually parsed

COVERAGE_DECREASED iff parsed_candidate < eligible_candidate
```

Three situations a raw count comparison confuses, now separated:

| Situation | Signal |
| --- | --- |
| the scanner failed to parse an eligible candidate file | `COVERAGE_DECREASED` then `PARTIAL` then `INCONCLUSIVE` |
| the candidate changed scanner selection or configuration | `POLICY_DRIFT` then `FAILED` |
| the candidate legitimately removed a file or resource | `FILE_DELETED_OR_RENAMED` or `RESOURCE_DELETED`, then policy decides |

Baseline and candidate file counts remain recorded as evidence because they are useful
context. They are not the gate.

### 5.2 `LOCATION_CHANGED` is a metadata delta, not a tier subtraction

An earlier draft defined it as "matches at `RELOCATED` but not `EXACT`". That is
unsatisfiable for a line-only move: line numbers are deliberately excluded from the
`EXACT` key (§3.3), so moving a resource down ten lines still matches at `EXACT` and
the subtraction yields nothing.

Location change is therefore computed independently of the identity tier, from the
metadata of findings that already matched:

```
identity_match    = matched at EXACT or RELOCATED
location_changed  = identity_match AND (
                      baseline.file_path  != candidate.file_path  OR
                      baseline.start_line != candidate.start_line OR
                      baseline.end_line   != candidate.end_line )
```

| Change | Signals |
| --- | --- |
| same resource, lines shifted | `LOCATION_CHANGED` (advisory) |
| same resource, moved to another file | `LOCATION_CHANGED` (advisory) |
| rule now on a **different** resource address | `RESOLVED_FINDING` on the old resource **plus** `NEW_FINDING` on the new one |

Line numbers stay out of the stable fingerprint, and location drift stays observable.
Both properties are required; neither is sacrificed to the other.

## 6. Gates

### P0 — Preflight

Paths exist, resolve inside the allowed root, are regular files or directories, and
contain no symlink escaping the root. Artifact kinds are detected; an ambiguous kind
is `UNSUPPORTED`, never a guess. Content hashes, config hash, lock hash, OS, and
architecture are recorded. Failure ⇒ `ERROR`.

### V1 — Independent validity

Syntax and schema validity are established **without** the security scanner, closing
audit finding F2. Reported as four independent fields: `syntax_valid`,
`schema_valid`, `validation_requires_init`, `unsupported`.

- Terraform/OpenTofu: independent HCL parse; optionally `terraform validate -json` or
  `tofu validate -json` in a controlled mode. `init`, `plan`, and `apply` are never
  run automatically. A validation needing provider schemas is
  `validation_requires_init`, not invalid.
- Kubernetes: safe multi-document YAML parse; optionally Kubeconform against pinned
  offline schemas. A missing schema is `UNSUPPORTED`, not valid.
- A scanner producing output does not prove validity, and empty scanner output proves
  nothing at all.

### V2 — Target outcomes

§4.

### V3 — Regression

§5.

### V4 — Change-risk metrics

`lines_added`, `lines_removed`, `lines_changed`, `diff_ratio` (retained for
continuity with the paper), plus `files_changed`, `resources_changed`,
`resources_added`, `resources_deleted`, `policy_files_changed`. Advisory by default;
`minimality.mode: gate` makes it decisive. Changes outside target scope are always
highlighted, even when every scanner passes.

### V5 — Scanner execution integrity

The gate that makes audit finding F1 impossible. Required evidence per scanner run:
`tool_version`, `executable_or_image_digest`, `exit_code`, `stdout_sha256`,
`stderr_sha256`, `duration_ms`, `files_eligible`, `files_discovered`, `files_parsed`,
`files_failed`, `checks_loaded`, `checks_failed_to_execute`, `parse_errors`.

`ERROR` or `PARTIAL` — never `PASS` — when any of the following holds:

1. empty stdout, or output that does not parse as the documented structure;
2. an exit code outside the adapter's documented contract;
3. `files_eligible > 0` and `files_discovered == 0`;
4. `files_parsed` less than `files_discovered` without an explicit allowance;
5. `files_failed > 0` or `checks_failed_to_execute > 0`;
6. `files_parsed` lower than the **independently computed eligible candidate set**
   (§5.1). A raw comparison against the baseline count is explicitly *not* used: a
   legitimate file removal lowers the candidate count without any loss of coverage;
7. `checks_loaded` disagreeing with the locked expected ruleset inventory. A count
   merely lower than the baseline is not sufficient — that is `RULE_OR_SCANNER_DRIFT`
   territory only when it contradicts the lock;
8. version outside the supported range, or differing between baseline and candidate;
9. timeout or termination by signal.

Success is never inferred from exit code alone, and failure is never inferred from
the presence of findings.

### V6 — Independent oracle

Optional for routine CI. **Required** before any case may be labelled a validated
scanner discrepancy. Must be deterministic, versioned, and independent of the scanner
under evaluation. Permitted mechanisms: declarative artifact assertions; bundled or
explicitly trusted Conftest/Rego policies. Arbitrary Python or shell from a case
bundle is never executed. Records oracle id, version, policy hash, result,
diagnostics, and an authoritative reference.

### V7 — Cross-scanner agreement

States: `AGREEMENT_PASS`, `AGREEMENT_FAIL`, `DISAGREEMENT`, `NOT_COMPARABLE`.
Computed only over `EXACT` mappings. Advisory. Never overrides V5 or V6, and never
converts a `DISAGREEMENT` into a defect claim by itself.

---

## 7. Verdict

Evaluated in this order, so that "we could not tell" can never be reported as either a
pass or a real negative result:

Validators and oracles carry the full `Status` vocabulary, not a boolean, because
"the artifact is definitively invalid" and "we could not check the artifact" have
different meanings and must not produce the same verdict.

```
1. INCONCLUSIVE if any of:
     P0 != PASS
     any required validator  (V1) in {ERROR, TIMEOUT, UNSUPPORTED, PARTIAL, INCONCLUSIVE}
     any required oracle     (V6) in {ERROR, TIMEOUT, UNSUPPORTED, PARTIAL, INCONCLUSIVE}
     any required scanner integrity (V5) != PASS
     any required target outcome in {SCANNER_ERROR, RULE_OR_SCANNER_DRIFT, INCONCLUSIVE}
     COVERAGE_DECREASED on a required scanner        (candidate-internal, §5.1)
     RULE_SUBSTITUTED on a required target

2. FAILED if any of:
     any required validator (V1) == FAIL             (the artifact is demonstrably invalid)
     any required oracle    (V6) == FAIL             (an independent oracle disproves the repair)
     POLICY_DRIFT is present                         (a definite negative result)
     any required target outcome is not FIXED and is not permitted by trusted policy
     regression policy (V3) != PASS
     suppression policy != PASS

3. VERIFIED otherwise
```

| Gate result | Meaning | Verdict contribution |
| --- | --- | --- |
| validator `PASS` | syntax and schema hold | continue |
| validator `FAIL` | the candidate is invalid IaC | `FAILED` |
| validator `ERROR` / `TIMEOUT` / `UNSUPPORTED` / `PARTIAL` | validation could not complete | `INCONCLUSIVE` |
| oracle `PASS` | independent evidence supports the repair | continue |
| oracle `FAIL` | independent evidence contradicts the repair | `FAILED` |
| oracle `ERROR` / `TIMEOUT` / `UNSUPPORTED` / `PARTIAL` | the oracle could not decide | `INCONCLUSIVE` |

Step 1 dominating step 2 is deliberate. If a scanner crashed **and** a target is still
present, the honest answer is `INCONCLUSIVE`: the crash means the finding set is not
trustworthy, so the apparent defect is not established evidence either.

`POLICY_DRIFT` sits in step 2 rather than step 1 because it is not missing evidence.
The candidate demonstrably attempted to alter the rules governing its own evaluation,
which is a conclusion, not an absence of one.

---

## 8. Control mappings

A `control_id` is owned by this project and carries: intent, secure expected outcome,
artifact kind, provider, resource types, scope limits, per-scanner rule ids with
version ranges and documented semantics, equivalence confidence (`EXACT`,
`OVERLAPPING`, `RELATED`, `NOT_COMPARABLE`, `UNKNOWN`), authoritative references,
review date, and known false-positive or false-negative caveats.

Only `EXACT` mappings may produce agreement or disagreement claims. Each published
`EXACT` mapping requires positive, negative, and boundary fixtures for every mapped
scanner. There is no minimum count: publishing zero `EXACT` mappings is a valid
outcome, and the semantic standard is never relaxed to reach a number.

---

## 9. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | `VERIFIED` |
| 1 | `FAILED` — a real negative result: unresolved target, regression, suppression, policy drift, or oracle failure |
| 2 | Usage or configuration error; nothing was verified |
| 3 | `INCONCLUSIVE` — required tool unavailable, unsupported, partial, timed out, or integrity failure |
| 4 | Unexpected internal error |

1 means the change is bad. 3 and 4 mean the verifier could not establish a
trustworthy result. Consumers must not treat them alike.

---

## 10. Determinism

For identical inputs, configuration, and tool lock, two runs MUST produce byte-equal
reports except for `run.started_at`, `run.duration_ms`, and `run.id` when
non-deterministic id generation is selected. Scanners, files, findings, deltas,
gates, and diagnostics are sorted by documented stable keys.

---

## 11. Anti-evasion detections

Each detection emits an event and evidence; §4.2 decides consequence.

Inline skip annotations; ignore-file entries; scanner config files; policy
exclusions; changes to `.checkov.yml`, `.trivyignore`, KICS config, `.tflint.hcl`,
`.iac-guard.yml`, workflow scan paths, or custom-check directories; file renames,
extension changes, and directory moves that remove an artifact from selection;
symlink changes; deletion of the offending resource, file, module, or attribute;
scanner version, image tag, or checks-bundle changes; reductions in files scanned,
files parsed, checks loaded, or eligible target instances; and generated-file markers
added to previously scanned paths.

---

## 12. Worked example — the case the old harness got wrong

Baseline: `aws_s3_bucket.data` fails `CKV_AWS_18` (access logging).
Candidate: unchanged resource, plus `#checkov:skip=CKV_AWS_18:reviewed`.

| Stage | Legacy harness (`qrs2026`) | Hardened |
| --- | --- | --- |
| Target | rule id absent from `failed_checks` ⇒ resolved | suppression covering scope detected ⇒ `SUPPRESSED` |
| Regression | rule-id set difference empty ⇒ none | `SUPPRESSION_ADDED` |
| Verdict | `overall_verified_fix: true` | `FAILED`, exit 1, event visible with `policy_permitted: false` |

Second case: Checkov writes nothing to stdout because it crashed.

| Stage | Legacy harness | Hardened |
| --- | --- | --- |
| Scanner integrity | not evaluated | empty stdout ⇒ V5 `ERROR` |
| Target | rule id absent ⇒ resolved | `SCANNER_ERROR` |
| Verdict | `overall_verified_fix: true` | `INCONCLUSIVE`, exit 3 |

Both rows of both tables are the reason this specification exists.
