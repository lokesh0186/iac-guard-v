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

Exactly one value per target instance. Only `FIXED` can contribute to `VERIFIED`.

| Outcome | Decision rule |
| --- | --- |
| `FIXED` | Target scope present in candidate; scanner integrity `PASS` for the required scanner; no suppression added in scope; no `EXACT`-tier finding for the target; required oracles `PASS` |
| `STILL_PRESENT` | An `EXACT` or `RELOCATED` finding for the target remains |
| `PARTIALLY_FIXED` | Target had N>1 occurrences; at least one remains |
| `SUPPRESSED` | The finding is absent and a suppression covering its scope appeared: inline skip, ignore file entry, config exclusion, path exclusion, baseline file, or custom-policy override |
| `RESOURCE_DELETED` | The resource address named by the target does not exist in the candidate |
| `FILE_DELETED_OR_RENAMED` | The target file is absent, and no rename mapping preserves scope |
| `OUT_OF_SCOPE` | The target artifact is no longer selected: framework changed, extension changed, path excluded, or generated-file marker added |
| `RULE_OR_SCANNER_DRIFT` | Scanner version, ruleset, check bundle, or rule ID differs between baseline and candidate runs |
| `SCANNER_ERROR` | The scanner did not produce a trustworthy result for the candidate (§6) |
| `INCONCLUSIVE` | Evidence cannot separate the above |

### 4.1 Ordering rule

Evaluate in this order and stop at the first match: `SCANNER_ERROR` →
`RULE_OR_SCANNER_DRIFT` → `OUT_OF_SCOPE` → `FILE_DELETED_OR_RENAMED` →
`RESOURCE_DELETED` → `SUPPRESSED` → `STILL_PRESENT` → `PARTIALLY_FIXED` → `FIXED` →
`INCONCLUSIVE`. Absence of a finding is never sufficient on its own; this ordering is
what prevents audit findings F1 and F4 from recurring.

### 4.2 Classification is not policy

The classifier emits the outcome. A separate policy layer decides pass or fail. A
deployment may legitimately allow `RESOURCE_DELETED` (deleting the offending bucket
is a real remediation) or an approved `SUPPRESSED`. Defaults:

| Outcome | Default decision |
| --- | --- |
| `FIXED` | pass |
| everything else | fail |

`allow_resource_deletion` and `allow_suppression` exist, default `false`, and when
enabled require an exception record per §2.4. A permitted outcome stays visible in
the report with `policy_permitted: true`.

---

## 5. Regression delta classes

Computed over finding **multisets**, never sets of rule IDs.

| Class | Definition |
| --- | --- |
| `NEW_FINDING` | Candidate finding with no baseline match at `EXACT` or `RELOCATED` |
| `MOVED_FINDING` | Matches at `RELOCATED` but not `EXACT`; reported as a regression, not as resolved-plus-new |
| `SEVERITY_INCREASED` | Same identity, higher severity |
| `SCOPE_EXPANDED` | Same rule now matches additional resource addresses |
| `RULE_SUBSTITUTED` | Same `EXACT` control now failing under a different native rule id after drift |
| `SUPPRESSION_ADDED` | New or broadened scanner-native suppression |
| `COVERAGE_DECREASED` | Fewer eligible, discovered, or parsed files, or fewer loaded checks |
| `DIAGNOSTIC_ADDED` | New parser or validator diagnostic |
| `DESTRUCTIVE_CHANGE` | Resource deletion or replacement, when plan data is supplied |
| `POLICY_DRIFT` | §2.3 |
| `RESOLVED_FINDING` | Baseline finding absent in candidate and not explained by suppression, deletion, or scope loss; recorded as a positive delta |

Default gate: no `NEW_FINDING` at or above `severity_floor`, no `MOVED_FINDING`, no
`SUPPRESSION_ADDED`, no `COVERAGE_DECREASED`, no `POLICY_DRIFT`.

---

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
6. `files_parsed` or `checks_loaded` lower in the candidate than the baseline;
7. version outside the supported range, or differing between baseline and candidate;
8. timeout or termination by signal.

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

```
VERIFIED  iff  P0 == PASS
          and  every required validator (V1) == PASS
          and  every required scanner integrity (V5) == PASS
          and  every required target outcome == FIXED
          and  regression policy (V3) == PASS
          and  suppression and POLICY_DRIFT policy (§2) == PASS
          and  every required oracle (V6) == PASS

FAILED       iff not VERIFIED and every required gate reached a decision
             (that is, at least one PASS/FAIL criterion evaluated to FAIL and no
              required gate is ERROR/TIMEOUT/UNSUPPORTED/PARTIAL/INCONCLUSIVE)

INCONCLUSIVE otherwise
```

Any `ERROR`, `TIMEOUT`, `UNSUPPORTED` required tool, `PARTIAL` scan,
`COVERAGE_DECREASED` on a required scanner, or `INCONCLUSIVE` required gate yields
`INCONCLUSIVE` — never `VERIFIED`, and never a silent `FAILED` that hides a broken
run.

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
