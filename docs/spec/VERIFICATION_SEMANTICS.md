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
| **fixed** | Only as the target outcome `FIXED`, defined in §4: target scope still present and eligible, scanner integrity intact, no suppression covering the scope added, and no matching finding remaining. Oracle results are **not** part of this predicate; they are whole-run gates (§4.3). |
| **resolved** | Synonym of `FIXED`; used only in prose that immediately cites §4. |
| **safe** | Not used normatively. The system makes no safety claim; it reports gate results and a `Verdict`. |
| **supported** | A `(scanner, version range, artifact kind)` triple that has both contract fixtures and a pinned integration test (`SCANNER_CONTRACTS.md`). Absent either, the adapter reports `UNSUPPORTED`. |
| **consensus** | Agreement between scanners **only** through an `EXACT` mapping in the control catalog (§8). Advisory always. Never ground truth. |
| **verified** | The single `Verdict` value `VERIFIED`, defined in §10. |
| **evidence** | A recorded, re-readable fact: a raw scanner output reference, a hash, a coverage counter, an oracle result, or a diff. Verdicts cite evidence; evidence never contains a verdict. |
| **baseline** | The artifact tree designated as the "before" state, plus its scan results. |
| **candidate** | The artifact tree designated as the "after" state, plus its scan results. |
| **target** | A selector `(scanner, rule_id, scope[, file/module])` resolved before execution to scanner, rule, canonical resource, file, artifact kind, and native lookup identity (§3). A coarse selector matching several roots is ambiguous. |
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
| `SKIPPED` | Not run by explicit configuration or because the independent eligible scope is empty; must name the typed reason | no |
| `PARTIAL` | Ran but did not cover everything it was asked to cover | no |
| `INCONCLUSIVE` | Ran, covered its input, and the evidence does not decide the question | no |

A boolean must never encode any of `ERROR`, `TIMEOUT`, `UNSUPPORTED`, `PARTIAL`, or
`INCONCLUSIVE`. This is the direct remedy for audit finding F6.

The closed `ArtifactKind` values are `TERRAFORM`, `KUBERNETES_YAML`, and
`KUBERNETES_JSON`. JSON-syntax Terraform (`.tf.json`) remains explicitly unsupported
in Phase D and therefore has no successful artifact-kind value.

The closed `ScanRole` values are `DISCOVERY`, `BASELINE`, and `CANDIDATE`. A
`DISCOVERY` plan is not differential evidence; a protected request re-attests it as the
exact configured side. The closed `ExecutionMode` values are `PR_BASE`,
`PROTECTED_POLICY_REPOSITORY`, and `EXPLICIT_OPERATOR`.

### 1.2 Process execution reasons and group inspection

`ProcessReason` is a closed execution-evidence vocabulary:

`COMPLETED_WITHIN_CONTRACT` `EXECUTABLE_NOT_FOUND` `SPAWN_FAILED`
`DEADLINE_EXCEEDED` `OUTPUT_LIMIT_EXCEEDED` `PROCESS_GROUP_CLEANUP_FAILED`
`LINGERING_DESCENDANTS_TERMINATED` `NO_EXIT_STATUS` `KILLED_BY_SIGNAL`
`EXIT_CODE_OUTSIDE_CONTRACT` `SCRATCH_CLEANUP_FAILED`

The executable status/reason table is:

| Status | Permitted process reasons |
| --- | --- |
| `PASS` | `COMPLETED_WITHIN_CONTRACT` |
| `UNSUPPORTED` | `EXECUTABLE_NOT_FOUND` |
| `TIMEOUT` | `DEADLINE_EXCEEDED` with `timed_out=true` |
| `PARTIAL` | `OUTPUT_LIMIT_EXCEEDED` with `truncated=true` |
| `ERROR` | `SPAWN_FAILED`, `PROCESS_GROUP_CLEANUP_FAILED`, `LINGERING_DESCENDANTS_TERMINATED`, `NO_EXIT_STATUS`, `KILLED_BY_SIGNAL`, `EXIT_CODE_OUTSIDE_CONTRACT`, `SCRATCH_CLEANUP_FAILED` |

`ProcessGroupState` is `ABSENT`, `ALIVE`, or `UNKNOWN`. Only a positive existence
probe yields `ALIVE`; only a not-found result yields `ABSENT`; permission and all other
inspection failures yield `UNKNOWN`. When cleanup remains unknown after a timeout or
output-limit event, the overall evidence is
`ERROR` / `PROCESS_GROUP_CLEANUP_FAILED`, and `primary_execution_event` preserves
`DEADLINE_EXCEEDED` or `OUTPUT_LIMIT_EXCEEDED`.

### 1.3 `MatchingReason` — occurrence-pairing uncertainty

`MATCHING_INCONCLUSIVE`

This is the only D3.1 matching-uncertainty reason. It means two or more occurrence
pairings remain equally supported after native, location, and unique constrained
matching. It must later map to the target outcome `INCONCLUSIVE`, never `FIXED`.

### 1.4 Checkov evaluation evidence

`CheckEvaluationResult` is `PASSED`, `FAILED`, `SKIPPED`, or `UNKNOWN`.

`CheckTargetReason` is `AFFIRMATIVE_TARGET_PASS`, `TARGET_FAILED`,
`TARGET_SUPPRESSED`, `TARGET_EVALUATION_UNKNOWN`, `TARGET_NOT_EVALUATED`,
`RESOURCE_NOT_OBSERVED`, `RULE_NOT_OBSERVED`, or `AGGREGATE_ONLY_EVIDENCE`.
`SCANNER_RUN_NOT_PASS` records that a native pass exists but its enclosing run failed an
integrity or completeness condition.

Only `AFFIRMATIVE_TARGET_PASS` carries `Status.PASS`. Absence and unknown/suppressed
native evidence remain non-pass target evidence.

### 1.5 D4.2 adapter evidence reasons

`RESOURCE_INVENTORY_MISSING` `RESOURCE_COUNT_MISMATCH`
`CONTRADICTORY_EVALUATION_EVIDENCE` `EMPTY_ELIGIBLE_SCOPE`
`INPUT_FILE_COUNT_EXCEEDED` `INPUT_FILE_BYTES_EXCEEDED`
`INPUT_TOTAL_BYTES_EXCEEDED`

These are closed adapter reasons for absent/mismatched independent resource evidence,
contradictory native claims, independently empty scope, and trusted scanner-input
budgets. Their status mappings are specified under V5.

### 1.6 `Verdict` — the outcome of a whole verification

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
stable `id`, `target_id`, `scope`, `reason`, `owner`, `created`, `expires`, and
`permitted_outcomes`, and its trust `origin` is **stamped by the loader that read it** — never taken from a field
inside the record. A record that declares `origin: trusted_base` while being read from
the candidate is stamped `candidate_head`.

The closed `ExceptionOrigin` values are `OPERATOR`, `PROTECTED_POLICY_REPO`,
`TRUSTED_BASE`, `CANDIDATE_HEAD`, and `UNKNOWN`. The first three are loader-trusted;
`CANDIDATE_HEAD` and `UNKNOWN` can never authorise an event.

- An expired exception is `FAIL`, not ignored.
- An exception appearing or broadening in the candidate is `POLICY_DRIFT`.
- An `owner` string is not proof of approval. Approval is established only by the
  record residing in the trusted source, and optionally by a configured
  `approval_binding`: a protected file path, a signed commit, or a required review.
- A suppressed event remains in the report with `policy_permitted: true` and the
  `exception_id` that permitted it.

### 2.5 Exceptions bind to one target, and only for a closed outcome set

A permission is **per target**, never per outcome type. Permitting an outcome type
would let one approved deletion waive every deletion in the repository.

Exception-eligible outcomes — the complete set:

| Outcome | Why it can be knowingly accepted |
| --- | --- |
| `SUPPRESSED` | an organisation may accept a documented, owned suppression |
| `RESOURCE_DELETED` | deleting the offending resource can be the correct remediation |
| `FILE_DELETED_OR_RENAMED` | removing the artifact can be the correct remediation |

Never exception-eligible, and no configuration may make them so:

| Outcome | Why not |
| --- | --- |
| `STILL_PRESENT` | the defect is present; approving it would convert a known unresolved finding into `VERIFIED` |
| `PARTIALLY_FIXED` | some occurrences remain; same reason |
| `SCANNER_ERROR` | absence of evidence cannot be approved into evidence |
| `RULE_OR_SCANNER_DRIFT` | the comparison is invalid; approval cannot make it valid |
| `INCONCLUSIVE` | nothing was established |
| `OUT_OF_SCOPE` | the artifact left scanner selection; that is a coverage loss, not a risk decision |

`FIXED` needs no exception.

#### The record must name the event it authorises

An exception carries `permitted_outcomes`: a non-empty, exact `frozenset[Outcome]` that
is a subset of the eligible set above. **There is no default.** Without this field one
record authorised all three eligible events, so approving a Checkov suppression also
approved deleting the whole Terraform resource and renaming the file out of scanner
scope. Those are different remediations with different risk, and an approval of one is
not an approval of another.

A permission holds only when **all** of these are true, and each clause exists because
its absence would let something through:

1. the outcome is in the exception-eligible set above;
2. an exception record with the claimed `exception_id` exists in the trusted policy;
3. that record names **this** `target_id`;
4. its `scope` matches the target's scope;
5. **the decision's outcome appears in the record's `permitted_outcomes`**;
6. its origin is trusted — never the evaluated change (`candidate_head`);
7. it carries a non-empty `reason` and `owner`;
8. `created <= evaluation_date <= expires`.

Trusted provenance and event authorisation are **separate** requirements: a record from a
trusted source that authorises suppression still cannot authorise deletion, and a record
naming the right event from an untrusted source authorises nothing.

Failing any clause leaves the target unresolved, and the report records the specific
rejection reason rather than silently ignoring the claim.

---

### 2.6 Input validity: malformed input is an invalid request, never `PASS`

Type annotations are documentation, not validation. An unknown status string is neither
in the undecided set nor equal to `FAIL`, so a permissive implementation lets it fall
through to `VERIFIED`. Measured in the reference model before this rule existed:
`required_validator_states=("BOGUS",)` produced `VERIFIED`, and
`scanner_integrity_ok="false"` was read as "integrity held", because a non-empty string
is truthy.

The following are therefore enforced at runtime, and each failure is an invalid request
(exit code 2) rather than a verdict:

1. **Required evidence is explicit.** Preflight, required scanner integrity, at least
   one required validator result, the regression-policy result, and the
   suppression-policy result must all be supplied by the caller. None of them defaults
   to `PASS`. Absence of evidence is not evidence.
2. **Statuses and outcomes are enum members**, not strings that happen to spell one.
3. **Structural flags are booleans**, not `"false"`, `0`, or `1`.
4. **Dates are dates**, not strings or datetimes.
5. **Identity and scope are non-blank and canonical.** Scope comparison uses the
   documented canonical form: trimmed, relative, forward-slash separated, with no
   empty, `.`, or `..` component.
6. **Line ranges are valid**: `start_line >= 1` and `end_line >= start_line`, over a
   canonical repository-relative path.
7. **Collections are validated and frozen at construction.** An exception index whose
   key disagrees with its record's `exception_id` is rejected, duplicate ids are
   rejected, and the collection is copied so that mutating the caller's structure
   cannot change an existing verdict.
8. **Optional gates come from a closed set** (`regression`, `suppression`) and only from
   a trusted configuration source.

### 2.6.1 Identity, scope, and path are validated separately

A resource address is not a filename, and using one path-shaped helper for both is how a
placeholder scope reached an exact-match comparison. Three validators, three rules:

| Kind | Examples | Rules |
| --- | --- | --- |
| identifier (`target_id`, `exception_id`, gate id) | `T-142`, `terraform_hcl_parse` | NFC-normalised, non-blank, no control characters or line breaks, not a reserved placeholder |
| resource scope | `aws_s3_bucket.data`, `module.net.aws_security_group.web[0]`, `apps/v1/Deployment/prod/api` | as above, plus relative, no backslash, no drive prefix, no empty/`.`/`..` component |
| repository path | `modules/s3/main.tf` | as resource scope, plus must name a file rather than a directory |

Reserved placeholders — `unspecified`, `unspecified/scope`, `unknown`, `default`, `n/a`,
`none`, `-`, `todo`, `tbd` and their case variants — are rejected everywhere. `target_scope`
has **no default**: a caller that omits it gets an invalid request, because a generic
placeholder previously matched a placeholder-scoped exception exactly and verified a
`RESOURCE_DELETED` with no real scope.

Identifiers are Unicode-normalised **before** duplicate detection, so `café` written
composed and decomposed is one identity rather than two.

### 2.6.2 Required gates are identities, not counts

Trusted configuration names the required validator and oracle gate **ids**. Observed
results must cover exactly that set:

| Condition | Result |
| --- | --- |
| a required gate produced no result | invalid request (exit code 2) |
| duplicate results for one gate id | invalid request |
| a result for a gate that was not required | invalid request — a substitution cannot stand in |
| one `PASS` where two distinct validators were required | invalid request |
| no oracle results, and no oracle required | valid |
| no oracle results, but an oracle required | invalid request |

Counting statuses is not the same as covering the gates: two required validators are not
satisfied by one `PASS`, and an unknown gate must never be able to fill a gap.

### 2.6.4 Target identity is structured, never a concatenated string

A target is `(scanner, rule_id, scope)`. Authorisation and matching bind that **structured
tuple**. A delimiter-concatenated form is ambiguous, and because exceptions bind to target
identity the ambiguity is exploitable — under `f"{scanner}:{rule_id}@{scope}"` both of
these pairs produced the same string:

```
("checkov", "RULE@X", "scope")  and  ("checkov", "RULE", "X@scope")
("foo:bar", "baz", "scope")     and  ("foo", "bar:baz", "scope")
```

so an exception approved for one target could authorise the other. Three derived forms,
with distinct jobs:

| Form | Purpose | Authoritative? |
| --- | --- | --- |
| `canonical_key` | equality, ordering, authorisation | **yes** |
| `reference` | `scanner=<v>;rule=<v>;scope=<v>` with `%`, `;`, `=` escaped; round-trips exactly | yes, losslessly |
| `opaque_id` | `tid1:` + SHA-256 over a length-prefixed encoding, for report keys | derived |
| `display_ref` | `scanner:rule@scope` for humans | **no**, and never parsed back |

Every report retains the structured fields alongside any derived form.

### 2.6.5 Scanner evidence is internally consistent

A `ScannerRun` owns the provenance of its findings: every finding must carry the run's
`scanner` and `scanner_version`. A Trivy finding inside a run claiming to be Checkov is
self-contradictory evidence, and rewriting the finding to match would destroy the
contradiction instead of reporting it.

`occurrence_index` is a canonical display ordinal only. It is regenerated from each
current finding set and therefore cannot prove occurrence identity: after one duplicate
is removed, a retained occurrence can inherit the removed occurrence's ordinal. Stable
scanner-native occurrence evidence is authoritative when available. Without it, matching
uses equal location evidence first, then only a unique constrained same-resource pairing;
equally supported pairings become `MATCHING_INCONCLUSIVE`. Canonical sorting still makes
report output independent of scanner emission order, and duplicate full evidence records
are rejected with `Counter`-based validation rather than quadratic counting.

### 2.6.6 Arbitrary `Mapping` behaviour is not trusted

The policy boundary accepts an exact `dict`, `tuple`, `list`, `set`, `frozenset`, or an
`ExceptionPolicy` — nothing else. A custom `Mapping` can return one set of records from
`items()` and a different set from `values()`, so validating keys proves nothing about
what is consumed: a probe whose `items()` reported `EX-1` while `values()` returned a
record with a different id built a policy containing that other record. Exact `dict` input is
snapshotted once, and that same snapshot is both validated and consumed.

### 2.6.3 Domain objects are frozen, slotted, and reconstructed

"Frozen" means there is no `__dict__` and no normal attribute assignment. Three designs
that looked immutable were not, and each allowed a stored verdict to change afterwards:
a frozen dataclass holding the caller's `dict`; a `__slots__` class whose object was
still assignable; and a frozen container that rebuilt itself while aliasing the records
inside it. Measured before the rule existed:
`RunObservation.__dict__["policy_drift"] = True` flipped `VERIFIED` to `FAILED`, and
`TargetObservation.__dict__["candidate_matches"] = -1` produced a `FIXED` classification
from an impossible state.

Therefore, for every persistent domain value:

| Rule | Consequence |
| --- | --- |
| frozen **and** slotted | no `__dict__` to write through, no attribute reassignment |
| nested values reconstructed | records, findings and decisions are rebuilt from copied primitives, enums and dates — never aliased |
| collections rebuilt into exact built-in types | a `tuple` subclass with a mutable `__iter__` cannot change a stored verdict |
| canonical ordering | exceptions by `exception_id`, decisions by `(target_id, target_scope, outcome, exception_id)`, findings by full evidence order with display ordinal last |
| exact types at security boundaries | `isinstance` is not used: a `TargetDecision` subclass reporting `FIXED` while storing `STILL_PRESENT` reached `VERIFIED` |

Out of scope, stated plainly: trusted code that deliberately calls
`object.__setattr__` on a frozen instance. That is what the constructor does, so it
cannot be distinguished from legitimate construction.

### 2.7 Evaluation time is trusted execution context

The evaluation date is supplied by the execution context, never defaulted and never
read from the evaluated repository. A hardcoded default silently keeps expired
exceptions valid: a record expiring 2026-12-31 remained in force in 2028 because the
model defaulted to 2026-08-09.

An exception is in force when `created <= evaluation_date <= expires`; both bounds are
**inclusive**. The evaluation date and timezone are recorded in the report so a reader
can tell which day the decision was made on.

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
| `EXACT` | scanner + version + artifact kind + rule_id + file_path + resource_address + stable native occurrence evidence; when native evidence is absent, equal start/end location is constrained evidence | same-domain before/after matching |
| `RELOCATED` | same scanner/version/artifact/rule/resource and equal native occurrence evidence; without native evidence, only a unique remaining pairing | detecting a moved finding instead of one resolved plus one new |
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

The current D3.1 primary algorithm is `iacgv2`: lowercase SHA-256 over canonical compact
JSON containing exactly `algorithm`, `scanner`, `rule_id`, repository-relative
`file_path`, canonical `resource_address`, `native_occurrence_fingerprint`, and
`artifact_kind`, with keys sorted. The stored form is
`iacgv2:<64 lowercase hex characters>`. The regenerated `occurrence_index` is excluded.
Scanner version, line numbers, severity, suppression state, rule display name, and
message are excluded; each remains separate evidence. Native occurrence evidence is
also retained in its own report field. A stored IaC-Guard-V fingerprint that does not
recompute from its finding is malformed evidence and is rejected. `iacgv1` remains a
historical algorithm identifier; D3.1 does not silently change its payload.

---

## 4. Target outcomes

Exactly one value per target. A target contributes to `VERIFIED` only when it is `FIXED`, or when its specific non-fix event is explicitly permitted by a trusted, target-scoped, unexpired exception that **names that outcome** and is drawn from the closed
exception-eligible set (§2.5).

For one target `(scanner, rule_id, scope)` define:

```
N = baseline occurrence count for the target        (N >= 1 by construction)
M = candidate occurrence count proven at EXACT or RELOCATED tier
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
| `FIXED` | `M == 0`, scope present and eligible, integrity `PASS`, no suppression covering the scope appeared, and the target rule/resource has an affirmative native `PASSED` evaluation (or a separately required independent target oracle). **Whole-run oracle results are deliberately not part of this predicate**; see §4.3 |
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

Target absence from failed findings is not affirmative evidence. If the rule, resource,
or target evaluation is absent; only summary counts exist; or the native target result is
`UNKNOWN` or `SKIPPED`, the target is `INCONCLUSIVE` (or `SUPPRESSED` when its complete
predicate is independently established), never `FIXED`.

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
enabled require an exception record per §2.5. A permitted outcome remains visible in
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

### 5.3 D3 matching and finding-derived delta boundary

Same-scanner comparison is an occurrence-preserving, multi-artifact multiset operation:

1. require one scanner/version run identity on each side, reject scanner/version drift,
   partition by artifact match domain, and reject duplicate full evidence records using
   linear `Counter` validation;
2. within every equal artifact domain, match stable-native rule/resource/occurrence keys
   before considering location evidence;
3. group remaining no-native findings by rule and resource. A one-to-one group may
   relocate. A multiple-occurrence group may pair by location only when cardinality is
   equal and both sides have the same unique location multiset. Cardinality or location
   churn makes the complete affected group inconclusive; a reused location is not
   consumed greedily;
4. emit typed `MATCHING_INCONCLUSIVE` evidence for unsupported pairings and remove
   those occurrences from ordinary resolved/new classification;
5. leave different resources and artifact domains present on only one side unmatched,
   producing canonical `RESOLVED_FINDING`/`NEW_FINDING` evidence without cross-domain
   pairing;
6. never use `occurrence_index` as an authoritative key.

The D3 finding-only diff layer may establish `NEW_FINDING`, `LOCATION_CHANGED`,
`SEVERITY_INCREASED`, `SCOPE_EXPANDED`, `SUPPRESSION_ADDED`, and
`RESOLVED_FINDING`. `RULE_SUBSTITUTED`, `COVERAGE_DECREASED`, `DIAGNOSTIC_ADDED`,
`DESTRUCTIVE_CHANGE`, and `POLICY_DRIFT` require engine, scanner, plan, or trusted-policy
evidence and cannot be publicly forged as finding-only deltas.

`FindingDelta` enforces each claim at construction: `LOCATION_CHANGED` requires proven
pair identity and different file/start/end evidence; `SEVERITY_INCREASED` requires a
strictly higher candidate severity rank; `SUPPRESSION_ADDED` requires `false -> true`;
and `SCOPE_EXPANDED` requires complete same-domain rule groups proving a strict resource
set superset. A false label is malformed domain evidence, not a harmless annotation.
Set-derived matching and delta objects also carry private in-process factory provenance.
Public JSON/configuration cannot submit `ScannerRun`, `FindingMatch`,
`FindingMultisetComparison`, `MatchingAmbiguity`, `FindingDelta`, `FindingDiffResult`,
or `CheckovTargetEvidence` as authoritative evidence. D5 accepts only adapter output and
matching/diffing results it invokes internally. This boundary protects deserialisation;
it is not a defence against arbitrary Python code already executing in the verifier.

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
`tool_version`, sanitized resolved launcher path, `launcher_digest`,
`scanner_environment_digest`, `policy_inventory_digest`,
`invocation_config_digest`, `exit_code`, `stdout_sha256`, `stderr_sha256`, `duration_ms`,
`files_eligible`, `files_discovered`, `files_parsed`, `files_failed`,
`evaluations_reported`, `checks_failed_to_execute`, `parse_errors`, byte-bound input-file
evidence, and per-rule/resource `CheckEvaluation` records.

`ERROR` or `PARTIAL` — never `PASS` — when any of the following holds:

1. empty stdout, or output that does not parse as the documented structure;
2. an exit code outside the adapter's documented contract;
3. `files_eligible > 0` and `files_discovered == 0`;
4. `files_parsed` less than `files_discovered` without an explicit allowance;
5. `files_failed > 0` or `checks_failed_to_execute > 0`;
6. `files_parsed` lower than the **independently computed eligible candidate set**
   (§5.1). A raw comparison against the baseline count is explicitly *not* used: a
   legitimate file removal lowers the candidate count without any loss of coverage;
7. scanner environment or policy inventory digest disagreeing with trusted
   configuration. `evaluations_reported` varies with resource count and is never a
   ruleset lock;
8. version outside the supported range, or differing between baseline and candidate;
9. timeout or termination by signal.

Success is never inferred from exit code alone, and failure is never inferred from
the presence of findings.

#### V5 Checkov evidence in D4

Checkov 0 and 1 are both execution-contract exits; only the documented JSON structure
and coverage reconciliation decide integrity. Product 3.3.0 is probed live and every
`summary.checkov_version` must match both that probe and trusted configuration. Research
3.2.517 has a contract fixture but no D4 claim of current native integration.

Because Checkov merges `.checkov.yml` found under its `-d` directory even when an
explicit config file is supplied, the adapter scans a private snapshot containing only
independently eligible files. Candidate configuration and custom checks are not inputs.
Kubernetes `resource_address` comes from the independent canonical identity map;
Checkov's abbreviated `Kind.namespace.name` string does not establish `apiVersion`.

Eligible files are byte-bound at request construction and copied from no-follow opened
descriptors under trusted file-count, per-file-byte, and total-byte limits. Portable
input evidence is path/type/size/SHA-256; device/inode are private runtime checks.
Coverage is derived from native evaluation paths/resources and reconciled separately
against independently expected files and resources. A summary count cannot prove that a
particular eligible file, rule, or resource was evaluated. The machine scan omits
`--quiet` so passed and skipped records remain available.

Process stdout/stderr hashes and the bounded raw-JSON hash are separate evidence. A
missing, empty, malformed, truncated, symlinked, over-cap, or multiply produced JSON
output; summary/results contradiction; parse error; version/digest mismatch; output-view
cleanup failure; or eligible input with no affirmative results/resource evidence cannot
be `PASS`.

JSON parsing rejects duplicate object keys at every nesting level. Result buckets are
closed: `passed_checks -> PASSED`, `failed_checks -> FAILED`,
`skipped_checks -> SKIPPED`, and supported unknown records -> `UNKNOWN`. A contradiction
is `ERROR/INVALID_RESULTS_STRUCTURE`; an unrecognized future bucket is
`PARTIAL/UNKNOWN_RESULT_BUCKET`, never silently discarded.

The expected resource inventory contains file, canonical address, artifact kind, and
native lookup identity. A nonempty scan without it cannot pass. Missing or unexpected
resources are coverage loss; `summary.resource_count` below distinct observed resources
is invalid structure, while disagreement with independent expected cardinality is
partial resource-count mismatch. Evaluation identity excludes native result and bucket;
incompatible claims for the same identity are
`ERROR/CONTRADICTORY_EVALUATION_EVIDENCE`. An independently empty eligible scope is
`SKIPPED/EMPTY_ELIGIBLE_SCOPE`, never `PASS/NO_RESULTS_STRUCTURE`, and cannot establish
`FIXED`.

Ruleset integrity is independent of overall scanner status. Policy/environment digest
mismatch is integrity `FAIL`; version uncertainty is integrity `INCONCLUSIVE`. Output or
process failure may retain integrity `PASS` only after the inventories were independently
proven for that request.

The closed adapter-reason family is: `COMPLETED`, `PROCESS_ERROR`, `EMPTY_OUTPUT`,
`MALFORMED_JSON`, `TRUNCATED_OUTPUT`, `UNEXPECTED_TOP_LEVEL`,
`EXIT_CODE_OUTSIDE_CONTRACT`, `DEADLINE_EXCEEDED`, `KILLED_PROCESS`, `PARTIAL_SCAN`,
`ZERO_FILES_DISCOVERED`, `UNSUPPORTED_VERSION`, `VERSION_MISMATCH`,
`VERSION_PROBE_FAILED`, `NO_RESULTS_STRUCTURE`, `INVALID_RESULTS_STRUCTURE`,
`COVERAGE_MISMATCH`, `FRAMEWORK_MISMATCH`,
`MISSING_RESOURCE_IDENTITY`, `RAW_OUTPUT_MISSING`, and `OUTPUT_CLEANUP_FAILED`.

Additional D4.1 reasons are `INPUT_CHANGED_DURING_SCAN_PREPARATION`,
`SCAN_VIEW_PREPARATION_FAILED`, `OUTPUT_DIRECTORY_INTEGRITY_FAILED`,
`UNKNOWN_RESULT_BUCKET`, `AGGREGATE_ONLY_EVIDENCE`,
`SCANNER_ENVIRONMENT_MISMATCH`, and `POLICY_INVENTORY_MISMATCH`.

D4.3 adds `JSON_DEPTH_EXCEEDED`. Checkov JSON nesting is capped at 128 before the
interpreter JSON decoder runs. Structural brackets inside strings do not count. This
makes the rejection reason deterministic across the supported Python matrix rather than
depending on an interpreter recursion threshold.

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

### 6.1 D5 production evidence boundary

The D5 request has no field for caller-authored `ScannerRun`, `FindingMatch`,
`FindingMultisetComparison`, `MatchingAmbiguity`, `FindingDelta`, `FindingDiffResult`,
`CheckovTargetEvidence`, target outcome, or verdict evidence. The engine invokes Checkov,
affirmative target evaluation, and multiset diffing internally and accepts their results
only with the corresponding private factory provenance. This protects serialized input;
it is not a boundary against Python code already executing inside the process.

Validator and oracle implementations are trusted in-process execution dependencies
selected outside candidate data. Each is invoked by required gate id and a result whose
id differs is malformed substitution. An unavailable implementation returns
`UNSUPPORTED`. It is never replaced by `PASS`.

Before execution, D5 requires an independently attested scan plan. Its factory treats a
public `CheckovScanRequest` only as paths and protected execution configuration, ignores
its caller-provided eligible/resource claims, re-discovers eligible files, reads bounded
regular-file bytes through no-follow descriptors, and detects supported Terraform and
Kubernetes resource identities from the bound content. The future public API therefore
cannot submit resource-presence conclusions. The private plan records portable
path/type/size/digest evidence and a deterministic inventory digest.

For target classification, scanner and ruleset integrity are evaluated before structure
and counts. Structural eligibility, file presence, resource presence, suppression
absence, occurrence sufficiency, and affirmative native target pass remain typed
statuses. Operational uncertainty maps to `INCONCLUSIVE`; a zero candidate finding count
maps to `FIXED` only when the affirmative target-pass status is `PASS`.

Affirmative evidence is file- and artifact-domain-bound. When the protected target has
multiple baseline occurrences, one generic `PASSED` evaluation does not close the
multiset: complete stable occurrence-token coverage in the same evidence domain or an
independent complete-target oracle is required. Counting distinct arbitrary
`evaluated_keys` or file/key pairs is forbidden. Otherwise the reason is
`OCCURRENCE_PASS_COVERAGE_INCOMPLETE`. Stable execution also requires equality of the
scanner identity, version, launcher digest, environment digest, policy inventory digest,
and invocation/config digest.

D5 owns typed evaluations of `RULE_SUBSTITUTED`, `COVERAGE_DECREASED`,
`DIAGNOSTIC_ADDED`, `DESTRUCTIVE_CHANGE`, and `POLICY_DRIFT`; D3 owns the other six
delta classes. Every engine result contains exactly one evaluation for each D5 class.
Unimplemented or uncertain checks are typed uncertainty, never Boolean absence. A
baseline resource missing from the candidate inventory is `DESTRUCTIVE_CHANGE`; an
unrelated deletion is a decisive regression. A new finding with `UNKNOWN` severity is
`INCONCLUSIVE/NEW_FINDING_SEVERITY_UNKNOWN` unless a protected policy later defines a
conservative failure rule.

P0 is derived from the bound file/resource plans and reports their canonical digest.
V4 records deterministic line, file, and resource changes; unavailable policy-file
metrics are explicitly named. Suppression detection reports whether the detector ran
successfully and emits target `SUPPRESSED` events separately. Policy consequence belongs
to D6, so a legitimate exact exception is not defeated by a synthetic global failure.

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

### 7.1 D6 executable policy boundary

The policy request accepts only a D5 `VerificationResult` carrying private engine
factory provenance and a `TrustedPolicyBundle` carrying private production-loader
provenance. It does not accept serialized scanner runs, deltas, target outcomes,
decisions, raw `ExceptionRecord`, collections of records, caller-created
`ExceptionPolicy`, candidate-policy parses, evaluation dates, optional gates, or origin
enums as a substitute.

The base-commit loader requires a protected `TrustedExecutionContext` that names the
authorized base commit, then reads trusted bytes from that Git tree object. A low-level
caller-selected `TrustedGitSource` is insufficient authority. It accepts no
caller-written source identity or arbitrary trusted filesystem path. The protected
policy-repository loader likewise requires an exact pinned commit in a repository
outside the evaluated workspace. The explicit operator loader remains a separate local
mode and reports `OPERATOR`; it is not a PR-mode fallback. Candidate loading always
stamps `CANDIDATE_HEAD` and cannot create a trusted bundle. Candidate comparisons use
bounded no-follow regular-file descriptors. Committed policy paths must be regular Git
tree entries. Policy JSON is strict: duplicate keys, excessive nesting, unknown fields,
malformed dates, duplicate outcomes, and unknown gate names are rejected. Optional gate
names come from the same trusted document as the exceptions.

The evaluation date is captured from a trusted timezone-aware execution clock, converted
to UTC, and stored with timezone and provenance. Repository/config/JSON input has no
evaluation-time field. Policy evidence retains the mechanically resolved source commit
and repository identity, trusted source identity and origin, trusted digest, candidate
presence and digest when present, path-by-path added/removed/changed/stable governed
evidence, and the loader source of each applied exception.

For each engine target classification, D6 derives a fresh decision. A permission exists
only when one record matches the resolved scanner/rule/resource/file/artifact/native
identity, names that exact exception-eligible outcome, has trusted loader-stamped origin, and satisfies
`created <= evaluation_date <= expires`. The event remains unchanged and visible.

Suppression detector operation and suppression policy disposition are separate. A real
`FAILED -> SKIPPED` target flow emits `SUPPRESSED`; an active exact loader-attested
exception may make that event policy-permitted and the otherwise complete result
`VERIFIED`. Candidate, expired, not-yet-active, wrong-event, and wrong-target records do
not. Loader-observed governed-policy drift is decisive even if an upstream caller digest
claimed equality.

The three-step table above is implemented in the written order. `ERROR`, `TIMEOUT`,
`UNSUPPORTED`, `SKIPPED`, `PARTIAL`, and `INCONCLUSIVE` on a required operational gate
cannot become either a pass or a real-negative verdict. An explicitly optional
regression or suppression gate may be `SKIPPED` only when that optionality came from
trusted configuration. Every policy result uses the closed verdict/exit mapping.

#### D6.3 authorized source and clock

The execution context binds mode, evaluated repository object identity, authorized base
commit, candidate commit/root, governed paths, optional protected-repository pin,
verification-config digest, and UTC clock source. The only public Phase-D context factory
is explicit operator mode and captures the current system UTC clock. PR/protected
context construction remains unavailable until protected D7 workflow plumbing exists;
ordinary CLI/config/JSON cannot turn a ref or timestamp into that authority.

`PolicyRequest` requires exact agreement between D5 authorization and D6 execution mode,
context/config identity, repository-object identity, and commit. A bundle from another
repository, base, candidate context, protected source, or operator mode is rejected.
Repository identity derives from protected remote/root Git objects rather than a local
absolute path. Candidate governed reads reject parent-component and final-component
symlinks.

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

## 13. D4.5 artifact-discovery closure

Independent discovery is syntax-complete for the representations supported in Phase D,
not a line-pattern heuristic. Strict HCL parsing governs `.tf`. Bounded syntax-node
inspection first separates ordinary YAML from Kubernetes-like YAML, after which strict
Kubernetes construction supports quoted/flow forms, multiple documents, and `List`
objects. Generic JSON receives strict duplicate-free, depth-bounded classification;
Kubernetes objects and Lists enter the scan as `KUBERNETES_JSON`. Duplicate keys, unsafe
Kubernetes tags, aliases, excessive depth, malformed or incomplete Kubernetes identity,
and currently unsupported `.tf.json` are explicit preflight failures. Every inspected
supported-extension file retains a path, byte digest, syntax kind, classification, and
detected resources; non-Kubernetes YAML/JSON is visible rather than silently vanishing.

## 14. D5.2 protected configuration and exact target binding

`VerificationRequest` contains independently discovered plans, target selectors, and a
private-factory `TrustedVerificationConfigBundle`. Severity floor, location policy,
required gates, framework universe, scanner locks, invocation limits, governed path
digests, and gate-registry identity are absent as ordinary request fields. The operator
loader is explicit local mode; serialized/public inputs cannot construct or restamp the
bundle.

The plan factory re-attests both roots under the bundle's framework/lock universe.
Governed files are discovered and hashed path by path with added, removed, changed, and
stable states. A target resolves to one `ResolvedTargetBinding` containing scanner, rule,
resource, file, artifact kind, and native lookup; repeated addresses require a file or
module selector. Destructive events retain complete `ExpectedResource` records and a
target deletion exempts only its exact key. Production gates come from the versioned
Terraform/Kubernetes registry; the runner exposes no arbitrary callback.

### 14.1 D5.3 role and implementation binding

The protected bundle binds distinct canonical baseline and candidate roots. Reversing
them, using one root twice, reusing a role-bound plan on the other side, changing its
snapshot manifest, or presenting a plan from another configuration is invalid before
execution. Each plan records role, byte-manifest digest, and configuration digest.

The production operator loader accepts gate identifiers only. Its closed packaged
registry records each gate's id, implementation version, code digest, and supported
artifact kinds; no callback parameter exists. Test executors are assembled only inside
the test suite. Governed-path comparison includes `.iac-guard.json` and the protected
scanner, ignore, custom-check, Terraform/OpenTofu, oracle, catalog, severity, exception,
and required-gate configuration catalog. Candidate-only files are `POLICY_DRIFT`.

`checkov-occurrence-v1` is the sole positive/negative Checkov occurrence-token domain.
It binds scanner version, artifact kind, file, rule, resource, evaluated keys, and any
native fingerprint. Multiple occurrences close only by exact token-set coverage or a
complete independent oracle.

## 15. D4.6 installed identity and mixed-repository YAML

The adapter contract identifier is `checkov-adapter-contract-v3`. Scanner evidence
separately records launcher, installed distribution, dependency/runtime lock, built-in
policy, custom-check, combined environment, and invocation digests. Installed Checkov
package/check/policy symlinks are invalid rather than excluded from the manifest;
bytecode caches are rejected deterministically. D4.8 requires wheel RECORD verification,
sets `PYTHONDONTWRITEBYTECODE=1`, and revalidates the executable environment after use.

Root-level syntax evidence decides whether Kubernetes semantics apply. Ordinary YAML
may use anchors, aliases, custom domain tags, or nested `kind` fields and remains
`NON_KUBERNETES_YAML`. A root Kubernetes object using unsafe syntax, or a complete
Kubernetes identity embedded in an unsupported root shape, remains a typed failure.

## 16. D5.4 one-snapshot evidence rule

Baseline and candidate each have one `SealedVerificationSnapshot` binding role,
portable repository identity and relative subpath, complete supported-artifact bytes and
classifications, governed-entry inventory, resource inventory, manifest root, and
trusted configuration digest. Checkov's private view is rebuilt only after its request
proves the eligible source bytes still equal those bindings. Validators and oracles
consume the bound bytes directly. Target presence, resource deletion, V4 metrics, and
report classifications use the same sealed records; no production gate reads the live
root after scanner evidence exists.

P0 performs a final no-follow re-enumeration immediately before aggregate result
construction. Any supported or governed file addition, removal, content change, type
change, or symlink replacement yields `ERROR/SNAPSHOT_CHANGED_DURING_VERIFICATION`.
The result cannot therefore combine scanner state A with validator state B. Canonical
configuration and report identities omit absolute roots and retain both role snapshot
identities, all artifact classifications, resources, governed records, and gate
implementation evidence. Gate identity covers parser/classifier helpers and dependency
versions, not only the dispatcher.

## 17. D6.4 candidate-tree equivalence

For protected Git modes, `candidate_root` is valid only while its `HEAD` equals the
authorized candidate commit and its index/worktree contains no staged, unstaged,
untracked, or ignored supported/governed input. This condition is checked when the
trusted execution context is created and again immediately before policy loading.
Candidate policy/governed bytes are read from the candidate Git object. A bundle is
usable only when its candidate snapshot digest and repository-relative prefix equal the
sealed D5 candidate evidence.

Monorepo verification carries one repository-relative prefix into both base and
candidate Git-object names. Governed paths retain typed absent/file/directory/symlink/
other evidence. A real governed directory is a bounded deterministic recursive manifest;
a symlink or type replacement is drift and cannot collapse to no evidence. Canonical
source identity excludes absolute filesystem roots.

### D4.7 artifact-universe completeness

`FilesystemArtifactEntry` is authoritative source evidence. Its canonical form records
relative path, exact `lstat` kind, regular-file digest and size, symlink target kind and
target-text SHA-256,
supported/governed membership, and any rejection reason. `ARTIFACT_UNIVERSE_UNRESOLVED`
is an `ERROR` preflight result. It is produced whenever either sealed role contains an
unsafe symlink or supported/governed non-regular object; it cannot be combined with
`VERIFIED`. Final revalidation compares the same canonical inventory, so type or target
changes alter the snapshot root.

### D5.5 canonical gate evidence

Every `TrustedVerificationConfigBundle` and `VerificationResult` carries deterministically
ordered gate records: `gate_id`, gate kind, contract version, complete source-manifest
digest, parser dependency identity, and supported artifact kinds. The source manifest
includes bounded file reading, HCL discovery, YAML node and duplicate-key checks,
root-Kubernetes classification, JSON depth handling, and the shared filesystem inventory.
Canonical result evidence also includes each snapshot's complete `filesystem_entries`;
runtime absolute roots and timestamps are not part of these identities.

### D5.6 validator dependency and link-target provenance

Gate records separate `contract_version`, `product_build_digest`,
`parser_dependency_digest`, and `schema_loader_contract_digest`. Parser dependency
identity verifies actual installed python-hcl2 and PyYAML distribution bytes against
RECORD and binds active parser callables. Raw symlink target text is noncanonical private
state; changing it still changes its canonical hash and the sealed snapshot root.

### D7.1 report and request state machine

The only report-v1 branches are verification `VERIFIED/0`, `FAILED/1`,
`INCONCLUSIVE/3`, and operational uncertainty `INCONCLUSIVE/3`. Verification requires
verification, policy, and execution-isolation evidence and forbids an operational
diagnostic; operational uncertainty requires the diagnostic and forbids verification or
policy. Exit 2 is outside report-v1 and means malformed invocation/configuration only.
