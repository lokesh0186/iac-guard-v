# Scanner Contracts

One section per tool. A tool is **supported** only when it has both contract fixtures
covering the shapes listed here and a pinned integration test. Anything else reports
`UNSUPPORTED`.

Observations marked **verified 2026-08-09** were captured by running the tool on this
machine and are reproduced verbatim. Fields for tools that are not installed here are
taken from official documentation and are marked accordingly; they must be re-verified
against a pinned image before the adapter is declared supported.

---

## 1. Checkov

| Item | Value |
| --- | --- |
| Research pin | **3.2.517** — `requirements.txt:4`, corroborated by `checkov_version` inside all 70 frozen baseline outputs |
| Product version under test | **3.3.0** (installed here) |
| Version probe | `checkov --version` → bare version on the last stdout line (verified: `3.3.0`) |
| Invocation | `checkov -d <private-eligible-file-view> --framework <fw> --output json --compact --output-file-path <private-dir> --config-file <adapter-config> --skip-download --download-external-modules false --skip-results-upload` |
| Frameworks validated | `terraform`, `kubernetes` (the two used by the frozen baselines) |
| External Python checks | **disabled by default**; enabling requires a trusted-source opt-in (threat model T2) |
| External module download | disabled |

The scan directory is an adapter-owned private view containing only paths supplied by
the independent eligible-file detector. Relative paths are preserved. Candidate
`.checkov.yml` / `.checkov.yaml`, custom-check directories, and unrelated repository
content are not copied and therefore cannot govern the run. An explicit adapter-owned
config is still passed because Checkov rejects an empty config document. Each request
binds canonical relative path, artifact type, size, and SHA-256 as portable evidence.
Device/inode remain private runtime race checks and never enter canonical report JSON.
The view is built by opening each source with no-follow safeguards, streaming and hashing
bytes from that descriptor directly into the bounded private copy, and verifying the
copy digest. Any difference is `INPUT_CHANGED_DURING_SCAN_PREPARATION`. It is a scanner
input view, not a native-execution sandbox.

### 1.1 Output shapes the adapter must handle

| Shape | Trigger | Required classification |
| --- | --- | --- |
| Object with `check_type`, `results`, `summary` | normal single-framework run (verified) | parse normally |
| **Summary-only object with no `results` and no `check_type`** | nothing eligible was scanned (verified, see 1.2) | `EMPTY_ELIGIBLE_SCOPE` → `SKIPPED` only when the independent eligible set is empty; otherwise `NO_RESULTS_STRUCTURE` → `ERROR` |
| List of objects | multiple frameworks in one run | parse each element; never silently take `[0]` |
| Empty stdout | crash, kill, or misdirected output | `ERROR` |
| Non-JSON prefix or suffix around JSON | log lines leaking into stdout | prefer `--output-file-path`; if stdout must be used, `ERROR` on parse failure rather than salvaging |
| Truncated JSON | output cap hit, or process killed mid-write | `ERROR` |
| Exit code outside `{0, 1}` | unexpected condition | `ERROR` |

### 1.2 Verified evidence for the empty-scope shape

```console
$ mkdir empty
$ checkov -d empty --framework terraform --output json --quiet --compact; echo "exit=$?"
{
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "parsing_errors": 0,
    "resource_count": 0,
    "checkov_version": "3.3.0"
}
exit=0
```

Two properties matter and both are dangerous if unhandled:

1. There is **no `results` key**, so `data.get("results", {}).get("failed_checks", [])`
   returns `[]` — indistinguishable from "scanned successfully, found nothing".
2. The **exit code is 0**.

This is the live, current-version version of audit finding F1. The adapter therefore
requires an affirmative `results` structure *and* a nonzero `files_eligible`
reconciliation before any target may be classified `FIXED`.

### 1.3 Normalised fields

From `results.passed_checks[]`, `failed_checks[]`, `skipped_checks[]`, and supported
`unknown_checks[]`: `check_id`, `check_name`, `severity` (may be absent on open source),
`resource`, `file_path`, `file_line_range`, `check_result.result`, ordered
`evaluated_keys`, and native fingerprint fields when present. Bucket and native result
must agree. Every record becomes a typed `CheckEvaluation`; failed and skipped records
also become findings.
From `summary`: `passed`, `failed`, `skipped`, `parsing_errors`, `resource_count`,
`checkov_version` (verified present in both 3.2.517 and 3.3.0).

When Checkov supplies no native fingerprint, the adapter retains occurrence evidence by
hashing its ordered `check_result.evaluated_keys` string array as
`checkov-eval-v1:<sha256>`. This remains separate from `iacgv2`; it exists so two checks
against different indexed keys on one resource do not collapse before deterministic
occurrence indices are assigned.

### 1.4 Integrity mapping (semantics V5)

| Evidence | Source |
| --- | --- |
| `tool_version` | `--version` probe, cross-checked against `summary.checkov_version` |
| `files_discovered` / `files_parsed` | distinct eligible paths carried by native evaluation records; never assigned from the eligible count |
| `parse_errors` | `summary.parsing_errors` plus its result bucket when present |
| `evaluations_reported` | `summary.passed + failed + skipped`, plus represented unknown evaluations; never a ruleset inventory |
| `resource_count` | `summary.resource_count` |
| suppressions | `results.skipped_checks[]`, detected independently of result disappearance |

`summary.checkov_version` differing from the probe is `ERROR`: the binary that
reported is not the binary that was probed.

The request also carries immutable independently expected resources: relative file,
canonical resource address, artifact kind, and scanner-native lookup identity where
needed. File and resource coverage are separate. `summary.resource_count` below the
number of distinct observed resources is `INVALID_RESULTS_STRUCTURE`; disagreement with
the independent inventory is `RESOURCE_COUNT_MISMATCH`; missing or unexpected resources
are `COVERAGE_MISMATCH`. A nonempty eligible scan without an independent resource
inventory is `RESOURCE_INVENTORY_MISSING` and cannot pass.

Evaluation identity excludes result and bucket: scanner, version, rule, file, resource,
and ordered evaluated keys. Incompatible claims for that identity are
`CONTRADICTORY_EVALUATION_EVIDENCE` and `ERROR`.

The trusted request separately pins the strictly resolved launcher digest, an installed
distribution-tree digest excluding policy files, and the installed Checkov
`checks/`/`policies/` inventory digest. All are recomputed immediately before use. The
report records sanitized resolved launcher path, `launcher_digest`,
`scanner_environment_digest`, `policy_inventory_digest`, and deterministic
`invocation_config_digest`. Evaluation count is never used as policy identity.

Raw JSON written through `--output-file-path` is accepted only as one nonsymlink regular
`.json` file, read with no-follow semantics under the configured byte cap. Its digest is
recorded separately as `raw_output_sha256`; `stdout_sha256` remains the process stdout
digest. Output-view cleanup failure is a typed `ERROR`, including when execution already
failed.

### 1.5 D4 closed adapter reasons

`COMPLETED`, `PROCESS_ERROR`, `EMPTY_OUTPUT`, `MALFORMED_JSON`,
`TRUNCATED_OUTPUT`, `UNEXPECTED_TOP_LEVEL`, `EXIT_CODE_OUTSIDE_CONTRACT`,
`DEADLINE_EXCEEDED`, `KILLED_PROCESS`, `PARTIAL_SCAN`, `ZERO_FILES_DISCOVERED`,
`UNSUPPORTED_VERSION`, `VERSION_MISMATCH`, `VERSION_PROBE_FAILED`,
`NO_RESULTS_STRUCTURE`, `INVALID_RESULTS_STRUCTURE`, `COVERAGE_MISMATCH`,
`FRAMEWORK_MISMATCH`, `MISSING_RESOURCE_IDENTITY`,
`RAW_OUTPUT_MISSING`, and `OUTPUT_CLEANUP_FAILED` are the complete D4 adapter-reason
family. Unknown scanner conditions are never accepted as a clean run.

D4.1 adds `INPUT_CHANGED_DURING_SCAN_PREPARATION`,
`SCAN_VIEW_PREPARATION_FAILED`, `OUTPUT_DIRECTORY_INTEGRITY_FAILED`,
`UNKNOWN_RESULT_BUCKET`, `AGGREGATE_ONLY_EVIDENCE`,
`SCANNER_ENVIRONMENT_MISMATCH`, and `POLICY_INVENTORY_MISMATCH`. Duplicate JSON object
keys at any nesting depth are `INVALID_RESULTS_STRUCTURE`.

D4.2 adds `RESOURCE_INVENTORY_MISSING`, `RESOURCE_COUNT_MISMATCH`,
`CONTRADICTORY_EVALUATION_EVIDENCE`, `EMPTY_ELIGIBLE_SCOPE`,
`INPUT_FILE_COUNT_EXCEEDED`, `INPUT_FILE_BYTES_EXCEEDED`, and
`INPUT_TOTAL_BYTES_EXCEEDED`. Input count, per-file bytes, and total bytes are trusted
request limits included in `invocation_config_digest` and enforced before spawn.

D4.3 adds `JSON_DEPTH_EXCEEDED`. Before invoking `json.loads`, the adapter enforces a
fixed maximum nesting depth of 128 over structural brackets outside JSON strings. The
scanner is independent of CPython's recursion threshold: depth 128 is accepted for
parsing, depth 129 is rejected with the same typed error on Python 3.10--3.13, and a raw
`RecursionError` remains contained as malformed scanner output.

`ruleset_integrity` is reason-mapped: policy or installed-environment mismatch is
`FAIL`; version mismatch, unsupported version, or failed version probe is
`INCONCLUSIVE`. Ordinary output failures retain `PASS` inventory evidence only because
the installed environment and policy inventories were independently revalidated.

### 1.6 Affirmative target evidence

The machine JSON scan does not use `--quiet`, because quiet output omits positive and
skip records. A target is affirmed only by a `PASSED` evaluation for that exact rule,
resource, and optional file. `FAILED` is failure evidence. `SKIPPED`, `UNKNOWN`, target
absence, resource absence, rule absence, and aggregate-only counts are typed non-pass
target evidence and later force `INCONCLUSIVE`; absence from `failed_checks` is never a
fix predicate.

---

## 2. KICS

Not installed here. Fields below come from the official results documentation and must
be re-verified against a pinned image before the adapter is supported.

| Item | Value |
| --- | --- |
| Version probe | `kics version` |
| Invocation | `kics scan -p <path> -o <output-dir> --report-formats json` (optionally `sarif`) |
| Execution | pinned container image preferred; digest recorded |

### 2.1 Report fields (official names — no shorthand)

Top level: `kics_version`, `files_scanned`, `lines_scanned`, `files_parsed`,
`lines_parsed`, `lines_ignored`, `files_failed_to_scan`, `queries_total`,
`queries_failed_to_execute`, `queries_failed_to_compute_similarity_id`, `scan_id`,
`severity_counters`, `total_counter`, `total_bom_resources`, `start`, `end`, `paths`,
`queries[]`.

Per query: `query_name`, `query_id`, `query_url`, `severity`, `platform`, `cwe`,
`risk_score`, `cloud_provider`, `category`, `experimental`, `description`,
`description_id`, `files[]`.

Per file entry: `file_name`, `similarity_id`, `line`, `resource_type`,
`resource_name`, `issue_type`, `search_key`, `search_line`, `search_value`,
`expected_value`, `actual_value`.

### 2.2 Completeness rules

Any of `files_failed_to_scan > 0`, `queries_failed_to_execute > 0`, or
`queries_failed_to_compute_similarity_id > 0` makes the run `PARTIAL`, and therefore
`INCONCLUSIVE` for a required scanner, unless policy explicitly permits it **and**
target coverage is independently proven. `files_parsed < files_scanned` is likewise
`PARTIAL`.

`similarity_id` is preserved as `native_fingerprint` and never used as the
IaC-Guard-V fingerprint.

---

## 3. Trivy

| Item | Value |
| --- | --- |
| Version installed here | **0.71.1** (verified) |
| Version probe | `trivy --version` → `Version: 0.71.1` on the first line (verified) |
| Invocation | `trivy config --quiet --format json --output <file> <path>` (verified) |
| Scanner scope | misconfiguration only; vulnerability and secret scanning are out of scope for this adapter |
| Checks bundle | pinned **independently** of the binary; digest recorded; no retrieval at scan time in locked mode |

### 3.1 Verified output shape

```
top level: ArtifactName, ArtifactType, CreatedAt, ReportID, Results, SchemaVersion, Trivy
Results[]: Class, MisconfSummary, Target, Type   (+ Misconfigurations[] when findings exist)
```

Two consequences captured from that run:

1. `Results` may contain entries with **no** `Misconfigurations` key. Absence of the
   key is not "no findings for the artifact"; it is "this result class carries none".
   The adapter reconciles against `MisconfSummary`.
2. With `--exit-code 1`, Trivy exited 1 for a tree whose first result had zero
   misconfigurations. Exit code alone therefore identifies neither success nor finding
   count, matching the general rule in semantics §6 V5.

### 3.2 Normalised fields

From `Misconfigurations[]`: `ID`, `AVDID`, `Title`, `Description`, `Message`,
`Namespace`, `Query`, `Resolution`, `Severity`, `Status`, `PrimaryURL`, and
`CauseMetadata` (`Resource`, `Provider`, `Service`, `StartLine`, `EndLine`, `Code`).
`SchemaVersion` is recorded; an unexpected value is `UNSUPPORTED`, not a best-effort
parse.

### 3.3 Offline behaviour

Air-gapped operation requires the checks bundle to be present in the image or cache.
A missing or unretrievable bundle is `PARTIAL`, never a clean pass, because absent
policies produce absent findings.

---

## 4. Independent validators

These establish validity without the security scanner (semantics V1). None is a
security scanner and none participates in agreement counts.

| Tool | Role | Notes |
| --- | --- | --- |
| Independent HCL parser | `syntax_valid` for Terraform/OpenTofu | required; removes Checkov from the parsing path (audit F2) |
| `terraform validate -json` | `schema_valid` | controlled mode only; needs provider schemas ⇒ `validation_requires_init`; `init`/`plan`/`apply` never automatic |
| `tofu validate -json` | `schema_valid` | same rules |
| Safe multi-document YAML parse | `syntax_valid` for Kubernetes | must handle multi-document streams and duplicate keys explicitly |
| `kubeconform` | `schema_valid` for Kubernetes | pinned offline schema bundle; missing schema ⇒ `UNSUPPORTED`, never valid |
| `tflint` | Terraform correctness and style | optional, labelled non-security, excluded from consensus |

None of these tools is installed on the development machine except through the pinned
container path; the support matrix below records that honestly.

---

## 5. Support matrix

| Tool | Version(s) | Contract fixtures | Pinned integration test | Status |
| --- | --- | --- | --- | --- |
| Checkov | 3.2.517 (research), 3.3.0 (product) | **PASS, D4.1** for both versions | **PASS, D4.1**: five installed 3.3.0 tests cover Terraform/Kubernetes affirmative pass, inline skip, missing-file coverage, byte replacement, and inert candidate config; 3.2.517 executable re-run remains Phase E | product 3.3.0 supported; research 3.2.517 has a frozen-shape contract fixture and offline replay, but is not claimed as a current native integration |
| KICS | pinned image, version TBD | Phase E | Phase E | documented from official schema; **not yet verified locally** |
| Trivy | 0.71.1 + pinned bundle | Phase E | Phase E | output shape verified 2026-08-09; bundle pinning outstanding |
| terraform validate | TBD | Phase E | Phase E | not installed locally |
| tofu validate | TBD | Phase E | Phase E | not installed locally |
| kubeconform | TBD | Phase E | Phase E | not installed locally |
| tflint | TBD | Phase E | Phase E | not installed locally |

## 6. Contract test set

Every adapter must pass the same twelve shapes before being called supported:

1. valid output with findings; 2. valid output with zero findings and eligible files;
3. empty stdout; 4. malformed JSON; 5. truncated JSON; 6. unexpected top-level type;
7. nonzero exit with valid findings; 8. timeout; 9. killed process;
10. partial-scan indicators set; 11. zero files parsed despite eligible inputs;
12. version outside the supported range.

Plus two adapter-specific additions established above: for Checkov, the
summary-only-no-`results` shape; for Trivy, a `Results` entry with no
`Misconfigurations` key.

## 7. Independent artifact-discovery contract (D4.5)

Terraform `.tf` files are decoded as strict UTF-8 and parsed with the bounded
`python-hcl2` grammar before resource addresses enter the expected inventory. Terraform
JSON (`.tf.json`) is deliberately unsupported in Phase D and its presence under a
required Terraform framework is an explicit preflight error, never an ignored file.

Kubernetes `.yaml`/`.yml` files use a bounded syntax-node classifier before strict
Kubernetes construction. This prevents YAML 1.1 scalar coercion or a non-Kubernetes
custom tag from rejecting ordinary workflows and CloudFormation documents. Once root or
nested `apiVersion`/`kind` evidence exists, duplicate keys, custom tags, aliases, nesting
above 64, more than 128 documents, excessive nodes, malformed syntax, and incomplete
identity fail closed. Quoted keys, flow maps, multiple documents, and Kubernetes `List`
items are supported; absent namespace means `default`.

When Kubernetes is required, generic `.json` files are decoded as strict UTF-8 and
parsed with duplicate-key and deterministic depth rejection. Kubernetes objects and
`List` items become `KUBERNETES_JSON` resources; ordinary JSON is classified but not
scanned. `.tf.json` remains the explicit Terraform-JSON error and is never reinterpreted
as Kubernetes. Every inspected `.tf`, `.yaml`, `.yml`, and relevant `.json` file has a
digest-bound classification record even when it is non-Kubernetes and therefore absent
from the private Checkov view.

## 8. Checkov adapter contract v3 (D4.6)

`checkov-adapter-contract-v3` changes whenever invocation flags, supported parser or
artifact semantics, coverage reconciliation, policy inputs, or output normalisation
change. Identity fields are deliberately separate: resolved launcher digest, installed
Checkov package manifest digest, dependency/runtime lock digest (verified wheel RECORD
closure), built-in policy inventory digest, custom-check digest, combined environment
digest, and invocation-config digest. `__pycache__`, `.pyc`, and `.pyo` are rejected. A symlink or
non-regular entry under the installed Checkov package, checks, or policies is rejected;
it is never silently skipped.

The YAML classifier first performs bounded syntax-preserving root inspection. Aliases,
anchors, domain tags, and nested `kind` fields in clearly non-Kubernetes documents do
not trigger Kubernetes-only restrictions. Root Kubernetes identity and unsupported
nested complete identity remain fail-closed. Every inspected supported-extension file
continues to retain its digest-bound `ArtifactClassification`.

## 9. Complete filesystem and native environment contract (D4.7)

The adapter receives eligible regular files from the same bounded no-follow inventory
that seals the role snapshot. Directory links are recorded and rejected without being
traversed. Supported-extension directories, FIFOs, sockets, devices, symlinks and other
non-regular entries are typed rejected evidence, not absent files. The scan-view input,
snapshot root and report bind the inventory entry and any rejection reason.

Native Checkov identity hashes actual regular bytes across the installed dependency
closure, not only `.dist-info` metadata. It rejects `__pycache__`, `.pyc`, and `.pyo`
and rejects missing, symlinked, escaping or non-regular executable/package/policy/
dependency content. Failure to establish this complete native identity is operational
uncertainty and cannot support a final `VERIFIED` result.

## 10. Executable native environment closure (D4.8)

Every executable installed file must be present in a wheel `RECORD` with a matching
SHA-256 and size. Missing files, extra executable code, escaping records, editable or
otherwise unverifiable installs, symlinks, and bytecode/cache content are rejected.
Unhashed interpreter-generated bytecode rows that pip appends to an installed `RECORD`
are excluded from the source manifest and the referenced bytecode is required to be
absent on disk.
Both version probing and scanning set `PYTHONDONTWRITEBYTECODE=1`; the environment is
revalidated after execution so newly created executable content becomes
`SCANNER_ENVIRONMENT_MISMATCH`, never clean evidence.
