# Threat Model

IaC-Guard-V reads infrastructure code that it does not trust, on a machine that
usually holds credentials, and reports a result someone will act on. All three of
those facts create attack surface.

Scope: the hardened runtime — CLI, Python API, container, and composite GitHub Action.
The research replay tooling is in scope only where it executes frozen content.

---

## 1. Assets

| Asset | Why an attacker wants it |
| --- | --- |
| CI credentials on the runner (`GITHUB_TOKEN`, cloud role, registry token) | lateral movement, supply-chain compromise |
| The verdict itself | a false `VERIFIED` merges an insecure change |
| Source under evaluation | exfiltration of private infrastructure code |
| Scanner and checks-bundle integrity | silent policy weakening |
| The frozen research artifact | destroying reproducibility of a published result |
| Report contents | secrets echoed into logs, PR comments, or SARIF |

## 2. Trust boundaries

```
UNTRUSTED                      | TRUSTED
-------------------------------+------------------------------------------
artifact under evaluation      | IaC-Guard-V code and its own dependencies
PR-head configuration          | policy from the trusted source (semantics §2)
PR-head custom checks/policies | bundled or explicitly trusted policies
scanner stdout/stderr          | pinned scanner binaries and image digests
case bundles from third parties| the frozen research artifact
```

Everything on the left is data. None of it may become instructions, and none of it may
govern its own evaluation.

## 3. Attacker goals and controls

### T1 — Obtain a false `VERIFIED`

| Vector | Control |
| --- | --- |
| Make the scanner produce nothing | V5 treats empty or unparseable output as `ERROR`; exit 3 (semantics §6) |
| Add a suppression | `SUPPRESSED` outcome plus `SUPPRESSION_ADDED` delta; fail by default |
| Delete the offending resource or file | `RESOURCE_DELETED`, `FILE_DELETED_OR_RENAMED` |
| Move the offending configuration to another resource | different resource address, so `RESOLVED_FINDING` on the old plus `NEW_FINDING` on the new; the new finding fails the gate |
| Rename or re-extension the file so it is not scanned | `OUT_OF_SCOPE` plus `COVERAGE_DECREASED` |
| Edit `.iac-guard.yml` or scanner config in the PR | `POLICY_DRIFT`; trusted config used; head version ignored |
| Forge an exception record granting itself approval | exceptions load only from the trusted source; `owner` is not proof; optional `approval_binding` |
| Downgrade the scanner version | V5 version contract; `RULE_OR_SCANNER_DRIFT` |
| Shrink the scanned set | independently eligible files/resources reconciled against per-evaluation path/resource evidence |
| Omit one resource while preserving file-level output | independent expected-resource inventory and separate resource coverage; missing/unexpected/count-mismatched resources cannot pass |
| Emit the same target as both passed and failed | evaluation-identity contradiction is a typed scanner error |

### T2 — Execute code on the runner

| Vector | Control |
| --- | --- |
| Checkov external Python checks | disabled by default; enabling requires an explicit trusted-source opt-in |
| Custom Rego/Conftest policies from a case bundle or PR | only bundled or explicitly trusted policies execute; arbitrary Python and shell never execute |
| `terraform init` fetching a malicious module or provider | `init`, `plan`, and `apply` are never automatic; `init -backend=false` only with explicit permission, a controlled plugin cache, and no backend access; missing modules ⇒ `PARTIAL`/`INCONCLUSIVE`, never success |
| Command injection through paths, rule ids, or config values | argument arrays only; never `shell=True`; no string interpolation into commands |
| Malicious `Makefile`/hooks in the artifact | nothing in the artifact is executed; only declared scanners run |

### T3 — Steal credentials

| Vector | Control |
| --- | --- |
| Scanner or policy reading the environment | environment allowlist (`PATH`, `HOME`, explicit additions); AWS, Azure, GCP, Kubernetes, and GitHub variables stripped |
| Docker or Kubernetes socket access | never mounted |
| Host credential directories | never mounted; workspace is the only source mount, read-only |
| `pull_request_target` with head checkout | never used; fork PRs never receive elevated tokens |
| Token in a PR comment step | comment posting is opt-in; default output is step summary plus SARIF artifact |

### T4 — Exfiltrate source

| Vector | Control |
| --- | --- |
| Scanner or policy calling out | `--network=none` in locked mode; no self-update of scanners or bundles at scan time |
| Telemetry | none, by design and by ADR |
| Report leaking code | source snippets off by default; hashes instead; secret redaction on |

### T5 — Denial of service

| Vector | Control |
| --- | --- |
| Pathological HCL/YAML causing hangs | per-scan deadline; process-group termination on timeout |
| Enormous output | output size cap (default 25 MB) with `PARTIAL` classification |
| Oversized eligible source set | trusted file-count, per-file-byte, and total-byte limits checked before spawn; descriptor bytes are streamed rather than accumulated |
| Deep scanner JSON | recursion/depth failure is typed malformed output, never a raw adapter exception |
| Zip bombs, deep trees, huge repos | independent detector budgets plus scanner-input limits; over-budget requests fail before execution |
| Fork bombs from a scanner | `--pids-limit`, `--memory`, `--cpus` on the container path |
| Orphan processes | kill the whole process group, then verify termination |

### T6 — Supply-chain compromise

| Vector | Control |
| --- | --- |
| Malicious scanner release | pinned versions; image digests; lock file; `--locked` makes drift an error |
| Trivy checks-bundle swap | bundle pinned and digest recorded independently of the binary |
| Kubeconform schema swap | pinned offline schema bundle |
| Third-party GitHub Action | pinned by commit SHA in repository-owned examples |
| Our own release tampered with | checksums, SBOM, build provenance and SBOM attestations, verification instructions |

### T7 — Path and filesystem abuse

Symlinks escaping the workspace, absolute paths in manifests, `..` traversal, device
and FIFO files, and case-collision tricks: all rejected at P0 as `ERROR`, never
silently scanned and never reported as a finding.

### T8 — Destroying research reproducibility

Byte manifest over 4,842 files, checked in CI; unlisted files under frozen prefixes
rejected; legacy semantics quarantined; no history rewrite except under an explicit
licensing determination (ADR-0011).

### T9 — Prompt-style injection through content

Artifacts, scanner output, and case bundles may contain text shaped like
instructions. Nothing in this system interprets content as instructions: there is no
model in the runtime path. Text is normalised, redacted, and rendered as data.

## 4. Trusted configuration as a security boundary

The control for T1's configuration vectors deserves stating on its own, because it is
the difference between a policy and a suggestion.

Governed inputs — `.iac-guard.yml`, exception records, severity policy, control
catalog, oracle policies, `.checkov.yml`, KICS configuration, Trivy configuration,
`.tflint.hcl`, ignore files, and custom-check directories — are loaded from the trusted
source defined in the verification semantics: an operator-supplied path, a protected
workflow input or policy repository, or the base commit of the comparison. Never from
the candidate.

The candidate's copies are read solely to be compared. A difference emits
`POLICY_DRIFT`, names the files and the nature of the change, records both digests as
evidence, and fails by default. Nothing in the candidate takes effect during the run
that evaluates it.

An exception's `owner` field is a label, not an authorisation. Authorisation comes from
the record's location in the trusted source, optionally strengthened by a configured
`approval_binding` (protected file path, signed commit, or required review). The
worked example this defends against is a pull request that adds an exception scoped to
`**` with `owner: security-team` and an expiry in 2099: well-formed, self-granted, and
inert.

Local `repair` mode is exempt, because the operator and the author are the same person
and no privilege boundary is being crossed.

## 5. Isolation the Action can and cannot promise

A Docker **container action** cannot set network, mount, user, or resource options —
`action.yml` exposes only `image`, `env`, `entrypoint`, `pre-entrypoint`,
`post-entrypoint`, and `args`. Promising `--network=none` from a container action
would be false.

Therefore the published Action is a **composite** action that invokes the container
itself:

```
docker run --rm \
  --network=none --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=256 --memory=2g --cpus=2 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --tmpfs /home/iacguard:rw,noexec,nosuid,size=128m \
  -e HOME=/home/iacguard \
  -v "$SRC:/src:ro" -v "$OUT:/out:rw" \
  <image@sha256:...> verify ...
```

`--read-only` without a writable tmpfs breaks Python, every scanner, and report
writing: verified locally, a read-only container fails with
`can't create /tmp/probe: Read-only file system`. The tmpfs mounts above are therefore
functional requirements, not hardening decoration.

A native pip execution mode exists, is labelled `reduced-isolation`, is documented as
unsuitable for hostile pull-request content, and is **never** selected automatically:
when Docker is unavailable the Action fails closed with exit 3.

## 5.1 Process runner is not a sandbox

The host process runner provides defence in depth — isolated HOME, environment stripping,
absolute executable resolution, output bounding, process-group lifecycle — but it is
**not** a filesystem sandbox. A malicious scanner binary or policy script that runs on the
host can still:

- read arbitrary absolute paths (e.g. `/etc/shadow`, `~/.kube/config`);
- read files anywhere in the workspace, not just the scan root;
- open network connections (prevented only by the container layer);
- exhaust CPU, file descriptors, or disk (prevented only by cgroups/ulimits).

The correct isolation boundary for hostile pull-request content is the hardened container
mode. Native execution is labeled `reduced-isolation` and is documented as suitable only
for local developer use where the operator and the author are the same person.

## 6. Residual risks accepted

1. **A scanner false negative remains a false negative.** IaC-Guard-V verifies that a
   change did what it claimed relative to the scanners it ran; it does not discover
   classes of misconfiguration no configured tool detects. V6 and V7 reduce, not
   eliminate, this.
2. **A malicious scanner binary defeats everything downstream.** Pinning and digest
   verification narrow the window; they do not close it.
3. **Redaction is heuristic.** Snippets are off by default precisely because pattern
   matching cannot guarantee secret suppression.
4. **`reduced-isolation` mode is exactly what its name says.** It exists for local
   developer convenience.
5. **Trusted-base policy assumes the base is trustworthy.** A compromised default
   branch compromises the policy. Branch protection is the mitigation and is an owner
   action.
6. **Resource limits are platform-dependent.** `--pids-limit` and cgroup limits behave
   differently across runners; the integration matrix records where they are proven
   rather than assuming them.

## 7. Reporting

Security issues are reported privately via the process in `SECURITY.md` (Phase G), not
through public issues. A finding that IaC-Guard-V can be induced to emit `VERIFIED`
for an unimproved artifact is treated as a vulnerability, not a bug.

## 7. D2.2 Execution Layer Threat Mitigations

### T2 vectors closed in D2.2

| Vector | Control |
| --- | --- |
| Orphaned child processes holding workspace open | Process group termination verifies group death, not just leader; SIGKILL escalation |
| LD_PRELOAD / DYLD_INSERT_LIBRARIES injection | Added to credential denylist; never reaches child |
| PYTHONPATH / NODE_OPTIONS preload | Added to credential denylist |
| Parent PATH pollution with attacker binary | Child PATH is fixed minimal system + explicit trusted_helper_dirs only |
| Secrets in canonical_dict / display_command / logs | redact_argv, redact_detail, redact_option_values applied to all report-facing output |
| Machine paths in reports revealing infrastructure | POSIX and Windows paths redacted; URLs preserved |
| Scratch cleanup failure masking as PASS | Typed gate: cleanup failure → ERROR/SCRATCH_CLEANUP_FAILED |
| Contradictory CommandResult states | __post_init__ rejects PASS+timed_out, PASS+truncated, etc. |
| cwd without workspace boundary | workspace_root mandatory when cwd supplied |
| No record of which binary executed | resolved_executable recorded and auditable |

### Information disclosure mitigations (D2.2)

Report-facing output is redacted through two layers:
1. **Option-value redaction**: values after --token, --password, --secret, --api-key,
   --header are replaced with [REDACTED] before any other processing.
2. **Credential pattern redaction**: AWS keys, GitHub tokens, bearer tokens, API keys,
   and long hex strings are pattern-matched and redacted.
3. **Path redaction**: POSIX paths under /Users, /home, /mnt, /private, /tmp, /var
   and Windows absolute paths are replaced with [PATH]. URLs (http://, https://) are
   preserved.

The `display_command` property on CommandRequest now returns a fully redacted,
shlex.quote'd representation safe for logs and reports.

## 8. D2.3 process-boundary controls and residual native risk

D2.3 closes the remaining direct process-report and path-boundary bypasses:

| Vector | Control |
| --- | --- |
| Adapter-specific secret flag or positional argument | Validated sensitivity metadata is applied identically to display and canonical report surfaces |
| Absolute local paths in arguments, details, exceptions, or cleanup logs | `/Users`, `/home`, `/mnt`, `/private`, `/tmp`, `/var`, `/opt`, `/root`, `/workspace`, `C:\\...`, and `C:/...` forms are replaced; URLs are preserved |
| Private absolute executable path in `argv[0]` | Reports retain only a sanitized basename/tool identity |
| Spawn failure followed by scratch cleanup failure | The result is finalized after cleanup and carries both typed events |
| Permission denied while checking a process group | `UNKNOWN`, never “absent”; unconfirmed cleanup is the stronger `ERROR` result |
| Candidate executable under the evaluated workspace | Strict resolution and workspace containment rejection before spawn |
| cwd/helper/executable path replacement after request construction | Resolution plus device/inode identity and containment are rechecked immediately before spawn |

These checks narrow a TOCTOU window; they do not eliminate it. Native path lookup is not
an atomic sandbox boundary, and a trusted host executable can still read host files or use
the network. Container mode remains mandatory for hostile pull-request evaluation.

Output evidence distinguishes bytes read from pipes (`*_observed_bytes`) from bytes kept
under the per-stream and combined caps (`*_retained_bytes`). When truncated, hashes are
explicitly labelled as covering retained bytes only.

## 9. D4 Checkov adapter controls

The Checkov adapter does not expose candidate configuration, custom-check, external-git,
or module-download inputs. Checkov nevertheless performs implicit config discovery under
the directory supplied to `-d`; an explicit trusted `--config-file` alone does not erase
values merged from candidate `.checkov.yml`. D4 therefore scans an adapter-owned view
containing only independently eligible IaC files. A live mutation probe proves a
candidate `skip-check` is inert in that view.

The adapter pins the version, resolved native-launcher SHA-256, installed environment
digest, and policy-inventory digest. It byte-binds each eligible input, revalidates all
identities immediately before use, disables policy/module downloads and result uploads,
and accepts only a bounded nonsymlink JSON output file with strict duplicate-key parsing.
Passed, failed, skipped, and unknown evaluations are retained. Checkov suppressions stay
typed and target absence never becomes affirmative pass evidence.

Residual risk remains explicit: tree hashing and path revalidation reduce TOCTOU exposure
but are not atomic sandbox boundaries; the private view is not a kernel sandbox, and
Checkov remains trusted executable code. Hostile pull-request evaluation still requires
the digest-bound hardened container. A current 3.2.517 native integration is not claimed
merely because the frozen research output has that version.
