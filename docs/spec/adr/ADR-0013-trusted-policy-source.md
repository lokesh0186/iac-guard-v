# ADR-0013 — Policy loads from the trusted base, never from the candidate

- Status: Accepted
- Date: 2026-08-09

## Context

The tool evaluates a change against a policy. If the change can edit the policy, it can
approve itself. Concretely, a pull request could add to `.iac-guard.yml`:

```yaml
exceptions:
  - id: EX-1
    scope: "**"
    reason: approved
    owner: security-team
    expires: 2099-12-31
```

Every field is present and well-formed. None of it is evidence of approval, because the
change being evaluated wrote it. The same applies to `.checkov.yml`, `.trivyignore`,
KICS configuration, `.tflint.hcl`, custom-check directories, and the workflow's own scan
paths — the frozen harness had no boundary here at all (audit finding F12).

## Decision

In PR mode, all governed configuration is loaded from a trusted source, in precedence
order: an explicit operator-supplied path; a protected workflow input or protected policy
repository; the **base commit** of the comparison. The candidate's copies are read only
to be compared, never to be applied.

Any difference emits `POLICY_DRIFT`, names the differing files and the nature of the
change, records both digests as evidence, and by default fails.

An `owner` string is never proof of approval. Approval is established by the record
living in the trusted source, optionally strengthened by a configured
`approval_binding`: a protected file path, a signed commit, or a required review.

In local `repair` mode the working tree may supply configuration, because the operator
and the author are the same person and there is no privilege boundary to cross.

## Amendment, 2026-08-09: provenance is stamped, not declared

Loading a record that contains `origin: trusted_base` and believing it reproduces the
original defect one level down: the candidate would be describing its own
trustworthiness. Trust is therefore a property of the **loader**, not of the record:

- `load_trusted_exception(payload, origin)` stamps an origin the caller establishes by
  having read the bytes from a trusted place, and rejects an untrusted origin outright;
- `load_candidate_exception(payload)` always stamps `candidate_head`, discarding any
  `origin` field in the payload;
- the evaluation date comes from the execution context, never from repository
  configuration, so a candidate cannot extend its own exception window.

Exception records also carry `created` as well as `expires`, and a record is in force
only when `created <= evaluation_date <= expires`, inclusive on both bounds. A record
whose window has not opened yet is rejected with `not yet in force`.

## Amendment, 2026-08-09 (second): trust and authorisation are separate

Binding an exception to a target and a scope was not sufficient. The record said *who*
approved *which target*, but not *what was approved*, so one record authorised all three
exception-eligible events: an approved Checkov suppression also authorised deleting the
Terraform resource and renaming the file out of scanner scope.

`ExceptionRecord` therefore carries `permitted_outcomes`, a non-empty exact
`frozenset[Outcome]` with no default, constrained to the eligible set. The permission
check requires `decision.outcome in record.permitted_outcomes` in addition to every
existing clause.

The two properties are independent and both required:

| | trusted origin | names the event |
| --- | --- | --- |
| authorises | yes | yes |
| rejected: `origin 'candidate_head' is not trusted` | no | yes |
| rejected: `authorises ['SUPPRESSED'], not RESOURCE_DELETED` | yes | no |

Loaders parse and validate the field, rejecting a missing authorisation, unknown outcome
names, duplicates, never-permittable outcomes, and malformed collection types.

## Consequences

- A legitimate policy change takes two steps: merge the policy, then the change that
  needs it. That friction is the security property, not a defect.
- The engine must fetch and compare configuration from a git ref, so PR mode needs the
  base commit available — the documented workflow uses `fetch-depth: 0`.
- `POLICY_DRIFT` will fire on legitimate housekeeping (reordering, comments). The event
  names the nature of the change so a reviewer can approve it quickly.
- A compromised default branch compromises the policy. Branch protection is the
  mitigation and is an owner action, recorded as a residual risk in the threat model.
- A forged-exception fixture is a required Phase D test, so this cannot regress silently.

## Alternatives considered

**Trust the candidate's config, and just report that it changed.** Rejected: reporting a
self-granted approval after applying it is theatre.

**Require policy to live in a separate repository.** Rejected as a default: too much
setup for a first-time user. Supported as an option for organisations that want it.

## Amendment, 2026-08-10: Checkov implicit configuration discovery

A D4 live probe showed that passing an explicit trusted `--config-file` does not by
itself neutralise candidate `.checkov.yml`: Checkov merges values from config discovered
under the `-d` directory. A candidate `skip-check` removed a known finding.

The Checkov adapter therefore builds an adapter-owned view containing only independently
eligible IaC files, preserving their relative paths, and scans that view. Candidate
Checkov configuration and custom-check sources are never copied or accepted as request
inputs. With the same mutation, both known findings remain present. This is the concrete
adapter enforcement of this ADR, not merely a loader convention.

D4.1 additionally binds the exact eligible-file bytes before scan-view preparation and
hashes the installed policy inventory independently of the launcher. No-follow reads and
copy-digest verification detect in-place replacement even when device/inode remain
unchanged. These checks reduce but do not eliminate TOCTOU exposure; native execution is
still not a sandbox.

## Amendment, 2026-08-11: trusted independent resource inventory

The expected resource inventory is trusted detector/parser output, not scanner output
and not a candidate-authored precomputed verdict. It binds canonical file, resource,
artifact kind, and the native lookup key used to reconcile Checkov. Policy/environment
digest mismatch fails ruleset integrity even when the overall execution already ended in
`ERROR`; status fields cannot contradict the integrity diagnostic.

## Amendment, 2026-08-11: permission is derived inside D6

D6 never trusts a caller-authored `policy_permitted` flag. It defensively rebuilds the
protected exception collection and creates a fresh decision only after proving exact
structured target identity, exact event authorisation, trusted loader-stamped origin,
and the inclusive execution-date window. The original event remains in the result.
Caller-authored engine, target, or delta evidence cannot reach this decision boundary.

## Amendment, 2026-08-11: production loader attestation

The loader convention is now executable production code. `PolicyRequest` accepts only a
private-loader-attested `TrustedPolicyBundle`, never a raw record, record collection,
caller-created policy, candidate parse, evaluation date, optional-gate set, or origin
enum. Base-commit, protected-policy-repository, and operator loaders stamp provenance;
candidate loading always stamps `CANDIDATE_HEAD`. Serialized `origin` is ignored.

The bundle binds trusted source identity/origin, trusted policy digest, candidate
presence/digest evidence, differing governed paths, protected optionality, and a UTC date captured from
the trusted execution clock. Policy reports preserve those facts and the exact loader
source for each applied exception. File loaders use bounded no-follow reads and strict
duplicate-free, depth-bounded JSON. This is an application trust boundary: arbitrary
Python code already executing inside the verifier remains trusted and can call internal
hooks, so the future public API must expose neither loader selection nor those hooks.

Target suppression is an event, not a detector failure. A completed detector reports
operational success while D6 applies the exact protected exception. Unrelated
`SUPPRESSION_ADDED` evidence remains a regression and is not waived by that target event.

## Amendment, 2026-08-11: candidate syntax cannot choose its scan universe

The trusted scan-plan factory parses required `.tf`, `.yaml`, and `.yml` inputs with
bounded independent parsers. Valid quoted or flow Kubernetes YAML enters the protected
view; malformed or unsupported identity evidence fails preflight. Candidate
`.checkov.yml` remains excluded, and `.tf.json` remains explicitly unsupported until a
tested contract exists.
