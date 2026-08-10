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
