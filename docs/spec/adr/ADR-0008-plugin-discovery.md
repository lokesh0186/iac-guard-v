# ADR-0008 — Entry-point adapter discovery with trusted-config activation

- Status: Accepted
- Date: 2026-08-09

## Context

Adapters should be extensible without forking the core: a user with an in-house scanner,
or a maintainer wanting KICS support before we ship it, should be able to plug in. But
an adapter is arbitrary code that runs in the same process as the verifier, on untrusted
input, possibly in CI with credentials nearby.

## Decision

Discovery uses the Python entry-point group `iac_guard_v.adapters`. Discovery is not
activation: a discovered adapter runs only when named in **trusted** configuration
(semantics §2). Listing an adapter in a pull request does not enable it.

Every adapter must implement the `ScannerAdapter` protocol including `contract()`, and
`doctor` reports every discovered adapter, its origin distribution, and whether it is
activated.

## Consequences

- Third-party adapters need no core change and no fork.
- A malicious package on the machine cannot silently join a scan; it must be named in
  trusted config.
- Adapters shipped by third parties will not have our contract fixtures, so `doctor`
  labels them unverified and they cannot be a required scanner unless the operator
  explicitly makes them one.
- The protocol becomes a compatibility surface. It is versioned, and a breaking change
  bumps the core major version.

## Alternatives considered

**Hard-coded adapter registry.** Rejected: every new scanner becomes a core release, and
private in-house scanners can never be supported.

**Auto-activate everything discovered.** Rejected: installation should not equal trust.
