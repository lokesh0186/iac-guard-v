# ADR-0005 — Deterministic, scanner-independent oracles only

- Status: Accepted
- Date: 2026-08-09

## Context

Two claims need evidence a scanner cannot supply. First, "this change genuinely improved
the artifact" — a scanner that stops reporting is not proof. Second, "this scanner has a
defect" — which cannot be established by another scanner disagreeing, because scanners
implement related but non-equivalent policies.

Case bundles will arrive from third parties. Executing arbitrary code from them on a
maintainer's machine or a CI runner is not acceptable (threat model T2).

## Decision

An oracle must be deterministic, versioned, testable, and independent of the scanner
being evaluated. Two mechanisms are permitted:

1. declarative artifact assertions evaluated by our own parser;
2. bundled or explicitly trusted Conftest/Rego policies.

Arbitrary Python, shell, or downloaded policy is never executed. Every oracle records
its id, version, policy hash, result, diagnostics, and an authoritative reference, and
ships with positive and negative fixtures.

The D5 engine invokes required oracle implementations as trusted in-process execution
dependencies selected by operator configuration. A result must repeat the requested
gate identity. Missing implementations are `UNSUPPORTED`, and serialized requests
cannot submit a precomputed oracle result as an engine substitute.

Oracles are optional for routine CI and **mandatory** before any case may be labelled a
validated scanner discrepancy.

## Consequences

- Some interesting checks cannot be expressed declaratively and will not be
  implemented. Accepted.
- Case review is cheap for a maintainer: the oracle result is reproducible without
  installing our tool.
- We can honestly say a disagreement is only an observation until an oracle or an
  authoritative specification settles the expected behaviour.
- Rego adds a runtime dependency for the oracle path only; the core does not require it.

## Alternatives considered

**Multi-scanner majority vote as oracle.** Rejected: agreement is evidence, not truth,
and a majority of tools sharing an upstream policy source is one opinion, not three.

**Allow user-supplied Python oracles behind a flag.** Rejected for 1.0: a flag that
executes untrusted code from a case bundle is a remote-code-execution feature with a
warning label.

## Amendment, 2026-08-11: trusted gate registry

Required gate ids and registry identity come from protected verification configuration.
The production registry implements strict Terraform HCL and Kubernetes YAML validation.

## Amendment, 2026-08-11: sealed gate input and implementation manifest

D5.4 passes one immutable candidate snapshot to every packaged validator and oracle;
gates cannot reread the mutable checkout. Registry implementation identity is a digest
over the dispatcher, Terraform and Kubernetes parser/classifier helpers, the contract
version, and parser dependency versions. A helper or dependency change therefore alters
the recorded identity.
`run_checkov_verification` accepts no callback. A private factory can install a unit-test
registry, but that capability is absent from serialized and future CLI/API inputs.

## Amendment, 2026-08-11: complete implementation manifest

D5.5 replaces selected-function hashing with a canonical manifest of every packaged
validation dispatcher, parser/classifier helper, bounded loader, source reader and path
inventory helper, plus a separate dependency identity. Mutation of any security-relevant
helper changes the implementation digest. Gate reports expose these records directly.

## Amendment, 2026-08-12: validator dependency code

D5.6 separates the gate contract, product implementation, parser distribution/code, and
schema/loader identities. Version strings alone are insufficient: python-hcl2 and PyYAML
installed files are verified against RECORD evidence, and active parser behavior is
bound. A modified or unverifiable dependency cannot silently retain the gate identity.

## Amendment, 2026-08-12: physical parser closure

D5.7 extends identity to every active parser dependency and to the complete physical
installed trees. Bytecode caches, unlisted content, symlinks, unsafe types, path escapes
and RECORD mismatches are incompatible with a trusted packaged gate. Parser identity is
checked before and after execution with bytecode writing disabled. Failure to prove the
identity is typed gate uncertainty, not absence of a validation defect.
