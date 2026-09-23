# IaC-Guard-V 1.0 support contract

Status: proposed. It becomes binding only after approval, implementation, release
candidate validation, and publication with `1.0.0`.

## Product claim

IaC-Guard-V 1.0 is a fail-closed, evidence-bound verifier for the specific IaC
artifacts, materializers, native-property families, and scanner paths declared
here. It does not claim universal infrastructure correctness, live runtime
behavior, provider evaluation, deployment safety, or equivalence among security
scanners.

## Supported artifacts

1. Rendered Kubernetes resources in the exact kinds understood by the selected
   native V1 property.
2. Local Helm charts rendered client-side with every semantic input bound and
   two byte-identical renders required.
3. Local Kustomize input within the reviewed deterministic subset. Remotes,
   plugins, exec, Helm inflation, and unbound external input are unsupported.
4. Terraform source for direct source-local references within the protected
   universe. Provider evaluation, plan instances, remote modules, `init`, and
   `apply` are not inferred or automatically executed.
5. OpenTofu source using the protected `.tf`, `.tofu`, `.tf.json`, and
   `.tofu.json` file-set and precedence rules, with bounded local modules only.

## Native semantic families

The 18 existing public V1 property IDs are the complete 1.0 native-property
set. Their identifiers, parameter schemas, result vocabulary, witness types,
and semantic meanings are stable throughout 1.x. Adding a new property is
permitted in a backward-compatible minor release. Changing a property's meaning
requires a new versioned property ID.

Security-context checks, generic Terraform attribute predicates, and generic
nested-block predicates are not part of the 1.0 native support contract.

## Materialization guarantees

IaC-Guard-V proves only facts about its protected materialized universe. A
materializer result is usable only when inputs are complete, tool identity is
supported, repeated rendering is deterministic, and the protected inventory is
bound into evidence. Missing or unbound input yields a typed non-success result.

## Scanner authority

Native properties independently adjudicate their supported semantics. Checkov
is authoritative only for exact reviewed property/target paths with complete
affirmative evidence and bound tool/policy identity. Trivy and KICS are advisory
by default. Missing output is never a pass. Scanner majority voting is forbidden.
An adapter cannot change the protected artifact universe.

## Fail-closed behavior

Uncertainty never becomes success. Unsupported syntax, ambiguous resolution,
partial scan, absent output, version drift, nondeterministic materialization,
incomplete universe, integrity failure, invalid provenance, and internal error
must resolve to the applicable `NOT_EVALUATED`, `UNSUPPORTED`, `INCONCLUSIVE`,
`INVALID`, or `ERROR` state and non-success exit code.

`SATISFIED` and `VIOLATED` are statements about the selected mechanical
property over the protected evidence. They are not automatic claims of a
project bug, vulnerability, outage, adoption, or runtime behavior.

## Provenance

The four Beta1 provenance tokens remain stable. The caller may use
`PROJECT_AUTHORED` only when public project evidence supports repository-owned
intent. `RESEARCH_HYPOTHESIS` and `SUGGESTED_CONTRACT` must remain available for
external proposals. IaC-Guard-V never upgrades provenance based on a successful
result.

## Schema and report compatibility

- Every Beta1 schema remains accepted exactly.
- A Beta1 v1alpha1 contract must lint, plan, verify, and explain under 1.0
  without source edits.
- If a stable `iac-guard-v.io/v1` contract is added, v1alpha1 remains a supported
  1.x input. A v1alpha1 input continues to produce a v1alpha1-compatible report
  unless the caller explicitly requests a stable-v1 conversion.
- Existing enum values, required fields, reason meanings, result values, and
  exit codes cannot be changed incompatibly in 1.x.
- Implementation and product-version digests are expected to change across
  releases; semantic fixture outcomes and machine-readable structure may not.

## Python and CLI compatibility

Python 3.10, 3.11, 3.12, and 3.13 are supported. Python 3.14 is explicitly not
supported in 1.0 unless the complete release profile passes on 3.14 before the
release candidate is frozen. Lack of 3.14 support is not a blocker when the
upper bound and documentation are explicit.

All Beta1 CLI commands, options, accepted tokens, output modes, public Python
exports, and exit-code mappings remain compatible through 1.x. Removal requires
2.0. Deprecation requires documentation, a warning, and at least one minor
release of overlap.

## External-compatibility guarantee

The release candidate must replay every known public IaC-Guard-V-dependent
issue, pull request, contract, fixture, and documented command. This includes
open, merged, closed, and declined proposals. No 1.0 release is permitted when:

- a Beta1 contract stops parsing or planning;
- a public workflow requires a source edit other than changing the package pin;
- a previously supported deterministic baseline changes result without a
  documented correctness defect;
- an expected negative or ambiguous control changes category without review;
- a JSON consumer, exit-code consumer, or Python consumer breaks;
- a public report can no longer be validated or explained.

If a Beta1 behavior is discovered to be incorrect, correctness takes priority,
but 1.0 must ship a documented compatibility mode or migration path and must not
silently change the result. That exception requires an explicit design decision,
adversarial fixture, and public migration note.

## Backward-compatibility policy

Patch releases may fix defects without changing supported semantics or schema.
Minor releases may add optional fields, new property IDs, or new materializers
without invalidating existing inputs. Incompatible command, schema, property,
result, provenance, witness, or public Python changes require 2.0.
