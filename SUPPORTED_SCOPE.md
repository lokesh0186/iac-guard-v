# Supported scope for IaC-Guard-V 1.0

This document is the release-facing support boundary for `iac-guard-v==1.0.0`.
Anything not listed here is not silently supported.

## Supported artifacts and materializers

IaC-Guard-V supports rendered Kubernetes resources for the exact native V1 property
selected by the request. It supports local Helm charts when all semantic inputs are
bound and two renders are byte-identical. It supports the reviewed local Kustomize
subset without remotes, exec plugins, Helm inflation, or unresolved external input.

Terraform support covers exact direct source-local references in `.tf` files. It does
not evaluate providers, plans, remote modules, `init`, or `apply`. OpenTofu support is
separate and covers bounded local `.tf`, `.tofu`, `.tf.json`, and `.tofu.json` file
sets with explicit precedence, shadowing, override, and local-module evidence.

Helm and Kustomize prove facts about protected rendered output, not about a live
cluster. The tool does not establish admission behavior, controller reconciliation,
CNI enforcement, packet delivery, provider behavior, or deployment safety.

## Native property boundary

The complete 1.0 native-property set is the 18 IDs in [Native properties](NATIVE_PROPERTIES.md).
Their version, parameters, witness type, result vocabulary, and semantic meaning are
stable for 1.x. Container security-context checks, generic Terraform attributes,
generic nested blocks, arbitrary CRDs, and general policy languages are not included.

## Deterministic evidence requirements

A successful result requires a complete protected input universe, supported syntax,
unambiguous identity and resolution, and content-bound evidence. Helm renders must be
byte-identical across two executions. Unsupported input, nondeterminism, incomplete
inventory, ambiguity, integrity failure, or missing evidence produces a typed
non-success result.

## Scanner support

Checkov 3.3.0 is authoritative only for exact reviewed property and target paths with
complete affirmative evidence. The frozen research version 3.2.517 remains historical
replay evidence. Trivy 0.73.0 and KICS 2.1.20 are advisory by default. Kubeconform,
TFLint, `terraform validate`, and `tofu validate` establish only the bounded facts
assigned to their validators. Scanner voting is never authoritative.

Third-party scanners and validators are installed separately and are not bundled in
the wheel.

## Python and operating boundary

Python 3.10, 3.11, 3.12, and 3.13 are supported. Python 3.14 is outside the 1.0
support matrix. Native execution and local materialization are reduced-isolation modes
for operator-controlled input. IaC-Guard-V 1.0 does not claim to sandbox hostile code.

## Schemas and provenance

The existing `iac-guard-v.io/v1alpha1` contract and report forms remain supported.
The stable `iac-guard-v.io/v1` form has the same semantics and is used only when a
caller explicitly chooses it. The four provenance tokens remain valid:
`PROJECT_AUTHORED`, `USER_AUTHORED`, `RESEARCH_HYPOTHESIS`, and
`SUGGESTED_CONTRACT`. Successful verification never upgrades provenance.

## Explicit exclusions

IaC-Guard-V does not claim universal IaC verification, vulnerability discovery,
authorization simulation, live infrastructure state, cloud correctness, arbitrary
Terraform evaluation, automatic remote dependency resolution, model inference, or
semantic equivalence between scanners. It has no telemetry and does not automatically
use cloud credentials, query a cluster, or call a model provider.
