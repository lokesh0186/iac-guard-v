# Supported scope and limitations

This document records the exact boundary of IaC-Guard-V `0.1.0a4`. The concise
landing-page description is intentionally easier to scan; this page is the
authoritative user-facing scope statement.

## Supported path

The supported initial path is target-scoped before/after verification of
Terraform and Kubernetes-related changes using a separately installed,
integrity-checked Checkov `3.3.0` environment.

It includes:

- exact file, resource, rule, scanner, and snapshot binding;
- automatic target discovery from exact baseline findings;
- target outcomes such as `FIXED`, `STILL_PRESENT`, `DELETED`, and
  `INCONCLUSIVE`;
- regression, suppression, deletion, scanner-integrity, parsing, and policy
  gates;
- direct directory verification and exact Git base/head materialization;
- validated `report-v1` evidence;
- bounded evidence for supported Checkov CKV2 connection-graph findings, including
  exact participants, relationships, files, policy bytes, and snapshots;
- deterministic console, JSON, SARIF 2.1.0, Markdown, and JUnit projections.
- deterministic local, client-side Helm rendering under the closed contract described
  in [Helm materialization](HELM_MATERIALIZATION.md).

Native execution is `reduced-isolation` and supports only input controlled by
the operator. A production hostile-input container and GitHub Action have not
been released.

### Terraform file-coverage contract

Every supported `.tf` file is parsed and byte-bound. Parsed files containing a
resource, data source, module, or provider block are `SCAN_EVIDENCE_BEARING` and must
participate in scanner coverage. Parsed support-only files, including files containing
only variable, output, terraform/version, or locals blocks, are `STRUCTURAL_ONLY`:
they remain inside governed scope and the parser universe but do not need an invented
scanner resource identity. Unsupported files remain unsupported, and unrecognized or
ambiguous parsed structure remains `INCONCLUSIVE`. Classification follows content,
not filenames.

## Report-v1 alpha compatibility

`0.1.0a2` retains the `report-v1` name and extends its closed schema with optional
`graph_evidence` and `inventory_completion_basis` members. The project did not promise
an immutable field-for-field wire shape across `0.1.x` alpha releases; prior accepted
report amendments also retained `report-v1` while adding evidence required for
fail-closed validation.

Because `report-v1` uses `additionalProperties: false`, a consumer validating an a2
graph report with a vendored `0.1.0a1` schema will correctly reject the unknown fields.
Such consumers must update to the schema distributed with `0.1.0a2`. `0.1.0a3` adds
the optional parsed file-coverage category described above; consumers using an older
vendored schema must update before validating a3 reports. Older non-graph reports
remain valid under the a3 schema. This is additive alpha evolution, not permission for
projections or consumers to ignore unknown evidence.

`0.1.0a4` adds optional Helm comparison/materialization evidence to `report-v1`.
Consumers using a vendored older schema must update before validating Helm reports.
Non-Helm reports accepted by the a3 schema remain valid under the a4 schema.

## Component status

| Area | Status |
| --- | --- |
| Checkov `3.3.0` | Supported scanner path for the technical alpha. |
| Terraform `.tf` | Supported within the protected parser and exact-target boundary. |
| Kubernetes YAML and Checkov Kubernetes findings | Supported where an exact target can be bound. |
| KICS and Trivy | Experimental/advisory adapters; incomplete runtime cells cannot become ground truth. |
| kubeconform and TFLint | Experimental/advisory validation evidence. |
| OpenTofu `.tofu` / `.tofu.json` | Not supported in the public alpha. |
| Terraform `.tf.json` | Explicitly unsupported/inconclusive end to end. |
| Checkov CKV2/graph findings | Supported only for bounded connection-query shapes with complete participant and relationship evidence; every other shape remains inconclusive. |
| Helm materialization | Supported only for local, client-side, deterministic charts under the bounded a4 contract. |
| Kustomize materialization | No protected materialization contract yet. |
| Multi-scanner consensus | Advisory only and disconnected from the final verdict. |
| Hardened container and composite Action | Not released. |

## Deliberate fail-closed outcomes

IaC-Guard-V does not call a change `VERIFIED` when:

- there are no baseline targets;
- file/resource binding is ambiguous;
- the scanner run is partial, unsupported, malformed, or unverifiable;
- parser or validation coverage is incomplete;
- a target is deleted, suppressed, or replaced rather than repaired;
- an exact supported predicate is unavailable;
- required evidence comes only from caller-authored assertions.

These conditions produce an invalid request, `FAILED`, or `INCONCLUSIVE`
according to the protected contract. An empty result is not a successful repair.

## Multi-scanner research boundary

The current control catalog has zero `EXACT` mappings and remains
`ADVISORY_ONLY`. Its relationships are not ready for automated
validated-discrepancy screening. KICS/Trivy/Checkov agreement therefore cannot
publish a scanner defect or change the product verdict.

This negative conclusion is intentional: incomplete scanner execution and
overlapping policy semantics must not be promoted to ground truth.

## Distribution boundary

The wheel contains product code, public schemas, reporters, validators, the
packaged demonstration, and the protected bundled oracle policy. It excludes:

- `paper.pdf`;
- frozen benchmark data and stored experiment runs;
- prompts, research datasets, and experiment scripts;
- test-only evidence factories and private screening material;
- scanner binaries and third-party schema bundles.

The kubeconform schema bundle remains excluded while its redistribution licence
is recorded as `NOASSERTION`.

## Research and product are separate

The frozen QRS 2026 artifact is historical evidence, not the current product.
Its scanner of record is Checkov `3.2.517`; the product path uses Checkov
`3.3.0`. Stored research outputs are never relabelled as hardened product runs.

See [RESEARCH_SNAPSHOT.md](../RESEARCH_SNAPSHOT.md) for the frozen manifest and
offline replay contract, and [Security model](SECURITY_MODEL.md) for trust and
execution boundaries.

## Current claims

The project claims the behavior demonstrated by its tests, public artifact, and
immutable reproduction records. It does not claim production hostile-input support,
authoritative multi-scanner consensus, automatic validated scanner discrepancies, or
external-project adoption without independent use.
