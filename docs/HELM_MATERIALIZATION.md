# Helm materialization

IaC-Guard-V can verify before/after changes in local Helm charts when the render is
deterministic, client-side, and completely source-bound. Candidate acceptance can also
evaluate selected properties across an ordered universe of independently rendered
local charts.

## Example

Install Helm and the separately protected Checkov `3.3.0` environment described in
[Advanced installation](ADVANCED_INSTALLATION.md), then run:

```bash
iac-guard helm-verify \
  --before-chart ./before-chart \
  --after-chart ./after-chart \
  --target CKV_K8S_16=apps/v1/Deployment/default/example \
  --helm-executable /absolute/path/to/helm \
  --helm-kube-version 1.31.0 \
  --local-trusted \
  --checkov-executable /absolute/path/to/checkov \
  --output ./iac-guard-helm-report.json
```

The same release name, namespace, values, overrides, Kubernetes version, API versions,
CRD mode, and test mode are required for the before and after renders. Chart bytes may
change because those bytes are the change being verified.

For candidate/head-only evaluation and cross-chart relationships, use the closed
[`helm-accept` request](CANDIDATE_ACCEPTANCE.md). Each chart retains its own protected
materialization identity. A separate combined-universe identity binds chart order,
rendered bytes, resource ownership, and cross-chart graph participants without
flattening source provenance.

## Protected evidence

The report binds:

- Helm version, executable digest, platform, and architecture;
- every chart file and the canonical chart-inventory root;
- `Chart.yaml`, `Chart.lock`, and frozen local dependency artifacts;
- ordered values files, redacted and typed overrides, release name, namespace,
  Kubernetes version, API versions, CRD mode, test mode, and exact argument identity;
- two fresh render attempts with isolated Helm state;
- stdout, stderr, rendered document, and rendered bundle digests;
- one exact `# Source:` marker and Kubernetes identity for each rendered document;
- a per-resource namespace proof binding the protected release namespace, emitted
  `metadata.namespace`, values or static helper source where applicable, resource
  scope, and materialization identity;
- a bounded action-reachability proof for dangerous Helm actions excluded by exact
  protected values;
- digest-only `tpl` evidence when the template string is an exact literal, protected
  values path, or bounded literal default of a protected values path;
- exact dynamic `include`/`template` target evidence when restricted `print` or
  `%s`-only `printf` operands resolve to one protected named template or source file;
- source chart/template to rendered resource to Checkov finding and graph relationship.

## Supported dependency boundary

Verification consumes only dependency bytes already present in the local chart. An
unpacked local subchart is accepted. A remote dependency is accepted only when its
matching artifact is vendored and `Chart.lock` is valid. IaC-Guard-V never runs
`helm dependency update`, resolves a mutable HTTP/OCI chart, or negotiates a version.

Dependency relevance follows `Chart.yaml` and actual content under `charts/`. When
both declare no dependency state, a stray `Chart.lock` remains byte-bound chart content
but does not manufacture a dependency contract. A malformed lock remains fatal when
declared or vendored dependency state is present.

## Fail-closed boundary

The materializer does not support:

- server-side dry runs or Kubernetes connectivity;
- reachable `lookup` or another security-relevant dependency on live cluster state;
- reachable random, password, UUID, or time-dependent helpers;
- dynamic template names, computed or unbound `tpl` inputs, or complex function
  pipelines whose branch reachability cannot be proven exactly;
- plugins, post-renderers, or arbitrary command arguments;
- remote chart locations or dependency downloads;
- ambiguous/missing source markers or duplicate rendered identities;
- unequal bytes, document order, resource identities, source mappings, or semantics
  across the two fresh renders.

These conditions produce a typed operational or `INCONCLUSIVE` result. They are not
silently ignored. Helm stderr is retained by digest and byte count, not copied into the
canonical materialization evidence.

For a namespaced resource that omits `metadata.namespace`, the protected Helm release
namespace is the effective namespace. Explicit literal, `.Release.Namespace`, bounded
values-derived, and bounded static named-helper namespaces retain their source proof.
Cluster-scoped resources must omit `metadata.namespace`. A custom-resource scope must
be established by exact local CRD bytes; an unavailable, dynamic, or contradictory
scope is inconclusive.

Action reachability is intentionally not a Go-template interpreter. It can exclude a
dangerous action only under exact protected values for bounded `if`/`else`, `with`,
`range`, and static named-template calls. Reachable dangerous actions keep their typed
fail-closed outcomes. Unknown reachability remains
`AMBIGUOUS_TEMPLATE_ACTION_GRAPH`; repeated deterministic output alone is not a proof
that a random or cluster-dependent branch is safe.

Bounded `tpl` analysis accepts only an exact quoted literal, an exact protected
`.Values` path, or a literal `default` applied to an exact protected values path.
Parenthesized equivalents are accepted. The resolved template string is never copied
into evidence; its digest, source path/class, callsite, protected-values identity,
nesting depth, nested-action digests, and reached/excluded dangerous-action identities
are bound instead. Nested content is evaluated by the same bounded action rules.
Unknown computed arguments, unsupported nested functions/pipelines, recursion, or
resource-limit exhaustion remain `AMBIGUOUS_TEMPLATE_ACTION_GRAPH`. Reachable lookup
and nondeterministic actions retain their stronger typed outcomes.

Bounded dynamic target resolution accepts only exact literals and the protected
`.Template.BasePath` built-in. Restricted `print` concatenation and `%s`-only `printf`
may resolve one named-template or chart-source identity. The callsite, operand digests,
normalized target string, protected target path/hash, parent/child edge, and bounded
resolution identity are recorded. A missing or duplicate target, path escape,
unsupported operand/pipeline, recursion, or resource-limit exhaustion remains
`AMBIGUOUS_TEMPLATE_ACTION_GRAPH`. Resolved targets are analyzed by the same bounded
action and `tpl` rules; deterministic output never overrides dangerous actions.

This command remains reduced isolation and is suitable only for charts controlled by
the operator. It is not a hostile pull-request sandbox.
