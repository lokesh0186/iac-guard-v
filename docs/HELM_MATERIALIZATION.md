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

The initial materializer does not support:

- server-side dry runs or Kubernetes connectivity;
- `lookup` or another security-relevant dependency on live cluster state;
- reachable random or time-dependent helpers;
- plugins, post-renderers, or arbitrary command arguments;
- remote chart locations or dependency downloads;
- ambiguous/missing source markers or duplicate rendered identities;
- unequal bytes, document order, resource identities, source mappings, or semantics
  across the two fresh renders.

These conditions produce a typed operational or `INCONCLUSIVE` result. They are not
silently ignored. Helm stderr is retained by digest and byte count, not copied into the
canonical materialization evidence.

For this alpha, resources rendered without `metadata.namespace` are authoritative only
under the `default` render namespace. A non-default namespace must be explicit in the
rendered document so Checkov and materialization identities cannot disagree.

This command remains reduced isolation and is suitable only for charts controlled by
the operator. It is not a hostile pull-request sandbox.
