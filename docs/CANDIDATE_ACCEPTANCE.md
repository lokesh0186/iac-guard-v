# Candidate acceptance

Candidate acceptance evaluates explicitly selected security properties on one complete
candidate snapshot. It is for changes that introduce a new configuration contract or
resource universe that the base revision cannot express.

It is not repair verification. A successful property is `SATISFIED`, never `FIXED`.
The final `VERIFIED` verdict means only that every requested candidate property was
authoritatively satisfied under the recorded snapshot, scanner, parser, materializer,
and evidence scope.

## Direct candidate example

```bash
iac-guard accept \
  --candidate ./candidate \
  --property CKV_AWS_53=aws_s3_bucket_public_access_block.example@main.tf \
  --framework terraform \
  --local-trusted \
  --checkov-executable /absolute/path/to/checkov \
  --output ./candidate-acceptance.json
```

The request must name at least one exact property. IaC-Guard-V does not turn a clean
candidate scan into a claim that the entire candidate is safe.

## Helm multi-chart example

`helm-accept` consumes a closed JSON request because each participating chart retains
its own protected release, namespace, values, override, dependency, and source
identity:

```json
{
  "schema_version": "helm-acceptance-v1",
  "checkov_executable": "/absolute/path/to/checkov",
  "charts": [
    {
      "universe_key": "app",
      "chart_root": "/absolute/path/to/charts/app",
      "helm_executable": "/absolute/path/to/helm",
      "release_name": "review-app",
      "namespace": "default",
      "kube_version": "1.31.0",
      "values_files": ["review-values.yaml"],
      "set": [],
      "set_string": [],
      "api_versions": [],
      "include_crds": false,
      "include_tests": false
    },
    {
      "universe_key": "infra",
      "chart_root": "/absolute/path/to/charts/infra",
      "helm_executable": "/absolute/path/to/helm",
      "release_name": "review-infra",
      "namespace": "default",
      "kube_version": "1.31.0",
      "values_files": ["review-values.yaml"],
      "set": [],
      "set_string": [],
      "api_versions": [],
      "include_crds": false,
      "include_tests": false
    }
  ],
  "properties": [
    {
      "rule_id": "CKV2_K8S_6",
      "resource_address": "apps/v1/Deployment/default/web",
      "file_path": "rendered.yaml"
    }
  ]
}
```

```bash
iac-guard helm-accept \
  --config ./helm-acceptance.json \
  --local-trusted \
  --output ./helm-acceptance-report.json
```

Every chart renders twice in fresh client-only Helm environments. The combined
verification universe binds the ordered chart materialization identities and preserves
source ownership for every rendered resource. Duplicate canonical resources, an
incomplete participating chart, nondeterministic rendering, cluster lookup, or
ambiguous graph evidence remains `INCONCLUSIVE`.

## Outcomes

| Property outcome | Meaning |
| --- | --- |
| `SATISFIED` | The exact requested property has complete affirmative evidence. |
| `VIOLATED` | The exact requested property has complete negative evidence. |
| `INCONCLUSIVE` | The target, scanner, graph, parser, or materialization evidence is incomplete or ambiguous. |

Unselected findings remain counted and digest-bound in the report. They do not become
requested properties and are not silently represented as safe.

## Evidence-completeness universes

Candidate acceptance records three distinct, closed universes:

1. The governed resource universe contains every parsed and rendered resource, with
   exact source/materialization provenance, identity, and hashes.
2. The scanner-addressable universe identifies resources for which the selected
   scanner/check contract can emit a primary evaluation. It is derived from the
   protected check semantics, not from whichever records happened to appear.
3. One target-relevant evidence universe is recorded for every requested property. It
   contains the primary target, every required graph participant, and an explicit
   structural determination for every relationship resource that cannot affect the
   property.

For the supported `CKV2_K8S_6` contract, workloads are primary evaluation targets and
NetworkPolicies are relationship participants. A NetworkPolicy need not have its own
standalone `CKV2_K8S_6` evaluation, but it never disappears from governance. It must be
source-bound and either participate in the requested workload relationship or be
proven irrelevant by namespace or selector semantics.

An unknown selector, missing expected workload evaluation, parser/scanner error,
unbound policy, or unexplained coverage mismatch remains `INCONCLUSIVE`. A raw Checkov
`PARTIAL` result may support a decisive selected property only when its diagnostics are
exactly the independently derived missing standalone records and every such record is
classified `GOVERNED_NON_TARGET_SCANNER_UNADDRESSED`. This is not a general relaxation
of scanner coverage.
