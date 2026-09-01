# Declared infrastructure intent contracts

IaC-Guard-V 0.1.0a10 verifies a closed, versioned infrastructure contract against
protected deterministic artifacts. Contracts state expected truth; the existing a9
native properties establish mechanical truth. A contract verdict never automatically
means that a project has a bug, vulnerability, outage, or runtime failure.

The single project convention is `.iac-guard-v/contracts.yaml`. A file at that exact
path may be classified `PROJECT_AUTHORED` only when its bytes are present in the exact
declared Git commit at the protected repository root. Working-tree-only files and files
supplied elsewhere require an explicit `USER_AUTHORED`,
`RESEARCH_HYPOTHESIS`, or `SUGGESTED_CONTRACT` provenance selection and can never be
promoted to project-authored by their contents.

## Minimal contract

```yaml
apiVersion: iac-guard-v.io/v1alpha1
kind: InfrastructureContract
metadata: {name: monitoring}
spec:
  artifactClass: kubernetes_rendered
  when:
    all:
      - value: {path: serviceMonitor.enabled, equals: true}
      - value: {path: networkPolicy.enabled, equals: true}
  subjects:
    include:
      identities:
        - monitoring.coreos.com/v1/ServiceMonitor/monitoring/example
    cardinality: {min: 1, max: 1}
  responsibility: {class: PROJECT_MANAGED}
  expect:
    - id: endpoint-resolves
      property:
        namespace: iac_guard_v
        id: IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1
        version: "1"
      relationCardinality: {targetMin: 1}
```

Contract provenance is verifier-derived; it is deliberately absent from the YAML.
Responsibility is interpretation metadata and never rewrites a native witness. An
explicit `OUT_OF_CONTRACT` scope produces fail-closed `NOT_EVALUATED` while retaining
the resolved subject denominator.

## Commands

```bash
iac-guard contract lint --contract .iac-guard-v/contracts.yaml

iac-guard contract plan --contract .iac-guard-v/contracts.yaml \
  --project-root . --source-commit <exact-commit-sha> \
  --contract-root rendered --activation-values values.yaml

iac-guard verify --contract .iac-guard-v/contracts.yaml \
  --project-root . --source-commit <exact-commit-sha> \
  --contract-root rendered --activation-values values.yaml \
  --format json --output contract-report.json

iac-guard explain contract-report.json
```

The project-authored form requires the canonical bytes at the exact commit. For a
working-tree reviewer or research contract, select `--contract-provenance
USER_AUTHORED` or `RESEARCH_HYPOTHESIS`; such a file is never promoted to project
authorship.

For Helm, replace `--contract-root` with `--contract-helm-chart`, provide an exact
`--contract-helm-kube-version`, and optionally provide reviewed values/override
arguments. Activation consumes the same protected effective values as deterministic
Helm materialization. Evidence records the typed value, origin, input digest, and
materialization identity. Unknown, ambiguous, unsupported, or wrong-typed values do not
become false; activation returns `NOT_EVALUATED`.

Activation is for configuration switches, not secrets. Only explicitly requested
scalar paths are emitted, common credential-bearing leaf names are rejected, and a
public evidence packet still requires a contract/report secret scan.

`contract plan` displays exact native requests without evaluating them. `contract lint`
validates strict bytes, syntax, schema, and internal declarations only; provenance is
derived only during plan/verify against a protected source identity.

## Closed semantics

- Results: `SATISFIED`, `VIOLATED`, `NOT_EVALUATED`, `UNSUPPORTED`, `ERROR`.
- Activation: typed scalar equality/presence, bounded `all`, and bounded `any`.
- Subjects: exact identities or exact Kubernetes label selectors.
- Exclusions: explicit and included in the denominator witness.
- Empty matches: not vacuously satisfied unless `allowEmpty: true` and `min: 0`.
- Relationship cardinality: independent `targetMin`/`targetMax`; minimum defaults to 1.
- Properties: immutable `iac_guard_v` native property IDs and versions only.
- Aggregation: every required clause must be satisfied; uncertainty fails closed.

The JSON report is authoritative. It binds contract/provenance, activation, protected
universe, subject denominator, exclusions, compiled native requests, native witnesses,
implementation/registry identities, responsibility, results, and hashes.

The static contract identity covers the protected contract source and declarations. A
separate execution identity covers the protected universe, activation evidence, native
registry, and compiler. Clause identities additionally bind activation and declared
responsibility, so a clause witness cannot be reused under a different activation or
responsibility scope.

Exit codes are 0 satisfied, 10 violated, 11 inactive/not evaluated, 12 unsupported,
20 invalid contract, and 21 contract execution error.

Contracts do not infer intent, vote scanners, call cloud APIs, query a live cluster,
simulate authorization, prove CNI enforcement, evaluate arbitrary CRDs, resolve remote
dependencies, or perform general Terraform evaluation. Checkov 3.3.0 retains its
reviewed authoritative paths; KICS and Trivy remain advisory.

`RESEARCH_HYPOTHESIS` reports state that the invariant came from a researcher and is not
claimed to represent project-authored intent.
