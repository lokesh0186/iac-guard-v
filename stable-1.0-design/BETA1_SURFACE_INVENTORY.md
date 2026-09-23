# Beta1 public-surface inventory

## Identity examined

- Package: `iac-guard-v==0.1.0b1`
- Source commit: `b538ad931f193aa7786694080a0beca2a04bbd76`
- Wheel SHA256: `4d5418ba9b4bb1cb9306eeb857732da19de37d896d9a932c4a54a5cb5a751244`
- Supported Python declaration: `>=3.10,<3.14`
- Console entry point: `iac-guard = iac_guard_v.cli:main`

The downloaded public wheel was inspected directly. Its seven schema files are
byte-for-byte identical to the current working-tree copies. The only tracked
change from the Beta1 release commit to the current repository head is release
workflow maintenance. This is encouraging evidence, but it is not a completed
1.0 compatibility replay.

## CLI surface

The declared Beta1 commands are:

| Command | Purpose | 1.0 disposition |
| --- | --- | --- |
| `verify` | Canonical before/after or declared-contract verification | `STABLE_FOR_1_0` |
| `accept` | Candidate-snapshot acceptance over explicit scanner properties | `STABLE_FOR_1_0`, scanner authority must remain bounded |
| `helm-verify` | Deterministic local before/after Helm rendering and verification | `STABLE_FOR_1_0` |
| `helm-accept` | Protected multi-chart Helm acceptance | `STABLE_FOR_1_0` |
| `kustomize-accept` | Bounded local Kustomize build and acceptance | `STABLE_FOR_1_0` |
| `contract init`, `lint`, `plan` | Contract creation, validation, and compilation | `NEEDS_HARDENING` for stable-v1 schema bridge |
| `properties list`, `describe` | Native-property discovery | `STABLE_FOR_1_0` |
| `doctor` | Environment and mode diagnosis | `NEEDS_HARDENING` for exact 1.0 install guidance |
| `demo` | Illustrative and packaged real example | `NEEDS_HARDENING` for non-implementer test |
| `explain` | Validate and render an existing report | `STABLE_FOR_1_0` |
| `support` | Machine-readable capability statement | `NEEDS_HARDENING` to state 1.0 contract exactly |
| `scan`, `differential` | Compatibility aliases for config-driven verification | `STABLE_FOR_1_0`; retain throughout 1.x |
| `lock` | Reduced-isolation environment lock | `STABLE_FOR_1_0` with non-evidentiary warning retained |
| `init` | Advanced config-v1 request creation | `STABLE_FOR_1_0` |
| `pr` | Git object verification without checkout mutation | `STABLE_FOR_1_0` |

All existing option names, defaults, accepted enum tokens, report formats, and
exit semantics require golden CLI tests before 1.0. Report formats are JSON,
console, SARIF, Markdown, and JUnit where the current command permits them.

## Result and exit-code surface

General verification exit codes are fixed for 1.x:

- `0`: `VERIFIED`
- `1`: `FAILED`
- `2`: invalid request
- `3`: `INCONCLUSIVE`
- `4`: internal error

Declared-contract exit codes are fixed for 1.x:

- `SATISFIED`: `0`
- `VIOLATED`: `10`
- `NOT_EVALUATED`: `11`
- `UNSUPPORTED`: `12`
- `INVALID`: `20`
- `ERROR`: `21`

Native-property results are `SATISFIED`, `VIOLATED`, `NOT_EVALUATED`,
`UNSUPPORTED`, and `ERROR`. No missing, empty, partial, ambiguous, or erroneous
evidence may be converted to `SATISFIED`.

## Schema surface

The public wheel contains:

| Schema | Beta1 SHA256 | 1.0 disposition |
| --- | --- | --- |
| `config-v1.schema.json` | `8116c90ab31cafcf7f2a22afd8d71debcdc2c2f5f4dfffc518ba638f9221b967` | freeze |
| `helm-acceptance-v1.schema.json` | `325a5c4d3c42c5571538c2f97185271472e011535de7656b55dcfdc1c4e54bd9` | freeze |
| `infrastructure-contract-v1alpha1.schema.json` | `eb21630e90cf29f724fd6b0886d31a4004249c87d4af25fd698dbee5e90ce721` | retain exact reader; add stable-v1 bridge only after golden proof |
| `infrastructure-contract-report-v1alpha1.schema.json` | `9104c1604cd4985df418645954e71d053e5b965666aeb8a3d6990cc3f43dc857` | retain exact validation and emission for v1alpha1 inputs |
| `native-property-request-v1.schema.json` | `d3533b86036f3ca8833b3d301acaaf9f9f0c9c5f2bdf37a8d98a8a1ba9fd01e8` | freeze |
| `native-property-report-v1.schema.json` | `2c394f49f92fbe6e4380fe6a14f24b3b9829371b5b3c0c8313295f10e6241cd9` | freeze |
| `report-v1.schema.json` | `4a9c856638e342f9672c384f80530802827a58b2e0a2d8db128fc427e99eec42` | freeze |

## Contract and provenance surface

The Beta1 API version is `iac-guard-v.io/v1alpha1`. Existing contracts must
continue to work without edits. Provenance tokens are frozen:

- `PROJECT_AUTHORED`
- `USER_AUTHORED`
- `RESEARCH_HYPOTHESIS`
- `SUGGESTED_CONTRACT`

Responsibility, activation, contract-result, reason-code, subject-cardinality,
and witness semantics used by existing contracts also require fixture-level
compatibility tests.

## Python surface

Beta1 deliberately declares a compatibility snapshot. The following modules and
exports therefore cannot be silently narrowed in 1.0:

- `iac_guard_v`: `__version__`, `api`, `contracts`, `native_properties`
- `iac_guard_v.native_properties`: the registry, model types, evaluation,
  universe loading, discovery, and registry-identity exports named in
  `beta_api.py`
- `iac_guard_v.contracts`: contract model, preparation, planning, evaluation,
  loading, linting, and report-validation exports named in `beta_api.py`

The complete `beta-public-api-v1` snapshot must become a golden 1.x compatibility
test. New stable exports may be added. Existing exports may be deprecated with
warnings and documentation but not removed or behaviorally repurposed before 2.0.

## Materializers and artifact scope

| Surface | Current bounded support | Classification |
| --- | --- | --- |
| Kubernetes YAML | Rendered-manifest semantics only; no live-cluster/runtime guarantee | `STABLE_FOR_1_0` |
| Helm | Local, client-side, double-rendered deterministic universe with bound inputs | `STABLE_FOR_1_0` |
| Kustomize | Reviewed local subset; no remotes, plugins, exec, Helm inflation, or unbound input | `STABLE_FOR_1_0` |
| Terraform | Source-local HCL/reference semantics; no provider evaluation, remote acquisition, plan, or apply | `STABLE_FOR_1_0` |
| OpenTofu | `.tf`, `.tofu`, `.tf.json`, `.tofu.json` protected file set with precedence and bounded local modules | `STABLE_FOR_1_0` |
| Scanner adapters | Checkov bounded-authoritative; Trivy/KICS advisory | `NEEDS_HARDENING` in public authority documentation |
| Hardened hostile-input container | Not released | `DEFER_POST_1_0` unless separately completed and gated |
| Marketplace/composite GitHub Action | Not released | `DEFER_POST_1_0`; provide a pip-based workflow example instead |

## Packaging and release surface

The package name, `iac-guard` entry point, Python 3.10-3.13 support, wheel/sdist
contents, no-telemetry posture, and PyPI Trusted Publishing are suitable bases
for 1.0. The release workflow remains Beta1-specific and needs hardening. SBOM,
build provenance attestations, repeat-build comparison, stable migration notes,
and final source/artifact identity publication remain release blockers.
