# Tested support matrix

This matrix is generated from versioned product capability metadata. A bounded
or advisory entry is not a claim of complete framework support.

Native registry: `ae1238dfde6fc626b1cb2016b9a79c1ea1fc274b01f62ab7a35a7d002703ae79`

| Surface | Protected input/materialization | Native semantics | Scanner authority | Major fail-closed boundary |
| --- | --- | --- | --- | --- |
| Kubernetes manifests | `DIRECT` | `BOUNDED` | `OPTIONAL` | no live cluster/runtime |
| Helm | `DETERMINISTIC_BOUNDED` | `KUBERNETES_AFTER_RENDER` | `OPTIONAL` | no lookup or remote dependencies |
| Kustomize | `DETERMINISTIC_BOUNDED` | `KUBERNETES_AFTER_RENDER` | `OPTIONAL` | reviewed transformer subset |
| Terraform | `SOURCE_LOCAL_TF_ONLY` | `REFERENCE_V1` | `CHECKOV_REVIEWED_PATHS` | no plan/provider/remote modules |
| OpenTofu | `PROTECTED_FILE_SET_V1` | `REFERENCE_V1` | `NOT_REQUIRED` | local static subset; remote modules fail closed |
| Intent contracts | `V1ALPHA1` | `COMPILED_EXISTING_PROPERTIES` | `NOT_REQUIRED` | explicit intent only |
| Checkov | `ADAPTER` | `NO` | `AUTHORITATIVE_REVIEWED_PATHS` | 3.3.0 locked identity |
| KICS | `ADAPTER` | `NO` | `ADVISORY` | zero findings is not target PASS |
| Trivy | `ADAPTER` | `NO` | `ADVISORY` | no target PASS without exact binding |

Use `iac-guard support --format json` for the machine-readable form.
