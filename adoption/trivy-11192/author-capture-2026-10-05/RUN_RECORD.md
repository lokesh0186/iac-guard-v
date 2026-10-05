# Author-run Trivy #11192 before/after capture

On 2026-10-05, the exact PR base
`99fde13b1439de741034e564c22b358b4880bbe8` and fix head
`d3ad0f949a529c47f451a9859b09e60a6a6294de` were built locally with
`go build -o bin/trivy ./cmd/trivy`. The Go VCS metadata reported those exact
clean commits. `reproduce.py` captured all three fixture directories with the
locally available Trivy checks bundle. All six scans exited zero; the
fix-branch `Test_OpenTofuFilePrecedence` also passed its five subcases.

| Fixture | Base file targets | Fix file targets |
| --- | --- | --- |
| `hcl` | `main.tf`, `main.tofu` | `main.tofu` |
| `json` | `main.tf.json`, `main.tofu.json` | `main.tofu.json` |
| `cross` | `main.tf.json`, `main.tofu` | `main.tf.json`, `main.tofu` |

The base's shadowed `main.tf` and `main.tf.json` each contained an
`AWS-0026` failure from an unencrypted EBS volume. Those shadowed-file
findings are absent in the fix capture. The mixed-syntax control still
reports the `main.tf.json` finding. This supports the source-precedence fix
on the exact draft branch; it does not establish a merged or released Trivy
fix, nor an independent maintainer rerun.

[`base/run-summary.json`](base/run-summary.json) and
[`fix/run-summary.json`](fix/run-summary.json) bind the source and binary
hashes, six fixture hashes, and each raw report hash. The corresponding
`hcl.json`, `json.json`, and `cross.json` files are preserved beside each
summary. Finding counts can vary with the checks bundle; the file-target
relationship is the comparison under review.
