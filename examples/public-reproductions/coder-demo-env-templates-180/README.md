# Coder `demo-env-templates` PR #180: target-scoped verification

This directory preserves independent IaC-Guard-V evidence for the privilege-hardening portion of [Coder `demo-env-templates` PR #180](https://github.com/coder/demo-env-templates/pull/180).

## Evidence identity

- Third-party PR: `coder/demo-env-templates#180`
- Verified base commit: `79953152fe83e2005910c9540d8cdc67e12a20bb`
- Verified head commit: `4cf0bd6e9363c34f6f03ecdc9dcf82783c9abbdb`
- IaC-Guard-V: `0.1.0a1`, installed from public PyPI
- Checkov: `3.3.0`
- Evaluation mode: native `reduced-isolation`; trusted local input only
- Evaluation date: `2026-08-21` UTC

## Scope

Only these Checkov targets were adjudicated on Terraform resource `kubernetes_deployment_v1.this` in `deployments/ai.coder.com/coder/realworld/workspace.tf`:

- `CKV_K8S_16` — privileged container
- `CKV_K8S_20` — privilege escalation

The complete resource block was extracted byte-for-byte from each verified commit. Its SHA-256 digests were:

- base projection: `06d8e24b17666a1989e61f31e2f7292154aee6224fbdc8276d73ebd18aa35dca`
- head projection: `2f78f01b68b2879ce2e5780ff0be9d0933c196a95f4a54b076841f0ea0c36a07`

**This is not a whole-PR verification.** It does not certify unrelated resources, modules, changes, or Checkov rules in the pull request.

## Result

| Target | Base | Head | IaC-Guard-V outcome |
| --- | --- | --- | --- |
| `CKV_K8S_16` / `kubernetes_deployment_v1.this` | failing | passing | `FIXED` |
| `CKV_K8S_20` / `kubernetes_deployment_v1.this` | failing | passing | `FIXED` |

- Scanner integrity: `PASS`
- Terraform HCL parse gate: `PASS`
- Regression gate for this target-scoped run: `PASS`
- Final target-scoped verdict: `VERIFIED`
- Exit code: `0`

The canonical validated evidence is [report.json](report.json). [report.md](report.md) is the deterministic Markdown projection generated from that report.

## Reproduce

Install the public `iac-guard-v==0.1.0a1` package and Checkov `3.3.0` using the repository's [advanced installation instructions](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/ADVANCED_INSTALLATION.md). Then, from an empty working directory, reconstruct the exact target projections:

```bash
git clone https://github.com/coder/demo-env-templates.git coder-demo-env-templates

base_sha=79953152fe83e2005910c9540d8cdc67e12a20bb
head_sha=4cf0bd6e9363c34f6f03ecdc9dcf82783c9abbdb
source_file=deployments/ai.coder.com/coder/realworld/workspace.tf

git -C coder-demo-env-templates fetch origin "$base_sha" "$head_sha"
mkdir -p reproduction/base reproduction/head

git -C coder-demo-env-templates show "$base_sha:$source_file" \
  | sed -n '/^resource "kubernetes_deployment_v1" "this" {$/,$p' \
  > reproduction/base/workspace.tf

git -C coder-demo-env-templates show "$head_sha:$source_file" \
  | sed -n '/^resource "kubernetes_deployment_v1" "this" {$/,$p' \
  > reproduction/head/workspace.tf

shasum -a 256 reproduction/base/workspace.tf reproduction/head/workspace.tf
```

Confirm the two hashes match the values above. With the bytecode-free product and scanner environments from the alpha instructions:

```bash
export PYTHONDONTWRITEBYTECODE=1

.venv-iac-guard/bin/iac-guard doctor \
  --mode local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov"

.venv-iac-guard/bin/iac-guard verify \
  --before ./reproduction/base \
  --after ./reproduction/head \
  --target CKV_K8S_16=kubernetes_deployment_v1.this \
  --target CKV_K8S_20=kubernetes_deployment_v1.this \
  --framework terraform \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --format json \
  --output ./coder-180-report.json
```

Reduced isolation is not a hardened sandbox and does not support hostile input. This reproduction evaluates only the exact, reviewed target projections identified above.
