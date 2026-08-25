# Reproduce the Shopsys #51 evidence

This reproduction uses only the public IaC-Guard-V `0.1.0a5` package, Checkov `3.3.0`, a local Helm executable, and the exact Shopsys pull-request head.

## 1. Resolve the exact source

```bash
git clone https://github.com/shopsys/helm.git shopsys-helm-51
cd shopsys-helm-51
git checkout --detach 381ceb17d5b630e38f6f6755c40acebd2a44d715
test "$(git rev-parse HEAD)" = "381ceb17d5b630e38f6f6755c40acebd2a44d715"
```

The live base recorded for this run was `29da91c8abd4d4e4c04d0d2a528b3c71cbae44c8`. Candidate-acceptance mode evaluates the head only and does not claim a baseline repair.

## 2. Freeze the local file dependency

Both participating charts declare the repository's local `shopsys-common` chart through `file://../shopsys-common`. Use an isolated Helm preparation environment and build, never update, the exact local dependency:

```bash
export HELM_CACHE_HOME="$PWD/.helm-prep/cache"
export HELM_CONFIG_HOME="$PWD/.helm-prep/config"
export HELM_DATA_HOME="$PWD/.helm-prep/data"
helm dependency build charts/shopsys-app
helm dependency build charts/shopsys-infra
```

Expected protected dependency identities:

```text
97059103f4c1f19441dbf96cfa2138575b70f271d59068b3189460c439720dea  charts/shopsys-app/Chart.lock
bb537e7bffaa98c9cd18f4812197162e5199b6fb0d7308670775be5bf415ecca  charts/shopsys-infra/Chart.lock
f3d7fe1958719de6efee15e6f5495adf60f68fbf8f5bf157755452733e704b0b  shopsys-common-1.0.0.tgz
```

## 3. Install the public verifier and protected scanner

Use two bytecode-free copied-file environments. The exact Python command can vary by platform; this example uses Python 3.13:

```bash
python3.13 -m venv --copies --without-pip .venv-iac-guard
python3.13 -m venv --copies --without-pip .venv-checkov330
python3.13 -m pip --python .venv-iac-guard/bin/python install --no-cache-dir --no-compile 'iac-guard-v==0.1.0a5'
python3.13 -m pip --python .venv-checkov330/bin/python install --no-cache-dir --no-compile 'checkov==3.3.0'
```

Run `iac-guard doctor` before verification. Do not invoke the protected Checkov launcher directly because ordinary Python startup may create bytecode caches.

```bash
.venv-iac-guard/bin/iac-guard doctor \
  --mode local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov"
```

## 4. Create the closed multi-chart request

Create `shopsys-accept.json` with absolute paths for `checkov_executable` and both `chart_root` values. Use this request shape:

```json
{
  "schema_version": "helm-acceptance-v1",
  "checkov_executable": "/ABS/shopsys-helm-51/.venv-checkov330/bin/checkov",
  "charts": [
    {
      "universe_key": "shopsys-app",
      "chart_root": "/ABS/shopsys-helm-51/charts/shopsys-app",
      "helm_executable": "/ABS/helm",
      "release_name": "shopsys-app",
      "namespace": "default",
      "kube_version": "1.31.0",
      "values_files": ["tests/values/required.yaml"],
      "set": [{"key": "networkPolicy.enabled", "value": "true"}],
      "set_string": [],
      "api_versions": [],
      "include_crds": false,
      "include_tests": false
    },
    {
      "universe_key": "shopsys-infra",
      "chart_root": "/ABS/shopsys-helm-51/charts/shopsys-infra",
      "helm_executable": "/ABS/helm",
      "release_name": "shopsys-infra",
      "namespace": "default",
      "kube_version": "1.31.0",
      "values_files": ["tests/values/required.yaml"],
      "set": [{"key": "networkPolicy.enabled", "value": "true"}],
      "set_string": [],
      "api_versions": [],
      "include_crds": false,
      "include_tests": false
    }
  ],
  "properties": [
    {"rule_id": "CKV2_K8S_6", "resource_address": "apps/v1/Deployment/default/webserver-php-fpm", "file_path": "rendered.yaml", "artifact_kind": "kubernetes_yaml"},
    {"rule_id": "CKV2_K8S_6", "resource_address": "apps/v1/Deployment/default/storefront", "file_path": "rendered.yaml", "artifact_kind": "kubernetes_yaml"},
    {"rule_id": "CKV2_K8S_6", "resource_address": "apps/v1/Deployment/default/cron", "file_path": "rendered.yaml", "artifact_kind": "kubernetes_yaml"},
    {"rule_id": "CKV2_K8S_6", "resource_address": "apps/v1/Deployment/default/redis", "file_path": "rendered.yaml", "artifact_kind": "kubernetes_yaml"},
    {"rule_id": "CKV2_K8S_6", "resource_address": "apps/v1/StatefulSet/default/rabbitmq", "file_path": "rendered.yaml", "artifact_kind": "kubernetes_yaml"}
  ]
}
```

## 5. Verify and validate

```bash
.venv-iac-guard/bin/iac-guard helm-accept \
  --config "$PWD/shopsys-accept.json" \
  --local-trusted \
  --format json \
  --output "$PWD/report.json" \
  --quiet

.venv-iac-guard/bin/iac-guard explain "$PWD/report.json" --format console --quiet
shasum -a 256 "$PWD/report.json"
```

The protected materialization identity may differ when the Helm executable, platform, or other bound environment input differs. The five selected properties must still be `SATISFIED`, all rendered resources must remain governed, and the final mode must be `candidate_acceptance` with verdict `VERIFIED` before making the same claim.
