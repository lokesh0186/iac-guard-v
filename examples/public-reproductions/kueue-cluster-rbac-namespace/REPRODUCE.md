# Reproduce the Kueue cluster-scoped RBAC namespace result

This procedure uses the exact public IaC-Guard-V release, public Kueue source, a local
client-side Helm renderer, and Checkov `3.3.0`. It does not connect to a Kubernetes
cluster.

## 1. Resolve the source

```bash
git clone https://github.com/kubernetes-sigs/kueue.git kueue-rbac-reproduction
cd kueue-rbac-reproduction
git checkout --detach 09560ad1624f75cb26cdd440281160f0b4cec776
test "$(git rev-parse HEAD)" = "09560ad1624f75cb26cdd440281160f0b4cec776"
```

## 2. Install only public released software

Use copied-file, bytecode-free environments. Adjust the Python executable for the
local platform if necessary.

```bash
python3.12 -m venv --copies --without-pip .venv-iac-guard
python3.12 -m venv --copies --without-pip .venv-checkov
python3.12 -m pip --python .venv-iac-guard/bin/python install --no-cache-dir --no-compile 'iac-guard-v==0.1.0a6'
python3.12 -m pip --python .venv-checkov/bin/python install --no-cache-dir --no-compile 'checkov==3.3.0'
.venv-iac-guard/bin/iac-guard --version
```

## 3. Confirm deterministic Helm output

Render twice with fresh Helm state directories. Replace `/ABS/helm` with the absolute
path to the local Helm executable.

```bash
export HELM_CACHE_HOME="$PWD/.helm-1/cache"
export HELM_CONFIG_HOME="$PWD/.helm-1/config"
export HELM_DATA_HOME="$PWD/.helm-1/data"
/ABS/helm template kueue charts/kueue --namespace default --kube-version 1.31.0 --set enableKueueViz=true --skip-tests > render-1.yaml

export HELM_CACHE_HOME="$PWD/.helm-2/cache"
export HELM_CONFIG_HOME="$PWD/.helm-2/config"
export HELM_DATA_HOME="$PWD/.helm-2/data"
/ABS/helm template kueue charts/kueue --namespace default --kube-version 1.31.0 --set enableKueueViz=true --skip-tests > render-2.yaml

cmp render-1.yaml render-2.yaml
shasum -a 256 render-1.yaml render-2.yaml
```

Both hashes for the recorded environment were
`8b9f39e5b10871cdc53901c874eb2c9d5411849a7670e5b58cde8b56dc1e4106`.

## 4. Run the protected public verifier

Create `kueue-accept.json`, replacing all `/ABS/` paths with absolute local paths:

```json
{
  "schema_version": "helm-acceptance-v1",
  "checkov_executable": "/ABS/kueue-rbac-reproduction/.venv-checkov/bin/checkov",
  "charts": [{
    "universe_key": "kueue",
    "chart_root": "/ABS/kueue-rbac-reproduction/charts/kueue",
    "helm_executable": "/ABS/helm",
    "release_name": "kueue",
    "namespace": "default",
    "kube_version": "1.31.0",
    "values_files": [],
    "set": [{"key": "enableKueueViz", "value": "true"}],
    "set_string": [],
    "api_versions": [],
    "include_crds": false,
    "include_tests": false
  }],
  "properties": [{
    "rule_id": "CKV_K8S_16",
    "resource_address": "apps/v1/Deployment/default/kueue-kueueviz-backend",
    "file_path": "rendered.yaml",
    "artifact_kind": "kubernetes_yaml"
  }]
}
```

```bash
.venv-iac-guard/bin/iac-guard doctor --mode local-trusted --checkov-executable "$PWD/.venv-checkov/bin/checkov"
set +e
.venv-iac-guard/bin/iac-guard helm-accept --config "$PWD/kueue-accept.json" --local-trusted --format json --output "$PWD/report.json" --quiet
status=$?
set -e
test "$status" = 3
.venv-iac-guard/bin/iac-guard explain "$PWD/report.json" --format console --quiet
shasum -a 256 "$PWD/report.json"
```

Expected reason: `CONTRADICTORY_NAMESPACE_PROVENANCE`.

## 5. Isolated generic boundary

The `fixture/minimal-chart` chart retains the same generic boundary without Kueue
names. Point the same request shape at that chart, set the property target to
`apps/v1/Deployment/default/example`, and expect the same fail-closed reason.
