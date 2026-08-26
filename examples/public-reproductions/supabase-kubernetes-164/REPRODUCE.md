# Reproduce Supabase Kubernetes #164 evidence

This procedure uses the exact public IaC-Guard-V release, public pull-request
source, a local client-side Helm renderer, and Checkov `3.3.0`. It does not
connect to a Kubernetes cluster.

## 1. Resolve the exact candidate

```bash
git clone https://github.com/supabase-community/supabase-kubernetes.git supabase-kubernetes-164
cd supabase-kubernetes-164
git fetch origin pull/164/head:pr-164
git checkout --detach 8d23520955879cb06c020d6dfe6f975a372f2ee6
test "$(git rev-parse HEAD)" = "8d23520955879cb06c020d6dfe6f975a372f2ee6"
```

The recorded base is `b6b399f1cc994e609cbaff4e1652a6c4a79381ee`.
Candidate-acceptance mode evaluates the proposed head and does not claim a
baseline repair.

## 2. Install released software

Use copied-file, bytecode-free environments. Adjust the Python executable for
the local platform if needed.

```bash
python3.12 -m venv --copies --without-pip .venv-iac-guard
python3.12 -m venv --copies --without-pip .venv-checkov
python3.12 -m pip --python .venv-iac-guard/bin/python install --no-cache-dir --no-compile 'iac-guard-v==0.1.0a6'
python3.12 -m pip --python .venv-checkov/bin/python install --no-cache-dir --no-compile 'checkov==3.3.0'
.venv-iac-guard/bin/iac-guard --version
.venv-iac-guard/bin/iac-guard doctor --mode local-trusted --checkov-executable "$PWD/.venv-checkov/bin/checkov"
```

Expected public wheel SHA-256:

```text
5f39e41478fc30c5f2a7af1e2008059178d7eaadeb91dea67ac9446fd472b256
```

## 3. Confirm deterministic rendering

Replace `/ABS/helm` with the local Helm executable. Use independently recreated
Helm state directories:

```bash
export HELM_CACHE_HOME="$PWD/.helm-1/cache"
export HELM_CONFIG_HOME="$PWD/.helm-1/config"
export HELM_DATA_HOME="$PWD/.helm-1/data"
/ABS/helm template supabase charts/supabase --namespace default --kube-version 1.31.0 --set networkPolicies.enabled=true --skip-tests > render-1.yaml

export HELM_CACHE_HOME="$PWD/.helm-2/cache"
export HELM_CONFIG_HOME="$PWD/.helm-2/config"
export HELM_DATA_HOME="$PWD/.helm-2/data"
/ABS/helm template supabase charts/supabase --namespace default --kube-version 1.31.0 --set networkPolicies.enabled=true --skip-tests > render-2.yaml

cmp render-1.yaml render-2.yaml
shasum -a 256 render-1.yaml render-2.yaml
```

Both recorded hashes are:

```text
5737e5db441957893490cf7fae857b7641a194d35ba4ec3182b2c1bf52e17715
```

## 4. Run candidate acceptance

Create `supabase-accept.json`, replacing `/ABS/` paths with absolute local
paths:

```json
{
  "schema_version": "helm-acceptance-v1",
  "checkov_executable": "/ABS/supabase-kubernetes-164/.venv-checkov/bin/checkov",
  "charts": [{
    "universe_key": "supabase",
    "chart_root": "/ABS/supabase-kubernetes-164/charts/supabase",
    "helm_executable": "/ABS/helm",
    "release_name": "supabase",
    "namespace": "default",
    "kube_version": "1.31.0",
    "values_files": [],
    "set": [{"key": "networkPolicies.enabled", "value": "true"}],
    "set_string": [],
    "api_versions": [],
    "include_crds": false,
    "include_tests": false
  }],
  "properties": [
    {"rule_id": "CKV2_K8S_6", "resource_address": "apps/v1/Deployment/default/supabase-supabase-auth", "file_path": "rendered.yaml", "artifact_kind": "kubernetes_yaml"},
    {"rule_id": "CKV2_K8S_6", "resource_address": "apps/v1/Deployment/default/supabase-supabase-kong", "file_path": "rendered.yaml", "artifact_kind": "kubernetes_yaml"},
    {"rule_id": "CKV2_K8S_6", "resource_address": "apps/v1/Deployment/default/supabase-supabase-rest", "file_path": "rendered.yaml", "artifact_kind": "kubernetes_yaml"}
  ]
}
```

```bash
.venv-iac-guard/bin/iac-guard helm-accept \
  --config "$PWD/supabase-accept.json" \
  --local-trusted \
  --format json \
  --output "$PWD/report.json" \
  --quiet

.venv-iac-guard/bin/iac-guard explain "$PWD/report.json" --format console --quiet
shasum -a 256 "$PWD/report.json"
```

The exact report hash depends on every bound executable and environment input.
The claim is repeatable only if all rendered resources remain governed, the
three selected relationships remain `SATISFIED`, scanner/parser/materialization
integrity passes, and the final result is `candidate_acceptance / VERIFIED`.

## 5. Inspect peer semantics

Inspect the Auth and REST NetworkPolicy documents in the protected rendered
bundle, then compare the `to` peers on TCP `465`, `587`, `443`, and `5432` with
the official Kubernetes definition:

https://kubernetes.io/docs/concepts/services-networking/network-policies/

The IaC-Guard-V report establishes the protected rendered universe and selected
policy/workload relationships. The peer-semantics findings are a separate
review of those governed policy bytes against the Kubernetes API contract.

