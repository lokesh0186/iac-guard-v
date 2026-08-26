# Reproduce Supabase Kubernetes PR #245 evidence

This reproduction uses only public IaC-Guard-V `0.1.0a6`, public Checkov
`3.3.0`, and exact public pull-request revisions.

## 1. Resolve exact revisions

```sh
git clone https://github.com/supabase-community/supabase-kubernetes.git supabase-245
git -C supabase-245 worktree add --detach ../supabase-245-base \
  d04a3133af93cc12af000b15f88c22507be5354f
git -C supabase-245 worktree add --detach ../supabase-245-head \
  36ab1fc6e1bbb60597148b726a05bd842888f570
```

## 2. Install public verifier and scanner

Use copied-file, bytecode-free Python 3.12 environments:

```sh
python3.12 -m venv --copies --without-pip .venv-iac-guard
python3.12 -m venv --copies --without-pip .venv-checkov330
.venv-iac-guard/bin/python -m ensurepip --default-pip
.venv-checkov330/bin/python -m ensurepip --default-pip
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/python -m pip install \
  --no-compile 'iac-guard-v==0.1.0a6'
PYTHONDONTWRITEBYTECODE=1 .venv-checkov330/bin/python -m pip install \
  --no-compile 'checkov==3.3.0'
find .venv-checkov330 -type d -name __pycache__ -prune -exec rm -rf {} +
find .venv-checkov330 -type f -name '*.pyc' -delete
```

The public wheel SHA256 is:

```text
5f39e41478fc30c5f2a7af1e2008059178d7eaadeb91dea67ac9446fd472b256
```

## 3. Render both revisions twice

For each base/head chart, run this protected Helm configuration twice in fresh state
directories:

```sh
run_root="$(mktemp -d)"
HELM_CACHE_HOME="$run_root/cache" \
HELM_CONFIG_HOME="$run_root/config" \
HELM_DATA_HOME="$run_root/data" \
helm template supabase CHART_ROOT \
  --namespace default \
  --kube-version 1.31.0 \
  --skip-tests \
  --set deployment.minio.enabled=true \
  --set deployment.kong.enabled=false \
  --set deployment.storage.enabled=true \
  --set deployment.storage.initDb=true \
  --set deployment.storage.securityContext.allowPrivilegeEscalation=false \
  --set deployment.storage.securityContext.privileged=false \
  --set deployment.storage.securityContext.readOnlyRootFilesystem=true \
  --set deployment.storage.securityContext.runAsNonRoot=true \
  --set deployment.storage.securityContext.runAsUser=10001 \
  --set deployment.storage.securityContext.seccompProfile.type=RuntimeDefault \
  > rendered.yaml
```

Expected exact bundle SHA256 values:

```text
7bc372a62d4181357cb2db2a1686617a74896e10a38c613ac9cf9eb886360673  base
5813fbfa9b0cbd34e46271cbbe11c95d2cc2ae5367a32e30cb26f75b9786faa9  head
```

Both runs must be byte-identical for each revision. Extract only the document with
source marker `supabase/templates/storage/deployment.yaml` into separate base and head
directories.

Expected extracted document SHA256 values:

```text
494fb3fcedb704ebcfc8a421c5d7eaa4d9924c8e6cf8ea0e43a375a679282e6b  base
cd51e33ded62b40ebf1ced1ed74a6279e042caa9b0f5af728aabc68787ec3cc6  head
```

## 4. Run target-scoped verification

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/iac-guard verify \
  --before "$PWD/direct/base" \
  --after "$PWD/direct/head" \
  --framework kubernetes \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --target CKV_K8S_20=apps/v1/Deployment/default/supabase-supabase-storage \
  --target CKV_K8S_22=apps/v1/Deployment/default/supabase-supabase-storage \
  --target CKV_K8S_30=apps/v1/Deployment/default/supabase-supabase-storage \
  --format json \
  --output "$PWD/report.json" \
  --quiet
```

Expected result:

```text
result_kind: verification
verdict: INCONCLUSIVE
scanner_integrity: PASS
kubernetes_yaml_parse: PASS
CKV_K8S_20: STILL_PRESENT
CKV_K8S_22: STILL_PRESENT
CKV_K8S_30: STILL_PRESENT
```

The base evaluation keys identify `initContainers[0]`. The candidate evaluation keys
identify `initContainers[1]`.

## 5. Validate the report

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/iac-guard explain \
  report.json --format console --quiet
shasum -a 256 report.json
```

Expected canonical report SHA256:

```text
d1c4b0c5336d7a484fdace2600be8ff0a6513e50599269aeb01743e413eebbcc
```

This is reduced-isolation verification of owner-reviewed local inputs. It is not a
hostile pull-request sandbox or a whole-chart security claim.
