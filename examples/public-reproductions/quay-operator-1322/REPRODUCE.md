# Reproduce Quay Operator PR #1322 evidence

This replay uses public IaC-Guard-V `0.1.0a8`, Checkov `3.3.0`, Kustomize `v5.7.1`,
and exact public pull-request source `1340fe9cdae651a0e36fc27a4322b2a2f5872223`.

## 1. Obtain the exact source

```sh
git clone https://github.com/quay/quay-operator.git quay-operator-1322
git -C quay-operator-1322 checkout --detach \
  1340fe9cdae651a0e36fc27a4322b2a2f5872223
test "$(git -C quay-operator-1322 rev-parse HEAD)" = \
  1340fe9cdae651a0e36fc27a4322b2a2f5872223
```

Copy the eight paths recorded in `SOURCE_IDENTITY.json` into one candidate directory,
using the packet's `source/` filenames. Verify their hashes against `SHA256SUMS`.

## 2. Install the public verifier and scanner

Use separate copied-file, bytecode-free Python 3.12 environments as documented by
IaC-Guard-V:

```sh
python3.12 -m venv --copies .venv-iac-guard
python3.12 -m venv --copies .venv-checkov330
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/python -m pip install \
  --no-compile 'iac-guard-v==0.1.0a8'
PYTHONDONTWRITEBYTECODE=1 .venv-checkov330/bin/python -m pip install \
  --no-compile 'checkov==3.3.0'
find .venv-iac-guard .venv-checkov330 -type f -name '*.pyc' -delete
find .venv-iac-guard .venv-checkov330 -depth -type d -name __pycache__ \
  -empty -delete
```

The expected public wheel SHA256 is:

```text
ef62cfedd3c4f8a3fa2bbdf4bad241a17c0f2c076a37cd6fc7bb008a0476015c
```

## 3. Replay the authoritative committed-source property

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/iac-guard accept \
  --candidate source \
  --property \
    CKV2_K8S_6=apps/v1/Deployment/default/clair-postgres-old@clair-pg-old.deployment.yaml \
  --framework kubernetes \
  --local-trusted \
  --checkov-executable .venv-checkov330/bin/checkov \
  --format json \
  --output replay-source-report.json \
  --quiet
```

Expected semantic result:

```text
verdict: FAILED
exit_code: 1
property outcome: VIOLATED
property reason: CANDIDATE_PROPERTY_VIOLATED
scanner integrity: PASS
target-relevant graph evidence: PASS
applicable NetworkPolicies: 3
selecting NetworkPolicies: 0
```

An exit code of 1 is the expected evidence result: the selected property is violated.

## 4. Reproduce the native-render corroboration

Place `materialization/kustomization.yaml` at
`quay-operator-1322/kustomize/tmp/kustomization.yaml`, then run:

```sh
kustomize build quay-operator-1322/kustomize/tmp \
  --load-restrictor LoadRestrictionsRootOnly > full-render.yaml
shasum -a 256 full-render.yaml
```

Expected full-render SHA256:

```text
fe4699b9f1138f8d238f118fd29418aa2e3a9238c313190883d16c31217a1105
```

Extract the four Deployments, one Job, and three NetworkPolicies listed in
`MATERIALIZATION.json`, retaining one YAML document per file and the filenames under
`rendered/`. Verify the extracted hashes against `SHA256SUMS`.

## 5. Replay both rendered properties

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/iac-guard accept \
  --candidate rendered \
  --property \
    CKV2_K8S_6=apps/v1/Deployment/quay-a8-validation/a8-clair-postgres-old@clair-postgres-old.deployment.yaml \
  --property \
    CKV2_K8S_6=batch/v1/Job/quay-a8-validation/a8-clair-postgres-upgrade@clair-postgres-upgrade.job.yaml \
  --framework kubernetes \
  --local-trusted \
  --checkov-executable .venv-checkov330/bin/checkov \
  --format json \
  --output replay-rendered-report.json \
  --quiet
```

Expected semantic result for both targets:

```text
outcome: VIOLATED
reason: CANDIDATE_PROPERTY_VIOLATED
target-relevant graph evidence: PASS
applicable NetworkPolicies: 3
selecting NetworkPolicies: 0
```

## 6. Validate reports and packet hashes

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/iac-guard explain \
  REPORT.json --format console --quiet
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/iac-guard explain \
  REPORT-rendered.json --format console --quiet
shasum -a 256 -c SHA256SUMS
```

This is reduced-isolation verification of inspected public inputs. It is not a hostile
pull-request sandbox, a general Kustomize-support claim, or whole-PR verification.
