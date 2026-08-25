# Reproduce the LitmusChaos #5599 evidence

This reproduction uses public IaC-Guard-V `0.1.0a5`, Checkov `3.3.0`, and exact files
from the recorded pull-request base and head.

## 1. Resolve the exact revisions

```bash
git clone https://github.com/litmuschaos/litmus.git litmus-5599
git -C litmus-5599 worktree add --detach ../litmus-5599-base \
  7777c27b324a48e997b8107bd0874ce9b8f90482
git -C litmus-5599 worktree add --detach ../litmus-5599-head \
  980cb1c105ebe6b43f79ae12d41a8295f4124534
```

Confirm the file hashes shown in [README.md](README.md):

```bash
shasum -a 256 \
  litmus-5599-base/monitoring/utils/metrics-exporters/litmus-metrics/chaos-exporter/chaos-exporter.yaml \
  litmus-5599-head/monitoring/utils/metrics-exporters/litmus-metrics/chaos-exporter/chaos-exporter.yaml \
  litmus-5599-base/monitoring/utils/metrics-exporters/mysqld-exporter/deployment.yaml \
  litmus-5599-head/monitoring/utils/metrics-exporters/mysqld-exporter/deployment.yaml
```

## 2. Install the released verifier and scanner separately

Use copied-file, bytecode-free environments. This example uses Python 3.13:

```bash
python3.13 -m venv --copies --without-pip .venv-iac-guard
python3.13 -m venv --copies --without-pip .venv-checkov330
python3 -m pip --python .venv-iac-guard/bin/python install --no-compile \
  'iac-guard-v==0.1.0a5'
python3 -m pip --python .venv-checkov330/bin/python install --no-compile \
  'checkov==3.3.0'

.venv-iac-guard/bin/iac-guard doctor \
  --mode local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov"
```

## 3. Verify `chaos-exporter`

```bash
.venv-iac-guard/bin/iac-guard verify \
  --before "$PWD/litmus-5599-base/monitoring/utils/metrics-exporters/litmus-metrics/chaos-exporter" \
  --after "$PWD/litmus-5599-head/monitoring/utils/metrics-exporters/litmus-metrics/chaos-exporter" \
  --framework kubernetes \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --target CKV_K8S_10=apps/v1/Deployment/litmus/chaos-exporter \
  --target CKV_K8S_11=apps/v1/Deployment/litmus/chaos-exporter \
  --target CKV_K8S_12=apps/v1/Deployment/litmus/chaos-exporter \
  --target CKV_K8S_13=apps/v1/Deployment/litmus/chaos-exporter \
  --target CKV_K8S_22=apps/v1/Deployment/litmus/chaos-exporter \
  --target CKV_K8S_23=apps/v1/Deployment/litmus/chaos-exporter \
  --target CKV_K8S_30=apps/v1/Deployment/litmus/chaos-exporter \
  --format json \
  --output "$PWD/report-chaos-exporter.json" \
  --quiet
```

## 4. Verify `mysql-exporter`

```bash
.venv-iac-guard/bin/iac-guard verify \
  --before "$PWD/litmus-5599-base/monitoring/utils/metrics-exporters/mysqld-exporter" \
  --after "$PWD/litmus-5599-head/monitoring/utils/metrics-exporters/mysqld-exporter" \
  --framework kubernetes \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --target CKV_K8S_10=apps/v1/Deployment/monitoring/mysql-exporter \
  --target CKV_K8S_11=apps/v1/Deployment/monitoring/mysql-exporter \
  --target CKV_K8S_12=apps/v1/Deployment/monitoring/mysql-exporter \
  --target CKV_K8S_13=apps/v1/Deployment/monitoring/mysql-exporter \
  --target CKV_K8S_22=apps/v1/Deployment/monitoring/mysql-exporter \
  --target CKV_K8S_23=apps/v1/Deployment/monitoring/mysql-exporter \
  --target CKV_K8S_30=apps/v1/Deployment/monitoring/mysql-exporter \
  --format json \
  --output "$PWD/report-mysql-exporter.json" \
  --quiet
```

## 5. Validate the reports

```bash
.venv-iac-guard/bin/iac-guard explain report-chaos-exporter.json \
  --format console --quiet
.venv-iac-guard/bin/iac-guard explain report-mysql-exporter.json \
  --format console --quiet
shasum -a 256 report-chaos-exporter.json report-mysql-exporter.json
```

Both reports must return `VERIFIED`, contain seven `FIXED` target outcomes for the exact
Deployment, and show scanner-integrity and Kubernetes-parse gates as `PASS`. Reduced
isolation is suitable only for operator-reviewed, trusted local inputs.
