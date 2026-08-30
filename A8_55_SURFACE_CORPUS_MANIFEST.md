# A8 55-surface corpus manifest

- Corpus: `a8-original-design-55-surfaces`
- Surfaces: `55` (40 Helm, 15 Kustomize)
- Repositories: `28`
- Manifest payload SHA256: `3a4d6ac6678c917879575c228c9b2521dd40b37a922d671afffdd28f8010ec4c`
- Original inventory SHA256: `53820b00a9123ed089990bbeaf7d4350a7524b8632a2188235b8919a3dba67b4`
- Recovery: exact roots, commits, default inputs, and dependency absence/presence

## Surfaces

| ID | Repository | SHA | Class | Root | Original a8 prediction | Confidence |
|---|---|---|---|---|---|---|
| `helm-001-airflow-airflow` | `apache/airflow` | `9d54ac94826d8f46c0d6d1032ee7d9988e562d70` | HELM | `chart` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-002-argo-helm-argo-cd` | `argoproj/argo-helm` | `e0e82f7a9b543405ee25798ce8c899705503a3d1` | HELM | `charts/argo-cd` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-003-coder-enterprise-helm-coder` | `coder/enterprise-helm` | `b096a369fe2d1b2de75a0b85af01fa9e272b221e` | HELM | `.` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-004-cortex-helm-chart-cortex` | `cortexproject/cortex-helm-chart` | `73337e251edec84ed394b47649ec0e4763cdb591` | HELM | `.` | `SUPPORTED` | `HIGH` |
| `helm-005-csi-driver-smb-csi-driver-smb` | `kubernetes-csi/csi-driver-smb` | `0f879a3208930a1a61cbe6fc2353719495845ba9` | HELM | `charts/latest/csi-driver-smb` | `SUPPORTED` | `HIGH` |
| `helm-006-external-secrets-external-secrets` | `external-secrets/external-secrets` | `8488600898e856d74a7e0f53ed5e3cc79d89f4e8` | HELM | `deploy/charts/external-secrets` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-007-grafana-grafana-agent-operator` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/agent-operator` | `SUPPORTED` | `HIGH` |
| `helm-008-grafana-enterprise-logs` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/enterprise-logs` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-009-grafana-enterprise-metrics` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/enterprise-metrics` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-010-grafana-grafana-sampling` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/grafana-sampling` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-011-grafana-lgtm-distributed` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/lgtm-distributed` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-012-grafana-pdc-agent` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/pdc-agent` | `PARTIALLY_REACHABLE` | `HIGH` |
| `helm-013-grafana-promtail` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/promtail` | `SUPPORTED` | `HIGH` |
| `helm-014-grafana-rollout-operator` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/rollout-operator` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-015-grafana-tempo-distributed` | `grafana/helm-charts` | `7a0ab968961a165318ab95ff678908c3b9bc3240` | HELM | `charts/tempo-distributed` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-016-harbor-helm-harbor` | `goharbor/harbor-helm` | `acb552529b7c73d86840130eee226f17dc79a5ab` | HELM | `.` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-017-harness-gitops-agent-gitops-agent` | `harness/gitops-agent-helm-chart` | `c4bfa0297cfbd27f0cc591f26a9ec39119ddbcb0` | HELM | `.` | `PARTIALLY_REACHABLE` | `HIGH` |
| `helm-018-jenkins-helm-jenkins` | `jenkinsci/helm-charts` | `41eeb20f3f00dda2515d2c5724b1343c5a237762` | HELM | `charts/jenkins` | `SUPPORTED` | `HIGH` |
| `helm-019-kyverno-kyverno` | `kyverno/kyverno` | `dc12fe22eb32b0aa8c4ba39e4b2f2a3bf5aacf34` | HELM | `charts/kyverno` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-020-kyverno-kyverno-policies` | `kyverno/kyverno` | `dc12fe22eb32b0aa8c4ba39e4b2f2a3bf5aacf34` | HELM | `charts/kyverno-policies` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-021-neo4j-helm-neo4j` | `neo4j/helm-charts` | `bd85d80c591e016fcf12e9960d626712ffddb642` | HELM | `neo4j` | `PARTIALLY_REACHABLE` | `HIGH` |
| `helm-022-onlyoffice-docs-docs` | `ONLYOFFICE/Kubernetes-Docs` | `c0e9bdfc515858758cbe4bf23eeec23376595e70` | HELM | `.` | `SUPPORTED` | `HIGH` |
| `helm-023-onlyoffice-docspace-docspace` | `ONLYOFFICE/Kubernetes-DocSpace` | `ae9cfca78e8485491a3cd7fcffe875abd3737579` | HELM | `.` | `PARTIALLY_REACHABLE` | `HIGH` |
| `helm-024-opencost-opencost` | `opencost/opencost-helm-chart` | `4242feee70e745ea540fc5d3177d4899b307dc2d` | HELM | `charts/opencost` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-025-opentelemetry-opentelemetry-demo` | `open-telemetry/opentelemetry-helm-charts` | `b1f24a2f0cc9bcee70bd1bf8e7b989240496385f` | HELM | `charts/opentelemetry-demo` | `PARTIALLY_REACHABLE` | `HIGH` |
| `helm-026-opentelemetry-opentelemetry-collector` | `open-telemetry/opentelemetry-helm-charts` | `b1f24a2f0cc9bcee70bd1bf8e7b989240496385f` | HELM | `charts/opentelemetry-collector` | `PARTIALLY_REACHABLE` | `HIGH` |
| `helm-027-opentelemetry-opentelemetry-kube-stack` | `open-telemetry/opentelemetry-helm-charts` | `b1f24a2f0cc9bcee70bd1bf8e7b989240496385f` | HELM | `charts/opentelemetry-kube-stack` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-028-opentelemetry-opentelemetry-operator` | `open-telemetry/opentelemetry-helm-charts` | `b1f24a2f0cc9bcee70bd1bf8e7b989240496385f` | HELM | `charts/opentelemetry-operator` | `SUPPORTED` | `HIGH` |
| `helm-029-opentelemetry-opentelemetry-target-allocator` | `open-telemetry/opentelemetry-helm-charts` | `b1f24a2f0cc9bcee70bd1bf8e7b989240496385f` | HELM | `charts/opentelemetry-target-allocator` | `SUPPORTED` | `HIGH` |
| `helm-030-prometheus-community-alertmanager` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/alertmanager` | `SUPPORTED` | `HIGH` |
| `helm-031-prometheus-community-kube-prometheus-stack` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/kube-prometheus-stack` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-032-prometheus-community-prometheus-adapter` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/prometheus-adapter` | `SUPPORTED` | `HIGH` |
| `helm-033-prometheus-community-prometheus-blackbox-exporter` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/prometheus-blackbox-exporter` | `SUPPORTED` | `HIGH` |
| `helm-034-prometheus-community-prometheus-node-exporter` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/prometheus-node-exporter` | `SUPPORTED` | `HIGH` |
| `helm-035-prometheus-community-prometheus-operator-admission-webhook` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/prometheus-operator-admission-webhook` | `SUPPORTED` | `HIGH` |
| `helm-036-prometheus-community-prometheus-pushgateway` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/prometheus-pushgateway` | `SUPPORTED` | `HIGH` |
| `helm-037-prometheus-community-prometheus-snmp-exporter` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/prometheus-snmp-exporter` | `SUPPORTED` | `HIGH` |
| `helm-038-prometheus-community-prometheus` | `prometheus-community/helm-charts` | `ed5d7d9b5933bcb0ea93f3f0a806e9db4f2b5988` | HELM | `charts/prometheus` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-039-valkey-io-valkey` | `valkey-io/valkey-helm` | `dd2d78213ae4e7b229074d473612999c7324d9be` | HELM | `valkey` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `helm-040-valkey-io-valkey-operator` | `valkey-io/valkey-helm` | `dd2d78213ae4e7b229074d473612999c7324d9be` | HELM | `valkey-operator` | `SUPPORTED` | `HIGH` |
| `kustomize-001-azure-blob-csi-deploy-v1.27.9` | `kubernetes-sigs/blob-csi-driver` | `d50172c7fbab36573ed92ef0b1f4b4b32d41ff19` | KUSTOMIZE | `deploy/v1.27.9` | `SUPPORTED` | `HIGH` |
| `kustomize-002-airflow-chart-kustomize-overlays-kerberos` | `apache/airflow` | `9d54ac94826d8f46c0d6d1032ee7d9988e562d70` | KUSTOMIZE | `chart/kustomize-overlays/kerberos` | `SUPPORTED` | `HIGH` |
| `kustomize-003-airflow-chart-kustomize-overlays-keda` | `apache/airflow` | `9d54ac94826d8f46c0d6d1032ee7d9988e562d70` | KUSTOMIZE | `chart/kustomize-overlays/keda` | `SUPPORTED` | `HIGH` |
| `kustomize-004-kyverno-scripts-config-kwok` | `kyverno/kyverno` | `dc12fe22eb32b0aa8c4ba39e4b2f2a3bf5aacf34` | KUSTOMIZE | `scripts/config/kwok` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `kustomize-005-argo-workflows-manifests-cluster-install` | `argoproj/argo-workflows` | `bde5adf915fbc2600a49e6e864a699544fb91368` | KUSTOMIZE | `manifests/cluster-install` | `SUPPORTED` | `HIGH` |
| `kustomize-006-argo-workflows-manifests-namespace-install` | `argoproj/argo-workflows` | `bde5adf915fbc2600a49e6e864a699544fb91368` | KUSTOMIZE | `manifests/namespace-install` | `SUPPORTED` | `HIGH` |
| `kustomize-007-aws-load-balancer-controller-config-default` | `kubernetes-sigs/aws-load-balancer-controller` | `7040d02b38580b8b8b47ba3fb2b279da9698f5d9` | KUSTOMIZE | `config/default` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `kustomize-008-cloudnative-pg-config-default` | `cloudnative-pg/cloudnative-pg` | `8179beb0592398b9ae3221d8488c815b73e94b2c` | KUSTOMIZE | `config/default` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `kustomize-009-descheduler-kubernetes-base` | `kubernetes-sigs/descheduler` | `8bbd0bd661f2328ade2615ab0bd7f8dcafa3e723` | KUSTOMIZE | `kubernetes/base` | `SUPPORTED` | `HIGH` |
| `kustomize-010-flux-source-controller-config-default` | `fluxcd/source-controller` | `208961aa7bf334cbef95bee390712b27a925dec2` | KUSTOMIZE | `config/default` | `SUPPORTED` | `HIGH` |
| `kustomize-011-flux-kustomize-controller-config-default` | `fluxcd/kustomize-controller` | `186fb3b29138ce82ff61ba1a9370b96a3dd598fe` | KUSTOMIZE | `config/default` | `FAIL_CLOSED_PRODUCT_BOUNDARY` | `HIGH` |
| `kustomize-012-gateway-api-config-crd` | `kubernetes-sigs/gateway-api` | `1ab0781ac715b26a25ff201ce444058a47703c4c` | KUSTOMIZE | `config/crd` | `SUPPORTED` | `HIGH` |
| `kustomize-013-metrics-server-manifests-base` | `kubernetes-sigs/metrics-server` | `4062beeed6ef996ba3ff7164967edafd3470e2e4` | KUSTOMIZE | `manifests/base` | `SUPPORTED` | `HIGH` |
| `kustomize-014-metrics-server-manifests-overlays-release` | `kubernetes-sigs/metrics-server` | `4062beeed6ef996ba3ff7164967edafd3470e2e4` | KUSTOMIZE | `manifests/overlays/release` | `SUPPORTED` | `HIGH` |
| `kustomize-015-prometheus-operator-root` | `prometheus-operator/prometheus-operator` | `146a99723a91c4b96abc41aeb46a147b04cf092b` | KUSTOMIZE | `.` | `SUPPORTED` | `HIGH` |

## Replay

```sh
.nox/tests-3-12/bin/python a8-coverage-corpus/replay/replay.py \
  --manifest A8_55_SURFACE_CORPUS_MANIFEST.json \
  --output a8-coverage-corpus/results/implemented-a8-replay.json
```

Validation without rendering:

```sh
.nox/tests-3-12/bin/python a8-coverage-corpus/replay/replay.py \
  --manifest A8_55_SURFACE_CORPUS_MANIFEST.json --validate-only
```
