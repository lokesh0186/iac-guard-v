# Reproduce the CoreDNS Helm 1.47.0 A/B evidence

This replay is local and source-only. It uses public IaC-Guard-V `0.1.0a9`,
Helm, and exact public CoreDNS chart source. It does not deploy anything.

## 1. Obtain exact chart source

```sh
git clone https://github.com/coredns/helm.git coredns-helm-1.47.0
git -C coredns-helm-1.47.0 checkout --detach \
  fd5b836b84e80f6ca5be9b59b77e4d2dd3505467
test "$(git -C coredns-helm-1.47.0 rev-parse HEAD)" = \
  fd5b836b84e80f6ca5be9b59b77e4d2dd3505467
test "$(git -C coredns-helm-1.47.0 rev-parse HEAD^{tree})" = \
  7e1d80e7366f7f97f65fc91debf4f4fd989657a4
```

## 2. Install the public verifier

```sh
python3.12 -m venv --copies .venv-iacgv-a9
PYTHONDONTWRITEBYTECODE=1 .venv-iacgv-a9/bin/python -m pip install \
  --no-compile 'iac-guard-v==0.1.0a9'
.venv-iacgv-a9/bin/python -c \
  'import iac_guard_v; assert iac_guard_v.__version__ == "0.1.0a9"'
```

The public wheel used to create this packet has SHA256:

```text
64727745b787fdb473712eed1c4cd332ee27b12553ab3edc34194045f637ee00
```

## 3. Reproduce both renders and native reports

From this packet directory, use a new output path:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iacgv-a9/bin/python reproduce.py \
  --source ./coredns-helm-1.47.0 \
  --output ./reproduced-evidence \
  --helm "$(command -v helm)"
```

The driver checks the release commit and tree, renders each case twice,
requires byte equality, protects the complete rendered universe, and evaluates
`IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1` version 1 against the
exact ServiceMonitor and expected metrics Service identities.

Expected outcomes:

```text
Case A: VIOLATED / SERVICEMONITOR_TARGET_UNRESOLVED
Case B: SATISFIED / SERVICEMONITOR_TARGET_RESOLVED / TCP 9153
```

Compare the reproduced files:

```sh
cmp reproduced-evidence/monitor-on-service-off/render-1.yaml \
  reproduced-evidence/monitor-on-service-off/render-2.yaml
cmp reproduced-evidence/monitor-on-service-on/render-1.yaml \
  reproduced-evidence/monitor-on-service-on/render-2.yaml
cmp reproduced-evidence/monitor-on-service-off/native-property-report-v1.json \
  REPORT_CASE_A.json
cmp reproduced-evidence/monitor-on-service-on/native-property-report-v1.json \
  REPORT_CASE_B.json
```

## 4. Run chart-native checks

```sh
helm lint coredns-helm-1.47.0/charts/coredns \
  --set prometheus.monitor.enabled=true \
  --set prometheus.service.enabled=false
```

The retained result is `1 chart(s) linted, 0 chart(s) failed`. With the
repository's pinned helm-unittest 1.0.2 plugin, the unmodified suite reports 15
suites / 24 tests passing. See `REGRESSION_DESCRIPTION.md` for the private
cross-template regression design.

## 5. Verify packet integrity

```sh
shasum -a 256 -c SHA256SUMS
```

The replay establishes protected rendered-resource semantics only. It is not a
live deployment, Prometheus scrape, packet test, or whole-project verification.
