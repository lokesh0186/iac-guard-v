# Reproduce the Falco Helm 9.1.0 A/B evidence

This replay is local and source-only. It uses public IaC-Guard-V `0.1.0a10`,
Helm, exact public Falco chart source, and the published chart artifact. It
does not deploy anything.

## 1. Obtain and bind the exact source and chart

```sh
git clone https://github.com/falcosecurity/charts.git falco-charts-9.1.0
git -C falco-charts-9.1.0 checkout --detach \
  53586de4fb9d8d02006131ade702b161cd7e06e3
test "$(git -C falco-charts-9.1.0 rev-parse HEAD)" = \
  53586de4fb9d8d02006131ade702b161cd7e06e3
test "$(git -C falco-charts-9.1.0 rev-parse HEAD^{tree})" = \
  ce376e495fdb9ee84daf44b118adc759090bd231

curl -fsSLo falco-9.1.0.tgz \
  https://github.com/falcosecurity/charts/releases/download/falco-9.1.0/falco-9.1.0.tgz
printf '%s  %s\n' \
  2a767d6aeccf2392c5e263ae1f5e0950520affe3a9908ff7986ac213649c45b4 \
  falco-9.1.0.tgz | shasum -a 256 -c -
```

## 2. Install the public verifier

```sh
python3.12 -m venv --copies .venv-iacgv-a10
PYTHONDONTWRITEBYTECODE=1 .venv-iacgv-a10/bin/python -m pip install \
  --no-compile 'iac-guard-v==0.1.0a10'
.venv-iacgv-a10/bin/iac-guard --version
```

Expected version: `iac-guard 0.1.0a10`.

## 3. Reproduce both a10 reports

From this packet directory, use a new output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iacgv-a10/bin/python reproduce.py \
  --source ./falco-charts-9.1.0 \
  --chart-archive ./falco-9.1.0.tgz \
  --output ./reproduced-evidence \
  --helm "$(command -v helm)"
```

Expected outcomes:

```text
Case A: VIOLATED / SERVICEMONITOR_TARGET_UNRESOLVED / zero matching Services
Case B: SATISFIED / SERVICEMONITOR_TARGET_RESOLVED / TCP 8765
```

The driver checks the source commit/tree and chart archive digest, renders each
case twice, requires byte equality, validates both semantic reports, and checks
that direct render bytes equal the protected render used by the contract.

## 4. Run chart-native checks

```sh
mkdir falco-chart-9.1.0
tar -xzf falco-9.1.0.tgz -C falco-chart-9.1.0
helm lint ./falco-chart-9.1.0/falco \
  --set serviceMonitor.create=true
```

The retained result is one chart linted and zero failed. The chart's existing
focused Go/Terratest Service and ServiceMonitor tests also pass; see
`REGRESSION_DESCRIPTION.md` for the cross-template regression design.

## 5. Verify packet integrity

```sh
shasum -a 256 -c SHA256SUMS
```
