# Reproduce Dgraph charts PR #146 evidence

This replay uses public IaC-Guard-V `0.1.0a8`, Checkov `3.3.0`, Helm
`v4.2.4+g3900f43`, and exact public pull-request source
`fe013a6d24ef21b6812cd2f55f28246f444ef563`.

## 1. Obtain the exact source

```sh
git clone https://github.com/dgraph-io/charts.git dgraph-charts-146
git -C dgraph-charts-146 checkout --detach \
  fe013a6d24ef21b6812cd2f55f28246f444ef563
test "$(git -C dgraph-charts-146 rev-parse HEAD)" = \
  fe013a6d24ef21b6812cd2f55f28246f444ef563
test "$(git -C dgraph-charts-146 rev-parse HEAD:charts/dgraph)" = \
  b374ebf4227ff9bd281ab70866074c868e67ad93
```

Compare `git ls-tree -r HEAD charts/dgraph` with `CHART_TREE.txt`, and verify
the retained relevant source hashes with `SHA256SUMS`.

## 2. Reproduce the two-feature native render

From a directory containing the upstream checkout and this packet's
`CONFIGURATION.yaml`:

```sh
helm template adjudicate dgraph-charts-146/charts/dgraph \
  --namespace dgraph-system \
  --kube-version 1.31.0 \
  --values CONFIGURATION.yaml \
  --output-dir render-1

helm template adjudicate dgraph-charts-146/charts/dgraph \
  --namespace dgraph-system \
  --kube-version 1.31.0 \
  --values CONFIGURATION.yaml \
  --output-dir render-2

diff -qr render-1 render-2

(cd render-1 && find dgraph -type f -exec shasum -a 256 {} + | sort | \
  shasum -a 256)
```

Expected: `diff` exits zero with no output. The file-set digest is:

```text
6864c5f3a72c8fa7ec77209addce481e842d25194f1223b90ebfa234a0672420
```

Run the native lint check:

```sh
helm lint dgraph-charts-146/charts/dgraph --values CONFIGURATION.yaml
```

Expected: exit zero and `1 chart(s) linted, 0 chart(s) failed`.

The four relationship-relevant outputs must match the retained `rendered/`
hashes in `SHA256SUMS`.

## 3. Install the public verifier and scanner

Use copied-file, bytecode-free Python 3.12 environments:

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

The expected public IaC-Guard-V wheel SHA256 is:

```text
ef62cfedd3c4f8a3fa2bbdf4bad241a17c0f2c076a37cd6fc7bb008a0476015c
```

## 4. Replay the authoritative A8 property

Create `a8-request.json` with absolute local executable/chart paths:

```json
{
  "schema_version": "helm-acceptance-v1",
  "checkov_executable": "/absolute/path/.venv-checkov330/bin/checkov",
  "charts": [
    {
      "universe_key": "dgraph-charts-146-authoritative",
      "chart_root": "/absolute/path/dgraph-charts-146/charts/dgraph",
      "helm_executable": "/absolute/path/to/helm",
      "release_name": "adjudicate",
      "namespace": "dgraph-system",
      "kube_version": "1.31.0",
      "values_files": [],
      "set": [
        {"key": "networkPolicy.enabled", "value": "true"}
      ],
      "set_string": [],
      "api_versions": [],
      "include_crds": false,
      "include_tests": false
    }
  ],
  "properties": [
    {
      "rule_id": "CKV2_K8S_6",
      "resource_address": "apps/v1/StatefulSet/dgraph-system/adjudicate-dgraph-zero",
      "file_path": "rendered.yaml"
    }
  ]
}
```

Then run:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/iac-guard helm-accept \
  --config a8-request.json \
  --local-trusted \
  --format json \
  --output replay-report.json \
  --quiet
```

Expected semantic result:

```text
verdict: VERIFIED
exit_code: 0
property: CKV2_K8S_6
resource: apps/v1/StatefulSet/dgraph-system/adjudicate-dgraph-zero
outcome: SATISFIED
reason: CANDIDATE_PROPERTY_SATISFIED
graph evidence: PASS / GRAPH_EVIDENCE_COMPLETE
edge: NetworkPolicy/dgraph-system/adjudicate-dgraph
      -> StatefulSet/dgraph-system/adjudicate-dgraph-zero
```

The authoritative run intentionally leaves `serviceMonitor.enabled=false`.
IaC-Guard-V a8 cannot authoritatively admit that external CRD without local CRD
namespace-provenance evidence. The separate native render in step 2 supplies the
corroborating ServiceMonitor semantics without turning that boundary into an A8
claim.

## 5. Validate the retained report and packet hashes

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-iac-guard/bin/iac-guard explain \
  REPORT.json --format console --quiet
shasum -a 256 -c SHA256SUMS
```

This is reduced-isolation verification of inspected public inputs. It is not a
live deployment, hostile pull-request sandbox, packet test, or whole-PR
verification.
