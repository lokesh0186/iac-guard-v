# Evaluate an external IaC repairer with IaC-Guard-V 1.0

This local interface accepts patches produced by any repair method. It never
generates repairs or calls a model provider. It applies each patch to a copy of
its baseline, then asks the released IaC-Guard-V 1.0.0 verifier to check one
exact Checkov finding with Checkov 3.3.0. `FAILED`, `INCONCLUSIVE`, patch errors,
and operational errors remain visible.

## Input layout

```text
my-evaluation/
  cases.json
  cases/
    case-001/before/main.tf
    case-002/before/main.tf
  repairs/
    case-001.patch
    case-002.patch
```

`cases.json`:

```json
{
  "schema": "iac-guard-repair-batch-v1",
  "cases": [
    {"id": "case-001", "target": "CKV_AWS_3=aws_ebs_volume.target"},
    {"id": "case-002", "target": "CKV_AWS_3=aws_ebs_volume.target"}
  ]
}
```

Each patch is a standard Git text diff whose paths are relative to its
`before/` directory. Cases must be locally trusted source, with no symlinks.
The runner accepts at most 100 cases and applies patches only in disposable
directories. It rejects binary, rename, copy, and symlink patches.

## Run

Install the released wheel and pinned Checkov in **separate** environments,
following [the protected installation guide](../../docs/ADVANCED_INSTALLATION.md#install-from-pypi).
Then run from a checkout containing this script:

```bash
python3.12 adoption/repairer-eval/evaluate.py \
  --input /absolute/path/to/my-evaluation \
  --output /absolute/path/to/new-output-directory \
  --iac-guard /absolute/path/to/.venv-iac-guard/bin/iac-guard \
  --checkov /absolute/path/to/.venv-checkov330/bin/checkov
```

The output directory must be new and outside the input tree. The runner writes
`results.json`, `summary.csv`, `verification_receipt.json`, and each case's raw
`report.json` and process logs. A zero process exit means every case is
`VERIFIED`; all other outcomes exit nonzero. The receipt binds input hashes,
executable hashes, and output hashes but is **unsigned** and is not a substitute
for examining the raw report and source. The verifier's conclusion concerns
the selected finding under the pinned environment, not all properties of a
repair or the repairer's overall quality.

The included [`example/`](example/) is a small interface smoke fixture. It is
not a benchmark result. Researchers can map their own public case IDs and
already produced patches into this layout, run from their own environment, and
publish the complete output directory plus source commit and case selection.
