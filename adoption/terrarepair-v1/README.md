# TerraRepair archived-repair adapter for IaC-Guard-V 1.0

This adapter converts ten **already published** TerraRepair repair records into
the [`repairer-eval` input format](../repairer-eval/README.md). It neither
generates a repair nor calls a model provider. It reads locally cloned,
commit-pinned public sources and writes third-party HCL only to the operator's
local output directory; this repository does not redistribute those files.

The selected sample numbers are the first ten baseline-exact cases from the
prior predeclared Alpha 7 ordering: `135, 66, 108, 30, 35, 61, 51, 69, 15,
122`. Selection uses no Alpha 7 or stable 1.0 verdict. These ten cases are a
small, nonrepresentative pilot; do not extrapolate a success rate to the full
TerraRepair benchmark. TerraRepair's original scanner-disappearance metric and
IaC-Guard-V's target-bound verdict answer different questions.

Clone and check out the exact public inputs:

```bash
git clone https://github.com/ManassehV2/TerraRepair.git terrarepair
git -C terrarepair checkout dd759a88ec831b6777132506b5a9d04522e92a57
git clone https://github.com/bridgecrewio/terragoat.git terragoat
git -C terragoat checkout 729f8da62c6a85ce4af5ad3d123de97776d954c4
git clone https://github.com/tenable/KaiMonkey.git kaimonkey
git -C kaimonkey checkout 3feb0bf1a5ab81a79f225407a5ed16db3acd59a4
```

Prepare local patch inputs:

```bash
python3.12 adoption/terrarepair-v1/prepare.py \
  --terrarepair /absolute/path/to/terrarepair \
  --terragoat /absolute/path/to/terragoat \
  --kaimonkey /absolute/path/to/kaimonkey \
  --output /absolute/path/to/new-terrarepair-input
```

Then run [`evaluate.py`](../repairer-eval/README.md#run) with that input and
separately installed `iac-guard-v==1.0.0` and `checkov==3.3.0`. Publish the
raw `results.json`, `summary.csv`, `verification_receipt.json`, all ten
`report.json` files, and the `provenance.json` if sharing a result. Review
third-party content and repository licensing before redistributing a complete
input/output archive.

The first [author-run stable 1.0 pilot](pilot-2026-10-05/RUN_RECORD.md) is
published with all ten raw reports. All ten were `INCONCLUSIVE` because
baseline target discovery could not accept the Checkov result structure for
these module snapshots. This is a visible limitation, not a repair failure or
external validation. A researcher rerun from an independent environment is
still requested.
