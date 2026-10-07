# IaCSecBench: independent IaC-Guard-V 1.0 rerun

This packet checks one public IaCSecBench canonical pair with the stable
`iac-guard-v==1.0.0` release. It is a small starting point for a maintainer-run
result, not a replacement for IaCSecBench's optional 26-pair integration.

The selected `ENC_UNENCRYPTED_VOLUME` pair changes the `encrypted` property of
`aws_ebs_volume.target`. IaCSecBench's merged integration maps it to Checkov
`3.3.0` rule `CKV_AWS_3`. The prior `0.1.0b1` run reported `VERIFIED`; this
packet does not assert a 1.0 outcome before an independent run produces one.

## Inputs and boundary

- IaCSecBench: [`v2.1.0`](https://github.com/mchittineni/iacsecbench/releases/tag/v2.1.0),
  commit `762d28e3d9cce4cf3bb3807a4b1f893a4d80a611`.
- IaC-Guard-V: public wheel `1.0.0`, in its own Python 3.10–3.13 environment.
- Checkov: `3.3.0`, in a **separate** environment. Its `hcl2` distribution
  overlaps the verifier's protected parser when both are installed together.
- Input: the two checked-in case directories named in `inputs.sha256`.
- Execution: local trusted mode, on source controlled by the person running it.
  No cluster, cloud account, model provider, Terraform provider download, or
  benchmark generation is involved.

The script verifies the exact checkout commit, a clean working tree, the file
set, and every input hash before it invokes IaC-Guard-V. It then runs the
verifier's environment doctor and the exact target. It writes a raw report,
standard output and error, and a compact `run-summary.json` into a new output
directory **outside** the IaCSecBench checkout. It preserves `FAILED` and
`INCONCLUSIVE` outcomes and operational errors.

## Run

1. Check out the IaCSecBench release at the commit above:

   ```bash
   git clone --depth 1 --branch v2.1.0 \
     https://github.com/mchittineni/iacsecbench.git iacsecbench-v2.1.0
   ```

   The script independently checks the resolved commit and case-file hashes.
2. Install the two separately pinned environments using
   [the protected installation guide](../../docs/ADVANCED_INSTALLATION.md#install-from-pypi).
   Use `iac-guard-v==1.0.0` and `checkov==3.3.0` exactly. Create both environments
   with `venv --copies --without-pip` and install through the host installer using
   `--no-compile`. See [fresh environment setup](../../docs/FRESH_ENVIRONMENT.md).
   Do not run `checkov --version` or import Checkov directly before the packet;
   those commands can create bytecode that `doctor` rejects. The packet protects
   its own version check with `PYTHONDONTWRITEBYTECODE=1`. If this already happened,
   preserve the doctor output and rebuild into new environment directories.
3. From an IaC-Guard-V checkout containing this packet, run:

```bash
python3.12 adoption/iacsecbench-v1-rerun/rerun.py \
  --repo /absolute/path/to/iacsecbench \
  --iac-guard /absolute/path/to/.venv-iac-guard/bin/iac-guard \
  --checkov /absolute/path/to/.venv-checkov330/bin/checkov \
  --output /absolute/path/to/new-rerun-output
```

The packet selects local trusted mode. A missing hardened-container image may be
reported as `INCONCLUSIVE` by that separate doctor check while the local environment
passes. This does not claim hostile-input isolation. See the
[CI trust boundary](../../docs/CI_TRUST_BOUNDARY.md).

The output directory must not exist yet. Installation time is separate from
verification time; neither has a measured five-minute guarantee for this
packet. Inspect `run-summary.json` and `report.json` before sharing them. A
`VERIFIED` result would establish the selected transition in this exact input
and environment, not the correctness of all 26 pairs or of IaCSecBench's
scanner leaderboard.

For a source-only check that does not invoke the verifier or scanner:

```bash
python3.12 adoption/iacsecbench-v1-rerun/rerun.py \
  --repo /absolute/path/to/iacsecbench --check-only
```

IaCSecBench's [merged paired-verification integration](https://github.com/mchittineni/iacsecbench/pull/88)
remains pinned to `0.1.0b1`. Its historical reports and published benchmark
results must retain that identity. A separate, reviewed integration update would
be needed before its full 26-pair command can use stable 1.0.
