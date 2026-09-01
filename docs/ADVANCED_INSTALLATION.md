# Advanced installation and workflows

IaC-Guard-V `0.1.0b1` uses a protected product environment and a separate
Checkov `3.3.0` environment for real verification. This is the tested native
path for operator-controlled input. Native execution is reduced isolation; it
is not suitable for hostile pull-request content.

For an immediate, non-evidentiary introduction, an ordinary installation is
enough:

```bash
python -m pip install iac-guard-v==0.1.0b1
iac-guard demo
```

The offline demo illustrates the verdict model. Follow the protected setup
below before relying on real scanner evidence.

The native OpenTofu reference path parses protected source and does not require a
`tofu` executable. Helm and Kustomize executables are required only for their bounded
materialization commands and are governed by the exact prerequisites in
[Helm materialization](HELM_MATERIALIZATION.md) and
[Kustomize materialization](KUSTOMIZE_MATERIALIZATION.md).

## Choose a Python interpreter

The protected environments must contain copied files, not symlinked interpreter
files. On macOS, Apple or framework Python builds may report that they cannot
create a virtual environment without symlinks. Do not remove `--copies`.
Install a standalone, uv-managed interpreter instead:

```bash
brew install uv
uv python install 3.12
BETA_PYTHON="$(uv python find --managed-python 3.12)"
```

On a Python installation that already supports copied-file environments:

```bash
BETA_PYTHON="$(command -v python3)"
```

## Install from PyPI

Upgrade the host installer first because the commands below use its `--python`
option. Then create the two environments without bundled pip and install without
compiling bytecode:

```bash
python3 -m pip install --upgrade pip

"$BETA_PYTHON" -m venv --copies --without-pip .venv-iac-guard
"$BETA_PYTHON" -m venv --copies --without-pip .venv-checkov330

python3 -m pip --python .venv-iac-guard/bin/python install --no-compile \
  'iac-guard-v==0.1.0b1'
python3 -m pip --python .venv-checkov330/bin/python install --no-compile \
  'checkov==3.3.0'
```

No cache cleanup or hidden environment variable is required. In particular,
you do not need to export `PYTHONDONTWRITEBYTECODE=1`: the installed wheel's
RECORD-bound startup policy prevents runtime bytecode.

The separate environments are intentional. Checkov `3.3.0` installs
`bc-python-hcl2`, while IaC-Guard-V uses `python-hcl2` as its protected parser.
Installing both distributions over the same `hcl2` files breaks wheel-RECORD
provenance and is rejected.

## Check the environment and run a real demo

```bash
.venv-iac-guard/bin/iac-guard doctor \
  --mode local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov"

.venv-iac-guard/bin/iac-guard demo \
  --real \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --format console \
  --output ./iac-guard-report.json
```

Expected conclusion:

```text
IaC-Guard-V: VERIFIED
exit_code: 0
target: CKV_AWS_53 aws_s3_bucket_public_access_block.example: FIXED
scanner integrity: PASS
regressions: none
policy: VERIFIED
```

`demo --real` reads its fixture from the installed wheel, so it works from an
otherwise empty directory and needs no source checkout. Run `doctor` and the
real demo a second time without cache cleanup to reproduce the release smoke.

Real verification may remain quiet for several minutes while Checkov runs and
IaC-Guard-V captures and validates its output. The conclusion is printed only
after the evidence is complete. The reviewed external macOS smoke reached its first
`VERIFIED` result in approximately three minutes.

## Verify your own before/after directories

Discover all exact baseline findings:

```bash
.venv-iac-guard/bin/iac-guard verify \
  --before ./before \
  --after ./after \
  --all-baseline-findings \
  --framework terraform \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --output ./iac-guard-report.json
```

Or select one exact finding:

```bash
.venv-iac-guard/bin/iac-guard verify \
  --before ./before \
  --after ./after \
  --target CKV_AWS_53=aws_s3_bucket_public_access_block.example \
  --framework terraform \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --output ./iac-guard-report.json
```

If a rule/resource selector maps to more than one file or occurrence, the
request is rejected and the exact candidates are shown. IaC-Guard-V never
guesses an ambiguous target.

## Verify exact Git revisions

The Git-aware path materializes exact objects in private temporary directories.
It does not modify the current checkout, index, branch, or worktree.
`--changed-only` limits target selection; regression coverage still evaluates
the complete candidate snapshot.

```bash
.venv-iac-guard/bin/iac-guard pr \
  --repository . \
  --base-ref origin/main \
  --head-ref HEAD \
  --all-baseline-findings \
  --changed-only \
  --framework terraform \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --format sarif \
  --output ./iac-guard.sarif
```

## Advanced pinned configuration

Direct arguments are the primary workflow. For reproducible automation, create
an explicit configuration:

```bash
.venv-iac-guard/bin/iac-guard init \
  --baseline ./before \
  --candidate ./after \
  --target CKV_AWS_53=aws_s3_bucket_public_access_block.example \
  --framework terraform \
  --execution-mode reduced-isolation \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --output ./iac-guard.config.json
```

The workflow commands enter the same sealed-snapshot and protected-policy
verifier:

```bash
.venv-iac-guard/bin/iac-guard scan \
  --config ./iac-guard.config.json --format json
.venv-iac-guard/bin/iac-guard differential \
  --config ./iac-guard.config.json --format markdown
.venv-iac-guard/bin/iac-guard pr \
  --changed-only --config ./iac-guard.config.json --format sarif
```

`scan` remains a differential `report-v1` workflow in this release: its config
names both baseline and candidate. The direct `verify` command is canonical.

Create a deterministic local environment record with:

```bash
.venv-iac-guard/bin/iac-guard lock \
  --config ./iac-guard.config.json \
  --output ./iac-guard.lock.json
```

The record is labelled `LOCK_RECORD_NOT_VERIFICATION_EVIDENCE`; it cannot be
submitted as scanner evidence or make a verdict trusted.

## Build from source

Source builds are for development and artifact reproduction. Never reuse a
stale distribution directory:

```bash
rm -rf dist build
find . -maxdepth 2 -type d -name '*.egg-info' -prune -exec rm -rf {} +
python3 -m pip install --upgrade pip
python3 -m pip install 'build>=1.2,<2'
python3 -m build --outdir dist
```

Use the freshly built wheel in place of `iac-guard-v==0.1.0b1` in the protected
installation commands above.

## Reports

Commands that accept `--format` can render validated `report-v1` as `json`,
`console`, `sarif`, `markdown`, or `junit`. Reporters do not reinterpret target
outcomes. JUnit represents uncertainty as skipped/error rather than success.

`explain` validates the complete evidence graph before rendering it:

```bash
.venv-iac-guard/bin/iac-guard explain ./iac-guard-report.json
```

Contradictory or forged reports are rejected as invalid requests.
