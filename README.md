# IaC-Guard-V

IaC-Guard-V is a fail-closed verifier for infrastructure-as-code changes. It asks a
more specific question than a scanner: **did this candidate change resolve the bound
finding without hiding evidence, deleting the target, introducing a regression, or
turning operational uncertainty into success?**

`0.1.0a1` is a Checkov-focused alpha. It is prepared for review but is not yet a
published release.

## Source-independent Checkov alpha path

This is the supported native alpha path for trusted local input. It uses copied-file
environments created without bundled pip, installs with `--no-compile`, and relies on
the wheel's RECORD-bound startup policy to prevent runtime bytecode. No cache cleanup or
hidden environment variable is required; specifically, users do not need to export
`PYTHONDONTWRITEBYTECODE=1`. The hardened hostile-input container is not released.

```bash
rm -rf dist build
find . -maxdepth 2 -type d -name '*.egg-info' -prune -exec rm -rf {} +
python -m pip install --upgrade pip
python -m pip install 'build>=1.2,<2'
python -m build --outdir dist

python -m venv --copies --without-pip .venv-iac-guard
python -m venv --copies --without-pip .venv-checkov330
python -m pip --python .venv-iac-guard/bin/python install --no-compile \
  dist/iac_guard_v-0.1.0a1-py3-none-any.whl
python -m pip --python .venv-checkov330/bin/python install --no-compile \
  'checkov==3.3.0'

.venv-iac-guard/bin/iac-guard doctor \
  --mode local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov"
.venv-iac-guard/bin/iac-guard demo \
  --real \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --format console \
  --output ./iac-guard-report.json
# IaC-Guard-V: VERIFIED
# exit_code: 0
# targets:
#   CKV_AWS_53 aws_s3_bucket_public_access_block.example: FIXED
# scanner integrity: PASS
# regressions: none
# policy: VERIFIED
```

Exit codes are `0` VERIFIED, `1` FAILED, `2` invalid request, `3` INCONCLUSIVE, and
`4` unexpected internal error. The saved file is canonical validated `report-v1` even
when console output is selected. Native `local-trusted` mode is reduced isolation:
use it only for operator-controlled input. [Advanced config workflow](#advanced-pinned-configuration)
remains available for reproducible automation.

`demo --real` reads the example from the installed wheel, so the command above works
from an otherwise empty directory and does not require a Git source checkout. To verify
your own before/after directories, use the same installed environments:

```bash
.venv-iac-guard/bin/iac-guard verify \
  --before ./my-before \
  --after ./my-after \
  --all-baseline-findings \
  --framework terraform \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --output ./iac-guard-report.json
```

Use an exact selector when a repository contains multiple occurrences or when only one
baseline finding should be verified:

```bash
.venv-iac-guard/bin/iac-guard verify \
  --before ./my-before \
  --after ./my-after \
  --target CKV_AWS_53=aws_s3_bucket_public_access_block.example \
  --framework terraform \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --output ./iac-guard-report.json
```

After publication, replace the local wheel path with `iac-guard-v==0.1.0a1` in the
same `pip --python ... install --no-compile` command. The packaged `demo --real` command
then remains source-independent; ordinary `verify` consumes directories supplied by the
user. Run `doctor` and the real demo again without cache cleanup—the release gate tests
that installed sequence twice.

## Project status

| Area | Status |
| --- | --- |
| Frozen QRS 2026 research snapshot | Bound to commit `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5` and `MANIFEST_ROOT` `a42cf0184aa345e50603caeed2c9035f3da45bc636c950633d766566f5e9b7b3`; public CI reconstructs and verifies the local-only annotated freeze tag, which is not published. |
| Hardened product core | Typed differential evidence, fail-closed report validation, Checkov 3.3.0 integration, and deterministic reporters. |
| Checkov-focused alpha | The supported initial product focus; package version `0.1.0a1` is not published. |
| KICS, Trivy, OpenTofu, kubeconform, and TFLint | Experimental and advisory; their agreement cannot change the final verdict. |
| Hardened production container and Action | Not released. |

There are no external-adoption, production-readiness, or multi-scanner-consensus
claims. The control catalog has zero `EXACT` mappings and is not ready for validated-
discrepancy screening.

Exact raw stdout/result hashes and durations remain run-specific provenance. The
release test requires stable semantic evidence and deterministic reporter projections
while preserving those exact raw identities.

`doctor --mode local-trusted` succeeds when the Checkov alpha is usable; `doctor --mode
hardened-container` remains inconclusive until that image exists. Multi-scanner evidence
remains experimental and advisory.

The two environments are intentional: Checkov 3.3.0 installs `bc-python-hcl2`, while
the product's protected Terraform parser is `python-hcl2`. Installing both distributions
over the same `hcl2` package files breaks wheel-RECORD provenance and is rejected.

The wheel contains product code, schemas, and protected bundled oracle policy. It does
not contain the paper, benchmark, stored runs, research datasets, experiment scripts,
or test-only evidence capabilities.

## Other alpha commands

### Direct Git pull-request verification

The Git-aware path reads exact objects into private temporary trees and does not change
the current checkout, index, branch, or worktree. `--changed-only` restricts target
selection; regression coverage still uses the complete candidate snapshot.

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

### Offline demo

`demo` is deterministic, requires neither Checkov nor Docker, and creates no trusted
verification evidence:

```bash
iac-guard demo
iac-guard demo --format json
```

Console demo shows illustrative VERIFIED, FAILED, SUPPRESSED, and INCONCLUSIVE states.
Its JSON `OFFLINE_DEMO_ONLY` report remains non-evidentiary. `demo --real
--local-trusted` runs the packaged Checkov example through the public verification path.

### Explain an existing report

`explain` validates the complete `report-v1` evidence graph before rendering it. It
does not create or change verification evidence:

```bash
iac-guard explain report.json
```

Contradictory or forged reports are rejected as invalid requests.

### Advanced pinned configuration

For operator-controlled local input, initialize an explicit reduced-isolation request:

```bash
iac-guard init \
  --baseline ./before \
  --candidate ./after \
  --target CKV_AWS_53=aws_s3_bucket_public_access_block.example \
  --framework terraform \
  --execution-mode reduced-isolation \
  --checkov-executable "$(command -v checkov)" \
  --output ./iac-guard.config.json
```

The workflow commands all enter the same sealed-snapshot and protected-policy verifier:

```bash
iac-guard scan --config ./iac-guard.config.json --format json
iac-guard differential --config ./iac-guard.config.json --format markdown
iac-guard pr --changed-only --config ./iac-guard.config.json --format sarif
```

`scan` remains a differential report-v1 workflow in this alpha: its config names both
the trusted baseline and candidate. `pr --changed-only` additionally requires every
selected target file to have changed, then the normal verifier independently reseals
both complete snapshots.

Create a deterministic local environment record with:

```bash
iac-guard lock \
  --config ./iac-guard.config.json \
  --output ./iac-guard.lock.json
```

The alpha lock is labelled `LOCK_RECORD_NOT_VERIFICATION_EVIDENCE`; it cannot be
submitted as scanner evidence or make a verdict trusted. Hardened-container lock
creation remains unavailable until that image is reviewed and released.

Validated report-v1 input can be projected as `json`, `console`, `sarif`, `markdown`,
or `junit` where the command accepts `--format`. Reporters never reinterpret a target
outcome, and JUnit represents uncertainty as skipped/error rather than success.

## Verdicts and exit codes

| Result | Exit | Meaning |
| --- | ---: | --- |
| `VERIFIED` | 0 | Every required protected predicate passed. |
| `FAILED` | 1 | The candidate is definitely invalid or failed policy. |
| Invalid request/configuration | 2 | The invocation or protected configuration is malformed. |
| `INCONCLUSIVE` / operational uncertainty | 3 | Required evidence is missing, partial, unsupported, or unverifiable. |

Uncertainty is never reported as a successful test.

## Security boundaries and current limitations

- Public CLI/config/API inputs cannot submit raw scanner results, precomputed policy
  decisions, oracle results, validator-universe results, callbacks, or trust claims.
- Native `reduced-isolation` is for trusted local input only.
- The production fully offline hardened container and composite GitHub Action are not
  released; their native-Linux UID/bind-mount gate remains pending.
- Multi-scanner and deterministic-oracle evidence remains advisory. V7 consensus is
  disconnected from final verdicts.
- `.tf.json` remains explicitly unsupported/inconclusive end to end.
- The kubeconform schema bundle has licence status `NOASSERTION` and is not publicly
  redistributed.
- IaC-Guard-V does not defend against hostile Python already executing inside its
  trusted interpreter.

See [SECURITY.md](SECURITY.md) for reporting guidance and
[`docs/spec/THREAT_MODEL.md`](docs/spec/THREAT_MODEL.md) for the detailed model.

## Research snapshot

The QRS 2026 artifact is historical evidence, not the current hardened product. Its
scanner of record is Checkov 3.2.517, while the alpha product contract uses Checkov
3.3.0. The stored experiment outputs are never re-labelled as hardened-engine runs.

See [RESEARCH_SNAPSHOT.md](RESEARCH_SNAPSHOT.md) for the manifest root, replay
contract, limitations, and exact offline verification commands. The pre-peer-review
manuscript has been submitted to arXiv, but its public identifier is still pending. No
placeholder identifier or broken link is published. The Springer Version of Record and
DOI will be linked when they become available.

## Contributing and roadmap

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [CHANGELOG.md](CHANGELOG.md)
- [NOTICE](NOTICE)

## Citation

Citation metadata for the accepted QRS 2026 paper and this software is in
[CITATION.cff](CITATION.cff). The arXiv submission is pending public availability. Once
Springer publishes the Version of Record, its DOI and publisher page will become the
primary paper citation; an available arXiv preprint may remain as a separate accessible
manuscript link.

## License

IaC-Guard-V is licensed under the [Apache License 2.0](LICENSE). Third-party tools are
not bundled and retain their own licences and trademarks.
