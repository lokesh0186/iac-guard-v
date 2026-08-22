# IaC-Guard-V

[![PyPI](https://img.shields.io/pypi/v/iac-guard-v)](https://pypi.org/project/iac-guard-v/)
[![Python](https://img.shields.io/pypi/pyversions/iac-guard-v)](https://pypi.org/project/iac-guard-v/)
[![Python compatibility](https://github.com/lokesh0186/iac-guard-v/actions/workflows/python-compat.yml/badge.svg?branch=main)](https://github.com/lokesh0186/iac-guard-v/actions/workflows/python-compat.yml)
[![License](https://img.shields.io/pypi/l/iac-guard-v)](https://github.com/lokesh0186/iac-guard-v/blob/main/LICENSE)
[![QRS 2026](https://img.shields.io/badge/QRS-2026-4b5563)](https://github.com/lokesh0186/iac-guard-v/blob/main/RESEARCH_SNAPSHOT.md)

**Verify that an infrastructure-as-code security fix actually fixed the intended
finding without hiding evidence, deleting the target, or introducing a regression.**

IaC-Guard-V works with changes written by people, AI coding agents, and remediation
tools. It binds scanner evidence to the exact before/after files and resources, then
fails closed when the evidence is incomplete or unverifiable.

> **Status:** `0.1.0a1` technical alpha · Checkov-focused · trusted local input only.
> The hardened hostile-input container and GitHub Action are not released.

## Why IaC-Guard-V?

A scanner can say, “this check passes now.” IaC-Guard-V asks the questions needed to
trust that conclusion:

- Was this exact finding present before?
- Is the candidate evidence bound to the same file and resource?
- Did the finding actually become a passing evaluation?
- Was the target deleted, renamed, suppressed, or replaced?
- Did another finding or destructive change appear?
- Did the scanner, ruleset, parser, and coverage remain trustworthy?

Uncertainty is reported as `INCONCLUSIVE`, never as success.

## Install and try it

Install the public package and run the deterministic offline demo:

```bash
python -m pip install iac-guard-v==0.1.0a1
iac-guard --version
iac-guard demo
```

```text
IaC-Guard-V offline demo (illustrative; not verification evidence)
VERIFIED     target FIXED; scanner integrity PASS; policy VERIFIED; exit 0
FAILED       target STILL_PRESENT; policy FAILED; exit 1
SUPPRESSED   suppression visible; policy FAILED; exit 1
INCONCLUSIVE scanner or coverage evidence unavailable; exit 3
```

The offline demo needs neither Checkov nor Docker. It explains the result model but
does not create verification evidence.

## Verify a real change

Real Checkov verification uses separate protected product and scanner environments.
Follow the tested [real-verification installation](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/ADVANCED_INSTALLATION.md),
then run:

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

A successful target-scoped repair looks like:

```text
IaC-Guard-V: VERIFIED
exit_code: 0
target: CKV_AWS_53 aws_s3_bucket_public_access_block.example: FIXED
scanner integrity: PASS
regressions: none
policy: VERIFIED
```

Use an exact selector when you want one finding or when a resource occurs in more than
one file:

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

Real verification may remain quiet for several minutes while Checkov runs and the
evidence is captured and validated. The validated conclusion is printed only after the
evidence is complete.

## Real-world example

IaC-Guard-V independently evaluated the privilege-hardening portion of
[Coder `demo-env-templates` PR #180](https://github.com/coder/demo-env-templates/pull/180):

| Exact target | Base | Head | Outcome |
| --- | --- | --- | --- |
| `CKV_K8S_16` · `kubernetes_deployment_v1.this` | failing | passing | `FIXED` |
| `CKV_K8S_20` · `kubernetes_deployment_v1.this` | failing | passing | `FIXED` |

Scanner integrity, Terraform parsing, and target-scoped regression gates passed,
producing `VERIFIED` with exit `0`. This is target-scoped evidence, not a whole-PR
certification. See the
[immutable reproduction and report](https://github.com/lokesh0186/iac-guard-v/tree/25cff91e2c039ddc648541a06191f4b9b9a813b7/examples/public-reproductions/coder-demo-env-templates-180).

## Main commands

| Command | Purpose |
| --- | --- |
| `iac-guard demo` | Show deterministic illustrative outcomes offline. |
| `iac-guard demo --real --local-trusted ...` | Run the packaged Checkov before/after fixture. |
| `iac-guard doctor --mode local-trusted ...` | Check whether the selected local verification environment is usable. |
| `iac-guard verify ...` | Verify exact before/after directories. |
| `iac-guard pr ...` | Materialize exact Git base/head objects and verify changed targets. |
| `iac-guard explain report.json` | Validate and explain an existing `report-v1`. |

Git-aware verification does not modify the current checkout, index, branch, or
worktree:

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

Advanced pinned configuration, lock records, source builds, macOS `uv` setup, and the
source-independent real demo are documented in
[Advanced installation and workflows](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/ADVANCED_INSTALLATION.md).

## Verdicts and exit codes

| Result | Exit | Meaning |
| --- | ---: | --- |
| `VERIFIED` | 0 | Every required protected predicate passed. |
| `FAILED` | 1 | The candidate definitely failed a required predicate or policy. |
| Invalid request/configuration | 2 | The invocation or protected configuration is malformed. |
| `INCONCLUSIVE` | 3 | Required evidence is missing, partial, unsupported, or unverifiable. |
| Unexpected internal error | 4 | The verifier could not complete safely. |

## Supported scope

The initial supported path verifies Terraform and Kubernetes-related changes with the
locked Checkov 3.3.0 environment and emits validated JSON, console, SARIF, Markdown, or
JUnit reports. Native execution is `reduced-isolation` and must be used only with
operator-controlled input.

KICS, Trivy, OpenTofu, kubeconform, TFLint, multi-scanner consensus, Helm
materialization, and candidate-only new-IaC review remain experimental, advisory, or
future work. They cannot silently change the final verdict.

See [Supported scope and limitations](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/SUPPORTED_SCOPE.md)
for exact boundaries and [Security model](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/SECURITY_MODEL.md)
for the fail-closed trust architecture.

## Documentation

- [Advanced installation and workflows](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/ADVANCED_INSTALLATION.md)
- [Supported scope and limitations](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/SUPPORTED_SCOPE.md)
- [Security model](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/SECURITY_MODEL.md)
- [Example walkthrough](https://github.com/lokesh0186/iac-guard-v/blob/main/docs/EXAMPLE_WALKTHROUGH.md)
- [Security policy](https://github.com/lokesh0186/iac-guard-v/blob/main/SECURITY.md)
- [Contributing](https://github.com/lokesh0186/iac-guard-v/blob/main/CONTRIBUTING.md)
- [Roadmap](https://github.com/lokesh0186/iac-guard-v/blob/main/ROADMAP.md)
- [Changelog](https://github.com/lokesh0186/iac-guard-v/blob/main/CHANGELOG.md)

## Research snapshot

IaC-Guard-V grew from a QRS 2026 study of infrastructure-as-code repair verification.
The frozen research artifact is historical evidence, not the current product. No
benchmark inference or model-provider call occurs during product verification.

See [RESEARCH_SNAPSHOT.md](https://github.com/lokesh0186/iac-guard-v/blob/main/RESEARCH_SNAPSHOT.md)
for the frozen manifest, replay contract, limitations, and offline reproduction. The
pre-peer-review manuscript is awaiting a public arXiv identifier; the Springer Version
of Record and DOI will be linked when available. No placeholder publication link is
published.

## Contributing, citation, and license

Small, test-backed documentation, compatibility, fixture, and adapter contributions are
welcome. Start with [CONTRIBUTING.md](https://github.com/lokesh0186/iac-guard-v/blob/main/CONTRIBUTING.md).

Citation metadata is in [CITATION.cff](https://github.com/lokesh0186/iac-guard-v/blob/main/CITATION.cff).
IaC-Guard-V is licensed under the [Apache License 2.0](https://github.com/lokesh0186/iac-guard-v/blob/main/LICENSE).
Third-party tools are not bundled and retain their own licences and trademarks.
