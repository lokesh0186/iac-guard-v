# IaC-Guard-V

IaC-Guard-V is a fail-closed verifier for infrastructure-as-code changes. It asks a
more specific question than a scanner: **did this candidate change resolve the bound
finding without hiding evidence, deleting the target, introducing a regression, or
turning operational uncertainty into success?**

`0.1.0a1` is a Checkov-focused alpha. It is prepared for review but is not yet a
published release.

## Project status

The repository contains two deliberately separate bodies of work:

| Area | Status |
| --- | --- |
| Frozen QRS 2026 research snapshot | Preserved at tag `qrs-2026-replication-v1`; 4,842 files and 630 stored runs can be checked without new model calls. |
| Hardened product core | Typed differential evidence, fail-closed report validation, Checkov 3.3.0 integration, deterministic SARIF/Markdown/JUnit projections, and closed workflow commands. |
| Checkov-focused alpha | The supported initial product focus. Packaging is prepared as `0.1.0a1`; it is not published. |
| KICS, Trivy, OpenTofu, kubeconform, and TFLint | Experimental, lock-bound adapters and validators. Their agreement is advisory and cannot change the final policy verdict. |
| Hardened production container | Not released. Hostile pull-request input does not have a released hardened execution path yet. |

There are no external-adoption, production-readiness, or multi-scanner-consensus
claims. The current control catalog has zero `EXACT` mappings and is explicitly not
ready for validated-discrepancy screening.

## Install

IaC-Guard-V supports CPython 3.10–3.13. After an owner-authorized package release,
install the alpha with:

```bash
python -m pip install "iac-guard-v==0.1.0a1"
```

Until publication, build and install the reviewed source locally:

```bash
python -m pip install build
python -m build
python -m pip install dist/iac_guard_v-0.1.0a1-py3-none-any.whl
```

Check the installed command:

```bash
iac-guard --version
# iac-guard 0.1.0a1
```

The wheel contains product code, schemas, and protected bundled oracle policy. It
does not contain the paper, benchmark, stored runs, research datasets, experiment
scripts, or test-only evidence capabilities.

## Quickstart

### Offline demo

`demo` is deterministic, requires neither Checkov nor Docker, and creates no trusted
verification evidence:

```bash
iac-guard demo
iac-guard demo --format json
```

Its `OFFLINE_DEMO_ONLY` diagnostic is intentional. It demonstrates the public report
shape; it is not a successful scan.

### Environment diagnosis

```bash
iac-guard doctor
iac-guard doctor --format json
```

`doctor` checks the installed Checkov closure, executable caches, validator registry,
and hardened-container availability. Exit 3 means the environment is incomplete,
unverifiable, or operationally uncertain; it is not silently converted to success.

Native Checkov execution is named **`reduced-isolation`**. Use it only for locally
trusted input. It is not a substitute for the unreleased hardened container and must
not be used for hostile pull-request content.

### Real Checkov before/after example

The repository includes a minimal Terraform repair under
[`examples/checkov-before-after`](examples/checkov-before-after). With Checkov 3.3.0:

```bash
checkov --framework terraform --check CKV_AWS_53 \
  --file examples/checkov-before-after/before.tf --quiet --compact --skip-download
# exit 1: block_public_acls is false

checkov --framework terraform --check CKV_AWS_53 \
  --file examples/checkov-before-after/after.tf --quiet --compact --skip-download
# exit 0: CKV_AWS_53 passes
```

This demonstrates the scanner observation only. An IaC-Guard-V `VERIFIED` result
additionally requires sealed baseline/candidate snapshots, exact target binding,
scanner and gate integrity, regression evidence, and protected policy evaluation.

### Explain an existing report

`explain` validates the complete `report-v1` evidence graph before rendering it. It
does not create or change verification evidence:

```bash
iac-guard explain report.json
```

Contradictory or forged reports are rejected as invalid requests.

### Local workflow commands

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
contract, limitations, and exact offline verification commands. No arXiv identifier is
published here because the owner has not supplied one.

## Contributing and roadmap

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [CHANGELOG.md](CHANGELOG.md)
- [NOTICE](NOTICE)

## Citation

Citation metadata for the accepted QRS 2026 paper and this software is in
[CITATION.cff](CITATION.cff). An arXiv link will be added only after the owner supplies
the identifier.

## License

IaC-Guard-V is licensed under the [Apache License 2.0](LICENSE). Third-party tools are
not bundled and retain their own licences and trademarks.
