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

IaC-Guard-V supports CPython 3.10–3.13. A normal installation is suitable for the
offline demo and inspection of an existing validated report:

```bash
python -m pip install "iac-guard-v==0.1.0a1"
```

That ordinary install is **not equivalent** to the bytecode-free environment required
for authoritative reduced-isolation verification. Normal installers may create Python
bytecode caches; IaC-Guard-V types a cache-bearing scanner/parser environment as
inconclusive rather than weakening that integrity control.

Until publication, the tested alpha bootstrap below installs a freshly built local
wheel. After publication, the wheel argument can be replaced with the exact published
`iac-guard-v==0.1.0a1` artifact.

## Five-minute Checkov alpha path

Run this one contiguous sequence from a reviewed source checkout. It creates separate
copied-file product/parser and scanner environments, prevents stale artifact reuse,
installs without bytecode,
executes the real Checkov 3.3.0 before/after workflow twice, validates both report-v1
documents, and checks deterministic semantic/Markdown output:

```bash
python3 -m venv --copies .venv-iac-guard
. .venv-iac-guard/bin/activate

python -m pip install --upgrade pip
python -m pip install --no-compile "build>=1.2,<2"

rm -rf dist build
find . -maxdepth 2 -type d -name '*.egg-info' -prune -exec rm -rf {} +
python -m build --outdir dist

python -m pip install --no-compile \
  ./dist/iac_guard_v-0.1.0a1-py3-none-any.whl

python3 -m venv --copies .venv-checkov330
.venv-checkov330/bin/python -m pip install --no-compile "checkov==3.3.0"

find .venv-iac-guard -name __pycache__ -type d -prune -exec rm -rf {} +
find .venv-iac-guard -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find .venv-checkov330 -name __pycache__ -type d -prune -exec rm -rf {} +
find .venv-checkov330 -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
export PYTHONDONTWRITEBYTECODE=1
export PATH="$PWD/.venv-checkov330/bin:$PATH"

iac-guard --version
# iac-guard 0.1.0a1
iac-guard doctor --format json

export ALPHA_WORK="$(mktemp -d)"
mkdir -p "$ALPHA_WORK/baseline" "$ALPHA_WORK/candidate"
cp examples/checkov-before-after/before.tf "$ALPHA_WORK/baseline/main.tf"
cp examples/checkov-before-after/after.tf "$ALPHA_WORK/candidate/main.tf"

iac-guard init \
  --baseline "$ALPHA_WORK/baseline" \
  --candidate "$ALPHA_WORK/candidate" \
  --target CKV_AWS_53=aws_s3_bucket_public_access_block.example \
  --framework terraform \
  --execution-mode reduced-isolation \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --output "$ALPHA_WORK/iac-guard.config.json" \
  --format json

iac-guard differential \
  --config "$ALPHA_WORK/iac-guard.config.json" \
  --format json > "$ALPHA_WORK/report-1.json"
iac-guard differential \
  --config "$ALPHA_WORK/iac-guard.config.json" \
  --format json > "$ALPHA_WORK/report-2.json"

python - <<'PY'
import copy, json, os
from pathlib import Path
from iac_guard_v.report import validate_report_payload
from iac_guard_v.reporters import render_markdown

root = Path(os.environ["ALPHA_WORK"])
reports = [json.loads((root / f"report-{n}.json").read_text()) for n in (1, 2)]
for report in reports:
    validate_report_payload(report)
    binding = report["verification"]["targets"][0]["binding"]
    assert report["verdict"] == "VERIFIED" and report["exit_code"] == 0
    assert report["execution_isolation"]["mode"] == "reduced-isolation"
    assert binding["artifact_kind"] == "terraform_hcl"
    assert binding["file_path"] == "main.tf"
    assert binding["identity"]["rule_id"] == "CKV_AWS_53"
    assert binding["identity"]["scope"] == \
           "aws_s3_bucket_public_access_block.example"
    assert str(root) not in json.dumps(report, sort_keys=True)
semantic = copy.deepcopy(reports)
for report in semantic:
    for run in ("baseline_run", "candidate_run"):
        for field in ("duration_ms", "raw_output_sha256", "stdout_sha256"):
            report["verification"][run].pop(field)
assert semantic[0] == semantic[1]
assert render_markdown(reports[0]) == render_markdown(reports[1])
print("VERIFIED exit=0 target=CKV_AWS_53 isolation=reduced-isolation deterministic=PASS")
PY
# VERIFIED exit=0 target=CKV_AWS_53 isolation=reduced-isolation deterministic=PASS
```

Exact raw stdout/result hashes and measured durations remain run-specific provenance in
report-v1 because Checkov emits a fresh private output path per execution. The test
therefore requires stable canonical scanner evidence and byte-identical deterministic
Markdown, while preserving—not erasing—the exact raw hashes.

`doctor` checks the installed Checkov closure, executable caches, validator registry,
and hardened-container availability. Exit 3 is expected in this alpha because the
hardened container is unavailable; Checkov and validator-registry checks must still
pass. Native **`reduced-isolation`** is for trusted local input only, never hostile pull-
request content. Multi-scanner evidence remains experimental and advisory.

The two environments are intentional: Checkov 3.3.0 installs `bc-python-hcl2`, while
the product's protected Terraform parser is `python-hcl2`. Installing both distributions
over the same `hcl2` package files breaks wheel-RECORD provenance and is rejected.

The wheel contains product code, schemas, and protected bundled oracle policy. It does
not contain the paper, benchmark, stored runs, research datasets, experiment scripts,
or test-only evidence capabilities.

## Other alpha commands

### Offline demo

`demo` is deterministic, requires neither Checkov nor Docker, and creates no trusted
verification evidence:

```bash
iac-guard demo
iac-guard demo --format json
```

Its `OFFLINE_DEMO_ONLY` diagnostic is intentional. It demonstrates the public report
shape; it is not a successful scan.

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
