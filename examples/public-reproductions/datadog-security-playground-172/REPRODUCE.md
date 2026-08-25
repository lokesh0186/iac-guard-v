# Reproduce the selected candidate property

Create clean, separate environments for public IaC-Guard-V `0.1.0a5` and the
supported Checkov `3.3.0` scanner:

```bash
python3 -m venv .venv-bootstrap
.venv-bootstrap/bin/python -m pip install uv
.venv-bootstrap/bin/uv venv --python 3.13 --seed .venv-iac-guard
.venv-bootstrap/bin/uv pip install --python .venv-iac-guard/bin/python \
  iac-guard-v==0.1.0a5
.venv-bootstrap/bin/uv venv --python 3.13 --seed .venv-checkov330
.venv-bootstrap/bin/uv pip install --python .venv-checkov330/bin/python \
  checkov==3.3.0
```

Fetch the exact PR head:

```bash
git clone https://github.com/DataDog/datadog-security-playground.git source
git -C source fetch origin fa1d0a898a2a03ae164114623026f5dcf7642daa
git -C source checkout --detach fa1d0a898a2a03ae164114623026f5dcf7642daa
```

Run the exact target-scoped candidate-property request:

```bash
.venv-iac-guard/bin/iac-guard accept \
  --candidate "$PWD/source/terraform/ecs-ec2" \
  --property CKV_AWS_24=aws_security_group.instance@main.tf \
  --framework terraform \
  --local-trusted \
  --checkov-executable "$PWD/.venv-checkov330/bin/checkov" \
  --format json \
  --output "$PWD/report.json"

.venv-iac-guard/bin/iac-guard explain \
  "$PWD/report.json" \
  --format markdown \
  --output "$PWD/report.md"
```

Expected selected result:

```text
verification_mode: candidate_acceptance
CKV_AWS_24 / aws_security_group.instance / main.tf: SATISFIED
verdict: VERIFIED
```

The report must retain all unselected findings in scope accounting. `SATISFIED` does
not mean `FIXED` and does not make a whole-module or runtime-security claim.
