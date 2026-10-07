# Verify a declared Terraform repair before committing

This is a repo-local hook recipe for a trusted `before/` and `after/` pair. It is
not a hook shipped by [pre-commit-terraform](https://github.com/antonbabenko/pre-commit-terraform).
Use it when a reviewer wants evidence that one named Checkov finding changed
from failing to passing on the same resource. The repository owner chooses the
pair and target. Checkov remains the authority for the rule's result.

## What the scanners already offer

[Checkov](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html) can scan both directories and emit full JSON with failed, passed,
skipped, and parsing-error records. Its `--baseline` option reports new failures
relative to an earlier scan. A repo-owned script can compare two full JSON
reports and require a failure before and a pass after for one exact check and
resource. That can be a good fit for a small, controlled case. The script also
needs to reject missing or duplicate target records, skips, parsing errors,
scanner failures, and configuration drift.

[Trivy](https://trivy.dev/docs/latest/references/configuration/cli/trivy_config/) can include successful misconfiguration checks in JSON, set a nonzero
exit code for findings, and run custom Rego checks. A custom policy or report
comparison may fit a project's own workflow. Neither scanner's overall exit
code, by itself, says whether a selected repair passed.

IaC-Guard-V 1.0 packages this paired check for supported Checkov evidence. It
binds the selected rule and resource to the before and after snapshots, checks
scanner and coverage evidence, and writes a canonical `report-v1`. It exits
nonzero when the selected repair cannot be verified. This adds a dependency
and uses the pinned Checkov 3.3.0 environment. It does not establish that
Checkov's underlying rule is correct or that every resource is secure.

## Repo-local hook

Install `iac-guard-v==1.0.0` and `checkov==3.3.0` in separate Python environments
using the [protected installation guide](../../docs/ADVANCED_INSTALLATION.md#install-from-pypi).
Download [`verify-repair.sh`](verify-repair.sh). From the root of your Terraform
repository, copy it into `scripts/` and make it executable:

```bash
mkdir -p scripts
cp /path/to/verify-repair.sh scripts/verify-iac-repair.sh
chmod +x scripts/verify-iac-repair.sh
```

Set these paths in your local environment or a project-owned wrapper:

```bash
export IACGV_BEFORE="$PWD/verification/before"
export IACGV_AFTER="$PWD/verification/after"
export IACGV_TARGET='CKV_AWS_3=aws_ebs_volume.target'
export IACGV_GUARD="$PWD/.venv-iac-guard/bin/iac-guard"
export IACGV_CHECKOV="$PWD/.venv-checkov330/bin/checkov"
```

Add this entry to `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: iac-guard-v-verify-repair
      name: Verify declared Terraform repair with IaC-Guard-V 1.0
      entry: scripts/verify-iac-repair.sh
      language: script
      pass_filenames: false
      always_run: true
      require_serial: true
```

Run `pre-commit run iac-guard-v-verify-repair --all-files`. The hook exits zero
only for `VERIFIED`. A failed or inconclusive result, missing scanner, invalid
request, or setup error blocks the commit. It prints the canonical report path
under `IACGV_REPORT_ROOT`, or under a temporary run directory if that variable
is unset. Inspect the report and the source pair when reviewing the result.

This 1.0 recipe accepts trusted local source only. It does not ship a hardened
container or a general pull-request Action for hostile input. It checks the
declared target, not all repairs or all resources. Keep the before and after
directories and the target under project review.

## Author-run checks

On 2026-10-06, the released 1.0.0 wheel and Checkov 3.3.0 returned
`VERIFIED/0` for a synthetic EBS encryption repair through the actual
`pre-commit run` command. The same local comparison rejected unchanged input,
deletion, suppression, a different passing resource, a duplicate failing
resource, malformed Terraform, and a missing scanner. Checkov's baseline
command exited zero for unchanged, deleted, and suppressed candidates, which
is expected for a new-findings filter. A small script over full Checkov JSON
also rejected those candidates. These are author-run fixture checks, not a
pre-commit-terraform maintainer run or adoption by that project.
