# Optional IaC-Guard-V 1.0 recipe for pre-commit-terraform users

This is a proposed **local hook recipe**, not a hook shipped by
[pre-commit-terraform](https://github.com/antonbabenko/pre-commit-terraform).
It fits a repository that stores a project-owned `before/` and `after/`
Terraform repair pair and wants a fail-closed check before committing.
It can run alongside that project's existing Checkov or Trivy hooks. Those
tools can identify a finding; IaC-Guard-V then checks one exact repair target.

Install `iac-guard-v==1.0.0` and `checkov==3.3.0` in **separate** Python
environments as described in the [protected installation guide](../../docs/ADVANCED_INSTALLATION.md#install-from-pypi).
Copy `verify-repair.sh` into your repository, for example at
`scripts/verify-iac-repair.sh`, and make it executable. Set these variables in
your local environment or a project-owned wrapper:

```bash
export IACGV_BEFORE="$PWD/verification/before"
export IACGV_AFTER="$PWD/verification/after"
export IACGV_TARGET='CKV_AWS_3=aws_ebs_volume.target'
export IACGV_GUARD="$PWD/.venv-iac-guard/bin/iac-guard"
export IACGV_CHECKOV="$PWD/.venv-checkov330/bin/checkov"
```

Add to `.pre-commit-config.yaml`:

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
only when the selected repair is `VERIFIED`. `FAILED`, `INCONCLUSIVE`, missing
dependencies, invalid requests, and setup errors block the commit. It prints
the preserved raw report path under `IACGV_REPORT_ROOT` (or a temporary run
directory) for inspection. Use trusted local source only; the 1.0 release does
not ship the hardened hostile-input container or a general pull-request Action.

This recipe does not infer intent from a Checkov/Trivy finding, validate all
resources, or turn a scanner's absence of output into a pass. The project must
choose and review its before/after pair and exact target. A repository owner
would need to adopt and maintain the hook or corresponding CI job before it
counts as repo-owned integration.

An author-run smoke check on 2026-10-05 used the released 1.0 wheel and
Checkov 3.3.0 against the synthetic EBS example in this repository. The hook
returned `VERIFIED/0` and preserved `report-v1`. This is not a
pre-commit-terraform maintainer run or adoption by that repository.
