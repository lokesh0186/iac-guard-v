# CI integration

The CLI is the canonical CI interface. Native and contract verification is read-only,
requires no cluster/cloud credentials, has no telemetry, and does not invoke model
providers. Beta1 is for trusted repository input; do not use `pull_request_target` to
check out and execute an untrusted pull-request head.

## GitHub Actions

Pin both Python and IaC-Guard-V. Replace the render command and contract inputs with
the project's reviewed deterministic workflow.

```yaml
name: IaC contract
on:
  push:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@COMMIT_SHA_FOR_V4
      - uses: actions/setup-python@COMMIT_SHA_FOR_V5
        with:
          python-version: "3.12"
      - run: python -m pip install --no-compile 'iac-guard-v==0.1.0b1'
      - run: iac-guard doctor --mode native --format json
      - run: iac-guard contract lint --contract .iac-guard-v/contracts.yaml
      - run: ./project-owned-deterministic-render-command
      - run: |
          iac-guard contract plan --contract .iac-guard-v/contracts.yaml \
            --project-root . --contract-root rendered --format json
      - run: |
          iac-guard verify --contract .iac-guard-v/contracts.yaml \
            --project-root . --contract-root rendered --format json \
            --output iac-guard-contract-report.json
```

Replace the action placeholders with reviewed immutable commit SHAs. The repository
does not publish a composite action in Beta1.

## Generic CI

The same commands work in GitLab CI, Jenkins, CircleCI, Buildkite, and POSIX-shell
jobs. Preserve the process exit code and archive the JSON report. Contract exit codes
are `0` satisfied, `10` violated, `11` not evaluated/inactive, `12` unsupported, `20`
invalid, and `21` execution error. Do not translate `11`, `12`, `20`, or `21` into
success.
