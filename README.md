# IaC-Guard-V

[![PyPI](https://img.shields.io/pypi/v/iac-guard-v)](https://pypi.org/project/iac-guard-v/)
[![Python compatibility](https://github.com/lokesh0186/iac-guard-v/actions/workflows/python-compat.yml/badge.svg?branch=main)](https://github.com/lokesh0186/iac-guard-v/actions/workflows/python-compat.yml)
[![License](https://img.shields.io/pypi/l/iac-guard-v)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22088272.svg)](https://doi.org/10.5281/zenodo.22088272)

IaC-Guard-V is a fail-closed verifier for declared infrastructure invariants over
protected, deterministically materialized infrastructure as code. Version 1.0 supports
an exact set of 18 native properties. It does not claim universal IaC correctness,
deployment safety, live-cluster behavior, or equivalence among security scanners.

The verifier is offline in native-property and contract modes. It does not call model
providers, cloud APIs, or a Kubernetes cluster. Missing, ambiguous, unsupported, or
incomplete evidence never becomes success.

## Install

IaC-Guard-V 1.0 supports Python 3.10, 3.11, 3.12, and 3.13. Python 3.14 is not in the
1.0 support matrix.

```bash
python -m pip install 'iac-guard-v==1.0.0'
iac-guard --version
iac-guard doctor --mode native --format json
iac-guard properties list
```

## First Kubernetes result

The packaged quickstart checks whether a rendered Deployment is selected by a
NetworkPolicy. Copy the `examples/quickstart/kubernetes/satisfied` directory, then run:

```bash
python -m iac_guard_v.native_properties \
  --config examples/quickstart/kubernetes/satisfied/native-request.json \
  --format json \
  --output kubernetes-report.json
```

The result is `SATISFIED`. The adjacent `violated` and `not-evaluated` examples show a
definite failed predicate and an unresolved named-port relationship:

```bash
python -m iac_guard_v.native_properties \
  --config examples/quickstart/kubernetes/violated/native-request.json \
  --format console
python -m iac_guard_v.native_properties \
  --config examples/quickstart/kubernetes/not-evaluated/native-request.json \
  --format console
```

Non-success is intentional. The native module returns `0` for all satisfied, `1` for a
violation, `3` for not evaluated or unsupported, `4` for an evaluation error, and `2`
for an invalid invocation. Contract commands use their separately frozen `0`, `10`,
`11`, `12`, `20`, and `21` mapping. Do not translate uncertainty into success.

## First Terraform result

The Terraform quickstart checks one exact source-local reference. It does not run
`terraform init`, evaluate providers, resolve remote modules, or infer a plan.

```bash
python -m iac_guard_v.native_properties \
  --config examples/quickstart/terraform/native-request.json \
  --format json \
  --output terraform-report.json
```

OpenTofu uses the distinct `opentofu_source` artifact class and
`IACGV_OPENTOFU_REFERENCE_RESOLVES_V1`, including the documented `.tofu` and JSON
precedence rules. Terraform V1 remains `.tf`-only.

## Declared contracts

Projects can place a contract at `.iac-guard-v/contracts.yaml` or supply one explicitly.
Version 1.0 accepts both the existing `iac-guard-v.io/v1alpha1` form and the stable
`iac-guard-v.io/v1` form. Existing v1alpha1 consumers do not need to rewrite contracts.

```bash
iac-guard contract lint --contract .iac-guard-v/contracts.yaml
iac-guard contract plan --contract .iac-guard-v/contracts.yaml \
  --project-root . --contract-root rendered --format json
iac-guard verify --contract .iac-guard-v/contracts.yaml \
  --project-root . --contract-root rendered --format json \
  --output iac-guard-contract-report.json
iac-guard explain iac-guard-contract-report.json
```

Contract provenance is not inferred from a successful result. Use
`PROJECT_AUTHORED` only when repository evidence supports project-owned intent.

## Result model

| Native or contract result | Meaning |
| --- | --- |
| `SATISFIED` | The selected mechanical property is proven over the protected evidence. |
| `VIOLATED` | The protected evidence proves the selected property false. |
| `NOT_EVALUATED` | Required evidence is missing, ambiguous, incomplete, or not applicable. |
| `UNSUPPORTED` | The request is outside the declared supported semantics. |
| `ERROR` | Evaluation could not complete safely. |

Scanner-based before/after repair verification retains its established `VERIFIED`,
`FAILED`, and `INCONCLUSIVE` result model and exit codes. See [Compatibility](COMPATIBILITY.md).

## Scanner authority

Native properties independently adjudicate their declared semantics. Checkov 3.3.0 is
authoritative only on reviewed property and target paths with complete affirmative
evidence. Trivy and KICS are advisory by default. Empty or missing scanner output is
never a pass, and scanners are never majority-voted. See
[Scanner authority](SCANNER_AUTHORITY.md).

## CI example

This example is read-only, uses no secrets or cluster, and pins both Python and the
package. Replace the render step and contract with project-owned inputs.

```yaml
name: IaC relationship verification
on:
  pull_request:
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065
        with:
          python-version: "3.12"
      - run: python -m pip install --no-compile 'iac-guard-v==1.0.0'
      - run: iac-guard doctor --mode native --format json
      - run: iac-guard contract lint --contract .iac-guard-v/contracts.yaml
      - run: ./project-owned-deterministic-render-command
      - run: |
          iac-guard verify --contract .iac-guard-v/contracts.yaml \
            --project-root . --contract-root rendered --format json \
            --output iac-guard-contract-report.json
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        if: always()
        with:
          name: iac-guard-report
          path: iac-guard-contract-report.json
```

Do not use `pull_request_target` to execute untrusted pull-request content. Local Helm,
Kustomize, and native execution are reduced-isolation modes for operator-controlled
input, not hostile-code sandboxes.

## Stable support boundary

- [Supported scope](SUPPORTED_SCOPE.md)
- [Security model](SECURITY_MODEL.md)
- [Compatibility policy](COMPATIBILITY.md)
- [Native properties](NATIVE_PROPERTIES.md)
- [Scanner authority](SCANNER_AUTHORITY.md)
- [Support policy](SUPPORT_POLICY.md)
- [Migration from 0.1.0b1](MIGRATION_0_1_0B1_TO_1_0.md)
- [1.0 release notes](RELEASE_NOTES_1_0.md)

More detailed materializer documentation remains in `docs/`. The frozen QRS research
artifact is historical evidence and is not required to understand or use the product.

## Citation and license

Use the concept DOI [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272)
for the evolving software. The final 1.0 version DOI is added only after the authorized
Zenodo archive exists. Machine-readable metadata is in [CITATION.cff](CITATION.cff).

IaC-Guard-V is licensed under the [Apache License 2.0](LICENSE). Third-party tools are
not bundled and retain their own licenses and trademarks.
