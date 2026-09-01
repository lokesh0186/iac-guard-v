# Falco Helm 9.1.0: ServiceMonitor-to-Service inconsistency

Classification: released feature-composition defect.

## Verifier

IaC-Guard-V `0.1.0a10`

- PyPI: <https://pypi.org/project/iac-guard-v/0.1.0a10/>
- software DOI: <https://doi.org/10.5281/zenodo.22226912>
- release source: `038bf38256706ffc83485bf5f33eb3c4992e3857`
- public wheel SHA256:
  `6ff89229083c88b3d9c35b9be21646e722dfccaf2e6b2ccf3d215bb4c2a3b57e`
- native property registry identity:
  `de9a293ea2d3da8dbdbbbe3b12aa5b5d212ba789af225ea714b18d91dc501f90`

## Exact released source

- repository: <https://github.com/falcosecurity/charts>
- release: <https://github.com/falcosecurity/charts/releases/tag/falco-9.1.0>
- commit: `53586de4fb9d8d02006131ade702b161cd7e06e3`
- tree: `ce376e495fdb9ee84daf44b118adc759090bd231`
- published chart SHA256:
  `2a767d6aeccf2392c5e263ae1f5e0950520affe3a9908ff7986ac213649c45b4`

At the final pre-publication check, 9.1.0 remained the current Falco chart
release and the default branch retained the same independent template gates.
No exact public issue, pull request, or current-main fix was found.

## Finding

In Falco chart `9.1.0`, enabling the documented
`serviceMonitor.create=true` option while retaining the documented
`metrics.enabled=false` default renders a ServiceMonitor whose selector
matches no Service.

Enabling `metrics.enabled=true` is the positive control: the expected metrics
Service appears and the relationship resolves to the Falco container on TCP
8765.

This is conditional behavior, not a default-install claim. The chart documents
the ServiceMonitor and metrics settings separately and does not document or
validate `metrics.enabled=true` as a prerequisite for rendering the
ServiceMonitor.

## Exact A/B result

The authoritative property is
`iac_guard_v:IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1`, version 1.

| Case | Monitor | Metrics | Matching Services | a10 contract/native result | Resolution |
|---|---:|---:|---:|---|---|
| A | true | false | 0 | `VIOLATED` | `SERVICEMONITOR_TARGET_UNRESOLVED` |
| B | true | true | 1 | `SATISFIED` | TCP 8765 |

Both Case A renders are byte-identical at SHA256
`712e943209cc4acd0057aed8d43eedadf8ce8bf258c8f7a174a6d088b71bec86`.
Both Case B renders are byte-identical at SHA256
`bc7068d5817cabf16a724ecf8c5e62fbbe2cc8c5ae64e91adf190f3729cc5fa2`.

IaC-Guard-V 0.1.0a10 provides the scanner-independent, witness-backed native
cross-resource verdict. The included a10 contract adds explicit activation and
non-vacuous target cardinality. Because the contract was supplied by this
investigation rather than committed by Falco, its provenance is correctly
recorded as `RESEARCH_HYPOTHESIS`, not `PROJECT_AUTHORED`.

Both cases are rendered twice and require byte-identical output. Helm lint and
the existing focused chart tests pass. A minimal private project-native
Go/Terratest regression reproduces the missing-Service relationship; see
`REGRESSION_DESCRIPTION.md`.

## Claim boundary

This packet proves a ServiceMonitor-to-Service inconsistency in protected,
rendered Helm resources. It does not claim a security vulnerability, outage,
live Prometheus behavior, live Kubernetes behavior, or runtime network result.

See `REPRODUCE.md` for public replay commands, `A_B_EXECUTION.json` for the
complete A/B identities, and `CLAIM_LEDGER.md` for the exact claim boundaries.
