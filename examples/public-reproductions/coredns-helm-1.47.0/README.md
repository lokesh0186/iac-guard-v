# CoreDNS Helm 1.47.0: ServiceMonitor-to-Service inconsistency

Classification: released feature-composition defect.

## Verifier

IaC-Guard-V `0.1.0a9`

PyPI: [`iac-guard-v==0.1.0a9`](https://pypi.org/project/iac-guard-v/0.1.0a9/)

Software DOI: <https://doi.org/10.5281/zenodo.22216372>

- IaC-Guard-V release source:
  `b4045c1e25e1abb10d55912698ea7130f13d54db`
- Public wheel SHA256:
  `64727745b787fdb473712eed1c4cd332ee27b12553ab3edc34194045f637ee00`
- Native property registry identity:
  `de9a293ea2d3da8dbdbbbe3b12aa5b5d212ba789af225ea714b18d91dc501f90`

## Exact released source

- Repository: [`coredns/helm`](https://github.com/coredns/helm)
- Release: [`coredns-1.47.0`](https://github.com/coredns/helm/releases/tag/coredns-1.47.0)
- Commit: `fd5b836b84e80f6ca5be9b59b77e4d2dd3505467`
- Tree: `7e1d80e7366f7f97f65fc91debf4f4fd989657a4`

At the final pre-publication check, 1.47.0 remained the latest release. The
current `master` branch retained the same relevant template blobs, and no exact
public issue or pull request described or fixed this option composition.

## Finding

In `coredns-1.47.0`, enabling the documented
`prometheus.monitor.enabled=true` option while leaving
`prometheus.service.enabled=false` renders a ServiceMonitor whose selector
matches no Service.

Enabling both options renders the expected metrics Service and the native
relationship becomes satisfied.

This is conditional behavior, not a default-install claim: the ServiceMonitor
feature is disabled by default. The chart documents the monitor and metrics
Service switches separately and has no values-schema or template validation
that declares their dependency.

## Exact A/B result

Property: `iac_guard_v:IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1`,
version 1.

| Case | Monitor | Metrics Service | Matching Services | Native result | Resolution |
|---|---:|---:|---:|---|---|
| A | true | false | 0 | `VIOLATED` | `SERVICEMONITOR_TARGET_UNRESOLVED` |
| B | true | true | 1 | `SATISFIED` | TCP 9153 to the CoreDNS container |

In Case A, the ordinary DNS Service matches three selector labels but lacks
the required `app.kubernetes.io/component=metrics` label. It is therefore not
an alternate target. In Case B, the added `a9-impact-coredns-metrics` Service
matches all four labels and resolves its named `metrics` endpoint through TCP
9153 to the protected CoreDNS Deployment/container.

Both Case A renders are byte-identical at SHA256
`706e01ebc5d54261c29b41b36fdb4f4fdd0e3c4069b288c856a1af492f8c2f9f`.
Both Case B renders are byte-identical at SHA256
`cab7531d54b0e71a895bc15fd4f4aa0dfd6839c39d94df47b62d03aa8b969719`.

IaC-Guard-V 0.1.0a9 provides the authoritative scanner-independent native
cross-resource verdict. Checkov, KICS, and Trivy are not the semantic authority
for this evidence.

## Project-native validation

Helm lint passes for Case A. The unmodified project suite passes 15 suites / 24
tests. Its ServiceMonitor and metrics-Service suites validate the templates
separately; neither asserts the cross-template relationship.

A minimal private helm-unittest regression demonstrates that monitor `true`
with service `false` emits the ServiceMonitor but zero metrics Service
documents. Its paired both-enabled positive control emits both objects with
matching labels and port names. `REGRESSION_DESCRIPTION.md` records only the
public-safe test design and results; the private fixture itself is not included.

## Claim boundary

This packet proves a ServiceMonitor-to-Service configuration inconsistency in
the exact rendered Helm resources. It does not claim a security vulnerability,
an outage, live Prometheus behavior, or failure in every environment. No live
Kubernetes cluster, Prometheus instance, or network traffic was used.

See `REPRODUCE.md` for public replay commands, `RESOURCE_INVENTORY.json` and
`AB_COMPARISON.json` for the mechanical comparison, and `CLAIM_LEDGER.md` for
the claim boundaries. `SHA256SUMS` binds every retained packet file.
