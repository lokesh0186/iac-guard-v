# Project-native regression

The private regression uses Falco chart's existing Go, Terratest, Helm, and
Testify unit-test framework. It renders `templates/serviceMonitor.yaml` and
`templates/service.yaml` under the same values rather than testing the two
templates independently.

| Case | Values | ServiceMonitor | Metrics Service | Result |
|---|---|---:|---:|---|
| monitor only | `serviceMonitor.create=true` | 1 | 0 | expected regression failure |
| positive control | monitor and `metrics.enabled=true` | 1 | 1 | pass |

The unmodified focused project tests for the ServiceMonitor and Service pass.
They cover each template independently and do not assert the cross-template
relationship. The proposed regression is not included here as an upstream
change and no fix pull request has been opened.
