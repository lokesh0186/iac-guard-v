# Project-native regression description

The private validation used the repository's existing helm-unittest framework
and its CI-pinned plugin version 1.0.2. No test was added to the upstream
repository.

The minimal negative regression sets:

```yaml
prometheus:
  monitor:
    enabled: true
  service:
    enabled: false
```

It establishes that the ServiceMonitor template emits one document, while the
metrics-Service template emits zero documents. An assertion that the required
metrics Service exists therefore fails with expected document count 1 and
actual count 0.

The paired positive control sets both switches to `true`. It establishes that:

- the ServiceMonitor emits one document;
- the metrics Service emits one document;
- both use `app.kubernetes.io/component: metrics` for the relationship; and
- both use the endpoint/ServicePort name `metrics`.

The positive control passed 1 suite / 2 tests. The negative regression failed
for the expected zero-document reason. The unmodified chart suite passed 15
suites / 24 tests, and Helm lint passed for the negative configuration. This
shows an actionable cross-template test gap without characterizing project CI
as defective.
