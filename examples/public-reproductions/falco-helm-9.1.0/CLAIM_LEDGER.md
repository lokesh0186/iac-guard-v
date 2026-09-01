# Claim ledger

| Claim | Evidence | Boundary |
|---|---|---|
| Monitor-only composition emits a ServiceMonitor with no matching Service | Case A a10 report and complete resource inventory | Exact Falco 9.1.0 chart artifact and values only |
| Enabling metrics completes the relationship | Case B a10 report | Resolves through the rendered Service to TCP 8765 |
| The result is scanner-independent | `IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1` witness | Checkov, KICS, and Trivy are not the semantic authority |
| The intent contract is externally supplied | Contract source provenance is `RESEARCH_HYPOTHESIS` | It is not represented as project-authored intent |
| Render is deterministic | Each case is rendered twice with byte equality | Local Helm materialization, not runtime deployment |
| Project-native tests miss the relation | Existing focused tests pass; private cross-template regression fails | No criticism of unrelated test coverage |

This packet does not claim a vulnerability, outage, live Prometheus failure,
runtime packet behavior, or failure in every Falco deployment.
