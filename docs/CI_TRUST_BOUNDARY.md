# CI trust boundary

IaC-Guard-V 1.0 local execution is reduced isolation for operator-controlled input. `doctor --mode local-trusted` checks the selected environment without claiming that a hostile-input container is configured.

An unavailable hardened-container check may be `INCONCLUSIVE` while the explicitly chosen local mode succeeds. This does not provide container isolation. Never silently fall back to local mode when hardened isolation was required.

Use a trusted project revision and a manual trigger for early CI examples. Give the job only `contents: read`, no deployment credentials or secrets. Do not use `pull_request_target` to check out and execute an untrusted PR head. Dependency installation has network access; verifier execution has no model-provider, cloud or live-cluster calls.

The [security model](../SECURITY_MODEL.md) and [scanner authority](../SCANNER_AUTHORITY.md) govern the result. Reports can contain resource names and diagnostics; review them before uploading publicly.
