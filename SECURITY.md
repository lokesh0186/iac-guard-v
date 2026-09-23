# Security Policy

IaC-Guard-V `1.0.0` supports operator-controlled local input under the bounded
security model in [`SECURITY_MODEL.md`](SECURITY_MODEL.md). It does not claim to be a
hostile-input sandbox. Checkov `3.3.0` is authoritative only on reviewed paths.

## Supported versions

| Version | Security support |
| --- | --- |
| Latest `1.x` release | Yes, within its documented bounded support matrix. |
| `0.1.x` prereleases | Migration support only. Upgrade to the latest `1.x` release. |

## Reporting a vulnerability

Please use the repository's private GitHub security-advisory channel. Do not include
credentials, private infrastructure, undisclosed third-party scanner cases, or
candidate repository contents in a public issue.

Include the IaC-Guard-V version, platform, execution mode, minimal reproduction, and
whether the input was trusted. Reports that concern an upstream scanner will not be
forwarded or published without the reporter's and project owner's authorization.

## Supported security boundary

- Public CLI, configuration, API, and report inputs may not manufacture trusted
  scanner, validator, oracle, or policy evidence.
- `INCONCLUSIVE` and operational errors are fail-closed and never equivalent to
  `VERIFIED`.
- Native mode is explicitly `reduced-isolation` and is suitable only for locally
  trusted input.
- Checkov is authoritative only on separately reviewed paths. KICS and Trivy remain
  advisory and cannot establish a protected target `PASS` or change the final verdict.
- Helm and Kustomize materialization are closed local contracts, not general
  interpreters. Remote resolution, live cluster state, and unsupported dynamic
  semantics fail closed.
- Declared intent contracts compile only to immutable supported native properties.
  Contract provenance, activation, exclusions, cardinality, and responsibility are
  explicit; a mechanical contract violation is not automatically a project defect,
  vulnerability, outage, or runtime claim.
- OpenTofu verification uses a distinct protected source mode. It does not fetch
  modules, run providers, or execute `init`, `plan`, or `apply`.
- Do not use local execution to evaluate hostile pull-request content. No supported
  mode silently claims hostile-input containment.
- The project does not defend against arbitrary hostile Python already running in its
  trusted interpreter.

The accessible product summary is in
[`SECURITY_MODEL.md`](SECURITY_MODEL.md); the normative detail is in
[`docs/spec/THREAT_MODEL.md`](docs/spec/THREAT_MODEL.md).

## Sensitive data

IaC-Guard-V has no telemetry or model-provider integration. Reports can nevertheless
contain repository-relative paths, resource identities, and scanner diagnostics.
Review artifacts before sharing them and keep protected cache material private.

## Suspected false SATISFIED

A credible false `SATISFIED` report is treated as a high-priority correctness issue.
Use the dedicated issue form for non-sensitive evidence or the private advisory channel
when disclosure itself is sensitive. The project freezes the evidence, reproduces the
case, fixes it generically, adds an adversarial regression, and reviews property/schema
version impact. Do not include private infrastructure or credentials.
