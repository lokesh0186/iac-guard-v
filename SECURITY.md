# Security Policy

IaC-Guard-V `0.1.0a3` is an alpha with a Checkov-focused product boundary. It is
not yet a production hardened-container release.

## Supported versions

| Version | Security support |
| --- | --- |
| `0.1.x` alpha | Yes, within the documented alpha boundary. |
| Earlier or unreleased builds | No. Upgrade to the latest published `0.1.x` release. |

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
- The hardened production container and GitHub Action are not released. Do not use
  the alpha to evaluate hostile pull-request content.
- The project does not defend against arbitrary hostile Python already running in its
  trusted interpreter.

The accessible product summary is in
[`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md); the normative detail is in
[`docs/spec/THREAT_MODEL.md`](docs/spec/THREAT_MODEL.md).

## Sensitive data

IaC-Guard-V has no telemetry or model-provider integration. Reports can nevertheless
contain repository-relative paths, resource identities, and scanner diagnostics.
Review artifacts before sharing them and keep protected cache material private.
