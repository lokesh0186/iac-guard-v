# ADR-0009 — No telemetry of any kind

- Status: Accepted
- Date: 2026-08-09

## Context

Usage data would help prioritise work: which scanners people actually run, where
`doctor` fails, which outcomes dominate. The inputs to this tool are private
infrastructure configuration, and it is designed to run in regulated and air-gapped
environments where any outbound connection is a review item.

## Decision

No telemetry, no usage pings, no crash reporting, no version check, no analytics — not
even opt-in. The core, CLI, container, and Action make no outbound network connection
during verification. `--network=none` is a supported and tested mode.

There is nothing to disable, which is the property enterprise reviewers can verify by
reading the dependency list and the network policy rather than trusting a setting.

## Consequences

- Prioritisation relies on issues, the pilot programme, and the usability log — slower,
  and honest.
- No crash aggregation; bug reports must be good instead. `explain` and the canonical
  report exist partly to make a report easy to attach.
- Adopters in regulated environments need no legal review of data flows.
- If telemetry is ever wanted, it requires a new ADR superseding this one, a major
  version, and an explicit opt-in, never a default.

## Alternatives considered

**Anonymous opt-in metrics.** Rejected for 1.0: an opt-in mechanism still ships network
code and still requires review; the credibility gained by having none exceeds the
prioritisation benefit.

**Version-check on startup.** Rejected: it is telemetry with a friendly name.
