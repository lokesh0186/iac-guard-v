# ADR-0001 — Keep the research artifact in this repository

- Status: Accepted
- Date: 2026-08-09

## Context

The repository is simultaneously the replication package for an accepted QRS 2026 paper
and the intended home of a product. 4,842 of 4,850 tracked files are research artifacts
(3,481 benchmark items, 630 run records, 630 patches, 70 baselines, 8 tables, 3 figures,
3 prompts, 11 scripts). External references — the paper, the citation file, future
proceedings text — point at this repository.

Splitting the research into a second repository would make the product tree cleaner and
would break every existing reference, orphan the citation metadata, and make the
"reproduce the paper" path a two-repository operation.

## Decision

Keep both in one repository. Separate them by **enforcement**, not by directory
aesthetics:

- research paths stay at their current locations, byte-frozen by
  `research/qrs2026-byte-manifest.jsonl` and checked in CI;
- product code lives under `src/iac_guard_v/`;
- the legacy verification profile lives under `research/compat/`, outside the product's
  profile directory, so it cannot be selected by product configuration;
- packaging excludes research data from wheel and sdist, enforced by a test.

## Consequences

- A clone is 28 MB. Acceptable; `pipx install` does not clone.
- Contributors see research directories they must not edit. The manifest turns that
  from a social rule into a failing check.
- The reproduce path stays single-repository and needs no credentials.
- Any relocation of research paths later would require a redirect strategy for external
  links; we accept the current layout as permanent.

## Alternatives considered

**Separate `iac-guard-v-research` repository.** Rejected: breaks references and
citations for a cosmetic gain.

**Move research under `research/` in this repository.** Rejected: same reference
breakage, and the byte manifest already provides the isolation that a move would only
imply.

## Amendment, 2026-08-11: quarantined D9 analysis

The offline legacy-versus-hardened comparator lives under `research/compat/`, outside
the product package. It reads stored frozen outputs and locally invokes only packaged
deterministic parsers. It has no scanner subprocess, provider SDK, network path, or write
path to frozen research data, and its result cannot be selected as a product profile.
