# ADR-0003 — Four-tier finding identity instead of rule IDs

- Status: Accepted
- Date: 2026-08-09

## Context

The frozen harness compares sets of `check_id` values
(`scripts/verify_patch.py:90`, `:93`, `:95`). Three failure modes follow directly, all
recorded as audit finding F3: a finding that moves between resources is invisible;
duplicate occurrences of one rule collapse to a single member, so fixing one of three
violations looks complete; and a target is "resolved" when its rule ID disappears for
any reason at all.

## Decision

Identity is tiered:

| Tier | Key | Purpose |
| --- | --- | --- |
| `EXACT` | scanner + rule + file + resource address + occurrence index | same-scanner before/after |
| `RELOCATED` | scanner + rule + resource address, tolerating file move and line drift | detect a moved finding rather than resolved-plus-new |
| `SEMANTIC` | control id + resource + artifact kind | cross-scanner, `EXACT` mappings only |
| `OCCURRENCE` | duplicates preserved | never collapse N violations into one |

Fingerprints carry an algorithm identifier, exclude line numbers and temporary paths,
canonicalise Terraform addresses (`type.name[index]`) and Kubernetes object identity
(`apiVersion/kind/namespace/name`), and are stored alongside — never instead of — the
scanner's native fingerprint.

## Consequences

- Comparison is a multiset operation, so `MOVED_FINDING` and `PARTIALLY_FIXED` become
  expressible, and both are default failures.
- Golden tests are needed for line drift, temp-root renaming, duplicates,
  multi-document YAML, and file moves.
- A fingerprint algorithm change is a visible, versioned event rather than a silent
  reshuffling of history.
- Adapters that expose no resource identity for some rule types will produce weaker
  identity for those findings; that case reports reduced confidence rather than
  pretending to precision.

## Alternatives considered

**Rule ID plus line number.** Rejected: line numbers move for unrelated reasons, so
this both misses real regressions and invents fake ones.

**Native scanner fingerprint only.** Rejected: not all scanners provide one, definitions
differ across tools and versions, and it is unusable for cross-scanner work.
