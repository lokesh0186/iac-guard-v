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

- Comparison is a multiset operation, so `LOCATION_CHANGED` and `PARTIALLY_FIXED`
  become expressible. `PARTIALLY_FIXED` fails by default; `LOCATION_CHANGED` is
  advisory, because a resource moving between files is a refactor, not a regression.
- A rule that disappears from resource A and appears on resource B is two findings, not
  one relocation: `RESOLVED_FINDING` on A plus `NEW_FINDING` on B. Only the resource
  address decides, which is precisely what tiering buys.
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

## Amendment, 2026-08-10: D3 executable identity algorithm

The first production algorithm is `iacgv1`. It hashes canonical compact JSON with sorted
keys over the algorithm id, scanner, rule id, scan-root-relative path, canonical resource
address, occurrence index, and artifact kind. Its stored form prefixes the lowercase
SHA-256 with `iacgv1:`. The algorithm excludes line numbers, scanner version, display
prose, severity, suppression state, and native fingerprint so those independently
reported facts cannot destabilize primary identity.

Occurrence indices are assigned by the canonical normalizer before attaching the
fingerprint. A caller-supplied fingerprint must recompute exactly or it is rejected.
Same-scanner comparison matches exact occurrences first, then unambiguous relocated
occurrences with the same resource. Ambiguous relocation is refused; different resources
remain two facts rather than one match.
