# ADR-0012 — Two freeze mechanisms: byte-exact and semantic

- Status: Accepted
- Date: 2026-08-09

## Context

The freeze has to satisfy two requirements that cannot be satisfied by one mechanism.

*Byte preservation*: the frozen artifact must be provably unchanged, which means hashing
exact bytes with no normalisation whatsoever.

*Semantic reproduction*: the derived tables must be shown to regenerate from the frozen
inputs. Verified 2026-08-09: they regenerate with **zero content differences**, but they
are **not** byte-identical, because Python's `csv` writer emits CRLF while git stores LF
under `* text=auto`. A byte comparison of regenerated output fails for a reason with no
research meaning.

An initial design tried to do both with one four-field checksum manifest validated by
`shasum -c`. That does not work: `shasum` treats everything after the digest as a
filename, so a `<digest>  <mode>  <size>  <path>` record fails with
`FAILED open or read` against a path that does not exist.

## Decision

Two mechanisms, two artifacts, two vocabularies.

**Byte freeze.** `research/qrs2026-byte-manifest.jsonl` — one JSON record per frozen
file binding `path`, `git_mode`, `git_blob_oid`, `size_bytes`, `sha256`, with no
normalisation. `MANIFEST_ROOT` lives in a typed `.root` sidecar so the record count
means file count and nothing else. Verified by
`research/verify_byte_manifest.py`, which also rejects missing files, **unlisted files
under frozen prefixes**, mode changes, symlinks, and a stale root.

**Semantic reproduction.** `research/replay_from_frozen_runs.py` rebuilds
`all_runs.csv` exactly (10,080 field comparisons) and compares the seven derived tables
after a declared canonicalisation (CRLF→LF, one trailing newline). Its verdict is
`SEMANTIC_MATCH`, and it records `byte_identical: false`. It never claims byte equality.

Scope is 4,842 research-critical files. The 8 mutable files — README, the two `docs/`
files, `CITATION.cff`, `LICENSE`, `.gitignore`, `.gitattributes`, `paper.pdf` — are
deliberately excluded so ordinary documentation work cannot trip the freeze.

## Consequences

- Two commands and two result vocabularies to learn; the alternative was one command
  that lies in one direction or the other.
- The `git_blob_oid` field lets the verifier distinguish an unstaged content edit from a
  CRLF checkout. Both fail, with different reason codes, so a Windows contributor is not
  told they tampered with research data.
- The "no unlisted file" check is load-bearing: without it, a new file added under
  `scripts/` or `runs/` would leave all 4,842 recorded hashes valid and pass.
- Adding a legitimate research file later requires regenerating the manifest, which is
  an explicit, reviewable act.

## Alternatives considered

**One `.sha256` manifest with `shasum -c`.** Rejected: demonstrated not to work with the
required fields, and it cannot detect added files at all.

**Normalise line endings in the byte manifest.** Rejected: a normalising byte manifest is
not a byte manifest.

**Compare regenerated tables byte-for-byte.** Rejected: guaranteed false failures with no
research meaning.
