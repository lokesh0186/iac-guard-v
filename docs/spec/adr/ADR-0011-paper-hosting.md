# ADR-0011 — Hosting of `paper.pdf` in the public repository

- Status: **Interim decision recorded — final choice open**
- Date: 2026-08-09
- Blocks: pushing the `qrs-2026-replication-v1` tag publicly
- Does **not** block: merging PR 1 (interim decision below)
- Does not block: the audit, the freeze manifest, the replay tooling, the
  specification package, or any Phase D work

## Context

The repository root contains `paper.pdf` (393,284 bytes, SHA-256
`c5d6bd9fd24a768f86a105e8846ca79b5dce939ea311eeca7ca69f27eeb16c24`). Verified
facts:

1. The file is **byte-identical** to an author-compiled LaTeX build produced from
   the camera-ready sources with `llncs.cls`. It is therefore an author-produced
   artifact, not a file downloaded from the publisher's platform.
2. Because it uses the LNCS class, it *looks* like the publisher's typeset version
   even though it is not.
3. `README.md:23` currently states: "The paper is not hosted in this repository."
   That sentence and the file contradict each other.
4. The paper is accepted at QRS 2026, with proceedings to appear in Springer LNCS.
5. The file's history is short but instructive. On 2026-07-08 the same 393,284-byte
   PDF was uploaded as `IaC-Guard-V-paper.pdf` (`a3c798d`, 16:52:54), deleted
   (`468d310`, 16:53:51), and re-added as `paper.pdf` (`7646d59`, 16:54:10).
   **The deleted blob is still fully retrievable today**, and it is byte-identical
   to the current file:

   ```console
   $ git ls-tree -r a3c798d | grep -i pdf
   100644 blob 1ece66d9ee7d62acc4747c400f5a533766e3d932	IaC-Guard-V-paper.pdf

   $ git cat-file -s 1ece66d9ee7d62acc4747c400f5a533766e3d932
   393284
   $ git cat-file blob 1ece66d9ee7d62acc4747c400f5a533766e3d932 | shasum -a 256
   c5d6bd9fd24a768f86a105e8846ca79b5dce939ea311eeca7ca69f27eeb16c24
   ```

   This repository therefore contains its own proof of the central consequence
   below: a deletion commit removed the file from the working tree eleven months
   ago and removed nothing from distribution.

Publisher policy, from Springer Nature's published self-archiving terms (to be
confirmed against the specific signed agreement for this paper):

- Self-archiving of the **accepted manuscript** — the post-peer-review version
  prior to copy-editing and typesetting — is permitted on an author's personal
  website and/or funder or institutional repository, **after an embargo period**.
- The **published version** on SpringerLink may not be self-archived.
- For books and chapters, which is the category LNCS proceedings papers fall into,
  the stated embargo is longer than for journals.

Three questions follow, and none of them can be answered from the repository:

- **Q1.** Does the signed copyright transfer or licence-to-publish for this paper
  permit posting the author's camera-ready PDF, and from what date?
- **Q2.** Does a public GitHub repository count as a permitted venue, given that the
  policy names a personal website and funder or institutional repositories?
- **Q3.** Does distributing an LNCS-formatted build risk being read as distributing
  the publisher's version, even though it is author-produced?

## Decision

**Interim owner decision, 2026-08-09: `KEEP_UNCHANGED_PENDING_RIGHTS_CONFIRMATION`.**

- `paper.pdf` is not modified, deleted, moved, or newly packaged.
- No history is rewritten.
- **PR 1 may merge** on this basis, so the PDF question does not block engineering.
- The public freeze tag **is not pushed** until redistribution rights are confirmed or
  the repository is remediated.

This records a decision state rather than resolving the underlying rights question. It
does not resolve, and cannot resolve, distribution that has already occurred: the blob
has been publicly reachable since 2026-07-08 under two names (see Context 5). The final
choice among options A–D below remains open and requires answers to Q1–Q3.

## Options

### Option A — Keep the file, fix the README

Change `README.md:23` to state that an author-produced camera-ready PDF is included.

- Requires an affirmative answer to Q1, Q2, and Q3.
- Cheapest for readers; highest exposure if the agreement disallows it.

### Option B — Replace with a preprint link (recommended default)

Remove `paper.pdf` from the working tree going forward, post the manuscript to
arXiv, and have the README link the arXiv record plus the publisher DOI when it
exists.

- Consistent with the current README sentence.
- arXiv gives a stable, citable, permissioned home and a version history.
- Does **not** remove the file from git history (see Consequences).
- Preferred because it is defensible under every answer to Q1–Q3, and because a
  preprint link ages better than a checked-in binary.

### Option C — Keep the file until the embargo expires, then decide

- Retains present exposure while deferring the decision; the weakest option unless
  Q1 is already known to be permissive.

### Option D — Remove the file from history

Rewrite history to expunge the blob, force-push, and ask GitHub Support to purge
cached views and forks.

- The only option that actually stops distribution of the bytes.
- **Overrides project invariant I2** (no history rewrite, no force push). I2 is an
  engineering discipline, not a legal shield: a licensing determination requiring
  non-distribution takes precedence over it.
- Breaks every existing commit reference, including any citation of a specific SHA.
- Should be chosen only on an explicit rights determination, not as a precaution.

## Consequences

- **A deletion commit does not undistribute the file.** This is not a theoretical
  concern here: the identical PDF was already deleted once under a different name in
  `468d310`, and its blob `1ece66d9` is still readable from this repository today
  (see Context 5). Removing `paper.pdf` in a new commit would leave the blob
  reachable through history, the GitHub UI, the API, and every existing clone or
  fork. Only Option D changes that, and only partially.
- **The 393,284-byte PDF also exists under a second name in history.** Any removal
  work must address both `paper.pdf` and `IaC-Guard-V-paper.pdf`.
- **The tag decision does not resolve past distribution.** Creating
  `qrs-2026-replication-v1` adds one more durable public reference to a commit whose
  tree already contains the file; withholding the tag removes nothing that is
  already public. This is why the tag is created locally and held.
- **The README must stop contradicting the repository** under every option. That
  wording change is queued for Phase G and is gated on this decision.
- **Reproducibility is unaffected.** `paper.pdf` is outside the 4,842-file frozen
  scope. Every reproduction path — byte manifest, replay, derived tables, tests —
  works without it. The paper is documentation, not data.
- **The `CITATION.cff` route stays correct regardless.** Citation metadata points at
  the DOI and repository, not the PDF.

## Owner action required

1. Answer Q1 from the signed agreement; if unclear, ask the QRS 2026 proceedings chair
   or Springer.
2. Answer Q2 and Q3.
3. Choose A, B, C, or D and record it here, superseding the interim decision.
4. Until then: the tag stays local. PR 1 may merge under
   `KEEP_UNCHANGED_PENDING_RIGHTS_CONFIRMATION`.

## Related: the freeze tag message

Separate from the rights question, the tag's original message told readers to run
`research/verify_byte_manifest.py`, which does not exist at the tagged
pre-productization commit. The local tag has been recreated from
`research/TAG_MESSAGE_REPLACEMENT.txt`, which states that verification tooling lives on
the productization branch and is run against the tag, and which declares exactly one
`MANIFEST_ROOT` — the verifier now rejects an annotation carrying more than one.
The tag remains unpushed.

## Verification

```console
$ shasum -a 256 paper.pdf
c5d6bd9fd24a768f86a105e8846ca79b5dce939ea311eeca7ca69f27eeb16c24  paper.pdf

$ git log --oneline --all -- paper.pdf
7646d59 Add files via upload

$ git log --oneline --all -- IaC-Guard-V-paper.pdf
468d310 Delete IaC-Guard-V-paper.pdf
a3c798d Add files via upload

$ python research/verify_byte_manifest.py --manifest research/qrs2026-byte-manifest.jsonl \
    --root . --expect-entries 4842 --strict | tail -1
PASS          # paper.pdf is outside the frozen scope; the freeze does not depend on it
```

## References

- Springer Nature self-archiving policy (accepted-manuscript terms and embargoes).
- `README.md:23` — the contradictory sentence.
- `docs/spec/CURRENT_STATE_AUDIT.md` §5, finding F14.
