# ADR-0014 — Publication links and the current-tip paper

- Status: **Accepted**
- Date: 2026-08-20
- Supersedes: ADR-0011's interim `KEEP_UNCHANGED_PENDING_RIGHTS_CONFIRMATION`

## Context

The Checkov-focused software alpha is ready for public review while the submitted arXiv
manuscript remains under moderation. The repository's existing public history contains an
author-produced camera-ready `paper.pdf`; ADR-0011 records the history, publication-rights
questions, and the fact that an ordinary deletion cannot undistribute historical objects.
The PDF is outside the frozen 4,842-file research manifest and outside package artifacts.

The software release does not technically or scientifically depend on a public arXiv
identifier. Publishing a fake identifier or a broken placeholder link would be misleading,
while waiting indefinitely would delay public testing and adoption of an otherwise reviewed
alpha.

## Decision

1. Remove `paper.pdf` from the current repository tip in an ordinary commit.
2. Do not rewrite Git history as part of the alpha release.
3. Do not publish a placeholder arXiv identifier or URL. State that the submission is
   pending until a public abstract record exists.
4. Do not make arXiv moderation or Springer production a blocker for the software alpha.
5. When the arXiv record becomes public, add its abstract URL in a documentation-only
   update.
6. When Springer publishes the Version of Record, use its DOI and publisher page as the
   primary scholarly citation. An available arXiv preprint may remain as a separate
   accessible-manuscript link.
7. Do not check in or redistribute the Springer PDF unless its licence expressly permits
   that distribution.
8. Keep `qrs-2026-replication-v1` local-only while the historical-distribution question
   remains separately unresolved.

## Consequences

- The current product tip and release artifacts do not contain the paper PDF.
- Prior Git objects remain reachable wherever the earlier history already exists. This ADR
  makes no claim that deletion erases those bytes.
- Frozen research reproduction remains unchanged because the PDF was never in the byte
  manifest.
- The alpha may proceed through branch review, public CI, external smoke testing, and
  owner-authorized release without inventing publication metadata.
- The eventual Springer DOI is preferred for formal citation because it identifies the
  publisher-maintained Version of Record. Linking to that record is distinct from hosting
  the publisher's PDF.

## Follow-up

- Add the real arXiv abstract URL when moderation completes.
- Add the Springer DOI and publisher page when available.
- Obtain separate legal/owner direction before any history rewrite, force push, freeze-tag
  publication, or redistribution of a publisher-produced PDF.
