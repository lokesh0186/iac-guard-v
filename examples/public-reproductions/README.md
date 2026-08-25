# Public reproduction packets

Public reproduction packets bind a third-party change to a specific released verifier
and an immutable evidence commit. Existing packets retain their original version-bound
metadata and must not be rewritten after external review.

Every future packet README must include a compact verifier identity block:

```text
Verifier:
IaC-Guard-V <version>
PyPI: iac-guard-v==<version>
Software DOI: <Zenodo version DOI>
```

Use the Version DOI associated with the exact IaC-Guard-V release that produced the
evidence. The Concept DOI identifies the evolving project and is not a substitute for
version-specific provenance.

Packets must also retain exact third-party base and head identities, supported target
scope, scanner identity, reproduction steps, report hashes, and an explicit statement
that target-scoped evidence is not whole-change verification.
