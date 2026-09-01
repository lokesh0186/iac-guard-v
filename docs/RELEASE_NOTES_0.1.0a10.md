# IaC-Guard-V 0.1.0a10

0.1.0a10 adds fail-closed verification of declared infrastructure intent contracts
over the protected deterministic semantic core released in a9.

Highlights:

- one strict project convention: `.iac-guard-v/contracts.yaml`;
- verifier-derived project, user, research, and suggested-contract provenance;
- typed protected activation evidence, including Helm effective-value provenance;
- exact include/exclude subject resolution and non-vacuous cardinality;
- deterministic compilation to immutable a9 native property IDs and versions;
- witness-first aggregation and authoritative JSON contract reports;
- `contract lint`, `contract plan`, `verify --contract`, and contract-aware `explain`;
- explicit responsibility boundaries and typed historical reproducibility reasons;
- reviewed real-world regressions without project-specific product code.

The native property registry remains the 17-property a9 registry. Checkov 3.3.0
compatibility and reviewed authority are preserved. KICS and Trivy remain advisory;
there is no scanner voting or absence-as-PASS inference.

This release does not infer project intent, call a contract violation a project defect,
claim runtime Kubernetes/network/cloud behavior, evaluate arbitrary custom resources,
perform general Terraform evaluation, or replace IaC scanners. Unsupported or ambiguous
semantics remain fail closed.
