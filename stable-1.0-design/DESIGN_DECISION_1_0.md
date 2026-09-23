# IaC-Guard-V 1.0 design decision

## Current Beta1 gaps

1. The long-term support contract is not yet approved or encoded as release
   gates.
2. The public contract and contract-report schemas still identify as v1alpha1;
   the stable-v1 bridge and exact backward reader have not been implemented.
3. The public API snapshot exists but is not yet the full executable 1.x CLI,
   schema, Python, and behavior compatibility suite.
4. The complete external compatibility replay has not been run. This is now a
   hard blocker because public integrations and evidence records must not break.
5. Per-property fixture traceability must be audited for every positive,
   negative, ambiguous, incomplete, and adversarial class.
6. Scanner authority needs one concise public and executable contract.
7. The release workflow remains Beta1-specific and lacks the final 1.0 SBOM,
   provenance-attestation, repeat-build, and publication evidence path.
8. Stable documentation, migration guidance, and non-implementer usability
   evidence are incomplete.
9. The old product specification assumes a bespoke GitHub Action that has not
   been released. The 1.0 plan replaces that requirement with a supported
   pip-based workflow example unless real demand justifies an Action.

## Proposed 1.0 scope

- the existing 18 native V1 properties only;
- rendered Kubernetes, deterministic local Helm, bounded local Kustomize,
  source-local Terraform, and bounded OpenTofu materialization;
- exact fail-closed native and contract results;
- Checkov authoritative only on reviewed paths;
- Trivy and KICS advisory by default;
- existing Beta1 CLI, Python, schema, report, provenance, and exit-code surface;
- Python 3.10-3.13;
- stable compatibility, security, support, and supply-chain commitments;
- no Marketplace Action, hostile-input container, Python 3.14, or new native
  property family unless separately completed before freeze.

## Breaking changes

None are permitted for existing Beta1 consumers. A stable v1 contract may be
added, but v1alpha1 remains accepted and behaviorally compatible throughout
1.x. Cross-version implementation/product digests will change and must be
documented; semantic results, consumer-visible structure, and exit behavior may
not break.

## External compatibility

The design protects current work by making all public IaC-Guard-V-dependent
issues and PRs an executable release gate, including open, merged, closed, and
declined proposals. Today this is a design promise, not completed proof. The
aggregate status is `REPLAY_NOT_YET_EXECUTED`.

## Versioning decision

`IS_1_0_SEMANTICALLY_JUSTIFIED: NO, NOT YET`

The proposed bounded scope is appropriate for a future 1.0, and the existing
Beta1 core, test volume, deterministic semantics, schemas, and release record
make that goal technically credible. A stable version is not justified today
because the compatibility replay, stable schema bridge, release-supply-chain
gates, documentation, and release-candidate validation remain incomplete.

This is not a recommendation to publish another Beta merely for optics. It is a
design-ready hardening program. When every blocker is closed without weakening
the evidence model, 1.0 will be semantically justified.

## Prometheus feedback incorporated

Prometheus Community helm-charts #7308 establishes two independent adoption
barriers: product maturity and project-specific need. The 1.0 program addresses
the former through a support contract, compatibility, documentation, security,
and supply-chain proof. It does not pretend to solve the latter. Future direct
integration work still requires a present project-owned problem with enough
value to justify the dependency.

## Final disposition

`IAC_GUARD_V_1_0_NOT_YET_JUSTIFIED`
