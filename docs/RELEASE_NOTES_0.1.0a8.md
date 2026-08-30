# IaC-Guard-V 0.1.0a8 release notes

IaC-Guard-V 0.1.0a8 extends the technical alpha without broadening its trust claims.
Checkov 3.3.0 remains the authoritative scanner path. KICS and Trivy remain advisory
and future adapter work; neither can establish a protected target `PASS` or change the
final verdict.

## Added in alpha 8

- A scanner-neutral verifier/evidence architecture that assigns protected artifact,
  target, property-observation, and evidence ownership independently of adapters.
- Bounded Helm dependency aliases and nested local dependency closure, including
  archive-backed and directory-backed logical instances.
- Helm-compatible dependency-version binding to exact protected lock, chart, physical,
  and logical identities.
- Equivalent duplicate named-template handling based on output-sensitive structural
  equivalence with all-member source/span provenance.
- Bounded namespace-provenance improvements for the reviewed helper grammar and exact
  Release/Values contexts.
- Bounded deterministic local Kustomize v5.7.1 materialization with a complete
  transitive input inventory, offline fresh double builds, conservative full-closure
  provenance, and exact rendered/scanner-universe identity.
- Stronger permanent real-world coverage and replay preservation through the
  content-bound 55-surface corpus. Its frozen classification remains 9 supported,
  5 partially reachable, and 41 fail closed.

## Deliberate boundaries

- General Helm interpretation is not supported.
- Remote Helm dependency and Kustomize resource resolution are not supported.
- Helm `lookup` and other live cluster state remain fail closed.
- Unsupported dynamic Helm or Kustomize semantics remain fail closed.
- Helm inflation through Kustomize, plugins/exec, unknown Kustomize control keys,
  path or symlink escapes, and nondeterministic fresh builds remain fail closed.
- Native execution remains reduced isolation for operator-controlled input only; the
  hostile-input container and GitHub Action are not released.

These constraints are part of the release contract, not temporary success-path
omissions. Alpha 8 does not claim broad Helm or Kustomize support.

## Public release identities

- GitHub prerelease: [`v0.1.0-alpha.8`](https://github.com/lokesh0186/iac-guard-v/releases/tag/v0.1.0-alpha.8)
- PyPI: [`iac-guard-v 0.1.0a8`](https://pypi.org/project/iac-guard-v/0.1.0a8/)
- Version DOI: [`10.5281/zenodo.22167878`](https://doi.org/10.5281/zenodo.22167878)
- Concept DOI: [`10.5281/zenodo.22088272`](https://doi.org/10.5281/zenodo.22088272)
