# Scanner authority in IaC-Guard-V 1.0

The requested predicate and protected artifact universe are defined independently of
a scanner. A scanner supplies evidence. It does not automatically define truth,
scope, or success.

## Checkov

Checkov 3.3.0 is authoritative only on reviewed property and target paths where
IaC-Guard-V proves exact tool, dependency, policy, invocation, and protected-input
identity; complete execution and target coverage; affirmative per-target pass
semantics; exact addressability; and valid suppression, parse, scope, version,
integrity, and partial-output evidence.

The frozen Checkov 3.2.517 research environment remains historical replay evidence,
not the current product-authoritative runtime.

## Advisory scanners and bounded validators

Trivy 0.73.0 and KICS 2.1.20 are advisory by default. Their output may document a
finding, omission, or discrepancy but cannot create an authoritative `SATISFIED`
result. Kubeconform, TFLint, `terraform validate`, and `tofu validate` establish only
their assigned bounded facts. Provider-requiring validation is operator-controlled and
never triggers automatic network access, `init`, plan, or apply.

## Rules that cannot be relaxed

1. Empty, absent, or partial output is never a pass.
2. Scanners are never majority-voted.
3. Related but non-equivalent predicates are not normalized into one property.
4. An adapter cannot shrink, expand, or redefine the protected universe.
5. Candidate-controlled policy, suppression, or result data cannot become protected
   truth.
6. A scanner exit code cannot become success without complete typed evidence.

A scanner can gain authority for one property and target path only through a separate
reviewed evidence contract with exact identities, oracle semantics, complete positive,
negative, ambiguous, and adversarial fixtures, protected-universe proof, and a
versioned compatibility commitment. That review does not promote the scanner generally.
