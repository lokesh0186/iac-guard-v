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

## 1.0.2 compatibility candidate

The local maintenance candidate adds an explicit property/version profile for
Checkov 3.3.1–3.3.30; it does not declare arbitrary versions or checks authoritative.
The existing 3.3.0 contract remains intact. CKV_K8S_40 is excluded on 3.3.8 and
newer because its policy semantics changed. Unknown versions and unqualified
properties fail closed; native properties remain independent.

See [the compatibility contract](docs/CHECKOV_COMPATIBILITY.md) and
[the qualification surface](CHECKOV_AUTHORITY_SURFACE.md). The opt-in shared
installation path binds a trusted build snapshot and excludes derived caches
from execution; it does not relax the existing bytecode-free installation gate.

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
