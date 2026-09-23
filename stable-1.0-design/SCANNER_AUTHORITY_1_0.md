# Scanner authority in IaC-Guard-V 1.0

## Governing rule

The protected universe and requested predicate are defined independently of a
scanner. A scanner supplies evidence. It does not automatically define truth,
scope, or success.

## Checkov

Checkov 3.3.0 is authoritative only on exact reviewed property/target paths for
which IaC-Guard-V proves all of the following:

1. exact executable, dependency, policy, invocation, and protected-input identity;
2. complete execution and complete coverage of the protected target;
3. affirmative per-target pass semantics, not merely absence of a finding;
4. exact addressability and unambiguous predicate identity;
5. suppression, parse, scope, version, integrity, and partial-output checks;
6. a reviewed evidence contract and adversarial equivalence suite.

The frozen research version 3.2.517 may be replayed as historical evidence but is
not the current product-authoritative runtime.

## Trivy and KICS

Trivy 0.73.0 and KICS 2.1.20 are advisory by default. Their outputs can document
findings, omissions, and discrepancies. They cannot create an authoritative
`SATISFIED` result without a new property-specific authority review meeting the
same requirements as Checkov.

## Independent validators

Kubeconform, TFLint, `terraform validate`, and `tofu validate` may establish the
bounded facts assigned to them. They do not inherit authority over security or
relationship properties. Provider-requiring validation is operator-controlled
and never triggers automatic network access, `init`, plan, or apply.

## Prohibited inference

1. Never infer pass from empty or missing output.
2. Never majority-vote scanners.
3. Never normalize related but non-equivalent predicates into one property.
4. Never let an adapter shrink, expand, or redefine the protected universe.
5. Never accept candidate-controlled policy, suppression, or result evidence as
   protected truth.
6. Never turn a scanner exit code into success without complete typed evidence.

## Authority promotion process

A scanner may become authoritative for one new property/target path only through
a separately reviewed evidence contract containing exact versions and digests,
native or independent oracle semantics, complete positive/negative/ambiguous and
adversarial fixtures, protected-universe proofs, and a versioned compatibility
commitment. Promotion for one path does not promote the scanner generally.
