# Datadog Security Playground PR #172

This packet records target-scoped candidate-property acceptance for
[DataDog/datadog-security-playground#172](https://github.com/DataDog/datadog-security-playground/pull/172).

## Exact revisions and verifier

- Base: `7b08378f7563f62eefd65906a222a0fcf6211342`
- Head: `fa1d0a898a2a03ae164114623026f5dcf7642daa`
- IaC-Guard-V: `0.1.0a5`
- PyPI: `iac-guard-v==0.1.0a5`
- IaC-Guard-V wheel SHA-256: `3986e43aa41917ae7f19716e879f8a8af0b0b2cf60e03f11590b5b0a554f450d`
- Software DOI: [`10.5281/zenodo.22099303`](https://doi.org/10.5281/zenodo.22099303)
- Checkov: `3.3.0`
- Python: `3.13`

## Repository context

Datadog Security Playground is intentionally vulnerable educational infrastructure.
Its application and attack scenarios are designed to exercise security detections in
a controlled environment. Scanner findings must therefore not automatically be
treated as unintended defects.

PR #172 nevertheless makes one explicit infrastructure-boundary claim: the new
ECS-on-EC2 stack uses Systems Manager access, has no SSH key pair, and defines no
inbound security-group rule. That narrow claim is the only property evaluated here.

## Selected candidate property

The PR introduces a new Terraform module, so there is no comparable baseline target.
IaC-Guard-V therefore used `candidate_acceptance`, not repair verification.

| Check | Resource | File | Outcome |
| --- | --- | --- | --- |
| `CKV_AWS_24` | `aws_security_group.instance` | `main.tf` | `SATISFIED` |

IaC-Guard-V returned target-scoped `VERIFIED`. The result means only that Checkov's
no-world-accessible-SSH property is authoritatively satisfied for the selected
security group under the recorded candidate snapshot and scanner contract.

## Scope limits

This evidence does not claim that the intentionally vulnerable playground, Terraform
module, AWS deployment, or PR is secure as a whole. It does not validate runtime AWS
behavior, Systems Manager availability, Datadog Workload Protection, or the safety of
the simulated attack scenarios.

Ten other Checkov failures remain count- and digest-bound in `report.json`. They are
outside this selected claim and are not relabeled as safe or asserted to be defects.
Some may reflect deliberate playground behavior, while others may be ordinary
hardening opportunities; this packet does not decide that question.

## Evidence identities

- Candidate snapshot SHA-256: `7cd7cf84fda08bb0352eedf6cf6c535b7269bee4bf86b33d1a6a5fb37daf5b36`
- `main.tf` SHA-256: `25eccba6971b61447cdfd3e50d5fc314a300d8ed94913bd9b8e26cea0148170c`
- `ecs.tf` SHA-256: `dd38001e115e1727118926a78e12544d515819a36627cc598c6acdee31a1bec1`
- Report JSON SHA-256: `3a2ca024e2a5c4540de5f1ecddd5c4f4421079f6e7e3dc3acb55817d0dc99e5b`
- Report Markdown SHA-256: `06f849e61fe4b811b5bf6e0858887757bdc9f0a8326446237b62c757986184a4`
- Unselected failed-findings digest: `7fcf151dfaffde55c91432c22121f3050fad446fabd2348edf52ee0c33fb6c11`

See [REPRODUCE.md](REPRODUCE.md) for the public-package reproduction.
