# Exact Checkov 3.4.3 qualification record

The proposed 1.0.3 profile is limited to Terraform `CKV_AWS_3` (the scanner's
EBS encryption predicate). It establishes neither provider-valid deployment nor
universal encryption safety. It does not qualify Kubernetes or graph checks.

| Scanner | Property | Authority |
| --- | --- | --- |
| 3.3.0–3.3.30 | Existing property profiles | Unchanged from 1.0.2 |
| 3.4.3 | Terraform CKV_AWS_3 | New narrowly qualified candidate |
| 3.4.3 | Any other check, including CKV_K8S_40 | Unqualified; non-success |
| 3.4.0–3.4.2, unknown future versions | Any Checkov property | Unqualified; non-success |

All five published wheels (3.3.30, 3.4.0, 3.4.1, 3.4.2, 3.4.3) were inspected.
These are all intervening released versions. Independent RECORD validation and
source comparison found identical EBS rule, base value-check implementation,
Terraform parser/runner and JSON report implementation. The intermediate changes
affect version metadata, Helm URL allowlists and Terraform remote-module
credentials/allowlists. All 52 dependency requirement lines are unchanged.
Source equality is supporting evidence, not runtime qualification.

The packaged profile binds these canonical SHA-256 identities:

- Checkov package inventory: `5de942be6207223d7e96dd2aa57288306014c62320e1a9d7094e30bd8ab7bc73`
- Console body: `aa73c383dde0101b77e9e3482673cbaa8864d13f4a3b5ca181748ca274f2258a`
- CKV_AWS_3 definition: `509cfd3f959218f7bd81e510f6398b2eab84b3f49271970e00d28a830de7a1b7`
- Property qualification: `90025e94e957170fd94ae07406ac220efcb63f9b62f0295144bf0c2a6ede1cdd`

Run the narrow public-interface corpus with an installed non-editable product:

```sh
/protected/product/bin/python -IB tools/compatibility/qualify_343.py \
  --ordinary /absolute/ordinary/checkov \
  --controlled /protected/scanner/checkov --output /new/evidence-directory
```

The runner requires doctor readiness, normal/source-only result equality and
exact public verdict/exit controls. It retains every command, stdout, stderr and
canonical report. A failed assertion prevents a PASS record. Qualification also
requires the ordinary product regression, integrity/adversarial tests, unchanged
legacy profiles and clean release validation. CI runs the narrow corpus for
3.4.3 and the original broad corpus for all 31 legacy versions; a floating
canary cannot modify profiles.
