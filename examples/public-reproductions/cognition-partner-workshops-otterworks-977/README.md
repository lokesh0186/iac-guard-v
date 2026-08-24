# Otterworks PR #977: archive-bucket hardening verification

This directory preserves independent IaC-Guard-V evidence for the archive-bucket
hardening portion of [Cognition Partner Workshops `otterworks` PR
#977](https://github.com/Cognition-Partner-Workshops/otterworks/pull/977).

## Evidence identity

- Third-party PR: `Cognition-Partner-Workshops/otterworks#977`
- Verified base commit: `e78e75994afbbfd8453a65de24cbc6d357ae4c53`
- Verified head commit: `fbad5383c50a5e1f3a4e5307b1497f4d5529f5d3`
- Base module Git tree: `46ea7799544e982b80389191edc171dfc06370c8`
- Head module Git tree: `fc3aa2c378979587a74d72f30cdf327e3536f683`
- Module: `infrastructure/terraform/tp-cronbox`
- IaC-Guard-V: public PyPI `0.1.0a3`
- Published wheel SHA-256: `7de633ff85595052c04a9fad2aa156a2e3f77062ba7d118f5a35fb15fd08405b`
- Checkov: protected `3.3.0` environment
- Python: `3.11.6`
- Evaluation mode: native `reduced-isolation`; trusted reviewed input only
- Evaluation date: `2026-08-24` UTC

The pull request was generated or assisted by the Devin AI integration.
IaC-Guard-V independently evaluates the resulting infrastructure code and does
not trust the generator's description or conclusions.

## Scope

This evidence verifies only the archive-bucket hardening and `CKV2_AWS_6`
portion of PR #977. The exact target is `aws_s3_bucket.audit_archive`.

**This is not whole-PR verification.** It does not certify the other code,
resources, behavior, or Checkov findings in the pull request.

The complete `infrastructure/terraform/tp-cronbox` module was materialized from
each Git commit. All six Terraform files were governed:

- scanner evidence-bearing: `audit_archive.tf`, `cron-cleanup.tf`, `main.tf`;
- structural-only: `outputs.tf`, `variables.tf`, `versions.tf`.

The module's `.gitignore`, `README.md`, and Lambda handler were also present in
the exact materialized trees but are not Terraform scanner inputs.

## Result

| Target | Base | Head | IaC-Guard-V outcome |
| --- | --- | --- | --- |
| `CKV2_AWS_6` / `aws_s3_bucket.audit_archive` | failing | passing | `FIXED` |

- Terraform parse gate: `PASS` (`6/6` governed Terraform files)
- Scanner integrity: `PASS`
- Regression gate: `PASS`
- Graph evidence: `PASS / GRAPH_EVIDENCE_COMPLETE`
- Final target-scoped verdict: `VERIFIED`
- Exit code: `0`

At the base commit, graph evidence contains the primary participant
`aws_s3_bucket.audit_archive` and no public-access-block relationship. At the
head commit, the evidence binds both:

- `main.tf` / `aws_s3_bucket.audit_archive`;
- `audit_archive.tf` / `aws_s3_bucket_public_access_block.audit_archive`.

The candidate relationship is a `terraform_reference` edge from the public
access block to the bucket with relation key
`resource.bucket:aws_s3_bucket.audit_archive`.

## Evidence hashes

- Baseline sealed snapshot:
  `68a247c8d4a825bf13b5d883857a9e3df6ff8a0f5add30b802b171aad108e25b`
- Candidate sealed snapshot:
  `e8dc95f1f0dfb48f12edddc7d221d889d42dfb4d79a0f96751557aea4b95cd47`
- Baseline scanner input manifest:
  `f725afbded349c930cf4e27e7a3918a86d216a9e42e4b85df3a7397de2802413`
- Candidate scanner input manifest:
  `256c3dbf83ae15daca7f97f4d8c30ce62df48c60917b664570bf7f649f97b54a`
- Canonical [report.json](report.json):
  `51cc99498b6762461abc14b20f205a2ba2f76ad00d7d87ad6274201b8c96bc19`
- Deterministic [report.md](report.md):
  `2d8bdea4183293cfd7fd74eb0ff5f5a44e32d7dee4e282065d63995464d3fbcb`

`report.json` is the canonical validated `report-v1` evidence. `report.md` is
its readable projection.

## Reproduce

Run [reproduce.sh](reproduce.sh) from an empty working directory with Git,
Python 3.11, and a host `pip` supporting `--python`:

```bash
curl -LO https://raw.githubusercontent.com/lokesh0186/iac-guard-v/REPLACE_WITH_IMMUTABLE_COMMIT/examples/public-reproductions/cognition-partner-workshops-otterworks-977/reproduce.sh
chmod +x reproduce.sh
./reproduce.sh
```

The script downloads IaC-Guard-V `0.1.0a3` from authoritative public PyPI,
verifies the published wheel hash, installs Checkov `3.3.0` in a separate
copied-file environment, materializes the exact module trees from the two Git
commits, checks their Git tree identities, runs doctor, and writes the canonical
report to `otterworks-977-report.json`.

Reduced isolation is not a hardened sandbox and does not support hostile input.
This reproduction uses fixed, reviewed public source commits.
