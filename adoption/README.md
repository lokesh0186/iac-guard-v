# Independent reruns and integrations

These packets let maintainers and researchers run a small check from their own
environment using the [IaC-Guard-V 1.0.0 release](https://github.com/lokesh0186/iac-guard-v/releases/tag/v1.0.0).
They are examples for locally trusted source. They do not change the stable
wheel or claim external adoption on their own.

- [IaCSecBench v2.1.0 one-pair rerun](iacsecbench-v1-rerun/README.md)
- [Trivy #11192 fix-branch capture](trivy-11192/README.md)
- [pre-commit-terraform optional local hook recipe](pre-commit-terraform-v1/README.md)
- [Bring-your-own-repairer patch runner](repairer-eval/README.md)
- [TerraRepair archived-repair adapter](terrarepair-v1/README.md)

## Reporting an independent run

Please share the exact command, operator-controlled source commit, tool
versions, input hashes, raw machine-readable reports, and any setup error.
`FAILED` and `INCONCLUSIVE` are useful results; do not recode them as passes.
If the run caused a repository change, link the issue, commit, PR, test, or CI
job that records that change. The operator should state what they actually
observed and did, for example:

> We ran [packet and version] on [source commit] in our environment. It
> returned [observed result]. We [specific follow-up action], recorded at
> [public link].

This is a factual run record, not a request for praise or endorsement. No
statement is requested before an external operator has completed a run.
