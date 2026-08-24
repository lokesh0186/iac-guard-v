# Reproduction

Use separate protected environments containing public `iac-guard-v==0.1.0a3`
and Checkov `3.3.0`, following the published IaC-Guard-V advanced-installation
instructions.

Materialize the exact public revisions without executing project code:

```bash
git clone --filter=blob:none https://github.com/bsv-blockchain/teranode.git teranode
cd teranode
git fetch origin \
  e01f7bca875225b14142c8068d799ec1d722c395 \
  4b25d8289645324b7eb556782f46e5c7b1d26b45
git worktree add --detach ../teranode-base \
  e01f7bca875225b14142c8068d799ec1d722c395
git worktree add --detach ../teranode-head \
  4b25d8289645324b7eb556782f46e5c7b1d26b45
```

Run the exact target-scoped verification from the parent directory, adjusting
only the two executable paths:

```bash
/path/to/iac-guard verify \
  --before ./teranode-base/deploy/kubernetes/kafka \
  --after ./teranode-head/deploy/kubernetes/kafka \
  --target 'CKV2_K8S_6=apps/v1/Deployment/default/kafka-shared' \
  --framework kubernetes \
  --local-trusted \
  --checkov-executable /path/to/checkov \
  --format console \
  --output ./report.json
```

Expected result:

```text
IaC-Guard-V: VERIFIED
exit_code: 0
targets:
  CKV2_K8S_6 apps/v1/Deployment/default/kafka-shared: FIXED
scanner integrity: PASS
regressions: none
policy: VERIFIED
```

Validate and render the canonical report:

```bash
/path/to/iac-guard explain report.json \
  --format markdown \
  --output report.md
```
