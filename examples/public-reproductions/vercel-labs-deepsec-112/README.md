# DeepSec PR #112: privileged-workload matcher boundaries

This directory preserves independent, target-scoped evidence for the privileged-
container portion of [Vercel Labs DeepSec PR #112](https://github.com/vercel-labs/deepsec/pull/112).

## Evidence identity

- Third-party PR: `vercel-labs/deepsec#112`
- PR base commit: `97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04`
- Verified PR head: `783195c4b2a1da94c23f5cacf55114a190c2032f`
- IaC-Guard-V: public PyPI `0.1.0a1`
- Checkov: protected `3.3.0` environment
- Evaluation mode: native `reduced-isolation`; trusted local input only
- Evaluation date: `2026-08-22` UTC

## Scope

The primary claim is narrow: the PR-head matcher detects block-form
`securityContext.privileged: true`, but does not detect the semantically equivalent
YAML flow mapping:

```yaml
securityContext: {privileged: true}
```

IaC-Guard-V's protected `kubernetes_no_privileged_containers_v1` oracle evaluates the
exact `v1/Pod/default/inline-demo` resource as `FAIL / ASSERTION_VIOLATED`.

Two additional boundaries are recorded for maintainer consideration:

- a top-level Kubernetes `List` containing a privileged Pod;
- Windows `windowsOptions.hostProcess: true`.

**This is not a whole-PR verification.** It does not certify the complete matcher,
repository, test suite, or every Kubernetes privilege control.

## Results

| Fixture | DeepSec PR matcher | IaC-Guard-V protected oracle |
| --- | --- | --- |
| block `privileged: true` | `privileged container` | not needed as the control case |
| inline `{privileged: true}` | no match | `FAIL / ASSERTION_VIOLATED` |
| `kind: List` with privileged Pod | no match | `FAIL / ASSERTION_VIOLATED` |
| Windows HostProcess Pod | no match | `FAIL / ASSERTION_VIOLATED` |

Kubernetes Pod Security Standards restrict privileged containers and Windows
HostProcess under the Baseline profile. Undefined, null, and false are permitted;
true violates the respective field control:

<https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline>

The machine-readable outputs are [matcher-result.json](matcher-result.json) and
[oracle-result.json](oracle-result.json). The fixture hashes in those files bind each
result to the exact YAML bytes in this directory. `oracle-result.json` is explicitly a
sanitized semantic projection of protected oracle output. It retains the policy,
target, status, reason, observations, controls, and authoritative reference while
omitting run-bound snapshot and implementation hashes.

## Reproduce the DeepSec result

```bash
git clone https://github.com/vercel-labs/deepsec.git deepsec
git -C deepsec checkout 783195c4b2a1da94c23f5cacf55114a190c2032f

evidence_dir="$PWD"
cd deepsec
corepack pnpm install --frozen-lockfile
corepack pnpm exec tsx "$evidence_dir/deepsec_probe.ts" "$PWD"
```

Run those commands from this evidence directory. The block fixture produces one
`privileged container` match; the three boundary fixtures produce no match at the
pinned PR head.

## Reproduce the IaC-Guard-V oracle result

Install `iac-guard-v==0.1.0a1` and Checkov `3.3.0` in the copied-file,
bytecode-free environments described in the project's
[advanced installation guide](../../../docs/ADVANCED_INSTALLATION.md). Then run from
this evidence directory:

```bash
export PYTHONDONTWRITEBYTECODE=1

"/path/to/iac-guard-env/bin/python" oracle_probe.py \
  --checkov-executable "/path/to/checkov-3.3.0-env/bin/checkov"
```

The script begins with untrusted scan requests, seals the complete Kubernetes
snapshot through IaC-Guard-V's protected scan-plan path, and invokes only oracle IDs
from the packaged closed registry. It cannot inject a caller-authored oracle result.
The script prints the same sanitized semantic projection committed here.

Reduced isolation is not a hardened sandbox and does not support hostile input. These
fixtures are fixed, reviewed public inputs.
