#!/usr/bin/env python3
"""Render the human Phase-E lock review from its canonical JSON graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "tools" / "locks" / "phase-e-locks.json"
DEFAULT_OUTPUT = ROOT / "docs" / "spec" / "PHASE_E_LOCK_REVIEW.md"


def render(payload: dict[str, Any]) -> str:
    """Return deterministic Markdown derived only from *payload*."""

    tools = payload["tools"]
    roles = {
        "kics": "Future scanner",
        "trivy": "Future scanner",
        "opentofu": "Future external validator",
        "terraform": "User-supplied validator; never bundled",
        "kubeconform": "Future external validator",
        "tflint": "Optional non-security lint",
    }
    rows = []
    for name in ("kics", "trivy", "opentofu", "terraform", "kubeconform", "tflint"):
        tool = tools[name]
        release = tool["release"]
        rows.append(
            f"| {name} | {release['tag']} | `{release['commit']}` | "
            f"{tool['compatibility_test']['result']} | {roles[name]} |"
        )

    signatures = []
    for name in sorted(tools):
        signature = tools[name]["archives"]["linux/amd64"]["acquisition"]["signature"]
        signatures.append(
            f"| {name} | {signature['method']} | {signature['status']} | "
            f"{signature['signer_identity'] or 'none'} |"
        )

    containers = []
    for name in sorted(tools):
        container = tools[name]["container"]
        containers.append(
            f"| {name} | `{container['index_digest']}` | "
            f"`{container['architecture_digests']['linux/amd64']}` | "
            f"`{container['architecture_digests']['linux/arm64']}` |"
        )

    schema = tools["kubeconform"]["schema_bundle"]
    checks = tools["trivy"]["checks"]
    runtime_rows = []
    for name in sorted(tools):
        for architecture in payload["architectures"]:
            record = tools[name]["runtime_records"][architecture]
            runtime_rows.append(
                f"| {name} | {architecture} | `{record['execution_digest']}` | "
                f"{record['output_schema_result']} |"
            )

    cache_attestation = payload["protected_cache_attestation"]
    return f"""# Phase E verified dependency lock review

## Scope and decision

E0.3 separates structural, source, and runtime verification and performs only
lock-verification smoke tests.
It does not implement a scanner adapter, validator integration, production
container, composite Action, or control catalog. The canonical graph is
`tools/locks/phase-e-locks.json`; this document is generated from that graph by
`tools/render_phase_e_lock_review.py`.

Lock contract: `{payload['lock_contract']}`

Canonical lock seal: `{payload['lock_payload_sha256']}`

Artifact-cache contract: `{payload['artifact_cache_contract']}`

Protected-cache manifest root: `{cache_attestation['manifest_root']}`

The lock itself records requirements, not self-authored PASS claims:

```text
schema:  {payload['verification_claims']['schema']}
source:  {payload['verification_claims']['source']}
runtime: {payload['verification_claims']['runtime']}
```

| Component | Tag | Full selected commit | Review result | Intended role |
| --- | --- | --- | --- | --- |
{chr(10).join(rows)}

KICS 2.1.21 remains rejected because its source release lacks the selected
official archives and runtime image. Terraform remains
`USER_SUPPLIED_ONLY_NEVER_BUNDLED`; TFLint remains `OPTIONAL_NON_SECURITY`.

## Reproducible acquisition and signature evidence

Every Linux archive has a version-pinned HTTPS URL, retrieval date, archive
SHA-256, cached checksum-manifest URL and SHA-256, and structured signature
evidence. A status of `AVAILABLE_NOT_VERIFIED` does not claim signer-policy
verification. `UNAVAILABLE` records the upstream absence explicitly.

| Component | Method | Status | Signer/key identity |
| --- | --- | --- | --- |
{chr(10).join(signatures)}

KICS, OpenTofu, and Terraform checksum signatures were reproduced with GnuPG
against the cached upstream keys. Trivy and TFLint Sigstore material was cached
but its signer policy was not verified. kubeconform publishes checksums without
a detached archive signature. The source-verification command rehashes the real
archives, verifies checksum membership, reruns the verified OpenPGP proofs, and
checks licence and output-fixture bytes.

## Container architecture binding

Execution references are stored directly as `repository@sha256:digest`; no
execution consumer constructs a reference from a floating tag. Each recorded
amd64 and arm64 child was found in the cached multi-platform index.

| Component | Index digest | linux/amd64 child | linux/arm64 child |
| --- | --- | --- | --- |
{chr(10).join(containers)}

The prospective Debian base is also bound by its index and both platform
children. Selection remains research evidence, not authorization to build the
production hardened container.

## kubeconform offline schema bundle

The schema source is `{schema['repository']}` at commit `{schema['commit']}`.
E0.1 selects Kubernetes {', '.join(schema['supported_kubernetes_versions'])}
standalone schemas. The non-strict tree contains
{schema['non_strict_tree']['file_count']} files with manifest root
`{schema['non_strict_tree']['manifest_root']}`; the strict tree contains
{schema['strict_tree']['file_count']} files with manifest root
`{schema['strict_tree']['manifest_root']}`. Their combined content digest is
`{schema['content_digest']}`.

The generated schema repository has no root licence file, so the lock records
`NOASSERTION`; redistribution requires a later licence decision. Network schema
fallback is forbidden. CRDs require a separately protected local schema lock or
produce unsupported evidence.

## Trivy checks offline proof

Trivy's binary and checks are distinct identities. The selected external checks
manifest is `{checks['external_manifest_digest']}` and its policy layer is
`{checks['external_layer_digest']}`. The cached offline smoke used Trivy 0.73.0,
`--skip-check-update`, Docker network mode `none`, and the exact cache metadata.
It parsed schema version 2 with `fallback_used=false`. Any external/embedded
switch, missing bundle, moving tag, cache mismatch, or fallback changes the
execution identity and is non-PASS.

## Runtime-smoke scope

All six selected images executed their version command for both linux/amd64 and
linux/arm64 with Docker networking disabled, a read-only root, tmpfs `/tmp`, and
no host mounts. The source/runtime verifier re-executes those exact digest-pinned
commands. This proves only the recorded platform child starts and emits the
recorded version bytes; it does not authorize an adapter or establish its output
contract. Trivy alone also executed an output-producing offline scan on both
architectures with the exact external checks cache and `fallback_used=false`.

| Component | Architecture | Execution digest | Scope |
| --- | --- | --- | --- |
{chr(10).join(runtime_rows)}

## Validation commands

```text
python tools/validate_phase_e_locks.py
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: NOT_RUN
PHASE_E_LOCK_RUNTIME: NOT_RUN

python tools/validate_phase_e_locks.py --verify-cached-artifacts \\
  --artifact-cache <protected-cache>
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)
PHASE_E_LOCK_RUNTIME: NOT_RUN

python tools/validate_phase_e_locks.py --verify-runtime \\
  --artifact-cache <protected-cache>
PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)
PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)
PHASE_E_LOCK_RUNTIME: PASS (both architectures and Trivy offline checks)
```

Source mode consumes real cached bytes and verifies the signed complete lstat-based
cache inventory before interpreting individual records. Symlinks and non-regular
entries are forbidden, and the inventory is checked before and after every runtime
process. It verifies tag relations, archives,
checksum/signature evidence, OCI indexes and architecture children, licence and
fixture bytes, both schema trees, and the Trivy external checks layer/cache.
Runtime mode re-executes both platform version smokes and both Trivy offline
checks. Trivy's normalized canonical output plus raw stdout/stderr are compared to
the lock, and the current cache and diagnostic evidence proves the external checks
manifest with fallback disabled. Structural validation alone is never called source
or runtime proof.

NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED

NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V

MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render(json.loads(args.lock.read_text(encoding="utf-8")))
    if args.check:
        if args.output.read_text(encoding="utf-8") != rendered:
            print("PHASE_E_LOCK_REVIEW: FAIL: Markdown differs from canonical JSON")
            return 1
        print("PHASE_E_LOCK_REVIEW: PASS")
        return 0
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
