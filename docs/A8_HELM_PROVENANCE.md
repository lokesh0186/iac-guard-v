# Historical a8 Helm artifact qualification

Audit date: 2026-10-20. Report: [issue #42](https://github.com/lokesh0186/iac-guard-v/issues/42)
by Maxym Vlasov. This is a repository/research provenance correction; it does not
change the installed IaC-Guard-V 1.0.1 package or its Helm support contract.

## Verified identities

The historical file `a8-coverage-corpus/tools/helm-v4.2.4-darwin-arm64` was added in
commit `aa82d1879786986a5e62dad55fa0fea8b8bbbcea`. It is **not byte-identical to the
official Helm release binary**. An independent download from Helm's distribution
source confirmed the reporter's checksums:

| Artifact | SHA-256 |
| --- | --- |
| [Official Darwin arm64 archive](https://get.helm.sh/helm-v4.2.4-darwin-arm64.tar.gz) | `d747eb4e28bd2727173d15b759fa0a17822291ec09db7ced3d55af290a3661a2` |
| Official archive member `darwin-arm64/helm` | `66f6b8881392bfa15c6c1dceef980426a28709c8122d5dc8a7a29697cad7334c` |
| Historical corpus executable | `ebf04b3606784d48568cf386483ac2b81fc747ed77859da4ba4f77df4c5e81d3` |

The archive hash matches Helm's [published checksum](https://get.helm.sh/helm-v4.2.4-darwin-arm64.tar.gz.sha256sum).
Both executables are 61,803,778 bytes. Static comparison, without executing either
binary, found 96 differing bytes (offsets below are one-based):

- 14 bytes in `LC_UUID`, within offsets 2145–2160;
- 18 bytes in the first Go build-ID component, within offsets 4113–4132;
- 64 bytes in the code-signature hashes for pages 0 and 1, offsets 61324675–61324738.

All other file bytes and the remaining 14,970 code-page hashes match. Both embedded
ad hoc, linker-signed CodeDirectories validate against their file pages, and macOS
`codesign --verify` succeeds. An ad hoc signature does not authenticate the publisher.
The `__TEXT,__text` section differs only at the embedded Go build ID; the comparison
does not establish formal semantic equivalence.

| Metadata | Official | Historical corpus |
| --- | --- | --- |
| Mach-O UUID | `4796B7C7-6B97-3146-F66F-F6E14DE1BA8D` | `15EFB715-1396-3166-DAAA-193A1EBB4127` |
| First Go build-ID component | `xY8qBdOgEjgLWoXJdpun` | `0SlqhV2OCEhoFcSudPcT` |

The other three Go build-ID components match. `go version -m` reports identical
module, dependency, and build settings after removing the displayed filename:
Go 1.26.5, `CGO_ENABLED=0`, `GOOS=darwin`, `GOARCH=arm64`, `GOARM64=v8.0`,
`-trimpath=true`, and Helm revision `3900f434fd3ef2b84065dc04508df48f288dba00`.
These observations are consistent with a rebuild/relink metadata difference.
They establish neither an exact build origin nor a tampering conclusion.

## Provenance status: PROVENANCE_PARTIAL

Git history establishes when these exact bytes entered the repository. The a8
release record and manifests preserve their identity, but record no upstream
acquisition checksum or build/copy command. The manifest generator hashes the
committed executable; the replay driver checks that recorded identity before use.
That is a historical content-identity check, not independent upstream authentication.

The available local Homebrew `helm/4.2.4/bin/helm` is byte-identical to the corpus
file. Its installation receipt identifies `homebrew/core`, version 4.2.4, arm64,
and `poured_from_bottle=true`; its saved formula invokes `make build` at the same
Helm revision. This is corroborating local evidence, not proof of the original
copy chain or of a particular upstream bottle's bytes. The reviewed Git history,
corpus-generation scripts, release/developer records, available shell history,
and retained local agent logs did not establish that chain. The historical file
must therefore not be described as the official Helm distribution binary.

## Preservation and future acquisition

The old binary, corpus manifests, replay driver, result files, historical release
records, and published tags remain unchanged. Historical replay continues to refer
to the exact recorded artifact and carries this provenance qualification. No
historical experiment has been rerun or reclassified by this audit. The wheel and
sdist contain neither this executable nor the research corpus.

For future experiments or a new corpus revision, acquire an official artifact into
a new directory outside the sealed corpus. Verify the upstream-published archive
checksum and the pinned reference hash before using its binary. For Darwin arm64:

```bash
mkdir helm-4.2.4-upstream-reference && \
cd helm-4.2.4-upstream-reference && \
curl -fL -o helm-v4.2.4-darwin-arm64.tar.gz \
  https://get.helm.sh/helm-v4.2.4-darwin-arm64.tar.gz && \
curl -fL -o helm-v4.2.4-darwin-arm64.tar.gz.sha256sum \
  https://get.helm.sh/helm-v4.2.4-darwin-arm64.tar.gz.sha256sum && \
shasum -a 256 -c helm-v4.2.4-darwin-arm64.tar.gz.sha256sum && \
printf '%s  %s\n' \
  d747eb4e28bd2727173d15b759fa0a17822291ec09db7ced3d55af290a3661a2 \
  helm-v4.2.4-darwin-arm64.tar.gz | shasum -a 256 -c - && \
tar -xOzf helm-v4.2.4-darwin-arm64.tar.gz darwin-arm64/helm > helm && \
printf '%s  %s\n' \
  66f6b8881392bfa15c6c1dceef980426a28709c8122d5dc8a7a29697cad7334c \
  helm | shasum -a 256 -c -
```

Retain the source URLs, published checksum, archive and binary identities, retrieval
date, and toolchain/platform in the new experiment's records. Downloaded references
belong outside Git; no second executable is added to this repository. A different
platform needs its own official archive/checksum pair. Substituting this binary
into the old corpus would change the historical experiment and is not a correction
to its existing manifest.

This qualification was prepared with Codex assistance using static inspection and
checksum comparison. No historical executable was run for this audit.
