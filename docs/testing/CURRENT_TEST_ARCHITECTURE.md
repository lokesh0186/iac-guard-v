# Current test architecture before persistent local orchestration

Recorded from public `main` at `0550f91d4adfb2ecf7f9d7298c9b07e8611dc0f6` on
2026-08-26. This inventory describes the behavior that the local harness must preserve.

## Public workflows

`.github/workflows/python-compat.yml` is the independent public pull-request and push
gate. It runs Python 3.10, 3.11, 3.12, and 3.13 on clean Ubuntu workers with
`fail-fast: false`. Every compatibility job creates `/tmp/iacgv-compat` with
`python -m venv --copies` and installs editable `.[compat-test]` with pip
`--no-compile`. It establishes the local-only frozen research tag, imports with
warnings treated as errors, runs the complete non-integration suite, and independently
enforces the D3, D4, D5, D6, D7, and Helm coverage gates at 90 percent.

The same workflow has a clean Python 3.11 job for Checkov 3.3.0. It creates
`/tmp/iacgv-checkov330` with `--copies`, installs the scanner, pytest, and build with
`--no-compile`, removes interpreter-generated scanner bytecode, and runs both the
pinned Checkov integration contract and installed-wheel golden workflow with
`PYTHONDONTWRITEBYTECODE=1`.

`.github/workflows/release.yml` is publication only. It downloads exactly two reviewed
GitHub Release distributions, enforces exact filenames and SHA-256 hashes, and publishes
those bytes through OIDC Trusted Publishing. It does not build or test source.

## Existing test surfaces

| Surface | Current authoritative command or location |
| --- | --- |
| Full compatibility | `pytest tests --ignore=tests/integration -q` on 3.10–3.13 |
| D3 | Three separate 90 percent module gates for fingerprints, matching, and diffing |
| D4 | Adapter, Checkov, graph, and Terraform parser branch coverage at 90 percent |
| D5 | Engine branch coverage at 90 percent |
| D6 | Policy branch coverage at 90 percent |
| D7 | Acceptance/API/CLI/config/report branch coverage at 90 percent |
| Helm | Helm materializer branch coverage at 90 percent |
| Checkov | `tests/integration/test_checkov_integration.py` with Checkov 3.3.0 |
| Installed wheel | `tests/integration/test_alpha_golden_quickstart.py` |
| Packaging | `tests/packaging/` including distribution and release-workflow contracts |
| QRS | `tests/research/test_qrs_regression.py` plus the frozen annotated tag |
| Public evidence | semantic checks within packaging and public-boundary test modules |

The D3 through Helm coverage selections are closed structured argv definitions in
`tools/testing/gates.py`. Both Nox and the public workflow execute that catalog. The
old and shared commands were mechanically compared for test-node identity, covered
modules, branch setting, threshold, coverage result, and exit status; the proof is in
`docs/testing/CI_GATE_EQUIVALENCE.md`.

## Integrity boundaries already present

The product verifies Checkov wheel RECORD material, rejects scanner bytecode/cache
content, binds scanner executable and policy inventory identities, disables bytecode in
scanner subprocesses, verifies parser distributions, tests clean installed-wheel
behavior, and protects frozen QRS bytes. The local harness adds a cheap pre-suite layer;
it does not replace any of those product or release checks.

## Local inefficiency being addressed

The public clean model is appropriate for CI, but repeating it manually reconstructs
four identical dependency environments and a large Checkov dependency closure after
ordinary source edits. There was no repository-owned environment fingerprint, stale
environment refusal, safe cache cleanup command, persistent scanner environment, or
standard focused/dev/matrix/pr/release profile distinction.
