# Contributing

Thank you for helping improve IaC-Guard-V. The project values small, reviewable
changes backed by adversarial tests.

## Good contributions

We especially welcome:

- reproducible scanner-compatibility issues;
- positive, negative, and boundary verification fixtures;
- bounded scanner or validator adapters with explicit evidence contracts;
- documentation and onboarding improvements;
- real-world before/after cases with exact file and resource identities.
- concise declared-invariant contracts with explicit intent provenance;
- OpenTofu file-set and source-local reference compatibility fixtures.

If a change would add a new framework, materializer, or public trust surface,
open an issue first so its contract and maintenance scope can be agreed before
implementation.

## Development setup

Use CPython 3.10–3.13. The maintained persistent local test workflow, clean
release boundary, and troubleshooting guidance are documented in
[`docs/TESTING.md`](docs/TESTING.md).

```bash
python3.12 -m venv --copies .venv-nox
python3.12 -m pip --python .venv-nox/bin/python install \
  --no-compile -r tools/testing/requirements-nox.txt
.venv-nox/bin/nox -s smoke
```

Build the public artifacts with:

```bash
python -m pip install build
python -m build
```

## Required boundaries

- Do not edit `benchmark/`, `runs/`, `results/`, `prompts/`, `scanners/`, `scripts/`,
  or `requirements.txt`. Those paths belong to the frozen QRS 2026 artifact.
- Do not run new benchmark inference or invoke a model provider as part of product
  development.
- Do not weaken, skip, delete, or xfail a security regression to make a change pass.
- Treat scanner/oracle agreement as advisory. V7 consensus cannot change the final
  verdict.
- Never add raw scanner evidence, caller callbacks, precomputed policy decisions, or
  trust assertions to a public input surface.
- Do not commit credentials, protected caches, private scanner candidates, or local
  absolute paths.
- KICS and Trivy advisory evidence must never be promoted to target PASS by absence,
  agreement, or voting.

## Changes and tests

Add a failing-before/passing-after test for every security-relevant correction. Run
the `focused` profile first, `dev` after a coherent change, and `pr` once before a
public pull request. Public CI remains a clean, independent check. Release validation
uses the non-reused `release` profile. Changed security modules must retain at least
90% branch coverage.

Public contributions should describe observed behavior and evidence without making
unverified adoption, scanner-defect, or production-readiness claims.
