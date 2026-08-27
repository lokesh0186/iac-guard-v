# Testing IaC-Guard-V

Reusable environments optimize developer feedback. GitHub CI and clean release
validation remain the authoritative proof boundaries.

## Workflow decision table

| Moment | Profile | Meaning |
| --- | --- | --- |
| While editing | `focused` | Explicit tests selected by the contributor |
| Coherent local change | `dev` | Complete non-integration suite on Python 3.12 |
| Cross-version concern | `matrix` | Complete suite on 3.10, 3.11, 3.12, and 3.13 |
| Before a PR | `pr` | Matrix, coverage, Checkov, QRS, packaging, and golden workflow |
| Owner-authorized release | `release` | Fresh non-reused environment and clean package proof |

Do not repeatedly run four full suites after every edit. Public GitHub Actions still
creates clean environments and validates the pull request independently.

## One-time setup

Install all four deliberate CPython interpreters. Nox never downloads Python. Confirm
the machine state:

```bash
for p in python3.10 python3.11 python3.12 python3.13; do
  command -v "$p" && "$p" -c 'import platform; print(platform.python_version(), platform.machine())'
done
```

Install the reviewed orchestrator in a small dedicated tooling environment:

```bash
python3.12 -m venv --copies .venv-nox
python3.12 -m pip --python .venv-nox/bin/python install \
  --disable-pip-version-check --no-compile \
  -r tools/testing/requirements-nox.txt
.venv-nox/bin/nox --version
```

The required Nox version is `2026.8.17`, the stable PyPI release reviewed for this
harness. Nox uses the standard-library `venv` backend, copied interpreters, persistent
`.nox/tests-3-*` environments, and `download_python=never`.

## Daily development

```bash
.venv-nox/bin/nox -s focused -- tests/unit/test_helm_materialization_a4.py -k tpl
.venv-nox/bin/nox -s dev
.venv-nox/bin/nox -s smoke
```

`focused` accepts ordinary pytest paths, nodes, `-k`, `--lf`, and `--ff`. The caller
selects tests; the product does not generate a test-selection policy. Harness-critical
installation and integrity options cannot be passed through. `release` accepts no
selection arguments.

The `dev` profile uses exactly two pytest-xdist workers for the non-research suite and
then runs `tests/research` serially. Repeated measurements showed a stable 40 percent
improvement with two workers. Matrix, coverage, Checkov, QRS, golden, and release proof
do not use xdist, and automatic CPU-count worker selection is intentionally disabled.

## Before a pull request

```bash
.venv-nox/bin/nox -s pr
```

The matrix runs across separate, integrity-checked environments with four concurrent
Python sessions by default. Deliberate overrides use `IACGV_MATRIX_JOBS=1..4`.
Missing interpreters fail the matrix rather than silently reducing it. The Checkov
profile reuses `.testenvs/scanners/checkov-3.3.0-py312` only after exact fingerprint,
`pip check`, version, executable, dependency closure, RECORD, and bytecode checks pass.

Individual pre-PR gates are available:

```bash
.venv-nox/bin/nox -s matrix
.venv-nox/bin/nox -s coverage
.venv-nox/bin/nox -s checkov
.venv-nox/bin/nox -s qrs
.venv-nox/bin/nox -s package
.venv-nox/bin/nox -s golden
```

Substantial profiles write ignored diagnostics under `.test-results/<run-id>/`.
Summaries bind the source commit/dirty state, timestamps, architecture, environment
fingerprints, command identities, aggregated child test counts, aggregate coverage
results, and QRS status when applicable. They contain no credentials, source-file
coverage paths, or temporary absolute paths and are not public research results.

## Environment identity and invalidation

Each managed environment contains `.iacgv-test-env.json`. Its stable fingerprint binds:

- exact CPython implementation/version, executable path identity/hash, and architecture;
- platform, `pyproject.toml`, and reviewed harness/scanner dependency inputs;
- Nox version, standard-library `venv`, copied interpreter, pip installer;
- editable `--no-compile` installation contract and bytecode prohibition;
- Checkov 3.3.0 and its installed scanner/dependency identities where applicable.

Timestamps are informational and are excluded from the fingerprint. A dependency,
Python, architecture, or install-contract change produces `TEST_ENVIRONMENT_STALE`.
Compatibility environments then refuse use with one exact remediation command. A stale
or corrupt repository-owned scanner environment is safely rebuilt under an exclusive
lock before integration tests.

Before a large suite, the harness verifies metadata, Python identity, editable project
presence, prohibited product bytecode, and `pip check`. Checkov additionally passes the
product's own `doctor`/RECORD integrity boundary. Failure happens before thousands of
tests execute.

## Release

Run only for an owner-authorized release candidate:

```bash
.venv-nox/bin/nox -s release
```

The session declares `reuse_venv=False` and writes a one-run freshness marker. If Nox
command-line state causes an existing release environment to survive, the marker causes
`RELEASE_REUSE_FORBIDDEN`. The profile does not accept pytest passthrough. It runs the
full suite, unchanged coverage gates, QRS, package contents, and the installed-wheel
golden workflow from disposable environments. Persistent state is never sole release
evidence; the reviewed exact-artifact owner gate remains required.

## Cleaning and fresh diagnostic mode

```bash
.venv-nox/bin/nox -s clean_test_envs
```

This removes only `.nox`, `.testenvs`, `.test-results`, and repository-local coverage
files after guarded path resolution. It refuses `/`, `..`, the repository, the user
home, symlinks, and arbitrary paths. It never removes the global pip download cache,
system Python, source, `.git`, Docker data, or the Nox tooling environment.

To force a complete reusable-environment rebuild, run `clean_test_envs` and then the
desired profile. That is the supported fresh diagnostic reference; no hidden cache is
required.

## Test-selection escalation

Escalate earlier than normal when changing `pyproject.toml`, packaging, environment
integrity, process execution, the engine, report schemas, scanner adapters, Helm,
graph evidence, or policy code. Changes to `noxfile.py`, `tools/testing/`, or CI require
harness self-tests and gate-equivalence review. Stop if any frozen research path changes.

## Troubleshooting

- `PYTHON_INTERPRETER_MISSING`: install the named CPython version deliberately, then
  rerun `doctor`. Nox will not download it.
- `TEST_ENVIRONMENT_STALE`: run `clean_test_envs`, then rerun the profile.
- `TEST_ENVIRONMENT_INTEGRITY_FAILED`: preserve the message, clean managed caches, and
  rebuild. Do not delete third-party files selectively.
- `CHECKOV_ENVIRONMENT_INTEGRITY_FAILED`: the scanner cache is rebuilt once. A repeated
  failure is a real blocker, not a skipped test.
- Wrong Nox version: recreate `.venv-nox` from `requirements-nox.txt`.
- Architecture mismatch: ensure all four interpreters report the host architecture and
  are not running under Rosetta.
- Disk cleanup: inspect `.nox`, `.testenvs`, and `.test-results`, then use the guarded
  clean profile. The pip cache is retained intentionally.
- Docker unavailable: no daily or PR profile requires Docker.
- Release clean-room failure: stop. Do not replace it with a reusable profile.

Run the harness diagnostic with:

```bash
.venv-nox/bin/nox -s doctor
```

## Automated-contributor rhythm

1. Run focused tests while editing.
2. Run `dev` when the logical implementation is complete.
3. Run only relevant coverage/integration gates while debugging.
4. Run `pr` once before opening or updating the PR.
5. Allow clean GitHub CI to validate independently.
6. Run `release` only for an owner-authorized release candidate.
