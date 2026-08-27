# CI gate equivalence map

Status: PR A inventory. Public GitHub Actions remains unchanged. This map is the
review input for a separate PR B and is not, by itself, authorization to migrate a
gate.

## Current duplication

`.github/workflows/python-compat.yml` embeds eight coverage invocations as shell
commands in every Python 3.10 through 3.13 job. `tools/testing/gates.py` expresses the
same selections as structured argument lists for the local Nox harness.

| Public workflow gate | Shared definition | Tests | Modules | Branch | Threshold |
| --- | --- | ---: | --- | --- | ---: |
| D3 fingerprints | `d3-fingerprints` | 4 | `iac_guard_v.fingerprints` | no | 90 |
| D3 matching | `d3-matching` | 4 | `iac_guard_v.matching` | no | 90 |
| D3 diffing | `d3-diffing` | 4 | `iac_guard_v.diffing` | no | 90 |
| D4 adapters/parser/graph | `d4-adapters-parser-graph` | 10 | adapters base/checkov, graph evidence, Terraform parser | yes | 90 |
| D5 engine | `d5-engine` | 14 | engine | yes | 90 |
| D6 policy | `d6-policy` | 6 | policy | yes | 90 |
| D7 public boundary | `d7-public-boundary` | 21 | acceptance, API, CLI, config, report | yes | 90 |
| Helm materializer | `helm-materializer` | 4 | Helm | yes | 90 |

The full compatibility selection is separately duplicated as
`tests --ignore=tests/integration`. Checkov integration, installed-wheel golden,
packaging, and QRS have shared path constants, but PR A does not route public CI
through them.

## Required mechanical proof before PR B

For every migrated coverage gate, execute the old workflow argv and the proposed
shared argv against one exact source tree and record:

- collected test count and node identities;
- covered module list;
- branch-coverage setting;
- observed coverage percentage;
- unchanged 90 percent threshold;
- exit result.

The new command must execute in the workflow's clean copied environment. GitHub CI
must continue to install with pip `--no-compile`, disable bytecode during test
execution, and avoid caching populated correctness environments. If any gate cannot
be proven equivalent, that gate remains in its current workflow form.
