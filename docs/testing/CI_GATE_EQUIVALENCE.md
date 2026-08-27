# CI gate equivalence map

Status: PR B mechanical equivalence PASS. Public GitHub Actions continues to create
clean copied environments; only the duplicated coverage argv definitions now come
from the shared closed catalog.

## Migrated duplication

Before PR B, `.github/workflows/python-compat.yml` embedded eight coverage
invocations as shell commands in every Python 3.10 through 3.13 job.
`tools/testing/gates.py` now supplies those exact selections to both the local Nox
harness and the argv-only `tools.testing.ci_gates` public-CI runner.

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

The full compatibility selection remains directly visible as
`tests --ignore=tests/integration`. Checkov integration and installed-wheel golden
also remain direct workflow commands. PR B does not migrate or otherwise alter those
independent public gates.

## Mechanical proof

On 2026-08-27, every old workflow argv and proposed shared argv was executed against
the same candidate source tree. Each pair used the same Python 3.12 environment,
`PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH=src`, an independent coverage data file, and
the unchanged 90 percent threshold.

| Gate | Nodes | Node-list SHA-256 | Coverage old/new | Exit old/new |
| --- | ---: | --- | ---: | --- |
| `d3-fingerprints` | 94 | `50a6f6b5eb93155c8b6ab12695f311a7c8558aa764d0932b1d7528a5acb86d81` | 100.00% / 100.00% | 0 / 0 |
| `d3-matching` | 94 | `50a6f6b5eb93155c8b6ab12695f311a7c8558aa764d0932b1d7528a5acb86d81` | 94.47% / 94.47% | 0 / 0 |
| `d3-diffing` | 94 | `50a6f6b5eb93155c8b6ab12695f311a7c8558aa764d0932b1d7528a5acb86d81` | 91.58% / 91.58% | 0 / 0 |
| `d4-adapters-parser-graph` | 272 | `d4e5314411b6230ce6512e49cc6bbdeff11a2c8052c8000c4208c11ef561e465` | 92.28% / 92.28% | 0 / 0 |
| `d5-engine` | 305 | `d5a560350cab39ea0de043a32423ac11020874ddad592c317016525e75b79019` | 90.66% / 90.66% | 0 / 0 |
| `d6-policy` | 195 | `1bdc788f9606c72dbcf4c43cb5d20822d7ccf272123de3a3693cbb813132b137` | 90.50% / 90.50% | 0 / 0 |
| `d7-public-boundary` | 774 | `e6511765816d7bdd79a8ef1d8133b5716eda4b77a3ca4ded3fe7fbe800993969` | 90.09% / 90.09% | 0 / 0 |
| `helm-materializer` | 422 | `9cb553e46bddae69c302bba20cf92a1e35bf70e950623b35380889c38512a11a` | 90.67% / 90.67% | 0 / 0 |

For all eight pairs, the collected node count and sorted node-list hash matched, the
covered module list and branch setting came from the same immutable gate object, and
the observed coverage percentage and exit status were identical. The three D3 gates
intentionally share one test selection, which explains their identical node-list
hash.

GitHub CI still creates `/tmp/iacgv-compat` with standard-library `venv --copies`,
installs with pip `--no-compile`, disables bytecode for migrated coverage execution,
and does not cache a populated correctness environment.
