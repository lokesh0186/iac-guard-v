# Historical hardened-evidence sufficiency comparison

This is an evidence-sufficiency analysis over frozen stored outputs. It is not a
production hardened-engine execution and makes zero hardened `VERIFIED` claims.

## Results

- 407 legacy `VERIFIED` records → hardened evidence `INCONCLUSIVE`: 407
- 223 legacy `FAILED` records → hardened evidence `INCONCLUSIVE`: 223
- Hardened `VERIFIED` claims: 0
- Local parser outcomes: `PASS=577`, `FAIL=53`, `UNSUPPORTED=0`, `ERROR=0`

## Missing evidence

- `AFFIRMATIVE_CANDIDATE_TARGET_EVALUATION_MISSING`
- `CANDIDATE_SCANNER_EXECUTION_IDENTITY_MISSING`
- `CANDIDATE_COVERAGE_INVENTORY_MISSING`
- `HISTORICAL_SEALED_SNAPSHOT_MISSING`
- `HISTORICAL_TRUSTED_POLICY_PROVENANCE_MISSING`

## Provenance and execution

- Analysis contract: `historical-hardened-evidence-sufficiency-v2`
- IaC-Guard-V implementation digest: `f1eef591befa8622360b58cb7108ea230d1234afa3db9a230596821a83a0b0d0`
- Parser `PyYAML` installed-code digest: `2f8cce8325d5b1745c716f5f3830cd23c935e5c31d9f18656f5743e3782c13f1`
- Parser `python-hcl2` installed-code digest: `98ca52742ffbb172fcde9bf435dfef50e7ec35336c87465dd032ded4796db6ee`
- stored_baselines_manifest_sha256: `6027ae079029e5907bb69c15392775edc75758256cc8ab5058358c0a2d9d4ff3`
- stored_patches_manifest_sha256: `c081e50b40657980666141dac524ab2062f5e5cb5ebd7a21b92cc8eef516577a`
- stored_runs_manifest_sha256: `d9ef4318911bc70fba2c2c0286626978bf3376b0de95a2d22f63a3e6ff51aef8`
- Scanner executions: 0
- Model-provider calls: 0
- New benchmark inference runs: 0
- Paper and historical tables changed: no

`PASS`, `FAIL`, `UNSUPPORTED`, and `ERROR` describe only the local independent
parser attempt. They are not production verification verdicts. Domain syntax
failure is `FAIL`; missing parser capability is `UNSUPPORTED`; internal or
operational parser failure is `ERROR`.

This file is generated from the canonical analysis values by
`research/compat/compare_legacy_hardened.py`; byte equality is tested.
