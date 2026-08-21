# Historical hardened-evidence sufficiency comparison

This is an evidence-sufficiency analysis over frozen stored outputs. It is not a
production hardened-engine execution and makes zero hardened `VERIFIED` claims.

## Results

- 407 legacy `VERIFIED` records → hardened evidence `INCONCLUSIVE`
- 223 legacy `FAILED` records → hardened evidence `INCONCLUSIVE`
- Hardened `VERIFIED` claims: 0
- Local parser outcomes: `PASS=577`, `FAIL=53`, `UNSUPPORTED=0`, `ERROR=0`

## Missing evidence

- `AFFIRMATIVE_CANDIDATE_TARGET_EVALUATION_MISSING`
- `CANDIDATE_SCANNER_EXECUTION_IDENTITY_MISSING`
- `CANDIDATE_COVERAGE_INVENTORY_MISSING`
- `HISTORICAL_SEALED_SNAPSHOT_MISSING`
- `HISTORICAL_TRUSTED_POLICY_PROVENANCE_MISSING`

## Provenance and execution

- Analysis contract: `historical-hardened-evidence-sufficiency-v3`
- Environment contract: `d9-hash-pinned-linux-amd64-v1`
- Environment manifest digest: `b182b0195008a91470a5cc29155c866fa5a432ed6cc8b6b606360620dd74fb57`
- Base image manifest: `sha256:83f339c1be6340ae1096010fdccf6552ac932d8f410d45d206014916bdf37e48`
- IaC-Guard-V implementation digest: `ee8fc8c2b63f05c929e77087f7a1f7d9da103445584167a2ff30fb8a0e38d1a9`
- Parser `PyYAML` 6.0.3 installed-code digest: `386acd57ff90f86e2e76edbce3071a44019a8febe077783331383fda9add02a0`
- Parser `python-hcl2` 7.3.1 installed-code digest: `e76a67d7e9b77f839e9fb209863f9d74518385e08dcbbb0132a43b7d4b06950c`
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
