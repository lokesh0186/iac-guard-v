# Author-run stable 1.0 TerraRepair pilot, 2026-10-05

The adapter's fixed ten archived TerraRepair repairs were prepared from the
commits and sample hash in [`provenance.json`](provenance.json), then checked
with the released `iac-guard-v==1.0.0` wheel and Checkov `3.3.0` in separate
local environments. These environments had passed the verifier's local-trusted
doctor. They were reused local environments, so this run is exploratory
adoption evidence, not clean release validation or an external researcher run.

| Outcome | Cases |
| --- | ---: |
| `VERIFIED` | 0 |
| `FAILED` | 0 |
| `INCONCLUSIVE` | 10 |
| Patch or operational errors | 0 |

All ten raw [`report.json`](terrarepair-015/report.json) files carry
`BASELINE_TARGET_DISCOVERY_UNAVAILABLE` with detail
`INVALID_RESULTS_STRUCTURE`. The runner preserved that uncertainty and exited
nonzero. It does **not** establish that the TerraRepair patches fail, nor that
they are verified. The source repairs were not regenerated and no model or
provider inference was run.

[`results.json`](results.json), [`summary.csv`](summary.csv), and the unsigned
[`verification_receipt.json`](verification_receipt.json) bind the case and
report hashes. The ten case directories contain the raw canonical reports;
third-party HCL and patch content are omitted. An independent operator can
reconstruct the inputs using `prepare.py` and run `evaluate.py` with their own
stable 1.0 and Checkov 3.3.0 installations. A discrepancy or setup error should
be reported as observed, not reconciled into a favorable verdict.
