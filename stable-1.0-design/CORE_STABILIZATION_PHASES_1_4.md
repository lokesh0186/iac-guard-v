# IaC-Guard-V 1.0 core stabilization record

Date: 2026-09-23

Scope: implementation phases 1 through 4 only. No public release, tag, version
change, or repository publication was performed.

## Phase 1: native-property freeze

Status: PASS

The complete set of 18 public V1 native properties is frozen by executable
semantic digests. Each record binds the property ID, version, artifact and subject
classes, closed parameter schema, semantic-definition identity, semantic binding,
capabilities, and witness type. The executable freeze also binds fixture suites,
public demand evidence, and the five-result vocabulary.

Implementation:

- `src/iac_guard_v/native_properties/stable_v1.py`
- `tests/unit/test_stable_v1_property_freeze.py`

No property ID or family was added.

## Phase 2: stable schema bridge

Status: PASS

The parser now accepts the exact existing `iac-guard-v.io/v1alpha1` contract and a
stable `iac-guard-v.io/v1` discriminator. The stable schema is derived from the
frozen Alpha schema by changing only the schema identifier and API discriminator.
Conversion is explicit and bidirectional. Alpha inputs continue to emit Alpha
reports, and stable inputs emit stable reports. Existing provenance and
responsibility values remain unchanged.

The report validators also recognize exact archived A10 and Beta1 identities while
rejecting altered historical definitions. This permits existing reports to remain
readable without weakening current-report identity checks.

Implementation:

- `src/iac_guard_v/contracts/schema_bridge.py`
- `src/iac_guard_v/contracts/model.py`
- `src/iac_guard_v/contracts/parser.py`
- `src/iac_guard_v/contracts/report.py`
- `src/iac_guard_v/native_properties/compatibility.py`
- `src/iac_guard_v/native_properties/report.py`
- `tests/unit/test_stable_v1_schema_bridge.py`

## Phase 3: API and CLI freeze

Status: PASS

Executable snapshots now freeze the complete recursive argparse surface, existing
public Python exports, all existing wire-schema bytes, provenance values, result
enums, and documented exit-code mappings. Path-valued defaults are normalized by
their public value rather than Python's private `pathlib` implementation class, so
the snapshot is stable across Python 3.10 through 3.13.

Implementation:

- `src/iac_guard_v/stable_api.py`
- `tests/unit/test_stable_v1_api_cli_freeze.py`

## Phase 4: external compatibility replay

Status: PASS

The executable manifest contains 32 public IaC-Guard-V-dependent or
IaC-Guard-V-evidenced cases from the design manifest. It validates preserved
Alpha/Beta contract, native-property, and general reports with the current
validators; binds preserved evidence by SHA-256; verifies referenced property IDs
and expected result classes; and requires the applicable semantic fixture suites.

Result:

- total: 32
- `UNCHANGED`: 32
- `STRICTER_BUT_COMPATIBLE`: 0
- `BREAKING`: 0
- `NEWLY_UNSUPPORTED`: 0
- `BLOCKED_BY_EXTERNAL_DRIFT`: 0

Implementation:

- `tools/compatibility/external_replay.py`
- `tests/unit/test_stable_v1_external_replay.py`

## Validation record

- supported Python matrix: PASS, Python 3.10, 3.11, 3.12, and 3.13;
  13,213 tests, zero failures, zero errors
- final phase 1 through 4 focused suite: PASS, 41 tests on each supported Python
- coverage profile: PASS; every aggregate gate exceeds the unchanged 90% threshold;
  stable contract aggregate 90.67%
- frozen QRS replay: PASS; 4,842/4,842 manifest checks, 630/630 replays,
  10,080/10,080 field checks, and 7/7 semantic table matches
- package integrity: PASS, 14 tests
- installed-wheel golden workflow outside the source checkout: PASS
- Checkov 3.3.0 managed integration: PASS, 9 tests
- external compatibility replay: PASS, 32/32 unchanged

Machine-readable test results are under `.test-results/` for the corresponding
2026-09-23 matrix, coverage, QRS, package, golden, and Checkov runs.

## Decision boundary

The existing 18-property semantic surface and its compatibility commitment are now
technically supportable. That makes the 1.0 semantic contract justified.

This record does not authorize a release. The remaining release work is outside
phases 1 through 4 and includes final stable product documentation, security and
supply-chain release review, release-candidate validation, stable-version artifact
identity, SBOM and attestations, Trusted Publishing verification, final migration
notes, and the owner-authorized release gate.
