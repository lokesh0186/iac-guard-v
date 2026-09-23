# API, CLI, and schema freeze for 1.0

## Freeze rule

The entire `beta-public-api-v1` snapshot is the minimum 1.x compatibility
surface. The freeze includes names and behavior. A function that remains
importable but changes the meaning of a result is not compatible.

## CLI compatibility tests

Before release, capture and golden-test:

1. top-level and every subcommand `--help` output after normalizing the version;
2. every Beta1 command, option, default, mutually exclusive group, and enum;
3. general and contract exit-code mappings;
4. JSON, console, SARIF, Markdown, and JUnit output where applicable;
5. stdin/stdout/stderr and `--quiet` behavior;
6. `contract lint`, `plan`, `verify`, and `explain` over every external contract;
7. `properties list` and `describe` over all 18 V1 IDs;
8. `support` and `doctor` machine-readable output;
9. `scan` and `differential` compatibility aliases;
10. `pip install` and `python -m` entry points where publicly documented.

No option may be repurposed. New options must be optional. Existing default
behavior must remain unless an explicit correctness exception is approved and a
compatibility mode is provided.

## Contract-schema bridge

The Beta1 `iac-guard-v.io/v1alpha1` schema cannot simply be renamed. The 1.0
implementation must:

- continue accepting the exact Beta1 v1alpha1 bytes;
- preserve every Beta1 provenance and responsibility enum;
- preserve planning and evaluation outcomes for the replay corpus;
- validate and explain archived v1alpha1 reports;
- add `iac-guard-v.io/v1` only if it has an explicit conversion table;
- emit a v1alpha1-compatible report for a v1alpha1 input by default;
- provide an explicit, testable conversion command or option rather than an
  implicit rewrite;
- retain the v1alpha1 reader for the entire 1.x line.

This bridge is a release blocker. Publishing 1.0 with only a renamed stable
schema would break current public integrations.

## Machine-readable compatibility

Stable fields may be added only when old strict consumers are not invalidated.
Closed Beta1 schemas therefore cannot receive arbitrary optional fields under
the same schema identity. New structures require a new schema version while the
old validator remains available.

Canonical digests that bind implementation bytes or product version will change
under 1.0. That is expected. Tests must compare contract meaning, results,
reason-code class, witness facts, exit code, and schema validity rather than
requiring cross-version report-byte equality. Identical inputs within one exact
release must remain byte-deterministic wherever the current contract promises it.

## Python compatibility

The Beta1 public exports listed in `beta_api.py` remain importable and retain
their constructor, validation, canonicalization, and evaluation behavior.
Private modules stay private. New 1.0 documentation must direct most consumers
to the CLI and schemas, reducing accidental expansion of the Python contract.

Deprecation policy:

1. document the replacement;
2. emit a targeted warning without changing results;
3. retain the old surface through at least the next minor release;
4. remove only in 2.0.
