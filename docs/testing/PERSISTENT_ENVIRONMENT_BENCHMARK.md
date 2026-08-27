# Persistent environment benchmark

Status: PR A candidate measurements complete. Values were recorded only after the
exact commands completed; no projected speedup is presented as observed data.

## Machine envelope

- Host: macOS arm64
- Logical CPUs: 8
- Memory: 8 GiB
- Python: CPython 3.10.20, 3.11.6, 3.12.4, 3.13.15, all arm64
- Helm: 4.2.4
- Nox: 2026.8.17

No hostname, username, or private filesystem path is retained.

Clean setup used each interpreter's standard-library `venv --copies`, its own pip,
`--no-compile -e '.[compat-test]'`, `pip check`, and an isolated distribution import.
The machine's existing pip download cache was retained, matching the documented local
rebuild policy. Temporary environments were measured one at a time and removed after
each row. Test runtimes are the matching sequential warm-matrix observations, so setup
and execution costs remain separately visible.

## Measurements

| Scenario | Cold setup | Test/runtime | Total | Peak memory | Status |
| --- | ---: | ---: | ---: | ---: | --- |
| Clean Python 3.10 | venv 2.64 s; install 6.39 s; preflight 0.34 s | 249.63 s warm reference | 258.99 s | 228 MiB environment | PASS |
| Clean Python 3.11 | venv 6.02 s; install 11.26 s; preflight 0.56 s | 239.18 s warm reference | 257.02 s | 233 MiB environment | PASS |
| Clean Python 3.12 | venv 2.76 s; install 8.67 s; preflight 0.54 s | 244.04 s warm reference | 256.02 s | 224 MiB environment | PASS |
| Clean Python 3.13 | venv 2.28 s; install 4.99 s; preflight 0.33 s | 233.12 s warm reference | 240.71 s | 197 MiB environment | PASS |
| Warm Python 3.12 dev, ordinary reference | 1.97 s preflight | 242.72 s | 244.69 s | 224 MiB | 2,741 passed before final harness self-tests |
| Warm Python 3.12 dev, maintained split | reused | 148.00 s parallel + 39.91 s serial research | 190.87 s | 216 MiB observed process maximum | 2,756 passed; no swaps |
| Clean-cache bootstrap matrix | 3 environments built; 3.12 reused from smoke | 10,976 interpreter-tests | 524.87 s | 271 MiB observed process maximum | PASS, no swaps |
| Four-version sequential matrix | reused | 3.10: 249.63 s; 3.11: 239.18 s; 3.12: 244.04 s; 3.13: 233.12 s | 980.46 s | 212 MiB observed process maximum | PASS, no swaps |
| Four-version 2-way matrix | reused | 10,968 interpreter-tests | 668.81 s | 214 MiB observed process maximum | PASS, no swaps |
| Four-version 4-way matrix | reused | 10,968 interpreter-tests | 477.23 s | 205 MiB observed process maximum | PASS, no swaps |
| Final PR A 4-way matrix | reused | 11,024 interpreter-tests | 474.68 s | 210 MiB observed process maximum | 2,756/version; PASS, no swaps |
| Checkov 3.3.0 cold | 39.77 s | 305.75 s | 345.52 s | 260 MiB | 9 passed |
| Checkov 3.3.0 warm | 11.20 s integrity preflight | 314.20 s | 325.40 s | 214 MiB | 9 passed, no reinstall |
| Frozen QRS | reused | 9.22 s | 11.24 s | not separately sampled | 29 tests; all frozen identities PASS |
| Coverage gates | reused | 287.6 s | 289.60 s | 215 MiB observed process maximum | 2,250 gate-tests; all eight thresholds PASS |
| Complete local PR profile | reusable matrix/scanner | matrix, coverage, Checkov, QRS, package, golden | 2,230.44 s | 239 MiB observed process maximum | 13,326 aggregated gate-tests; PASS, no swaps |

## Parallel and optional experiments

`MATRIX_DEFAULT_PARALLELISM` is four. It reduced the identical warm matrix wall time by
51 percent versus sequential and 29 percent versus two-way execution. All modes passed,
and the four-way run reported no swap activity on the 8 GiB host. The macOS maximum-RSS
figure is the largest observed process, not a sum across concurrent children.

The bounded pytest-xdist experiment used a separate Python 3.12 environment. Ordinary
runs took 257.91 s and the comparable prior warm run took 244.69 s. Two-worker runs took
147.60 s and 153.64 s, a stable improvement of about 40 percent. Automatic worker-count
runs took 146.21 s and 90.95 s, but their high variance and full-host scheduling make
them a poor default. Every run passed 2,744 tests with no swap activity or source-tree
mutation. The maintained `dev` profile therefore uses exactly two workers for
non-research tests, then runs research tests serially. Matrix, coverage, scanner, QRS,
and release profiles remain non-xdist. Result: `ENABLED_WITH_EVIDENCE`.

The Docker experiment used the pinned local arm64 Python 3.12 image identity
`sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`,
a non-root user, a read-only source mount, no Docker socket, no runtime network, and an
image-provided build-backend wheelhouse. The cold image build took 62.04 s, a cached
rebuild took 4.47 s, and the complete 2,744-test run took 154.28 s. This was only about
16 percent faster than the maintained native `dev` profile while the image occupied
about 767 MB and duplicated Linux image maintenance already provided by clean GitHub
CI. The named experimental image and context were removed; shared Docker caches were
not pruned. Result: `NOT_RETAINED`.

## Persistent disk footprint

After the final cold-scanner PR run, the four Nox compatibility environments occupied
about 1.0 GiB, the governed Checkov environment 139 MiB, local result summaries and
JUnit/coverage diagnostics 11 MiB, and the pinned Nox tooling environment 27 MiB.
The guarded `clean_test_envs` profile removes the first three categories only. It
retains the small Nox bootstrap environment and the global pip download cache so a
deliberate rebuild remains fast.
