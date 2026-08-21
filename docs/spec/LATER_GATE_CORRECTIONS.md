# Corrections carried into later gates

Recorded during Phase C so that Phase D and later phases inherit them. Each item is a
defect found in the plan's own gate definitions, not a new requirement.

---

## 1. Gate D must use real fixture refs and an executable coverage threshold

The plan's Gate D contained:

```bash
iac-guard pr --base-ref BASE --head-ref HEAD ...
```

`BASE` and `HEAD` are undefined placeholders; the command cannot run. Coverage was
likewise stated as prose ("coverage ≥90%"), which nothing enforces.

Required in Phase D:

```bash
# fixtures create their own two-commit repository, so refs are real and hermetic
python -m pytest tests/adversarial/test_forged_exception.py -q

iac-guard pr \
  --repo "$(pytest --fixture-path forged_exception)" \
  --base-ref "$(git -C "$FIXTURE" rev-parse refs/heads/base)" \
  --head-ref "$(git -C "$FIXTURE" rev-parse refs/heads/head)" \
  --policy-from base
# expect: POLICY_DRIFT reported, head-side exception ignored, exit 1

pytest --cov=src/iac_guard_v --cov-report=term-missing \
  --cov-fail-under=90 \
  --cov=src/iac_guard_v/engine.py --cov=src/iac_guard_v/policy.py \
  --cov=src/iac_guard_v/matching.py --cov=src/iac_guard_v/fingerprints.py
```

`--cov-fail-under` makes the threshold a gate rather than an intention. Per-module
thresholds are configured in `pyproject.toml` so that a well-covered utility module
cannot mask a thin engine.

## 2. The container gate must prove the mapped non-root user can write

`--read-only` with no writable tmpfs breaks Python, every scanner, and report writing.
Verified locally:

```
read-only, no tmpfs   -> sh: can't create /tmp/probe: Read-only file system
read-only + --tmpfs   -> WROTE_OK
--user $(id -u):$(id -g) + -v $OUT:/out:rw -> OUT_WRITE_OK, file owned by host user
```

The host-output result above was obtained on Docker Desktop for macOS, where bind-mount
ownership is permissive. **Linux CI is stricter and must re-prove it.** The Phase E gate
therefore asserts three things inside one run, on Linux:

1. `HOME` is writable (tmpfs) — the process can create its cache;
2. `/tmp` is writable (tmpfs) — scanners can stage files;
3. the report file exists on the host afterwards and is readable by the workflow user.

```bash
mkdir -p out
docker run --rm --network=none --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=256 --memory=2g --cpus=2 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --tmpfs /home/iacguard:rw,noexec,nosuid,size=128m \
  -e HOME=/home/iacguard \
  -v "$PWD/tests/fixtures:/src:ro" -v "$PWD/out:/out:rw" \
  iac-guard-v:test verify --before /src/a --after /src/b --output /out
test -s out/report.json && python -c "import json;json.load(open('out/report.json'))"
```

If the mapped UID cannot write, the gate fails rather than falling back to root.

## 3. Phase F: privacy first, and no shell globstar dependence

Two corrections.

**Privacy.** Predeclaration details for undisclosed candidates stay in
`$PRIVATE_WORKSPACE`. The public `cases/screening-manifest.jsonl` carries the
candidate id, disposition, and non-sensitive metadata; specifics of an undisclosed
finding are published only after the owner approves disclosure and any appropriate
maintainer notification has happened.

**Globstar.** The plan used `iac-guard case validate cases/**`, which depends on
`shopt -s globstar` and silently validates the wrong set — or nothing — in shells where
it is off. The command takes a root and walks it itself:

```bash
python -m iac_guard_v.cases validate --root cases --recursive
python tools/check_screening_manifest.py \
  --manifest cases/screening-manifest.jsonl \
  --minimum-predeclared-candidates 20 \
  --require-unique-ids --require-disposition
python tools/check_case_privacy.py --public-root cases \
  --private-root "$PRIVATE_WORKSPACE/cases"
```

The same rule applies anywhere else a gate would otherwise rely on shell glob
expansion: the tool walks, the shell does not.

## 4. Where these are enforced

| Correction | Enforced by | Phase |
| --- | --- | --- |
| Real fixture refs | hermetic fixtures that build their own git repository | D |
| Coverage threshold | `--cov-fail-under` in CI, per-module config in `pyproject.toml` | D |
| Container write proof | Linux integration job asserting all three writes | E |
| Case privacy | `tools/check_case_privacy.py` | F |
| No globstar reliance | tool-side recursive walking; grep for `/**` in gate scripts | E/F |
