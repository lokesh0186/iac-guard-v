# IaC-Guard-V 0.1.0a1 release gate

This checklist prepares reviewed artifacts; it does not authorize a push, tag, upload,
or publication. Run it only from the owner-reviewed release commit with a clean tree.

## Current legal blocker

The release is **BLOCKED** until all of the following are true in a separate,
owner-authorized documentation/legal-tip commit:

- the owner supplies the arXiv identifier for the pre-peer-review manuscript;
- `paper.pdf is absent from the current tree`;
- README.md, CITATION.cff, and RESEARCH_SNAPSHOT.md link the arXiv abstract record.

An ordinary deletion does not remove historical Git objects. Do not push the frozen
historical tag while the paper-distribution question remains unresolved.

## Clean source gate

- [ ] Confirm the branch is `adoption/phase-e-multiscanner`.
- [ ] Record and independently review the exact release HEAD.
- [ ] Confirm `git status --short` is empty.
- [ ] Confirm the arXiv/paper conditions above.
- [ ] Confirm no secret, token, absolute private path, or private test capability is
      present in a public surface.

## Fresh build

The build starts by deleting ignored outputs so stale artifacts can never be reused:

```bash
rm -rf dist build
find . -maxdepth 2 -type d -name '*.egg-info' -prune -exec rm -rf {} +
python -m pip install --upgrade pip
python -m pip install --no-compile "build>=1.2,<2"
python -m build --outdir dist
```

- [ ] `dist/` was absent or empty immediately before `python -m build`.
- [ ] Exactly one `0.1.0a1` wheel and one `0.1.0a1` sdist were created.
- [ ] Package-content tests pass against a separately created empty output directory.
- [ ] The wheel contains workflow.py, all three reporters, both public schemas, the
      protected oracle policy, packaged demo fixture, the RECORD-bound no-bytecode
      startup policy, LICENSE, and NOTICE.
- [ ] Wheel and sdist exclude paper.pdf, frozen research/benchmark material, tests,
      tools, scripts, and test-only evidence capabilities.

Record the exact reviewed artifact hashes without rebuilding them:

```bash
python - <<'PY'
from hashlib import sha256
from pathlib import Path
for path in sorted(Path("dist").iterdir()):
    if path.is_file():
        print(sha256(path.read_bytes()).hexdigest(), path)
PY
```

## External installation and golden workflow

- [ ] Create separate copied-file product/parser and Checkov environments with
      `venv --copies --without-pip`; never overlay `python-hcl2` and `bc-python-hcl2`.
- [ ] From the external installer, install the reviewed wheel and Checkov 3.3.0 with
      `pip --python <environment-python> install --no-compile`.
- [ ] Do not manually delete caches or set `PYTHONDONTWRITEBYTECODE`; the installed
      startup policy and scanner subprocess contract must keep both environments clean.
- [ ] Run `iac-guard --version` and the literal README
      `iac-guard doctor --mode local-trusted --checkov-executable <exact-path>`;
      doctor must return 0 without an undocumented `PATH` change even though
      hardened-container mode remains unavailable.
- [ ] Run the README automatic-target
      `iac-guard verify --before ... --after ... --all-baseline-findings` command twice,
      then rerun doctor, without repairing or cleaning either environment.
- [ ] Both reports are semantically valid report-v1 documents with `VERIFIED`, exit 0,
      exact CKV_AWS_53 file/resource binding, visible reduced-isolation, and no private
      absolute paths. Their semantic views and Markdown projections are byte-identical;
      exact raw hashes and measured durations remain run-specific provenance.
- [ ] Run the direct Git `iac-guard pr --base-ref ... --head-ref ...
      --all-baseline-findings --changed-only` path against a temporary repository;
      require exit 0, valid SARIF, exact Checkov rule evidence, no private paths, and
      an unchanged checkout/index/worktree.

## Project gates

- [ ] Public CI uses the reviewed immutable action commits:
      `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`
      (`v4.2.2`) and
      `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`
      (`v5.6.0`). These tag-to-commit relations were resolved from the official
      repositories on 2026-08-13.
- [ ] Both public-CI checkouts use `fetch-depth: 0`; when the intentionally unpushed
      `qrs-2026-replication-v1` tag is absent, CI creates and verifies only a local
      annotated tag at `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5` from
      `research/TAG_MESSAGE_REPLACEMENT.txt`. No CI command pushes the tag.
- [ ] The shallow/no-tag public-clone regression proves the historical commit is
      initially unavailable, becomes available only after full-history fetch, and the
      local tag bootstrap is deterministic and idempotent.
- [ ] Python 3.10, 3.11, 3.12, and 3.13 non-integration matrices pass.
- [ ] Checkov 3.3.0 locked integration passes.
- [ ] Changed release/alpha modules retain at least 90% branch coverage.
- [ ] `tools/spec_lint.py docs/spec/` reports zero warnings.
- [ ] Frozen manifest remains 4,842/4,842 with the reviewed manifest root.
- [ ] Replay remains 630/630 and 10,080/10,080 with no verdict mismatch.
- [ ] All seven derived tables remain `SEMANTIC_MATCH`.
- [ ] Frozen-scope diff is empty.
- [ ] No benchmark inference or model-provider call occurred.

## Authorization boundary

Do not push a tag, publish a GitHub release, upload to PyPI, push a branch, or contact
an upstream project until the owner separately authorizes that exact action. The same
reviewed wheel and sdist must be used for GitHub and PyPI; do not rebuild between them.
