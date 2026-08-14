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
      protected oracle policy, LICENSE, and NOTICE.
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

- [ ] Create separate copied-file product/parser and Checkov environments outside the
      source checkout; never overlay `python-hcl2` and `bc-python-hcl2` files.
- [ ] Install the reviewed wheel and Checkov 3.3.0 into their respective environments
      with `--no-compile`.
- [ ] Remove all `__pycache__`, `.pyc`, and `.pyo` entries from both environments.
- [ ] Set `PYTHONDONTWRITEBYTECODE=1` before any product execution.
- [ ] Run `iac-guard --version` and `iac-guard doctor`.
- [ ] Run the README golden Checkov workflow twice.
- [ ] Both reports are semantically valid report-v1 documents with `VERIFIED`, exit 0,
      exact CKV_AWS_53 file/resource binding, visible reduced-isolation, and no private
      absolute paths. Their semantic views and Markdown projections are byte-identical;
      exact raw hashes and measured durations remain run-specific provenance.

## Project gates

- [ ] Public CI uses the reviewed immutable action commits:
      `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`
      (`v4.2.2`) and
      `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`
      (`v5.6.0`). These tag-to-commit relations were resolved from the official
      repositories on 2026-08-13.
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
