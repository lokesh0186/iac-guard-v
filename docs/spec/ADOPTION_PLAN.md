# Adoption Plan

Adoption follows usefulness. Nothing in this plan involves manufacturing activity,
soliciting endorsements, or asking anyone to cite the paper.

---

## 1. Five-minute onboarding

Three entry points, each independently sufficient:

```bash
# 1. local CLI
pipx install iac-guard-v && iac-guard doctor && iac-guard demo

# 2. container, no local Python
docker run --rm -v "$PWD:/src:ro" ghcr.io/<owner>/iac-guard-v:<version> demo

# 3. one workflow step
- uses: <owner>/iac-guard-v@v1
  with: { mode: pr }
```

Success means: no account, no API key, no cloud credential, and a first result that a
reviewer can read without the paper. `doctor` must name every missing tool with the
exact command to install it, and `demo` must show all four interesting outcomes —
verified, failed, suppressed, inconclusive — on bundled fixtures.

## 2. Channels

| Channel | Purpose | Gate |
| --- | --- | --- |
| PyPI (`pipx`, `uv tool`) | local and CI use | owner publishes |
| GHCR images | pinned, offline-capable CI | owner publishes |
| GitHub Action | the main adoption surface | owner lists on Marketplace |
| Sample repository | copyable working example | owner creates |
| Docs set | onboarding and troubleshooting | Phase G |

## 3. The three demonstrations that explain the product

1. A candidate that adds `#checkov:skip` passes a naive rule-disappearance check and is
   rejected here as `SUPPRESSED`.
2. A finding that moves from resource A to resource B looks resolved to a rule-ID set
   comparison and is reported here as `MOVED_FINDING`.
3. A scanner that produces no output looks clean to the old harness — including with
   current Checkov, where an empty scope returns a summary-only object and exit 0 — and
   is `SCANNER_ERROR`, exit 3, here.

These are the product in one screen each, and all three come from real defects recorded
in the audit.

## 4. Usability testing before any outreach

Required before `1.0.0`, and started right after `0.1.0a1`. A person who did not
implement the tool performs, unaided, with the log recorded in
`docs/adoption/QUICKSTART_USABILITY_LOG.md`:

1. install; 2. `iac-guard doctor`; 3. `iac-guard demo`; 4. verify a real before/after
change in a repository they choose; 5. add the Action to a pull request;
6. deliberately break a scanner and interpret the inconclusive result;
7. read a report and state, in their own words, what happened and what to do next.

Recorded per step: elapsed time, whether they succeeded without help, where they had to
guess, and every error message they hit. Anything that required explanation from the
implementer is a documentation defect, not a user error.

## 5. Pilot programme

`docs/adoption/PILOT_PROTOCOL.md` defines the protocol; `MAINTAINER_FIT_MATRIX.md`
records candidates with relevance evidence. No contact happens without owner approval,
one candidate at a time.

### Candidate criteria

Active public repository with meaningful Terraform or Kubernetes change traffic;
already runs at least one supported scanner; accepts unsolicited tooling suggestions
per its own contribution guidance; and no employer conflict. AI repair and agent
projects that need before/after verification are a natural second group.

### Explicit exclusions

Inactive repositories; projects whose guidance discourages unsolicited proposals;
anything touching an employer relationship; and any repository where the value would be
a favour rather than a fit.

### What is offered and asked

Offered: a minimal workflow, help interpreting results, quick fixes to onboarding
problems, and credit to the reporter. Optionally, and only if preferred, a narrowly
scoped pull request.

Asked: honest technical feedback, including "we removed it and here is why". Never
asked: praise, citations, stars, endorsements, or anything related to the owner's
personal circumstances.

### Measures

| Measure | Definition |
| --- | --- |
| Time to first successful result | from clone to a report they understand |
| Install failure rate | failures per attempt, with cause and `doctor` resolution |
| Report interpretation errors | cases where a user misread a verdict |
| 30-day retention | integration still present and running |
| 60-day retention | same, plus whether it caught something real |
| Removal reason | recorded verbatim, published in aggregate |
| Independent finding | user reports a useful result without prompting |

A pilot that ends in removal is a successful pilot with a negative result, and it is
recorded as such.

## 6. Upstream case workflow

Screening effort is predeclared in `cases/screening-manifest.jsonl` before results are
seen: at least twenty unique candidates with source, licence, target control, and
rationale, and a disposition recorded for every one.

A case becomes `validated` only when an independent oracle or authoritative
specification establishes the expected behaviour **and** configuration, suppression,
partial scan, parser failure, version drift, and documented policy-semantic differences
between scanners are all excluded. Scanners implement related but non-equivalent
policies; disagreement is not a defect.

Zero validated cases is an acceptable published outcome. There is no quota, and the
semantic standard is never relaxed to produce one. Undisclosed cases and all upstream
drafts live outside this repository until the owner approves disclosure. No
submission automation is implemented.

## 7. Community surfaces

Contribution guide with an adapter walkthrough and a case walkthrough; issue forms for
bug, adapter, discrepancy case, feature, and docs; a PR template requiring tests,
provenance, and a public-claim check; `SECURITY.md` with private reporting;
`ADOPTERS.md` containing only voluntary, verifiable entries. An empty `ADOPTERS.md` is
the correct state until someone asks to be listed.

## 8. Evidence hygiene

A signal counts only when an independent party makes a real technical decision. Five
pull requests to one project remain one ecosystem relationship. A star is not adoption.
Self-authored work becomes an upstream signal only when the independent project accepts
it and the change is substantive. Records live outside the public repository.

## 9. Release discovery

After `0.9.0rc1` and the usability test, and only then: a neutral technical post
showing the three demonstrations; short reproducible tutorials for Checkov-only,
multi-scanner, Action, and agent integration; and talk or demo submissions to relevant
communities. Nothing is published before the product does what the post says it does.
