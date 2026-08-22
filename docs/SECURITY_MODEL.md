# Security model

IaC-Guard-V verifies evidence rather than trusting a scanner's final count. This
page summarizes the product boundary; the normative detail remains in the
[threat model](spec/THREAT_MODEL.md) and specification documents.

## Trust boundary

Public CLI, configuration, API, and report inputs may supply paths, target
selectors, protected configuration locations, and output formats. They may not
manufacture or inject:

- raw scanner results;
- precomputed deltas or policy decisions;
- oracle or validation-universe results;
- trusted execution capabilities or callbacks;
- caller-authored trust assertions.

The product constructs the verification request, seals the complete before and
after snapshots, invokes the selected scanner under the protected contract, and
validates the resulting evidence graph before reporting a verdict.

## Fail-closed semantics

`VERIFIED` means every required protected predicate passed. Missing, partial,
unsupported, inconsistent, or unverifiable evidence is `INCONCLUSIVE` or an
operational error—never success.

Examples include:

- a scanner reports zero findings but provides no affirmative target coverage;
- a resource selector matches multiple files or occurrences;
- a parser cannot independently inventory the target;
- a validator is skipped or not applicable;
- a report contradicts its child evidence;
- a target is removed or suppressed instead of repaired.

Validated reporters consume only canonical `report-v1`. They cannot weaken an
outcome or recalculate policy permissively.

## Execution modes

### Local trusted mode

`--local-trusted` is explicit reduced isolation. It is appropriate only for
operator-controlled input. The Checkov executable, distribution, ruleset,
parser, and product environments are identity-checked and recorded, but native
execution is not a hostile-code sandbox.

IaC-Guard-V does not defend against arbitrary hostile Python already executing
inside its trusted interpreter.

### Hardened container mode

The production fully offline container and composite GitHub Action are not
released. Until the native-Linux UID/GID and read-only bind-mount gate passes,
hostile pull-request input is out of scope. There is no silent downgrade from
hardened-container mode to local-trusted mode.

## Scanner and validator authority

Checkov `3.3.0` is the supported scanner path for this release. Experimental
KICS, Trivy, kubeconform, TFLint, and deterministic-oracle evidence remains
advisory unless its exact protected contract is complete.

Multi-scanner V7 consensus is disconnected from final product verdicts. Scanner
agreement cannot turn `INCONCLUSIVE` into `VERIFIED`, create a validated
discrepancy, or overrule the trusted policy.

## Environment provenance

Real native verification uses separate copied-file environments for the product
and Checkov. The startup and parser boundaries reject executable bytecode caches
and overlapping package files that prevent trustworthy RECORD provenance. See
[Advanced installation](ADVANCED_INSTALLATION.md) for the tested setup.

## Data handling

IaC-Guard-V has no telemetry, model-provider SDK, or benchmark-inference path in
product verification. Reports may still contain repository-relative paths,
resource identities, scanner diagnostics, and source metadata. Review an
artifact before sharing it and keep protected caches and private screening data
private.

Atomic output creation rejects symlinks and existing targets; callers must
select a new regular-file destination. Git-aware verification materializes exact
objects in private temporary locations and does not alter the current checkout,
index, branch, or worktree.

## Reporting a vulnerability

Use the repository's private GitHub security-advisory channel and follow
[SECURITY.md](../SECURITY.md). Do not publish credentials, private
infrastructure, protected cache material, or undisclosed third-party cases.

