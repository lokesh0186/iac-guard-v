# Security model for IaC-Guard-V 1.0

IaC-Guard-V protects the evidence used to decide a bounded property. It is not a
general sandbox for hostile IaC or arbitrary external tools.

## Trust boundary

The caller may select paths, targets, contracts, and output formats. Caller-controlled
input may not inject trusted scanner results, policy decisions, validation-universe
results, callbacks, or provenance claims. The verifier constructs requests, binds
input bytes and resource identities, and validates the evidence graph before reporting
a result.

Native and contract verification operate without telemetry, model-provider calls,
cloud credentials, or live-cluster access. Reports can contain repository-relative
paths, resource names, and tool diagnostics, so they must be reviewed before sharing.

## Fail-closed decisions

Missing output is not a pass. Partial scans, unsupported syntax, ambiguous identities,
unresolved named ports or references, incomplete resource sets, nondeterministic
materialization, integrity failure, invalid provenance, and internal errors resolve to
`NOT_EVALUATED`, `UNSUPPORTED`, `INCONCLUSIVE`, `INVALID`, or `ERROR` as applicable.

`SATISFIED` and `VIOLATED` apply only to the requested mechanical property over the
protected evidence. They do not establish a project bug, vulnerability, outage,
runtime behavior, or whole-deployment safety.

## Process and command execution

External commands are invoked only through reviewed, typed command builders. The
product does not load dynamic verifier plugins or execute caller-supplied command
tails. Local scanner, Helm, Kustomize, Terraform, and OpenTofu tooling remains inside
the explicitly selected reduced-isolation boundary. No supported mode silently falls
back from a stronger boundary to a weaker one.

Local Helm uses fresh cache, config, data, and plugin directories. It rejects remote
charts, plugins, post-renderers, dependency updates, `lookup`, unresolved dependencies,
reachable nondeterministic helpers, chart mutation, unequal repeated renders, and
duplicate rendered identities. Kustomize rejects remotes, exec plugins, Helm inflation,
and unbound external resources in its supported subset.

## Filesystem and output

Protected inputs are content-bound before evaluation. Output creation rejects symlinks
and existing targets. Git-aware verification materializes exact objects in temporary
locations without changing the checkout, index, branch, or worktree. Temporary paths
and package contents are checked for private-path leakage before release.

## Scanner integrity

Scanner authority is property-specific. Executable, dependency, ruleset, invocation,
input, policy, coverage, suppression, and output evidence must satisfy the selected
authority contract. A scanner cannot redefine or narrow the protected universe, and
agreement among scanners cannot turn uncertainty into success.

## Hostile-input limitation

Version 1.0 supports operator-controlled local input. It does not claim containment of
arbitrary hostile templates, plugins, binaries, Python code, or resource-exhaustion
attacks. Use an independently hardened build and execution environment for untrusted
pull-request content. Do not use a privileged `pull_request_target` workflow to check
out and execute an untrusted head.

## Vulnerability reporting

Report suspected false `SATISFIED` results or boundary bypasses through the repository's
private GitHub security-advisory channel. Do not disclose credentials, private
infrastructure, protected caches, or undisclosed third-party evidence in a public issue.
