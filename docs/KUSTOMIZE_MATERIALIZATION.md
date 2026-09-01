# Kustomize materialization

IaC-Guard-V can evaluate explicitly selected candidate properties after one
bounded local Kustomize build. This is a closed deterministic materialization contract,
not general Kustomize support.

The `kustomize-accept` command requires a local repository root, a contained build root,
the exact allowlisted Kustomize v5.7.1 executable, an explicit Checkov 3.3.0 executable,
and `--local-trusted`. Checkov remains the authoritative scanner path.

Before execution, IaC-Guard-V parses the complete transitive local control graph and
binds every control document, resource, component, patch, replacement source, and
generator input by role, referrer, size, and SHA256. It runs two fresh builds under the
reviewed offline wrapper, requires identical bytes and resource identities, and binds
the rendered output as the exact scanner universe. Conservative full-closure provenance
prevents generated or transformed resources from escaping source governance.

Only the reviewed Kustomization/Component types, explicitly allowlisted keys, contained
local references, bounded patch/replacement/generator shapes, and fixed resource limits
are accepted. Unknown keys or shapes fail closed.

The following are not supported:

- remote URLs, Git references, OCI references, or any dependency download;
- Helm chart inflation;
- plugins, functions, exec generators, or custom transformers/generators;
- custom field specifications, unbound paths, path/symlink escapes, or inputs outside
  the protected repository;
- nondeterministic output, incomplete source closure, or output beyond the fixed
  file/document/byte limits;
- live cluster state or any unsupported dynamic behavior.

KICS and Trivy remain advisory/future adapter work and cannot establish an
authoritative result for this path. Unsupported cases return a typed error or
`INCONCLUSIVE`; they never become success through an empty scanner result.
