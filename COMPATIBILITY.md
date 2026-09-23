# IaC-Guard-V 1.x compatibility policy

Version 1.0 makes a compatibility commitment over its declared bounded scope.

## Stable through 1.x

The following surfaces remain compatible throughout 1.x:

- documented CLI command names, options, accepted tokens, and exit-code meanings;
- the public Python exports recorded by the executable stable API snapshot;
- v1alpha1 and stable-v1 contract and report schemas;
- the 18 V1 native property IDs, versions, parameter schemas, witness types, and
  semantic meanings;
- native and contract result enums, reason meanings, provenance tokens, and required
  machine-readable fields.

Implementation digests, product-version fields, timestamps, build metadata, and whole
report hashes may change. Consumers should validate schemas and semantic fields rather
than compare whole report bytes across product versions.

## v1alpha1 bridge

All valid 0.1.0b1 `iac-guard-v.io/v1alpha1` contracts remain accepted without source
edits. They continue to produce v1alpha1-compatible reports unless the caller
explicitly requests conversion. `iac-guard-v.io/v1` has equivalent contract semantics.
Conversion changes only the version discriminator after both forms validate.

## Versioning rules

Patch releases may correct implementation defects without changing supported property
semantics or schema meaning. Minor releases may add optional fields, new versioned
properties, or new materializers without invalidating existing inputs. Removing or
incompatibly changing a command, schema, property, result, provenance value, witness,
exit code, or public Python export requires 2.0.

A deprecation must be documented, emit a warning where practical, and remain usable
for at least one minor release before a major-version removal.

## External replay gate

Every known public IaC-Guard-V-dependent contract, command, report consumer, issue,
and pull request is replayed before release. The 1.0 gate covers 32 cases and permits
no unexplained `BREAKING` or `NEWLY_UNSUPPORTED` result. Changing a package pin from
`0.1.0b1` to `1.0.0` is the only expected consumer edit.
