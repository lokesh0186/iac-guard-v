# Bounded OpenTofu source verification

IaC-Guard-V Beta1 adds a distinct protected OpenTofu source mode and the native
property `IACGV_OPENTOFU_REFERENCE_RESOLVES_V1`. It does not route OpenTofu files
through Terraform V1 semantics.

The file-set contract accepts `.tf`, `.tofu`, `.tf.json`, and `.tofu.json`. Within
one module, `.tofu` shadows a same-basename `.tf`, and `.tofu.json` shadows a
same-basename `.tf.json`. Evidence retains both effective and shadowed files, their
hashes, module identities, file classes, and the reason for precedence. A malformed
winning file fails closed; IaC-Guard-V never falls back to a valid shadowed file.

Normal files are parsed before `override.tofu`, `*_override.tofu`, and JSON override
equivalents. Beta1 models only exact top-level scalar replacement on an existing
resource. Nested/complex override expressions are `UNSUPPORTED`. Literal local child
modules are protected recursively. Missing modules are `NOT_EVALUATED`; remote,
dynamic, cyclic, escaping, and symlinked module sources are unsupported or rejected.

The property proves an exact direct source-local reference at a protected attribute
path. It does not run `tofu init`, `plan`, or `apply`; fetch modules; evaluate provider
outputs; expand `count`/`for_each`; or claim deployed cloud state.

Example native request:

```json
{
  "schema_version": "native-property-request-v1",
  "root": "module",
  "artifact_class": "opentofu_source",
  "requests": [{
    "request_id": "bucket-reference",
    "property_id": "IACGV_OPENTOFU_REFERENCE_RESOLVES_V1",
    "property_version": "1",
    "subject_identity": "aws_s3_bucket_notification.events",
    "parameters": {
      "attribute_path": ["bucket"],
      "expected_target": "aws_s3_bucket.logs",
      "mode": "DIRECT"
    }
  }]
}
```

Use `python -m iac_guard_v.native_properties --config request.json --format json`.
Every decisive result includes the protected file-set digest, effective/shadowed file
records, exact source/target identities, attribute origin, and a source span.
