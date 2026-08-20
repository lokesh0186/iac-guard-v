# PUBLIC.1 clean-build artifact record

This records the fresh local artifacts produced after removing `paper.pdf` from the
current product tip and separating software release readiness from pending publication
metadata. It is not a push, tag, upload, or publication authorization. The submitted
manuscript's public arXiv identifier and the Springer Version of Record remain follow-up
links; no placeholder identifier is present.

| Artifact | Bytes | SHA-256 | Files |
| --- | ---: | --- | ---: |
| `iac_guard_v-0.1.0a1-py3-none-any.whl` | 248617 | `7d81dbf71432d402845245212c5cebfbfb0f3452c5a113aa98af600f42ad5358` | 52 |
| `iac_guard_v-0.1.0a1.tar.gz` | 240234 | `de683d77f53f1ef1b612c4f9dae617c1a56e6f91214057ec17fa5d4bf7c5c92c` | 65 |

## Wheel inventory

```text
iac_guard_v-0.1.0a1.dist-info/METADATA
iac_guard_v-0.1.0a1.dist-info/RECORD
iac_guard_v-0.1.0a1.dist-info/WHEEL
iac_guard_v-0.1.0a1.dist-info/entry_points.txt
iac_guard_v-0.1.0a1.dist-info/licenses/LICENSE
iac_guard_v-0.1.0a1.dist-info/licenses/NOTICE
iac_guard_v/__init__.py
iac_guard_v/adapters/__init__.py
iac_guard_v/adapters/base.py
iac_guard_v/adapters/checkov.py
iac_guard_v/adapters/kics.py
iac_guard_v/adapters/phase_e_lock.py
iac_guard_v/adapters/phase_e_runtime.py
iac_guard_v/adapters/trivy.py
iac_guard_v/api.py
iac_guard_v/cli.py
iac_guard_v/config.py
iac_guard_v/diffing.py
iac_guard_v/engine.py
iac_guard_v/enums.py
iac_guard_v/examples/checkov-before-after/after.tf
iac_guard_v/examples/checkov-before-after/before.tf
iac_guard_v/fingerprints.py
iac_guard_v/matching.py
iac_guard_v/models.py
iac_guard_v/normalisation.py
iac_guard_v/oracles/__init__.py
iac_guard_v/oracles/base.py
iac_guard_v/oracles/policies.json
iac_guard_v/oracles/preconditions.py
iac_guard_v/oracles/structural.py
iac_guard_v/policy.py
iac_guard_v/process.py
iac_guard_v/redaction.py
iac_guard_v/report.py
iac_guard_v/reporters/__init__.py
iac_guard_v/reporters/_shared.py
iac_guard_v/reporters/junit.py
iac_guard_v/reporters/markdown.py
iac_guard_v/reporters/sarif.py
iac_guard_v/schemas/config-v1.schema.json
iac_guard_v/schemas/report-v1.schema.json
iac_guard_v/validators/__init__.py
iac_guard_v/validators/base.py
iac_guard_v/validators/kubeconform.py
iac_guard_v/validators/materialization.py
iac_guard_v/validators/registry.py
iac_guard_v/validators/terraform.py
iac_guard_v/validators/tflint.py
iac_guard_v/validators/universe.py
iac_guard_v/workflow.py
iac_guard_v_no_bytecode.pth
```

## Sdist inventory

```text
iac_guard_v-0.1.0a1/.gitignore
iac_guard_v-0.1.0a1/CHANGELOG.md
iac_guard_v-0.1.0a1/CITATION.cff
iac_guard_v-0.1.0a1/CONTRIBUTING.md
iac_guard_v-0.1.0a1/LICENSE
iac_guard_v-0.1.0a1/NOTICE
iac_guard_v-0.1.0a1/PKG-INFO
iac_guard_v-0.1.0a1/README.md
iac_guard_v-0.1.0a1/RESEARCH_SNAPSHOT.md
iac_guard_v-0.1.0a1/ROADMAP.md
iac_guard_v-0.1.0a1/SECURITY.md
iac_guard_v-0.1.0a1/docs/ALPHA_RELEASE_CHECKLIST.md
iac_guard_v-0.1.0a1/docs/spec/THREAT_MODEL.md
iac_guard_v-0.1.0a1/docs/spec/adr/README.md
iac_guard_v-0.1.0a1/examples/checkov-before-after/after.tf
iac_guard_v-0.1.0a1/examples/checkov-before-after/after/main.tf
iac_guard_v-0.1.0a1/examples/checkov-before-after/before.tf
iac_guard_v-0.1.0a1/examples/checkov-before-after/before/main.tf
iac_guard_v-0.1.0a1/packaging/iac_guard_v_no_bytecode.pth
iac_guard_v-0.1.0a1/pyproject.toml
iac_guard_v-0.1.0a1/src/iac_guard_v/__init__.py
iac_guard_v-0.1.0a1/src/iac_guard_v/adapters/__init__.py
iac_guard_v-0.1.0a1/src/iac_guard_v/adapters/base.py
iac_guard_v-0.1.0a1/src/iac_guard_v/adapters/checkov.py
iac_guard_v-0.1.0a1/src/iac_guard_v/adapters/kics.py
iac_guard_v-0.1.0a1/src/iac_guard_v/adapters/phase_e_lock.py
iac_guard_v-0.1.0a1/src/iac_guard_v/adapters/phase_e_runtime.py
iac_guard_v-0.1.0a1/src/iac_guard_v/adapters/trivy.py
iac_guard_v-0.1.0a1/src/iac_guard_v/api.py
iac_guard_v-0.1.0a1/src/iac_guard_v/cli.py
iac_guard_v-0.1.0a1/src/iac_guard_v/config.py
iac_guard_v-0.1.0a1/src/iac_guard_v/diffing.py
iac_guard_v-0.1.0a1/src/iac_guard_v/engine.py
iac_guard_v-0.1.0a1/src/iac_guard_v/enums.py
iac_guard_v-0.1.0a1/src/iac_guard_v/examples/checkov-before-after/after.tf
iac_guard_v-0.1.0a1/src/iac_guard_v/examples/checkov-before-after/before.tf
iac_guard_v-0.1.0a1/src/iac_guard_v/fingerprints.py
iac_guard_v-0.1.0a1/src/iac_guard_v/matching.py
iac_guard_v-0.1.0a1/src/iac_guard_v/models.py
iac_guard_v-0.1.0a1/src/iac_guard_v/normalisation.py
iac_guard_v-0.1.0a1/src/iac_guard_v/oracles/__init__.py
iac_guard_v-0.1.0a1/src/iac_guard_v/oracles/base.py
iac_guard_v-0.1.0a1/src/iac_guard_v/oracles/policies.json
iac_guard_v-0.1.0a1/src/iac_guard_v/oracles/preconditions.py
iac_guard_v-0.1.0a1/src/iac_guard_v/oracles/structural.py
iac_guard_v-0.1.0a1/src/iac_guard_v/policy.py
iac_guard_v-0.1.0a1/src/iac_guard_v/process.py
iac_guard_v-0.1.0a1/src/iac_guard_v/redaction.py
iac_guard_v-0.1.0a1/src/iac_guard_v/report.py
iac_guard_v-0.1.0a1/src/iac_guard_v/reporters/__init__.py
iac_guard_v-0.1.0a1/src/iac_guard_v/reporters/_shared.py
iac_guard_v-0.1.0a1/src/iac_guard_v/reporters/junit.py
iac_guard_v-0.1.0a1/src/iac_guard_v/reporters/markdown.py
iac_guard_v-0.1.0a1/src/iac_guard_v/reporters/sarif.py
iac_guard_v-0.1.0a1/src/iac_guard_v/schemas/config-v1.schema.json
iac_guard_v-0.1.0a1/src/iac_guard_v/schemas/report-v1.schema.json
iac_guard_v-0.1.0a1/src/iac_guard_v/validators/__init__.py
iac_guard_v-0.1.0a1/src/iac_guard_v/validators/base.py
iac_guard_v-0.1.0a1/src/iac_guard_v/validators/kubeconform.py
iac_guard_v-0.1.0a1/src/iac_guard_v/validators/materialization.py
iac_guard_v-0.1.0a1/src/iac_guard_v/validators/registry.py
iac_guard_v-0.1.0a1/src/iac_guard_v/validators/terraform.py
iac_guard_v-0.1.0a1/src/iac_guard_v/validators/tflint.py
iac_guard_v-0.1.0a1/src/iac_guard_v/validators/universe.py
iac_guard_v-0.1.0a1/src/iac_guard_v/workflow.py
```
