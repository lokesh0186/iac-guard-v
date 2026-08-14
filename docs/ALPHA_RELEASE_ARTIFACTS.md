# ALPHA.2 clean-build artifact record

This records the fresh local artifacts produced by the bounded ALPHA.2 gate. It is not
a publication authorization. The arXiv/paper-tip gate in ALPHA_RELEASE_CHECKLIST.md is
still blocked.

| Artifact | Bytes | SHA-256 | Files |
| --- | ---: | --- | ---: |
| `iac_guard_v-0.1.0a1-py3-none-any.whl` | 238275 | `928312f7a44d3e790c6da058a99ed4b998e6519ec08d53c2002d81441a43e1ff` | 49 |
| `iac_guard_v-0.1.0a1.tar.gz` | 229679 | `9175652f381de2fcc60b589fbe0317b020a9259f5deaa7397e342181f7027171` | 60 |

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
iac_guard_v-0.1.0a1/examples/checkov-before-after/before.tf
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
