# Evaluate an existing repair artifact

The [bring-your-own-repairer runner](../adoption/repairer-eval/README.md) accepts a case manifest, baseline directory and an existing Git text patch. Each case declares one exact Checkov finding and resource identity. It emits `results.json`, `summary.csv`, per-case raw reports and an unsigned `verification_receipt.json`.

The interface does not generate repairs or call model providers. It does not promote scanner outputs supplied by a caller to authoritative evidence. Use Checkov 3.3.0 separately and IaC-Guard-V 1.0.0 within the [declared support boundary](../SUPPORTED_SCOPE.md).

Predeclare case selection, retain exclusions and inconclusive results, preserve licenses, and keep historical scanner versions distinct from the verifier's environment. Do not call this path scanner-independent: the repair verdict uses Checkov-backed evidence. For a scanner-independent study, select one of the supported native properties and use its exact request schema; generic Terraform attributes and container security-context properties are outside that native surface.

The [TerraRepair adapter](../adoption/terrarepair-v1/README.md) shows how to convert already published repairs. Its initial ten-case stable run was entirely inconclusive, a recorded limitation that must remain visible.
