# IaC-Guard-V 1.0 design packet

Status: private design draft. No implementation or release is authorized by
this packet.

This packet defines the work required before `iac-guard-v==1.0.0` can make a
long-term compatibility commitment. The governing rule is that every public
IaC-Guard-V-dependent issue, pull request, example, command, contract, and
report consumer already created must continue to work. Compatibility is a
release gate, not a migration aspiration.

Documents:

- [BETA1_SURFACE_INVENTORY.md](BETA1_SURFACE_INVENTORY.md)
- [IAC_GUARD_V_1_0_SUPPORT_CONTRACT.md](IAC_GUARD_V_1_0_SUPPORT_CONTRACT.md)
- [NATIVE_PROPERTIES_1_0.md](NATIVE_PROPERTIES_1_0.md)
- [SCANNER_AUTHORITY_1_0.md](SCANNER_AUTHORITY_1_0.md)
- [API_CLI_FREEZE_1_0.md](API_CLI_FREEZE_1_0.md)
- [EXTERNAL_COMPATIBILITY_MANIFEST_1_0.md](EXTERNAL_COMPATIBILITY_MANIFEST_1_0.md)
- [RELEASE_QUALITY_GATE_1_0.md](RELEASE_QUALITY_GATE_1_0.md)
- [PRODUCT_DOCUMENTATION_1_0.md](PRODUCT_DOCUMENTATION_1_0.md)
- [IMPLEMENTATION_PLAN_1_0.md](IMPLEMENTATION_PLAN_1_0.md)
- [DESIGN_DECISION_1_0.md](DESIGN_DECISION_1_0.md)
- [CORE_STABILIZATION_PHASES_1_4.md](CORE_STABILIZATION_PHASES_1_4.md)
- [FINALIZATION_PHASES_5_8.md](FINALIZATION_PHASES_5_8.md)

The original design conclusion was `NOT_YET`. The compatibility replay and stable
schema bridge are now implemented and recorded in
`CORE_STABILIZATION_PHASES_1_4.md`. Release supply-chain additions, final product
documentation, release-candidate validation, and the separately authorized release
decision are implemented only in the local private candidate described in
`FINALIZATION_PHASES_5_8.md`. Publication remains separately owner-authorized.
