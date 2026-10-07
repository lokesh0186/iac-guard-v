# Independent reruns

Start with the [IaCSecBench one-pair packet](../adoption/iacsecbench-v1-rerun/README.md) or the [repairer patch runner](../adoption/repairer-eval/README.md). Use a fresh protected environment and exact public inputs.

Record the source commit, case selection, tool versions, input hashes, command, execution mode, raw report, process exit, summary and any setup error. Expected results describe an earlier observation; the new operator must record the result actually produced. `FAILED`, `INCONCLUSIVE`, unsupported requests and operational errors remain distinct.

An unsigned local receipt binds bytes but does not authenticate the operator. Publish reports only after checking them for sensitive identifiers. One run establishes the selected case under that environment; repeated project operation requires separate records.

The IaCSecBench full integration still pins `0.1.0b1`. Its historical benchmark artifacts keep that identity. The stable one-pair packet is a separate command, not an upgrade to the full integration.
