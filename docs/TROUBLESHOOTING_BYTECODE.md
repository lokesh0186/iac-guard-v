# Bytecode setup errors

`CHECKOV_ENVIRONMENT_UNSAFE_BYTECODE` and `WRITABLE_NATIVE_PACKAGE_HAS_EXECUTABLE_CACHE` mean the environment contains executable caches outside the accepted integrity boundary. They are setup failures, not results about the IaC repair.

The IaCSecBench owner encountered these errors after an ordinary install and resolved them by rebuilding with copied, pip-free environments and `--no-compile`. A direct `checkov --version` invocation can also create caches.

Create new environment directories with the [fresh setup](FRESH_ENVIRONMENT.md). Install with the host's `pip --python` option and run `doctor` first. Preserve the failed doctor's output. Avoid deleting individual third-party cache or package files to force acceptance; rebuilding provides a clear provenance boundary.

For a deliberate diagnostic invocation outside the packet, `PYTHONDONTWRITEBYTECODE=1 checkov --version` prevents new Python bytecode. It does not repair an environment that already contains unsafe caches. Packet scripts set that option themselves.

Checkov and IaC-Guard-V must remain separate because their HCL parser distributions overlap. Never remove an integrity check or reinterpret an environment error as `VERIFIED`.
