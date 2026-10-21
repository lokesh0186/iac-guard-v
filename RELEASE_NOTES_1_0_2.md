# IaC-Guard-V 1.0.2

This maintenance version adds explicit Checkov version/property authority profiles and an
opt-in way to reuse one existing Checkov installation from a separate product
venv. It preserves the existing strict installation path and the ordinary Checkov
executable, caches and hook behavior.

The qualified version set is 3.3.0 through 3.3.30, enumerated explicitly. Additional
versions are limited to the properties in the packaged profile. CKV_K8S_40 remains
excluded on 3.3.8 and newer because its semantics changed. Unknown future versions
and unqualified properties fail closed with a specific compatibility diagnostic;
native properties remain scanner-independent.

See [the compatibility and authority contract](docs/CHECKOV_COMPATIBILITY.md) for
property lists, build requirements, and CHECKOV_VERSION behavior. The 18 native
V1 properties, schemas, public interfaces and Python 3.10–3.13 support remain
unchanged. Compatibility is not a promise to support arbitrary Checkov versions.

The controlled launcher also disables Checkov’s optional PyPI update notification,
avoiding network lookup latency during version probes. Source-only execution,
runtime drift detection and the ordinary Checkov path remain unchanged.

Implementation and validation preparation were assisted by Codex.
