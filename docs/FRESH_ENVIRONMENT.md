# Fresh environment for IaC-Guard-V 1.0

Use Python 3.10 through 3.13 and keep IaC-Guard-V and Checkov in separate environments. For operator-controlled local input, follow the complete [protected installation commands](ADVANCED_INSTALLATION.md#install-from-pypi).

The required sequence is:

1. Choose an interpreter that supports copied virtual environments. On macOS, use the standalone interpreter described in the installation guide if framework Python cannot copy its executable.
2. Create both environments with `venv --copies --without-pip`.
3. Use the host installer with `pip --python ENV/bin/python install --no-compile`, pinning `iac-guard-v==1.0.0` and `checkov==3.3.0` separately.
4. Run IaC-Guard-V `doctor --mode local-trusted --checkov-executable ...` before scanning.
5. Run the packet and retain its raw report, logs and summary.

Do not run `checkov --version`, import Checkov, or run other Python commands inside the scanner environment before `doctor`. Checkov can create executable bytecode caches in a writable environment; `doctor` rejects those caches. The packet's own version check explicitly disables bytecode. The product wheel includes its own RECORD-bound startup policy; that policy does not govern a separate Checkov interpreter.

Installation time depends on dependency downloads. A five-minute installation guarantee has not been established. The packet does not need cloud credentials, Terraform providers, a cluster or a model API.

For setup errors, see [bytecode troubleshooting](TROUBLESHOOTING_BYTECODE.md). A successful local doctor may still show an unavailable hardened container as `INCONCLUSIVE`; see the [trust boundary](CI_TRUST_BOUNDARY.md).
