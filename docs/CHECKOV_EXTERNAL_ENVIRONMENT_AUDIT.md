# Existing pre-commit-terraform installation audit

Reference: upstream 443ffdff1cc1663b701ae73e7459029fe883455a; released IaC-Guard-V
1.0.1; Linux/arm64, Python 3.12.11. Earlier measurements remain unchanged in their
sealed diagnostic packet. This addendum separates installation facts from trust
decisions; none is a claim of compromise.

| Invariant | Expected in 1.0.1 | Actual upstream shape / why | Reason for check | Can normal packaging satisfy it? / relaxation consequence |
| --- | --- | --- | --- | --- |
| Bytecode | No pyc or cache directories in scanner/dependency tree | 6,519 pyc at 3.3.0; ordinary pip compilation and CLI imports create them | Cache bytes can override reviewed source, including timestamp-valid caches; `-B` only prevents writes | Yes, but deleting or disabling global caches regresses other users. Merely ignoring cache files weakens authority; a separate invocation must provably exclude them |
| RECORD presence | Wheel manifests available | Present for Checkov and dependencies | Establish installed file provenance and detect altered source | Valid normal shape; retain source verification |
| RECORD completeness | Every recorded non-cache target exists at original path | Multistage copy moves console scripts and omits auxiliary docs; stale base pip metadata also survives the merge. Observed missing non-cache paths are `bin`/`share` assets | Do not accept missing executable/dependency content or an invented complete installation | Source identity can be established with exact published Checkov bytes and a protected build manifest for the actual layout. Silently skipping missing rows in the legacy contract would weaken it |
| Launcher | Executable regular file tied to interpreter | `/usr/bin/checkov` is a regular copied pip console script; its shebang names `/usr/local/bin/python3` | Bind the executable actually invoked | Valid normal packaging; retain original hook and launcher bytes |
| Interpreter | Shebang target itself nonsymlink | `/usr/local/bin/python3` is a normal alias to `python3.12` | Avoid mutable indirection between validation and execution | A new invocation may resolve and bind the regular target, then execute that exact target. Removing the legacy rejection without binding the target would weaken identity |
| Metadata | Complete coherent prefix | Runtime base pip metadata and copied builder metadata coexist; ordinary `pip check` is clean | Metadata can affect dependency selection and imports | Build-time provenance must describe the actual layout and bind metadata; do not equate pip check with provenance |
| Ownership/layout | Operator-controlled environment outside scan workspace | Global `/usr/local` runtime; product can live in `/opt` SSP venv | Candidate input must not control executable/import/policy roots | Valid operator-controlled layout; all roots must remain explicit, identity-bound and outside candidate workspace |
| Dependencies | All executable source recorded and bound | Single global Checkov dependency tree; product needs python-hcl2 rather than Checkov's bc-python-hcl2 fork | Parser and transitive code can alter results | Keep Checkov's interpreter/import roots separate from the product's import resolution, even when the product venv exposes global packages |
| Checkov package | Complete regular source tree | Package source bytes match the corresponding published wheel in the measured installation | Protect scanner implementation | Preserve exact-version published-package digest checks |
| Policies | Installed policy/check inventory bound | Seven existing implementation files changed between endpoints; one check added | Check IDs alone do not freeze policy semantics | Qualify explicit properties and versions. Do not promote changed policies merely because JSON still parses |
| Import path | No candidate config, path or startup injection | A usual Python startup processes site and caches | `.pth`, sitecustomize, user-site, cwd and caches can affect execution | A dedicated source-only invocation must fix import roots, bypass site processing and exclude cached bytecode; normal hook startup remains untouched |
| SSP behavior | Product and scanner identities remain separate | SSP exposes global Checkov; product-local hcl2 shadows Checkov's fork only inside the product process | Sharing visibility must not change scanner parser selection | Scanner subprocess must use the existing global distribution with explicit protected import roots; no duplicate scanner installation is required in principle |

The standard bytecode and layout differences are not evidence of tampering.
Missing importable source, changed recorded source, candidate-controlled paths or
unbound runtime bytes are integrity failures. A new supported packaging shape
needs its own reproducible execution and provenance contract; legacy checks are
not to be silently relaxed.
