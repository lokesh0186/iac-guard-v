"""IaC-Guard-V: differential verification for infrastructure-as-code changes.

Scanners report what they observe. This tool decides whether a proposed change actually
fixed what it claimed to fix, without hiding findings, deleting the resource, losing
scanner coverage, or turning a scanner failure into a pass.

The public API is deliberately small and is added as each phase lands. Through Review 2
it includes the typed domain, hardened native process boundary, deterministic finding
identity/matching, and the locked/offline Checkov adapter. No model-provider path exists.
"""
from __future__ import annotations

__version__ = "0.1.0a1"

from . import (  # noqa: F401
    adapters,
    diffing,
    enums,
    fingerprints,
    matching,
    models,
    normalisation,
    process,
    redaction,
)

__all__ = [
    "__version__",
    "adapters",
    "diffing",
    "enums",
    "fingerprints",
    "matching",
    "models",
    "normalisation",
    "process",
    "redaction",
]
