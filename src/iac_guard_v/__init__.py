"""IaC-Guard-V: differential verification for infrastructure-as-code changes.

Scanners report what they observe. This tool decides whether a proposed change actually
fixed what it claimed to fix, without hiding findings, deleting the resource, losing
scanner coverage, or turning a scanner failure into a pass.

The public API is deliberately small and is added as each phase lands. Phase D1 provides
the typed vocabulary and the immutable domain models; nothing here executes a scanner or
contacts a network yet.
"""
from __future__ import annotations

__version__ = "0.1.0a1"

from . import enums, models  # noqa: F401

__all__ = ["__version__", "enums", "models"]
