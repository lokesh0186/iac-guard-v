"""Scanner adapters: the only package allowed to understand native tool output."""

from .base import AdapterReason, ScannerContract
from .checkov import (
    CHECKOV_CONTRACT,
    CheckovAdapter,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
)

__all__ = [
    "AdapterReason",
    "CHECKOV_CONTRACT",
    "CheckovAdapter",
    "CheckovKubernetesIdentity",
    "CheckovScanRequest",
    "ScannerContract",
]
