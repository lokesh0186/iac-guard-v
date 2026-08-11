"""Scanner adapters: the only package allowed to understand native tool output."""

from .base import AdapterReason, ScannerContract
from .checkov import (
    CHECKOV_CONTRACT,
    CheckovAdapter,
    CheckovDistributionIdentity,
    CheckovEligibleFileEvidence,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
    CheckovTargetEvidence,
    checkov_distribution_identity,
    evaluate_checkov_target,
)

__all__ = [
    "AdapterReason",
    "CHECKOV_CONTRACT",
    "CheckovAdapter",
    "CheckovDistributionIdentity",
    "CheckovEligibleFileEvidence",
    "CheckovKubernetesIdentity",
    "CheckovScanRequest",
    "CheckovTargetEvidence",
    "ScannerContract",
    "checkov_distribution_identity",
    "evaluate_checkov_target",
]
