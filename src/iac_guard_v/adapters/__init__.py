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
    checkov_occurrence_token,
    evaluate_checkov_target,
    require_trusted_checkov_target_evidence,
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
    "checkov_occurrence_token",
    "evaluate_checkov_target",
    "require_trusted_checkov_target_evidence",
]
