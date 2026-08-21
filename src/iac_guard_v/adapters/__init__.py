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
from .kics import (
    KICS_ADAPTER_CONTRACT,
    KICS_CONTRACT,
    KicsAdapter,
    KicsExecutionEvidence,
    KicsScanRequest,
    create_kics_scan_request,
)
from .phase_e_lock import (
    LockedContainerIdentity,
    ProtectedPhaseEEvidenceBundle,
    load_locked_container_identity,
    load_protected_phase_e_evidence,
)
from .trivy import (
    TRIVY_ADAPTER_CONTRACT,
    TRIVY_CONTRACT,
    TrivyAdapter,
    TrivyExecutionEvidence,
    TrivyScanRequest,
    create_trivy_scan_request,
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
    "KICS_ADAPTER_CONTRACT",
    "KICS_CONTRACT",
    "KicsAdapter",
    "KicsExecutionEvidence",
    "KicsScanRequest",
    "LockedContainerIdentity",
    "ProtectedPhaseEEvidenceBundle",
    "ScannerContract",
    "TRIVY_ADAPTER_CONTRACT",
    "TRIVY_CONTRACT",
    "TrivyAdapter",
    "TrivyExecutionEvidence",
    "TrivyScanRequest",
    "checkov_distribution_identity",
    "checkov_occurrence_token",
    "evaluate_checkov_target",
    "create_kics_scan_request",
    "create_trivy_scan_request",
    "load_locked_container_identity",
    "load_protected_phase_e_evidence",
    "require_trusted_checkov_target_evidence",
]
