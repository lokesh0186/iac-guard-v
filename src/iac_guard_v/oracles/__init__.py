"""Protected deterministic oracle implementations."""

from .base import OracleObservation, OracleResult, require_trusted_oracle_evidence
from .preconditions import require_authoritative_oracle_precondition
from .structural import (
    ProtectedOracleRegistry,
    ProtectedOracleRequest,
    create_protected_oracle_request,
)

__all__ = [
    "OracleObservation",
    "OracleResult",
    "ProtectedOracleRegistry",
    "ProtectedOracleRequest",
    "create_protected_oracle_request",
    "require_trusted_oracle_evidence",
    "require_authoritative_oracle_precondition",
]
