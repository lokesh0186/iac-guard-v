"""Protected deterministic oracle implementations."""

from .base import OracleObservation, OracleResult, require_trusted_oracle_evidence
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
]
