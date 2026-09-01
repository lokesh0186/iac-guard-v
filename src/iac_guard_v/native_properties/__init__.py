"""Scanner-independent native semantic properties over protected IaC artifacts.

This package is deliberately separate from :mod:`iac_guard_v.scanner_core`.  A native
property owns its semantic contract and witness; scanner observations can corroborate
it but cannot create or vote on its result.
"""
from .engine import evaluate_native_request, evaluate_native_requests
from .model import (
    NativeArtifactClass,
    NativePropertyCapabilities,
    NativePropertyDefinition,
    NativePropertyImplementationIdentity,
    NativePropertyObservation,
    NativePropertyRequest,
    NativePropertyResult,
    NativePropertyWitness,
    NativeSemanticVersionBinding,
)
from .registry import NATIVE_PROPERTY_REGISTRY, native_registry_identity
from .universe import ProtectedNativeUniverse, load_protected_native_universe


def list_native_properties() -> dict:
    """Return deterministic discovery metadata for the immutable native registry."""
    from ..beta_support import property_catalog
    return property_catalog()


def describe_native_property(property_id: str) -> dict:
    """Describe one exact property ID without exposing mutable registry internals."""
    from ..beta_support import describe_property
    return describe_property(property_id)

__all__ = [
    "NATIVE_PROPERTY_REGISTRY",
    "NativeArtifactClass",
    "NativePropertyCapabilities",
    "NativePropertyDefinition",
    "NativePropertyImplementationIdentity",
    "NativePropertyObservation",
    "NativePropertyRequest",
    "NativePropertyResult",
    "NativePropertyWitness",
    "NativeSemanticVersionBinding",
    "ProtectedNativeUniverse",
    "evaluate_native_request",
    "evaluate_native_requests",
    "describe_native_property",
    "list_native_properties",
    "load_protected_native_universe",
    "native_registry_identity",
]
