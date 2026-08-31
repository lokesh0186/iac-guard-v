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
    "load_protected_native_universe",
    "native_registry_identity",
]
