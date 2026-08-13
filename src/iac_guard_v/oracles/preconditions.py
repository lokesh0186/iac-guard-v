"""Authoritative-use preconditions for protected structural oracle evidence."""
from __future__ import annotations

from ..enums import ArtifactKind, Status
from ..models import DomainError
from ..validators.universe import ValidationUniverseResult
from .base import OracleResult, require_trusted_oracle_evidence


def require_authoritative_oracle_precondition(
    oracle: OracleResult, universe: ValidationUniverseResult,
) -> OracleResult:
    """Require exact, role-bound Kubernetes validity before authoritative use.

    This does not make scanner agreement authoritative. It only proves that the
    narrow structural predicate was evaluated for a resource in a complete,
    passing Kubernetes validation universe.
    """
    require_trusted_oracle_evidence(oracle)
    if type(universe) is not ValidationUniverseResult:
        raise DomainError("oracle precondition requires a validation-universe result")
    if (
        universe.validator_id != "kubeconform_validate"
        or universe.status is not Status.PASS
        or universe.kubernetes_result is None
        or universe.kubernetes_result.status is not Status.PASS
    ):
        raise DomainError("oracle precondition requires a passing Kubernetes universe")
    plan = universe._plan
    if (
        oracle.role is not universe.role
        or oracle.sealed_snapshot_identity != plan.sealed_snapshot_identity
        or oracle.file_path not in {item.file_path for item in plan.kubernetes_files}
        or f"{oracle.file_path}:{oracle.resource_identity}"
        not in plan.kubernetes_resource_identities
    ):
        raise DomainError("oracle evidence is not bound to the validated resource universe")
    if oracle.artifact_kind not in {
        ArtifactKind.KUBERNETES_YAML, ArtifactKind.KUBERNETES_JSON,
    }:
        raise DomainError("oracle artifact kind is not Kubernetes")
    matches = tuple(item for item in plan._snapshot.resources if (
        item.file_path == oracle.file_path
        and item.resource_address == oracle.resource_identity
        and item.artifact_kind is oracle.artifact_kind
    ))
    if len(matches) != 1:
        raise DomainError("oracle artifact identity disagrees with sealed snapshot")
    return oracle
