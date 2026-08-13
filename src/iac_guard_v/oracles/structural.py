"""Closed structural assertions over exact sealed Kubernetes resources."""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass
from importlib.resources import files

from ..engine import (
    SealedVerificationSnapshot,
    _bounded_yaml_documents,
    _strict_json_document,
)
from ..enums import ArtifactKind, Status
from ..models import DomainError, canonical_repo_path, canonical_resource_scope
from .base import ORACLE_CONTRACT, OracleObservation, OracleResult, create_oracle_result


_REQUEST_CONTEXT = object()
_POLICY_RESOURCE = "policies.json"
_CONTROLS = (
    "candidate-policy-disabled",
    "callbacks-disabled",
    "network-disabled",
    "sealed-snapshot-bytes",
    "unpinned-bundles-disabled",
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


def _policy_bytes() -> bytes:
    return files("iac_guard_v.oracles").joinpath(_POLICY_RESOURCE).read_bytes()


def _policies() -> dict[str, dict]:
    raw = _policy_bytes()

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise DomainError("bundled oracle policy contains duplicate keys")
            value[key] = item
        return value

    try:
        payload = json.loads(raw, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DomainError("bundled oracle policy is malformed") from exc
    if payload.get("contract") != "iac-guard-v-bundled-oracle-policy-v1":
        raise DomainError("bundled oracle policy contract is unsupported")
    records = payload.get("policies")
    if type(records) is not list:
        raise DomainError("bundled oracle policy records are malformed")
    result = {}
    for item in records:
        if type(item) is not dict or set(item) != {
            "oracle_id", "predicate", "authoritative_reference", "supported_kinds",
        }:
            raise DomainError("bundled oracle policy record is malformed")
        if item["oracle_id"] in result:
            raise DomainError("bundled oracle policy ids are duplicated")
        result[item["oracle_id"]] = item
    return result


@dataclass(frozen=True, slots=True)
class ProtectedOracleRequest:
    oracle_id: str
    snapshot: SealedVerificationSnapshot
    file_path: str
    artifact_kind: ArtifactKind
    resource_identity: str
    _trusted_context: object = None

    def __post_init__(self) -> None:
        if self._trusted_context is not _REQUEST_CONTEXT:
            raise DomainError("oracle request requires the protected factory")
        if type(self.snapshot) is not SealedVerificationSnapshot or not self.snapshot._trusted:
            raise DomainError("oracle request requires a trusted sealed snapshot")
        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        object.__setattr__(
            self, "resource_identity",
            canonical_resource_scope(self.resource_identity, "oracle resource identity"),
        )
        matches = tuple(item for item in self.snapshot.resources if (
            item.file_path == self.file_path
            and item.resource_address == self.resource_identity
            and item.artifact_kind is self.artifact_kind
        ))
        if len(matches) != 1:
            raise DomainError("oracle target is not an exact sealed resource")
        if self.oracle_id not in _policies():
            raise DomainError("oracle id is not in the protected registry")


def create_protected_oracle_request(
    *, oracle_id: str, snapshot: SealedVerificationSnapshot, file_path: str,
    artifact_kind: ArtifactKind, resource_identity: str,
) -> ProtectedOracleRequest:
    return ProtectedOracleRequest(
        oracle_id, snapshot, file_path, artifact_kind, resource_identity,
        _trusted_context=_REQUEST_CONTEXT,
    )


def _documents(request: ProtectedOracleRequest) -> tuple[dict, ...]:
    matches = tuple(item for item in request.snapshot.files if item.file_path == request.file_path)
    if len(matches) != 1:
        raise DomainError("oracle source bytes are not unique in sealed snapshot")
    source = matches[0]
    if request.artifact_kind is ArtifactKind.KUBERNETES_YAML:
        documents = _bounded_yaml_documents(source.content)
    elif request.artifact_kind is ArtifactKind.KUBERNETES_JSON:
        documents = (_strict_json_document(source.content),)
    else:
        raise DomainError("structural Kubernetes oracle does not support artifact kind")
    expanded = []
    for item in documents:
        if type(item) is dict and item.get("kind") == "List":
            children = item.get("items")
            if type(children) is not list:
                raise DomainError("oracle Kubernetes List items are malformed")
            expanded.extend(children)
        else:
            expanded.append(item)
    return tuple(expanded)


def _identity(document: dict) -> str:
    metadata = document.get("metadata")
    if type(metadata) is not dict:
        return ""
    values = (
        document.get("apiVersion"), document.get("kind"),
        metadata.get("namespace", "default"), metadata.get("name"),
    )
    if any(type(item) is not str or not item.strip() for item in values):
        return ""
    return "/".join(item.strip() for item in values)


def _containers(document: dict) -> tuple[dict, ...] | None:
    kind = document.get("kind")
    try:
        if kind == "Pod":
            spec = document["spec"]
        elif kind == "CronJob":
            spec = document["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        else:
            spec = document["spec"]["template"]["spec"]
    except (KeyError, TypeError):
        return None
    if type(spec) is not dict:
        return None
    ordinary = spec.get("containers", [])
    initial = spec.get("initContainers", [])
    if type(ordinary) is not list or type(initial) is not list:
        return None
    values = tuple((*ordinary, *initial))
    if any(type(item) is not dict for item in values):
        return None
    return values


def _evaluate(policy: dict, document: dict) -> tuple[Status, str, tuple[OracleObservation, ...]]:
    if document.get("kind") not in policy["supported_kinds"]:
        return Status.UNSUPPORTED, "RESOURCE_KIND_UNSUPPORTED", ()
    containers = _containers(document)
    if containers is None or not containers:
        return Status.INCONCLUSIVE, "CONTAINER_SCOPE_UNRESOLVED", ()
    observations = []
    for index, container in enumerate(containers):
        name = container.get("name")
        label = name if type(name) is str and name else str(index)
        context = container.get("securityContext")
        context = context if type(context) is dict else {}
        def boolean(value: object) -> bool | None:
            if type(value) is bool:
                return value
            if type(value) is str and value.lower() in {"true", "false"}:
                return value.lower() == "true"
            return None
        if policy["predicate"] == "no_container_is_privileged":
            satisfied = boolean(context.get("privileged")) is not True
            detail = "securityContext.privileged is not true"
            path = f"containers/{label}/securityContext/privileged"
        elif policy["predicate"] == "all_containers_explicitly_disable_privilege_escalation":
            satisfied = boolean(context.get("allowPrivilegeEscalation")) is False
            detail = "securityContext.allowPrivilegeEscalation is explicitly false"
            path = f"containers/{label}/securityContext/allowPrivilegeEscalation"
        else:
            return Status.ERROR, "PROTECTED_POLICY_UNSUPPORTED", ()
        observations.append(OracleObservation(
            path, "SATISFIED" if satisfied else "VIOLATED", detail,
        ))
    result = Status.PASS if all(item.result == "SATISFIED" for item in observations) else Status.FAIL
    return result, "ASSERTION_SATISFIED" if result is Status.PASS else "ASSERTION_VIOLATED", tuple(observations)


class ProtectedOracleRegistry:
    """Closed registry; it accepts no callbacks, policy bytes, or precomputed output."""

    @property
    def policy_sha256(self) -> str:
        return hashlib.sha256(_policy_bytes()).hexdigest()

    @property
    def implementation_build_identity(self) -> str:
        return _canonical_sha({
            "contract": ORACLE_CONTRACT,
            "base": inspect.getsource(OracleResult),
            "implementation": inspect.getsource(_evaluate),
            "loader": inspect.getsource(_policies),
            "policy_sha256": self.policy_sha256,
        })

    @property
    def oracle_ids(self) -> tuple[str, ...]:
        return tuple(sorted(_policies()))

    def execute(self, request: ProtectedOracleRequest) -> OracleResult:
        if type(request) is not ProtectedOracleRequest or request._trusted_context is not _REQUEST_CONTEXT:
            raise DomainError("oracle registry rejects caller-authored requests")
        policy = _policies()[request.oracle_id]
        try:
            matching = tuple(
                item for item in _documents(request)
                if type(item) is dict and _identity(item) == request.resource_identity
            )
            if len(matching) != 1:
                status, reason, observations = Status.INCONCLUSIVE, "TARGET_SCOPE_UNRESOLVED", ()
            else:
                status, reason, observations = _evaluate(policy, matching[0])
        except DomainError:
            status, reason, observations = Status.ERROR, "SEALED_ARTIFACT_PARSE_ERROR", ()
        raw = {
            "oracle_id": request.oracle_id,
            "resource_identity": request.resource_identity,
            "status": status.value,
            "reason": reason,
            "observations": [item.canonical_dict() for item in observations],
        }
        encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        return create_oracle_result(
            oracle_id=request.oracle_id,
            contract_version=ORACLE_CONTRACT,
            implementation_build_identity=self.implementation_build_identity,
            protected_policy_sha256=self.policy_sha256,
            sealed_snapshot_identity=request.snapshot.snapshot_sha256,
            role=request.snapshot.role,
            file_path=request.file_path,
            artifact_kind=request.artifact_kind,
            resource_identity=request.resource_identity,
            status=status,
            reason=reason,
            observations=observations,
            raw_output_sha256=digest,
            canonical_output_sha256=digest,
            execution_controls=_CONTROLS,
            authoritative_reference=policy["authoritative_reference"],
        )
