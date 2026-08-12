"""Private factories for the reviewed, canonically sealed Phase-E tool lock.

The lock graph is evidence, not user configuration.  Adapters accept only the small
immutable identities produced here, and the factory verifies both the graph seal and
the exact E0.3 contracts before constructing them.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any

from ..models import DomainError, canonical_identifier


_LOCK_CONTEXT = object()
_SHA = re.compile(r"[0-9a-f]{64}")
_PREFIXED_SHA = re.compile(r"sha256:([0-9a-f]{64})")
_COMMIT = re.compile(r"[0-9a-f]{40}")
PHASE_E_LOCK_CONTRACT = "phase-e-verified-tool-locks-v4"
PHASE_E_LOCK_PAYLOAD_SHA256 = (
    "6a945cd22b117283825bd12724dc29b7dcc406bf014b61af41c6cd2efae4e0a6"
)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
    ).hexdigest()


def _lock_seal(payload: dict) -> str:
    unsigned = copy.deepcopy(payload)
    unsigned.pop("lock_payload_sha256", None)
    return _canonical_sha256(unsigned)


def _sha(value: Any, field_name: str, *, prefixed: bool = False) -> str:
    matcher = _PREFIXED_SHA if prefixed else _SHA
    if type(value) is not str or matcher.fullmatch(value) is None:
        raise DomainError(f"{field_name} must be a canonical SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class LockedContainerIdentity:
    """Portable executable identity for one E0.3-authorized platform child."""

    tool: str
    version: str
    architecture: str
    execution_reference: str
    image_index_digest: str
    image_architecture_digest: str
    release_commit: str
    archive_sha256: str
    invocation_contract: str
    output_fixture_sha256: str
    lock_payload_sha256: str
    policy_inventory_digest: str
    checks_manifest_digest: str = ""
    checks_layer_digest: str = ""
    checks_cache_identity: str = ""
    source: str = "bundled"
    fallback_used: bool = False
    _trusted_context: InitVar[object] = None
    _trusted_lock_evidence: bool = field(
        init=False, default=False, repr=False, compare=False
    )

    def __post_init__(self, _trusted_context: object) -> None:
        object.__setattr__(self, "tool", canonical_identifier(self.tool, "locked tool"))
        object.__setattr__(
            self, "version", canonical_identifier(self.version, "locked tool version")
        )
        if self.architecture not in {"linux/amd64", "linux/arm64"}:
            raise DomainError("locked architecture is unsupported")
        for name in (
            "image_index_digest", "image_architecture_digest",
        ):
            _sha(getattr(self, name), name, prefixed=True)
        for name in (
            "archive_sha256", "output_fixture_sha256",
            "lock_payload_sha256", "policy_inventory_digest",
        ):
            _sha(getattr(self, name), name)
        if type(self.release_commit) is not str or _COMMIT.fullmatch(self.release_commit) is None:
            raise DomainError("release_commit must be a full lowercase Git commit")
        if self.checks_manifest_digest:
            _sha(self.checks_manifest_digest, "checks_manifest_digest", prefixed=True)
        if self.checks_layer_digest:
            _sha(self.checks_layer_digest, "checks_layer_digest", prefixed=True)
        object.__setattr__(
            self, "invocation_contract",
            canonical_identifier(self.invocation_contract, "invocation contract"),
        )
        object.__setattr__(self, "source", canonical_identifier(self.source, "source"))
        expected_reference = self.execution_reference.rsplit("@", 1)
        if len(expected_reference) != 2 or expected_reference[1] != self.image_architecture_digest:
            raise DomainError("execution reference does not bind its architecture digest")
        if type(self.fallback_used) is not bool:
            raise DomainError("fallback_used must be a bool")
        if _trusted_context is _LOCK_CONTEXT:
            object.__setattr__(self, "_trusted_lock_evidence", True)

    def canonical_dict(self) -> dict:
        return {
            "tool": self.tool,
            "version": self.version,
            "architecture": self.architecture,
            "execution_reference": self.execution_reference,
            "image_index_digest": self.image_index_digest,
            "image_architecture_digest": self.image_architecture_digest,
            "release_commit": self.release_commit,
            "archive_sha256": self.archive_sha256,
            "invocation_contract": self.invocation_contract,
            "output_fixture_sha256": self.output_fixture_sha256,
            "lock_payload_sha256": self.lock_payload_sha256,
            "policy_inventory_digest": self.policy_inventory_digest,
            "checks_manifest_digest": self.checks_manifest_digest,
            "checks_layer_digest": self.checks_layer_digest,
            "checks_cache_identity": self.checks_cache_identity,
            "source": self.source,
            "fallback_used": self.fallback_used,
        }

    @property
    def environment_digest(self) -> str:
        return _canonical_sha256(self.canonical_dict())

    @property
    def launcher_digest(self) -> str:
        return self.image_architecture_digest.removeprefix("sha256:")


def require_locked_identity(value: object, tool: str) -> LockedContainerIdentity:
    if type(value) is not LockedContainerIdentity or not value._trusted_lock_evidence:
        raise DomainError("scanner identity must come from the reviewed Phase-E lock")
    if value.tool != tool:
        raise DomainError(f"{tool} adapter received a {value.tool} lock")
    return value


def load_locked_container_identity(
    lock_path: Path, tool: str, architecture: str
) -> LockedContainerIdentity:
    """Load one tool identity only after the exact E0.3 graph seal is verified."""
    if not isinstance(lock_path, Path):
        raise DomainError("lock_path must be pathlib.Path")
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DomainError("Phase-E lock cannot be decoded") from exc
    if type(payload) is not dict or payload.get("lock_contract") != PHASE_E_LOCK_CONTRACT:
        raise DomainError("Phase-E lock contract is unsupported")
    seal = payload.get("lock_payload_sha256")
    if (
        seal != PHASE_E_LOCK_PAYLOAD_SHA256
        or seal != _lock_seal(payload)
    ):
        raise DomainError("Phase-E lock graph differs from the reviewed E0.3 seal")
    if tool not in {"kics", "trivy"} or architecture not in {
        "linux/amd64", "linux/arm64",
    }:
        raise DomainError("tool or architecture is outside the E0.3 adapter lock")
    record = payload.get("tools", {}).get(tool)
    if type(record) is not dict:
        raise DomainError("locked tool record is absent")
    expected = {
        "kics": ("2.1.20", "kics-adapter-contract-research-v1"),
        "trivy": ("0.73.0", "trivy-config-adapter-contract-research-v1"),
    }[tool]
    if (
        record.get("version") != expected[0]
        or record.get("invocation_contract", {}).get("contract_version") != expected[1]
    ):
        raise DomainError("tool version or invocation contract differs from E0.3")
    container = record.get("container", {})
    archive = record.get("archives", {}).get(architecture, {})
    release = record.get("release", {})
    fixture = record.get("output_schema_fixture", {})
    image_index = _sha(container.get("index_digest"), "image index", prefixed=True)
    image_child = _sha(
        container.get("architecture_digests", {}).get(architecture),
        "image architecture", prefixed=True,
    )
    execution_reference = container.get("execution_references", {}).get(architecture)
    if execution_reference != f"{container.get('image')}@{image_child}":
        raise DomainError("locked execution reference is not canonical")
    checks = record.get("checks", {}) if tool == "trivy" else {}
    if tool == "trivy" and (
        checks.get("selected_source") != "external"
        or checks.get("fallback_used") is not False
    ):
        raise DomainError("Trivy lock does not select the external checks bundle")
    policy_payload = (
        {
            "image": image_child,
            "release": release.get("commit"),
            "fixture": fixture.get("sha256"),
        }
        if tool == "kics"
        else {
            "manifest": checks.get("external_manifest_digest"),
            "layer": checks.get("external_layer_digest"),
            "cache": checks.get("cache_identity"),
            "source": checks.get("selected_source"),
            "fallback_used": checks.get("fallback_used"),
        }
    )
    return LockedContainerIdentity(
        tool=tool,
        version=record["version"],
        architecture=architecture,
        execution_reference=execution_reference,
        image_index_digest=image_index,
        image_architecture_digest=image_child,
        release_commit=release.get("commit"),
        archive_sha256=_sha(archive.get("sha256"), "archive SHA-256"),
        invocation_contract=expected[1],
        output_fixture_sha256=_sha(fixture.get("sha256"), "fixture SHA-256"),
        lock_payload_sha256=seal,
        policy_inventory_digest=_canonical_sha256(policy_payload),
        checks_manifest_digest=checks.get("external_manifest_digest", ""),
        checks_layer_digest=checks.get("external_layer_digest", ""),
        checks_cache_identity=checks.get("cache_identity", ""),
        source=checks.get("selected_source", "bundled"),
        fallback_used=checks.get("fallback_used", False),
        _trusted_context=_LOCK_CONTEXT,
    )


__all__ = [
    "LockedContainerIdentity",
    "PHASE_E_LOCK_CONTRACT",
    "PHASE_E_LOCK_PAYLOAD_SHA256",
    "load_locked_container_identity",
    "require_locked_identity",
]
