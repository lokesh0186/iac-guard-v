"""Private factories for the reviewed, canonically sealed Phase-E tool lock.

The lock graph is evidence, not user configuration.  Adapters accept only the small
immutable identities produced here, and the factory verifies both the graph seal and
the exact E0.3 contracts before constructing them.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any

from ..models import DomainError, canonical_identifier


_LOCK_CONTEXT = object()
_CACHE_CONTEXT = object()
_SHA = re.compile(r"[0-9a-f]{64}")
_PREFIXED_SHA = re.compile(r"sha256:([0-9a-f]{64})")
_COMMIT = re.compile(r"[0-9a-f]{40}")
PHASE_E_LOCK_CONTRACT = "phase-e-verified-tool-locks-v4"
PHASE_E_LOCK_PAYLOAD_SHA256 = (
    "6a945cd22b117283825bd12724dc29b7dcc406bf014b61af41c6cd2efae4e0a6"
)
_CACHE_MANIFEST_CONTRACT = "phase-e-cache-manifest-v2"
_CACHE_ATTESTATION_CONTRACT = "phase-e-protected-cache-attestation-v2"
_TRIVY_CACHE_PREFIX = "runtime-v2/trivy-cache"


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


def _physical_inventory(root: Path, *, prefix: str = "") -> tuple[dict, ...]:
    """Complete no-follow inventory used by signed-cache and subtree revalidation."""
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise DomainError("protected checks cache is unavailable") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise DomainError("protected checks cache root must be a real directory")
    entries: list[dict] = []

    def inspect(directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise DomainError("protected checks cache directory is unreadable") from exc
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            stored_path = f"{prefix}/{relative}" if prefix else relative
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise DomainError("protected checks cache contains a forbidden symlink")
            if stat.S_ISDIR(metadata.st_mode):
                entries.append({
                    "path": stored_path, "kind": "DIRECTORY",
                    "size": None, "sha256": None,
                })
                inspect(path)
            elif stat.S_ISREG(metadata.st_mode):
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    opened = os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode) or opened.st_size != metadata.st_size:
                        raise DomainError("protected checks cache entry changed during verification")
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(descriptor, 64 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                finally:
                    os.close(descriptor)
                entries.append({
                    "path": stored_path, "kind": "REGULAR_FILE",
                    "size": metadata.st_size, "sha256": digest.hexdigest(),
                })
            else:
                raise DomainError("protected checks cache contains a forbidden special entry")

    inspect(root)
    return tuple(entries)


@dataclass(frozen=True, slots=True)
class ProtectedChecksCacheIdentity:
    """E0.3-signed physical Trivy cache identity; local path is noncanonical."""

    protected_manifest_root: str
    trivy_subtree_root: str
    external_manifest_digest: str
    external_layer_digest: str
    cache_metadata_sha256: str
    cache_attestation_identity: str
    cache_attestation_record_sha256: str
    cache_attestation_signature_sha256: str
    _cache_root: Path = field(repr=False, compare=False)
    _expected_subtree_entries: tuple = field(repr=False, compare=False)
    _trusted_context: InitVar[object] = None
    _trusted_cache_evidence: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        for name in (
            "protected_manifest_root", "trivy_subtree_root", "cache_metadata_sha256",
            "cache_attestation_record_sha256", "cache_attestation_signature_sha256",
        ):
            _sha(getattr(self, name), name)
        _sha(self.external_manifest_digest, "external_manifest_digest", prefixed=True)
        _sha(self.external_layer_digest, "external_layer_digest", prefixed=True)
        if type(self.cache_attestation_identity) is not str or not self.cache_attestation_identity:
            raise DomainError("cache attestation identity is required")
        if not isinstance(self._cache_root, Path) or type(self._expected_subtree_entries) is not tuple:
            raise DomainError("protected checks cache private evidence is invalid")
        if _trusted_context is _CACHE_CONTEXT:
            object.__setattr__(self, "_trusted_cache_evidence", True)

    @property
    def cache_root(self) -> Path:
        return self._cache_root / _TRIVY_CACHE_PREFIX

    def canonical_dict(self) -> dict:
        return {
            "protected_manifest_root": self.protected_manifest_root,
            "trivy_subtree_root": self.trivy_subtree_root,
            "external_manifest_digest": self.external_manifest_digest,
            "external_layer_digest": self.external_layer_digest,
            "cache_metadata_sha256": self.cache_metadata_sha256,
            "cache_attestation_identity": self.cache_attestation_identity,
            "cache_attestation_record_sha256": self.cache_attestation_record_sha256,
            "cache_attestation_signature_sha256": self.cache_attestation_signature_sha256,
        }

    def revalidate(self) -> str:
        try:
            current = _physical_inventory(self.cache_root, prefix=_TRIVY_CACHE_PREFIX)
        except DomainError as exc:
            raise DomainError("CACHE_CHANGED_DURING_EXECUTION") from exc
        if current != self._expected_subtree_entries:
            raise DomainError("CACHE_CHANGED_DURING_EXECUTION")
        root = _canonical_sha256(list(current))
        if root != self.trivy_subtree_root:
            raise DomainError("CACHE_CHANGED_DURING_EXECUTION")
        return root


def _strict_object(raw: bytes, label: str) -> dict:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DomainError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DomainError(f"{label} is malformed") from exc
    if type(value) is not dict:
        raise DomainError(f"{label} must be an object")
    return value


def load_protected_checks_cache_identity(
    lock_path: Path, protected_cache_root: Path,
) -> ProtectedChecksCacheIdentity:
    """Verify the signed E0.3 cache and bind its exact Trivy subtree."""
    locked = load_locked_container_identity(lock_path, "trivy", "linux/amd64")
    repo_root = Path(__file__).resolve().parents[3]
    payload = _strict_object(lock_path.read_bytes(), "Phase-E lock")
    record = payload.get("protected_cache_attestation")
    if type(record) is not dict or record.get("contract") != _CACHE_ATTESTATION_CONTRACT:
        raise DomainError("protected cache attestation contract is invalid")
    evidence_paths = {
        name: repo_root / record[field]
        for name, field in {
            "manifest": "manifest_path", "attestation": "attestation_path",
            "signature": "signature_path", "public_key": "public_key_path",
        }.items()
    }
    for name, field in {
        "manifest": "manifest_sha256", "attestation": "attestation_sha256",
        "signature": "signature_sha256", "public_key": "public_key_sha256",
    }.items():
        path = evidence_paths[name]
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record[field]:
            raise DomainError("protected cache repository attestation evidence changed")
    manifest = _strict_object(evidence_paths["manifest"].read_bytes(), "cache manifest")
    entries = manifest.get("entries")
    if manifest.get("contract") != _CACHE_MANIFEST_CONTRACT or type(entries) is not list:
        raise DomainError("protected cache manifest is invalid")
    if _canonical_sha256(entries) != record.get("manifest_root"):
        raise DomainError("protected cache manifest root is invalid")
    attestation = _strict_object(evidence_paths["attestation"].read_bytes(), "cache attestation")
    if (
        attestation.get("manifest_root") != record.get("manifest_root")
        or attestation.get("manifest_sha256") != record.get("manifest_sha256")
        or attestation.get("signer_identity") != record.get("signer_identity")
    ):
        raise DomainError("protected cache attestation binding is invalid")
    verified = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
         str(evidence_paths["public_key"]), "-sigfile", str(evidence_paths["signature"]),
         "-in", str(evidence_paths["attestation"])],
        check=False, capture_output=True,
    )
    if verified.returncode != 0:
        raise DomainError("protected cache signature verification failed")
    cache_root = protected_cache_root.resolve(strict=True)
    actual = _physical_inventory(cache_root)
    if list(actual) != entries:
        raise DomainError("protected cache physical inventory differs from signed manifest")
    subtree = tuple(
        item for item in actual
        if item["path"].startswith(_TRIVY_CACHE_PREFIX + "/")
    )
    metadata = cache_root / _TRIVY_CACHE_PREFIX / "policy/metadata.json"
    metadata_sha = hashlib.sha256(metadata.read_bytes()).hexdigest()
    return ProtectedChecksCacheIdentity(
        protected_manifest_root=record["manifest_root"],
        trivy_subtree_root=_canonical_sha256(list(subtree)),
        external_manifest_digest=locked.checks_manifest_digest,
        external_layer_digest=locked.checks_layer_digest,
        cache_metadata_sha256=metadata_sha,
        cache_attestation_identity=record["signer_identity"],
        cache_attestation_record_sha256=record["attestation_sha256"],
        cache_attestation_signature_sha256=record["signature_sha256"],
        _cache_root=cache_root, _expected_subtree_entries=subtree,
        _trusted_context=_CACHE_CONTEXT,
    )


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
    "ProtectedChecksCacheIdentity",
    "PHASE_E_LOCK_CONTRACT",
    "PHASE_E_LOCK_PAYLOAD_SHA256",
    "load_locked_container_identity",
    "load_protected_checks_cache_identity",
    "require_locked_identity",
]
