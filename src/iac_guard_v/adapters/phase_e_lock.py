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
_BUNDLE_CONTEXT = object()
_SCHEMA_CONTEXT = object()
PHASE_E_EVIDENCE_BUNDLE_CONTRACT = "protected-phase-e-evidence-bundle-v1"


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


def _regular_nofollow_bytes(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DomainError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DomainError(f"{label} must be a nonsymlink regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            raise DomainError(f"{label} changed during verification")
        chunks = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


@dataclass(frozen=True, slots=True)
class ProtectedPhaseEEvidenceBundle:
    """Portable Phase-E lock and signed-cache evidence rooted outside adapter input."""

    contract: str
    lock_sha256: str
    manifest_sha256: str
    attestation_sha256: str
    signature_sha256: str
    public_key_sha256: str
    expected_manifest_root: str
    cache_attestation_identity: str
    runtime_evidence_record_identities_sha256: str
    container_engine_contract: str
    _root: Path = field(repr=False, compare=False)
    _lock_path: Path = field(repr=False, compare=False)
    _manifest_path: Path = field(repr=False, compare=False)
    _attestation_path: Path = field(repr=False, compare=False)
    _signature_path: Path = field(repr=False, compare=False)
    _public_key_path: Path = field(repr=False, compare=False)
    _trusted_context: InitVar[object] = None
    _trusted_evidence: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if self.contract != PHASE_E_EVIDENCE_BUNDLE_CONTRACT:
            raise DomainError("Phase-E evidence bundle contract is unsupported")
        for name in (
            "lock_sha256", "manifest_sha256", "attestation_sha256",
            "signature_sha256", "public_key_sha256", "expected_manifest_root",
            "runtime_evidence_record_identities_sha256",
        ):
            _sha(getattr(self, name), name)
        if type(self.cache_attestation_identity) is not str or not self.cache_attestation_identity:
            raise DomainError("Phase-E cache attestation identity is required")
        if type(self.container_engine_contract) is not str or not self.container_engine_contract:
            raise DomainError("Phase-E container engine contract is required")
        for path in (
            self._root, self._lock_path, self._manifest_path, self._attestation_path,
            self._signature_path, self._public_key_path,
        ):
            if not isinstance(path, Path):
                raise DomainError("Phase-E evidence bundle private path is invalid")
        if _trusted_context is _BUNDLE_CONTEXT:
            object.__setattr__(self, "_trusted_evidence", True)

    @property
    def identity(self) -> str:
        return _canonical_sha256(self.canonical_dict())

    def canonical_dict(self) -> dict:
        return {
            "contract": self.contract,
            "lock_sha256": self.lock_sha256,
            "manifest_sha256": self.manifest_sha256,
            "attestation_sha256": self.attestation_sha256,
            "signature_sha256": self.signature_sha256,
            "public_key_sha256": self.public_key_sha256,
            "expected_manifest_root": self.expected_manifest_root,
            "cache_attestation_identity": self.cache_attestation_identity,
            "runtime_evidence_record_identities_sha256": (
                self.runtime_evidence_record_identities_sha256
            ),
            "container_engine_contract": self.container_engine_contract,
        }


def load_protected_phase_e_evidence(root: Path) -> ProtectedPhaseEEvidenceBundle:
    """Load a portable bundle from an explicit protected root, never from __file__."""
    if not isinstance(root, Path):
        raise DomainError("protected Phase-E evidence root must be pathlib.Path")
    try:
        canonical = root.resolve(strict=True)
        metadata = root.lstat()
    except (OSError, RuntimeError) as exc:
        raise DomainError("protected Phase-E evidence root is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise DomainError("protected Phase-E evidence root must be a real directory")
    lock_path = canonical / "tools/locks/phase-e-locks.json"
    lock_raw = _regular_nofollow_bytes(lock_path, "Phase-E lock")
    lock = _strict_object(lock_raw, "Phase-E lock")
    record = lock.get("protected_cache_attestation")
    if type(record) is not dict or record.get("contract") != _CACHE_ATTESTATION_CONTRACT:
        raise DomainError("protected cache attestation record is invalid")

    def protected_path(field_name: str) -> Path:
        value = record.get(field_name)
        if type(value) is not str or not value or Path(value).is_absolute():
            raise DomainError("protected evidence path must be repository relative")
        path = canonical / value
        try:
            path.relative_to(canonical)
        except ValueError as exc:
            raise DomainError("protected evidence path escapes its bundle") from exc
        return path

    paths = {
        "manifest": protected_path("manifest_path"),
        "attestation": protected_path("attestation_path"),
        "signature": protected_path("signature_path"),
        "public_key": protected_path("public_key_path"),
    }
    raw = {
        name: _regular_nofollow_bytes(path, f"Phase-E {name}")
        for name, path in paths.items()
    }
    expected = {
        "manifest": "manifest_sha256", "attestation": "attestation_sha256",
        "signature": "signature_sha256", "public_key": "public_key_sha256",
    }
    for name, field_name in expected.items():
        if hashlib.sha256(raw[name]).hexdigest() != record.get(field_name):
            raise DomainError("protected Phase-E evidence bytes changed")
    manifest = _strict_object(raw["manifest"], "cache manifest")
    if (
        manifest.get("contract") != _CACHE_MANIFEST_CONTRACT
        or _canonical_sha256(manifest.get("entries")) != record.get("manifest_root")
    ):
        raise DomainError("protected Phase-E cache manifest is invalid")
    attestation = _strict_object(raw["attestation"], "cache attestation")
    runtime_records = attestation.get("runtime_record_identities")
    if type(runtime_records) is not dict:
        raise DomainError("Phase-E runtime evidence records are absent")
    return ProtectedPhaseEEvidenceBundle(
        contract=PHASE_E_EVIDENCE_BUNDLE_CONTRACT,
        lock_sha256=hashlib.sha256(lock_raw).hexdigest(),
        manifest_sha256=record["manifest_sha256"],
        attestation_sha256=record["attestation_sha256"],
        signature_sha256=record["signature_sha256"],
        public_key_sha256=record["public_key_sha256"],
        expected_manifest_root=record["manifest_root"],
        cache_attestation_identity=record["signer_identity"],
        runtime_evidence_record_identities_sha256=_canonical_sha256(runtime_records),
        container_engine_contract=attestation.get("container_engine"),
        _root=canonical, _lock_path=lock_path, _manifest_path=paths["manifest"],
        _attestation_path=paths["attestation"], _signature_path=paths["signature"],
        _public_key_path=paths["public_key"], _trusted_context=_BUNDLE_CONTEXT,
    )


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
    protected_evidence_identity: str
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
            "protected_evidence_identity",
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
            "protected_evidence_identity": self.protected_evidence_identity,
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
    cache_attestation_public_key_sha256: str
    cache_attestation_record_sha256: str
    cache_attestation_signature_sha256: str
    _cache_root: Path = field(repr=False, compare=False)
    _expected_full_entries: tuple = field(repr=False, compare=False)
    _expected_subtree_entries: tuple = field(repr=False, compare=False)
    _trusted_context: InitVar[object] = None
    _trusted_cache_evidence: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        for name in (
            "protected_manifest_root", "trivy_subtree_root", "cache_metadata_sha256",
            "cache_attestation_record_sha256", "cache_attestation_signature_sha256",
            "cache_attestation_public_key_sha256",
        ):
            _sha(getattr(self, name), name)
        _sha(self.external_manifest_digest, "external_manifest_digest", prefixed=True)
        _sha(self.external_layer_digest, "external_layer_digest", prefixed=True)
        if type(self.cache_attestation_identity) is not str or not self.cache_attestation_identity:
            raise DomainError("cache attestation identity is required")
        if (
            not isinstance(self._cache_root, Path)
            or type(self._expected_full_entries) is not tuple
            or type(self._expected_subtree_entries) is not tuple
        ):
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
            "cache_attestation_public_key_sha256": self.cache_attestation_public_key_sha256,
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

    def revalidate_full(self) -> str:
        try:
            current = _physical_inventory(self._cache_root)
        except DomainError as exc:
            raise DomainError("CACHE_CHANGED_DURING_EXECUTION") from exc
        if current != self._expected_full_entries:
            raise DomainError("CACHE_CHANGED_DURING_EXECUTION")
        root = _canonical_sha256(list(current))
        if root != self.protected_manifest_root:
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
    evidence_bundle: ProtectedPhaseEEvidenceBundle, protected_cache_root: Path,
) -> ProtectedChecksCacheIdentity:
    """Verify the signed E0.3 cache and bind its exact Trivy subtree."""
    bundle = require_protected_phase_e_evidence(evidence_bundle)
    locked = load_locked_container_identity(bundle, "trivy", "linux/amd64")
    payload = _strict_object(
        _regular_nofollow_bytes(bundle._lock_path, "Phase-E lock"), "Phase-E lock"
    )
    record = payload.get("protected_cache_attestation")
    if type(record) is not dict or record.get("contract") != _CACHE_ATTESTATION_CONTRACT:
        raise DomainError("protected cache attestation contract is invalid")
    evidence_paths = {
        name: getattr(bundle, {
            "manifest": "_manifest_path", "attestation": "_attestation_path",
            "signature": "_signature_path", "public_key": "_public_key_path",
        }[name])
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
        if hashlib.sha256(_regular_nofollow_bytes(path, name)).hexdigest() != record[field]:
            raise DomainError("protected cache repository attestation evidence changed")
    manifest = _strict_object(
        _regular_nofollow_bytes(evidence_paths["manifest"], "cache manifest"),
        "cache manifest",
    )
    entries = manifest.get("entries")
    if manifest.get("contract") != _CACHE_MANIFEST_CONTRACT or type(entries) is not list:
        raise DomainError("protected cache manifest is invalid")
    if _canonical_sha256(entries) != record.get("manifest_root"):
        raise DomainError("protected cache manifest root is invalid")
    attestation = _strict_object(
        _regular_nofollow_bytes(evidence_paths["attestation"], "cache attestation"),
        "cache attestation",
    )
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
        cache_attestation_public_key_sha256=bundle.public_key_sha256,
        cache_attestation_record_sha256=record["attestation_sha256"],
        cache_attestation_signature_sha256=record["signature_sha256"],
        _cache_root=cache_root, _expected_full_entries=actual,
        _expected_subtree_entries=subtree,
        _trusted_context=_CACHE_CONTEXT,
    )


def _schema_tree_manifest(root: Path) -> tuple[str, int, int]:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise DomainError("protected Kubernetes schema tree is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise DomainError("protected Kubernetes schema tree must be a real directory")
    digest = hashlib.sha256()
    count = total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        item = path.lstat()
        if stat.S_ISLNK(item.st_mode) or not (
            stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)
        ):
            raise DomainError("protected Kubernetes schema tree contains an unsafe entry")
        if stat.S_ISDIR(item.st_mode):
            continue
        raw = _regular_nofollow_bytes(path, "Kubernetes schema")
        relative = path.relative_to(root).as_posix()
        file_digest = hashlib.sha256(raw).hexdigest()
        digest.update(f"{relative}\0{len(raw)}\0{file_digest}\n".encode())
        count += 1
        total += len(raw)
    return digest.hexdigest(), count, total


@dataclass(frozen=True, slots=True)
class ProtectedKubernetesSchemaIdentity:
    """Signed E0.3 kubeconform schema capability; local paths are noncanonical."""

    repository: str
    commit: str
    kubernetes_version: str
    strict: bool
    tree_manifest_root: str
    file_count: int
    total_bytes: int
    bundle_content_digest: str
    license_id: str
    protected_cache_manifest_root: str
    cache_attestation_identity: str
    _schema_root: Path = field(repr=False, compare=False)
    _protected_cache: ProtectedChecksCacheIdentity = field(repr=False, compare=False)
    _trusted_context: InitVar[object] = None
    _trusted_schema_evidence: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if self.repository != "https://github.com/yannh/kubernetes-json-schema":
            raise DomainError("Kubernetes schema repository is not authorized")
        if _COMMIT.fullmatch(self.commit) is None or self.kubernetes_version != "1.34.0":
            raise DomainError("Kubernetes schema commit/version is unsupported")
        if type(self.strict) is not bool or self.strict is not True:
            raise DomainError("kubeconform requires the strict schema tree")
        for name in ("tree_manifest_root", "bundle_content_digest", "protected_cache_manifest_root"):
            _sha(getattr(self, name), name)
        if type(self.file_count) is not int or self.file_count <= 0:
            raise DomainError("Kubernetes schema file count must be positive")
        if type(self.total_bytes) is not int or self.total_bytes <= 0:
            raise DomainError("Kubernetes schema byte count must be positive")
        if self.license_id != "NOASSERTION" or not self.cache_attestation_identity:
            raise DomainError("Kubernetes schema licence/attestation evidence is incomplete")
        if not isinstance(self._schema_root, Path):
            raise DomainError("Kubernetes schema private root is invalid")
        if (
            type(self._protected_cache) is not ProtectedChecksCacheIdentity
            or not self._protected_cache._trusted_cache_evidence
        ):
            raise DomainError("Kubernetes schema requires signed cache evidence")
        if _trusted_context is _SCHEMA_CONTEXT:
            object.__setattr__(self, "_trusted_schema_evidence", True)

    @property
    def schema_root(self) -> Path:
        return self._schema_root

    @property
    def identity(self) -> str:
        return _canonical_sha256(self.canonical_dict())

    def canonical_dict(self) -> dict:
        return {
            "repository": self.repository, "commit": self.commit,
            "kubernetes_version": self.kubernetes_version, "strict": self.strict,
            "tree_manifest_root": self.tree_manifest_root,
            "file_count": self.file_count, "total_bytes": self.total_bytes,
            "bundle_content_digest": self.bundle_content_digest,
            "license_id": self.license_id,
            "protected_cache_manifest_root": self.protected_cache_manifest_root,
            "cache_attestation_identity": self.cache_attestation_identity,
        }

    def revalidate(self) -> str:
        self._protected_cache.revalidate_full()
        observed = _schema_tree_manifest(self._schema_root)
        if observed != (self.tree_manifest_root, self.file_count, self.total_bytes):
            raise DomainError("SCHEMA_BUNDLE_CHANGED")
        return self.tree_manifest_root


def load_protected_kubernetes_schema_identity(
    evidence_bundle: ProtectedPhaseEEvidenceBundle, protected_cache_root: Path,
) -> ProtectedKubernetesSchemaIdentity:
    """Verify the signed cache and exact strict kubeconform schema tree."""
    bundle = require_protected_phase_e_evidence(evidence_bundle)
    cache = load_protected_checks_cache_identity(bundle, protected_cache_root)
    payload = _strict_object(
        _regular_nofollow_bytes(bundle._lock_path, "Phase-E lock"), "Phase-E lock"
    )
    schema = payload.get("tools", {}).get("kubeconform", {}).get("schema_bundle")
    if type(schema) is not dict:
        raise DomainError("kubeconform schema lock is absent")
    strict_tree = schema.get("strict_tree")
    if type(strict_tree) is not dict:
        raise DomainError("kubeconform strict schema lock is absent")
    root = protected_cache_root.resolve(strict=True) / schema["cache_root"] / strict_tree["relative_path"]
    observed = _schema_tree_manifest(root)
    expected = (
        strict_tree.get("manifest_root"), strict_tree.get("file_count"),
        strict_tree.get("total_bytes"),
    )
    if observed != expected:
        raise DomainError("SCHEMA_BUNDLE_CHANGED")
    return ProtectedKubernetesSchemaIdentity(
        repository=schema["repository"], commit=schema["commit"],
        kubernetes_version=schema["supported_kubernetes_versions"][0], strict=True,
        tree_manifest_root=observed[0], file_count=observed[1], total_bytes=observed[2],
        bundle_content_digest=schema["content_digest"],
        license_id=schema["license"]["id"],
        protected_cache_manifest_root=cache.protected_manifest_root,
        cache_attestation_identity=cache.cache_attestation_identity,
        _schema_root=root, _protected_cache=cache, _trusted_context=_SCHEMA_CONTEXT,
    )


def require_locked_identity(value: object, tool: str) -> LockedContainerIdentity:
    if type(value) is not LockedContainerIdentity or not value._trusted_lock_evidence:
        raise DomainError("scanner identity must come from the reviewed Phase-E lock")
    if value.tool != tool:
        raise DomainError(f"{tool} adapter received a {value.tool} lock")
    return value


def require_protected_phase_e_evidence(
    value: object,
) -> ProtectedPhaseEEvidenceBundle:
    if type(value) is not ProtectedPhaseEEvidenceBundle or not value._trusted_evidence:
        raise DomainError("Phase-E evidence must come from the protected bundle loader")
    return value


def load_locked_container_identity(
    evidence_bundle: ProtectedPhaseEEvidenceBundle, tool: str, architecture: str
) -> LockedContainerIdentity:
    """Load one tool identity only after the exact E0.3 graph seal is verified."""
    bundle = require_protected_phase_e_evidence(evidence_bundle)
    try:
        payload = json.loads(
            _regular_nofollow_bytes(bundle._lock_path, "Phase-E lock")
            .decode("utf-8", errors="strict")
        )
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
    if tool not in {"kics", "trivy", "opentofu", "terraform", "kubeconform"} or architecture not in {
        "linux/amd64", "linux/arm64",
    }:
        raise DomainError("tool or architecture is outside the E0.3 adapter lock")
    record = payload.get("tools", {}).get(tool)
    if type(record) is not dict:
        raise DomainError("locked tool record is absent")
    expected = {
        "kics": ("2.1.20", "kics-adapter-contract-research-v1"),
        "trivy": ("0.73.0", "trivy-config-adapter-contract-research-v1"),
        "opentofu": ("1.12.5", "tofu-validate-contract-research-v1"),
        "terraform": ("1.15.8", "terraform-validate-contract-research-v1"),
        "kubeconform": ("0.8.0", "kubeconform-validator-contract-research-v1"),
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
        if tool != "trivy"
        else {
            "manifest": checks.get("external_manifest_digest"),
            "layer": checks.get("external_layer_digest"),
            "cache": checks.get("cache_identity"),
            "source": checks.get("selected_source"),
            "fallback_used": checks.get("fallback_used"),
        }
    )
    if tool == "kubeconform":
        schema = record.get("schema_bundle", {})
        policy_payload["schema_content_digest"] = schema.get("content_digest")
        policy_payload["schema_commit"] = schema.get("commit")
        policy_payload["strict_tree"] = schema.get("strict_tree", {}).get("manifest_root")
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
        protected_evidence_identity=bundle.identity,
        checks_manifest_digest=checks.get("external_manifest_digest", ""),
        checks_layer_digest=checks.get("external_layer_digest", ""),
        checks_cache_identity=checks.get("cache_identity", ""),
        source=checks.get("selected_source", "bundled"),
        fallback_used=checks.get("fallback_used", False),
        _trusted_context=_LOCK_CONTEXT,
    )


__all__ = [
    "LockedContainerIdentity",
    "ProtectedPhaseEEvidenceBundle",
    "ProtectedChecksCacheIdentity",
    "ProtectedKubernetesSchemaIdentity",
    "PHASE_E_LOCK_CONTRACT",
    "PHASE_E_LOCK_PAYLOAD_SHA256",
    "PHASE_E_EVIDENCE_BUNDLE_CONTRACT",
    "load_locked_container_identity",
    "load_protected_phase_e_evidence",
    "load_protected_checks_cache_identity",
    "load_protected_kubernetes_schema_identity",
    "require_locked_identity",
    "require_protected_phase_e_evidence",
]
