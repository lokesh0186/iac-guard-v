"""Verification engine: trusted execution evidence to outcomes and gates.

The public request deliberately has no field for ``ScannerRun``, matching, delta, or
target-evaluation evidence.  Those values are obtained in this module by invoking the
adapter and the D3 factories.  The engine emits evidence and events; only ``policy.py``
may collapse them to a verdict.
"""
from __future__ import annotations

import difflib
import base64
import hashlib
import inspect
import json
import ntpath
import os
import stat
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from collections.abc import Callable, Mapping

import hcl2
import yaml
from yaml.constructor import ConstructorError
from yaml.events import (
    AliasEvent,
    MappingEndEvent,
    MappingStartEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .adapters.checkov import (
    CheckovAdapter,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
    evaluate_checkov_target,
)
from .adapters.base import AdapterReason
from .diffing import FindingDiffResult, diff_findings, require_trusted_diff_result
from .enums import (
    CheckTargetReason,
    ArtifactKind,
    DeltaClass,
    Outcome,
    SEVERITY_ORDER,
    Severity,
    Status, ScanRole, ExecutionMode,
)
from .models import (
    DomainError,
    ExpectedResource,
    GateResult,
    RequiredGates,
    ResolvedTargetBinding,
    ScannerRun,
    Target,
    TargetIdentity,
    canonical_identifier,
    require_enum,
    require_exact_type,
    require_trusted_scanner_run,
)


_TRUSTED_ENGINE_CONTEXT = object()
_TRUSTED_SCAN_PLAN_CONTEXT = object()
_TRUSTED_CONFIG_CONTEXT = object()
_TRUSTED_GATE_REGISTRY_CONTEXT = object()
_TRUSTED_POLICY_AUTHORIZATION_CONTEXT = object()
_SHA256 = __import__("re").compile(r"^[0-9a-f]{64}$")
_GOVERNED_FILE_NAMES = frozenset({
    ".iac-guard.yml", ".iac-guard.yaml", ".iac-guard.json",
    ".checkov.yml", ".checkov.yaml", ".checkovignore",
    ".trivyignore", ".trivy.yaml", ".trivy.yml", "trivy.yaml", "trivy.yml",
    ".tflint.hcl", ".tflint.json", ".kics.yaml", ".kics.yml", ".kics-config",
    ".terraformrc", "terraform.rc", ".terraform.lock.hcl",
    "iac-guard.lock.yml", "exceptions.json", "control-catalog.json",
    "oracle-policy.json", "severity-policy.json", "gate-policy.json",
})
_GOVERNED_DIRECTORY_NAMES = frozenset({
    ".iac-guard", ".checkov", "checkov_custom_checks", "custom_checks",
    "oracle-policy", "control-catalog",
})
_MAX_GOVERNED_FILES = 10_000
_MAX_GOVERNED_FILE_BYTES = 10 * 1024 * 1024
_MAX_GOVERNED_TOTAL_BYTES = 100 * 1024 * 1024
_GOVERNED_KINDS = frozenset({
    "ABSENT", "REGULAR_FILE", "REAL_DIRECTORY", "SYMLINK", "FIFO", "SOCKET",
    "BLOCK_DEVICE", "CHARACTER_DEVICE", "OTHER",
})
_SUPPORTED_SUFFIXES = frozenset({".tf", ".yaml", ".yml", ".json"})
_FILESYSTEM_KINDS = _GOVERNED_KINDS - {"ABSENT"}


def _digest(value: object, name: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise DomainError(f"{name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class GovernedPathRecord:
    """One no-follow governed entry in a role-specific snapshot."""

    file_path: str
    kind: str
    sha256: str | None
    size: int

    def __post_init__(self) -> None:
        from .models import canonical_repo_path

        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        if self.kind not in _GOVERNED_KINDS - {"ABSENT"}:
            raise DomainError("governed path record kind is unsupported")
        if type(self.size) is not int or self.size < 0:
            raise DomainError("governed path record size must be nonnegative")
        if self.sha256 is None:
            raise DomainError("present governed path record requires a digest")
        _digest(self.sha256, "governed path record digest")

    def canonical_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "kind": self.kind,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class FilesystemArtifactEntry:
    """One portable lstat record from the shared no-follow source inventory."""

    file_path: str
    kind: str
    size: int
    sha256: str | None
    symlink_target: str | None
    supported: bool
    governed: bool
    rejection_reason: str = ""
    content: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        from .models import canonical_repo_path

        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        if self.kind not in _FILESYSTEM_KINDS:
            raise DomainError("filesystem artifact entry kind is unsupported")
        if type(self.size) is not int or self.size < 0:
            raise DomainError("filesystem artifact entry size must be nonnegative")
        if type(self.supported) is not bool or type(self.governed) is not bool:
            raise DomainError("filesystem artifact scope flags must be exact bool values")
        if self.sha256 is not None:
            _digest(self.sha256, "filesystem artifact content digest")
        if self.kind == "REGULAR_FILE" and self.sha256 is None:
            raise DomainError("regular filesystem artifact requires a content digest")
        if self.content is not None:
            if type(self.content) is not bytes or self.kind != "REGULAR_FILE":
                raise DomainError("filesystem artifact content is only valid for regular files")
            if len(self.content) != self.size or hashlib.sha256(self.content).hexdigest() != self.sha256:
                raise DomainError("filesystem artifact content contradicts its bound evidence")
        if self.kind == "SYMLINK":
            if type(self.symlink_target) is not str:
                raise DomainError("symlink artifact requires target text")
        elif self.symlink_target is not None:
            raise DomainError("non-symlink artifact cannot carry symlink target text")
        if type(self.rejection_reason) is not str:
            raise DomainError("filesystem artifact rejection reason must be a string")

    def canonical_dict(self) -> dict:
        target_kind = None
        target_digest = None
        if self.symlink_target is not None:
            target_kind = (
                "absolute"
                if Path(self.symlink_target).is_absolute() or ntpath.isabs(self.symlink_target)
                else "relative"
            )
            target_digest = hashlib.sha256(self.symlink_target.encode("utf-8")).hexdigest()
        return {
            "file_path": self.file_path,
            "kind": self.kind,
            "size": self.size,
            "sha256": self.sha256,
            "symlink_target_kind": target_kind,
            "symlink_target_sha256": target_digest,
            "supported": self.supported,
            "governed": self.governed,
            "rejection_reason": self.rejection_reason,
        }


@dataclass(frozen=True, slots=True)
class GovernedConfigEvidence:
    """Path-by-path protected/candidate configuration comparison."""

    file_path: str
    trusted_sha256: str | None
    candidate_sha256: str | None
    state: str
    trusted_kind: str = ""
    candidate_kind: str = ""
    trusted_size: int = 0
    candidate_size: int = 0

    def __post_init__(self) -> None:
        from .models import canonical_repo_path

        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        for name in ("trusted_sha256", "candidate_sha256"):
            value = getattr(self, name)
            if value is not None:
                _digest(value, f"governed config {name}")
        trusted_kind = self.trusted_kind or (
            "REGULAR_FILE" if self.trusted_sha256 is not None else "ABSENT"
        )
        candidate_kind = self.candidate_kind or (
            "REGULAR_FILE" if self.candidate_sha256 is not None else "ABSENT"
        )
        if trusted_kind not in _GOVERNED_KINDS or candidate_kind not in _GOVERNED_KINDS:
            raise DomainError("governed config entry kind is unsupported")
        object.__setattr__(self, "trusted_kind", trusted_kind)
        object.__setattr__(self, "candidate_kind", candidate_kind)
        for name in ("trusted_size", "candidate_size"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise DomainError("governed config entry size must be nonnegative")
        expected = (
            "added" if trusted_kind == "ABSENT"
            else "removed" if candidate_kind == "ABSENT"
            else "type_changed" if trusted_kind != candidate_kind
            else "stable" if (
                trusted_kind in {"REGULAR_FILE", "REAL_DIRECTORY"}
                and self.trusted_sha256 == self.candidate_sha256
            )
            else "changed"
        )
        if self.state != expected:
            raise DomainError("governed config state contradicts its digests")

    def canonical_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "trusted_sha256": self.trusted_sha256,
            "candidate_sha256": self.candidate_sha256,
            "state": self.state,
            "trusted_kind": self.trusted_kind,
            "candidate_kind": self.candidate_kind,
            "trusted_size": self.trusted_size,
            "candidate_size": self.candidate_size,
        }


@dataclass(frozen=True, slots=True)
class PolicySourceAuthorization:
    """Non-serializable authorization for the policy source accepted by D6."""

    mode: ExecutionMode
    repository_identity: str
    commit_sha: str
    candidate_identity: str
    context_identity: str
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_enum(self.mode, ExecutionMode, "execution mode")
        object.__setattr__(
            self, "candidate_identity",
            canonical_identifier(self.candidate_identity, "authorized candidate identity"),
        )
        object.__setattr__(
            self, "context_identity",
            canonical_identifier(self.context_identity, "execution context identity"),
        )
        if self.repository_identity:
            object.__setattr__(
                self, "repository_identity",
                canonical_identifier(self.repository_identity, "authorized repository identity"),
            )
        if self.commit_sha and not __import__("re").fullmatch(r"[0-9a-f]{40,64}", self.commit_sha):
            raise DomainError("authorized policy commit must be a full Git SHA")
        if self.mode is ExecutionMode.EXPLICIT_OPERATOR:
            if self.repository_identity or self.commit_sha:
                raise DomainError("operator policy authorization cannot claim Git identity")
        elif not self.repository_identity or not self.commit_sha:
            raise DomainError("Git policy authorization requires repository and commit")
        if _trusted_context is not _TRUSTED_POLICY_AUTHORIZATION_CONTEXT:
            raise DomainError("policy source authorization requires protected provenance")
        object.__setattr__(self, "_trusted", True)

    def canonical_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "repository_identity": self.repository_identity,
            "commit_sha": self.commit_sha,
            "candidate_identity": self.candidate_identity,
            "context_identity": self.context_identity,
        }


GateExecutor = Callable[[str, str, "SealedVerificationSnapshot"], GateResult]


@dataclass(frozen=True, slots=True)
class GateImplementation:
    gate_id: str
    kind: str
    version: str
    code_sha256: str
    artifact_kinds: tuple
    dependency_identity: str = "0" * 64
    schema_loader_contract_digest: str = "0" * 64

    def __post_init__(self) -> None:
        object.__setattr__(self, "gate_id", canonical_identifier(self.gate_id, "gate id"))
        if self.kind not in {"validator", "oracle"}:
            raise DomainError("gate implementation kind is unsupported")
        object.__setattr__(self, "version", canonical_identifier(self.version, "gate version"))
        _digest(self.code_sha256, "gate implementation digest")
        _digest(self.dependency_identity, "gate dependency identity")
        _digest(self.schema_loader_contract_digest, "gate schema/loader contract identity")
        if type(self.artifact_kinds) is not tuple or any(
            type(item) is not ArtifactKind for item in self.artifact_kinds
        ):
            raise DomainError("gate artifact kinds must be exact ArtifactKind values")

    def canonical_dict(self) -> dict:
        return {
            "gate_id": self.gate_id,
            "kind": self.kind,
            "version": self.version,
            "code_sha256": self.code_sha256,
            "dependency_identity": self.dependency_identity,
            "contract_version": self.version,
            "product_build_digest": self.code_sha256,
            "parser_dependency_digest": self.dependency_identity,
            "schema_loader_contract_digest": self.schema_loader_contract_digest,
            "artifact_kinds": [item.value for item in self.artifact_kinds],
        }


@dataclass(frozen=True, slots=True)
class TrustedGateRegistry:
    """Factory-stamped gate implementations; never accepted from serialized input."""

    identity: str
    validator_ids: tuple
    oracle_ids: tuple
    implementations: tuple
    _executor: Callable = field(repr=False, compare=False)
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        object.__setattr__(self, "identity", canonical_identifier(self.identity, "gate registry identity"))
        for name in ("validator_ids", "oracle_ids"):
            value = getattr(self, name)
            if type(value) is not tuple:
                raise DomainError(f"{name} must be an exact tuple")
            rebuilt = tuple(canonical_identifier(item, "gate id") for item in value)
            if len(rebuilt) != len(set(rebuilt)):
                raise DomainError(f"{name} contains duplicate gate ids")
            object.__setattr__(self, name, tuple(sorted(rebuilt)))
        if type(self.implementations) is not tuple or any(
            type(item) is not GateImplementation for item in self.implementations
        ):
            raise DomainError("gate implementations must be exact typed records")
        implementation_ids = {
            (item.kind, item.gate_id) for item in self.implementations
        }
        expected_ids = {
            *(("validator", item) for item in self.validator_ids),
            *(("oracle", item) for item in self.oracle_ids),
        }
        if implementation_ids != expected_ids or len(implementation_ids) != len(self.implementations):
            raise DomainError("gate implementation evidence disagrees with registry ids")
        if not callable(self._executor):
            raise DomainError("gate registry executor must be callable")
        if _trusted_context is not _TRUSTED_GATE_REGISTRY_CONTEXT:
            raise DomainError("TrustedGateRegistry requires factory provenance")
        object.__setattr__(self, "_trusted", True)

    def execute(
        self, kind: str, gate_id: str, snapshot: "SealedVerificationSnapshot"
    ) -> GateResult:
        supported = self.validator_ids if kind == "validator" else self.oracle_ids
        if gate_id not in supported:
            return GateResult(gate_id, Status.UNSUPPORTED, "GATE_IMPLEMENTATION_UNAVAILABLE")
        result = self._executor(kind, gate_id, snapshot)
        require_exact_type(result, GateResult, "gate registry result")
        if result.gate_id != gate_id:
            raise DomainError("trusted gate registry substituted a different gate id")
        return GateResult(result.gate_id, result.status, result.reason_code, result.detail)


def _production_gate_executor(
    kind: str, gate_id: str, snapshot: "SealedVerificationSnapshot"
) -> GateResult:
    if kind != "validator":
        return GateResult(gate_id, Status.UNSUPPORTED, "ORACLE_IMPLEMENTATION_UNAVAILABLE")
    suffixes = (
        {".tf"} if gate_id == "terraform_hcl_parse"
        else {".yaml", ".yml", ".json"} if gate_id == "kubernetes_yaml_parse"
        else set()
    )
    try:
        checked = 0
        for bound in snapshot.files:
            path = Path(bound.file_path)
            if path.suffix.lower() not in suffixes:
                continue
            relative = bound.file_path
            content = bound.content
            if gate_id == "terraform_hcl_parse":
                _terraform_resources(relative, content)
            elif path.suffix.lower() == ".json":
                _kubernetes_json_resources(relative, content)
            else:
                _kubernetes_resources(relative, content)
            checked += 1
    except DomainError as exc:
        return GateResult(gate_id, Status.FAIL, "ARTIFACT_SYNTAX_INVALID", str(exc))
    return GateResult(gate_id, Status.PASS, "VALIDATOR_COMPLETED", f"files={checked}")


def _callable_behavior_digest(value: Callable) -> str:
    code = getattr(value, "__code__", None)
    if code is None:
        return hashlib.sha256(repr(type(value)).encode()).hexdigest()
    payload = {
        "bytecode": code.co_code.hex(),
        "constants": [repr(item) for item in code.co_consts],
        "names": list(code.co_names),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _verified_parser_distribution_digest(name: str) -> str:
    """Bind installed parser bytes and verify every RECORD-backed file."""
    import importlib.metadata

    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise DomainError(f"required parser distribution is unavailable: {name}") from exc
    files = distribution.files
    if not files:
        raise DomainError(f"parser distribution has no RECORD manifest: {name}")
    records = []
    for entry in sorted(files, key=str):
        relative = str(entry).replace("\\", "/")
        if "__pycache__" in relative.split("/") or relative.endswith((".pyc", ".pyo")):
            continue
        path = Path(distribution.locate_file(entry))
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise DomainError(f"parser distribution file is missing: {name}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise DomainError(f"parser distribution contains unsafe file type: {name}")
        if entry.hash is None:
            if not relative.endswith(".dist-info/RECORD"):
                raise DomainError(f"parser distribution file lacks RECORD hash: {name}")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            if entry.hash.mode != "sha256":
                raise DomainError(f"parser distribution uses unsupported RECORD digest: {name}")
            expected = base64.urlsafe_b64decode(entry.hash.value + "=" * (-len(entry.hash.value) % 4))
            actual = hashlib.sha256(path.read_bytes()).digest()
            if actual != expected:
                raise DomainError(f"parser distribution RECORD hash mismatch: {name}")
            digest = actual.hex()
        if entry.size is not None and entry.size != metadata.st_size:
            raise DomainError(f"parser distribution RECORD size mismatch: {name}")
        records.append((relative, metadata.st_size, digest))
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def production_gate_registry() -> TrustedGateRegistry:

    implementation_sources = (
        _production_gate_executor,
        _terraform_resources,
        _construct_unique_mapping,
        _kubernetes_identity,
        _resources_from_kubernetes_documents,
        _validate_yaml_node,
        _yaml_root_has_identity,
        _yaml_nested_complete_identity,
        _bounded_yaml_documents,
        _kubernetes_resources,
        _strict_json_document,
        _json_contains_identity,
        _kubernetes_json_resources,
        _read_detector_file,
        _filesystem_kind,
        _filesystem_inventory,
    )
    dependencies = {
        "python-hcl2": _verified_parser_distribution_digest("python-hcl2"),
        "PyYAML": _verified_parser_distribution_digest("PyYAML"),
        "hcl2.loads.behavior": _callable_behavior_digest(hcl2.loads),
        "yaml.load.behavior": _callable_behavior_digest(yaml.load),
    }
    payload = {
        "contract": "phase-d-gate-implementation-v4",
        "sources": [inspect.getsource(item) for item in implementation_sources],
    }
    code_digest = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    dependency_digest = hashlib.sha256(json.dumps(
        dependencies, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    schema_loader_digest = hashlib.sha256(json.dumps({
        "json_depth": inspect.getsource(_strict_json_document),
        "yaml_loader": inspect.getsource(_bounded_yaml_documents),
        "hcl_loader": inspect.getsource(_terraform_resources),
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return TrustedGateRegistry(
        "iac_guard_v_phase_d_registry_v4",
        ("kubernetes_yaml_parse", "terraform_hcl_parse"),
        (),
        (
            GateImplementation(
                "kubernetes_yaml_parse", "validator", "4", code_digest,
                (ArtifactKind.KUBERNETES_YAML, ArtifactKind.KUBERNETES_JSON),
                dependency_digest,
                schema_loader_digest,
            ),
            GateImplementation(
                "terraform_hcl_parse", "validator", "4", code_digest,
                (ArtifactKind.TERRAFORM_HCL,),
                dependency_digest,
                schema_loader_digest,
            ),
        ),
        _production_gate_executor,
        _trusted_context=_TRUSTED_GATE_REGISTRY_CONTEXT,
    )

def _governed_file(path: Path, relative: str) -> bool:
    parts = Path(relative).parts
    return (
        path.name in _GOVERNED_FILE_NAMES
        or any(part in _GOVERNED_DIRECTORY_NAMES for part in parts)
    )


def _supported_artifact_path(path: Path) -> bool:
    return (
        path.suffix.lower() in _SUPPORTED_SUFFIXES
        or path.name.lower().endswith(".tf.json")
    )


def _filesystem_kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "REGULAR_FILE"
    if stat.S_ISDIR(mode):
        return "REAL_DIRECTORY"
    if stat.S_ISLNK(mode):
        return "SYMLINK"
    if stat.S_ISFIFO(mode):
        return "FIFO"
    if stat.S_ISSOCK(mode):
        return "SOCKET"
    if stat.S_ISBLK(mode):
        return "BLOCK_DEVICE"
    if stat.S_ISCHR(mode):
        return "CHARACTER_DEVICE"
    return "OTHER"


def _filesystem_inventory(
    root: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> tuple[FilesystemArtifactEntry, ...]:
    """Walk once with lstat semantics and never traverse directory symlinks."""
    root = root.resolve(strict=True)
    entries: list[FilesystemArtifactEntry] = []
    supported_count = governed_count = 0
    supported_total = governed_total = 0

    def visit(directory: Path) -> None:
        nonlocal supported_count, governed_count, supported_total, governed_total
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise DomainError("source inventory directory could not be inspected") from exc
        for child in children:
            if directory == root and child.name == ".git":
                continue
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise DomainError("source inventory entry could not be inspected") from exc
            kind = _filesystem_kind(metadata.st_mode)
            supported = _supported_artifact_path(path)
            governed = _governed_file(path, relative)
            # Every symlink is security-relevant, even without a governed/supported name.
            record = supported or governed or kind == "SYMLINK"
            content: bytes | None = None
            digest: str | None = None
            target: str | None = None
            rejection = ""
            size = metadata.st_size if kind == "REGULAR_FILE" else 0
            if supported:
                supported_count += 1
                if supported_count > max_files:
                    raise DomainError("snapshot exceeds its eligible-file limit (file count)")
            if governed:
                governed_count += 1
                if governed_count > _MAX_GOVERNED_FILES:
                    raise DomainError("governed configuration exceeds its file-count limit")
            if kind == "REGULAR_FILE" and (supported or governed):
                limit = min(
                    max_file_bytes if supported else _MAX_GOVERNED_FILE_BYTES,
                    _MAX_GOVERNED_FILE_BYTES if governed else max_file_bytes,
                )
                content = _read_detector_file(path, root, limit)
                size = len(content)
                digest = hashlib.sha256(content).hexdigest()
                if supported:
                    supported_total += size
                    if supported_total > max_total_bytes:
                        raise DomainError("snapshot exceeds its supported-file byte limit")
                if governed:
                    governed_total += size
                    if governed_total > _MAX_GOVERNED_TOTAL_BYTES:
                        raise DomainError("governed configuration exceeds its total-byte limit")
            elif kind == "SYMLINK":
                try:
                    target = os.readlink(path)
                    target.encode("utf-8", errors="strict")
                except (OSError, UnicodeError) as exc:
                    raise DomainError("source inventory symlink target could not be recorded") from exc
                rejection = "UNSAFE_SYMLINK_ENTRY"
            elif supported and kind != "REGULAR_FILE":
                rejection = "UNSUPPORTED_ARTIFACT_PATH_TYPE"
            elif governed and kind not in {"REGULAR_FILE", "REAL_DIRECTORY"}:
                rejection = "UNSAFE_GOVERNED_PATH_TYPE"
            if record:
                entries.append(FilesystemArtifactEntry(
                    relative, kind, size, digest, target, supported, governed,
                    rejection, content,
                ))
            if kind == "REAL_DIRECTORY":
                visit(path)

    visit(root)
    return tuple(sorted(entries, key=lambda item: item.file_path))


def _governed_inventory_from_entries(
    entries: tuple[FilesystemArtifactEntry, ...],
) -> dict[str, GovernedPathRecord]:
    result: dict[str, GovernedPathRecord] = {}
    for entry in entries:
        if not entry.governed:
            continue
        if entry.kind == "REGULAR_FILE":
            digest = entry.sha256
            size = entry.size
        elif entry.kind == "SYMLINK":
            payload = entry.symlink_target.encode("utf-8")
            digest, size = hashlib.sha256(payload).hexdigest(), len(payload)
        elif entry.kind == "REAL_DIRECTORY":
            payload = b"directory"
            digest, size = hashlib.sha256(payload).hexdigest(), len(payload)
        elif entry.kind == "REAL_DIRECTORY":
            payload = b"directory"
            digest, size = hashlib.sha256(payload).hexdigest(), len(payload)
        else:
            payload = f"kind:{entry.kind}".encode("ascii")
            digest, size = hashlib.sha256(payload).hexdigest(), len(payload)
        governed_kind = (
            entry.kind
            if entry.kind in {"REGULAR_FILE", "REAL_DIRECTORY", "SYMLINK"}
            else "OTHER"
        )
        result[entry.file_path] = GovernedPathRecord(
            entry.file_path, governed_kind, digest, size
        )
    for relative, record in tuple(result.items()):
        if record.kind != "REAL_DIRECTORY":
            continue
        prefix = relative + "/"
        descendants = [
            item.canonical_dict() for name, item in sorted(result.items())
            if name.startswith(prefix)
        ]
        payload = json.dumps(descendants, sort_keys=True, separators=(",", ":")).encode()
        result[relative] = GovernedPathRecord(
            relative, record.kind, hashlib.sha256(payload).hexdigest(), len(payload)
        )
    return result


def _governed_inventory(root: Path) -> dict[str, GovernedPathRecord]:
    entries = _filesystem_inventory(
        root,
        max_files=10_000,
        max_file_bytes=_MAX_GOVERNED_FILE_BYTES,
        max_total_bytes=2**63 - 1,
    )
    return _governed_inventory_from_entries(entries)


def _governed_comparison_from_entries(
    baseline_entries: tuple[FilesystemArtifactEntry, ...],
    candidate_entries: tuple[FilesystemArtifactEntry, ...],
) -> tuple:
    trusted = _governed_inventory_from_entries(baseline_entries)
    candidate = _governed_inventory_from_entries(candidate_entries)
    evidence = []
    for path in sorted(set(trusted) | set(candidate)):
        before = trusted.get(path)
        after = candidate.get(path)
        before_kind = "ABSENT" if before is None else before.kind
        after_kind = "ABSENT" if after is None else after.kind
        before_digest = None if before is None else before.sha256
        after_digest = None if after is None else after.sha256
        state = (
            "added" if before is None
            else "removed" if after is None
            else "type_changed" if before.kind != after.kind
            else "stable" if (
                before.kind in {"REGULAR_FILE", "REAL_DIRECTORY"}
                and before.sha256 == after.sha256
            )
            else "changed"
        )
        evidence.append(GovernedConfigEvidence(
            path, before_digest, after_digest, state,
            before_kind, after_kind,
            0 if before is None else before.size,
            0 if after is None else after.size,
        ))
    return tuple(evidence)


def _governed_comparison(baseline_root: Path, candidate_root: Path) -> tuple:
    baseline_entries = _filesystem_inventory(
        baseline_root, max_files=10_000,
        max_file_bytes=_MAX_GOVERNED_FILE_BYTES,
        max_total_bytes=_MAX_GOVERNED_TOTAL_BYTES,
    )
    candidate_entries = _filesystem_inventory(
        candidate_root, max_files=10_000,
        max_file_bytes=_MAX_GOVERNED_FILE_BYTES,
        max_total_bytes=_MAX_GOVERNED_TOTAL_BYTES,
    )
    return _governed_comparison_from_entries(baseline_entries, candidate_entries)


def _source_snapshot_state(
    root: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
    include_entries: bool = False,
) -> tuple:
    """Portable no-follow state for supported artifacts plus governed entries."""
    entries = _filesystem_inventory(
        root,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )
    governed = _governed_inventory_from_entries(entries)
    records = [item.canonical_dict() for item in entries]
    digest = hashlib.sha256(json.dumps(
        sorted(records, key=lambda item: item["file_path"]),
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    complete = (
        digest,
        tuple(governed[path] for path in sorted(governed)),
        entries,
    )
    return complete if include_entries else complete[:2]


def _repository_relative_subpath(root: Path) -> str:
    """Best-effort portable subtree label; Git authorization remains D6's job."""
    resolved = root.resolve(strict=True)
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").exists():
            relative = resolved.relative_to(parent).as_posix()
            return relative or "."
    return "."


@dataclass(frozen=True, slots=True)
class TrustedVerificationConfigBundle:
    """Protected scanner, regression, gate, and governed-config policy."""

    baseline_root: Path
    candidate_root: Path
    scanner_executable: Path
    frameworks: tuple
    expected_version: str
    expected_executable_sha256: str
    expected_scanner_environment_sha256: str
    expected_policy_inventory_sha256: str
    required_gates: RequiredGates
    severity_floor: Severity
    fail_on_location_change: bool
    timeout_seconds: int
    max_output_bytes: int
    max_eligible_files: int
    max_file_bytes: int
    max_total_eligible_bytes: int
    governed_config: tuple
    source_identity: str
    source_provenance: str
    policy_source_authorization: PolicySourceAuthorization
    gate_registry: TrustedGateRegistry = field(repr=False, compare=False)
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)
    config_sha256: str = field(init=False)
    baseline_source_snapshot_sha256: str = field(init=False)
    candidate_source_snapshot_sha256: str = field(init=False)
    baseline_repository_relative_subpath: str = field(init=False)
    candidate_repository_relative_subpath: str = field(init=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if _trusted_context is not _TRUSTED_CONFIG_CONTEXT:
            raise DomainError("TrustedVerificationConfigBundle requires loader provenance")
        for name in ("baseline_root", "candidate_root"):
            value = getattr(self, name)
            if not isinstance(value, Path):
                raise DomainError(f"{name} must be pathlib.Path")
            object.__setattr__(self, name, value.resolve(strict=True))
        if self.baseline_root == self.candidate_root:
            raise DomainError("baseline and candidate roots must be distinct")
        if not isinstance(self.scanner_executable, Path):
            raise DomainError("scanner_executable must be pathlib.Path")
        object.__setattr__(self, "scanner_executable", self.scanner_executable.resolve(strict=True))
        frameworks = tuple(sorted(canonical_identifier(item, "framework") for item in self.frameworks))
        if type(self.frameworks) is not tuple or not frameworks or len(frameworks) != len(set(frameworks)):
            raise DomainError("trusted frameworks must be a nonempty unique tuple")
        object.__setattr__(self, "frameworks", frameworks)
        require_exact_type(self.required_gates, RequiredGates, "trusted required gates")
        require_enum(self.severity_floor, Severity, "trusted severity floor")
        if type(self.fail_on_location_change) is not bool:
            raise DomainError("trusted location policy must be bool")
        for name in (
            "timeout_seconds", "max_output_bytes", "max_eligible_files",
            "max_file_bytes", "max_total_eligible_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise DomainError(f"{name} must be a positive exact int")
        for name in (
            "expected_executable_sha256", "expected_scanner_environment_sha256",
            "expected_policy_inventory_sha256",
        ):
            _digest(getattr(self, name), name)
        object.__setattr__(self, "expected_version", canonical_identifier(self.expected_version, "scanner version"))
        object.__setattr__(self, "source_identity", canonical_identifier(self.source_identity, "config source identity"))
        object.__setattr__(self, "source_provenance", canonical_identifier(self.source_provenance, "config source provenance"))
        require_exact_type(
            self.policy_source_authorization, PolicySourceAuthorization,
            "policy source authorization",
        )
        if not self.policy_source_authorization._trusted:
            raise DomainError("policy source authorization lacks protected provenance")
        if type(self.governed_config) is not tuple or any(type(item) is not GovernedConfigEvidence for item in self.governed_config):
            raise DomainError("governed_config must contain exact evidence records")
        require_exact_type(self.gate_registry, TrustedGateRegistry, "trusted gate registry")
        if not self.gate_registry._trusted:
            raise DomainError("gate registry lacks factory provenance")
        baseline_state, _baseline_governed, baseline_entries = _source_snapshot_state(
            self.baseline_root,
            max_files=self.max_eligible_files,
            max_file_bytes=self.max_file_bytes,
            max_total_bytes=self.max_total_eligible_bytes,
            include_entries=True,
        )
        candidate_state, _candidate_governed, candidate_entries = _source_snapshot_state(
            self.candidate_root,
            max_files=self.max_eligible_files,
            max_file_bytes=self.max_file_bytes,
            max_total_bytes=self.max_total_eligible_bytes,
            include_entries=True,
        )
        object.__setattr__(self, "baseline_source_snapshot_sha256", baseline_state)
        object.__setattr__(self, "candidate_source_snapshot_sha256", candidate_state)
        observed_governed = _governed_comparison_from_entries(
            baseline_entries, candidate_entries
        )
        if self.governed_config and self.governed_config != observed_governed:
            raise DomainError("governed configuration evidence disagrees with source inventory")
        object.__setattr__(self, "governed_config", observed_governed)
        baseline_subpath = _repository_relative_subpath(self.baseline_root)
        candidate_subpath = _repository_relative_subpath(self.candidate_root)
        object.__setattr__(self, "baseline_repository_relative_subpath", baseline_subpath)
        object.__setattr__(self, "candidate_repository_relative_subpath", candidate_subpath)
        payload = {
            "role_snapshots": {
                "baseline": baseline_state,
                "candidate": candidate_state,
            },
            "role_subpaths": {
                "baseline": baseline_subpath,
                "candidate": candidate_subpath,
            },
            "frameworks": list(frameworks),
            "version": self.expected_version,
            "launcher": self.expected_executable_sha256,
            "environment": self.expected_scanner_environment_sha256,
            "policy": self.expected_policy_inventory_sha256,
            "required_gates": self.required_gates.canonical_dict(),
            "severity_floor": self.severity_floor.value,
            "fail_on_location_change": self.fail_on_location_change,
            "limits": [self.timeout_seconds, self.max_output_bytes, self.max_eligible_files, self.max_file_bytes, self.max_total_eligible_bytes],
            "governed_config": [item.canonical_dict() for item in self.governed_config],
            "source": [self.source_identity, self.source_provenance],
            "policy_source_authorization": self.policy_source_authorization.canonical_dict(),
            "gate_registry": {
                "identity": self.gate_registry.identity,
                "implementations": [
                    item.canonical_dict() for item in self.gate_registry.implementations
                ],
            },
        }
        object.__setattr__(self, "config_sha256", hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        object.__setattr__(self, "_trusted", True)

    @property
    def policy_drift_paths(self) -> tuple:
        return tuple(item.file_path for item in self.governed_config if item.state != "stable")

    def canonical_dict(self) -> dict:
        return {
            "config_sha256": self.config_sha256,
            "source_identity": self.source_identity,
            "source_provenance": self.source_provenance,
            "policy_source_authorization": self.policy_source_authorization.canonical_dict(),
            "frameworks": list(self.frameworks),
            "severity_floor": self.severity_floor.value,
            "fail_on_location_change": self.fail_on_location_change,
            "required_gates": self.required_gates.canonical_dict(),
            "gate_registry_identity": self.gate_registry.identity,
            "gate_implementations": [
                item.canonical_dict() for item in self.gate_registry.implementations
            ],
            "governed_config": [item.canonical_dict() for item in self.governed_config],
            "role_snapshots": {
                "baseline": self.baseline_source_snapshot_sha256,
                "candidate": self.candidate_source_snapshot_sha256,
            },
            "role_subpaths": {
                "baseline": self.baseline_repository_relative_subpath,
                "candidate": self.candidate_repository_relative_subpath,
            },
        }


def load_operator_verification_config(
    baseline_request: CheckovScanRequest,
    candidate_request: CheckovScanRequest,
    *,
    required_gates: RequiredGates,
    severity_floor: Severity = Severity.HIGH,
    fail_on_location_change: bool = False,
    frameworks: tuple | None = None,
) -> TrustedVerificationConfigBundle:
    """Explicit local/operator loader; future PR mode uses a Git-attested source."""
    require_exact_type(baseline_request, CheckovScanRequest, "baseline Checkov request")
    require_exact_type(candidate_request, CheckovScanRequest, "candidate Checkov request")
    lock_fields = (
        "executable", "expected_version", "expected_executable_sha256",
        "expected_scanner_environment_sha256", "expected_policy_inventory_sha256",
        "timeout_seconds", "max_output_bytes", "max_eligible_files", "max_file_bytes",
        "max_total_eligible_bytes",
    )
    if any(getattr(baseline_request, name) != getattr(candidate_request, name) for name in lock_fields):
        raise DomainError("baseline and candidate scanner lock inputs differ")
    registry = production_gate_registry()
    selected_frameworks = frameworks if frameworks is not None else baseline_request.frameworks
    source_payload = {
        "mode": "operator",
        "frameworks": list(selected_frameworks),
        "severity_floor": severity_floor.value if type(severity_floor) is Severity else str(severity_floor),
        "required_gates": required_gates.canonical_dict(),
        "gate_registry": registry.identity,
    }
    source_identity = "operator_" + hashlib.sha256(json.dumps(source_payload, sort_keys=True).encode()).hexdigest()
    authorization = PolicySourceAuthorization(
        ExecutionMode.EXPLICIT_OPERATOR, "", "",
        f"operator_candidate_{source_identity}", source_identity,
        _trusted_context=_TRUSTED_POLICY_AUTHORIZATION_CONTEXT,
    )
    return TrustedVerificationConfigBundle(
        baseline_request.scan_root,
        candidate_request.scan_root,
        baseline_request.executable,
        selected_frameworks,
        baseline_request.expected_version,
        baseline_request.expected_executable_sha256,
        baseline_request.expected_scanner_environment_sha256,
        baseline_request.expected_policy_inventory_sha256,
        required_gates,
        severity_floor,
        fail_on_location_change,
        baseline_request.timeout_seconds,
        baseline_request.max_output_bytes,
        baseline_request.max_eligible_files,
        baseline_request.max_file_bytes,
        baseline_request.max_total_eligible_bytes,
        (),
        source_identity,
        "operator",
        authorization,
        registry,
        _trusted_context=_TRUSTED_CONFIG_CONTEXT,
    )


@dataclass(frozen=True, slots=True)
class ScanPlanFile:
    file_path: str
    file_type: str
    size: int
    sha256: str
    content: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.file_path) is not str or not self.file_path:
            raise DomainError("scan-plan file path must be nonblank")
        if type(self.file_type) is not str or not self.file_type:
            raise DomainError("scan-plan file type must be nonblank")
        if type(self.size) is not int or self.size < 0 or self.size != len(self.content):
            raise DomainError("scan-plan file size does not match bound content")
        _digest(self.sha256, "scan-plan file digest")
        if hashlib.sha256(self.content).hexdigest() != self.sha256:
            raise DomainError("scan-plan file digest does not match bound content")

    def canonical_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "size": self.size,
            "sha256": self.sha256,
        }


_ARTIFACT_CLASSIFICATIONS = frozenset({
    "TERRAFORM_RESOURCES",
    "KUBERNETES_RESOURCES",
    "NON_KUBERNETES_YAML",
    "NON_KUBERNETES_JSON",
})
_ARTIFACT_SYNTAX_KINDS = frozenset({"terraform_hcl", "yaml", "json"})


@dataclass(frozen=True, slots=True)
class ArtifactClassification:
    """Digest-bound classification for every independently inspected IaC-like file."""

    file_path: str
    sha256: str
    size: int
    syntax_kind: str
    classification: str
    resources: tuple = ()
    reason: str = ""

    def __post_init__(self) -> None:
        from .models import canonical_repo_path

        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        _digest(self.sha256, "artifact classification digest")
        if type(self.size) is not int or self.size < 0:
            raise DomainError("artifact classification size must be nonnegative")
        if self.syntax_kind not in _ARTIFACT_SYNTAX_KINDS:
            raise DomainError("artifact classification syntax kind is unsupported")
        if self.classification not in _ARTIFACT_CLASSIFICATIONS:
            raise DomainError("artifact classification is unsupported")
        if type(self.resources) is not tuple or any(
            type(item) is not ExpectedResource for item in self.resources
        ):
            raise DomainError("artifact classification resources must be typed")
        if self.classification == "KUBERNETES_RESOURCES" and not self.resources:
            raise DomainError("Kubernetes resource classification requires resources")
        if self.classification.startswith("NON_KUBERNETES") and self.resources:
            raise DomainError("non-Kubernetes classification cannot claim resources")
        if type(self.reason) is not str:
            raise DomainError("artifact classification reason must be a string")

    def canonical_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "sha256": self.sha256,
            "size": self.size,
            "syntax_kind": self.syntax_kind,
            "classification": self.classification,
            "resources": [item.canonical_dict() for item in self.resources],
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class SealedVerificationSnapshot:
    """Portable immutable bytes and inventories consumed by every Phase-D gate."""

    role: ScanRole
    repository_identity: str
    repository_relative_subpath: str
    snapshot_sha256: str
    artifact_manifest_sha256: str
    resource_inventory_sha256: str
    config_sha256: str
    files: tuple
    classifications: tuple
    resources: tuple
    governed_paths: tuple
    filesystem_entries: tuple = ()
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        from .models import canonical_repo_path

        require_enum(self.role, ScanRole, "sealed snapshot role")
        if self.role is ScanRole.DISCOVERY:
            raise DomainError("sealed verification snapshot requires baseline/candidate role")
        object.__setattr__(
            self, "repository_identity",
            canonical_identifier(self.repository_identity, "snapshot repository identity"),
        )
        subpath = self.repository_relative_subpath
        if subpath == ".":
            canonical_subpath = "."
        else:
            canonical_subpath = canonical_repo_path(subpath, "snapshot repository subpath")
        object.__setattr__(self, "repository_relative_subpath", canonical_subpath)
        for name in (
            "snapshot_sha256", "artifact_manifest_sha256",
            "resource_inventory_sha256", "config_sha256",
        ):
            _digest(getattr(self, name), name)
        typed_collections = (
            ("files", ScanPlanFile),
            ("classifications", ArtifactClassification),
            ("resources", ExpectedResource),
            ("governed_paths", GovernedPathRecord),
            ("filesystem_entries", FilesystemArtifactEntry),
        )
        for name, item_type in typed_collections:
            values = getattr(self, name)
            if type(values) is not tuple or any(type(item) is not item_type for item in values):
                raise DomainError(f"sealed snapshot {name} must be an exact typed tuple")
        paths = [item.file_path for item in self.files]
        if len(paths) != len(set(paths)):
            raise DomainError("sealed snapshot files contain duplicate paths")
        if _trusted_context is not _TRUSTED_SCAN_PLAN_CONTEXT:
            raise DomainError("sealed snapshot requires scan-plan factory provenance")
        object.__setattr__(self, "_trusted", True)

    def canonical_dict(self) -> dict:
        return {
            "role": self.role.value,
            "repository_identity": self.repository_identity,
            "repository_relative_subpath": self.repository_relative_subpath,
            "snapshot_sha256": self.snapshot_sha256,
            "artifact_manifest_sha256": self.artifact_manifest_sha256,
            "resource_inventory_sha256": self.resource_inventory_sha256,
            "config_sha256": self.config_sha256,
            "files": [item.canonical_dict() for item in self.files],
            "classifications": [item.canonical_dict() for item in self.classifications],
            "resources": [item.canonical_dict() for item in self.resources],
            "governed_paths": [item.canonical_dict() for item in self.governed_paths],
            "filesystem_entries": [
                item.canonical_dict() for item in self.filesystem_entries
            ],
        }


@dataclass(frozen=True, slots=True)
class TrustedScanPlan:
    """Private-factory scan plan whose resources were detected from bound bytes."""

    request: CheckovScanRequest
    files: tuple
    resources: tuple
    inventory_sha256: str
    classifications: tuple = ()
    inspected_files: tuple = ()
    governed_paths: tuple = ()
    role: ScanRole = ScanRole.DISCOVERY
    snapshot_sha256: str = ""
    artifact_manifest_sha256: str = ""
    source_state_sha256: str = ""
    config_sha256: str = ""
    repository_identity: str = "operator_content_repository_v1"
    repository_relative_subpath: str = "."
    filesystem_entries: tuple = ()
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)
    sealed_snapshot: SealedVerificationSnapshot | None = field(
        init=False, default=None, repr=False, compare=False
    )

    def __post_init__(self, _trusted_context: object) -> None:
        require_exact_type(self.request, CheckovScanRequest, "scan-plan request")
        if type(self.files) is not tuple or any(type(item) is not ScanPlanFile for item in self.files):
            raise DomainError("scan-plan files must be exact ScanPlanFile values")
        if type(self.resources) is not tuple or any(type(item) is not ExpectedResource for item in self.resources):
            raise DomainError("scan-plan resources must be exact ExpectedResource values")
        if type(self.classifications) is not tuple or any(
            type(item) is not ArtifactClassification for item in self.classifications
        ):
            raise DomainError("scan-plan classifications must be exact typed records")
        if type(self.inspected_files) is not tuple or any(
            type(item) is not ScanPlanFile for item in self.inspected_files
        ):
            raise DomainError("scan-plan inspected files must be exact ScanPlanFile values")
        if not self.inspected_files:
            object.__setattr__(self, "inspected_files", self.files)
        if type(self.governed_paths) is not tuple or any(
            type(item) is not GovernedPathRecord for item in self.governed_paths
        ):
            raise DomainError("scan-plan governed paths must be exact typed records")
        if type(self.filesystem_entries) is not tuple or any(
            type(item) is not FilesystemArtifactEntry for item in self.filesystem_entries
        ):
            raise DomainError("scan-plan filesystem entries must be exact typed records")
        require_enum(self.role, ScanRole, "scan-plan role")
        if tuple(self.request.expected_resources) != self.resources:
            raise DomainError("scan-plan resources disagree with its adapter request")
        if _trusted_context is not _TRUSTED_SCAN_PLAN_CONTEXT:
            raise DomainError("TrustedScanPlan requires independent detector provenance")
        paths = [item.file_path for item in self.classifications]
        if len(paths) != len(set(paths)):
            raise DomainError("scan-plan classifications contain duplicate paths")
        files_by_path = {item.file_path: item for item in self.files}
        inspected_by_path = {item.file_path: item for item in self.inspected_files}
        if set(inspected_by_path) != set(paths):
            raise DomainError("scan-plan inspected bytes disagree with classifications")
        classified_eligible = {
            item.file_path: item for item in self.classifications
            if not item.classification.startswith("NON_KUBERNETES")
        }
        if set(files_by_path) != set(classified_eligible):
            raise DomainError("eligible scan-plan files disagree with classifications")
        for path, bound in inspected_by_path.items():
            classified = next(item for item in self.classifications if item.file_path == path)
            if (classified.sha256, classified.size) != (bound.sha256, bound.size):
                raise DomainError("scan-plan classification bytes disagree with inspected file")
        for path, bound in files_by_path.items():
            classified = classified_eligible[path]
            if (classified.sha256, classified.size) != (bound.sha256, bound.size):
                raise DomainError("scan-plan classification bytes disagree with file")
        classified_resources = tuple(sorted(
            (
                resource for item in self.classifications
                for resource in item.resources
            ),
            key=lambda item: item.canonical_key,
        ))
        if classified_resources != self.resources:
            raise DomainError("scan-plan resources disagree with classifications")
        _digest(self.inventory_sha256, "resource inventory digest")
        inventory_payload = {
            "resources": [item.canonical_dict() for item in self.resources],
            "classifications": [
                item.canonical_dict() for item in self.classifications
            ],
        }
        computed_inventory = hashlib.sha256(
            json.dumps(
                inventory_payload, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        if computed_inventory != self.inventory_sha256:
            raise DomainError("scan-plan inventory digest is not canonical")
        computed_artifact_manifest = hashlib.sha256(json.dumps(
            {
                "root_files": [item.canonical_dict() for item in self.classifications],
                "eligible_files": [item.canonical_dict() for item in self.files],
                "filesystem_entries": [
                    item.canonical_dict() for item in self.filesystem_entries
                ],
            }, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        if self.artifact_manifest_sha256 and self.artifact_manifest_sha256 != computed_artifact_manifest:
            raise DomainError("scan-plan artifact manifest digest is not canonical")
        object.__setattr__(self, "artifact_manifest_sha256", computed_artifact_manifest)
        if self.role is ScanRole.DISCOVERY:
            if self.config_sha256 or self.source_state_sha256:
                raise DomainError("discovery scan plan cannot claim a config identity")
            computed_snapshot = computed_artifact_manifest
        else:
            _digest(self.config_sha256, "scan-plan config digest")
            _digest(self.source_state_sha256, "scan-plan source-state digest")
            computed_snapshot = self.source_state_sha256
        if self.snapshot_sha256 and self.snapshot_sha256 != computed_snapshot:
            raise DomainError("scan-plan snapshot digest is not canonical")
        object.__setattr__(self, "snapshot_sha256", computed_snapshot)
        if self.role is not ScanRole.DISCOVERY:
            sealed = SealedVerificationSnapshot(
                self.role,
                self.repository_identity,
                self.repository_relative_subpath,
                computed_snapshot,
                computed_artifact_manifest,
                self.inventory_sha256,
                self.config_sha256,
                self.inspected_files,
                self.classifications,
                self.resources,
                self.governed_paths,
                self.filesystem_entries,
                _trusted_context=_TRUSTED_SCAN_PLAN_CONTEXT,
            )
            object.__setattr__(self, "sealed_snapshot", sealed)
        object.__setattr__(self, "_trusted", True)

    @property
    def scan_root(self) -> Path:
        return self.request.scan_root

    @property
    def executable(self) -> Path:
        return self.request.executable

    @property
    def expected_executable_sha256(self) -> str:
        return self.request.expected_executable_sha256

    @property
    def expected_scanner_environment_sha256(self) -> str:
        return self.request.expected_scanner_environment_sha256

    @property
    def expected_policy_inventory_sha256(self) -> str:
        return self.request.expected_policy_inventory_sha256

    @property
    def files_eligible(self) -> tuple:
        return self.request.files_eligible

    @property
    def expected_resources(self) -> tuple:
        return self.resources

    @property
    def eligible_file_evidence(self) -> tuple:
        return self.request.eligible_file_evidence

    def canonical_dict(self) -> dict:
        return {
            "files": [item.canonical_dict() for item in self.files],
            "resources": [item.canonical_dict() for item in self.resources],
            "inventory_sha256": self.inventory_sha256,
            "role": self.role.value,
            "snapshot_sha256": self.snapshot_sha256,
            "artifact_manifest_sha256": self.artifact_manifest_sha256,
            "source_state_sha256": self.source_state_sha256,
            "config_sha256": self.config_sha256,
            "classifications": [
                item.canonical_dict() for item in self.classifications
            ],
            "governed_paths": [item.canonical_dict() for item in self.governed_paths],
        }


def _terraform_resources(relative: str, content: bytes) -> tuple[ExpectedResource, ...]:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DomainError("Terraform source must be UTF-8") from exc
    block_start = text.find("/*")
    if block_start >= 0 and text.find("*/", block_start + 2) < 0:
        raise DomainError("unterminated Terraform block comment")
    escaped = False
    quote_count = 0
    for character in text:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quote_count += 1
    if quote_count % 2:
        raise DomainError("unterminated Terraform string")
    try:
        document = hcl2.loads(text)
    except Exception as exc:
        raise DomainError("Terraform HCL syntax is invalid") from exc
    if type(document) is not dict:
        raise DomainError("Terraform HCL parser returned an invalid document")
    resources: list[ExpectedResource] = []
    seen: set[str] = set()
    blocks = document.get("resource", [])
    if type(blocks) is not list:
        raise DomainError("Terraform resource structure is invalid")
    for block in blocks:
        if type(block) is not dict:
            raise DomainError("Terraform resource block is invalid")
        for resource_type, instances in block.items():
            if type(resource_type) is not str or type(instances) is not dict:
                raise DomainError("Terraform resource identity is invalid")
            for resource_name in instances:
                if type(resource_name) is not str:
                    raise DomainError("Terraform resource name is invalid")
                address = f"{resource_type}.{resource_name}"
                if address in seen:
                    raise DomainError("duplicate Terraform resource identity")
                seen.add(address)
                resources.append(
                    ExpectedResource(
                        relative, address, ArtifactKind.TERRAFORM_HCL, address
                    )
                )
    return tuple(sorted(resources, key=lambda item: item.canonical_key))


_MAX_YAML_DEPTH = 64
_MAX_YAML_DOCUMENTS = 128
_MAX_YAML_NODES = 10_000


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe loader with a closed mapping-key and duplicate-key contract."""


def _construct_unique_mapping(
    loader: _StrictSafeLoader, node: MappingNode, deep: bool = False
) -> dict:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a YAML mapping", node.start_mark)
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark,
                "YAML mapping keys must be strings", key_node.start_mark,
            )
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"duplicate YAML mapping key {key!r}", key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _kubernetes_identity(
    relative: str, value: object, artifact_kind: ArtifactKind
) -> tuple[ExpectedResource, CheckovKubernetesIdentity]:
    if type(value) is not dict:
        raise DomainError("unsupported Kubernetes identity shape")
    api_version = value.get("apiVersion")
    kind = value.get("kind")
    metadata = value.get("metadata")
    if type(api_version) is not str or not api_version.strip():
        raise DomainError("incomplete Kubernetes resource identity: apiVersion")
    if type(kind) is not str or not kind.strip():
        raise DomainError("incomplete Kubernetes resource identity: kind")
    if type(metadata) is not dict:
        raise DomainError("incomplete Kubernetes resource identity: metadata")
    name = metadata.get("name")
    namespace = metadata.get("namespace", "default")
    if name is None or name == "":
        raise DomainError("incomplete Kubernetes resource identity: metadata.name")
    if type(name) is not str:
        raise DomainError("unsupported complex Kubernetes metadata.name")
    if namespace is None:
        namespace = "default"
    if type(namespace) is not str:
        raise DomainError("unsupported complex Kubernetes metadata.namespace")
    if not namespace.strip():
        raise DomainError("unsupported Kubernetes identity shape: metadata.namespace")
    api_version = api_version.strip()
    kind = kind.strip()
    name = name.strip()
    namespace = namespace.strip()
    canonical = f"{api_version}/{kind}/{namespace}/{name}"
    native = f"{kind}.{namespace}.{name}"
    return (
        ExpectedResource(relative, canonical, artifact_kind, native),
        CheckovKubernetesIdentity(
            relative, native, api_version, kind, namespace, name
        ),
    )


def _resources_from_kubernetes_documents(
    relative: str, documents: tuple, artifact_kind: ArtifactKind
) -> tuple[tuple[ExpectedResource, ...], tuple[CheckovKubernetesIdentity, ...]]:
    resources: list[ExpectedResource] = []
    identities: list[CheckovKubernetesIdentity] = []
    for document in documents:
        if document is None:
            continue
        if type(document) is not dict:
            raise DomainError("unsupported Kubernetes YAML document shape")
        has_identity_evidence = any(
            key in document for key in ("apiVersion", "kind", "metadata")
        )
        if not has_identity_evidence:
            continue
        if document.get("kind") == "List":
            if type(document.get("apiVersion")) is not str:
                raise DomainError("incomplete Kubernetes List identity")
            items = document.get("items")
            if type(items) is not list:
                raise DomainError("unsupported Kubernetes List items shape")
            for item in items:
                resource, identity = _kubernetes_identity(relative, item, artifact_kind)
                resources.append(resource)
                identities.append(identity)
        else:
            resource, identity = _kubernetes_identity(relative, document, artifact_kind)
            resources.append(resource)
            identities.append(identity)
    keys = [item.canonical_key for item in resources]
    if len(keys) != len(set(keys)):
        raise DomainError("duplicate Kubernetes resource identity")
    return (
        tuple(sorted(resources, key=lambda item: item.canonical_key)),
        tuple(sorted(identities, key=lambda item: (item.file_path, item.canonical_address))),
    )


_SAFE_YAML_TAGS = frozenset({
    "tag:yaml.org,2002:null", "tag:yaml.org,2002:bool",
    "tag:yaml.org,2002:int", "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:binary", "tag:yaml.org,2002:timestamp",
    "tag:yaml.org,2002:omap", "tag:yaml.org,2002:pairs",
    "tag:yaml.org,2002:set", "tag:yaml.org,2002:str",
    "tag:yaml.org,2002:seq", "tag:yaml.org,2002:map",
})


def _validate_yaml_node(node: Node) -> None:
    if isinstance(node, MappingNode):
        seen: set[str] = set()
        for key, value in node.value:
            if not isinstance(key, ScalarNode):
                raise DomainError("YAML mapping keys must be scalar strings")
            raw = key.value
            if raw in seen:
                raise DomainError(f"duplicate YAML mapping key {raw!r}")
            seen.add(raw)
            _validate_yaml_node(value)
    elif isinstance(node, SequenceNode):
        for value in node.value:
            _validate_yaml_node(value)


def _yaml_root_has_identity(node: Node) -> bool:
    if not isinstance(node, MappingNode):
        return False
    keys = {
        key.value for key, _value in node.value if isinstance(key, ScalarNode)
    }
    return bool(keys & {"apiVersion", "kind"})


def _yaml_nested_complete_identity(node: Node) -> bool:
    if isinstance(node, MappingNode):
        keys = {
            key.value for key, _value in node.value if isinstance(key, ScalarNode)
        }
        if {"apiVersion", "kind"} <= keys:
            return True
        return any(
            _yaml_nested_complete_identity(value) for _key, value in node.value
        )
    if isinstance(node, SequenceNode):
        return any(_yaml_nested_complete_identity(value) for value in node.value)
    return False


def _bounded_yaml_documents(content: bytes) -> tuple:
    """Classify first from syntax nodes; construct only Kubernetes-like documents."""
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DomainError("Kubernetes YAML must be UTF-8") from exc
    depth = nodes = aliases = 0
    try:
        for event in yaml.parse(text, Loader=yaml.BaseLoader):
            if isinstance(event, AliasEvent):
                aliases += 1
                if aliases > _MAX_YAML_NODES:
                    raise DomainError("YAML alias limit exceeded")
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                depth += 1
                nodes += 1
                if depth > _MAX_YAML_DEPTH:
                    raise DomainError("Kubernetes YAML depth limit exceeded")
                if nodes > _MAX_YAML_NODES:
                    raise DomainError("Kubernetes YAML node limit exceeded")
            elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                depth -= 1
        composed = tuple(yaml.compose_all(text, Loader=yaml.BaseLoader))
    except DomainError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        raise DomainError("Kubernetes YAML syntax is malformed or unsupported") from exc
    if len(composed) > _MAX_YAML_DOCUMENTS:
        raise DomainError("Kubernetes YAML document limit exceeded")
    documents = []
    for node in composed:
        if node is None:
            continue
        _validate_yaml_node(node)
        if not _yaml_root_has_identity(node):
            if _yaml_nested_complete_identity(node):
                raise DomainError("unsupported Kubernetes YAML document shape")
            continue
        if aliases:
            raise DomainError("Kubernetes YAML aliases are unsupported")
        stack = [node]
        while stack:
            current = stack.pop()
            if current.tag not in _SAFE_YAML_TAGS:
                raise DomainError("Kubernetes YAML rejected: unsafe/custom YAML tag")
            if isinstance(current, MappingNode):
                stack.extend(part for pair in current.value for part in pair)
            elif isinstance(current, SequenceNode):
                stack.extend(current.value)
        try:
            rendered = yaml.serialize(node)
            documents.append(yaml.load(rendered, Loader=_StrictSafeLoader))
        except (yaml.YAMLError, RecursionError) as exc:
            raise DomainError("Kubernetes YAML syntax is malformed or unsupported") from exc
    return tuple(documents)


def _kubernetes_resources(
    relative: str, content: bytes
) -> tuple[tuple[ExpectedResource, ...], tuple[CheckovKubernetesIdentity, ...]]:
    return _resources_from_kubernetes_documents(
        relative, _bounded_yaml_documents(content), ArtifactKind.KUBERNETES_YAML
    )


def _strict_json_document(content: bytes) -> object:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DomainError("Kubernetes JSON must be UTF-8") from exc
    in_string = escaped = False
    depth = 0
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_YAML_DEPTH:
                raise DomainError("Kubernetes JSON depth limit exceeded")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise DomainError("Kubernetes JSON structure is unbalanced")

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise DomainError(f"duplicate Kubernetes JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=unique_pairs)
    except DomainError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise DomainError("Kubernetes JSON syntax is malformed or unsupported") from exc


def _json_contains_identity(value: object) -> bool:
    if type(value) is dict:
        if set(value) & {"apiVersion", "kind"}:
            return True
        return any(_json_contains_identity(item) for item in value.values())
    if type(value) is list:
        return any(_json_contains_identity(item) for item in value)
    return False


def _kubernetes_json_resources(
    relative: str, content: bytes
) -> tuple[tuple[ExpectedResource, ...], tuple[CheckovKubernetesIdentity, ...]]:
    document = _strict_json_document(content)
    if not _json_contains_identity(document):
        return (), ()
    if type(document) is not dict:
        raise DomainError("unsupported Kubernetes JSON document shape")
    return _resources_from_kubernetes_documents(
        relative, (document,), ArtifactKind.KUBERNETES_JSON
    )


def _read_detector_file(path: Path, root: Path, max_bytes: int) -> bytes:
    """Read one bounded regular file through a no-follow descriptor."""
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise DomainError("independent detector path escaped its scan root") from exc
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    chunks: list[bytes] = []
    size = 0
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise DomainError("independent detector input is not a regular file")
            while True:
                chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise DomainError("independent detector input exceeds its per-file limit")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DomainError("independent detector could not safely open an input") from exc
    return b"".join(chunks)


def attest_checkov_scan_plan(
    untrusted: CheckovScanRequest,
    config: TrustedVerificationConfigBundle | None = None,
    role: ScanRole = ScanRole.DISCOVERY,
) -> TrustedScanPlan:
    """Re-discover bytes/resources; production calls provide protected config."""
    require_exact_type(untrusted, CheckovScanRequest, "unattested Checkov request")
    require_enum(role, ScanRole, "scan-plan role")
    if config is not None:
        require_exact_type(config, TrustedVerificationConfigBundle, "verification config")
        if not config._trusted:
            raise DomainError("verification config lacks loader provenance")
        expected_root = (
            config.baseline_root if role is ScanRole.BASELINE
            else config.candidate_root if role is ScanRole.CANDIDATE
            else None
        )
        if expected_root is None:
            raise DomainError("protected scan-plan attestation requires an exact role")
        if untrusted.scan_root != expected_root:
            raise DomainError("scan root does not match its protected baseline/candidate role")
        frameworks = config.frameworks
        max_file_bytes = config.max_file_bytes
        max_total_bytes = config.max_total_eligible_bytes
        max_files = config.max_eligible_files
    else:
        # Discovery-only compatibility path. VerificationRequest always re-attests both
        # sides with its protected bundle before evidence can reach D5.
        frameworks = untrusted.frameworks
        max_file_bytes = untrusted.max_file_bytes
        max_total_bytes = untrusted.max_total_eligible_bytes
        max_files = untrusted.max_eligible_files
    files: list[ScanPlanFile] = []
    inspected_files: list[ScanPlanFile] = []
    resources: list[ExpectedResource] = []
    kubernetes: list[CheckovKubernetesIdentity] = []
    eligible: list[str] = []
    classifications: list[ArtifactClassification] = []
    root = untrusted.scan_root
    source_state, governed_paths, filesystem_entries = _source_snapshot_state(
        root,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        include_entries=True,
    )
    for entry in filesystem_entries:
        path = root / entry.file_path
        is_tf_json = path.name.lower().endswith(".tf.json")
        suffix = path.suffix.lower()
        relevant = (
            (suffix == ".tf" or is_tf_json) and "terraform" in frameworks
        ) or (
            suffix in {".yaml", ".yml", ".json"}
            and not is_tf_json
            and "kubernetes" in frameworks
        )
        if entry.kind != "REGULAR_FILE":
            if relevant and config is None:
                raise DomainError("independent detector refuses symlinked IaC input")
            continue
        if not relevant:
            continue
        relative = entry.file_path
        if is_tf_json and "terraform" in frameworks:
            raise DomainError("Terraform JSON (.tf.json) is explicitly unsupported")
        if entry.content is None:
            raise DomainError("shared source inventory omitted regular-file bytes")
        content = entry.content
        detected: tuple[ExpectedResource, ...] = ()
        file_type = ""
        classification = ""
        syntax_kind = ""
        if suffix == ".tf" and "terraform" in frameworks:
            detected = _terraform_resources(relative, content)
            file_type = ArtifactKind.TERRAFORM_HCL.value
            classification = "TERRAFORM_RESOURCES"
            syntax_kind = "terraform_hcl"
        elif suffix in {".yaml", ".yml"} and "kubernetes" in frameworks:
            detected, identities = _kubernetes_resources(relative, content)
            if not detected:
                classification = "NON_KUBERNETES_YAML"
            else:
                kubernetes.extend(identities)
                file_type = ArtifactKind.KUBERNETES_YAML.value
                classification = "KUBERNETES_RESOURCES"
            syntax_kind = "yaml"
        elif suffix == ".json" and "kubernetes" in frameworks:
            detected, identities = _kubernetes_json_resources(relative, content)
            if not detected:
                classification = "NON_KUBERNETES_JSON"
            else:
                kubernetes.extend(identities)
                file_type = ArtifactKind.KUBERNETES_JSON.value
                classification = "KUBERNETES_RESOURCES"
            syntax_kind = "json"
        else:
            continue
        classifications.append(
            ArtifactClassification(
                relative,
                hashlib.sha256(content).hexdigest(),
                len(content),
                syntax_kind,
                classification,
                tuple(detected),
            )
        )
        inspected_files.append(
            ScanPlanFile(
                relative,
                file_type or f"classified_{syntax_kind}",
                len(content),
                hashlib.sha256(content).hexdigest(),
                content,
            )
        )
        if not file_type:
            continue
        if len(eligible) >= max_files:
            raise DomainError("independent detector input exceeds its eligible-file limit")
        eligible.append(relative)
        resources.extend(detected)
        files.append(
            ScanPlanFile(
                relative, file_type, len(content), hashlib.sha256(content).hexdigest(), content
            )
        )
    request = CheckovScanRequest(
        executable=config.scanner_executable if config else untrusted.executable,
        scan_root=untrusted.scan_root,
        workspace_root=untrusted.workspace_root,
        frameworks=frameworks,
        files_eligible=tuple(eligible),
        expected_version=config.expected_version if config else untrusted.expected_version,
        expected_executable_sha256=(config.expected_executable_sha256 if config else untrusted.expected_executable_sha256),
        expected_scanner_environment_sha256=(config.expected_scanner_environment_sha256 if config else untrusted.expected_scanner_environment_sha256),
        expected_policy_inventory_sha256=(config.expected_policy_inventory_sha256 if config else untrusted.expected_policy_inventory_sha256),
        kubernetes_identities=tuple(kubernetes),
        expected_resources=tuple(resources),
        timeout_seconds=config.timeout_seconds if config else untrusted.timeout_seconds,
        max_output_bytes=config.max_output_bytes if config else untrusted.max_output_bytes,
        max_eligible_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_eligible_bytes=max_total_bytes,
    )
    evidence_by_path = {item.file_path: item for item in request.eligible_file_evidence}
    if any(
        evidence_by_path[item.file_path].sha256 != item.sha256
        or evidence_by_path[item.file_path].size != item.size
        for item in files
    ):
        raise DomainError("source bytes changed during independent scan-plan attestation")
    ordered_resources = tuple(sorted(resources, key=lambda item: item.canonical_key))
    ordered_classifications = tuple(
        sorted(classifications, key=lambda item: item.file_path)
    )
    inventory_payload = {
        "resources": [item.canonical_dict() for item in ordered_resources],
        "classifications": [
            item.canonical_dict() for item in ordered_classifications
        ],
    }
    inventory_digest = hashlib.sha256(
        json.dumps(inventory_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if config is not None:
        expected_state = (
            config.baseline_source_snapshot_sha256
            if role is ScanRole.BASELINE
            else config.candidate_source_snapshot_sha256
        )
        if source_state != expected_state:
            raise DomainError("role source snapshot changed after protected configuration")
    return TrustedScanPlan(
        request=request,
        files=tuple(sorted(files, key=lambda item: item.file_path)),
        resources=ordered_resources,
        inventory_sha256=inventory_digest,
        classifications=ordered_classifications,
        inspected_files=tuple(sorted(inspected_files, key=lambda item: item.file_path)),
        governed_paths=governed_paths,
        role=role,
        snapshot_sha256="",
        artifact_manifest_sha256="",
        source_state_sha256=source_state if config is not None else "",
        config_sha256=config.config_sha256 if config is not None else "",
        repository_identity=(
            config.policy_source_authorization.repository_identity
            or "operator_content_repository_v1"
            if config is not None else "operator_content_repository_v1"
        ),
        repository_relative_subpath=(
            config.baseline_repository_relative_subpath
            if role is ScanRole.BASELINE
            else config.candidate_repository_relative_subpath
            if role is ScanRole.CANDIDATE
            else "."
        ) if config is not None else ".",
        filesystem_entries=filesystem_entries,
        _trusted_context=_TRUSTED_SCAN_PLAN_CONTEXT,
    )


@dataclass(frozen=True, slots=True)
class VerificationRequest:
    """Paths, selectors, and one loader-attested protected configuration."""

    baseline_scan: TrustedScanPlan
    candidate_scan: TrustedScanPlan
    targets: tuple
    config: TrustedVerificationConfigBundle

    def __post_init__(self) -> None:
        require_exact_type(self.baseline_scan, TrustedScanPlan, "baseline trusted scan plan")
        require_exact_type(self.candidate_scan, TrustedScanPlan, "candidate trusted scan plan")
        if not self.baseline_scan._trusted or not self.candidate_scan._trusted:
            raise DomainError("verification scan plans require detector provenance")
        require_exact_type(self.config, TrustedVerificationConfigBundle, "verification config")
        if not self.config._trusted:
            raise DomainError("verification config lacks loader provenance")
        if self.config.baseline_root == self.config.candidate_root:
            raise DomainError("differential verification requires distinct roots")
        if self.baseline_scan.scan_root != self.config.baseline_root:
            raise DomainError("baseline scan root does not match the protected baseline role")
        if self.candidate_scan.scan_root != self.config.candidate_root:
            raise DomainError("candidate scan root does not match the protected candidate role")
        if self.baseline_scan.role is ScanRole.CANDIDATE:
            raise DomainError("candidate-attested scan plan cannot be reused as baseline")
        if self.candidate_scan.role is ScanRole.BASELINE:
            raise DomainError("baseline-attested scan plan cannot be reused as candidate")
        for supplied in (self.baseline_scan, self.candidate_scan):
            if supplied.role is not ScanRole.DISCOVERY and supplied.config_sha256 != self.config.config_sha256:
                raise DomainError("role-bound scan plan belongs to a different trusted config")
        baseline = attest_checkov_scan_plan(
            self.baseline_scan.request, self.config, ScanRole.BASELINE
        )
        candidate = attest_checkov_scan_plan(
            self.candidate_scan.request, self.config, ScanRole.CANDIDATE
        )
        if (
            self.baseline_scan.role is ScanRole.BASELINE
            and self.baseline_scan.snapshot_sha256 != baseline.snapshot_sha256
        ):
            raise DomainError("baseline role snapshot changed after attestation")
        if (
            self.candidate_scan.role is ScanRole.CANDIDATE
            and self.candidate_scan.snapshot_sha256 != candidate.snapshot_sha256
        ):
            raise DomainError("candidate role snapshot changed after attestation")
        object.__setattr__(self, "baseline_scan", baseline)
        object.__setattr__(self, "candidate_scan", candidate)
        if type(self.targets) is not tuple or not self.targets:
            raise DomainError("targets must be a nonempty exact tuple")
        rebuilt: list[ResolvedTargetBinding] = []
        for item in self.targets:
            require_exact_type(item, Target, "verification target")
            matches = [
                resource for resource in baseline.expected_resources
                if resource.resource_address == item.scope
                and (not item.file_path or resource.file_path == item.file_path)
                and (
                    item.artifact_kind is ArtifactKind.UNKNOWN
                    or resource.artifact_kind is item.artifact_kind
                )
                and (
                    not item.scanner_native_lookup
                    or resource.scanner_native_lookup == item.scanner_native_lookup
                )
            ]
            if not matches:
                raise DomainError("target selector does not resolve in baseline inventory")
            if len(matches) != 1:
                raise DomainError(
                    "target selector is ambiguous; provide file/artifact/native identity"
                )
            resource = matches[0]
            rebuilt.append(
                ResolvedTargetBinding(
                    TargetIdentity(
                        item.identity.scanner,
                        item.identity.rule_id,
                        item.identity.scope,
                    ),
                    resource.file_path,
                    resource.artifact_kind,
                    resource.scanner_native_lookup,
                    item.baseline_occurrences,
                )
            )
        keys = [item.canonical_key for item in rebuilt]
        if len(keys) != len(set(keys)):
            raise DomainError("verification targets contain duplicate identities")
        if any(item.scanner != "checkov" for item in rebuilt):
            raise DomainError("D5 supports Checkov targets only")
        object.__setattr__(self, "targets", tuple(sorted(rebuilt, key=lambda x: x.canonical_key)))

    @property
    def required_gates(self) -> RequiredGates:
        return self.config.required_gates

    @property
    def severity_floor(self) -> Severity:
        return self.config.severity_floor

    @property
    def fail_on_location_change(self) -> bool:
        return self.config.fail_on_location_change


@dataclass(frozen=True, slots=True)
class TargetObservation:
    """Typed facts used by the total target classifier.

    ``PASS`` means the named positive property was established; ``FAIL`` means its
    specified contrary was established; every operational state remains uncertainty.
    """

    identity: TargetIdentity
    baseline_occurrences: int
    candidate_matches: int
    scanner_integrity: Status
    ruleset_integrity: Status
    artifact_eligibility: Status
    target_file_presence: Status
    target_resource_presence: Status
    suppression_absence: Status
    occurrence_evidence: Status
    affirmative_target_pass: Status

    def __post_init__(self) -> None:
        require_exact_type(self.identity, TargetIdentity, "target identity")
        for name in ("baseline_occurrences", "candidate_matches"):
            value = getattr(self, name)
            if type(value) is not int or value < (1 if name == "baseline_occurrences" else 0):
                raise DomainError(f"{name} is outside its valid count domain")
        for name in (
            "scanner_integrity", "ruleset_integrity", "artifact_eligibility",
            "target_file_presence", "target_resource_presence", "suppression_absence",
            "occurrence_evidence", "affirmative_target_pass",
        ):
            require_enum(getattr(self, name), Status, name)


def classify_target(observation: TargetObservation) -> Outcome:
    """Apply semantics section 4 in fail-closed order."""
    require_exact_type(observation, TargetObservation, "target observation")
    o = observation
    if o.scanner_integrity is not Status.PASS:
        return Outcome.SCANNER_ERROR
    if o.ruleset_integrity is Status.FAIL:
        return Outcome.RULE_OR_SCANNER_DRIFT
    if o.ruleset_integrity is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.artifact_eligibility is Status.FAIL:
        return Outcome.OUT_OF_SCOPE
    if o.artifact_eligibility is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.target_file_presence is Status.FAIL:
        return Outcome.FILE_DELETED_OR_RENAMED
    if o.target_file_presence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.target_resource_presence is Status.FAIL:
        return Outcome.RESOURCE_DELETED
    if o.target_resource_presence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.suppression_absence is Status.FAIL:
        return Outcome.SUPPRESSED
    if o.suppression_absence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.occurrence_evidence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.baseline_occurrences > 1 and 0 < o.candidate_matches < o.baseline_occurrences:
        return Outcome.PARTIALLY_FIXED
    if o.candidate_matches >= o.baseline_occurrences:
        return Outcome.STILL_PRESENT
    if o.candidate_matches == 0 and o.affirmative_target_pass is Status.PASS:
        return Outcome.FIXED
    return Outcome.INCONCLUSIVE


@dataclass(frozen=True, slots=True)
class TargetOutcomeEvidence:
    identity: TargetIdentity
    binding: ResolvedTargetBinding
    outcome: Outcome
    observation: TargetObservation
    target_reason: str
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_exact_type(self.identity, TargetIdentity, "target identity")
        require_exact_type(self.binding, ResolvedTargetBinding, "resolved target binding")
        if self.binding.identity.canonical_key != self.identity.canonical_key:
            raise DomainError("resolved target binding disagrees with target identity")
        require_enum(self.outcome, Outcome, "target outcome")
        require_exact_type(self.observation, TargetObservation, "target observation")
        if self.identity.canonical_key != self.observation.identity.canonical_key:
            raise DomainError("target outcome identity disagrees with its observation")
        if self.outcome is not classify_target(self.observation):
            raise DomainError("target outcome does not satisfy its classification predicate")
        object.__setattr__(self, "target_reason", canonical_identifier(self.target_reason, "target reason"))
        if _trusted_context is not _TRUSTED_ENGINE_CONTEXT:
            raise DomainError("target outcome evidence requires trusted engine execution")
        object.__setattr__(self, "_trusted", True)

    @property
    def canonical_key(self) -> tuple:
        return (*self.binding.canonical_key, self.outcome.value)

    def canonical_dict(self) -> dict:
        return {
            "identity": self.identity.canonical_dict(),
            "binding": self.binding.canonical_dict(),
            "outcome": self.outcome.value,
            "target_reason": self.target_reason,
            "counts": {
                "baseline": self.observation.baseline_occurrences,
                "candidate": self.observation.candidate_matches,
            },
        }


_ENGINE_DELTA_CLASSES = frozenset({
    DeltaClass.RULE_SUBSTITUTED,
    DeltaClass.COVERAGE_DECREASED,
    DeltaClass.DIAGNOSTIC_ADDED,
    DeltaClass.DESTRUCTIVE_CHANGE,
    DeltaClass.POLICY_DRIFT,
})


@dataclass(frozen=True, slots=True)
class EngineEventEvaluation:
    """Typed evaluation of one delta class that D3 finding evidence cannot prove."""

    delta_class: DeltaClass
    status: Status
    reason_code: str
    affected_resource_records: tuple = ()
    affected_resources: tuple = ()
    affected_paths: tuple = ()
    detail: str = ""

    def __post_init__(self) -> None:
        require_enum(self.delta_class, DeltaClass, "engine delta class")
        if self.delta_class not in _ENGINE_DELTA_CLASSES:
            raise DomainError("EngineEventEvaluation accepts only D5-derived delta classes")
        require_enum(self.status, Status, "engine event status")
        object.__setattr__(self, "reason_code", canonical_identifier(self.reason_code, "engine event reason"))
        if type(self.affected_resource_records) is not tuple or any(
            type(item) is not ExpectedResource for item in self.affected_resource_records
        ):
            raise DomainError(
                "affected_resource_records must be an exact tuple of ExpectedResource"
            )
        object.__setattr__(
            self,
            "affected_resource_records",
            tuple(sorted(self.affected_resource_records, key=lambda item: item.canonical_key)),
        )
        for name in ("affected_resources", "affected_paths"):
            raw = getattr(self, name)
            if type(raw) is not tuple or any(type(item) is not str or not item for item in raw):
                raise DomainError(f"{name} must be an exact tuple of nonblank strings")
            object.__setattr__(self, name, tuple(sorted(set(raw))))
        if type(self.detail) is not str:
            raise DomainError("engine event detail must be a string")

    @property
    def canonical_key(self) -> tuple:
        return (self.delta_class.value, self.status.value, self.reason_code,
                tuple(item.canonical_key for item in self.affected_resource_records),
                self.affected_resources, self.affected_paths, self.detail)

    def canonical_dict(self) -> dict:
        return {
            "delta_class": self.delta_class.value,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "affected_resource_records": [
                item.canonical_dict() for item in self.affected_resource_records
            ],
            "affected_resources": list(self.affected_resources),
            "affected_paths": list(self.affected_paths),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ChangeMetrics:
    """Deterministic V4 metrics; unavailable values are named, never omitted."""

    lines_added: int
    lines_removed: int
    lines_changed: int
    diff_ratio: float
    files_changed: int
    resources_changed: int
    resources_added: int
    resources_deleted: int
    policy_files_changed: int | None
    unavailable_metrics: tuple = ()

    def __post_init__(self) -> None:
        for name in (
            "lines_added", "lines_removed", "lines_changed", "files_changed",
            "resources_changed", "resources_added", "resources_deleted",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise DomainError(f"{name} must be a nonnegative exact int")
        if type(self.diff_ratio) is not float or self.diff_ratio < 0:
            raise DomainError("diff_ratio must be a nonnegative float")
        if self.policy_files_changed is not None and (
            type(self.policy_files_changed) is not int or self.policy_files_changed < 0
        ):
            raise DomainError("policy_files_changed must be a nonnegative int or None")
        if type(self.unavailable_metrics) is not tuple:
            raise DomainError("unavailable_metrics must be an exact tuple")
        object.__setattr__(self, "unavailable_metrics", tuple(sorted(set(self.unavailable_metrics))))

    def canonical_dict(self) -> dict:
        return {
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "lines_changed": self.lines_changed,
            "diff_ratio": self.diff_ratio,
            "files_changed": self.files_changed,
            "resources_changed": self.resources_changed,
            "resources_added": self.resources_added,
            "resources_deleted": self.resources_deleted,
            "policy_files_changed": self.policy_files_changed,
            "unavailable_metrics": list(self.unavailable_metrics),
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    baseline_run: ScannerRun
    candidate_run: ScannerRun
    finding_diff: FindingDiffResult
    target_outcomes: tuple
    preflight: GateResult
    scanner_integrity: GateResult
    validator_results: tuple
    oracle_results: tuple
    regression: GateResult
    suppression: GateResult
    engine_events: tuple
    change_metrics: ChangeMetrics
    required_gates: RequiredGates
    verification_config: TrustedVerificationConfigBundle
    baseline_snapshot: SealedVerificationSnapshot
    candidate_snapshot: SealedVerificationSnapshot
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_trusted_scanner_run(self.baseline_run)
        require_trusted_scanner_run(self.candidate_run)
        require_trusted_diff_result(self.finding_diff)
        require_exact_type(self.required_gates, RequiredGates, "required gates")
        require_exact_type(
            self.verification_config,
            TrustedVerificationConfigBundle,
            "verification config",
        )
        if not self.verification_config._trusted:
            raise DomainError("verification result config lacks loader provenance")
        for name, role in (
            ("baseline_snapshot", ScanRole.BASELINE),
            ("candidate_snapshot", ScanRole.CANDIDATE),
        ):
            snapshot = getattr(self, name)
            require_exact_type(snapshot, SealedVerificationSnapshot, name)
            if not snapshot._trusted or snapshot.role is not role:
                raise DomainError(f"{name} lacks role-bound factory provenance")
            if snapshot.config_sha256 != self.verification_config.config_sha256:
                raise DomainError(f"{name} belongs to a different verification config")
        if self.required_gates != self.verification_config.required_gates:
            raise DomainError("verification result gates disagree with protected config")
        for name in ("preflight", "scanner_integrity", "regression", "suppression"):
            require_exact_type(getattr(self, name), GateResult, name)
        for name, expected_ids in (
            ("validator_results", self.required_gates.validator_ids),
            ("oracle_results", self.required_gates.oracle_ids),
        ):
            values = getattr(self, name)
            if type(values) is not tuple or any(type(item) is not GateResult for item in values):
                raise DomainError(f"{name} must be an exact tuple of GateResult")
            if tuple(item.gate_id for item in values) != expected_ids:
                raise DomainError(f"{name} do not exactly cover required gate identities")
        if type(self.target_outcomes) is not tuple or not self.target_outcomes:
            raise DomainError("target outcomes must be a nonempty exact tuple")
        if any(type(item) is not TargetOutcomeEvidence or not item._trusted for item in self.target_outcomes):
            raise DomainError("target outcomes contain caller-authored evidence")
        if type(self.engine_events) is not tuple:
            raise DomainError("engine_events must be an exact tuple")
        expected_classes = _ENGINE_DELTA_CLASSES
        actual_classes = {item.delta_class for item in self.engine_events
                          if type(item) is EngineEventEvaluation}
        if any(type(item) is not EngineEventEvaluation for item in self.engine_events):
            raise DomainError("engine_events must contain exact EngineEventEvaluation values")
        if actual_classes != expected_classes or len(self.engine_events) != len(expected_classes):
            raise DomainError("engine_events must evaluate every D5-derived delta class exactly once")
        require_exact_type(self.change_metrics, ChangeMetrics, "change metrics")
        if _trusted_context is not _TRUSTED_ENGINE_CONTEXT:
            raise DomainError("VerificationResult requires trusted engine execution")
        object.__setattr__(self, "target_outcomes", tuple(sorted(self.target_outcomes, key=lambda x: x.canonical_key)))
        object.__setattr__(self, "engine_events", tuple(sorted(self.engine_events, key=lambda x: x.canonical_key)))
        object.__setattr__(self, "_trusted", True)

    def _event(self, delta_class: DeltaClass) -> EngineEventEvaluation:
        return next(item for item in self.engine_events if item.delta_class is delta_class)

    @property
    def policy_drift(self) -> bool:
        return self._event(DeltaClass.POLICY_DRIFT).status is Status.FAIL

    @property
    def coverage_decreased_on_required_scanner(self) -> bool:
        return self._event(DeltaClass.COVERAGE_DECREASED).status is not Status.PASS

    @property
    def rule_substituted_on_required_target(self) -> bool:
        return self._event(DeltaClass.RULE_SUBSTITUTED).status is not Status.PASS

    def canonical_dict(self) -> dict:
        return {
            "preflight": self.preflight.canonical_dict(),
            "scanner_integrity": self.scanner_integrity.canonical_dict(),
            "validators": [item.canonical_dict() for item in self.validator_results],
            "oracles": [item.canonical_dict() for item in self.oracle_results],
            "targets": [item.canonical_dict() for item in self.target_outcomes],
            "finding_diff": self.finding_diff.canonical_dict(),
            "regression": self.regression.canonical_dict(),
            "suppression": self.suppression.canonical_dict(),
            "engine_events": [item.canonical_dict() for item in self.engine_events],
            "change_metrics": self.change_metrics.canonical_dict(),
            "baseline_run": self.baseline_run.canonical_dict(),
            "candidate_run": self.candidate_run.canonical_dict(),
            "verification_config": self.verification_config.canonical_dict(),
            "gate_implementations": [
                item.canonical_dict()
                for item in self.verification_config.gate_registry.implementations
            ],
            "baseline_snapshot": self.baseline_snapshot.canonical_dict(),
            "candidate_snapshot": self.candidate_snapshot.canonical_dict(),
        }


def require_trusted_verification_result(value: object) -> VerificationResult:
    require_exact_type(value, VerificationResult, "verification result")
    if not value._trusted:
        raise DomainError("verification result is caller-authored, not trusted engine evidence")
    return value


def _gate_results(
    ids: tuple,
    kind: str,
    snapshot: SealedVerificationSnapshot,
    registry: TrustedGateRegistry,
) -> tuple[GateResult, ...]:
    results: list[GateResult] = []
    for gate_id in ids:
        result = registry.execute(kind, gate_id, snapshot)
        results.append(result)
    return tuple(results)


def _target_paths(run: ScannerRun, target: ResolvedTargetBinding) -> tuple[str, ...]:
    return tuple(sorted({
        finding.location.file_path
        for finding in run.findings
        if finding.scanner == target.scanner
        and finding.rule_id == target.rule_id
        and finding.resource_address == target.scope
        and finding.location.file_path == target.file_path
        and finding.artifact_kind is target.artifact_kind
    }))


def _execution_identity(run: ScannerRun) -> tuple:
    return (
        run.scanner,
        run.scanner_version,
        run.launcher_digest,
        run.scanner_environment_digest,
        run.policy_inventory_digest,
        run.invocation_config_digest,
        run.installed_distribution_digest,
        run.dependency_lock_digest,
        run.custom_check_digest,
    )


def _occurrence_complete_pass(
    target: ResolvedTargetBinding,
    baseline_findings: tuple,
    candidate: ScannerRun,
    candidate_resource_paths: frozenset[str],
) -> bool:
    """A generic positive record closes one occurrence, never an arbitrary multiset."""
    passed = tuple(
        item for item in candidate.evaluations
        if item.rule_id == target.rule_id
        and item.resource_address == target.scope
        and item.native_result.value == "PASSED"
        and item.file_path in candidate_resource_paths
    )
    if not passed:
        return False
    if target.baseline_occurrences == 1:
        return True
    baseline_tokens = {
        item.native_fingerprint for item in baseline_findings if item.native_fingerprint
    }
    evaluated_tokens = {item.occurrence_token for item in passed if item.occurrence_token}
    if len(baseline_tokens) == target.baseline_occurrences:
        return baseline_tokens <= evaluated_tokens
    return False


def _target_observation(
    target: ResolvedTargetBinding,
    baseline: ScannerRun,
    candidate: ScannerRun,
    diff: FindingDiffResult,
    request: VerificationRequest,
) -> tuple[TargetObservation, str]:
    run_ok = baseline.status is Status.PASS and candidate.status is Status.PASS
    stable = (
        baseline.scanner == candidate.scanner == target.scanner
        and _execution_identity(baseline) == _execution_identity(candidate)
        and baseline.ruleset_integrity is Status.PASS
        and candidate.ruleset_integrity is Status.PASS
    )
    baseline_findings = tuple(
        f for f in baseline.findings
        if f.rule_id == target.rule_id and f.resource_address == target.scope
        and f.location.file_path == target.file_path
        and f.artifact_kind is target.artifact_kind
    )
    candidate_findings = tuple(
        f for f in candidate.findings
        if f.rule_id == target.rule_id and f.resource_address == target.scope and not f.suppressed
        and f.location.file_path == target.file_path
        and f.artifact_kind is target.artifact_kind
    )
    baseline_paths = _target_paths(baseline, target)
    eligible = set(request.candidate_scan.files_eligible)
    target_resource_records = tuple(
        item for item in request.candidate_scan.expected_resources
        if item.canonical_key == target.resource_key
    )
    expected_resources = {item.canonical_key for item in request.candidate_scan.expected_resources}
    resource_present = target.resource_key in expected_resources
    path_present = resource_present or any(path in eligible for path in baseline_paths)
    classified_paths = {
        item.file_path for item in request.candidate_scan.classifications
    }
    physical_present = any(path in classified_paths for path in baseline_paths)
    if resource_present or path_present:
        file_state = Status.PASS
        eligibility = Status.PASS
    elif baseline_paths and physical_present:
        file_state = Status.PASS
        eligibility = Status.FAIL
    elif baseline_paths:
        file_state = Status.FAIL
        eligibility = Status.PASS
    else:
        file_state = Status.INCONCLUSIVE
        eligibility = Status.INCONCLUSIVE
    resource_state = Status.PASS if resource_present else Status.FAIL
    ambiguity = any(
        any(f.rule_id == target.rule_id and f.resource_address == target.scope
            and f.location.file_path == target.file_path
            and f.artifact_kind is target.artifact_kind
            for f in (*item.baseline, *item.candidate))
        for item in diff.ambiguities
    )
    target_evidence = evaluate_checkov_target(
        candidate, target.rule_id, target.scope,
        target.file_path if target.file_path in eligible else None,
    )
    suppressed = (
        target_evidence.reason is CheckTargetReason.TARGET_SUPPRESSED
        or any(f.suppressed for f in candidate.findings
               if f.rule_id == target.rule_id and f.resource_address == target.scope
               and f.location.file_path == target.file_path
               and f.artifact_kind is target.artifact_kind)
    )
    baseline_count_ok = len(baseline_findings) == target.baseline_occurrences
    candidate_resource_paths = frozenset(item.file_path for item in target_resource_records)
    artifact_kinds = {item.artifact_kind for item in baseline_findings}
    candidate_artifact_kinds = {item.artifact_kind for item in target_resource_records}
    domain_bound = (
        len(artifact_kinds) == 1
        and artifact_kinds == candidate_artifact_kinds
        and bool(candidate_resource_paths)
    )
    complete_pass = (
        target_evidence.status is Status.PASS
        and domain_bound
        and _occurrence_complete_pass(
            target, baseline_findings, candidate, candidate_resource_paths
        )
    )
    affirmative_status = (
        Status.PASS if complete_pass
        else Status.INCONCLUSIVE if target_evidence.status is Status.PASS
        else target_evidence.status
    )
    observation = TargetObservation(
        identity=target.identity,
        baseline_occurrences=target.baseline_occurrences,
        candidate_matches=len(candidate_findings),
        scanner_integrity=Status.PASS if run_ok else Status.ERROR,
        ruleset_integrity=Status.PASS if stable else Status.FAIL,
        artifact_eligibility=eligibility,
        target_file_presence=file_state,
        target_resource_presence=resource_state,
        suppression_absence=Status.FAIL if suppressed else Status.PASS,
        occurrence_evidence=(Status.PASS if baseline_count_ok and not ambiguity else Status.INCONCLUSIVE),
        affirmative_target_pass=affirmative_status,
    )
    reason = (
        "OCCURRENCE_PASS_COVERAGE_INCOMPLETE"
        if target_evidence.status is Status.PASS and not complete_pass
        else target_evidence.reason.value
    )
    return observation, reason


def _regression_result(
    request: VerificationRequest,
    diff: FindingDiffResult,
    outcomes: tuple,
    engine_events: tuple,
) -> GateResult:
    if diff.ambiguities:
        return GateResult("regression", Status.INCONCLUSIVE, "MATCHING_INCONCLUSIVE")
    decisive = []
    uncertain = []
    floor = SEVERITY_ORDER.index(request.severity_floor)
    suppressed_targets = {
        (
            item.identity.scanner,
            item.identity.rule_id,
            item.identity.scope,
            item.binding.file_path,
            item.binding.artifact_kind.value,
        )
        for item in outcomes if item.outcome is Outcome.SUPPRESSED
    }
    for delta in diff.deltas:
        if delta.delta_class is DeltaClass.NEW_FINDING:
            if delta.candidate.severity is Severity.UNKNOWN:
                uncertain.append("NEW_FINDING_SEVERITY_UNKNOWN")
            elif SEVERITY_ORDER.index(delta.candidate.severity) >= floor:
                decisive.append(delta.delta_class.value)
        elif delta.delta_class in {
            DeltaClass.SEVERITY_INCREASED,
            DeltaClass.SCOPE_EXPANDED,
            DeltaClass.SUPPRESSION_ADDED,
        }:
            if delta.delta_class is DeltaClass.SUPPRESSION_ADDED:
                candidate = delta.candidate
                identity = (
                    candidate.scanner,
                    candidate.rule_id,
                    candidate.resource_address,
                    candidate.location.file_path,
                    candidate.artifact_kind.value,
                )
                if identity in suppressed_targets:
                    continue
            decisive.append(delta.delta_class.value)
        elif delta.delta_class is DeltaClass.LOCATION_CHANGED and request.fail_on_location_change:
            decisive.append(delta.delta_class.value)
    destructive = next(
        item for item in engine_events
        if item.delta_class is DeltaClass.DESTRUCTIVE_CHANGE
    )
    target_resource_keys = {
        item.binding.resource_key for item in outcomes
        if item.outcome in {Outcome.RESOURCE_DELETED, Outcome.FILE_DELETED_OR_RENAMED}
    }
    unrelated_deleted = {
        item.canonical_key for item in destructive.affected_resource_records
    } - target_resource_keys
    if unrelated_deleted:
        decisive.append(DeltaClass.DESTRUCTIVE_CHANGE.value)
    if uncertain:
        return GateResult(
            "regression", Status.INCONCLUSIVE, uncertain[0],
            ",".join(sorted(set(uncertain))),
        )
    if decisive:
        return GateResult("regression", Status.FAIL, "REGRESSION_DETECTED", ",".join(sorted(set(decisive))))
    return GateResult("regression", Status.PASS, "NO_DECISIVE_REGRESSION")


def _preflight_result(
    request: VerificationRequest, baseline: ScannerRun, candidate: ScannerRun
) -> GateResult:
    try:
        baseline_state, _baseline_governed, baseline_entries = _source_snapshot_state(
            request.config.baseline_root,
            max_files=request.config.max_eligible_files,
            max_file_bytes=request.config.max_file_bytes,
            max_total_bytes=request.config.max_total_eligible_bytes,
            include_entries=True,
        )
        candidate_state, _candidate_governed, candidate_entries = _source_snapshot_state(
            request.config.candidate_root,
            max_files=request.config.max_eligible_files,
            max_file_bytes=request.config.max_file_bytes,
            max_total_bytes=request.config.max_total_eligible_bytes,
            include_entries=True,
        )
        current_governed = _governed_comparison_from_entries(
            baseline_entries, candidate_entries
        )
    except DomainError as exc:
        return GateResult(
            "preflight", Status.ERROR, "GOVERNED_CONFIG_REVALIDATION_FAILED", str(exc)
        )
    if (
        baseline_state != request.baseline_scan.source_state_sha256
        or candidate_state != request.candidate_scan.source_state_sha256
    ):
        return GateResult(
            "preflight", Status.ERROR, "SNAPSHOT_CHANGED_DURING_VERIFICATION"
        )
    if tuple(item.canonical_dict() for item in current_governed) != tuple(
        item.canonical_dict() for item in request.config.governed_config
    ):
        return GateResult(
            "preflight", Status.ERROR, "GOVERNED_CONFIG_CHANGED_AFTER_ATTESTATION"
        )
    unsafe_artifacts = tuple(sorted(
        f"{role}:{item.file_path}:{item.rejection_reason}"
        for role, entries in (
            ("baseline", baseline_entries), ("candidate", candidate_entries)
        )
        for item in entries if item.rejection_reason
    ))
    if unsafe_artifacts:
        return GateResult(
            "preflight", Status.ERROR, "ARTIFACT_UNIVERSE_UNRESOLVED",
            ",".join(unsafe_artifacts),
        )
    unsafe_governed = tuple(
        item.file_path for item in current_governed
        if item.candidate_kind in {"SYMLINK", "OTHER"}
    )
    if unsafe_governed:
        return GateResult(
            "preflight", Status.ERROR, "GOVERNED_PATH_TYPE_UNSAFE",
            ",".join(unsafe_governed),
        )
    payload = {
        "baseline": [item.canonical_dict() for item in request.baseline_scan.eligible_file_evidence],
        "candidate": [item.canonical_dict() for item in request.candidate_scan.eligible_file_evidence],
        "baseline_resources": [item.canonical_dict() for item in request.baseline_scan.expected_resources],
        "candidate_resources": [item.canonical_dict() for item in request.candidate_scan.expected_resources],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    expected_inputs = (
        tuple(item.canonical_dict() for item in request.baseline_scan.eligible_file_evidence),
        tuple(item.canonical_dict() for item in request.candidate_scan.eligible_file_evidence),
    )
    actual_inputs = (
        tuple(item.canonical_dict() for item in baseline.input_files),
        tuple(item.canonical_dict() for item in candidate.input_files),
    )
    preparation_failures = {
        AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value,
        AdapterReason.SCAN_VIEW_PREPARATION_FAILED.value,
        AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value,
    }
    failed_diagnostics = tuple(sorted(
        diagnostic for run in (baseline, candidate) for diagnostic in run.diagnostics
        if diagnostic in preparation_failures
    ))
    if actual_inputs != expected_inputs or failed_diagnostics:
        return GateResult(
            "preflight", Status.ERROR, "BOUND_INPUT_REVALIDATION_FAILED",
            ",".join(failed_diagnostics) or "adapter input evidence disagrees with plan",
        )
    return GateResult(
        "preflight", Status.PASS, "BOUND_SCAN_PLAN_VALIDATED",
        f"plan_sha256={digest};files={len(payload['baseline'])}+{len(payload['candidate'])}",
    )


def _engine_events(
    request: VerificationRequest,
    baseline: ScannerRun,
    candidate: ScannerRun,
    stable_run: bool,
) -> tuple[EngineEventEvaluation, ...]:
    baseline_resources = {
        item.canonical_key: item for item in request.baseline_scan.expected_resources
    }
    candidate_resources = {
        item.canonical_key: item for item in request.candidate_scan.expected_resources
    }
    deleted_records = tuple(
        baseline_resources[key]
        for key in sorted(set(baseline_resources) - set(candidate_resources))
    )
    deleted = tuple(sorted({item.resource_address for item in deleted_records}))
    deleted_paths = tuple(sorted({item.file_path for item in deleted_records}))
    coverage_decreased = (
        candidate.status is Status.PARTIAL
        or candidate.coverage.files_parsed < candidate.coverage.files_eligible
        or candidate.resource_coverage.resources_observed
        < candidate.resource_coverage.resources_expected
    )
    coverage_status = (
        Status.FAIL if coverage_decreased
        else Status.PASS if candidate.status is Status.PASS
        else Status.INCONCLUSIVE
    )
    added_diagnostics = tuple(sorted(set(candidate.diagnostics) - set(baseline.diagnostics)))
    policy_drift_paths = request.config.policy_drift_paths
    policy_drift = bool(policy_drift_paths)
    return (
        EngineEventEvaluation(
            DeltaClass.RULE_SUBSTITUTED,
            Status.PASS if stable_run else Status.INCONCLUSIVE,
            "RULE_IDENTITY_STABLE" if stable_run else "RULE_SUBSTITUTION_NOT_DECIDABLE",
        ),
        EngineEventEvaluation(
            DeltaClass.COVERAGE_DECREASED,
            coverage_status,
            "COVERAGE_COMPLETE" if coverage_status is Status.PASS else "COVERAGE_DECREASED_OR_UNCERTAIN",
        ),
        EngineEventEvaluation(
            DeltaClass.DIAGNOSTIC_ADDED,
            Status.FAIL if added_diagnostics else Status.PASS,
            "DIAGNOSTICS_ADDED" if added_diagnostics else "NO_DIAGNOSTICS_ADDED",
            detail=",".join(added_diagnostics),
        ),
        EngineEventEvaluation(
            DeltaClass.DESTRUCTIVE_CHANGE,
            Status.FAIL if deleted else Status.PASS,
            "RESOURCES_DELETED" if deleted else "NO_RESOURCES_DELETED",
            affected_resource_records=deleted_records,
            affected_resources=deleted,
            affected_paths=deleted_paths,
        ),
        EngineEventEvaluation(
            DeltaClass.POLICY_DRIFT,
            Status.FAIL if policy_drift else Status.PASS,
            "GOVERNED_CONFIG_DRIFT" if policy_drift else "GOVERNED_CONFIG_STABLE",
            affected_paths=policy_drift_paths,
            detail=f"config={request.config.config_sha256}",
        ),
    )


def _read_bound_texts(scan: TrustedScanPlan) -> dict[str, tuple[str, ...]]:
    values = {}
    for evidence in scan.files:
        values[evidence.file_path] = tuple(
            evidence.content.decode("utf-8", errors="strict").splitlines()
        )
    return values


def _change_metrics(request: VerificationRequest) -> ChangeMetrics:
    before = _read_bound_texts(request.baseline_scan)
    after = _read_bound_texts(request.candidate_scan)
    added = removed = 0
    changed_files = 0
    for path in sorted(set(before) | set(after)):
        old = before.get(path, ())
        new = after.get(path, ())
        if old == new:
            continue
        changed_files += 1
        for line in difflib.ndiff(old, new):
            if line.startswith("+ "):
                added += 1
            elif line.startswith("- "):
                removed += 1
    before_resources = {item.canonical_key for item in request.baseline_scan.expected_resources}
    after_resources = {item.canonical_key for item in request.candidate_scan.expected_resources}
    resource_added = len(after_resources - before_resources)
    resource_deleted = len(before_resources - after_resources)
    denominator = max(sum(len(lines) for lines in before.values()), 1)
    return ChangeMetrics(
        added, removed, added + removed, float((added + removed) / denominator),
        changed_files, resource_added + resource_deleted, resource_added,
        resource_deleted, len(request.config.policy_drift_paths), (),
    )


def run_checkov_verification(
    request: VerificationRequest,
) -> VerificationResult:
    """Run both scans and derive all D5 evidence internally.

    Gate implementations come only from the loader-attested registry carried privately
    by the protected configuration bundle.
    """
    require_exact_type(request, VerificationRequest, "verification request")
    adapter = CheckovAdapter()
    baseline = require_trusted_scanner_run(adapter.scan(request.baseline_scan.request))
    candidate = require_trusted_scanner_run(adapter.scan(request.candidate_scan.request))
    stable_run = (
        _execution_identity(baseline) == _execution_identity(candidate)
        and baseline.ruleset_integrity is Status.PASS
        and candidate.ruleset_integrity is Status.PASS
    )
    if stable_run:
        diff = diff_findings(baseline.findings, candidate.findings)
    else:
        diff = diff_findings((), ())
    outcomes = []
    for target in request.targets:
        observation, reason = _target_observation(target, baseline, candidate, diff, request)
        outcomes.append(
            TargetOutcomeEvidence(
                target.identity,
                target,
                classify_target(observation),
                observation,
                reason,
                _trusted_context=_TRUSTED_ENGINE_CONTEXT,
            )
        )
    if (
        request.baseline_scan.sealed_snapshot is None
        or request.candidate_scan.sealed_snapshot is None
    ):
        raise DomainError("verification request lacks role-sealed snapshots")
    validators = _gate_results(
        request.required_gates.validator_ids, "validator",
        request.candidate_scan.sealed_snapshot,
        request.config.gate_registry,
    )
    oracles = _gate_results(
        request.required_gates.oracle_ids, "oracle",
        request.candidate_scan.sealed_snapshot,
        request.config.gate_registry,
    )
    scanner_status = (
        Status.PASS
        if baseline.status is Status.PASS and candidate.status is Status.PASS and stable_run
        else Status.INCONCLUSIVE
    )
    engine_events = _engine_events(request, baseline, candidate, stable_run)
    regression = _regression_result(request, diff, tuple(outcomes), engine_events)
    suppression_status = (
        Status.PASS if candidate.status is Status.PASS else Status.INCONCLUSIVE
    )
    preflight = _preflight_result(request, baseline, candidate)
    return VerificationResult(
        baseline,
        candidate,
        diff,
        tuple(outcomes),
        preflight,
        GateResult(
            "scanner_integrity", scanner_status,
            "SCANNER_EVIDENCE_RECONCILED" if scanner_status is Status.PASS
            else "SCANNER_EXECUTION_IDENTITY_DRIFT_OR_FAILURE",
        ),
        validators,
        oracles,
        regression,
        GateResult("suppression", suppression_status, "SUPPRESSION_DETECTOR_COMPLETED"),
        engine_events,
        _change_metrics(request),
        request.required_gates,
        request.config,
        request.baseline_scan.sealed_snapshot,
        request.candidate_scan.sealed_snapshot,
        _trusted_context=_TRUSTED_ENGINE_CONTEXT,
    )


__all__ = [
    "ArtifactClassification", "ChangeMetrics", "EngineEventEvaluation",
    "GateImplementation", "PolicySourceAuthorization",
    "GovernedConfigEvidence", "GovernedPathRecord",
    "ScanPlanFile", "TargetObservation",
    "SealedVerificationSnapshot", "TargetOutcomeEvidence", "TrustedScanPlan", "VerificationRequest",
    "TrustedGateRegistry", "TrustedVerificationConfigBundle", "VerificationResult",
    "attest_checkov_scan_plan", "classify_target",
    "load_operator_verification_config", "production_gate_registry",
    "require_trusted_verification_result", "run_checkov_verification",
]
