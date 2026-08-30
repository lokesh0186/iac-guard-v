"""Closed, local, deterministic Kustomize materialization for a8.

The external engine is allowed to transform only a complete preflighted source DAG.
Control documents are protected build inputs and never scanner target resources.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Iterator

import yaml

from .enums import Status
from .models import DomainError, canonical_repo_path
from .process import CommandRequest, run_command
from .redaction import redact_detail


KUSTOMIZE_MATERIALIZATION_CONTRACT = "kustomize-materialization-v1"
_CONTROL_NAMES = ("kustomization.yaml", "kustomization.yml", "Kustomization")
_ALLOWED_KEYS = frozenset({
    "apiVersion", "kind", "resources", "bases", "components", "namespace",
    "namePrefix", "nameSuffix", "commonLabels", "labels", "images", "patches",
    "patchesStrategicMerge", "patchesJson6902", "replacements",
    "configMapGenerator", "secretGenerator", "generatorOptions",
})
_FORBIDDEN_KEYS = frozenset({
    "configurations", "vars", "helmCharts", "generators", "transformers", "crds",
    "replicas", "sortOptions", "buildMetadata", "plugins", "functions", "exec",
})
_REMOTE = re.compile(
    r"^(?:https?|git|ssh|oci|github|s3|gs)://|^[^/\s]+@[^:]+:|(?:^|[?&])ref=",
    re.IGNORECASE,
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_INPUTS = 10_000
_MAX_INPUT_BYTES = 100 * 1024 * 1024
_MAX_FILE_BYTES = 10 * 1024 * 1024
_MAX_DEPTH = 64
_MAX_OUTPUT_BYTES = 32 * 1024 * 1024
_MAX_OUTPUT_DOCUMENTS = 5_000


class _StrictLoader(yaml.SafeLoader):
    pass


def _strict_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict:
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                "unhashable mapping key", key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"duplicate key {key!r}", key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=False)
    return result


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _strict_mapping
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha(value: object) -> str:
    return _sha(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"))


class KustomizeMaterializationError(DomainError):
    def __init__(self, reason_code: str, detail: str) -> None:
        if re.fullmatch(r"[A-Z0-9_]+", reason_code) is None:
            raise DomainError("Kustomize reason code must be closed uppercase text")
        self.reason_code = reason_code
        self.safe_detail = redact_detail(detail)
        super().__init__(f"{reason_code}: {self.safe_detail}")


@dataclass(frozen=True, slots=True)
class KustomizeBuildSpec:
    repository_root: Path
    build_root: Path
    executable: Path

    def __post_init__(self) -> None:
        if not all(isinstance(item, Path) for item in (
            self.repository_root, self.build_root, self.executable
        )):
            raise DomainError("Kustomize roots and executable must be pathlib.Path")
        try:
            repository = self.repository_root.resolve(strict=True)
            build = self.build_root.resolve(strict=True)
            executable = self.executable.resolve(strict=True)
        except OSError as exc:
            raise DomainError("Kustomize root or executable is unavailable") from exc
        if not repository.is_dir() or not build.is_dir():
            raise DomainError("Kustomize repository and build roots must be directories")
        try:
            build.relative_to(repository)
        except ValueError as exc:
            raise DomainError("Kustomize build root must be inside repository root") from exc
        metadata = executable.stat()
        if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
            raise DomainError("Kustomize executable must be an executable regular file")
        try:
            executable.relative_to(repository)
        except ValueError:
            pass
        else:
            raise DomainError("Kustomize executable must not be inside protected sources")
        object.__setattr__(self, "repository_root", repository)
        object.__setattr__(self, "build_root", build)
        object.__setattr__(self, "executable", executable)


@dataclass(frozen=True, slots=True)
class KustomizeSourceRecord:
    path: str
    roles: tuple[str, ...]
    referrers: tuple[str, ...]
    size: int
    sha256: str
    device: int
    inode: int

    def canonical_dict(self) -> dict:
        return {
            "path": self.path, "roles": list(self.roles),
            "referrers": list(self.referrers), "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class KustomizeRenderedDocument:
    index: int
    sha256: str
    api_version: str
    kind: str
    namespace: str
    name: str
    resource_identity: str
    provenance_root_sha256: str
    generated_secret: bool

    def canonical_dict(self) -> dict:
        return {
            "index": self.index, "sha256": self.sha256,
            "api_version": self.api_version, "kind": self.kind,
            "namespace": self.namespace, "name": self.name,
            "resource_identity": self.resource_identity,
            "provenance_root_sha256": self.provenance_root_sha256,
            "generated_secret": self.generated_secret,
        }


@dataclass(frozen=True, slots=True)
class KustomizeMaterializationEvidence:
    engine: MappingProxyType
    build: MappingProxyType
    inputs: tuple[KustomizeSourceRecord, ...]
    output: MappingProxyType
    documents: tuple[KustomizeRenderedDocument, ...]
    materialization_identity: str

    def canonical_dict(self) -> dict:
        return {
            "contract": KUSTOMIZE_MATERIALIZATION_CONTRACT,
            "status": "PASS",
            "reason_code": "DETERMINISTIC_LOCAL_KUSTOMIZE_BUILD_BOUND",
            "engine": dict(self.engine), "build": dict(self.build),
            "inputs": [item.canonical_dict() for item in self.inputs],
            "output": dict(self.output),
            "documents": [item.canonical_dict() for item in self.documents],
            "materialization_identity": self.materialization_identity,
        }


@dataclass(frozen=True, slots=True)
class KustomizeMaterializedUniverse:
    scanner_root: Path
    evidence: KustomizeMaterializationEvidence


def _engine_lock() -> dict:
    value = json.loads(files("iac_guard_v").joinpath(
        "kustomize-engine-v5.7.1.json"
    ).read_text(encoding="utf-8"))
    if type(value) is not dict or value.get("contract") != (
        "iac-guard-v-kustomize-engine-lock-v1"
    ):
        raise KustomizeMaterializationError(
            "KUSTOMIZE_ENGINE_RELEASE_LOCK_BLOCKED", "engine lock is invalid"
        )
    expected_registry = value.get("implementation_registry_sha256")
    body = dict(value)
    body.pop("implementation_registry_sha256", None)
    if expected_registry != _canonical_sha(body):
        raise KustomizeMaterializationError(
            "KUSTOMIZE_ENGINE_RELEASE_LOCK_BLOCKED",
            "engine registry digest is inconsistent",
        )
    release = value.get("release")
    platforms = value.get("platforms")
    if (
        type(release) is not dict
        or set(release) != {
            "repository", "tag", "release_id", "version", "published_at",
            "checksums_sha256",
        }
        or type(platforms) is not dict
        or not platforms
        or any(
            type(record) is not dict
            or set(record) != {"archive", "archive_sha256", "executable_sha256"}
            or any(
                type(record[key]) is not str
                or (key.endswith("sha256") and _SHA256.fullmatch(record[key]) is None)
                for key in record
            )
            for record in platforms.values()
        )
    ):
        raise KustomizeMaterializationError(
            "KUSTOMIZE_ENGINE_RELEASE_LOCK_BLOCKED", "engine registry shape is invalid"
        )
    return value


def _platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)
    return f"{system}/{machine}"


def _bind_engine(spec: KustomizeBuildSpec) -> dict:
    lock = _engine_lock()
    record = lock["platforms"].get(_platform_key())
    if type(record) is not dict:
        raise KustomizeMaterializationError(
            "KUSTOMIZE_ENGINE_UNAVAILABLE", "platform has no reviewed engine artifact"
        )
    executable_sha = _sha(spec.executable.read_bytes())
    if executable_sha != record["executable_sha256"]:
        raise KustomizeMaterializationError(
            "KUSTOMIZE_ENGINE_DIGEST_MISMATCH", "executable digest is not allowlisted"
        )
    probe = run_command(CommandRequest(
        (str(spec.executable), "version"), workspace_root=spec.repository_root,
        timeout_seconds=30, max_output_bytes=64 * 1024,
        max_stdout_bytes=32 * 1024, max_stderr_bytes=32 * 1024,
    ))
    if probe.status is not Status.PASS or probe.exit_code != 0:
        raise KustomizeMaterializationError(
            "KUSTOMIZE_ENGINE_VERSION_MISMATCH", "version probe failed"
        )
    version = probe.stdout.decode("utf-8", errors="strict").strip()
    if version != f"v{lock['release']['version']}":
        raise KustomizeMaterializationError(
            "KUSTOMIZE_ENGINE_VERSION_MISMATCH", "engine version is not locked"
        )
    return {
        "name": "kustomize", "version": lock["release"]["version"],
        "release_tag": lock["release"]["tag"],
        "release_id": lock["release"]["release_id"],
        "platform": _platform_key(), "executable_sha256": executable_sha,
        "archive_sha256": record["archive_sha256"],
        "checksums_sha256": lock["release"]["checksums_sha256"],
        "implementation_registry_sha256": lock["implementation_registry_sha256"],
    }


class _Inventory:
    def __init__(self, repository: Path) -> None:
        self.repository = repository
        self._roles: dict[str, set[str]] = {}
        self._referrers: dict[str, set[str]] = {}
        self._control_stack: set[str] = set()
        self._portable_paths: dict[str, str] = {}

    def _contained(self, declaring: Path, raw: str, role: str) -> Path:
        if type(raw) is not str or not raw or "\x00" in raw or _REMOTE.search(raw):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_REFERENCE_REMOTE", f"{role} is not a local path"
            )
        pure = PurePosixPath(raw)
        if pure.is_absolute() or "\\" in raw:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_PATH_ESCAPE", f"{role} is not a portable relative path"
            )
        target = declaring / Path(*pure.parts)
        lexical = Path(os.path.normpath(str(target.absolute())))
        current = self.repository
        try:
            relative_parts = lexical.relative_to(self.repository).parts
        except ValueError as exc:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_PATH_ESCAPE", f"{role} escapes protected repository"
            ) from exc
        for part in relative_parts:
            current = current / part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_INPUT_MISSING", f"{role} input is unavailable"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_SYMLINK", f"{role} traverses a symlink"
                )
        resolved = lexical.resolve(strict=True)
        try:
            resolved.relative_to(self.repository)
        except ValueError as exc:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_PATH_ESCAPE", f"{role} escapes protected repository"
            ) from exc
        return resolved

    def add_file(self, path: Path, role: str, referrer: str) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_INPUT_MISSING", "declared input is unavailable"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_SYMLINK", "declared input is a symlink"
            )
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_REFERENCE_UNSUPPORTED",
                "declared input must be a single-linked regular file",
            )
        if metadata.st_size > _MAX_FILE_BYTES:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_INPUT_LIMIT_EXCEEDED", "input exceeds file size limit"
            )
        relative = canonical_repo_path(path.relative_to(self.repository).as_posix())
        portable = unicodedata.normalize("NFC", relative).casefold()
        prior_path = self._portable_paths.get(portable)
        if prior_path is not None and prior_path != relative:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_REFERENCE_UNSUPPORTED",
                "protected inputs have a case/Unicode path identity collision",
            )
        self._portable_paths[portable] = relative
        self._roles.setdefault(relative, set()).add(role)
        self._referrers.setdefault(relative, set()).add(referrer)
        if len(self._roles) > _MAX_INPUTS:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_INPUT_LIMIT_EXCEEDED", "input count limit exceeded"
            )

    def control_path(self, directory: Path) -> Path:
        found = tuple(directory / name for name in _CONTROL_NAMES if (directory / name).exists())
        if not found:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_CONTROL_MISSING", "build directory has no control document"
            )
        if len(found) != 1:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_CONTROL_AMBIGUOUS", "multiple control documents are present"
            )
        return found[0]

    def discover(self, build_root: Path) -> tuple[KustomizeSourceRecord, ...]:
        self._walk_control(self.control_path(build_root), 0, "ROOT")
        records = []
        total = 0
        for relative in sorted(self._roles):
            path = self.repository / relative
            metadata = path.stat()
            payload = path.read_bytes()
            if (
                len(payload) != metadata.st_size
                or path.stat().st_ino != metadata.st_ino
            ):
                raise KustomizeMaterializationError(
                    "KUSTOMIZE_INPUT_MUTATED", "input changed while inventorying"
                )
            total += len(payload)
            if total > _MAX_INPUT_BYTES:
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_INPUT_LIMIT_EXCEEDED", "input byte limit exceeded"
                )
            records.append(KustomizeSourceRecord(
                relative, tuple(sorted(self._roles[relative])),
                tuple(sorted(self._referrers[relative])), len(payload), _sha(payload),
                metadata.st_dev, metadata.st_ino,
            ))
        return tuple(records)

    def _load_control(self, path: Path, *, component_required: bool) -> dict:
        try:
            value = yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictLoader)
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_CONTROL_INVALID", "control document is invalid YAML"
            ) from exc
        if type(value) is not dict:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_CONTROL_INVALID", "control document must be a mapping"
            )
        unknown = set(value) - _ALLOWED_KEYS
        if unknown:
            reason = (
                "KUSTOMIZATION_CUSTOM_FIELD_SPEC_UNSUPPORTED"
                if unknown & {"configurations", "vars"} else "KUSTOMIZATION_UNKNOWN_KEY"
            )
            raise KustomizeMaterializationError(reason, "control document has unsupported keys")
        api_version, kind = value.get("apiVersion"), value.get("kind")
        if (api_version is None) != (kind is None):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_CONTROL_INVALID", "control type metadata is partial"
            )
        actual_type = (api_version, kind)
        allowed_type = (
            ("kustomize.config.k8s.io/v1alpha1", "Component")
            if component_required else
            ("kustomize.config.k8s.io/v1beta1", "Kustomization")
        )
        if component_required and actual_type != allowed_type:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_CONTROL_INVALID",
                "referenced component lacks the reviewed Component type",
            )
        if not component_required and api_version is not None and actual_type != allowed_type:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_CONTROL_INVALID", "control type is unsupported"
            )
        return value

    def _paths(self, value: object, field: str) -> tuple[str, ...]:
        if value is None:
            return ()
        if type(value) is not list or any(type(item) is not str for item in value):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_FIELD_SHAPE_INVALID", f"{field} must be local path strings"
            )
        return tuple(value)

    def _walk_control(self, path: Path, depth: int, role: str) -> None:
        if depth > _MAX_DEPTH:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_INPUT_LIMIT_EXCEEDED", "control depth limit exceeded"
            )
        relative = canonical_repo_path(path.relative_to(self.repository).as_posix())
        if relative in self._control_stack:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_INPUT_CYCLE", "local composition contains a cycle"
            )
        self._control_stack.add(relative)
        self.add_file(path, "control_document", role)
        component_required = role.endswith(":components")
        value = self._load_control(path, component_required=component_required)
        declaring = path.parent
        for field in ("resources", "bases", "components"):
            for raw in self._paths(value.get(field), field):
                target = self._contained(declaring, raw, field)
                if target.is_dir():
                    self._walk_control(self.control_path(target), depth + 1, f"{relative}:{field}")
                elif target.name in _CONTROL_NAMES:
                    self._walk_control(target, depth + 1, f"{relative}:{field}")
                else:
                    self.add_file(target, "resource_manifest", f"{relative}:{field}")
        for field in ("patchesStrategicMerge",):
            entries = value.get(field, [])
            if entries is None:
                entries = []
            if type(entries) is not list:
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_FIELD_SHAPE_INVALID", f"{field} must be a list"
                )
            for item in entries:
                if type(item) is str:
                    self.add_file(
                        self._contained(declaring, item, field), "patch_input",
                        f"{relative}:{field}",
                    )
                elif type(item) is not dict or not self._inline_resource(item):
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_FIELD_SHAPE_INVALID", f"{field} entry is invalid"
                    )
        self._discover_patches(value, declaring, relative)
        self._discover_replacements(value, declaring, relative)
        self._discover_generators(value, declaring, relative)
        self._validate_shapes(value)
        self._control_stack.remove(relative)

    def _discover_patches(self, value: dict, declaring: Path, relative: str) -> None:
        for field in ("patches", "patchesJson6902"):
            entries = value.get(field, []) or []
            if type(entries) is not list:
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_FIELD_SHAPE_INVALID", f"{field} must be a list"
                )
            for item in entries:
                if type(item) is not dict:
                    if field == "patches" and type(item) is str:
                        self.add_file(self._contained(declaring, item, field), "patch_input", f"{relative}:{field}")
                        continue
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_FIELD_SHAPE_INVALID", f"{field} entry must be a mapping"
                    )
                allowed = {"path", "patch", "target", "options"} if field == "patches" else {"path", "patch", "target"}
                if set(item) - allowed or ("path" in item) == ("patch" in item):
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_PATCH_INPUT_UNBOUND", "patch input is ambiguous"
                    )
                if "path" in item:
                    self.add_file(self._contained(declaring, item["path"], field), "patch_input", f"{relative}:{field}")
                elif type(item["patch"]) not in {str, list}:
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_FIELD_SHAPE_INVALID", "inline patch has invalid shape"
                    )
                self._validate_target(item.get("target"))
                options = item.get("options")
                if options is not None and (
                    type(options) is not dict
                    or set(options) - {"allowNameChange", "allowKindChange"}
                    or any(type(flag) is not bool for flag in options.values())
                ):
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_FIELD_SHAPE_INVALID",
                        "patch options are outside the closed grammar",
                    )
                if field == "patchesJson6902" and "patch" in item:
                    self._validate_json_patch(item["patch"])

    @staticmethod
    def _inline_resource(value: dict) -> bool:
        metadata = value.get("metadata")
        return (
            type(value.get("apiVersion")) is str
            and type(value.get("kind")) is str
            and type(metadata) is dict
            and type(metadata.get("name")) is str
        )

    @staticmethod
    def _validate_json_patch(value: object) -> None:
        if type(value) is not list or not value:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_FIELD_SHAPE_INVALID", "JSON patch must be a nonempty list"
            )
        allowed_ops = {"add", "remove", "replace", "move", "copy", "test"}
        for operation in value:
            if (
                type(operation) is not dict
                or set(operation) - {"op", "path", "from", "value"}
                or operation.get("op") not in allowed_ops
                or type(operation.get("path")) is not str
                or ("from" in operation and type(operation["from"]) is not str)
            ):
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_FIELD_SHAPE_INVALID",
                    "JSON patch operation is outside the closed grammar",
                )

    def _validate_target(self, target: object) -> None:
        if target is None:
            return
        allowed = {"group", "version", "kind", "name", "namespace", "labelSelector", "annotationSelector"}
        if type(target) is not dict or set(target) - allowed or any(
            type(item) is not str for item in target.values()
        ):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_FIELD_SHAPE_INVALID", "patch target is outside closed grammar"
            )

    def _discover_replacements(self, value: dict, declaring: Path, relative: str) -> None:
        entries = value.get("replacements", []) or []
        if type(entries) is not list:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_FIELD_SHAPE_INVALID", "replacements must be a list"
            )
        for item in entries:
            if type(item) is not dict:
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_FIELD_SHAPE_INVALID", "replacement must be a mapping"
                )
            if set(item) == {"path"}:
                self.add_file(self._contained(declaring, item["path"], "replacements"), "replacement_input", f"{relative}:replacements")
                continue
            if set(item) - {"source", "targets"} or "source" not in item or "targets" not in item:
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_REPLACEMENT_INPUT_UNBOUND", "replacement shape is unsupported"
                )
            self._validate_replacement(item)

    def _validate_replacement(self, item: dict) -> None:
        source = item["source"]
        targets = item["targets"]
        selector = {"group", "version", "kind", "name", "namespace"}
        if (
            type(source) is not dict
            or set(source) - (selector | {"fieldPath", "options"})
            or any(
                type(value) is not str
                for key, value in source.items() if key != "options"
            )
        ):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_REPLACEMENT_INPUT_UNBOUND",
                "replacement source is outside the closed grammar",
            )
        self._validate_field_options(source.get("options"), allow_create=False)
        if type(targets) is not list or not targets:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_REPLACEMENT_INPUT_UNBOUND",
                "replacement targets must be a nonempty list",
            )
        for target in targets:
            if type(target) is not dict or set(target) - {"select", "reject", "fieldPaths", "options"}:
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_REPLACEMENT_INPUT_UNBOUND",
                    "replacement target is outside the closed grammar",
                )
            for selector_name in ("select", "reject"):
                selected = target.get(selector_name)
                if selected is not None:
                    self._validate_target(selected)
            fields = target.get("fieldPaths")
            if type(fields) is not list or not fields or any(
                type(field) is not str or not field for field in fields
            ):
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_REPLACEMENT_INPUT_UNBOUND",
                    "replacement field paths are invalid",
                )
            self._validate_field_options(target.get("options"), allow_create=True)

    @staticmethod
    def _validate_field_options(value: object, *, allow_create: bool) -> None:
        if value is None:
            return
        allowed = {"delimiter", "index"} | ({"create"} if allow_create else set())
        if (
            type(value) is not dict
            or set(value) - allowed
            or ("delimiter" in value and type(value["delimiter"]) is not str)
            or ("index" in value and type(value["index"]) is not int)
            or ("create" in value and type(value["create"]) is not bool)
        ):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_REPLACEMENT_INPUT_UNBOUND",
                "replacement field options are invalid",
            )

    def _discover_generators(self, value: dict, declaring: Path, relative: str) -> None:
        for field in ("configMapGenerator", "secretGenerator"):
            entries = value.get(field, []) or []
            if type(entries) is not list:
                raise KustomizeMaterializationError(
                    "KUSTOMIZATION_FIELD_SHAPE_INVALID", f"{field} must be a list"
                )
            allowed = {"name", "namespace", "behavior", "literals", "files", "envs", "env", "options"}
            if field == "secretGenerator":
                allowed.add("type")
            for item in entries:
                if type(item) is not dict or set(item) - allowed or type(item.get("name")) is not str:
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_FIELD_SHAPE_INVALID", f"{field} entry is invalid"
                    )
                if (
                    not item["name"]
                    or ("namespace" in item and type(item["namespace"]) is not str)
                    or item.get("behavior", "create") not in {"create", "merge", "replace"}
                    or ("type" in item and type(item["type"]) is not str)
                ):
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_FIELD_SHAPE_INVALID",
                        f"{field} identity or behavior is invalid",
                    )
                literals = item.get("literals", []) or []
                files = item.get("files", []) or []
                if (
                    type(literals) is not list
                    or any(type(raw) is not str for raw in literals)
                    or type(files) is not list
                ):
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_FIELD_SHAPE_INVALID",
                        f"{field} source list is invalid",
                    )
                keys: set[str] = set()
                for literal in literals:
                    if "=" not in literal or not literal.split("=", 1)[0]:
                        raise KustomizeMaterializationError(
                            "KUSTOMIZATION_GENERATOR_INPUT_UNBOUND",
                            f"{field} literal lacks an exact output key",
                        )
                    self._claim_generator_key(keys, literal.split("=", 1)[0], field)
                for raw in item.get("files", []) or []:
                    if type(raw) is not str:
                        raise KustomizeMaterializationError("KUSTOMIZATION_FIELD_SHAPE_INVALID", "generator file is invalid")
                    if "=" in raw:
                        key, source = raw.split("=", 1)
                    else:
                        source = raw
                        key = PurePosixPath(raw).name
                    if not source:
                        raise KustomizeMaterializationError(
                            "KUSTOMIZATION_GENERATOR_INPUT_UNBOUND",
                            f"{field} file input is incomplete",
                        )
                    self._claim_generator_key(keys, key, field)
                    self.add_file(self._contained(declaring, source, field), "generator_input", f"{relative}:{field}")
                envs = item.get("envs", []) or []
                if "env" in item:
                    if "envs" in item:
                        raise KustomizeMaterializationError(
                            "KUSTOMIZATION_GENERATOR_INPUT_UNBOUND",
                            "deprecated env and current envs cannot be combined",
                        )
                    if type(item["env"]) is not str:
                        raise KustomizeMaterializationError(
                            "KUSTOMIZATION_FIELD_SHAPE_INVALID",
                            "generator env input is invalid",
                        )
                    envs = [*envs, item["env"]]
                if type(envs) is not list or any(type(raw) is not str for raw in envs):
                    raise KustomizeMaterializationError("KUSTOMIZATION_FIELD_SHAPE_INVALID", "generator env input is invalid")
                for raw in envs:
                    env_path = self._contained(declaring, raw, field)
                    self.add_file(env_path, "generator_input", f"{relative}:{field}")
                    try:
                        lines = env_path.read_text(encoding="utf-8").splitlines()
                    except (OSError, UnicodeError) as exc:
                        raise KustomizeMaterializationError(
                            "KUSTOMIZATION_GENERATOR_INPUT_UNBOUND",
                            f"{field} env input is not deterministic UTF-8",
                        ) from exc
                    for line in lines:
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#"):
                            continue
                        if "=" not in stripped or not stripped.split("=", 1)[0]:
                            raise KustomizeMaterializationError(
                                "KUSTOMIZATION_GENERATOR_INPUT_UNBOUND",
                                f"{field} env entry could require process environment",
                            )
                        self._claim_generator_key(
                            keys, stripped.split("=", 1)[0], field
                        )
                self._validate_generator_options(item.get("options"))

    @staticmethod
    def _claim_generator_key(keys: set[str], key: str, field: str) -> None:
        if not key or key != key.strip() or any(char in key for char in "\r\n\x00"):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_GENERATOR_INPUT_UNBOUND",
                f"{field} output key is invalid",
            )
        if key in keys:
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_GENERATOR_INPUT_UNBOUND",
                f"{field} contains a duplicate output key",
            )
        keys.add(key)

    @staticmethod
    def _string_map(value: object) -> bool:
        return type(value) is dict and all(
            type(key) is str and type(item) is str for key, item in value.items()
        )

    def _validate_generator_options(self, options: object) -> None:
        if options is None:
            return
        if (
            type(options) is not dict
            or set(options) - {
                "disableNameSuffixHash", "labels", "annotations", "immutable"
            }
            or any(
                type(options[key]) is not bool
                for key in {"disableNameSuffixHash", "immutable"} & set(options)
            )
            or any(
                not self._string_map(options[key])
                for key in {"labels", "annotations"} & set(options)
            )
        ):
            raise KustomizeMaterializationError(
                "KUSTOMIZATION_FIELD_SHAPE_INVALID",
                "generator options are outside the closed grammar",
            )

    def _validate_shapes(self, value: dict) -> None:
        for field in ("namespace", "namePrefix", "nameSuffix"):
            if field in value and type(value[field]) is not str:
                raise KustomizeMaterializationError("KUSTOMIZATION_FIELD_SHAPE_INVALID", f"{field} must be a string")
        if "commonLabels" in value and (
            type(value["commonLabels"]) is not dict or any(
                type(key) is not str or type(item) is not str
                for key, item in value["commonLabels"].items()
            )
        ):
            raise KustomizeMaterializationError("KUSTOMIZATION_FIELD_SHAPE_INVALID", "commonLabels must be a string map")
        if "labels" in value:
            labels = value["labels"]
            if type(labels) is not list or any(
                type(item) is not dict or set(item) - {"pairs", "includeSelectors", "includeTemplates"}
                or "pairs" not in item
                or not self._string_map(item["pairs"])
                or any(
                    type(item[key]) is not bool
                    for key in {"includeSelectors", "includeTemplates"} & set(item)
                )
                for item in labels
            ):
                raise KustomizeMaterializationError("KUSTOMIZATION_FIELD_SHAPE_INVALID", "labels are outside closed grammar")
        if "images" in value:
            images = value["images"]
            if type(images) is not list:
                raise KustomizeMaterializationError("KUSTOMIZATION_FIELD_SHAPE_INVALID", "images must be a list")
            for image in images:
                if type(image) is str and image:
                    continue
                if (
                    type(image) is not dict
                    or set(image) - {"name", "newName", "newTag", "digest"}
                    or type(image.get("name")) is not str
                    or not image["name"]
                    or any(type(item) is not str for item in image.values())
                    or ("newTag" in image and "digest" in image)
                ):
                    raise KustomizeMaterializationError(
                        "KUSTOMIZATION_FIELD_SHAPE_INVALID",
                        "image transform is outside the closed grammar",
                    )
        options = value.get("generatorOptions")
        self._validate_generator_options(options)


def preflight_kustomize(spec: KustomizeBuildSpec) -> tuple[KustomizeSourceRecord, ...]:
    if type(spec) is not KustomizeBuildSpec:
        raise TypeError("preflight requires an exact KustomizeBuildSpec")
    return _Inventory(spec.repository_root).discover(spec.build_root)


def _revalidate(spec: KustomizeBuildSpec, records: tuple[KustomizeSourceRecord, ...]) -> None:
    for item in records:
        path = spec.repository_root / item.path
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != (item.device, item.inode)
            or metadata.st_size != item.size or _sha(path.read_bytes()) != item.sha256
        ):
            raise KustomizeMaterializationError(
                "KUSTOMIZE_INPUT_MUTATED", "protected input changed after preflight"
            )


def _sealed_view(repository: Path, records: tuple[KustomizeSourceRecord, ...], root: Path) -> Path:
    view = root / "repository"
    view.mkdir(mode=0o700, parents=True)
    for item in records:
        source = repository / item.path
        destination = view / item.path
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags, 0o400)
        try:
            payload = source.read_bytes()
            if _sha(payload) != item.sha256:
                raise KustomizeMaterializationError("KUSTOMIZE_INPUT_MUTATED", "input changed while sealing")
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise KustomizeMaterializationError(
                        "KUSTOMIZE_RUNTIME_INTEGRITY_FAILED",
                        "sealed input copy did not complete",
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    # The materializer receives a byte-for-byte sealed read-only view.  Directory
    # traversal remains possible, but neither the engine nor inherited state may add
    # or replace inputs after preflight.
    for directory in sorted(
        (item for item in view.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts), reverse=True,
    ):
        directory.chmod(0o500)
    view.chmod(0o500)
    return view


def _offline_argv(executable: Path, build: Path) -> tuple[str, ...]:
    base = (
        str(executable), "build", str(build),
        "--load-restrictor", "LoadRestrictionsNone",
    )
    system = platform.system().lower()
    if system == "darwin" and Path("/usr/bin/sandbox-exec").is_file():
        return (
            "/usr/bin/sandbox-exec", "-p",
            "(version 1) (allow default) (deny network*)", *base,
        )
    if system == "linux" and shutil.which("unshare"):
        return (str(Path(shutil.which("unshare")).resolve()), "-n", "--", *base)
    raise KustomizeMaterializationError(
        "KUSTOMIZE_OFFLINE_CONTRACT_FAILED", "no reviewed offline wrapper is available"
    )


def _run_build(spec: KustomizeBuildSpec, records: tuple[KustomizeSourceRecord, ...], root: Path) -> bytes:
    view = _sealed_view(spec.repository_root, records, root)
    relative_build = spec.build_root.relative_to(spec.repository_root)
    build = view / relative_build
    argv = _offline_argv(spec.executable, build)
    request = CommandRequest(
        argv, cwd=build, workspace_root=view, timeout_seconds=120,
        max_output_bytes=_MAX_OUTPUT_BYTES + 1024 * 1024,
        max_stdout_bytes=_MAX_OUTPUT_BYTES, max_stderr_bytes=1024 * 1024,
        trusted_helper_dirs=(Path(argv[0]).parent,),
    )
    result = run_command(request)
    if result.status is not Status.PASS or result.exit_code != 0:
        detail = result.stderr.decode("utf-8", errors="replace")
        reason = (
            "KUSTOMIZE_OFFLINE_CONTRACT_FAILED"
            if "Operation not permitted" in detail else "KUSTOMIZE_BUILD_FAILED"
        )
        raise KustomizeMaterializationError(reason, "locked offline Kustomize build failed")
    if result.stderr:
        # Deprecation warnings are evidence-compatible; other diagnostics are not.
        diagnostic = result.stderr.decode("utf-8", errors="strict")
        if any(
            line and "deprecated" not in line.lower()
            for line in diagnostic.splitlines()
        ):
            raise KustomizeMaterializationError(
                "KUSTOMIZE_BUILD_FAILED", "engine emitted an unexpected diagnostic"
            )
    return result.stdout


_CLUSTER_GROUP_KINDS = frozenset({
    ("", "Namespace"), ("", "Node"), ("", "PersistentVolume"),
    ("admissionregistration.k8s.io", "MutatingWebhookConfiguration"),
    ("admissionregistration.k8s.io", "ValidatingAdmissionPolicy"),
    ("admissionregistration.k8s.io", "ValidatingAdmissionPolicyBinding"),
    ("admissionregistration.k8s.io", "ValidatingWebhookConfiguration"),
    ("apiregistration.k8s.io", "APIService"),
    ("apiextensions.k8s.io", "CustomResourceDefinition"),
    ("certificates.k8s.io", "CertificateSigningRequest"),
    ("flowcontrol.apiserver.k8s.io", "FlowSchema"),
    ("flowcontrol.apiserver.k8s.io", "PriorityLevelConfiguration"),
    ("networking.k8s.io", "IngressClass"),
    ("node.k8s.io", "RuntimeClass"),
    ("policy", "PodSecurityPolicy"),
    ("rbac.authorization.k8s.io", "ClusterRole"),
    ("rbac.authorization.k8s.io", "ClusterRoleBinding"),
    ("scheduling.k8s.io", "PriorityClass"),
    ("storage.k8s.io", "CSIDriver"),
    ("storage.k8s.io", "CSINode"),
    ("storage.k8s.io", "StorageClass"),
    ("storage.k8s.io", "VolumeAttachment"),
})


def _documents(payload: bytes, provenance_root: str) -> tuple[KustomizeRenderedDocument, ...]:
    try:
        text = payload.decode("utf-8", errors="strict")
        raw_documents = tuple(item for item in re.split(r"(?m)^---\s*$", text) if item.strip())
    except UnicodeError as exc:
        raise KustomizeMaterializationError("KUSTOMIZE_OUTPUT_INVALID", "output is not UTF-8") from exc
    if len(raw_documents) > _MAX_OUTPUT_DOCUMENTS:
        raise KustomizeMaterializationError("KUSTOMIZATION_INPUT_LIMIT_EXCEEDED", "output document limit exceeded")
    scopes: dict[tuple[str, str], str] = {}
    parsed: list[tuple[bytes, dict]] = []
    for raw in raw_documents:
        try:
            value = yaml.load(raw, Loader=_StrictLoader)
        except yaml.YAMLError as exc:
            raise KustomizeMaterializationError("KUSTOMIZE_OUTPUT_INVALID", "output YAML is invalid") from exc
        if type(value) is not dict:
            raise KustomizeMaterializationError("KUSTOMIZE_OUTPUT_INVALID", "output document is not a mapping")
        encoded = raw.encode("utf-8")
        parsed.append((encoded, value))
        if value.get("kind") == "CustomResourceDefinition":
            spec = value.get("spec", {})
            names = spec.get("names", {}) if type(spec) is dict else {}
            group, kind, scope = spec.get("group"), names.get("kind"), spec.get("scope")
            if type(group) is str and type(kind) is str and scope in {"Cluster", "Namespaced"}:
                scopes[(group, kind)] = scope
    result = []
    identities = set()
    for index, (raw, value) in enumerate(parsed, 1):
        api_version, kind, metadata = value.get("apiVersion"), value.get("kind"), value.get("metadata")
        if type(api_version) is not str or type(kind) is not str or type(metadata) is not dict:
            raise KustomizeMaterializationError("KUSTOMIZE_OUTPUT_INVALID", "resource identity is incomplete")
        name = metadata.get("name")
        if type(name) is not str or not name:
            raise KustomizeMaterializationError("KUSTOMIZE_OUTPUT_INVALID", "resource name is missing")
        group = api_version.split("/", 1)[0] if "/" in api_version else ""
        if (group, kind) in _CLUSTER_GROUP_KINDS:
            # The protected Kubernetes parser and Checkov both use the literal
            # ``default`` segment when addressing cluster-scoped documents whose
            # metadata has no namespace.  Preserve that scanner-facing convention
            # here so target/graph containment compares identical protected IDs;
            # cluster scope remains established independently by kind semantics.
            namespace = metadata.get("namespace") or "default"
        elif group in {"", "apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io", "policy", "autoscaling", "storage.k8s.io"}:
            namespace = metadata.get("namespace") or "default"
        else:
            scope = scopes.get((group, kind))
            if scope is None:
                raise KustomizeMaterializationError("KUSTOMIZE_RESOURCE_SCOPE_UNRESOLVED", "custom resource scope is unproven")
            namespace = metadata.get("namespace") or "default"
        identity = f"{api_version}/{kind}/{namespace}/{name}"
        if identity in identities:
            raise KustomizeMaterializationError("KUSTOMIZE_DUPLICATE_RENDERED_IDENTITY", "rendered identity is duplicated")
        identities.add(identity)
        result.append(KustomizeRenderedDocument(
            index, _sha(raw), api_version, kind, namespace, name, identity,
            provenance_root, kind == "Secret",
        ))
    if not result:
        raise KustomizeMaterializationError("KUSTOMIZE_OUTPUT_INVALID", "build rendered no resources")
    return tuple(result)


def materialize_kustomize(spec: KustomizeBuildSpec, output_root: Path) -> KustomizeMaterializationEvidence:
    if type(spec) is not KustomizeBuildSpec or not isinstance(output_root, Path):
        raise TypeError("materialization requires exact Kustomize inputs")
    if output_root.exists():
        raise DomainError("Kustomize output root must not already exist")
    records = preflight_kustomize(spec)
    engine = _bind_engine(spec)
    input_root = _canonical_sha([item.canonical_dict() for item in records])
    _revalidate(spec, records)
    with tempfile.TemporaryDirectory(prefix="iacgv-kustomize-builds-") as temporary:
        root = Path(temporary)
        first = _run_build(spec, records, root / "first")
        if _sha(spec.executable.read_bytes()) != engine["executable_sha256"]:
            raise KustomizeMaterializationError(
                "KUSTOMIZE_RUNTIME_INTEGRITY_FAILED", "engine changed during first build"
            )
        _revalidate(spec, records)
        second = _run_build(spec, records, root / "second")
        if _sha(spec.executable.read_bytes()) != engine["executable_sha256"]:
            raise KustomizeMaterializationError(
                "KUSTOMIZE_RUNTIME_INTEGRITY_FAILED", "engine changed during second build"
            )
    _revalidate(spec, records)
    if first != second:
        raise KustomizeMaterializationError("KUSTOMIZE_NONDETERMINISTIC_BUILD", "fresh builds produced unequal raw bytes")
    documents = _documents(first, input_root)
    output_root.mkdir(mode=0o700, parents=True)
    rendered = output_root / "rendered.yaml"
    rendered.write_bytes(first)
    rendered.chmod(0o600)
    output = {
        "rendered_bundle_path": "rendered.yaml",
        "rendered_bundle_sha256": _sha(first),
        "rendered_bundle_bytes": len(first),
        "resource_count": len(documents), "fresh_build_count": 2,
        "document_inventory_sha256": _canonical_sha([
            item.canonical_dict() for item in documents
        ]),
    }
    build = {
        "repository_root_identity": _canonical_sha({
            "input_manifest_root": input_root,
            "build_root": spec.build_root.relative_to(spec.repository_root).as_posix(),
        }),
        "build_root": spec.build_root.relative_to(spec.repository_root).as_posix() or ".",
        "transitive_input_manifest_sha256": input_root,
        "control_graph_sha256": _canonical_sha([
            item.canonical_dict() for item in records if "control_document" in item.roles
        ]),
        "transform_declaration_sha256": _canonical_sha([
            item.canonical_dict() for item in records if "control_document" in item.roles
        ]),
        "canonical_invocation_sha256": _canonical_sha({
            "argv": ["kustomize", "build", "<sealed-build-root>",
                     "--load-restrictor", "LoadRestrictionsNone"],
            "network": "denied", "plugins": False, "helm": False,
            "fresh_state": True,
        }),
        "build_1_raw_output_sha256": _sha(first),
        "build_2_raw_output_sha256": _sha(second),
        "source_to_output_lineage_sha256": _canonical_sha({
            "input": input_root, "output": _sha(first),
        }),
        "offline": True, "plugins": False, "exec": False, "helm": False,
    }
    body = {
        "engine": engine, "build": build,
        "inputs": [item.canonical_dict() for item in records],
        "output": output,
        "documents": [item.canonical_dict() for item in documents],
    }
    return KustomizeMaterializationEvidence(
        MappingProxyType(engine), MappingProxyType(build), records,
        MappingProxyType(output), documents, _canonical_sha(body),
    )


@contextmanager
def materialize_kustomize_universe(
    spec: KustomizeBuildSpec,
) -> Iterator[KustomizeMaterializedUniverse]:
    with tempfile.TemporaryDirectory(prefix="iacgv-kustomize-universe-") as temporary:
        root = Path(temporary) / "scanner"
        evidence = materialize_kustomize(spec, root)
        yield KustomizeMaterializedUniverse(root, evidence)


__all__ = [
    "KUSTOMIZE_MATERIALIZATION_CONTRACT", "KustomizeBuildSpec",
    "KustomizeMaterializationError", "KustomizeMaterializationEvidence",
    "KustomizeMaterializedUniverse", "KustomizeRenderedDocument",
    "KustomizeSourceRecord", "materialize_kustomize",
    "materialize_kustomize_universe", "preflight_kustomize",
]
