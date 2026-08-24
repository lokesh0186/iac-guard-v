"""Bounded, deterministic, client-side Helm materialization.

The materializer accepts only a local chart and a closed typed render contract.
It never contacts Kubernetes, resolves a remote dependency, executes a plugin or
post-renderer, or evaluates an arbitrary command tail.  Two fresh renders must
produce byte-identical, source-bound Kubernetes documents before their output is
eligible for the existing Checkov verification path.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Iterator

import yaml

from .enums import Status
from .models import DomainError, canonical_repo_path
from .process import CommandRequest, run_command
from .redaction import redact_detail


HELM_MATERIALIZATION_CONTRACT = "helm-materialization-v1"
_MAX_CHART_FILES = 10_000
_MAX_CHART_FILE_BYTES = 10 * 1024 * 1024
_MAX_CHART_BYTES = 64 * 1024 * 1024
_MAX_RENDER_BYTES = 32 * 1024 * 1024
_MAX_RENDER_DOCUMENTS = 5_000
_MAX_ARCHIVE_MEMBERS = 10_000
_MAX_ARCHIVE_EXPANDED_BYTES = 64 * 1024 * 1024
_HELM_VERSION = re.compile(r"v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)")
_ACTION = re.compile(r"{{-?(.*?)-?}}", re.DOTALL)
_TEMPLATE_COMMENT = re.compile(r"^\s*/\*.*\*/\s*$", re.DOTALL)
_RANDOM_FUNCTION = re.compile(
    r"(?<![A-Za-z0-9_])("
    r"randAlphaNum|randAlpha|randNumeric|randAscii|uuidv4|now|dateInZone|ago|"
    r"genCA|genSelfSignedCert|genSignedCert|genPrivateKey|encryptAES|htpasswd"
    r")(?![A-Za-z0-9_])"
)
_LOOKUP_FUNCTION = re.compile(r"(?<![A-Za-z0-9_])lookup(?![A-Za-z0-9_])")
_NAMED_TEMPLATE_CALL = re.compile(
    r'(?:^|[\s(|])(?:include|template)\s+"([^"\r\n]+)"'
)
_NAMED_TEMPLATE_ANY = re.compile(r"(?:^|[\s(|])(?:include|template)(?=\s)")
_DEFINE_ACTION = re.compile(r'^\s*define\s+"([^"\r\n]+)"')
_CONTROL_START = re.compile(r"^\s*(?:if|range|with|block)(?:\s|$)")
_CONTROL_END = re.compile(r"^\s*end(?:\s|$)")
_SOURCE_MARKER = re.compile(r"^# Source: ([^\r\n]+)$", re.MULTILINE)
_DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")
_DNS_SUBDOMAIN = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?")
_SET_KEY = re.compile(r"[A-Za-z0-9_.\[\]-]+")


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that refuses duplicate mapping keys."""


def _construct_strict_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict:
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=False)
    return result


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_strict_mapping,
)


class HelmMaterializationError(DomainError):
    """Typed, public-safe materialization refusal."""

    def __init__(self, reason_code: str, detail: str) -> None:
        if type(reason_code) is not str or not re.fullmatch(r"[A-Z0-9_]+", reason_code):
            raise DomainError("Helm failure reason must be a closed uppercase identifier")
        if type(detail) is not str or not detail.strip():
            raise DomainError("Helm failure detail must be nonblank")
        self.reason_code = reason_code
        self.safe_detail = redact_detail(detail)
        super().__init__(f"{reason_code}: {self.safe_detail}")


@dataclass(frozen=True, slots=True)
class _TemplateActionScope:
    functions: frozenset[str]
    calls: frozenset[str]
    dynamic_call: bool


@dataclass(frozen=True, slots=True)
class _TemplateActionIndex:
    roots: dict[str, _TemplateActionScope]
    definitions: dict[str, _TemplateActionScope]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha(value: object) -> str:
    return _sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8"))


def _safe_dns(value: object, label: str, *, namespace: bool = False) -> str:
    pattern = _DNS_LABEL if namespace else _DNS_SUBDOMAIN
    limit = 63 if namespace else 253
    if type(value) is not str or len(value) > limit or pattern.fullmatch(value) is None:
        raise DomainError(f"{label} must be a canonical Kubernetes DNS name")
    return value


def _safe_version(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is None:
        raise DomainError(f"{label} must use numeric major.minor.patch form")
    return value


def _typed_overrides(raw: object, label: str) -> tuple[tuple[str, str], ...]:
    if type(raw) is not tuple:
        raise DomainError(f"{label} must be an exact tuple")
    result: list[tuple[str, str]] = []
    for item in raw:
        if (
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            or _SET_KEY.fullmatch(item[0]) is None
            or not item[1]
            or "\x00" in item[1]
        ):
            raise DomainError(f"{label} entries must be exact safe key/value tuples")
        result.append(item)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class HelmRenderSpec:
    chart_root: Path
    helm_executable: Path
    release_name: str
    namespace: str
    kube_version: str
    values_files: tuple[str, ...] = ()
    set_values: tuple[tuple[str, str], ...] = ()
    set_strings: tuple[tuple[str, str], ...] = ()
    api_versions: tuple[str, ...] = ()
    include_crds: bool = False
    include_tests: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.chart_root, Path) or not isinstance(self.helm_executable, Path):
            raise DomainError("Helm chart and executable must be pathlib.Path values")
        try:
            chart = self.chart_root.resolve(strict=True)
            executable = self.helm_executable.resolve(strict=True)
        except OSError as exc:
            raise DomainError("Helm chart or executable is unavailable") from exc
        if not chart.is_dir():
            raise DomainError("Helm chart root must be a directory")
        metadata = executable.stat()
        if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
            raise DomainError("Helm executable must be an executable regular file")
        if executable == chart or chart in executable.parents:
            raise DomainError("Helm executable must not be inside the chart")
        object.__setattr__(self, "chart_root", chart)
        object.__setattr__(self, "helm_executable", executable)
        object.__setattr__(
            self, "release_name", _safe_dns(self.release_name, "Helm release name")
        )
        object.__setattr__(
            self, "namespace", _safe_dns(self.namespace, "Helm namespace", namespace=True)
        )
        object.__setattr__(
            self, "kube_version", _safe_version(self.kube_version, "Helm kube version")
        )
        if type(self.values_files) is not tuple:
            raise DomainError("Helm values files must be an exact tuple")
        values = tuple(canonical_repo_path(item, "Helm values file") for item in self.values_files)
        if len(values) != len(set(values)):
            raise DomainError("Helm values files must not contain duplicates")
        for relative in values:
            target = chart / relative
            try:
                resolved = target.resolve(strict=True)
            except OSError as exc:
                raise DomainError("Helm values file is unavailable") from exc
            if chart not in resolved.parents or not resolved.is_file() or target.is_symlink():
                raise DomainError("Helm values file must be a regular file inside the chart")
        object.__setattr__(self, "values_files", values)
        object.__setattr__(self, "set_values", _typed_overrides(self.set_values, "Helm set"))
        object.__setattr__(
            self, "set_strings", _typed_overrides(self.set_strings, "Helm set-string")
        )
        set_keys = {key for key, _ in self.set_values}
        set_string_keys = {key for key, _ in self.set_strings}
        if set_keys & set_string_keys:
            raise DomainError("Helm set and set-string keys must not overlap")
        if type(self.api_versions) is not tuple or any(
            type(item) is not str
            or not item
            or len(item) > 253
            or any(ord(char) < 32 for char in item)
            for item in self.api_versions
        ):
            raise DomainError("Helm API versions must be an exact tuple of safe strings")
        if len(self.api_versions) != len(set(self.api_versions)):
            raise DomainError("Helm API versions must not contain duplicates")
        if type(self.include_crds) is not bool or type(self.include_tests) is not bool:
            raise DomainError("Helm CRD and test modes must be booleans")


@dataclass(frozen=True, slots=True)
class HelmChartFile:
    path: str
    size: int
    mode: int
    sha256: str

    def canonical_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "mode": self.mode,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class HelmRenderedDocument:
    index: int
    sha256: str
    api_version: str
    kind: str
    namespace: str
    name: str
    resource_identity: str
    source_template: str
    source_chart: str

    def canonical_dict(self) -> dict:
        return {
            "index": self.index,
            "sha256": self.sha256,
            "api_version": self.api_version,
            "kind": self.kind,
            "namespace": self.namespace,
            "name": self.name,
            "resource_identity": self.resource_identity,
            "source_template": self.source_template,
            "source_chart": self.source_chart,
        }


@dataclass(frozen=True, slots=True)
class HelmMaterializationEvidence:
    executable: MappingProxyType
    chart: MappingProxyType
    render_inputs: MappingProxyType
    output: MappingProxyType
    documents: tuple[HelmRenderedDocument, ...]
    materialization_identity: str

    def canonical_dict(self) -> dict:
        return {
            "contract": HELM_MATERIALIZATION_CONTRACT,
            "status": "PASS",
            "reason_code": "DETERMINISTIC_CLIENT_RENDER_BOUND",
            "executable": dict(self.executable),
            "chart": dict(self.chart),
            "render_inputs": dict(self.render_inputs),
            "output": dict(self.output),
            "documents": [item.canonical_dict() for item in self.documents],
            "materialization_identity": self.materialization_identity,
        }


@dataclass(frozen=True, slots=True)
class HelmMaterializedPair:
    baseline_root: Path
    candidate_root: Path
    baseline: HelmMaterializationEvidence
    candidate: HelmMaterializationEvidence
    comparison_identity: str

    def canonical_dict(self) -> dict:
        return {
            "contract": "helm-comparison-v1",
            "baseline": self.baseline.canonical_dict(),
            "candidate": self.candidate.canonical_dict(),
            "comparison_identity": self.comparison_identity,
        }


def _inventory(root: Path) -> tuple[tuple[HelmChartFile, ...], str]:
    files: list[HelmChartFile] = []
    total = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in tuple(dirnames):
            path = current / name
            if path.is_symlink():
                raise HelmMaterializationError(
                    "CHART_PATH_ESCAPE", "chart directory symlinks are not supported"
                )
        for name in filenames:
            path = current / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise HelmMaterializationError(
                    "CHART_INVENTORY_UNAVAILABLE", "chart file cannot be inspected"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise HelmMaterializationError(
                    "CHART_PATH_ESCAPE", "chart file symlinks are not supported"
                )
            if not stat.S_ISREG(metadata.st_mode):
                raise HelmMaterializationError(
                    "CHART_INVENTORY_UNAVAILABLE", "chart contains an unsupported file type"
                )
            if metadata.st_size > _MAX_CHART_FILE_BYTES:
                raise HelmMaterializationError(
                    "HELM_RESOURCE_LIMIT_EXCEEDED", "chart file exceeds the size limit"
                )
            total += metadata.st_size
            if total > _MAX_CHART_BYTES:
                raise HelmMaterializationError(
                    "HELM_RESOURCE_LIMIT_EXCEEDED", "chart exceeds the total-byte limit"
                )
            relative = path.relative_to(root).as_posix()
            payload = path.read_bytes()
            if len(payload) != metadata.st_size or path.stat().st_ino != metadata.st_ino:
                raise HelmMaterializationError(
                    "CHART_MUTATED_DURING_RENDER", "chart changed during inventory"
                )
            files.append(HelmChartFile(
                canonical_repo_path(relative, "chart file"),
                len(payload),
                stat.S_IMODE(metadata.st_mode),
                _sha256(payload),
            ))
            if len(files) > _MAX_CHART_FILES:
                raise HelmMaterializationError(
                    "HELM_RESOURCE_LIMIT_EXCEEDED", "chart exceeds the file-count limit"
                )
    ordered = tuple(sorted(files, key=lambda item: item.path))
    root_hash = _canonical_sha([item.canonical_dict() for item in ordered])
    return ordered, root_hash


def _strict_yaml(path: Path, label: str) -> dict:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictSafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", f"{label} is not valid UTF-8 YAML"
        ) from exc
    if type(value) is not dict:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", f"{label} must be a YAML mapping"
        )
    return value


def _dependency_key(value: object) -> tuple[str, str, str]:
    if type(value) is not dict:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "chart dependency entry is not a mapping"
        )
    name = value.get("name")
    version = value.get("version")
    repository = value.get("repository", "")
    if any(type(item) is not str or not item for item in (name, version)) or type(
        repository
    ) is not str:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "chart dependency identity is incomplete"
        )
    return name, version, repository


def _dependency_record(value: object) -> dict:
    """Reproduce Helm's dependency JSON field order for Chart.lock HashReq."""
    if type(value) is not dict:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "chart dependency entry is not a mapping"
        )
    allowed = {
        "name", "version", "repository", "condition", "tags", "enabled",
        "import-values", "alias",
    }
    if set(value) - allowed:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "dependency contains unmodeled fields"
        )
    name, version, repository = _dependency_key(value)
    result = {"name": name, "version": version, "repository": repository}
    condition = value.get("condition", "")
    tags = value.get("tags", [])
    enabled = value.get("enabled", False)
    imports = value.get("import-values", [])
    alias = value.get("alias", "")
    if type(condition) is not str or type(alias) is not str:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "dependency condition or alias is invalid"
        )
    if type(tags) is not list or any(type(item) is not str for item in tags):
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "dependency tags are invalid"
        )
    if type(enabled) is not bool or type(imports) is not list:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "dependency options are invalid"
        )
    if condition:
        result["condition"] = condition
    if tags:
        result["tags"] = tags
    if enabled:
        result["enabled"] = True
    if imports:
        result["import-values"] = imports
    if alias:
        result["alias"] = alias
    return result


def _helm_dependency_digest(requirements: list, locked: list) -> str:
    request_records = [_dependency_record(item) for item in requirements]
    lock_records = [_dependency_record(item) for item in locked]
    payload = json.dumps(
        [request_records, lock_records],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + _sha256(payload)


def _inspect_archive(
    path: Path, expected_name: str, expected_version: str
) -> list[dict]:
    expanded = 0
    expanded_files = []
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                raise HelmMaterializationError(
                    "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive has too many members"
                )
            chart_yaml = None
            for member in members:
                pure = PurePosixPath(member.name)
                if (
                    pure.is_absolute()
                    or ".." in pure.parts
                    or member.issym()
                    or member.islnk()
                    or not (member.isfile() or member.isdir())
                ):
                    raise HelmMaterializationError(
                        "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive contains unsafe paths"
                    )
                if not pure.parts or pure.parts[0] != expected_name:
                    raise HelmMaterializationError(
                        "UNSAFE_DEPENDENCY_ARCHIVE",
                        "dependency archive has an unexpected root directory",
                    )
                expanded += max(member.size, 0)
                if expanded > _MAX_ARCHIVE_EXPANDED_BYTES:
                    raise HelmMaterializationError(
                        "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive expands beyond its limit"
                    )
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise HelmMaterializationError(
                            "UNSAFE_DEPENDENCY_ARCHIVE",
                            "dependency archive member cannot be read",
                        )
                    payload = stream.read()
                    if len(payload) != member.size:
                        raise HelmMaterializationError(
                            "UNSAFE_DEPENDENCY_ARCHIVE",
                            "dependency archive member has inconsistent bytes",
                        )
                    virtual = PurePosixPath("charts", expected_name, *pure.parts[1:])
                    expanded_files.append({
                        "path": canonical_repo_path(
                            virtual.as_posix(), "expanded Helm dependency file"
                        ),
                        "size": len(payload),
                        "mode": stat.S_IMODE(member.mode),
                        "sha256": _sha256(payload),
                    })
                    if pure.name == "Chart.yaml" and len(pure.parts) == 2:
                        chart_yaml = yaml.load(payload, Loader=_StrictSafeLoader)
            if type(chart_yaml) is not dict or chart_yaml.get("name") != expected_name or str(
                chart_yaml.get("version")
            ) != expected_version:
                raise HelmMaterializationError(
                    "UNREPRODUCIBLE_DEPENDENCIES", "vendored archive identity is inconsistent"
                )
            if not expanded_files:
                raise HelmMaterializationError(
                    "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive has no regular files"
                )
    except HelmMaterializationError:
        raise
    except (OSError, tarfile.TarError, yaml.YAMLError) as exc:
        raise HelmMaterializationError(
            "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive cannot be safely inspected"
        ) from exc
    return sorted(expanded_files, key=lambda item: item["path"])


def _validate_dependencies(root: Path, chart: dict) -> dict:
    raw_dependencies = chart.get("dependencies", [])
    if raw_dependencies is None:
        raw_dependencies = []
    if type(raw_dependencies) is not list:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "Chart.yaml dependencies must be a list"
        )
    if any(type(item) is dict and item.get("alias", "") for item in raw_dependencies):
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES",
            "dependency aliases are not supported by this bounded contract",
        )
    dependencies = tuple(_dependency_key(item) for item in raw_dependencies)
    if len(dependencies) != len(set(dependencies)):
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "Chart.yaml contains duplicate dependencies"
        )
    lock_path = root / "Chart.lock"
    lock_hash = ""
    if lock_path.exists():
        lock = _strict_yaml(lock_path, "Chart.lock")
        locked = lock.get("dependencies", [])
        if type(locked) is not list or tuple(_dependency_key(item) for item in locked) != dependencies:
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES", "Chart.lock does not match Chart.yaml"
            )
        digest = lock.get("digest")
        if type(digest) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES", "Chart.lock digest is missing or malformed"
            )
        if digest != _helm_dependency_digest(raw_dependencies, locked):
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES", "Chart.lock digest is out of sync"
            )
        lock_hash = _sha256(lock_path.read_bytes())
    charts = root / "charts"
    artifacts = []
    for name, version, repository in dependencies:
        directory = charts / name
        archive = charts / f"{name}-{version}.tgz"
        if directory.is_dir() and not directory.is_symlink():
            child = _strict_yaml(directory / "Chart.yaml", "vendored subchart Chart.yaml")
            if child.get("name") != name or str(child.get("version")) != version:
                raise HelmMaterializationError(
                    "UNREPRODUCIBLE_DEPENDENCIES", "vendored subchart identity is inconsistent"
                )
            artifacts.append({
                "name": name,
                "version": version,
                "form": "directory",
                "expanded_files": [],
            })
        elif archive.is_file() and not archive.is_symlink():
            expanded_files = _inspect_archive(archive, name, version)
            artifacts.append({
                "name": name,
                "version": version,
                "form": "archive",
                "sha256": _sha256(archive.read_bytes()),
                "expanded_files": expanded_files,
            })
        else:
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES", "declared dependency is not locally vendored"
            )
        if not repository.startswith("file://") and not lock_path.exists():
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES",
                "non-local dependency requires a lock and vendored bytes",
            )
    return {
        "count": len(dependencies),
        "chart_lock_sha256": lock_hash,
        "artifacts": artifacts,
    }


def _unquoted_action(action: str) -> str:
    """Mask quoted Go-template literals before looking for function calls."""
    output = []
    quote = ""
    escaped = False
    for char in action:
        if quote:
            if escaped:
                escaped = False
            elif quote == '"' and char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            output.append(" ")
        elif char in ('"', "'", "`"):
            quote = char
            output.append(" ")
        else:
            output.append(char)
    return "".join(output)


def _template_sources(root: Path, dependencies: dict) -> tuple[tuple[str, str], ...]:
    result = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if "templates" not in relative.parts and "crds" not in relative.parts:
            continue
        try:
            result.append((relative.as_posix(), path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError) as exc:
            raise HelmMaterializationError(
                "CHART_INVENTORY_UNAVAILABLE", "Helm template is not valid UTF-8"
            ) from exc
    for artifact in dependencies["artifacts"]:
        if artifact["form"] != "archive":
            continue
        archive_path = root / "charts" / f"{artifact['name']}-{artifact['version']}.tgz"
        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                for member in archive.getmembers():
                    pure = PurePosixPath(member.name)
                    if not member.isfile() or not (
                        "templates" in pure.parts or "crds" in pure.parts
                    ):
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise HelmMaterializationError(
                            "UNSAFE_DEPENDENCY_ARCHIVE",
                            "dependency template cannot be read",
                        )
                    payload = stream.read()
                    try:
                        text = payload.decode("utf-8", errors="strict")
                    except UnicodeError as exc:
                        raise HelmMaterializationError(
                            "CHART_INVENTORY_UNAVAILABLE",
                            "dependency template is not valid UTF-8",
                        ) from exc
                    virtual = PurePosixPath("charts", artifact["name"], *pure.parts[1:])
                    result.append((virtual.as_posix(), text))
        except HelmMaterializationError:
            raise
        except (OSError, tarfile.TarError) as exc:
            raise HelmMaterializationError(
                "UNSAFE_DEPENDENCY_ARCHIVE", "dependency templates cannot be inspected"
            ) from exc
    paths = [path for path, _ in result]
    if len(paths) != len(set(paths)):
        raise HelmMaterializationError(
            "AMBIGUOUS_TEMPLATE_ACTION_GRAPH", "template source identity is duplicated"
        )
    return tuple(sorted(result))


def _template_actions(root: Path, dependencies: dict) -> _TemplateActionIndex:
    root_state: dict[str, tuple[set[str], set[str], bool]] = {}
    definition_state: dict[str, tuple[set[str], set[str], bool]] = {}
    for path, text in _template_sources(root, dependencies):
        root_functions: set[str] = set()
        root_calls: set[str] = set()
        root_dynamic = False
        current_name: str | None = None
        current_functions: set[str] | None = None
        current_calls: set[str] | None = None
        current_dynamic = False
        definition_depth = 0
        for match in _ACTION.finditer(text):
            action = match.group(1)
            if _TEMPLATE_COMMENT.fullmatch(action):
                continue
            definition = _DEFINE_ACTION.match(action)
            if definition is not None:
                if current_name is not None or definition.group(1) in definition_state:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
                        "named Helm template definition is duplicated or nested",
                    )
                current_name = definition.group(1)
                current_functions = set()
                current_calls = set()
                current_dynamic = False
                definition_depth = 1
                continue
            code = _unquoted_action(action)
            functions = {
                item.group(1) for item in _RANDOM_FUNCTION.finditer(code)
            }
            if _LOOKUP_FUNCTION.search(code):
                functions.add("lookup")
            calls = set(_NAMED_TEMPLATE_CALL.findall(action))
            dynamic = bool(_NAMED_TEMPLATE_ANY.search(code)) and not calls
            if current_name is None:
                root_functions.update(functions)
                root_calls.update(calls)
                root_dynamic = root_dynamic or dynamic
            else:
                assert current_functions is not None and current_calls is not None
                current_functions.update(functions)
                current_calls.update(calls)
                current_dynamic = current_dynamic or dynamic
                if _CONTROL_START.match(code):
                    definition_depth += 1
                if _CONTROL_END.match(code):
                    definition_depth -= 1
                    if definition_depth == 0:
                        definition_state[current_name] = (
                            current_functions,
                            current_calls,
                            current_dynamic,
                        )
                        current_name = None
                        current_functions = None
                        current_calls = None
                        current_dynamic = False
        if current_name is not None:
            raise HelmMaterializationError(
                "AMBIGUOUS_TEMPLATE_ACTION_GRAPH", "named Helm template is not closed"
            )
        root_state[path] = (root_functions, root_calls, root_dynamic)
    return _TemplateActionIndex(
        roots={
            path: _TemplateActionScope(frozenset(functions), frozenset(calls), dynamic)
            for path, (functions, calls, dynamic) in root_state.items()
        },
        definitions={
            name: _TemplateActionScope(frozenset(functions), frozenset(calls), dynamic)
            for name, (functions, calls, dynamic) in definition_state.items()
        },
    )


def _helm_identity(executable: Path, chart_root: Path) -> dict:
    digest = _sha256(executable.read_bytes())
    result = run_command(CommandRequest(
        (str(executable), "version", "--template", "{{.Version}}"),
        workspace_root=chart_root,
        timeout_seconds=30,
        max_output_bytes=64 * 1024,
        max_stdout_bytes=32 * 1024,
        max_stderr_bytes=32 * 1024,
    ))
    if result.status is not Status.PASS or result.exit_code != 0:
        raise HelmMaterializationError(
            "HELM_ENVIRONMENT_INCOMPLETE", "Helm version probe did not succeed"
        )
    version_text = result.stdout.decode("utf-8", errors="strict").strip()
    version = _HELM_VERSION.fullmatch(version_text)
    if version is None:
        raise HelmMaterializationError(
            "HELM_ENVIRONMENT_INCOMPLETE", "Helm version output is not canonical"
        )
    if _sha256(executable.read_bytes()) != digest:
        raise HelmMaterializationError(
            "HELM_ENVIRONMENT_INCOMPLETE", "Helm executable changed during probing"
        )
    return {
        "version": version.group(1),
        "launcher_name": executable.name,
        "executable_sha256": digest,
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
    }


def _argv(spec: HelmRenderSpec) -> tuple[tuple[str, ...], tuple[int, ...]]:
    arguments = [
        str(spec.helm_executable),
        "template",
        spec.release_name,
        ".",
        "--namespace",
        spec.namespace,
        "--kube-version",
        spec.kube_version,
    ]
    for value in spec.api_versions:
        arguments.extend(("--api-versions", value))
    for value in spec.values_files:
        arguments.extend(("--values", value))
    sensitive = []
    for key, value in spec.set_values:
        arguments.extend(("--set", f"{key}={value}"))
        sensitive.append(len(arguments) - 1)
    for key, value in spec.set_strings:
        arguments.extend(("--set-string", f"{key}={value}"))
        sensitive.append(len(arguments) - 1)
    if spec.include_crds:
        arguments.append("--include-crds")
    if not spec.include_tests:
        arguments.append("--skip-tests")
    return tuple(arguments), tuple(sensitive)


def _render(spec: HelmRenderSpec, state_root: Path) -> tuple[bytes, bytes, tuple[str, ...], str]:
    state_root.mkdir(mode=0o700)
    cache = state_root / "cache"
    config = state_root / "config"
    data = state_root / "data"
    plugins = state_root / "plugins"
    for path in (cache, config, data, plugins):
        path.mkdir(mode=0o700)
    argv, sensitive = _argv(spec)
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HELM_CACHE_HOME": str(cache),
        "HELM_CONFIG_HOME": str(config),
        "HELM_DATA_HOME": str(data),
        "HELM_PLUGINS": str(plugins),
        "HELM_REGISTRY_CONFIG": str(config / "registry.json"),
        "HELM_REPOSITORY_CONFIG": str(config / "repositories.yaml"),
        "HELM_REPOSITORY_CACHE": str(cache / "repository"),
    }
    result = run_command(CommandRequest(
        argv,
        cwd=spec.chart_root,
        workspace_root=spec.chart_root,
        timeout_seconds=120,
        max_output_bytes=_MAX_RENDER_BYTES,
        max_stdout_bytes=_MAX_RENDER_BYTES - 256 * 1024,
        max_stderr_bytes=256 * 1024,
        env_allowlist=(),
        env_extra=MappingProxyType(environment),
        sensitive_argument_indices=sensitive,
    ))
    if result.status is Status.PARTIAL:
        raise HelmMaterializationError(
            "HELM_RESOURCE_LIMIT_EXCEEDED", "Helm output exceeded its protected limit"
        )
    if result.status is not Status.PASS or result.exit_code != 0:
        raise HelmMaterializationError(
            "HELM_RENDER_FAILED", "Helm client render did not complete successfully"
        )
    safe_argv = tuple(result.canonical_dict()["argv"])
    canonical_argv = (spec.helm_executable.name, *argv[1:])
    return result.stdout, result.stderr, safe_argv, _canonical_sha(list(canonical_argv))


def _split_documents(payload: bytes) -> tuple[bytes, ...]:
    lines = payload.splitlines(keepends=True)
    documents: list[bytes] = []
    current: list[bytes] = []
    for line in lines:
        if line.rstrip(b"\r\n") == b"---":
            if b"".join(current).strip():
                documents.append(b"".join(current))
            current = []
        else:
            current.append(line)
    if b"".join(current).strip():
        documents.append(b"".join(current))
    if len(documents) > _MAX_RENDER_DOCUMENTS:
        raise HelmMaterializationError(
            "HELM_RESOURCE_LIMIT_EXCEEDED", "render has too many YAML documents"
        )
    return tuple(documents)


def _source_path(marker: str, chart_name: str, files: set[str]) -> tuple[str, str]:
    if marker.startswith(f"{chart_name}/"):
        relative = marker[len(chart_name) + 1:]
    else:
        raise HelmMaterializationError(
            "AMBIGUOUS_SOURCE_PROVENANCE", "source marker names another chart root"
        )
    relative = canonical_repo_path(relative, "Helm source marker")
    if relative not in files:
        raise HelmMaterializationError(
            "AMBIGUOUS_SOURCE_PROVENANCE", "source marker does not resolve to chart bytes"
        )
    parts = PurePosixPath(marker).parts
    source_chart = parts[0]
    if "charts" in parts:
        index = len(parts) - 1 - tuple(reversed(parts)).index("charts")
        if len(parts) > index + 1:
            source_chart = parts[index + 1]
    return relative, source_chart


def _documents(
    stdout: bytes,
    *,
    chart_name: str,
    chart_files: tuple[HelmChartFile, ...],
    expanded_dependency_files: tuple[str, ...],
    default_namespace: str,
) -> tuple[HelmRenderedDocument, ...]:
    result = []
    identities = set()
    files = {item.path for item in chart_files} | set(expanded_dependency_files)
    for index, raw in enumerate(_split_documents(stdout), start=1):
        try:
            text = raw.decode("utf-8", errors="strict")
            nonblank = [line for line in text.splitlines() if line.strip()]
            markers = _SOURCE_MARKER.findall(text)
            if not nonblank or _SOURCE_MARKER.fullmatch(nonblank[0]) is None:
                markers = []
            value = yaml.load(text, Loader=_StrictSafeLoader)
        except (UnicodeError, yaml.YAMLError) as exc:
            raise HelmMaterializationError(
                "RENDERED_YAML_INVALID", "rendered output contains invalid YAML"
            ) from exc
        if value is None:
            continue
        if type(value) is not dict:
            raise HelmMaterializationError(
                "RENDERED_YAML_INVALID", "rendered YAML document is not a mapping"
            )
        if len(markers) != 1:
            raise HelmMaterializationError(
                "AMBIGUOUS_SOURCE_PROVENANCE", "rendered document lacks one source marker"
            )
        source, source_chart = _source_path(markers[0], chart_name, files)
        api_version = value.get("apiVersion")
        kind = value.get("kind")
        metadata = value.get("metadata")
        if type(api_version) is not str or type(kind) is not str or type(metadata) is not dict:
            raise HelmMaterializationError(
                "MISSING_RENDERED_RESOURCE_IDENTITY", "rendered document has no stable identity"
            )
        name = metadata.get("name")
        if type(name) is not str or not name or metadata.get("generateName") and not name:
            raise HelmMaterializationError(
                "MISSING_RENDERED_RESOURCE_IDENTITY", "rendered resource has no stable name"
            )
        explicit_namespace = metadata.get("namespace")
        if explicit_namespace in (None, "") and default_namespace != "default":
            raise HelmMaterializationError(
                "UNMODELED_RENDER_INPUT",
                "a non-default render namespace is absent from rendered resource metadata",
            )
        namespace = explicit_namespace or default_namespace
        if type(namespace) is not str:
            raise HelmMaterializationError(
                "MISSING_RENDERED_RESOURCE_IDENTITY", "rendered namespace is not a string"
            )
        identity = f"{api_version}/{kind}/{namespace}/{name}"
        if identity in identities:
            raise HelmMaterializationError(
                "DUPLICATE_RENDERED_IDENTITY", "rendered resource identity is duplicated"
            )
        identities.add(identity)
        result.append(HelmRenderedDocument(
            index,
            _sha256(raw),
            api_version,
            kind,
            namespace,
            name,
            identity,
            source,
            source_chart,
        ))
    if not result:
        raise HelmMaterializationError(
            "MISSING_RENDERED_RESOURCE_IDENTITY", "Helm rendered no Kubernetes resources"
        )
    return tuple(result)


def _participating_action_failure(
    actions: _TemplateActionIndex,
    documents: tuple[HelmRenderedDocument, ...],
) -> str | None:
    sources = {item.source_template for item in documents}
    active_functions = set()
    pending = set()
    ambiguous = False
    for path in sources:
        scope = actions.roots.get(path)
        if scope is None:
            ambiguous = True
            continue
        ambiguous = ambiguous or scope.dynamic_call
        active_functions.update(scope.functions)
        pending.update(scope.calls)
    visited = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        scope = actions.definitions.get(name)
        if scope is None:
            ambiguous = True
            continue
        ambiguous = ambiguous or scope.dynamic_call
        active_functions.update(scope.functions)
        pending.update(scope.calls - visited)
    if "lookup" in active_functions:
        return "CLUSTER_STATE_REQUIRED"
    if active_functions:
        return "NONDETERMINISTIC_RENDER"
    if ambiguous:
        raise HelmMaterializationError(
            "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
            "participating Helm template action identity is incomplete",
        )
    return None


def materialize_helm(spec: HelmRenderSpec, output_root: Path) -> HelmMaterializationEvidence:
    """Render one chart twice and write one protected deterministic scanner bundle."""
    if type(spec) is not HelmRenderSpec or not isinstance(output_root, Path):
        raise DomainError("Helm materialization requires exact typed inputs")
    if output_root.exists():
        raise DomainError("Helm output root must not already exist")
    chart_files, chart_root_sha = _inventory(spec.chart_root)
    chart_path = spec.chart_root / "Chart.yaml"
    if not chart_path.is_file() or chart_path.is_symlink():
        raise HelmMaterializationError(
            "CHART_INVENTORY_UNAVAILABLE", "chart has no regular Chart.yaml"
        )
    chart_value = _strict_yaml(chart_path, "Chart.yaml")
    chart_name = chart_value.get("name")
    chart_version = chart_value.get("version")
    if type(chart_name) is not str or type(chart_version) not in (str, int, float):
        raise HelmMaterializationError(
            "CHART_INVENTORY_UNAVAILABLE", "Chart.yaml identity is incomplete"
        )
    dependencies = _validate_dependencies(spec.chart_root, chart_value)
    expanded_dependency_files = tuple(
        item["path"]
        for artifact in dependencies["artifacts"]
        for item in artifact["expanded_files"]
    )
    actions = _template_actions(spec.chart_root, dependencies)
    executable = _helm_identity(spec.helm_executable, spec.chart_root)
    with tempfile.TemporaryDirectory(prefix="iacgv-helm-renders-") as temporary:
        temp = Path(temporary)
        first_stdout, first_stderr, safe_argv, argv_sha = _render(spec, temp / "first")
        if _sha256(spec.helm_executable.read_bytes()) != executable["executable_sha256"]:
            raise HelmMaterializationError(
                "HELM_ENVIRONMENT_INCOMPLETE", "Helm executable changed before rendering"
            )
        first_documents = _documents(
            first_stdout,
            chart_name=chart_name,
            chart_files=chart_files,
            expanded_dependency_files=expanded_dependency_files,
            default_namespace=spec.namespace,
        )
        action_failure = _participating_action_failure(actions, first_documents)
        if action_failure == "CLUSTER_STATE_REQUIRED":
            raise HelmMaterializationError(
                action_failure, "a participating Helm template requires live cluster lookup"
            )
        second_stdout, second_stderr, second_argv, second_argv_sha = _render(
            spec, temp / "second"
        )
        if _sha256(spec.helm_executable.read_bytes()) != executable["executable_sha256"]:
            raise HelmMaterializationError(
                "HELM_ENVIRONMENT_INCOMPLETE", "Helm executable changed during rendering"
            )
        second_documents = _documents(
            second_stdout,
            chart_name=chart_name,
            chart_files=chart_files,
            expanded_dependency_files=expanded_dependency_files,
            default_namespace=spec.namespace,
        )
    current_files, current_root_sha = _inventory(spec.chart_root)
    if current_files != chart_files or current_root_sha != chart_root_sha:
        raise HelmMaterializationError(
            "CHART_MUTATED_DURING_RENDER", "chart inventory changed during rendering"
        )
    if (
        first_stdout != second_stdout
        or first_stderr != second_stderr
        or first_documents != second_documents
        or safe_argv != second_argv
        or argv_sha != second_argv_sha
    ):
        raise HelmMaterializationError(
            "NONDETERMINISTIC_RENDER", "fresh Helm renders produced different evidence"
        )
    if action_failure == "NONDETERMINISTIC_RENDER":
        raise HelmMaterializationError(
            action_failure, "a participating Helm template invokes a nondeterministic helper"
        )
    output_root.mkdir(mode=0o700, parents=True)
    rendered = output_root / "rendered.yaml"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(rendered, flags, 0o600)
    try:
        offset = 0
        while offset < len(first_stdout):
            written = os.write(descriptor, first_stdout[offset:])
            if written <= 0:
                raise HelmMaterializationError(
                    "HELM_STATE_NOT_ISOLATED", "rendered bundle write did not complete"
                )
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if _sha256(rendered.read_bytes()) != _sha256(first_stdout):
        raise HelmMaterializationError(
            "HELM_STATE_NOT_ISOLATED", "rendered bundle digest changed after writing"
        )
    values_evidence = [
        {"path": relative, "sha256": _sha256((spec.chart_root / relative).read_bytes())}
        for relative in spec.values_files
    ]
    overrides = {
        "set": [
            {"key": key, "value_sha256": _sha256(value.encode("utf-8")), "type": "typed"}
            for key, value in spec.set_values
        ],
        "set_string": [
            {"key": key, "value_sha256": _sha256(value.encode("utf-8")), "type": "string"}
            for key, value in spec.set_strings
        ],
    }
    render_inputs = {
        "release_name": spec.release_name,
        "namespace": spec.namespace,
        "kube_version": spec.kube_version,
        "api_versions": list(spec.api_versions),
        "values_files": values_evidence,
        "overrides": overrides,
        "crds": "include" if spec.include_crds else "exclude",
        "tests": "include" if spec.include_tests else "exclude",
        "argv": list(safe_argv),
        "argv_sha256": argv_sha,
        "environment_sha256": _canonical_sha({
            "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "helm_homes": "fresh-per-render", "kubeconfig": "unavailable",
        }),
    }
    chart_evidence = {
        "name": chart_name,
        "version": str(chart_version),
        "inventory_root_sha256": chart_root_sha,
        "chart_yaml_sha256": _sha256(chart_path.read_bytes()),
        "files": [item.canonical_dict() for item in chart_files],
        "dependencies": dependencies,
    }
    output = {
        "stdout_sha256": _sha256(first_stdout),
        "stderr_sha256": _sha256(first_stderr),
        "stdout_bytes": len(first_stdout),
        "stderr_bytes": len(first_stderr),
        "rendered_bundle_path": "rendered.yaml",
        "rendered_bundle_sha256": _sha256(first_stdout),
        "document_inventory_sha256": _canonical_sha([
            item.canonical_dict() for item in first_documents
        ]),
        "resource_count": len(first_documents),
        "fresh_render_count": 2,
    }
    body = {
        "executable": executable,
        "chart": chart_evidence,
        "render_inputs": render_inputs,
        "output": output,
        "documents": [item.canonical_dict() for item in first_documents],
    }
    return HelmMaterializationEvidence(
        MappingProxyType(executable),
        MappingProxyType(chart_evidence),
        MappingProxyType(render_inputs),
        MappingProxyType(output),
        first_documents,
        _canonical_sha(body),
    )


@contextmanager
def materialize_helm_comparison(
    baseline: HelmRenderSpec, candidate: HelmRenderSpec
) -> Iterator[HelmMaterializedPair]:
    if type(baseline) is not HelmRenderSpec or type(candidate) is not HelmRenderSpec:
        raise DomainError("Helm comparison requires exact render specifications")
    input_contracts = (
        baseline.release_name,
        baseline.namespace,
        baseline.kube_version,
        baseline.values_files,
        baseline.set_values,
        baseline.set_strings,
        baseline.api_versions,
        baseline.include_crds,
        baseline.include_tests,
    ), (
        candidate.release_name,
        candidate.namespace,
        candidate.kube_version,
        candidate.values_files,
        candidate.set_values,
        candidate.set_strings,
        candidate.api_versions,
        candidate.include_crds,
        candidate.include_tests,
    )
    if input_contracts[0] != input_contracts[1]:
        raise DomainError("Helm before and after renders must use identical protected inputs")
    with tempfile.TemporaryDirectory(prefix="iacgv-helm-comparison-") as temporary:
        root = Path(temporary)
        baseline_root = root / "baseline"
        candidate_root = root / "candidate"
        baseline_evidence = materialize_helm(baseline, baseline_root)
        candidate_evidence = materialize_helm(candidate, candidate_root)
        comparison = _canonical_sha({
            "baseline": baseline_evidence.materialization_identity,
            "candidate": candidate_evidence.materialization_identity,
        })
        yield HelmMaterializedPair(
            baseline_root,
            candidate_root,
            baseline_evidence,
            candidate_evidence,
            comparison,
        )


__all__ = [
    "HELM_MATERIALIZATION_CONTRACT",
    "HelmMaterializationError",
    "HelmMaterializationEvidence",
    "HelmMaterializedPair",
    "HelmRenderSpec",
    "materialize_helm",
    "materialize_helm_comparison",
]
