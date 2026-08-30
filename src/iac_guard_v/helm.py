"""Bounded, deterministic, client-side Helm materialization.

The materializer accepts only a local chart and a closed typed render contract.
It never contacts Kubernetes, resolves a remote dependency, executes a plugin or
post-renderer, or evaluates an arbitrary command tail.  Two fresh renders must
produce byte-identical, source-bound Kubernetes documents before their output is
eligible for the existing Checkov verification path.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shlex
import stat
import tarfile
import tempfile
import unicodedata
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Iterator

import yaml

from .enums import Status
from .helm_semver import HelmSemverError, prove_constraint
from .models import DomainError, canonical_repo_path
from .process import CommandRequest, run_command
from .redaction import redact_detail


HELM_MATERIALIZATION_CONTRACT = "helm-materialization-v1"
HELM_UNIVERSE_CONTRACT = "helm-universe-v1"
_MAX_CHART_FILES = 10_000
_MAX_CHART_FILE_BYTES = 10 * 1024 * 1024
_MAX_CHART_BYTES = 64 * 1024 * 1024
_MAX_RENDER_BYTES = 32 * 1024 * 1024
_MAX_RENDER_DOCUMENTS = 5_000
_MAX_ARCHIVE_MEMBERS = 10_000
_MAX_ARCHIVE_EXPANDED_BYTES = 64 * 1024 * 1024
_MAX_TPL_NESTING_DEPTH = 4
_MAX_TPL_EXPANDED_BYTES = 64 * 1024
_MAX_TPL_NESTED_ACTIONS = 256
_MAX_TEMPLATE_CALL_DEPTH = 32
_MAX_DYNAMIC_INCLUDE_DEPTH = 16
_MAX_DYNAMIC_INCLUDE_NODES = 256
_MAX_DYNAMIC_INCLUDE_ACTION_BYTES = 256 * 1024
_MAX_DYNAMIC_INCLUDE_TARGETS = 128
_HELM_VERSION = re.compile(r"v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)")
_TEMPLATE_COMMENT = re.compile(r"^\s*/\*.*\*/\s*$", re.DOTALL)
_RANDOM_FUNCTION = re.compile(
    r"(?<![A-Za-z0-9_])("
    r"randAlphaNum|randAlpha|randNumeric|randAscii|uuidv4|now|dateInZone|ago|"
    r"genCA|genSelfSignedCert|genSignedCert|genPrivateKey|encryptAES|htpasswd"
    r")(?![A-Za-z0-9_])"
)
_LOOKUP_FUNCTION = re.compile(r"(?<![A-Za-z0-9_])lookup(?![A-Za-z0-9_])")
_TPL_FUNCTION = re.compile(r"(?:^|[\s(|])tpl(?=\s|$)")
_NAMED_TEMPLATE_CALL = re.compile(
    r'(?:^|[\s(|])(?:include|template)\s+"([^"\r\n]+)"'
)
_NAMED_TEMPLATE_ANY = re.compile(r"(?:^|[\s(|])(?:include|template)(?=\s)")
_DEFINE_ACTION = re.compile(r'^\s*define\s+"([^"\r\n]+)"')
_CONTROL_START = re.compile(r"^\s*(?:if|range|with|block)(?:\s|$)")
_CONTROL_END = re.compile(r"^\s*end(?:\s|$)")
_CONTROL_ELSE = re.compile(r"^\s*else(?:\s+if\s+(.+))?\s*$", re.DOTALL)
_VALUES_PATH = re.compile(r"^\.Values(?:\.([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*))?$")
_NAMESPACE_LINE = re.compile(r"^\s*namespace\s*:\s*(.*?)\s*$", re.MULTILINE)
_SOURCE_MARKER = re.compile(r"^# Source: ([^\r\n]+)$", re.MULTILINE)
_DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")
_DNS_SUBDOMAIN = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?")
_SET_KEY = re.compile(r"[A-Za-z0-9_.\[\]-]+")
_DEPENDENCY_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,252})")
_DEPENDENCY_VALUE_PATH = re.compile(
    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*"
)
_CLUSTER_SCOPED_GROUP_KINDS = frozenset({
    ("", "Namespace"),
    ("", "Node"),
    ("", "PersistentVolume"),
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

_NAMESPACED_GROUPS = frozenset({
    "",
    "apps",
    "autoscaling",
    "batch",
    "coordination.k8s.io",
    "discovery.k8s.io",
    "events.k8s.io",
    "extensions",
    "networking.k8s.io",
    "policy",
    "rbac.authorization.k8s.io",
    "storage.k8s.io",
})


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
class _ArchiveMember:
    path: str
    kind: str
    mode: int
    size: int
    sha256: str
    payload: bytes | None = field(default=None, repr=False)

    def evidence_dict(self) -> dict:
        result = {
            "path": self.path,
            "type": self.kind,
            "mode": self.mode,
            "size": self.size,
        }
        if self.kind == "file":
            result["sha256"] = self.sha256
        return result


@dataclass(frozen=True, slots=True)
class _ArchiveInspection:
    archive_sha256: str
    chart_root: str
    chart: dict
    chart_yaml_sha256: str
    members: tuple[_ArchiveMember, ...]
    member_manifest_root_sha256: str
    chart_member_subtree_root_sha256: str
    expanded_files: tuple[dict, ...]


@dataclass(slots=True)
class _DependencyArchiveBudget:
    members: int = 0
    expanded_bytes: int = 0

    def consume(self, *, members: int, expanded_bytes: int) -> None:
        self.members += members
        self.expanded_bytes += expanded_bytes
        if self.members > _MAX_ARCHIVE_MEMBERS:
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_LIMIT_EXCEEDED",
                "nested dependency archive closure has too many members",
            )
        if self.expanded_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_LIMIT_EXCEEDED",
                "nested dependency archive closure expands beyond its limit",
            )


@dataclass(frozen=True, slots=True)
class _TemplateActionScope:
    source_path: str
    actions: tuple[str, ...]
    definition_ordinal: int = 0
    definition_span_sha256: str = ""


@dataclass(frozen=True, slots=True)
class _TemplateActionIndex:
    roots: dict[str, _TemplateActionScope]
    definitions: dict[str, _TemplateActionScope]
    sources: dict[str, str]
    source_base_paths: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    source_template_names: dict[str, tuple[str, ...]] = field(default_factory=dict)
    source_chart_contexts: dict[str, str] = field(default_factory=dict)
    protected_files: dict[str, dict[str, "_ProtectedTplFile"]] = field(
        default_factory=dict
    )
    definition_members: dict[str, tuple[_TemplateActionScope, ...]] = field(
        default_factory=dict
    )
    definition_graphs: dict[str, tuple] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _ActionToken:
    text: str
    quoted: bool = False


@dataclass(frozen=True, slots=True)
class _TplArgument:
    content: str
    source_kind: str
    source_path: str
    protected_file: "_ProtectedTplFile | None" = None


@dataclass(frozen=True, slots=True)
class _ProtectedTplFile:
    content: bytes
    chart_context: str
    chart_identity: str
    chart_inventory_root_sha256: str
    protected_path: str
    relative_path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _ResolvedIncludeTarget:
    call_function: str
    expression_type: str
    operands: tuple[dict, ...]
    target_string: str
    target_kind: str
    target_identity: str
    target_scope: _TemplateActionScope
    target_source_sha256: str


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
    protected_repository_root: Path | None = None

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
        repository = self.protected_repository_root
        if repository is None:
            repository = chart
        if not isinstance(repository, Path):
            raise DomainError("Helm protected repository root must be pathlib.Path")
        try:
            repository = repository.resolve(strict=True)
            chart.relative_to(repository)
        except (OSError, ValueError) as exc:
            raise DomainError(
                "Helm chart root must be inside the protected repository root"
            ) from exc
        if not repository.is_dir():
            raise DomainError("Helm protected repository root must be a directory")
        object.__setattr__(self, "chart_root", chart)
        object.__setattr__(self, "helm_executable", executable)
        object.__setattr__(self, "protected_repository_root", repository)
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
    namespace_provenance: MappingProxyType

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
            "namespace_provenance": dict(self.namespace_provenance),
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


@dataclass(frozen=True, slots=True)
class HelmUniverseChart:
    universe_key: str
    specification: HelmRenderSpec

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "universe_key",
            _safe_dns(self.universe_key, "Helm universe chart key", namespace=True),
        )
        if type(self.specification) is not HelmRenderSpec:
            raise DomainError("Helm universe chart requires an exact render specification")


@dataclass(frozen=True, slots=True)
class HelmMaterializedUniverse:
    scanner_root: Path
    charts: tuple[tuple[str, HelmMaterializationEvidence], ...]
    combined_output: MappingProxyType
    resource_ownership: tuple[tuple[str, HelmRenderedDocument], ...]
    universe_identity: str

    def canonical_dict(self) -> dict:
        return {
            "contract": HELM_UNIVERSE_CONTRACT,
            "status": "PASS",
            "reason_code": "DETERMINISTIC_MULTI_CHART_UNIVERSE_BOUND",
            "charts": [
                {
                    "universe_key": key,
                    "materialization": evidence.canonical_dict(),
                }
                for key, evidence in self.charts
            ],
            "combined_output": dict(self.combined_output),
            "resource_ownership": [
                {"universe_key": key, "document": document.canonical_dict()}
                for key, document in self.resource_ownership
            ],
            "universe_identity": self.universe_identity,
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
    if alias and _DEPENDENCY_NAME.fullmatch(alias) is None:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_METADATA_INVALID", "dependency alias is invalid"
        )
    condition_paths = tuple(item.strip() for item in condition.split(",") if item.strip())
    if condition and (
        not condition_paths
        or any(_DEPENDENCY_VALUE_PATH.fullmatch(item) is None for item in condition_paths)
    ):
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_METADATA_INVALID", "dependency condition paths are invalid"
        )
    if type(tags) is not list or any(type(item) is not str for item in tags):
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "dependency tags are invalid"
        )
    if any(not item or _DEPENDENCY_NAME.fullmatch(item) is None for item in tags) or len(
        tags
    ) != len(set(tags)):
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_METADATA_INVALID", "dependency tags are invalid or duplicated"
        )
    if type(enabled) is not bool or type(imports) is not list:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "dependency options are invalid"
        )
    for item in imports:
        if type(item) is str:
            valid = bool(item and _DEPENDENCY_VALUE_PATH.fullmatch(item))
        elif type(item) is dict and set(item) == {"child", "parent"}:
            valid = all(
                type(item[key]) is str
                and bool(item[key])
                and _DEPENDENCY_VALUE_PATH.fullmatch(item[key]) is not None
                for key in ("child", "parent")
            )
        else:
            valid = False
        if not valid:
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_IMPORT_UNSUPPORTED",
                "dependency import-values entry is outside the closed grammar",
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


def _dependency_version_proof(declared: str, resolved: str) -> dict:
    """Prove one Chart.yaml constraint against one protected lock version."""
    try:
        evidence = prove_constraint(declared, resolved)
    except HelmSemverError as exc:
        reason = (
            "HELM_DEPENDENCY_RESOLVED_VERSION_INVALID"
            if exc.reason == "MALFORMED_RESOLVED_VERSION"
            else "HELM_DEPENDENCY_VERSION_CONSTRAINT_UNSUPPORTED"
        )
        raise HelmMaterializationError(reason, exc.detail) from exc
    if not evidence["satisfied"]:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_VERSION_CONSTRAINT_MISMATCH",
            "protected lock version does not satisfy the declared dependency constraint",
        )
    return evidence


def _bind_dependency_version_evidence(artifact: dict, evidence: dict) -> None:
    """Bind range proof to the independently established artifact identities."""
    body = dict(evidence)
    body["protected_lock_resolved_version"] = body.pop("resolved_version")
    body["dependency_chart_version"] = artifact["version"]
    body["physical_dependency_identity"] = artifact["physical_dependency"][
        "physical_dependency_identity"
    ]
    body["logical_instance_identity"] = artifact["logical_instance"][
        "logical_instance_identity"
    ]
    artifact["version_binding"] = {
        **body,
        "version_binding_identity": _canonical_sha(body),
    }


def _rebind_dependency_version_evidence(artifact: dict) -> None:
    binding = artifact.get("version_binding")
    if binding is None:
        return
    body = dict(binding)
    body.pop("version_binding_identity", None)
    body["physical_dependency_identity"] = artifact["physical_dependency"][
        "physical_dependency_identity"
    ]
    body["logical_instance_identity"] = artifact["logical_instance"][
        "logical_instance_identity"
    ]
    artifact["version_binding"] = {
        **body,
        "version_binding_identity": _canonical_sha(body),
    }


def _portable_archive_member_identity(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _inspect_archive_payload(
    archive_payload: bytes,
    expected_name: str,
    expected_version: str,
    *,
    budget: _DependencyArchiveBudget | None = None,
) -> _ArchiveInspection:
    expanded = 0
    expanded_files: list[dict] = []
    records: list[_ArchiveMember] = []
    portable_paths: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                raise HelmMaterializationError(
                    "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive has too many members"
                )
            chart_yaml: dict | None = None
            chart_yaml_sha256 = ""
            for member in members:
                pure = PurePosixPath(member.name)
                canonical = pure.as_posix()
                raw_without_directory_suffix = member.name.rstrip("/")
                if (
                    pure.is_absolute()
                    or ".." in pure.parts
                    or not pure.parts
                    or raw_without_directory_suffix != canonical
                    or member.issym()
                    or member.islnk()
                    or not (member.isfile() or member.isdir())
                ):
                    raise HelmMaterializationError(
                        "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive contains unsafe paths"
                    )
                portable = _portable_archive_member_identity(canonical)
                if portable in portable_paths:
                    raise HelmMaterializationError(
                        "UNSAFE_DEPENDENCY_ARCHIVE",
                        "dependency archive contains duplicate portable paths",
                    )
                portable_paths.add(portable)
                if pure.parts[0] != expected_name:
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
                    member_payload = stream.read()
                    if len(member_payload) != member.size:
                        raise HelmMaterializationError(
                            "UNSAFE_DEPENDENCY_ARCHIVE",
                            "dependency archive member has inconsistent bytes",
                        )
                    digest = _sha256(member_payload)
                    records.append(_ArchiveMember(
                        path=canonical,
                        kind="file",
                        mode=stat.S_IMODE(member.mode),
                        size=len(member_payload),
                        sha256=digest,
                        payload=member_payload,
                    ))
                    virtual = PurePosixPath("charts", expected_name, *pure.parts[1:])
                    expanded_files.append({
                        "path": canonical_repo_path(
                            virtual.as_posix(), "expanded Helm dependency file"
                        ),
                        "size": len(member_payload),
                        "mode": stat.S_IMODE(member.mode),
                        "sha256": digest,
                    })
                    if pure.name == "Chart.yaml" and len(pure.parts) == 2:
                        chart_yaml = yaml.load(member_payload, Loader=_StrictSafeLoader)
                        chart_yaml_sha256 = digest
                else:
                    records.append(_ArchiveMember(
                        path=canonical,
                        kind="directory",
                        mode=stat.S_IMODE(member.mode),
                        size=0,
                        sha256="",
                    ))
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
    if budget is not None:
        budget.consume(members=len(records), expanded_bytes=expanded)
    ordered = tuple(sorted(records, key=lambda item: item.path))
    member_manifest = [item.evidence_dict() for item in ordered]
    subtree = [
        {
            **item.evidence_dict(),
            "path": PurePosixPath(item.path).relative_to(expected_name).as_posix(),
        }
        for item in ordered
        if item.path != expected_name and item.path.startswith(f"{expected_name}/")
    ]
    return _ArchiveInspection(
        archive_sha256=_sha256(archive_payload),
        chart_root=expected_name,
        chart=chart_yaml,
        chart_yaml_sha256=chart_yaml_sha256,
        members=ordered,
        member_manifest_root_sha256=_canonical_sha(member_manifest),
        chart_member_subtree_root_sha256=_canonical_sha(subtree),
        expanded_files=tuple(sorted(expanded_files, key=lambda item: item["path"])),
    )


def _inspect_archive(
    path: Path,
    expected_name: str,
    expected_version: str,
    *,
    budget: _DependencyArchiveBudget | None = None,
) -> _ArchiveInspection:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise HelmMaterializationError(
            "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive cannot be safely inspected"
        ) from exc
    return _inspect_archive_payload(
        payload, expected_name, expected_version, budget=budget
    )


def _write_archive_inspection(
    inspection: _ArchiveInspection, destination: Path
) -> Path:
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for member in inspection.members:
        target = destination.joinpath(*PurePosixPath(member.path).parts)
        if member.kind == "directory":
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            continue
        if member.payload is None:
            raise HelmMaterializationError(
                "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive member bytes are unavailable"
            )
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            offset = 0
            while offset < len(member.payload):
                written = os.write(descriptor, member.payload[offset:])
                if written <= 0:
                    raise HelmMaterializationError(
                        "UNSAFE_DEPENDENCY_ARCHIVE",
                        "dependency archive member extraction did not complete",
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    root = destination / inspection.chart_root
    if not root.is_dir() or root.is_symlink():
        raise HelmMaterializationError(
            "UNSAFE_DEPENDENCY_ARCHIVE", "dependency archive chart root is malformed"
        )
    return root


def _dependency_path_value(values: dict, path: str) -> tuple[bool, object]:
    current: object = values
    for part in path.split("."):
        if type(current) is not dict or part not in current:
            return False, None
        current = current[part]
    return True, current


def _dependency_activation(record: dict, values: dict) -> dict:
    tag_inputs = []
    tag_result: bool | None = None
    if record.get("tags"):
        table = values.get("tags", {})
        if type(table) is not dict:
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS",
                "top-level dependency tags value is not a mapping",
            )
        states = []
        for tag in record["tags"]:
            state = table.get(tag, False)
            if type(state) is not bool:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS",
                    "dependency tag value is not Boolean",
                )
            states.append(state)
            tag_inputs.append({"tag": tag, "value": state})
        tag_result = any(states)
    condition_inputs = []
    condition_result: bool | None = None
    for path in tuple(
        item.strip() for item in record.get("condition", "").split(",") if item.strip()
    ):
        found, state = _dependency_path_value(values, path)
        condition_inputs.append({"path": path, "found": found,
                                 "value": state if type(state) is bool else None})
        if not found:
            continue
        if type(state) is not bool:
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS",
                "first existing dependency condition is not Boolean",
            )
        condition_result = state
        break
    result = (
        condition_result if condition_result is not None
        else tag_result if tag_result is not None
        else True
    )
    return {
        "condition_inputs": condition_inputs,
        "tag_inputs": tag_inputs,
        "declared_enabled_metadata": record.get("enabled", False),
        "result": result,
    }


def _local_dependency_source(
    declaring_root: Path, repository_root: Path, repository: str
) -> Path:
    if not repository.startswith("file://"):
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_REMOTE_RESOLUTION_REQUIRED",
            "dependency bytes are not locally available",
        )
    encoded = repository[len("file://"):]
    if not encoded or "?" in encoded or "#" in encoded:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_PATH_ESCAPE", "file dependency URI is invalid"
        )
    try:
        relative = urllib.parse.unquote(encoded, errors="strict")
    except (UnicodeError, ValueError) as exc:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_PATH_ESCAPE", "file dependency URI encoding is invalid"
        ) from exc
    pure = PurePosixPath(relative)
    if pure.is_absolute() or "\\" in relative or "\x00" in relative:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_PATH_ESCAPE", "file dependency path is not portable"
        )
    # Compare lexical containment only after both roots use the same canonical
    # filesystem spelling.  On macOS, temporary paths may otherwise mix the
    # equivalent /var and /private/var prefixes and reject a contained source.
    declaring_root = declaring_root.resolve(strict=True)
    repository_root = repository_root.resolve(strict=True)
    target = Path(os.path.normpath(str(declaring_root.joinpath(*pure.parts))))
    try:
        lexical = target.absolute().relative_to(repository_root)
    except ValueError as exc:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_PATH_ESCAPE", "file dependency escapes protected repository"
        ) from exc
    current = repository_root
    for part in lexical.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_ARTIFACT_MISSING",
                "file dependency input is unavailable",
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_SYMLINK", "file dependency traverses a symlink"
            )
    resolved = target.resolve(strict=True)
    try:
        resolved.relative_to(repository_root)
    except ValueError as exc:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_PATH_ESCAPE", "file dependency escapes protected repository"
        ) from exc
    return resolved


def _archive_provenance(
    inspection: _ArchiveInspection, repository_path: str
) -> dict:
    body = {
        "repository_path": canonical_repo_path(
            repository_path, "Helm dependency archive repository path"
        ),
        "archive_sha256": inspection.archive_sha256,
        "archive_member_manifest_root_sha256": (
            inspection.member_manifest_root_sha256
        ),
        "chart_member_path": inspection.chart_root,
        "chart_yaml_sha256": inspection.chart_yaml_sha256,
        "chart_member_subtree_root_sha256": (
            inspection.chart_member_subtree_root_sha256
        ),
    }
    return {**body, "provenance_identity": _canonical_sha(body)}


def _archive_member_records(
    inspection: _ArchiveInspection, member_path: str
) -> list[dict]:
    prefix = f"{member_path}/"
    result = []
    for member in inspection.members:
        if member.path == member_path:
            relative = "."
        elif member.path.startswith(prefix):
            relative = member.path[len(prefix):]
        else:
            continue
        record = member.evidence_dict()
        record["path"] = relative
        result.append(record)
    return sorted(result, key=lambda item: item["path"])


def _archive_member_provenance(
    inspection: _ArchiveInspection,
    *,
    artifact_member_path: str,
    chart_member_path: str,
    chart_yaml_sha256: str,
    parent_dependency_identity: str,
) -> dict:
    records = _archive_member_records(inspection, artifact_member_path)
    if not records:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
            "nested dependency member subtree is unavailable",
        )
    body = {
        "outer_archive_sha256": inspection.archive_sha256,
        "outer_archive_member_manifest_root_sha256": (
            inspection.member_manifest_root_sha256
        ),
        "artifact_member_path": canonical_repo_path(
            artifact_member_path, "nested Helm dependency member path"
        ),
        "chart_member_path": canonical_repo_path(
            chart_member_path, "nested Helm dependency chart member path"
        ),
        "chart_yaml_sha256": chart_yaml_sha256,
        "member_subtree_root_sha256": _canonical_sha(records),
        "parent_dependency_identity": parent_dependency_identity,
    }
    return {**body, "provenance_identity": _canonical_sha(body)}


def _dependency_artifact_root(artifact: dict, source_path: Path | None = None) -> str:
    if artifact["form"] in {"directory", "local-directory"}:
        if source_path is None:
            return artifact["physical_root_sha256"]
        _records, identity = _inventory(source_path)
        return identity
    if artifact["form"] == "archive-member-directory":
        return artifact["physical_root_sha256"]
    return artifact["sha256"]


def _attach_dependency_identity(
    artifact: dict,
    *,
    record: dict,
    repository: str,
    parent_instance: str,
    ordinal: int,
    effective_name: str,
    logical_prefix: str,
    activation: dict,
    protected_values: dict | None,
    source_path: Path | None,
) -> None:
    imports = list(record.get("import-values", []))
    physical = {
        "declared_name": artifact["name"],
        "resolved_version": artifact["version"],
        "repository": repository,
        "artifact_kind": artifact["form"],
        "protected_artifact_root_sha256": _dependency_artifact_root(
            artifact, source_path
        ),
    }
    physical_identity = _canonical_sha(physical)
    artifact["physical_dependency"] = {
        **physical, "physical_dependency_identity": physical_identity,
    }
    effective_values = (
        protected_values.get(effective_name, {})
        if protected_values is not None else {}
    )
    global_values = (
        protected_values.get("global", {})
        if protected_values is not None else {}
    )
    if type(effective_values) is not dict or type(global_values) is not dict:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS",
            "logical dependency Values roots must be mappings",
        )
    logical = {
        "parent_instance": parent_instance,
        "ordinal": ordinal,
        "effective_name": effective_name,
        "declared_name": artifact["name"],
        "physical_dependency_identity": physical_identity,
        "activation_metadata_sha256": _canonical_sha(activation),
        "import_metadata_sha256": _canonical_sha(imports),
        "effective_values_root_sha256": _canonical_sha(effective_values),
        "global_values_sha256": _canonical_sha(global_values),
        "source_marker_context": (
            f"{logical_prefix}/charts/{effective_name}"
            if logical_prefix else f"charts/{effective_name}"
        ),
    }
    logical["logical_instance_identity"] = _canonical_sha(logical)
    artifact["activation"] = activation
    artifact["imports"] = imports
    artifact["logical_instance"] = logical


def _rebind_dependency_identity(artifact: dict, parent_instance: str) -> str:
    physical = dict(artifact["physical_dependency"])
    physical.pop("physical_dependency_identity", None)
    physical["artifact_kind"] = artifact["form"]
    if (
        artifact["form"] == "directory"
        and "physical_root_sha256" not in artifact
    ):
        # The already-bound vendored directory root remains the same while only
        # its logical/effective Values identity is being rebound.
        pass
    else:
        physical["protected_artifact_root_sha256"] = _dependency_artifact_root(
            artifact
        )
    physical_identity = _canonical_sha(physical)
    artifact["physical_dependency"] = {
        **physical, "physical_dependency_identity": physical_identity,
    }
    logical = dict(artifact["logical_instance"])
    logical.pop("logical_instance_identity", None)
    logical["parent_instance"] = parent_instance
    logical["physical_dependency_identity"] = physical_identity
    logical_identity = _canonical_sha(logical)
    artifact["logical_instance"] = {
        **logical, "logical_instance_identity": logical_identity,
    }
    values_provenance = artifact.get("values_provenance")
    if values_provenance is not None:
        values_body = dict(values_provenance)
        values_body.pop("provenance_identity", None)
        values_body["logical_instance_identity"] = logical_identity
        artifact["values_provenance"] = {
            **values_body, "provenance_identity": _canonical_sha(values_body),
        }
    _rebind_dependency_version_evidence(artifact)
    return logical_identity


def _reparent_dependency_closure(closure: dict, parent_instance: str) -> None:
    for artifact in closure["artifacts"]:
        logical = artifact.get("logical_instance")
        identity = (
            _rebind_dependency_identity(artifact, parent_instance)
            if logical is not None else parent_instance
        )
        member = artifact.get("archive_member_provenance")
        if member is not None and logical is not None:
            body = dict(member)
            body.pop("provenance_identity", None)
            body["parent_dependency_identity"] = parent_instance
            artifact["archive_member_provenance"] = {
                **body, "provenance_identity": _canonical_sha(body),
            }
        nested = artifact.get("dependencies")
        if nested is not None:
            _reparent_dependency_closure(nested, identity)


def _bind_archive_member_closure(
    closure: dict,
    inspection: _ArchiveInspection,
    *,
    physical_prefix: str,
    parent_instance: str,
) -> None:
    for artifact in closure["artifacts"]:
        original_form = artifact["form"]
        if original_form in {"local-directory", "local-archive"}:
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                "nested archive dependency escapes the local charts closure",
            )
        if original_form == "directory":
            artifact_member_path = f"{physical_prefix}/charts/{artifact['name']}"
            chart_member_path = artifact_member_path
            chart_record = next((
                member for member in inspection.members
                if member.path == f"{chart_member_path}/Chart.yaml"
            ), None)
            if chart_record is None:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested directory dependency Chart.yaml is unavailable",
                )
            physical_files = []
            prefix = f"{chart_member_path}/"
            for member in inspection.members:
                if member.kind != "file" or not member.path.startswith(prefix):
                    continue
                physical_files.append({
                    "path": member.path[len(prefix):],
                    "size": member.size,
                    "mode": member.mode,
                    "sha256": member.sha256,
                })
            physical_files.sort(key=lambda item: item["path"])
            if not physical_files:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested directory dependency member subtree is empty",
                )
            artifact["physical_files"] = physical_files
            artifact["physical_root_sha256"] = _canonical_sha(physical_files)
            artifact["form"] = "archive-member-directory"
            artifact["archive_member_provenance"] = _archive_member_provenance(
                inspection,
                artifact_member_path=artifact_member_path,
                chart_member_path=chart_member_path,
                chart_yaml_sha256=chart_record.sha256,
                parent_dependency_identity=parent_instance,
            )
            identity = _rebind_dependency_identity(artifact, parent_instance)
            nested = artifact.get("dependencies")
            if nested is not None:
                _bind_archive_member_closure(
                    nested,
                    inspection,
                    physical_prefix=chart_member_path,
                    parent_instance=identity,
                )
            continue
        if original_form == "archive":
            artifact_member_path = (
                f"{physical_prefix}/charts/"
                f"{artifact['name']}-{artifact['version']}.tgz"
            )
            archive_record = next((
                member for member in inspection.members
                if member.path == artifact_member_path and member.kind == "file"
            ), None)
            if archive_record is None:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested archive dependency bytes are unavailable",
                )
            inner = artifact.get("archive_provenance")
            if inner is None:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested archive dependency provenance is unavailable",
                )
            inner_body = dict(inner)
            inner_body.pop("provenance_identity", None)
            inner_body["repository_path"] = artifact_member_path
            artifact["archive_provenance"] = {
                **inner_body, "provenance_identity": _canonical_sha(inner_body),
            }
            artifact["form"] = "archive-member-archive"
            artifact["archive_member_provenance"] = _archive_member_provenance(
                inspection,
                artifact_member_path=artifact_member_path,
                chart_member_path=inner["chart_member_path"],
                chart_yaml_sha256=inner["chart_yaml_sha256"],
                parent_dependency_identity=parent_instance,
            )
            identity = _rebind_dependency_identity(artifact, parent_instance)
            nested = artifact.get("dependencies")
            if nested is not None:
                _reparent_dependency_closure(nested, identity)
            continue
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
            "nested archive dependency has an unsupported physical form",
        )


def _validate_dependencies(
    root: Path,
    chart: dict,
    protected_values: dict | None = None,
    *,
    repository_root: Path | None = None,
    parent_instance: str = ".",
    logical_prefix: str = "",
    depth: int = 0,
    ancestry: tuple[Path, ...] = (),
    archive_ancestry: tuple[str, ...] = (),
    archive_budget: _DependencyArchiveBudget | None = None,
    force_dependency_identities: bool = False,
) -> dict:
    repository_root = (repository_root or root).resolve(strict=True)
    archive_budget = archive_budget or _DependencyArchiveBudget()
    if depth > _MAX_TEMPLATE_CALL_DEPTH:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_LIMIT_EXCEEDED", "dependency closure exceeds depth limit"
        )
    physical_root = root.resolve(strict=True)
    if physical_root in ancestry:
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
            "local dependency closure contains a cycle",
        )
    ancestry = (*ancestry, physical_root)
    raw_dependencies = chart.get("dependencies", [])
    if raw_dependencies is None:
        raw_dependencies = []
    if type(raw_dependencies) is not list:
        raise HelmMaterializationError(
            "UNREPRODUCIBLE_DEPENDENCIES", "Chart.yaml dependencies must be a list"
        )
    dependencies = tuple(_dependency_key(item) for item in raw_dependencies)
    effective_names = tuple(
        item.get("alias") or item.get("name")
        for item in raw_dependencies if type(item) is dict
    )
    if len(effective_names) != len(raw_dependencies) or any(
        type(item) is not str or not item for item in effective_names
    ):
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_METADATA_INVALID", "dependency effective name is invalid"
        )
    if len(effective_names) != len(set(effective_names)):
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_EFFECTIVE_NAME_COLLISION",
            "dependency logical instances have a duplicate effective name",
        )
    logical_keys = tuple(
        (*_dependency_key(item), effective_names[index])
        for index, item in enumerate(raw_dependencies)
    )
    if len(logical_keys) != len(set(logical_keys)):
        raise HelmMaterializationError(
            "HELM_DEPENDENCY_EFFECTIVE_NAME_COLLISION",
            "Chart.yaml contains duplicate logical dependencies",
        )
    lock_path = root / "Chart.lock"
    lock_hash = ""
    resolved_dependencies = dependencies
    version_proofs: tuple[dict | None, ...] = (None,) * len(dependencies)
    charts = root / "charts"
    chart_entries = (
        tuple(sorted(charts.iterdir(), key=lambda item: item.name))
        if charts.is_dir()
        else ()
    )
    dependency_state_relevant = bool(dependencies or chart_entries)
    lock_relevance = "ABSENT"
    if lock_path.exists() and not dependency_state_relevant:
        # Chart.lock is part of the protected chart byte inventory even when Helm has
        # no dependency graph to lock.  Parsing an otherwise irrelevant stray file
        # would manufacture a dependency contract that Chart.yaml and charts/ do not
        # contain.
        if lock_path.is_symlink() or not lock_path.is_file():
            raise HelmMaterializationError(
                "CHART_PATH_ESCAPE", "Chart.lock must be a regular chart file"
            )
        lock_hash = _sha256(lock_path.read_bytes())
        lock_relevance = "NON_PARTICIPATING"
    elif lock_path.exists():
        lock = _strict_yaml(lock_path, "Chart.lock")
        locked = lock.get("dependencies", [])
        if type(locked) is not list or len(locked) != len(dependencies):
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES", "Chart.lock does not match Chart.yaml"
            )
        locked_dependencies = tuple(_dependency_key(item) for item in locked)
        proofs: list[dict | None] = []
        for declared_key, locked_key in zip(
            dependencies, locked_dependencies, strict=True
        ):
            declared_name, declared_version, declared_repository = declared_key
            locked_name, locked_version, locked_repository = locked_key
            if (
                locked_name != declared_name
                or locked_repository != declared_repository
            ):
                raise HelmMaterializationError(
                    "UNREPRODUCIBLE_DEPENDENCIES",
                    "Chart.lock dependency name or repository does not match Chart.yaml",
                )
            proof = (
                _dependency_version_proof(declared_version, locked_version)
                if declared_version != locked_version else None
            )
            proofs.append(proof)
        resolved_dependencies = locked_dependencies
        version_proofs = tuple(proofs)
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
        lock_relevance = "PARTICIPATING"
    artifacts = []
    for ordinal, (name, version, repository) in enumerate(resolved_dependencies):
        record = _dependency_record(raw_dependencies[ordinal])
        effective_name = effective_names[ordinal]
        directory = charts / name
        archive = charts / f"{name}-{version}.tgz"
        source_path: Path | None = None
        archive_inspection: _ArchiveInspection | None = None
        archive_repository_path = ""
        if directory.is_dir() and not directory.is_symlink():
            source_path = directory.resolve(strict=True)
            child = _strict_yaml(directory / "Chart.yaml", "vendored subchart Chart.yaml")
            if child.get("name") != name or str(child.get("version")) != version:
                raise HelmMaterializationError(
                    "UNREPRODUCIBLE_DEPENDENCIES", "vendored subchart identity is inconsistent"
                )
            artifact = {
                "name": name,
                "version": version,
                "form": "directory",
                "expanded_files": [],
            }
        elif archive.is_file() and not archive.is_symlink():
            archive_inspection = _inspect_archive(
                archive, name, version, budget=archive_budget
            )
            if archive_inspection.archive_sha256 in archive_ancestry:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested dependency archive closure contains a repeated identity",
                )
            archive_repository_path = canonical_repo_path(
                archive.resolve(strict=True).relative_to(repository_root).as_posix(),
                "Helm dependency archive repository path",
            )
            artifact = {
                "name": name,
                "version": version,
                "form": "archive",
                "sha256": archive_inspection.archive_sha256,
                "expanded_files": list(archive_inspection.expanded_files),
            }
        else:
            if not repository.startswith("file://"):
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_REMOTE_RESOLUTION_REQUIRED",
                    "declared dependency is not locally vendored",
                )
            source_path = _local_dependency_source(root, repository_root, repository)
            if source_path.is_dir():
                child = _strict_yaml(source_path / "Chart.yaml", "local dependency Chart.yaml")
                if child.get("name") != name or str(child.get("version")) != version:
                    raise HelmMaterializationError(
                        "HELM_DEPENDENCY_ARTIFACT_IDENTITY_MISMATCH",
                        "local dependency identity is inconsistent",
                    )
                source_inventory, source_root = _inventory(source_path)
                artifact = {
                    "name": name, "version": version, "form": "local-directory",
                    "source_repository_path": source_path.relative_to(
                        repository_root
                    ).as_posix(),
                    "physical_root_sha256": source_root,
                    "physical_files": [item.canonical_dict() for item in source_inventory],
                    "expanded_files": [],
                }
            elif source_path.is_file() and source_path.suffix == ".tgz":
                archive_inspection = _inspect_archive(
                    source_path, name, version, budget=archive_budget
                )
                if archive_inspection.archive_sha256 in archive_ancestry:
                    raise HelmMaterializationError(
                        "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                        "nested dependency archive closure contains a repeated identity",
                    )
                archive_repository_path = canonical_repo_path(
                    source_path.relative_to(repository_root).as_posix(),
                    "Helm dependency archive repository path",
                )
                artifact = {
                    "name": name, "version": version, "form": "local-archive",
                    "source_repository_path": archive_repository_path,
                    "sha256": archive_inspection.archive_sha256,
                    "expanded_files": list(archive_inspection.expanded_files),
                }
                # Archive members are represented by the protected expanded-file
                # inventory above.  They are not a directory that may be traversed
                # through the host filesystem for nested closure processing.
                source_path = None
            else:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_ARTIFACT_MISSING",
                    "file dependency is not a supported directory or archive",
                )
        if not repository.startswith("file://") and not lock_path.exists():
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES",
                "non-local dependency requires a lock and vendored bytes",
            )
        activation = (
            _dependency_activation(record, protected_values)
            if protected_values is not None else {
                "condition": record.get("condition", ""),
                "tags": list(record.get("tags", [])),
                "enabled": record.get("enabled", False),
            }
        )
        archive_has_nested_closure = bool(
            archive_inspection is not None and (
                archive_inspection.chart.get("dependencies")
                or any(
                    member.path.startswith(
                        f"{archive_inspection.chart_root}/charts/"
                    )
                    for member in archive_inspection.members
                )
            )
        )
        identity_required = bool(
            effective_name != name
            or force_dependency_identities
            or archive_has_nested_closure
            or version_proofs[ordinal] is not None
        )
        if any((
            effective_name != name,
            force_dependency_identities,
            archive_has_nested_closure,
            bool(record.get("condition")),
            bool(record.get("tags")),
            bool(record.get("enabled")),
            bool(record.get("import-values")),
        )):
            artifact["activation"] = activation
            artifact["imports"] = list(record.get("import-values", []))
        if identity_required:
            _attach_dependency_identity(
                artifact,
                record=record,
                repository=repository,
                parent_instance=parent_instance,
                ordinal=ordinal,
                effective_name=effective_name,
                logical_prefix=logical_prefix,
                activation=activation,
                protected_values=protected_values,
                source_path=source_path,
            )
            if version_proofs[ordinal] is not None:
                _bind_dependency_version_evidence(
                    artifact, version_proofs[ordinal]
                )
        if archive_inspection is not None and (
            archive_has_nested_closure or force_dependency_identities
        ):
            artifact["archive_provenance"] = _archive_provenance(
                archive_inspection, archive_repository_path
            )
        context = (
            f"{logical_prefix}/charts/{effective_name}"
            if logical_prefix else f"charts/{effective_name}"
        )
        if effective_name != name or logical_prefix:
            artifact["logical_context"] = context
        if archive_inspection is not None and archive_has_nested_closure:
            child_values = {}
            values_member = next((
                member for member in archive_inspection.members
                if member.path == f"{archive_inspection.chart_root}/values.yaml"
                and member.kind == "file"
            ), None)
            if values_member is not None and values_member.payload is not None:
                try:
                    loaded_values = yaml.load(
                        values_member.payload, Loader=_StrictSafeLoader
                    )
                except yaml.YAMLError as exc:
                    raise HelmMaterializationError(
                        "UNREPRODUCIBLE_DEPENDENCIES",
                        "dependency archive values are malformed",
                    ) from exc
                if loaded_values is not None and type(loaded_values) is not dict:
                    raise HelmMaterializationError(
                        "UNREPRODUCIBLE_DEPENDENCIES",
                        "dependency archive values must be a mapping",
                    )
                child_values = loaded_values or {}
            if protected_values is not None:
                parent_override = protected_values.get(effective_name, {})
                if type(parent_override) is not dict:
                    raise HelmMaterializationError(
                        "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS",
                        "dependency Values root is not a mapping",
                    )
                child_values = _merge_values(child_values, parent_override)
                globals_value = protected_values.get("global")
                if globals_value is not None:
                    if type(globals_value) is not dict:
                        raise HelmMaterializationError(
                            "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS",
                            "global dependency Values root is not a mapping",
                        )
                    child_values["global"] = _merge_values(
                        child_values.get("global", {})
                        if type(child_values.get("global", {})) is dict else {},
                        globals_value,
                    )
            with tempfile.TemporaryDirectory(
                prefix="iacgv-helm-archive-closure-"
            ) as temporary:
                extracted = _write_archive_inspection(
                    archive_inspection, Path(temporary)
                )
                nested = _validate_dependencies(
                    extracted,
                    archive_inspection.chart,
                    child_values,
                    repository_root=extracted,
                    parent_instance=artifact["logical_instance"][
                        "logical_instance_identity"
                    ],
                    logical_prefix=context,
                    depth=depth + 1,
                    ancestry=ancestry,
                    archive_ancestry=(
                        *archive_ancestry, archive_inspection.archive_sha256
                    ),
                    archive_budget=archive_budget,
                    force_dependency_identities=True,
                )
            if nested["artifacts"]:
                _bind_archive_member_closure(
                    nested,
                    archive_inspection,
                    physical_prefix=archive_inspection.chart_root,
                    parent_instance=artifact["logical_instance"][
                        "logical_instance_identity"
                    ],
                )
                artifact["dependencies"] = nested
        elif source_path is not None:
            child_chart = _strict_yaml(source_path / "Chart.yaml", "dependency Chart.yaml")
            child_values = {}
            child_default = source_path / "values.yaml"
            if child_default.is_file() and not child_default.is_symlink():
                child_values = _load_values_file(child_default)
            if protected_values is not None:
                parent_override = protected_values.get(effective_name, {})
                if type(parent_override) is not dict:
                    raise HelmMaterializationError(
                        "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS",
                        "dependency Values root is not a mapping",
                    )
                child_values = _merge_values(child_values, parent_override)
                globals_value = protected_values.get("global")
                if globals_value is not None:
                    if type(globals_value) is not dict:
                        raise HelmMaterializationError(
                            "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS",
                            "global dependency Values root is not a mapping",
                        )
                    child_values["global"] = _merge_values(
                        child_values.get("global", {})
                        if type(child_values.get("global", {})) is dict else {},
                        globals_value,
                    )
            nested = _validate_dependencies(
                source_path, child_chart, child_values,
                repository_root=repository_root,
                parent_instance=(
                    artifact.get("logical_instance", {}).get(
                        "logical_instance_identity", context
                    )
                ),
                logical_prefix=context,
                depth=depth + 1,
                ancestry=ancestry,
                archive_ancestry=archive_ancestry,
                archive_budget=archive_budget,
                force_dependency_identities=force_dependency_identities,
            )
            if nested["artifacts"]:
                artifact["dependencies"] = nested
        artifacts.append(artifact)
    declared_entries = {
        value
        for name, version, _repository in resolved_dependencies
        for value in (name, f"{name}-{version}.tgz")
    }
    for entry in chart_entries:
        if entry.name in declared_entries:
            continue
        if entry.is_symlink():
            raise HelmMaterializationError(
                "CHART_PATH_ESCAPE", "dependency symlinks are not supported"
            )
        if entry.is_file():
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES",
                "undeclared dependency archives are not source-bound",
            )
        if not entry.is_dir():
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES",
                "dependency content has an unsupported path type",
            )
        child = _strict_yaml(entry / "Chart.yaml", "manually managed subchart Chart.yaml")
        child_name = child.get("name")
        child_version = child.get("version")
        if (
            type(child_name) is not str
            or child_name != entry.name
            or type(child_version) not in (str, int, float)
        ):
            raise HelmMaterializationError(
                "UNREPRODUCIBLE_DEPENDENCIES",
                "manually managed subchart identity is inconsistent",
            )
        artifact = {
            "name": child_name,
            "version": str(child_version),
            "form": "directory",
            "expanded_files": [],
        }
        if depth or logical_prefix:
            artifact["logical_context"] = (
                f"{logical_prefix}/charts/{child_name}"
                if logical_prefix else f"charts/{child_name}"
            )
        artifacts.append(artifact)
    return {
        "count": len(artifacts),
        "chart_lock_sha256": lock_hash,
        "chart_lock_relevance": lock_relevance,
        "artifacts": artifacts,
    }


def _inactive_dependency_contexts(dependencies: dict) -> tuple[str, ...]:
    result = []
    for artifact in dependencies["artifacts"]:
        context = artifact.get("logical_context") or f"charts/{artifact['name']}"
        if artifact.get("activation", {}).get("result") is False:
            result.append(context)
        nested = artifact.get("dependencies")
        if nested is not None:
            result.extend(_inactive_dependency_contexts(nested))
    return tuple(sorted(result))


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


def _iter_template_actions(text: str) -> tuple[str, ...]:
    """Return Go-template actions without treating delimiters in strings as syntax."""
    result: list[str] = []
    cursor = 0
    while True:
        start = text.find("{{", cursor)
        if start < 0:
            return tuple(result)
        index = start + 2
        if index < len(text) and text[index] == "-":
            index += 1
        content_start = index
        comment_start = index
        while comment_start < len(text) and text[comment_start].isspace():
            comment_start += 1
        if text.startswith("/*", comment_start):
            comment_end = text.find("*/", comment_start + 2)
            if comment_end < 0:
                raise HelmMaterializationError(
                    "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
                    "Helm template comment is not closed",
                )
            closing_start = comment_end + 2
            while closing_start < len(text) and text[closing_start].isspace():
                closing_start += 1
            if text.startswith("-}}", closing_start):
                closing = 3
            elif text.startswith("}}", closing_start):
                closing = 2
            else:
                raise HelmMaterializationError(
                    "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
                    "Helm template comment has an ambiguous closing delimiter",
                )
            result.append(text[content_start:comment_end + 2].strip())
            cursor = closing_start + closing
            continue
        quote = ""
        escaped = False
        while index < len(text):
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif quote == '"' and char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                index += 1
                continue
            if char in ('"', "'", "`"):
                quote = char
                index += 1
                continue
            if text.startswith("}}", index) or text.startswith("-}}", index):
                end = index
                closing = 3 if text.startswith("-}}", index) else 2
                result.append(text[content_start:end].strip())
                cursor = index + closing
                break
            index += 1
        else:
            raise HelmMaterializationError(
                "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
                "Helm template action delimiter is not closed",
            )


def _action_tokens(action: str) -> tuple[_ActionToken, ...] | None:
    tokens: list[_ActionToken] = []
    index = 0
    while index < len(action):
        if action[index].isspace():
            index += 1
            continue
        if action[index] in "()|":
            tokens.append(_ActionToken(action[index]))
            index += 1
            continue
        if action[index] in ('"', "'", "`"):
            quote = action[index]
            start = index
            index += 1
            escaped = False
            value: list[str] = []
            while index < len(action):
                char = action[index]
                if escaped:
                    value.append(char)
                    escaped = False
                elif quote == '"' and char == "\\":
                    escaped = True
                elif char == quote:
                    break
                else:
                    value.append(char)
                index += 1
            if index >= len(action) or action[index] != quote:
                return None
            raw_value = "".join(value)
            if quote == '"':
                try:
                    decoded = json.loads(action[start:index + 1])
                except (TypeError, ValueError, json.JSONDecodeError):
                    return None
                if type(decoded) is not str:
                    return None
                raw_value = decoded
            elif quote == "'":
                # Go templates do not define single-quoted string literals.
                return None
            tokens.append(_ActionToken(raw_value, quoted=True))
            index += 1
            continue
        start = index
        while (
            index < len(action)
            and not action[index].isspace()
            and action[index] not in "()|"
        ):
            index += 1
        tokens.append(_ActionToken(action[start:index]))
    return tuple(tokens)


def _template_nodes(text: str) -> tuple[tuple, ...]:
    """Parse output-sensitive template nodes for duplicate-definition equality."""
    nodes: list[tuple] = []
    cursor = 0
    trim_next = False
    while cursor < len(text):
        start = text.find("{{", cursor)
        if start < 0:
            fragment = text[cursor:]
            if trim_next:
                fragment = fragment.lstrip()
            if fragment:
                nodes.append(("text", fragment))
            break
        fragment = text[cursor:start]
        left_trim = text.startswith("{{-", start)
        if trim_next:
            fragment = fragment.lstrip()
        if left_trim:
            fragment = fragment.rstrip()
        if fragment:
            nodes.append(("text", fragment))
        probe = start + (3 if left_trim else 2)
        comment_probe = probe
        while comment_probe < len(text) and text[comment_probe].isspace():
            comment_probe += 1
        if text.startswith("/*", comment_probe):
            comment_end = text.find("*/", comment_probe + 2)
            if comment_end < 0:
                raise HelmMaterializationError(
                    "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
                    "Helm template comment is not closed",
                )
            closing = comment_end + 2
            while closing < len(text) and text[closing].isspace():
                closing += 1
            if text.startswith("-}}", closing):
                right_trim = True
                cursor = closing + 3
            elif text.startswith("}}", closing):
                right_trim = False
                cursor = closing + 2
            else:
                raise HelmMaterializationError(
                    "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
                    "Helm template comment closing is ambiguous",
                )
            trim_next = right_trim
            continue
        quote = ""
        escaped = False
        while probe < len(text):
            char = text[probe]
            if quote:
                if escaped:
                    escaped = False
                elif quote == '"' and char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                probe += 1
                continue
            if char in ('"', "'", "`"):
                quote = char
                probe += 1
                continue
            if text.startswith("-}}", probe) or text.startswith("}}", probe):
                right_trim = text.startswith("-}}", probe)
                content_start = start + (3 if left_trim else 2)
                action = text[content_start:probe].strip()
                tokens = _action_tokens(action)
                if tokens is None:
                    raise HelmMaterializationError(
                        "HELM_TEMPLATE_DEFINITION_PARSE_FAILED",
                        "named template action cannot be tokenized",
                    )
                if not _TEMPLATE_COMMENT.fullmatch(action):
                    nodes.append((
                        "action", left_trim, right_trim,
                        tuple((item.text, item.quoted) for item in tokens),
                    ))
                cursor = probe + (3 if right_trim else 2)
                trim_next = right_trim
                break
            probe += 1
        else:
            raise HelmMaterializationError(
                "HELM_TEMPLATE_DEFINITION_PARSE_FAILED",
                "named template action is not closed",
            )
    return tuple(nodes)


def _definition_graphs(text: str) -> dict[str, tuple]:
    nodes = _template_nodes(text)
    result: dict[str, tuple] = {}
    current: str | None = None
    body: list[tuple] = []
    depth = 0
    for node in nodes:
        if node[0] != "action":
            if current is not None:
                body.append(node)
            continue
        tokens = node[3]
        action = " ".join(
            json.dumps(value) if quoted else value for value, quoted in tokens
        )
        definition = _DEFINE_ACTION.match(action)
        if definition is not None:
            if current is not None:
                raise HelmMaterializationError(
                    "HELM_TEMPLATE_DEFINITION_PARSE_FAILED",
                    "named template definitions cannot be nested",
                )
            current = definition.group(1)
            body = []
            depth = 1
            continue
        if current is None:
            continue
        code = _unquoted_action(action)
        if _CONTROL_START.match(code):
            depth += 1
        if _CONTROL_END.match(code):
            depth -= 1
            if depth == 0:
                graph = tuple(body)
                prior = result.get(current)
                if prior is not None and prior != graph:
                    raise HelmMaterializationError(
                        "HELM_TEMPLATE_DUPLICATE_NON_EQUIVALENT",
                        "one source contains non-equivalent duplicate definitions",
                    )
                result[current] = graph
                current = None
                body = []
                continue
        body.append(node)
    if current is not None:
        raise HelmMaterializationError(
            "HELM_TEMPLATE_DEFINITION_PARSE_FAILED", "named template is not closed"
        )
    return result


def _matching_parenthesis(tokens: tuple[_ActionToken, ...], start: int) -> int | None:
    if start >= len(tokens) or tokens[start].text != "(":
        return None
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].text == "(":
            depth += 1
        elif tokens[index].text == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _helm_glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile the filepath.Match subset used by Helm's .helmignore rules."""
    output = ["^"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            output.append("[^/]*")
        elif char == "?":
            output.append("[^/]")
        elif char == "[":
            end = pattern.find("]", index + 1)
            if end < 0:
                raise HelmMaterializationError(
                    "CHART_INVENTORY_UNAVAILABLE", ".helmignore has an invalid pattern"
                )
            body = pattern[index + 1:end]
            if not body:
                raise HelmMaterializationError(
                    "CHART_INVENTORY_UNAVAILABLE", ".helmignore has an invalid pattern"
                )
            if body[0] in {"!", "^"}:
                body = "^" + body[1:]
            output.append("[" + body.replace("\\", "\\\\") + "]")
            index = end
        elif char == "\\":
            index += 1
            if index >= len(pattern):
                raise HelmMaterializationError(
                    "CHART_INVENTORY_UNAVAILABLE", ".helmignore has an invalid pattern"
                )
            output.append(re.escape(pattern[index]))
        else:
            output.append(re.escape(char))
        index += 1
    output.append("$")
    try:
        return re.compile("".join(output))
    except re.error as exc:
        raise HelmMaterializationError(
            "CHART_INVENTORY_UNAVAILABLE", ".helmignore has an invalid pattern"
        ) from exc


def _helmignore_rules(chart_root: Path) -> tuple[tuple[re.Pattern[str], bool, bool], ...]:
    path = chart_root / ".helmignore"
    if not path.exists():
        return ()
    if path.is_symlink() or not path.is_file():
        raise HelmMaterializationError(
            "CHART_PATH_ESCAPE", ".helmignore must be a regular chart file"
        )
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        raise HelmMaterializationError(
            "CHART_INVENTORY_UNAVAILABLE", ".helmignore is not valid UTF-8"
        ) from exc
    result = []
    for raw in lines:
        rule = raw.strip()
        if not rule or rule.startswith("#"):
            continue
        if "**" in rule:
            raise HelmMaterializationError(
                "CHART_INVENTORY_UNAVAILABLE", ".helmignore double-star is unsupported by Helm"
            )
        negate = rule.startswith("!")
        if negate:
            rule = rule[1:]
        must_dir = rule.endswith("/")
        if must_dir:
            rule = rule[:-1]
        anchored = rule.startswith("/")
        if anchored:
            rule = rule[1:]
        if not rule:
            raise HelmMaterializationError(
                "CHART_INVENTORY_UNAVAILABLE", ".helmignore has an invalid pattern"
            )
        match_pattern = rule if anchored or "/" in rule else f"__BASENAME__/{rule}"
        result.append((_helm_glob_regex(match_pattern), negate, must_dir))
    return tuple(result)


def _helmignore_matches(
    relative: str,
    *,
    is_dir: bool,
    rules: tuple[tuple[re.Pattern[str], bool, bool], ...],
) -> bool:
    for pattern, negate, must_dir in rules:
        candidate = (
            f"__BASENAME__/{PurePosixPath(relative).name}"
            if pattern.pattern.startswith("^__BASENAME__/")
            else relative
        )
        matched = pattern.fullmatch(candidate) is not None
        # This deliberately mirrors Helm v3's first-match and negative-rule
        # behavior rather than importing gitignore semantics.
        if negate:
            if must_dir and not is_dir:
                return True
            if not matched:
                return True
            continue
        if must_dir and not is_dir:
            continue
        if matched:
            return True
    return False


def _chart_file_is_ignored(chart_root: Path, relative: str) -> bool:
    rules = _helmignore_rules(chart_root)
    parts = PurePosixPath(relative).parts
    for end in range(1, len(parts)):
        directory = PurePosixPath(*parts[:end]).as_posix()
        if _helmignore_matches(directory, is_dir=True, rules=rules):
            return True
    return _helmignore_matches(relative, is_dir=False, rules=rules)


def _chart_context_for_source(source_path: str) -> str:
    parts = PurePosixPath(source_path).parts
    template_index = next(
        (position for position, part in enumerate(parts) if part in {"templates", "crds"}),
        None,
    )
    if template_index is None:
        return "."
    prefix = parts[:template_index]
    return PurePosixPath(*prefix).as_posix() if prefix else "."


def _protected_directory_files(
    chart_root: Path,
    *,
    chart_context: str,
    chart_name: str,
    inventory_root_sha256: str,
) -> dict[str, _ProtectedTplFile]:
    inventory, current_root = _inventory(chart_root)
    if current_root != inventory_root_sha256:
        raise HelmMaterializationError(
            "CHART_MUTATED_DURING_RENDER", "chart changed while protected files were indexed"
        )
    chart_identity = _canonical_sha({
        "chart_context": chart_context,
        "chart_name": chart_name,
        "inventory_root_sha256": inventory_root_sha256,
    })
    result: dict[str, _ProtectedTplFile] = {}
    special = {"Chart.yaml", "Chart.lock", "values.yaml", "values.schema.json"}
    for item in inventory:
        relative = PurePosixPath(item.path)
        if relative.parts[0] in {"templates", "charts"} or item.path in special:
            continue
        if _chart_file_is_ignored(chart_root, item.path):
            continue
        path = chart_root / item.path
        payload = path.read_bytes()
        if len(payload) != item.size or _sha256(payload) != item.sha256:
            raise HelmMaterializationError(
                "CHART_MUTATED_DURING_RENDER", "protected chart file changed during indexing"
            )
        protected_path = (
            item.path if chart_context == "." else f"{chart_context}/{item.path}"
        )
        result[item.path] = _ProtectedTplFile(
            payload,
            chart_context,
            chart_identity,
            inventory_root_sha256,
            canonical_repo_path(protected_path, "protected Helm file"),
            item.path,
            item.size,
            item.sha256,
        )
    return result


def _protected_tpl_files(
    root: Path,
    dependencies: dict,
    root_inventory_sha256: str,
    repository_root: Path | None = None,
) -> dict[str, dict[str, _ProtectedTplFile]]:
    repository_root = (repository_root or root).resolve(strict=True)
    chart = _strict_yaml(root / "Chart.yaml", "Chart.yaml")
    name = chart.get("name")
    assert type(name) is str
    result = {
        ".": _protected_directory_files(
            root,
            chart_context=".",
            chart_name=name,
            inventory_root_sha256=root_inventory_sha256,
        )
    }

    def archive_inspection_for(
        archive_path: Path, artifact: dict
    ) -> _ArchiveInspection:
        inspection = _inspect_archive(
            archive_path, artifact["name"], artifact["version"]
        )
        if inspection.archive_sha256 != artifact["sha256"]:
            raise HelmMaterializationError(
                "CHART_MUTATED_DURING_RENDER",
                "dependency archive changed after protected closure validation",
            )
        return inspection

    def nested_archive_inspection(
        outer: _ArchiveInspection, artifact: dict
    ) -> _ArchiveInspection:
        provenance = artifact["archive_member_provenance"]
        member = next((
            item for item in outer.members
            if item.path == provenance["artifact_member_path"]
            and item.kind == "file"
        ), None)
        if member is None or member.payload is None or member.sha256 != artifact["sha256"]:
            raise HelmMaterializationError(
                "CHART_MUTATED_DURING_RENDER",
                "nested dependency archive bytes contradict protected provenance",
            )
        return _inspect_archive_payload(
            member.payload, artifact["name"], artifact["version"]
        )

    def add_archive_chart(
        inspection: _ArchiveInspection,
        *,
        chart_member_path: str,
        context: str,
        chart_name: str,
        closure: dict,
        inventory_root_sha256: str,
    ) -> None:
        chart_identity = _canonical_sha({
            "chart_context": context,
            "chart_name": chart_name,
            "inventory_root_sha256": inventory_root_sha256,
            "archive_sha256": inspection.archive_sha256,
            "chart_member_path": chart_member_path,
        })
        visible: dict[str, _ProtectedTplFile] = {}
        prefix = f"{chart_member_path}/"
        special = {"Chart.yaml", "Chart.lock", "values.yaml", "values.schema.json"}
        for member in inspection.members:
            if member.kind != "file" or not member.path.startswith(prefix):
                continue
            relative = PurePosixPath(member.path[len(prefix):])
            if not relative.parts or relative.parts[0] in {"templates", "charts"}:
                continue
            relative_path = relative.as_posix()
            if relative_path in special or member.payload is None:
                continue
            visible[relative_path] = _ProtectedTplFile(
                member.payload,
                context,
                chart_identity,
                inventory_root_sha256,
                canonical_repo_path(
                    f"{context}/{relative_path}", "protected Helm file"
                ),
                relative_path,
                member.size,
                member.sha256,
            )
        result[context] = visible
        for child in closure["artifacts"]:
            child_context = child.get("logical_context") or (
                f"{context}/charts/{child['name']}"
            )
            provenance = child.get("archive_member_provenance")
            if provenance is None:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested archive dependency lacks member provenance",
                )
            if child["form"] == "archive-member-directory":
                add_archive_chart(
                    inspection,
                    chart_member_path=provenance["artifact_member_path"],
                    context=child_context,
                    chart_name=child["name"],
                    closure=child.get("dependencies", {"artifacts": []}),
                    inventory_root_sha256=child["physical_root_sha256"],
                )
            elif child["form"] == "archive-member-archive":
                inner = nested_archive_inspection(inspection, child)
                add_archive_chart(
                    inner,
                    chart_member_path=inner.chart_root,
                    context=child_context,
                    chart_name=child["name"],
                    closure=child.get("dependencies", {"artifacts": []}),
                    inventory_root_sha256=_canonical_sha(child["expanded_files"]),
                )
            else:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested archive dependency form is not source-bound",
                )

    def add_artifacts(parent_root: Path, closure: dict) -> None:
        for artifact in closure["artifacts"]:
            context = artifact.get("logical_context") or f"charts/{artifact['name']}"
            if artifact["form"] in {"directory", "local-directory"}:
                child_root = (
                    parent_root / "charts" / artifact["name"]
                    if artifact["form"] == "directory" else
                    repository_root / artifact["source_repository_path"]
                )
                _child_inventory, child_hash = _inventory(child_root)
                result[context] = _protected_directory_files(
                    child_root,
                    chart_context=context,
                    chart_name=artifact["name"],
                    inventory_root_sha256=child_hash,
                )
                add_artifacts(
                    child_root, artifact.get("dependencies", {"artifacts": []})
                )
                continue
            archive_path = (
                parent_root / "charts" / f"{artifact['name']}-{artifact['version']}.tgz"
                if artifact["form"] == "archive" else
                repository_root / artifact["source_repository_path"]
            )
            inspection = archive_inspection_for(archive_path, artifact)
            add_archive_chart(
                inspection,
                chart_member_path=inspection.chart_root,
                context=context,
                chart_name=artifact["name"],
                closure=artifact.get("dependencies", {"artifacts": []}),
                inventory_root_sha256=_canonical_sha(artifact["expanded_files"]),
            )

    add_artifacts(root, dependencies)
    return result


def _template_sources(
    root: Path, dependencies: dict, repository_root: Path | None = None
) -> tuple[tuple[str, str], ...]:
    repository_root = (repository_root or root).resolve(strict=True)
    result: list[tuple[str, str]] = []

    def emit_archive_chart(
        inspection: _ArchiveInspection,
        *,
        chart_member_path: str,
        context: str,
        closure: dict,
    ) -> None:
        prefix = f"{chart_member_path}/"
        for member in inspection.members:
            if member.kind != "file" or not member.path.startswith(prefix):
                continue
            relative = PurePosixPath(member.path[len(prefix):])
            if not relative.parts or relative.parts[0] == "charts":
                continue
            if "templates" not in relative.parts and "crds" not in relative.parts:
                continue
            if member.payload is None:
                raise HelmMaterializationError(
                    "UNSAFE_DEPENDENCY_ARCHIVE",
                    "dependency template bytes are unavailable",
                )
            try:
                text = member.payload.decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise HelmMaterializationError(
                    "CHART_INVENTORY_UNAVAILABLE",
                    "dependency template is not valid UTF-8",
                ) from exc
            result.append((f"{context}/{relative.as_posix()}", text))
        for child in closure["artifacts"]:
            child_context = child.get("logical_context") or (
                f"{context}/charts/{child['name']}"
            )
            provenance = child.get("archive_member_provenance")
            if provenance is None:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested archive template source lacks member provenance",
                )
            if child["form"] == "archive-member-directory":
                emit_archive_chart(
                    inspection,
                    chart_member_path=provenance["artifact_member_path"],
                    context=child_context,
                    closure=child.get("dependencies", {"artifacts": []}),
                )
            elif child["form"] == "archive-member-archive":
                member = next((
                    item for item in inspection.members
                    if item.path == provenance["artifact_member_path"]
                    and item.kind == "file"
                ), None)
                if (
                    member is None or member.payload is None
                    or member.sha256 != child["sha256"]
                ):
                    raise HelmMaterializationError(
                        "CHART_MUTATED_DURING_RENDER",
                        "nested dependency archive contradicts protected provenance",
                    )
                inner = _inspect_archive_payload(
                    member.payload, child["name"], child["version"]
                )
                emit_archive_chart(
                    inner,
                    chart_member_path=inner.chart_root,
                    context=child_context,
                    closure=child.get("dependencies", {"artifacts": []}),
                )
            else:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested archive template source has an unsupported form",
                )

    def emit_directory(chart_root: Path, context: str, closure: dict) -> None:
        for path in sorted(chart_root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(chart_root)
            # Nested charts are emitted only through their logical instance below.
            if relative.parts and relative.parts[0] == "charts":
                continue
            if "templates" not in relative.parts and "crds" not in relative.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise HelmMaterializationError(
                    "CHART_INVENTORY_UNAVAILABLE", "Helm template is not valid UTF-8"
                ) from exc
            logical = f"{context}/{relative.as_posix()}" if context else relative.as_posix()
            result.append((logical, text))
        for artifact in closure["artifacts"]:
            context_path = artifact.get("logical_context") or (
                f"{context}/charts/{artifact['name']}"
                if context else f"charts/{artifact['name']}"
            )
            form = artifact["form"]
            if form == "directory":
                child_root = chart_root / "charts" / artifact["name"]
                emit_directory(child_root, context_path, artifact.get(
                    "dependencies", {"artifacts": []}
                ))
                continue
            if form == "local-directory":
                child_root = repository_root / artifact["source_repository_path"]
                emit_directory(child_root, context_path, artifact.get(
                    "dependencies", {"artifacts": []}
                ))
                continue
            archive_path = (
                chart_root / "charts" / f"{artifact['name']}-{artifact['version']}.tgz"
                if form == "archive" else
                repository_root / artifact["source_repository_path"]
            )
            inspection = _inspect_archive(
                archive_path, artifact["name"], artifact["version"]
            )
            if inspection.archive_sha256 != artifact["sha256"]:
                raise HelmMaterializationError(
                    "CHART_MUTATED_DURING_RENDER",
                    "dependency archive changed after protected closure validation",
                )
            emit_archive_chart(
                inspection,
                chart_member_path=inspection.chart_root,
                context=context_path,
                closure=artifact.get("dependencies", {"artifacts": []}),
            )

    emit_directory(root, "", dependencies)
    paths = [path for path, _ in result]
    if len(paths) != len(set(paths)):
        raise HelmMaterializationError(
            "AMBIGUOUS_TEMPLATE_ACTION_GRAPH", "template source identity is duplicated"
        )
    return tuple(sorted(result))


def _template_actions(
    root: Path, dependencies: dict, chart_inventory_root_sha256: str,
    repository_root: Path | None = None,
) -> _TemplateActionIndex:
    roots: dict[str, _TemplateActionScope] = {}
    definitions: dict[str, _TemplateActionScope] = {}
    definition_members: dict[str, list[_TemplateActionScope]] = {}
    definition_graphs: dict[str, tuple] = {}
    sources = dict(_template_sources(root, dependencies, repository_root))
    root_chart = _strict_yaml(root / "Chart.yaml", "Chart.yaml")
    root_chart_name = root_chart.get("name")
    if type(root_chart_name) is not str or not root_chart_name:
        raise HelmMaterializationError(
            "CHART_INVENTORY_UNAVAILABLE", "Chart.yaml identity is incomplete"
        )
    source_base_paths: dict[str, tuple[str, str, str]] = {}
    source_template_names: dict[str, list[str]] = {}
    source_chart_contexts: dict[str, str] = {}
    for path, text in sources.items():
        source_definition_graphs = (
            _definition_graphs(text) if re.search(r"{{-?\s*define\s+\"", text) else {}
        )
        parts = PurePosixPath(path).parts
        template_positions = [
            position for position, part in enumerate(parts) if part == "templates"
        ]
        if not template_positions:
            # CRDs are governed source bytes but are not Helm include targets.
            source_chart_name = root_chart_name
            protected_base = "crds"
            actual_base = f"{root_chart_name}/crds"
        else:
            template_position = template_positions[-1]
            protected_base = PurePosixPath(*parts[:template_position + 1]).as_posix()
            chart_positions = [
                position for position in range(template_position)
                if parts[position] == "charts" and position + 1 < template_position
            ]
            if chart_positions:
                source_chart_name = parts[chart_positions[-1] + 1]
            else:
                source_chart_name = root_chart_name
            actual_base = f"{source_chart_name}/templates"
            suffix = PurePosixPath(*parts[template_position + 1:]).as_posix()
            actual_name = f"{actual_base}/{suffix}"
            source_template_names.setdefault(actual_name, []).append(path)
        source_base_paths[path] = (
            actual_base,
            protected_base,
            f"{source_chart_name}@{protected_base}",
        )
        source_chart_contexts[path] = _chart_context_for_source(path)
        root_actions: list[str] = []
        current_name: str | None = None
        current_actions: list[str] | None = None
        definition_depth = 0
        definition_occurrences: dict[str, int] = {}
        for action in _iter_template_actions(text):
            if _TEMPLATE_COMMENT.fullmatch(action):
                continue
            definition = _DEFINE_ACTION.match(action)
            if definition is not None:
                if current_name is not None:
                    raise HelmMaterializationError(
                        "HELM_TEMPLATE_DEFINITION_PARSE_FAILED",
                        "named Helm template definition is nested",
                    )
                current_name = definition.group(1)
                current_actions = []
                definition_depth = 1
                continue
            if current_name is None:
                root_actions.append(action)
            else:
                assert current_actions is not None
                code = _unquoted_action(action)
                if _CONTROL_START.match(code):
                    definition_depth += 1
                if _CONTROL_END.match(code):
                    definition_depth -= 1
                    if definition_depth == 0:
                        graph = source_definition_graphs.get(current_name)
                        if graph is None:
                            raise HelmMaterializationError(
                                "HELM_TEMPLATE_DEFINITION_PARSE_FAILED",
                                "named template graph is unavailable",
                            )
                        prior_graph = definition_graphs.get(current_name)
                        if prior_graph is not None and prior_graph != graph:
                            raise HelmMaterializationError(
                                "HELM_TEMPLATE_DUPLICATE_NON_EQUIVALENT",
                                "named template definitions have different action graphs",
                            )
                        ordinal = definition_occurrences.get(current_name, 0)
                        definition_occurrences[current_name] = ordinal + 1
                        span_sha256 = _canonical_sha({
                            "definition_name": current_name,
                            "definition_ordinal": ordinal,
                            "actions": current_actions,
                            "action_graph": graph,
                        })
                        member = _TemplateActionScope(
                            path, tuple(current_actions), ordinal, span_sha256
                        )
                        definition_graphs.setdefault(current_name, graph)
                        definition_members.setdefault(current_name, []).append(member)
                        definitions.setdefault(current_name, member)
                        current_name = None
                        current_actions = None
                        continue
                current_actions.append(action)
        if current_name is not None:
            raise HelmMaterializationError(
                "AMBIGUOUS_TEMPLATE_ACTION_GRAPH", "named Helm template is not closed"
            )
        roots[path] = _TemplateActionScope(path, tuple(root_actions))
    return _TemplateActionIndex(
        roots,
        definitions,
        sources,
        source_base_paths,
        {name: tuple(sorted(paths)) for name, paths in source_template_names.items()},
        source_chart_contexts,
        _protected_tpl_files(
            root, dependencies, chart_inventory_root_sha256, repository_root
        ),
        {
            name: tuple(sorted(members, key=lambda item: item.source_path))
            for name, members in definition_members.items()
        },
        definition_graphs,
    )


_UNKNOWN = object()
_UNMODELED_VALUES = object()
_SUBCHART_VALUES = object()


def _merge_values(target: dict, update: dict) -> dict:
    result = dict(target)
    for key, value in update.items():
        if type(key) is not str:
            raise HelmMaterializationError(
                "UNMODELED_RENDER_INPUT", "Helm values keys must be strings"
            )
        if type(value) is dict and type(result.get(key)) is dict:
            result[key] = _merge_values(result[key], value)
        else:
            result[key] = value
    return result


def _effective_values_projection(values: dict) -> dict:
    """Return the exact bounded Values semantics without traversal-only sentinels."""
    projected: dict[str, object] = {}
    for key, value in values.items():
        if type(key) is not str:
            continue
        if type(value) is dict:
            projected[key] = _effective_values_projection(value)["values"]
        elif type(value) is list:
            projected[key] = [
                _effective_values_projection(item)["values"]
                if type(item) is dict else item
                for item in value
            ]
        else:
            projected[key] = value
    return {
        "values": projected,
        "unmodeled": values.get(_UNMODELED_VALUES) is True,
    }


def _effective_values_sha256(values: dict) -> str:
    projected = _effective_values_projection(values)
    return _canonical_sha(
        projected if projected["unmodeled"] else projected["values"]
    )


def _load_values_file(path: Path) -> dict:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictSafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise HelmMaterializationError(
            "UNMODELED_RENDER_INPUT", "Helm values are not valid UTF-8 YAML"
        ) from exc
    if value is None:
        return {}
    if type(value) is not dict:
        raise HelmMaterializationError(
            "UNMODELED_RENDER_INPUT", "Helm values root must be a mapping"
        )
    return value


def _set_value_path(values: dict, path: str, value: object) -> bool:
    # The bounded proof model accepts simple dotted maps. Helm's richer --set
    # index/escape grammar remains rendered and hashed but cannot establish a
    # branch proof.
    if re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", path) is None:
        return False
    parts = path.split(".")
    current = values
    for part in parts[:-1]:
        child = current.get(part)
        if type(child) is not dict:
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = value
    return True


def _protected_values(
    spec: HelmRenderSpec, dependencies: dict | None = None
) -> tuple[dict, str]:
    values: dict = {}
    identity: list[dict] = []
    default_values = spec.chart_root / "values.yaml"
    if default_values.is_file() and not default_values.is_symlink():
        values = _merge_values(values, _load_values_file(default_values))
        identity.append({"source": "chart-default", "sha256": _sha256(default_values.read_bytes())})
    for relative in spec.values_files:
        path = spec.chart_root / relative
        values = _merge_values(values, _load_values_file(path))
        identity.append({"source": relative, "sha256": _sha256(path.read_bytes())})
    for key, raw in spec.set_values:
        try:
            value = yaml.load(raw, Loader=_StrictSafeLoader)
        except yaml.YAMLError as exc:
            raise HelmMaterializationError(
                "UNMODELED_RENDER_INPUT", "typed Helm override cannot be modeled exactly"
            ) from exc
        if not _set_value_path(values, key, value):
            values[_UNMODELED_VALUES] = True
        identity.append({
            "source": "set", "key": key, "value_sha256": _sha256(raw.encode("utf-8"))
        })
    for key, raw in spec.set_strings:
        if not _set_value_path(values, key, raw):
            values[_UNMODELED_VALUES] = True
        identity.append({
            "source": "set-string", "key": key,
            "value_sha256": _sha256(raw.encode("utf-8")),
        })
    subcharts: dict[str, dict] = {}
    charts_root = spec.chart_root / "charts"
    if dependencies is not None:
        def archive_member(
            inspection: _ArchiveInspection, path: str, label: str
        ) -> _ArchiveMember | None:
            selected = next((item for item in inspection.members if item.path == path), None)
            if selected is not None and (
                selected.kind != "file" or selected.payload is None
            ):
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    f"{label} is not a protected regular archive member",
                )
            return selected

        def inspect_path(path: Path, artifact: dict) -> _ArchiveInspection:
            inspection = _inspect_archive(path, artifact["name"], artifact["version"])
            if inspection.archive_sha256 != artifact["sha256"]:
                raise HelmMaterializationError(
                    "CHART_MUTATED_DURING_RENDER",
                    "dependency archive changed while effective Values were bound",
                )
            return inspection

        def inspect_nested(
            inspection: _ArchiveInspection, artifact: dict
        ) -> _ArchiveInspection:
            provenance = artifact.get("archive_member_provenance")
            if provenance is None:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                    "nested dependency Values lack archive-member provenance",
                )
            member = archive_member(
                inspection,
                provenance["artifact_member_path"],
                "nested dependency archive",
            )
            if member is None or member.sha256 != artifact["sha256"]:
                raise HelmMaterializationError(
                    "CHART_MUTATED_DURING_RENDER",
                    "nested dependency archive contradicts protected Values provenance",
                )
            nested = _inspect_archive_payload(
                member.payload, artifact["name"], artifact["version"]
            )
            if nested.archive_sha256 != artifact["sha256"]:
                raise HelmMaterializationError(
                    "CHART_MUTATED_DURING_RENDER",
                    "nested dependency archive digest changed during Values binding",
                )
            return nested

        def load_archive_values(
            inspection: _ArchiveInspection, chart_member_path: str
        ) -> tuple[dict, dict]:
            path = f"{chart_member_path}/values.yaml"
            member = archive_member(inspection, path, "dependency values.yaml")
            if member is None:
                return {}, {
                    "kind": "ABSENT",
                    "path": "",
                    "sha256": _canonical_sha({"values_yaml": "ABSENT"}),
                }
            try:
                loaded = yaml.load(member.payload, Loader=_StrictSafeLoader)
            except yaml.YAMLError as exc:
                raise HelmMaterializationError(
                    "UNREPRODUCIBLE_DEPENDENCIES",
                    "dependency archive values are malformed",
                ) from exc
            if loaded is not None and type(loaded) is not dict:
                raise HelmMaterializationError(
                    "UNREPRODUCIBLE_DEPENDENCIES",
                    "dependency archive values must be a mapping",
                )
            return loaded or {}, {
                "kind": "ARCHIVE_MEMBER",
                "path": path,
                "sha256": member.sha256,
            }

        def dependency_defaults(
            parent: Path,
            artifact: dict,
            enclosing_archive: _ArchiveInspection | None,
        ) -> tuple[dict, dict, Path, _ArchiveInspection | None]:
            form = artifact["form"]
            if form in {"directory", "local-directory"}:
                child = (
                    parent / "charts" / artifact["name"]
                    if form == "directory" else
                    spec.protected_repository_root / artifact["source_repository_path"]
                )
                path = child / "values.yaml"
                if path.is_file() and not path.is_symlink():
                    return _load_values_file(path), {
                        "kind": "FILE",
                        "path": canonical_repo_path(
                            path.relative_to(spec.protected_repository_root).as_posix(),
                            "Helm dependency values path",
                        ),
                        "sha256": _sha256(path.read_bytes()),
                    }, child, None
                return {}, {
                    "kind": "ABSENT", "path": "",
                    "sha256": _canonical_sha({"values_yaml": "ABSENT"}),
                }, child, None
            if form in {"archive", "local-archive"}:
                path = (
                    parent / "charts" / f"{artifact['name']}-{artifact['version']}.tgz"
                    if form == "archive" else
                    spec.protected_repository_root / artifact["source_repository_path"]
                )
                inspection = inspect_path(path, artifact)
                defaults, source = load_archive_values(
                    inspection, inspection.chart_root
                )
                return defaults, source, parent, inspection
            if form == "archive-member-directory":
                if enclosing_archive is None:
                    raise HelmMaterializationError(
                        "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                        "archive-member Values lack their protected outer archive",
                    )
                provenance = artifact["archive_member_provenance"]
                defaults, source = load_archive_values(
                    enclosing_archive, provenance["chart_member_path"]
                )
                return defaults, source, parent, enclosing_archive
            if form == "archive-member-archive":
                if enclosing_archive is None:
                    raise HelmMaterializationError(
                        "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                        "nested archive Values lack their protected outer archive",
                    )
                inspection = inspect_nested(enclosing_archive, artifact)
                defaults, source = load_archive_values(
                    inspection, inspection.chart_root
                )
                return defaults, source, parent, inspection
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_TRANSITIVE_CLOSURE_INCOMPLETE",
                "dependency Values use an unsupported physical form",
            )

        def set_path(root: dict, path: str, selected: object) -> dict:
            parts = path.split(".")
            result: dict = {}
            current = result
            for part in parts[:-1]:
                child: dict = {}
                current[part] = child
                current = child
            current[parts[-1]] = selected
            return result

        def apply_imports(
            parent_values: dict,
            artifact: dict,
            child_values: dict,
            contributions: list[dict],
        ) -> None:
            if not artifact.get("activation", {}).get("result", True):
                return
            for ordinal, item in enumerate(artifact.get("imports", [])):
                if type(item) is str:
                    found, selected = _dependency_path_value(
                        child_values, f"exports.{item}"
                    )
                    if not found or type(selected) is not dict:
                        raise HelmMaterializationError(
                            "HELM_DEPENDENCY_IMPORT_UNSUPPORTED",
                            "string import does not resolve to a protected table",
                        )
                    merged = _merge_values(selected, parent_values)
                else:
                    found, selected = _dependency_path_value(
                        child_values, item["child"]
                    )
                    if not found:
                        raise HelmMaterializationError(
                            "HELM_DEPENDENCY_IMPORT_UNSUPPORTED",
                            "mapped import child path is unavailable",
                        )
                    merged = _merge_values(
                        set_path({}, item["parent"], selected), parent_values
                    )
                contributions.append({
                    "ordinal": ordinal,
                    "child": item if type(item) is str else item["child"],
                    "parent": item if type(item) is str else item["parent"],
                    "selected_values_sha256": _canonical_sha(selected),
                })
                parent_values.clear()
                parent_values.update(merged)

        def build_children(
            parent: Path,
            closure: dict,
            parent_values: dict,
            enclosing_archive: _ArchiveInspection | None = None,
            imports_applied_to_parent: list[dict] | None = None,
        ) -> dict[str, dict]:
            result: dict[str, dict] = {}
            for artifact in closure["artifacts"]:
                effective_name = artifact.get("logical_instance", {}).get(
                    "effective_name", artifact["name"]
                )
                child_values, default_source, child, child_archive = dependency_defaults(
                    parent, artifact, enclosing_archive
                )
                default_values_sha256 = _effective_values_sha256(child_values)
                overrides = parent_values.get(effective_name, {})
                if type(overrides) is not dict:
                    child_values[_UNMODELED_VALUES] = True
                    parent_values_sha256 = _canonical_sha({
                        "effective_name": effective_name,
                        "type": type(overrides).__name__,
                        "modeled": False,
                    })
                else:
                    parent_values_sha256 = _effective_values_sha256(overrides)
                    child_values = _merge_values(child_values, overrides)
                globals_value = parent_values.get("global")
                global_values = globals_value if type(globals_value) is dict else {}
                if globals_value is not None:
                    existing_global = child_values.get("global", {})
                    if type(globals_value) is not dict or type(existing_global) is not dict:
                        child_values[_UNMODELED_VALUES] = True
                    else:
                        child_values["global"] = _merge_values(
                            existing_global, globals_value
                        )
                child_import_contributions: list[dict] = []
                child_values[_SUBCHART_VALUES] = build_children(
                    child,
                    artifact.get("dependencies", {"artifacts": []}),
                    child_values,
                    child_archive,
                    child_import_contributions,
                )
                result[effective_name] = child_values
                apply_imports(
                    parent_values,
                    artifact,
                    child_values,
                    imports_applied_to_parent
                    if imports_applied_to_parent is not None else [],
                )
                logical = artifact.get("logical_instance")
                if logical is not None:
                    effective_values_sha256 = _effective_values_sha256(child_values)
                    logical["effective_values_root_sha256"] = effective_values_sha256
                    logical["global_values_sha256"] = _effective_values_sha256(
                        global_values
                    )
                    values_body = {
                        "contract": "helm-logical-effective-values-v1",
                        "effective_name": effective_name,
                        "dependency_defaults_source_kind": default_source["kind"],
                        "dependency_defaults_source_path": default_source["path"],
                        "dependency_defaults_source_sha256": default_source["sha256"],
                        "dependency_defaults_values_sha256": default_values_sha256,
                        "parent_scoped_values_sha256": parent_values_sha256,
                        "global_values_sha256": logical["global_values_sha256"],
                        "import_values_contribution_sha256": _canonical_sha(
                            child_import_contributions
                        ),
                        "effective_values_root_sha256": effective_values_sha256,
                        "source_marker_context": logical["source_marker_context"],
                        "logical_instance_identity": logical[
                            "logical_instance_identity"
                        ],
                    }
                    artifact["values_provenance"] = {
                        **values_body,
                        "provenance_identity": _canonical_sha(values_body),
                    }
            return result

        subcharts = build_children(spec.chart_root, dependencies, values)
        _reparent_dependency_closure(dependencies, ".")
    elif charts_root.is_dir():
        for child in sorted(charts_root.iterdir(), key=lambda item: item.name):
            if not child.is_dir() or child.is_symlink():
                continue
            child_values = {}
            child_default = child / "values.yaml"
            if child_default.is_file() and not child_default.is_symlink():
                child_values = _load_values_file(child_default)
            parent_values = values.get(child.name, {})
            if type(parent_values) is dict:
                child_values = _merge_values(child_values, parent_values)
            else:
                child_values[_UNMODELED_VALUES] = True
            subcharts[child.name] = child_values
    values[_SUBCHART_VALUES] = subcharts
    return values, _canonical_sha(identity)


def _values_for_source(values: dict, source_template: str) -> dict:
    parts = PurePosixPath(source_template).parts
    context = values
    index = 0
    while index + 1 < len(parts) and parts[index] == "charts":
        child = context.get(_SUBCHART_VALUES, {}).get(parts[index + 1])
        if type(child) is not dict:
            return {_UNMODELED_VALUES: True}
        context = child
        index += 2
    return context


def _sealed_helm_chart(
    spec: HelmRenderSpec, dependencies: dict, destination: Path
) -> HelmRenderSpec:
    """Create the complete read-only local chart/dependency build view."""
    destination.mkdir(mode=0o700, parents=True)

    def copy_file(source: Path, target: Path) -> None:
        payload = source.read_bytes()
        if target.exists():
            if not target.is_file() or target.is_symlink() or target.read_bytes() != payload:
                raise HelmMaterializationError(
                    "HELM_DEPENDENCY_ARTIFACT_IDENTITY_MISMATCH",
                    "logical instances require conflicting physical bytes",
                )
            return
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise HelmMaterializationError(
                        "HELM_STATE_NOT_ISOLATED", "sealed chart copy did not complete"
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def copy_tree(source: Path, target: Path) -> None:
        inventory, _identity = _inventory(source)
        for record in inventory:
            copy_file(source / record.path, target / record.path)

    copy_tree(spec.chart_root, destination)

    def add_closure(physical_parent: Path, sealed_parent: Path, closure: dict) -> None:
        for artifact in closure["artifacts"]:
            form = artifact["form"]
            if form == "directory":
                physical = physical_parent / "charts" / artifact["name"]
                sealed = sealed_parent / "charts" / artifact["name"]
            elif form == "local-directory":
                physical = (
                    spec.protected_repository_root / artifact["source_repository_path"]
                )
                sealed = sealed_parent / "charts" / artifact["name"]
                copy_tree(physical, sealed)
            elif form == "local-archive":
                physical = (
                    spec.protected_repository_root / artifact["source_repository_path"]
                )
                copy_file(
                    physical,
                    sealed_parent / "charts" /
                    f"{artifact['name']}-{artifact['version']}.tgz",
                )
                continue
            else:
                continue
            add_closure(
                physical, sealed, artifact.get("dependencies", {"artifacts": []})
            )

    add_closure(spec.chart_root, destination, dependencies)
    for directory in sorted(
        (item for item in destination.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts), reverse=True,
    ):
        directory.chmod(0o500)
    destination.chmod(0o500)
    return replace(
        spec,
        chart_root=destination,
        protected_repository_root=destination,
    )


def _value_at(values: object, expression: str) -> object:
    match = _VALUES_PATH.fullmatch(expression.strip())
    if match is None:
        return _UNKNOWN
    if type(values) is dict and values.get(_UNMODELED_VALUES) is True:
        return _UNKNOWN
    path = match.group(1)
    if path is None:
        return values
    current = values
    for part in path.split("."):
        if type(current) is not dict or part not in current:
            return _UNKNOWN
        current = current[part]
    return current


def _exact_value_at(values: object, expression: str) -> tuple[bool, object]:
    match = _VALUES_PATH.fullmatch(expression.strip())
    if match is None or type(values) is not dict or values.get(_UNMODELED_VALUES) is True:
        return False, None
    current: object = values
    path = match.group(1)
    if path is None:
        return True, current
    for part in path.split("."):
        if type(current) is not dict or part not in current:
            return False, None
        current = current[part]
    return True, current


def _strip_outer_parentheses(
    tokens: tuple[_ActionToken, ...],
) -> tuple[_ActionToken, ...]:
    result = tokens
    while len(result) >= 2 and result[0].text == "(":
        end = _matching_parenthesis(result, 0)
        if end != len(result) - 1:
            break
        result = result[1:-1]
    return result


def _resolve_tpl_expression(
    tokens: tuple[_ActionToken, ...],
    values: dict,
    index: _TemplateActionIndex | None = None,
    file_chart_context: str | None = None,
) -> _TplArgument | None:
    expression = _strip_outer_parentheses(tokens)
    if len(expression) == 1:
        token = expression[0]
        if token.quoted:
            return _TplArgument(token.text, "LITERAL", "")
        found, value = _exact_value_at(values, token.text)
        if found and type(value) is str:
            match = _VALUES_PATH.fullmatch(token.text)
            assert match is not None and match.group(1) is not None
            return _TplArgument(value, "PROTECTED_VALUES_PATH", match.group(1))
        return None
    if (
        len(expression) == 2
        and not expression[0].quoted
        and expression[0].text == ".Files.Get"
        and expression[1].quoted
    ):
        requested = expression[1].text
        path = PurePosixPath(requested)
        if (
            index is None
            or file_chart_context is None
            or not requested
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != requested
        ):
            return None
        protected = index.protected_files.get(file_chart_context, {}).get(requested)
        if protected is None:
            return None
        try:
            content = protected.content.decode("utf-8", errors="strict")
        except UnicodeError:
            return None
        return _TplArgument(
            content,
            "PROTECTED_CHART_FILE",
            protected.protected_path,
            protected,
        )
    if len(expression) == 3 and expression[0].text == "default":
        fallback = expression[1]
        requested = expression[2]
        if not fallback.quoted:
            return None
        found, value = _exact_value_at(values, requested.text)
        selected = value if found and _truth(value) else fallback.text
        if type(selected) is not str:
            return None
        match = _VALUES_PATH.fullmatch(requested.text)
        if match is None or match.group(1) is None:
            return None
        return _TplArgument(selected, "PROTECTED_VALUES_DEFAULT", match.group(1))
    return None


def _resolve_tpl_call(
    tokens: tuple[_ActionToken, ...],
    start: int,
    values: dict,
    index: _TemplateActionIndex | None = None,
    file_chart_context: str | None = None,
) -> tuple[_TplArgument, int] | None:
    if start >= len(tokens) or tokens[start].quoted or tokens[start].text != "tpl":
        return None
    argument_start = start + 1
    if argument_start >= len(tokens):
        return None
    if tokens[argument_start].text == "(":
        argument_end = _matching_parenthesis(tokens, argument_start)
        if argument_end is None:
            return None
        argument_tokens = tokens[argument_start + 1:argument_end]
        context_index = argument_end + 1
    else:
        argument_tokens = tokens[argument_start:argument_start + 1]
        context_index = argument_start + 1
    argument = _resolve_tpl_expression(
        argument_tokens, values, index, file_chart_context
    )
    if (
        argument is None
        or context_index >= len(tokens)
        or tokens[context_index].quoted
        or tokens[context_index].text not in {".", "$"}
    ):
        return None
    return argument, context_index + 1


def _tpl_condition_value(expression: str, values: dict) -> object:
    tokens = _action_tokens(expression)
    if tokens is None:
        return _UNKNOWN
    tokens = _strip_outer_parentheses(tokens)
    resolved = _resolve_tpl_call(tokens, 0, values)
    if resolved is None or resolved[1] != len(tokens):
        return _UNKNOWN
    argument = resolved[0]
    if _iter_template_actions(argument.content):
        return _UNKNOWN
    return argument.content


def _literal_or_value(token: str, values: dict) -> object:
    value = _value_at(values, token)
    if value is not _UNKNOWN:
        return value
    lowered = token.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"nil", "null"}:
        return None
    if re.fullmatch(r"-?[0-9]+", token):
        return int(token)
    if re.fullmatch(r"-?[0-9]+\.[0-9]+", token):
        return float(token)
    # shlex has already removed quotes, so an unrecognized bare token is not
    # distinguishable from a literal. Only strings in an equality operand are
    # admitted by the caller.
    return _UNKNOWN


def _truth(value: object) -> bool | None:
    if value is _UNKNOWN:
        return None
    if value is None or value is False:
        return False
    if value == 0 or value == "" or value == [] or value == {}:
        return False
    return True


def _condition(expression: str, values: dict) -> bool | None:
    expression = expression.strip()
    while expression.startswith("(") and expression.endswith(")"):
        expression = expression[1:-1].strip()
    if "|" in expression:
        return None
    tpl_value = _tpl_condition_value(expression, values)
    if tpl_value is not _UNKNOWN:
        return _truth(tpl_value)
    try:
        tokens = shlex.split(expression, posix=True)
    except ValueError:
        return None
    if not tokens:
        return None
    if len(tokens) == 1:
        return _truth(_literal_or_value(tokens[0], values))
    if len(tokens) == 2 and tokens[0] == "not":
        inner = _condition(tokens[1], values)
        return None if inner is None else not inner
    if len(tokens) == 3 and tokens[0] in {"eq", "ne"}:
        left = _literal_or_value(tokens[1], values)
        right = _literal_or_value(tokens[2], values)
        # Quoted strings lose their delimiters under shlex. Treat an operand as
        # a literal only when the original expression contains its quoted form.
        if left is _UNKNOWN and re.search(rf"(['\"])\s*{re.escape(tokens[1])}\s*\1", expression):
            left = tokens[1]
        if right is _UNKNOWN and re.search(rf"(['\"])\s*{re.escape(tokens[2])}\s*\1", expression):
            right = tokens[2]
        if left is _UNKNOWN or right is _UNKNOWN:
            return None
        result = left == right
        return result if tokens[0] == "eq" else not result
    return None


def _combine(parent: bool | None, child: bool | None) -> bool | None:
    if parent is False or child is False:
        return False
    if parent is True and child is True:
        return True
    return None


@dataclass(slots=True)
class _ActionState:
    reachable_functions: set[str]
    reached_definitions: set[str]
    excluded: list[dict]
    ambiguous: bool = False
    tpl_evidence: list[dict] | None = None
    protected_values_sha256: str = ""
    tpl_expanded_bytes: int = 0
    tpl_nested_actions: int = 0
    reachable_details: list[dict] | None = None
    dynamic_include_evidence: list[dict] | None = None
    dynamic_include_nodes: int = 0
    dynamic_include_action_bytes: int = 0
    dynamic_include_targets: int = 0

    def __post_init__(self) -> None:
        if self.tpl_evidence is None:
            self.tpl_evidence = []
        if self.reachable_details is None:
            self.reachable_details = []
        if self.dynamic_include_evidence is None:
            self.dynamic_include_evidence = []


def _action_parts(action: str) -> tuple[set[str], set[str], bool]:
    code = _unquoted_action(action)
    functions = {item.group(1) for item in _RANDOM_FUNCTION.finditer(code)}
    if _LOOKUP_FUNCTION.search(code):
        functions.add("lookup")
    calls = set(_NAMED_TEMPLATE_CALL.findall(action))
    tokens = _action_tokens(action)
    dynamic = tokens is None and bool(_NAMED_TEMPLATE_ANY.search(code))
    if tokens is not None:
        dynamic = any(
            not token.quoted
            and token.text in {"include", "template"}
            and position + 1 < len(tokens)
            and not tokens[position + 1].quoted
            for position, token in enumerate(tokens)
        )
    return functions, calls, dynamic


def _all_dangerous(
    scope: _TemplateActionScope,
    index: _TemplateActionIndex,
    visited: set[str] | None = None,
) -> tuple[tuple[str, str, str], ...]:
    visited = set() if visited is None else visited
    result: list[tuple[str, str, str]] = []
    for action in scope.actions:
        functions, calls, _dynamic = _action_parts(action)
        result.extend((scope.source_path, item, _sha256(action.encode())) for item in functions)
        for name in calls:
            if name in visited:
                continue
            visited.add(name)
            called = index.definitions.get(name)
            if called is not None:
                result.extend(_all_dangerous(called, index, visited))
    return tuple(result)


def _scope_has_action_risk(
    scope: _TemplateActionScope,
    index: _TemplateActionIndex,
    visited: set[str] | None = None,
) -> bool:
    visited = set() if visited is None else visited
    for action in scope.actions:
        functions, calls, dynamic = _action_parts(action)
        if functions or dynamic or _TPL_FUNCTION.search(_unquoted_action(action)):
            return True
        for name in calls:
            if name in visited:
                continue
            called = index.definitions.get(name)
            if called is None:
                return True
            visited.add(name)
            if _scope_has_action_risk(called, index, visited):
                return True
    return False


def _record_excluded(
    state: _ActionState,
    scope: _TemplateActionScope,
    action: str,
    functions: set[str],
    calls: set[str],
    index: _TemplateActionIndex,
) -> None:
    records = [(scope.source_path, item, _sha256(action.encode())) for item in functions]
    for name in calls:
        called = index.definitions.get(name)
        if called is not None:
            records.extend(_all_dangerous(called, index, {name}))
    for source, function, digest in records:
        record = {
            "source_template": source,
            "action_class": "lookup" if function == "lookup" else "nondeterministic",
            "action_sha256": digest,
        }
        if record not in state.excluded:
            state.excluded.append(record)


def _record_reachable(
    state: _ActionState,
    scope: _TemplateActionScope,
    action: str,
    functions: set[str],
) -> None:
    assert state.reachable_details is not None
    for function in sorted(functions):
        record = {
            "source_template": scope.source_path,
            "action_class": "lookup" if function == "lookup" else "nondeterministic",
            "action_sha256": _sha256(action.encode("utf-8")),
        }
        if record not in state.reachable_details:
            state.reachable_details.append(record)


def _nested_action_is_bounded(action: str, values: dict) -> bool:
    code = _unquoted_action(action).strip()
    if not code:
        return True
    if _CONTROL_END.match(code) or _CONTROL_ELSE.match(code):
        alternate = _CONTROL_ELSE.match(code)
        return alternate is None or alternate.group(1) is None or (
            _condition(alternate.group(1), values) is not None
        )
    start = re.match(r"^(if|with|range)(?:\s+(.*))?$", action.strip(), re.DOTALL)
    if start is not None:
        return _condition((start.group(2) or "").strip(), values) is not None
    if _CONTROL_START.match(code):
        return False
    functions, calls, dynamic = _action_parts(action)
    if functions or calls or dynamic or _TPL_FUNCTION.search(code):
        return True
    tokens = _action_tokens(action)
    if tokens is None or "|" in {item.text for item in tokens}:
        return False
    if len(tokens) != 1:
        return False
    token = tokens[0]
    if token.quoted or token.text in {".", "$", ".Release.Namespace"}:
        return True
    found, _value = _exact_value_at(values, token.text)
    return found


def _dynamic_include_operand(
    token: _ActionToken,
    scope: _TemplateActionScope,
    index: _TemplateActionIndex,
) -> tuple[str, dict] | None:
    if token.quoted:
        return token.text, {
            "kind": "LITERAL",
            "identity_sha256": _sha256(token.text.encode("utf-8")),
        }
    if token.text not in {".Template.BasePath", "$.Template.BasePath"}:
        return None
    base = index.source_base_paths.get(scope.source_path)
    if base is None:
        return None
    actual_base, protected_base, chart_identity = base
    return actual_base, {
        "kind": "TEMPLATE_BASE_PATH",
        "protected_path": protected_base,
        "chart_identity": chart_identity,
        "identity_sha256": _canonical_sha({
            "kind": "TEMPLATE_BASE_PATH",
            "source_template": scope.source_path,
            "actual_base_sha256": _sha256(actual_base.encode("utf-8")),
            "protected_path": protected_base,
            "chart_identity": chart_identity,
        }),
    }


def _bounded_printf(format_string: str, operands: tuple[str, ...]) -> str | None:
    output: list[str] = []
    operand_index = 0
    index = 0
    while index < len(format_string):
        if format_string[index] != "%":
            output.append(format_string[index])
            index += 1
            continue
        if index + 1 >= len(format_string):
            return None
        verb = format_string[index + 1]
        if verb == "%":
            output.append("%")
        elif verb == "s" and operand_index < len(operands):
            output.append(operands[operand_index])
            operand_index += 1
        else:
            return None
        index += 2
    if operand_index != len(operands):
        return None
    return "".join(output)


def _resolve_dynamic_include_expression(
    tokens: tuple[_ActionToken, ...],
    scope: _TemplateActionScope,
    index: _TemplateActionIndex,
) -> tuple[str, tuple[dict, ...], str] | None:
    while (
        len(tokens) >= 2
        and tokens[0].text == "("
        and _matching_parenthesis(tokens, 0) == len(tokens) - 1
    ):
        tokens = tokens[1:-1]
    if len(tokens) < 2 or tokens[0].quoted:
        return None
    function = tokens[0].text
    if function not in {"print", "printf"}:
        return None
    values: list[str] = []
    identities: list[dict] = []
    for token in tokens[1:]:
        if token.text in {"(", ")", "|"}:
            return None
        operand = _dynamic_include_operand(token, scope, index)
        if operand is None:
            return None
        value, identity = operand
        values.append(value)
        identities.append(identity)
    if function == "print":
        target = "".join(values)
        expression_type = (
            "PRINT_TEMPLATE_BASE_PATH"
            if any(item["kind"] == "TEMPLATE_BASE_PATH" for item in identities)
            else "PRINT_LITERALS"
        )
    else:
        if not tokens[1].quoted:
            return None
        target = _bounded_printf(values[0], tuple(values[1:]))
        if target is None:
            return None
        expression_type = (
            "PRINTF_TEMPLATE_BASE_PATH"
            if any(item["kind"] == "TEMPLATE_BASE_PATH" for item in identities[1:])
            else "PRINTF_LITERALS"
        )
    if (
        not target
        or len(target.encode("utf-8")) > 4096
        or "\x00" in target
        or any(ord(character) < 32 for character in target)
    ):
        return None
    return target, tuple(identities), expression_type


def _map_dynamic_include_target(
    call_function: str,
    target: str,
    expression_type: str,
    operands: tuple[dict, ...],
    index: _TemplateActionIndex,
) -> _ResolvedIncludeTarget | None:
    if "/" in target:
        path = PurePosixPath(target)
        if path.is_absolute() or ".." in path.parts:
            return None
    candidates: list[tuple[str, str, _TemplateActionScope]] = []
    definition = index.definitions.get(target)
    if definition is not None:
        candidates.append(("NAMED_TEMPLATE", f"named-template:{target}", definition))
    for source in index.source_template_names.get(target, ()):
        scope = index.roots.get(source)
        if scope is not None:
            candidates.append(("SOURCE_TEMPLATE", f"source-template:{source}", scope))
    if len(candidates) != 1:
        return None
    target_kind, target_identity, target_scope = candidates[0]
    source_text = index.sources.get(target_scope.source_path)
    if source_text is None:
        return None
    return _ResolvedIncludeTarget(
        call_function,
        expression_type,
        operands,
        target,
        target_kind,
        target_identity,
        target_scope,
        _sha256(source_text.encode("utf-8")),
    )


def _resolved_dynamic_include_calls(
    action: str,
    scope: _TemplateActionScope,
    index: _TemplateActionIndex,
) -> tuple[_ResolvedIncludeTarget, ...] | None:
    tokens = _action_tokens(action)
    if tokens is None:
        return None
    dynamic_positions = [
        position for position, token in enumerate(tokens)
        if not token.quoted
        and token.text in {"include", "template"}
        and position + 1 < len(tokens)
        and not tokens[position + 1].quoted
    ]
    if not dynamic_positions:
        return ()
    if len(dynamic_positions) != 1:
        return None
    position = dynamic_positions[0]
    expression_start = position + 1
    if tokens[expression_start].text != "(":
        return None
    expression_end = _matching_parenthesis(tokens, expression_start)
    if expression_end is None or expression_end + 1 >= len(tokens):
        return None
    context = tokens[expression_end + 1]
    if context.quoted or context.text not in {".", "$"}:
        return None
    tail = tuple(item.text for item in tokens[expression_end + 2:])
    if tail not in {(), ("|", "sha256sum")}:
        return None
    expression = _resolve_dynamic_include_expression(
        tokens[expression_start:expression_end + 1], scope, index
    )
    if expression is None:
        return None
    target, operands, expression_type = expression
    resolved = _map_dynamic_include_target(
        tokens[position].text, target, expression_type, operands, index
    )
    if resolved is None:
        return None
    return (resolved,)


def _dynamic_include_callsite_identity(
    scope: _TemplateActionScope,
    action: str,
    action_index: int,
    include_ordinal: int,
    target: _ResolvedIncludeTarget,
    recursion_depth: int,
    parent_callsite_identity: str,
) -> str:
    return _canonical_sha({
        "source_template": scope.source_path,
        "callsite_action_sha256": _sha256(action.encode("utf-8")),
        "callsite_action_index": action_index,
        "include_ordinal": include_ordinal,
        "call_function": target.call_function,
        "resolved_expression_type": target.expression_type,
        "resolved_target_identity": target.target_identity,
        "recursion_depth": recursion_depth,
        "parent_callsite_identity": parent_callsite_identity,
    })


def _analyze_dynamic_include_calls(
    action: str,
    scope: _TemplateActionScope,
    action_index: int,
    index: _TemplateActionIndex,
    values: dict,
    state: _ActionState,
    execution_state: bool | None,
    call_stack: tuple[str, ...],
    tpl_depth: int,
    tpl_stack: tuple[str, ...],
    tpl_call_stack: tuple[str, ...],
    dynamic_target_stack: tuple[str, ...],
    dynamic_callsite_stack: tuple[str, ...],
    nested_contract: bool,
    file_chart_context: str | None,
) -> bool:
    if not _action_parts(action)[2]:
        return True
    resolved = _resolved_dynamic_include_calls(action, scope, index)
    if resolved is None:
        state.ambiguous = True
        return False
    for include_ordinal, target in enumerate(resolved, start=1):
        recursion_depth = len(dynamic_target_stack) + 1
        action_bytes = sum(
            len(item.encode("utf-8")) for item in target.target_scope.actions
        )
        if (
            recursion_depth > _MAX_DYNAMIC_INCLUDE_DEPTH
            or target.target_identity in dynamic_target_stack
            or state.dynamic_include_nodes + 1 > _MAX_DYNAMIC_INCLUDE_NODES
            or state.dynamic_include_targets + 1 > _MAX_DYNAMIC_INCLUDE_TARGETS
            or state.dynamic_include_action_bytes + action_bytes
            > _MAX_DYNAMIC_INCLUDE_ACTION_BYTES
        ):
            state.ambiguous = True
            return False
        state.dynamic_include_nodes += 1
        state.dynamic_include_targets += 1
        state.dynamic_include_action_bytes += action_bytes
        parent_callsite = dynamic_callsite_stack[-1] if dynamic_callsite_stack else ""
        callsite_identity = _dynamic_include_callsite_identity(
            scope,
            action,
            action_index,
            include_ordinal,
            target,
            recursion_depth,
            parent_callsite,
        )
        record = {
            "source_template": scope.source_path,
            "callsite_action_sha256": _sha256(action.encode("utf-8")),
            "callsite_action_index": action_index,
            "include_ordinal": include_ordinal,
            "call_function": target.call_function,
            "callsite_identity": callsite_identity,
            "parent_callsite_identity": parent_callsite,
            "original_expression_sha256": _sha256(action.encode("utf-8")),
            "resolved_expression_type": target.expression_type,
            "operand_identities": [dict(item) for item in target.operands],
            "resolved_target_string": target.target_string,
            "resolved_target_kind": target.target_kind,
            "resolved_target_identity": target.target_identity,
            "target_source_template": target.target_scope.source_path,
            "target_source_sha256": target.target_source_sha256,
            "recursion_depth": recursion_depth,
            "reached_dangerous_actions": [],
            "excluded_dangerous_actions": [],
            "child_callsite_identities": [],
            "resolution_identity": "",
        }
        assert state.dynamic_include_evidence is not None
        state.dynamic_include_evidence.append(record)
        evidence_start = len(state.dynamic_include_evidence)
        excluded_start = len(state.excluded)
        assert state.reachable_details is not None
        reachable_start = len(state.reachable_details)
        if execution_state is True:
            if target.target_kind == "NAMED_TEMPLATE":
                state.reached_definitions.add(target.target_string)
            _evaluate_scope(
                target.target_scope,
                index,
                values,
                state,
                initial=True,
                call_stack=call_stack,
                tpl_depth=tpl_depth,
                tpl_stack=tpl_stack,
                tpl_call_stack=tpl_call_stack,
                dynamic_target_stack=(*dynamic_target_stack, target.target_identity),
                dynamic_callsite_stack=(*dynamic_callsite_stack, callsite_identity),
                nested_contract=nested_contract,
                file_chart_context=file_chart_context,
            )
        elif execution_state is None:
            if _scope_has_action_risk(target.target_scope, index, {target.target_identity}):
                state.ambiguous = True
        else:
            _record_excluded(
                state,
                target.target_scope,
                action,
                set(),
                set(),
                index,
            )
            for source, function, digest in _all_dangerous(
                target.target_scope, index, {target.target_identity}
            ):
                excluded_record = {
                    "source_template": source,
                    "action_class": (
                        "lookup" if function == "lookup" else "nondeterministic"
                    ),
                    "action_sha256": digest,
                }
                if excluded_record not in state.excluded:
                    state.excluded.append(excluded_record)
        record["reached_dangerous_actions"] = [
            dict(item) for item in state.reachable_details[reachable_start:]
        ]
        record["excluded_dangerous_actions"] = [
            dict(item) for item in state.excluded[excluded_start:]
        ]
        record["child_callsite_identities"] = [
            item["callsite_identity"]
            for item in state.dynamic_include_evidence[evidence_start:]
            if item["parent_callsite_identity"] == callsite_identity
        ]
        resolution_body = {
            "callsite_identity": callsite_identity,
            "original_expression_sha256": record["original_expression_sha256"],
            "resolved_expression_type": target.expression_type,
            "operand_identities": record["operand_identities"],
            "resolved_target_string": target.target_string,
            "resolved_target_kind": target.target_kind,
            "resolved_target_identity": target.target_identity,
            "target_source_template": target.target_scope.source_path,
            "target_source_sha256": target.target_source_sha256,
            "recursion_depth": recursion_depth,
            "reached_dangerous_actions": record["reached_dangerous_actions"],
            "excluded_dangerous_actions": record["excluded_dangerous_actions"],
            "child_callsite_identities": record["child_callsite_identities"],
        }
        record["resolution_identity"] = _canonical_sha(resolution_body)
    return True


def _tpl_callsite_identity(
    scope: _TemplateActionScope,
    action: str,
    action_index: int,
    tpl_ordinal: int,
    argument: _TplArgument,
    nesting_depth: int,
    parent_callsite_identity: str,
) -> str:
    body = {
        "source_template": scope.source_path,
        "callsite_action_sha256": _sha256(action.encode("utf-8")),
        "callsite_action_index": action_index,
        "tpl_ordinal": tpl_ordinal,
        "template_string_source": argument.source_kind,
        "template_string_path": argument.source_path,
        "nesting_depth": nesting_depth,
        "parent_callsite_identity": parent_callsite_identity,
    }
    if argument.protected_file is not None:
        body["protected_file_identity"] = _canonical_sha({
            "chart_identity": argument.protected_file.chart_identity,
            "chart_inventory_root_sha256": (
                argument.protected_file.chart_inventory_root_sha256
            ),
            "protected_path": argument.protected_file.protected_path,
            "relative_path": argument.protected_file.relative_path,
            "size": argument.protected_file.size,
            "sha256": argument.protected_file.sha256,
        })
    return _canonical_sha(body)


def _analyze_tpl_calls(
    action: str,
    scope: _TemplateActionScope,
    action_index: int,
    index: _TemplateActionIndex,
    values: dict,
    state: _ActionState,
    execution_state: bool | None,
    call_stack: tuple[str, ...],
    tpl_depth: int,
    tpl_stack: tuple[str, ...],
    tpl_call_stack: tuple[str, ...],
    dynamic_target_stack: tuple[str, ...],
    dynamic_callsite_stack: tuple[str, ...],
    file_chart_context: str | None,
) -> None:
    code = _unquoted_action(action)
    if _TPL_FUNCTION.search(code) is None or execution_state is False:
        return
    tokens = _action_tokens(action)
    if tokens is None:
        state.ambiguous = True
        return
    cursor = 0
    tpl_ordinal = 0
    while cursor < len(tokens):
        token = tokens[cursor]
        if token.quoted or token.text != "tpl":
            cursor += 1
            continue
        tpl_ordinal += 1
        resolved = _resolve_tpl_call(
            tokens, cursor, values, index, file_chart_context
        )
        if resolved is None:
            state.ambiguous = True
            cursor += 1
            continue
        argument, cursor = resolved
        nesting_depth = tpl_depth + 1
        content_bytes = argument.content.encode("utf-8")
        content_sha256 = _sha256(content_bytes)
        if (
            nesting_depth > _MAX_TPL_NESTING_DEPTH
            or content_sha256 in tpl_stack
            or len(content_bytes) > _MAX_TPL_EXPANDED_BYTES
            or state.tpl_expanded_bytes + len(content_bytes) > _MAX_TPL_EXPANDED_BYTES
        ):
            state.ambiguous = True
            continue
        try:
            nested_actions = _iter_template_actions(argument.content)
        except HelmMaterializationError:
            state.ambiguous = True
            continue
        if (
            len(nested_actions) > _MAX_TPL_NESTED_ACTIONS
            or state.tpl_nested_actions + len(nested_actions) > _MAX_TPL_NESTED_ACTIONS
        ):
            state.ambiguous = True
            continue
        state.tpl_expanded_bytes += len(content_bytes)
        state.tpl_nested_actions += len(nested_actions)
        parent_callsite_identity = (
            tpl_call_stack[-1]
            if tpl_call_stack
            else dynamic_callsite_stack[-1]
            if dynamic_callsite_stack
            else ""
        )
        callsite_identity = _tpl_callsite_identity(
            scope,
            action,
            action_index,
            tpl_ordinal,
            argument,
            nesting_depth,
            parent_callsite_identity,
        )
        nested_action_sha256 = [
            _sha256(item.encode("utf-8")) for item in nested_actions
        ]
        record = {
            "source_template": scope.source_path,
            "callsite_action_sha256": _sha256(action.encode("utf-8")),
            "callsite_action_index": action_index,
            "tpl_ordinal": tpl_ordinal,
            "callsite_identity": callsite_identity,
            "parent_callsite_identity": parent_callsite_identity,
            "template_string_source": argument.source_kind,
            "template_string_path": argument.source_path,
            "template_string_sha256": content_sha256,
            "protected_values_sha256": state.protected_values_sha256,
            "nesting_depth": nesting_depth,
            "expanded_template_bytes": len(content_bytes),
            "nested_action_sha256": nested_action_sha256,
            "nested_action_count": len(nested_actions),
            "reached_dangerous_actions": [],
            "excluded_dangerous_actions": [],
            "nested_action_graph_identity": "",
        }
        if argument.protected_file is not None:
            protected_file_body = {
                "chart_context": argument.protected_file.chart_context,
                "chart_identity": argument.protected_file.chart_identity,
                "chart_inventory_root_sha256": (
                    argument.protected_file.chart_inventory_root_sha256
                ),
                "protected_path": argument.protected_file.protected_path,
                "relative_path": argument.protected_file.relative_path,
                "size": argument.protected_file.size,
                "sha256": argument.protected_file.sha256,
                "files_get_expression_sha256": _sha256(
                    (
                        ".Files.Get "
                        + json.dumps(argument.protected_file.relative_path)
                    ).encode("utf-8")
                ),
            }
            protected_file_identity = _canonical_sha({
                key: value
                for key, value in protected_file_body.items()
                if key not in {"chart_context", "files_get_expression_sha256"}
            })
            protected_file_body["protected_file_identity"] = protected_file_identity
            protected_file_body["protected_render_input_identity"] = _canonical_sha({
                "chart_identity": argument.protected_file.chart_identity,
                "chart_inventory_root_sha256": (
                    argument.protected_file.chart_inventory_root_sha256
                ),
                "protected_values_sha256": state.protected_values_sha256,
            })
            record["protected_file"] = protected_file_body
        assert state.tpl_evidence is not None
        state.tpl_evidence.append(record)
        excluded_start = len(state.excluded)
        assert state.reachable_details is not None
        reachable_start = len(state.reachable_details)
        if nested_actions:
            _evaluate_scope(
                _TemplateActionScope(scope.source_path, nested_actions),
                index,
                values,
                state,
                initial=execution_state,
                call_stack=call_stack,
                tpl_depth=nesting_depth,
                tpl_stack=(*tpl_stack, content_sha256),
                tpl_call_stack=(*tpl_call_stack, callsite_identity),
                dynamic_target_stack=dynamic_target_stack,
                dynamic_callsite_stack=dynamic_callsite_stack,
                nested_contract=True,
                file_chart_context=file_chart_context,
            )
        record["reached_dangerous_actions"] = [
            dict(item) for item in state.reachable_details[reachable_start:]
        ]
        record["excluded_dangerous_actions"] = [
            dict(item) for item in state.excluded[excluded_start:]
        ]
        graph_body = {
            "callsite_identity": callsite_identity,
            "template_string_sha256": content_sha256,
            "nesting_depth": nesting_depth,
            "nested_action_sha256": nested_action_sha256,
            "reached_dangerous_actions": record["reached_dangerous_actions"],
            "excluded_dangerous_actions": record["excluded_dangerous_actions"],
        }
        record["nested_action_graph_identity"] = _canonical_sha(graph_body)


def _evaluate_scope(
    scope: _TemplateActionScope,
    index: _TemplateActionIndex,
    values: dict,
    state: _ActionState,
    *,
    initial: bool | None = True,
    call_stack: tuple[str, ...] = (),
    tpl_depth: int = 0,
    tpl_stack: tuple[str, ...] = (),
    tpl_call_stack: tuple[str, ...] = (),
    dynamic_target_stack: tuple[str, ...] = (),
    dynamic_callsite_stack: tuple[str, ...] = (),
    nested_contract: bool = False,
    file_chart_context: str | None = None,
) -> None:
    active = initial
    controls: list[tuple[bool | None, bool | None]] = []
    for action_index, action in enumerate(scope.actions):
        code = _unquoted_action(action).strip()
        functions, calls, dynamic = _action_parts(action)
        # Control expressions execute under the parent state, before the body
        # reachability is selected.
        execution_state = active
        if _CONTROL_ELSE.match(code) or _CONTROL_END.match(code):
            execution_state = False
        if execution_state is not False and nested_contract and not _nested_action_is_bounded(
            action, values
        ):
            state.ambiguous = True
        _analyze_tpl_calls(
            action,
            scope,
            action_index,
            index,
            values,
            state,
            execution_state,
            call_stack,
            tpl_depth,
            tpl_stack,
            tpl_call_stack,
            dynamic_target_stack,
            dynamic_callsite_stack,
            file_chart_context,
        )
        dynamic_resolved = _analyze_dynamic_include_calls(
            action,
            scope,
            action_index,
            index,
            values,
            state,
            execution_state,
            call_stack,
            tpl_depth,
            tpl_stack,
            tpl_call_stack,
            dynamic_target_stack,
            dynamic_callsite_stack,
            nested_contract,
            file_chart_context,
        )
        if execution_state is True:
            state.reachable_functions.update(functions)
            _record_reachable(state, scope, action, functions)
            state.ambiguous = state.ambiguous or (dynamic and not dynamic_resolved)
        elif execution_state is None:
            if functions or (dynamic and not dynamic_resolved):
                state.ambiguous = True
            for name in calls:
                called = index.definitions.get(name)
                if called is None or name in call_stack:
                    state.ambiguous = True
                    continue
                if len(call_stack) >= _MAX_TEMPLATE_CALL_DEPTH:
                    state.ambiguous = True
                    continue
                # An unknown outer branch does not make a referenced helper
                # ambiguous when every possible participating action inside
                # that helper is itself bounded and non-dangerous. Analyze it
                # under the unknown state so the same tpl/file/danger rules
                # decide that question; never infer safety from output bytes.
                _evaluate_scope(
                    called,
                    index,
                    values,
                    state,
                    initial=None,
                    call_stack=(*call_stack, name),
                    tpl_depth=tpl_depth,
                    tpl_stack=tpl_stack,
                    tpl_call_stack=tpl_call_stack,
                    dynamic_target_stack=dynamic_target_stack,
                    dynamic_callsite_stack=dynamic_callsite_stack,
                    nested_contract=nested_contract,
                    file_chart_context=file_chart_context,
                )
        elif execution_state is False:
            _record_excluded(state, scope, action, functions, calls, index)
        if execution_state is True:
            for name in sorted(calls):
                called = index.definitions.get(name)
                if called is None:
                    state.ambiguous = True
                    continue
                if name in call_stack:
                    continue
                if len(call_stack) >= _MAX_TEMPLATE_CALL_DEPTH:
                    state.ambiguous = True
                    continue
                state.reached_definitions.add(name)
                _evaluate_scope(
                    called, index, values, state,
                    initial=True, call_stack=(*call_stack, name),
                    tpl_depth=tpl_depth, tpl_stack=tpl_stack,
                    tpl_call_stack=tpl_call_stack,
                    dynamic_target_stack=dynamic_target_stack,
                    dynamic_callsite_stack=dynamic_callsite_stack,
                    nested_contract=nested_contract,
                    file_chart_context=file_chart_context,
                )

        start = re.match(
            r"^(if|with|range|block)(?:\s+(.*))?$", action.strip(), re.DOTALL
        )
        if start is not None:
            expression = (start.group(2) or "").strip()
            selected = None if start.group(1) == "block" else _condition(expression, values)
            controls.append((active, selected))
            active = _combine(active, selected)
            continue
        alternate = _CONTROL_ELSE.match(action.strip())
        if alternate is not None:
            if not controls:
                state.ambiguous = True
                continue
            parent, selected = controls[-1]
            if alternate.group(1) is None:
                inverse = None if selected is None else not selected
                active = _combine(parent, inverse)
            else:
                inverse = None if selected is None else not selected
                active = _combine(_combine(parent, inverse), _condition(alternate.group(1), values))
            continue
        if _CONTROL_END.match(code):
            if not controls:
                state.ambiguous = True
            else:
                active, _selected = controls.pop()
            continue

        if active is False:
            _record_excluded(state, scope, action, functions, calls, index)
    if controls:
        state.ambiguous = True


def _participating_action_analysis(
    actions: _TemplateActionIndex,
    documents: tuple[HelmRenderedDocument, ...],
    values: dict,
    values_sha256: str,
) -> tuple[str | None, dict]:
    sources = tuple(sorted({item.source_template for item in documents}))
    state = _ActionState(
        set(), set(), [], protected_values_sha256=values_sha256
    )
    for path in sources:
        scope = actions.roots.get(path)
        if scope is None:
            state.ambiguous = True
            continue
        _evaluate_scope(
            scope,
            actions,
            _values_for_source(values, path),
            state,
            file_chart_context=actions.source_chart_contexts.get(path),
        )
    if "lookup" in state.reachable_functions:
        return "CLUSTER_STATE_REQUIRED", {}
    if state.reachable_functions:
        return "NONDETERMINISTIC_RENDER", {}
    if state.ambiguous:
        raise HelmMaterializationError(
            "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
            "participating Helm template action reachability is not exactly provable",
        )
    excluded = sorted(
        state.excluded,
        key=lambda item: (
            item["source_template"], item["action_class"], item["action_sha256"]
        ),
    )
    tpl_by_callsite: dict[str, dict] = {}
    tpl_evidence: list[dict] = []
    for item in state.tpl_evidence or []:
        callsite = item["callsite_identity"]
        existing = tpl_by_callsite.get(callsite)
        if existing is not None and existing != item:
            raise HelmMaterializationError(
                "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
                "a Helm tpl source callsite has contradictory bounded evidence",
            )
        if existing is None:
            tpl_evidence.append(item)
        tpl_by_callsite[callsite] = item
    body = {
        "contract": "helm-template-action-reachability-v1",
        "status": "PASS",
        "reason_code": "BOUNDED_TEMPLATE_ACTION_REACHABILITY_PROVEN",
        "protected_values_sha256": values_sha256,
        "participating_source_templates": list(sources),
        "reachable_named_templates": sorted(state.reached_definitions),
        "excluded_dangerous_actions": excluded,
        "excluded_dangerous_action_count": len(excluded),
        "tpl_evidence": tpl_evidence,
        "tpl_evidence_count": len(tpl_evidence),
        "tpl_limits": {
            "maximum_nesting_depth": _MAX_TPL_NESTING_DEPTH,
            "maximum_expanded_template_bytes": _MAX_TPL_EXPANDED_BYTES,
            "maximum_nested_actions": _MAX_TPL_NESTED_ACTIONS,
            "maximum_named_template_call_depth": _MAX_TEMPLATE_CALL_DEPTH,
        },
        "dynamic_include_evidence": state.dynamic_include_evidence,
        "dynamic_include_evidence_count": len(state.dynamic_include_evidence or []),
        "dynamic_include_limits": {
            "maximum_resolution_depth": _MAX_DYNAMIC_INCLUDE_DEPTH,
            "maximum_call_graph_nodes": _MAX_DYNAMIC_INCLUDE_NODES,
            "maximum_parsed_action_bytes": _MAX_DYNAMIC_INCLUDE_ACTION_BYTES,
            "maximum_resolved_targets": _MAX_DYNAMIC_INCLUDE_TARGETS,
        },
    }
    body["analysis_identity"] = _canonical_sha(body)
    return None, body


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


def _namespace_expression(source: str) -> str | None:
    declarations = []
    for item in _NAMESPACE_LINE.findall(source):
        compact = item.strip()
        if (
            len(compact) >= 2
            and compact[0] == compact[-1]
            and compact[0] in {"'", '"'}
        ):
            compact = compact[1:-1].strip()
        if re.fullmatch(
            r"{{-?\s*\$?\.Release\.Namespace(?:\s*\|\s*quote)?\s*-?}}",
            compact,
        ):
            compact = "{{ .Release.Namespace }}"
        include = re.fullmatch(
            r'{{-?\s*include\s+"([^"\r\n]+)"\s+[.$]\s*-?}}', compact
        )
        if include is not None:
            compact = f'{{{{ include "{include.group(1)}" . }}}}'
        declarations.append(compact)
    if not declarations:
        return None
    unique = tuple(dict.fromkeys(declarations))
    if len(unique) != 1:
        raise HelmMaterializationError(
            "AMBIGUOUS_NAMESPACE_PROVENANCE",
            "source template contains contradictory namespace declarations",
        )
    return unique[0]


def _namespace_helper_value(
    scope: _TemplateActionScope, values: dict, release_namespace: str
) -> str | None:
    actions = tuple(item.strip() for item in scope.actions)

    def direct(expression: str) -> str | None:
        if expression in {".Release.Namespace", "$.Release.Namespace"}:
            return release_namespace
        value = _value_at(values, expression)
        return value if type(value) is str else None

    if len(actions) == 1:
        value = direct(actions[0])
        if value is not None:
            return value
        tokens = _action_tokens(actions[0])
        if tokens is None:
            return None
        words = tuple((item.text, item.quoted) for item in tokens)
        if len(words) >= 3 and words[0] == ("default", False):
            release = words[1] in {
                (".Release.Namespace", False), ("$.Release.Namespace", False)
            }
            value_path = words[2][0] if not words[2][1] else ""
            if (
                not release
                or _VALUES_PATH.fullmatch(value_path) is None
                or values.get(_UNMODELED_VALUES) is True
            ):
                return None
            found, protected = _exact_value_at(values, value_path)
            if not found:
                protected = None
            selected = release_namespace if not _truth(protected) else protected
            if type(selected) is not str:
                return None
            if len(words) == 3:
                return selected
            expected_tail = (
                ("|", False), ("trunc", False), ("63", False),
                ("|", False), ("trimSuffix", False), ("-", True),
            )
            if words[3:] != expected_tail:
                return None
            raw = selected.encode("utf-8")[:63]
            try:
                truncated = raw.decode("utf-8", errors="strict")
            except UnicodeError:
                return None
            return truncated[:-1] if truncated.endswith("-") else truncated
        return None

    if len(actions) == 5:
        condition = re.fullmatch(r"if\s+(\.?\$?\.Values\.[A-Za-z0-9_.-]+)", actions[0])
        alternate = _CONTROL_ELSE.fullmatch(actions[2])
        if condition is None or alternate is None or actions[4] != "end":
            return None
        path = condition.group(1).replace(".$.", "$.")
        if actions[1] != path or actions[3] not in {
            ".Release.Namespace", "$.Release.Namespace"
        }:
            return None
        if values.get(_UNMODELED_VALUES) is True:
            return None
        found, protected = _exact_value_at(values, path)
        if not found:
            protected = None
        selected = protected if _truth(protected) else release_namespace
        return selected if type(selected) is str else None
    return None


def _namespace_call(
    expression: str, source_text: str
) -> tuple[str, str] | None:
    """Recognize only the closed a8 literal helper call/context grammar."""
    nodes = _template_nodes(expression)
    if len(nodes) != 1 or nodes[0][0] != "action":
        return None
    words = nodes[0][3]
    if len(words) not in {3, 5}:
        return None
    function, name, context = words[:3]
    if function not in {("include", False), ("template", False)} or not name[1]:
        return None
    if len(words) == 5 and words[3:] != (("|", False), ("quote", False)):
        return None
    if context in {(".", False), ("$", False)}:
        return name[0], context[0]
    if context != ("$root", False):
        return None
    call_action = " ".join(
        json.dumps(value) if quoted else value for value, quoted in words
    )
    depth = 0
    bound = False
    call_seen = False
    for action in _iter_template_actions(source_text):
        compact = action.strip()
        code = _unquoted_action(compact)
        if compact in {"$root := .", "$root := $"}:
            if depth != 0 or bound or call_seen:
                return None
            bound = True
            continue
        if re.match(r"^\$root\s*(?::=|=)", compact):
            return None
        if call_action == compact:
            if not bound:
                return None
            call_seen = True
        if _CONTROL_START.match(code):
            depth += 1
        elif _CONTROL_END.match(code):
            depth = max(0, depth - 1)
    return (name[0], "$root") if call_seen else None


def _custom_resource_scopes(sources: dict[str, str]) -> dict[tuple[str, str], str]:
    """Derive custom-resource scope only from exact local CRD source bytes."""
    result: dict[tuple[str, str], str] = {}
    for path, text in sources.items():
        if "crds" not in PurePosixPath(path).parts:
            continue
        try:
            documents = tuple(
                yaml.load_all(text, Loader=_StrictSafeLoader)
            )
        except yaml.YAMLError:
            # Templated or otherwise non-static CRDs cannot prove resource scope.
            continue
        for document in documents:
            if type(document) is not dict or document.get("kind") != "CustomResourceDefinition":
                continue
            specification = document.get("spec")
            if type(specification) is not dict:
                continue
            names = specification.get("names")
            group = specification.get("group")
            scope = specification.get("scope")
            kind = names.get("kind") if type(names) is dict else None
            if (
                type(group) is not str
                or type(kind) is not str
                or scope not in {"Cluster", "Namespaced"}
            ):
                continue
            key = (group, kind)
            prior = result.get(key)
            if prior is not None and prior != scope:
                raise HelmMaterializationError(
                    "AMBIGUOUS_NAMESPACE_PROVENANCE",
                    "local CRD sources contradict resource scope",
                )
            result[key] = scope
    return result


def _resource_scope(
    api_version: str,
    kind: str,
    custom_scopes: dict[tuple[str, str], str],
) -> str:
    group = api_version.split("/", 1)[0] if "/" in api_version else ""
    key = (group, kind)
    if key in _CLUSTER_SCOPED_GROUP_KINDS:
        return "Cluster"
    if group in _NAMESPACED_GROUPS:
        return "Namespaced"
    scope = custom_scopes.get(key)
    if scope is None:
        raise HelmMaterializationError(
            "AMBIGUOUS_NAMESPACE_PROVENANCE",
            "rendered custom-resource scope is not proven by local CRD evidence",
        )
    return scope


def _namespace_provenance(
    *,
    api_version: str,
    kind: str,
    explicit_namespace: object,
    release_namespace: str,
    source_template: str,
    source_text: str,
    values: dict,
    actions: _TemplateActionIndex,
    custom_scopes: dict[tuple[str, str], str],
    logical_values: dict | None = None,
) -> tuple[str, MappingProxyType]:
    if explicit_namespace == "":
        explicit_namespace = None
    helper_evidence: dict | None = None
    if explicit_namespace is not None and type(explicit_namespace) is not str:
        raise HelmMaterializationError(
            "MISSING_RENDERED_RESOURCE_IDENTITY", "rendered namespace is not a string"
        )
    scope = _resource_scope(api_version, kind, custom_scopes)
    if scope == "Cluster":
        effective = None
        resolution = "CLUSTER_SCOPED"
        value_path = ""
        value_sha = ""
        expression = (
            _namespace_expression(source_text)
            if explicit_namespace is not None
            else ""
        ) or ""
        contradiction = "NONE"
        # The API server clears namespace before validating a cluster-scoped
        # object. Keep the emitted value in provenance, while using the value
        # Checkov actually reports as the scanner-facing address segment.
        canonical_namespace = explicit_namespace or "default"
    elif explicit_namespace is None:
        effective = release_namespace
        resolution = "HELM_RELEASE_NAMESPACE_DEFAULT"
        value_path = ""
        value_sha = ""
        expression = ""
        contradiction = "NONE"
        canonical_namespace = release_namespace
    else:
        effective = explicit_namespace
        canonical_namespace = explicit_namespace
        expression = _namespace_expression(source_text)
        value_path = ""
        value_sha = ""
        contradiction = (
            "NONE" if explicit_namespace == release_namespace
            else "EXPLICIT_NAMESPACE_OVERRIDES_RELEASE_NAMESPACE"
        )
        if expression is None:
            resolution = "EXPLICIT_RENDERED_NAMESPACE"
            expression = ""
        else:
            compact = expression.strip()
            if (
                len(compact) >= 2
                and compact[0] == compact[-1]
                and compact[0] in {"'", '"'}
            ):
                compact = compact[1:-1].strip()
            release_match = re.fullmatch(
                r"{{-?\s*\$?\.Release\.Namespace(?:\s*\|\s*quote)?\s*-?}}", compact
            )
            value_match = re.fullmatch(
                r"{{-?\s*\.Values\.([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)"
                r"(?:\s*\|\s*quote)?\s*-?}}",
                compact,
            )
            value_default_release_match = re.fullmatch(
                r"{{-?\s*\.Values\.([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)"
                r"\s*\|\s*default\s+\.Release\.Namespace(?:\s*\|\s*quote)?\s*-?}}",
                compact,
            )
            namespace_call = _namespace_call(compact, source_text)
            if release_match is not None:
                resolution = "RELEASE_NAMESPACE_EXPRESSION"
                if explicit_namespace != release_namespace:
                    contradiction = "RELEASE_NAMESPACE_EXPRESSION_CONTRADICTS_RENDER"
            elif namespace_call is not None:
                helper_name, helper_context = namespace_call
                members = actions.definition_members.get(helper_name, ())
                if not members:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_NAMESPACE_PROVENANCE",
                        "named namespace template is outside the bounded proof contract",
                    )
                resolved_members = tuple(
                    _namespace_helper_value(member, values, release_namespace)
                    for member in members
                )
                if any(item is None for item in resolved_members):
                    raise HelmMaterializationError(
                        "HELM_NAMESPACE_HELPER_BODY_UNSUPPORTED",
                        "named namespace helper is outside the closed result grammar",
                    )
                if len(set(resolved_members)) != 1:
                    raise HelmMaterializationError(
                        "HELM_TEMPLATE_CONSUMER_VALUE_MISMATCH",
                        "equivalent namespace helpers produced different values",
                    )
                resolved = resolved_members[0]
                if resolved != explicit_namespace:
                    raise HelmMaterializationError(
                        "CONTRADICTORY_NAMESPACE_PROVENANCE",
                        "named namespace template contradicts rendered metadata",
                    )
                resolution = "STATIC_NAMED_NAMESPACE_TEMPLATE"
                value_path = helper_name
                value_sha = _sha256(resolved.encode("utf-8"))
                member_records = []
                graph = actions.definition_graphs.get(helper_name)
                if graph is None:
                    raise HelmMaterializationError(
                        "HELM_NAMESPACE_HELPER_EQUIVALENCE_UNPROVEN",
                        "namespace helper equivalence graph is unavailable",
                    )
                graph_sha = _canonical_sha(graph)
                for member, member_value in zip(members, resolved_members):
                    source = actions.sources.get(member.source_path)
                    if source is None:
                        raise HelmMaterializationError(
                            "HELM_TEMPLATE_DEFINITION_SOURCE_MUTATED",
                            "namespace helper source is unavailable",
                        )
                    member_records.append({
                        "source_path": member.source_path,
                        "source_sha256": _sha256(source.encode("utf-8")),
                        "definition_ordinal": member.definition_ordinal,
                        "definition_span_sha256": member.definition_span_sha256,
                        "action_graph_sha256": graph_sha,
                        "consumer_value_sha256": _sha256(
                            member_value.encode("utf-8")
                        ),
                    })
                helper_evidence = {
                    "call_kind": _template_nodes(compact)[0][3][0][0],
                    "literal_helper_name": helper_name,
                    "context_kind": helper_context,
                    "members": member_records,
                    "equivalence_identity": _canonical_sha(member_records),
                    "consumer_value_sha256": value_sha,
                }
            elif value_default_release_match is not None:
                resolution = "VALUES_DEFAULT_RELEASE_NAMESPACE_EXPRESSION"
                value_path = value_default_release_match.group(1)
                protected = _value_at(values, f".Values.{value_path}")
                if protected is _UNKNOWN:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_NAMESPACE_PROVENANCE",
                        "values-derived namespace default lacks an exact protected value",
                    )
                selected = release_namespace if not _truth(protected) else protected
                if type(selected) is not str:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_NAMESPACE_PROVENANCE",
                        "values-derived namespace default is not an exact string",
                    )
                value_sha = _canonical_sha(protected)
                if selected != explicit_namespace:
                    raise HelmMaterializationError(
                        "CONTRADICTORY_NAMESPACE_PROVENANCE",
                        "values-derived namespace default contradicts rendered metadata",
                    )
            elif value_match is not None:
                resolution = "VALUES_NAMESPACE_EXPRESSION"
                value_path = value_match.group(1)
                protected = _value_at(values, f".Values.{value_path}")
                if type(protected) is not str:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_NAMESPACE_PROVENANCE",
                        "values-derived namespace is not an exact protected string",
                    )
                value_sha = _sha256(protected.encode("utf-8"))
                if protected != explicit_namespace:
                    raise HelmMaterializationError(
                        "CONTRADICTORY_NAMESPACE_PROVENANCE",
                        "values-derived namespace contradicts rendered metadata",
                    )
            elif len(_template_nodes(compact)) == 1 and _template_nodes(compact)[0][0] == "action":
                node = _template_nodes(compact)[0]
                action_text = " ".join(
                    json.dumps(value) if quoted else value
                    for value, quoted in node[3]
                )
                bounded = _namespace_helper_value(
                    _TemplateActionScope(source_template, (action_text,)),
                    values,
                    release_namespace,
                )
                if bounded is None:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_NAMESPACE_PROVENANCE",
                        "namespace pipeline is outside the closed normalization grammar",
                    )
                if bounded != explicit_namespace:
                    raise HelmMaterializationError(
                        "HELM_NAMESPACE_RENDER_CONTRADICTION",
                        "bounded namespace expression contradicts rendered metadata",
                    )
                resolution = "BOUNDED_NAMESPACE_EXPRESSION"
                value_sha = _sha256(bounded.encode("utf-8"))
            elif "{{" in compact or "}}" in compact:
                raise HelmMaterializationError(
                    "AMBIGUOUS_NAMESPACE_PROVENANCE",
                    "dynamic namespace construction is outside the bounded proof contract",
                )
            else:
                try:
                    literal = yaml.load(compact, Loader=_StrictSafeLoader)
                except yaml.YAMLError as exc:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_NAMESPACE_PROVENANCE",
                        "literal namespace source cannot be parsed",
                    ) from exc
                if literal != explicit_namespace:
                    raise HelmMaterializationError(
                        "CONTRADICTORY_NAMESPACE_PROVENANCE",
                        "literal namespace source contradicts rendered metadata",
                    )
                resolution = "LITERAL_NAMESPACE_EXPRESSION"
    body = {
        "contract": "helm-namespace-provenance-v1",
        "request_namespace": release_namespace,
        "helm_argument_namespace": release_namespace,
        "release_namespace": release_namespace,
        "emitted_metadata_namespace": explicit_namespace,
        "effective_namespace": effective,
        "resolution": resolution,
        "source_template": source_template,
        "source_expression_sha256": _sha256(expression.encode("utf-8")) if expression else "",
        "value_path": value_path,
        "value_sha256": value_sha,
        "contradiction": contradiction,
    }
    if helper_evidence is not None:
        body["named_template_equivalence"] = helper_evidence
    if logical_values is not None:
        values_body = {
            **logical_values,
            "release_namespace": release_namespace,
        }
        body["logical_values_binding"] = {
            **values_body,
            "binding_identity": _canonical_sha(values_body),
        }
    body["provenance_identity"] = _canonical_sha(body)
    return canonical_namespace, MappingProxyType(body)


def _api_resource_identity(document: HelmRenderedDocument) -> str:
    """Return the Kubernetes API identity after namespace normalization."""
    provenance = document.namespace_provenance
    namespace = provenance["effective_namespace"]
    namespace_segment = "" if namespace is None else namespace
    return (
        f"{document.api_version}/{document.kind}/"
        f"{namespace_segment}/{document.name}"
    )


def _logical_values_by_context(
    dependencies: dict, root_effective_values_sha256: str
) -> dict[str, dict]:
    result = {
        ".": {
            "logical_instance_identity": ".",
            "source_marker_context": ".",
            "effective_values_root_sha256": root_effective_values_sha256,
            "values_provenance_identity": root_effective_values_sha256,
        }
    }

    def add(closure: dict) -> None:
        for artifact in closure["artifacts"]:
            logical = artifact.get("logical_instance")
            values_provenance = artifact.get("values_provenance")
            if logical is not None:
                if values_provenance is None:
                    raise HelmMaterializationError(
                        "HELM_DEPENDENCY_VALUES_PROVENANCE_INCOMPLETE",
                        "logical dependency lacks effective Values provenance",
                    )
                context = logical["source_marker_context"]
                if context in result:
                    raise HelmMaterializationError(
                        "HELM_DEPENDENCY_EFFECTIVE_NAME_COLLISION",
                        "logical dependency Values context is duplicated",
                    )
                result[context] = {
                    "logical_instance_identity": logical[
                        "logical_instance_identity"
                    ],
                    "source_marker_context": context,
                    "effective_values_root_sha256": logical[
                        "effective_values_root_sha256"
                    ],
                    "values_provenance_identity": values_provenance[
                        "provenance_identity"
                    ],
                }
            nested = artifact.get("dependencies")
            if nested is not None:
                add(nested)

    add(dependencies)
    return result


def _documents(
    stdout: bytes,
    *,
    chart_name: str,
    chart_files: tuple[HelmChartFile, ...],
    expanded_dependency_files: tuple[str, ...],
    release_namespace: str,
    template_actions: _TemplateActionIndex,
    protected_values: dict,
    logical_values_by_context: dict[str, dict],
) -> tuple[HelmRenderedDocument, ...]:
    result = []
    identities = set()
    api_identities = set()
    files = {item.path for item in chart_files} | set(expanded_dependency_files)
    custom_scopes = _custom_resource_scopes(template_actions.sources)
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
        source_text = template_actions.sources.get(source)
        if source_text is None:
            raise HelmMaterializationError(
                "AMBIGUOUS_SOURCE_PROVENANCE", "source template text is unavailable"
            )
        source_values = _values_for_source(protected_values, source)
        source_context = _chart_context_for_source(source)
        logical_values = logical_values_by_context.get(source_context)
        if logical_values is not None and logical_values[
            "effective_values_root_sha256"
        ] != _effective_values_sha256(source_values):
            raise HelmMaterializationError(
                "HELM_NAMESPACE_LOGICAL_VALUES_MISMATCH",
                "namespace proof Values differ from the protected logical instance",
            )
        namespace, namespace_provenance = _namespace_provenance(
            api_version=api_version,
            kind=kind,
            explicit_namespace=metadata.get("namespace"),
            release_namespace=release_namespace,
            source_template=source,
            source_text=source_text,
            values=source_values,
            actions=template_actions,
            custom_scopes=custom_scopes,
            logical_values=logical_values,
        )
        identity = f"{api_version}/{kind}/{namespace}/{name}"
        if identity in identities:
            raise HelmMaterializationError(
                "DUPLICATE_RENDERED_IDENTITY", "rendered resource identity is duplicated"
            )
        identities.add(identity)
        document = HelmRenderedDocument(
            index,
            _sha256(raw),
            api_version,
            kind,
            namespace,
            name,
            identity,
            source,
            source_chart,
            namespace_provenance,
        )
        api_identity = _api_resource_identity(document)
        if api_identity in api_identities:
            raise HelmMaterializationError(
                "DUPLICATE_RENDERED_IDENTITY",
                "rendered resources normalize to the same Kubernetes API identity",
            )
        api_identities.add(api_identity)
        result.append(document)
    if not result:
        raise HelmMaterializationError(
            "MISSING_RENDERED_RESOURCE_IDENTITY", "Helm rendered no Kubernetes resources"
        )
    return tuple(result)


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
    root_values, _root_values_sha = _protected_values(spec)
    dependencies = _validate_dependencies(
        spec.chart_root,
        chart_value,
        protected_values=root_values,
        repository_root=spec.protected_repository_root,
    )
    protected_values, protected_values_sha = _protected_values(spec, dependencies)
    root_effective_values_sha256 = _effective_values_sha256(protected_values)
    logical_values_by_context = _logical_values_by_context(
        dependencies, root_effective_values_sha256
    )
    actions = _template_actions(
        spec.chart_root,
        dependencies,
        chart_root_sha,
        spec.protected_repository_root,
    )
    expanded_dependency_files = tuple(sorted(actions.sources))
    executable = _helm_identity(spec.helm_executable, spec.chart_root)
    with tempfile.TemporaryDirectory(prefix="iacgv-helm-renders-") as temporary:
        temp = Path(temporary)
        render_spec = _sealed_helm_chart(spec, dependencies, temp / "protected-chart")
        sealed_files, sealed_root_sha = _inventory(render_spec.chart_root)
        first_stdout, first_stderr, safe_argv, argv_sha = _render(
            render_spec, temp / "first"
        )
        if any(
            marker in first_stderr.lower()
            for marker in (b"permission denied", b"operation not permitted", b"read-only")
        ):
            raise HelmMaterializationError(
                "CHART_MUTATED_DURING_RENDER",
                "render attempted to mutate the sealed protected chart",
            )
        if _inventory(render_spec.chart_root) != (sealed_files, sealed_root_sha):
            raise HelmMaterializationError(
                "CHART_MUTATED_DURING_RENDER",
                "sealed protected chart changed during first render",
            )
        if _sha256(spec.helm_executable.read_bytes()) != executable["executable_sha256"]:
            raise HelmMaterializationError(
                "HELM_ENVIRONMENT_INCOMPLETE", "Helm executable changed before rendering"
            )
        first_documents = _documents(
            first_stdout,
            chart_name=chart_name,
            chart_files=chart_files,
            expanded_dependency_files=expanded_dependency_files,
            release_namespace=spec.namespace,
            template_actions=actions,
            protected_values=protected_values,
            logical_values_by_context=logical_values_by_context,
        )
        inactive_contexts = _inactive_dependency_contexts(dependencies)
        if any(
            document.source_template == context
            or document.source_template.startswith(f"{context}/")
            for document in first_documents for context in inactive_contexts
        ):
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_SOURCE_MARKER_CONTRADICTION",
                "rendered source marker belongs to an inactive logical dependency",
            )
        action_failure, action_reachability = _participating_action_analysis(
            actions, first_documents, protected_values, protected_values_sha
        )
        if action_failure == "CLUSTER_STATE_REQUIRED":
            raise HelmMaterializationError(
                action_failure, "a participating Helm template requires live cluster lookup"
            )
        second_stdout, second_stderr, second_argv, second_argv_sha = _render(
            render_spec, temp / "second"
        )
        if _inventory(render_spec.chart_root) != (sealed_files, sealed_root_sha):
            raise HelmMaterializationError(
                "CHART_MUTATED_DURING_RENDER",
                "sealed protected chart changed during second render",
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
            release_namespace=spec.namespace,
            template_actions=actions,
            protected_values=protected_values,
            logical_values_by_context=logical_values_by_context,
        )
        if any(
            document.source_template == context
            or document.source_template.startswith(f"{context}/")
            for document in second_documents for context in inactive_contexts
        ):
            raise HelmMaterializationError(
                "HELM_DEPENDENCY_SOURCE_MARKER_CONTRADICTION",
                "second render contradicts dependency activation evidence",
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
        "protected_root_effective_values_sha256": root_effective_values_sha256,
        "template_action_reachability": action_reachability,
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


@contextmanager
def materialize_helm_universe(
    charts: tuple[HelmUniverseChart, ...],
) -> Iterator[HelmMaterializedUniverse]:
    """Render an ordered set of charts and bind one cross-chart scan universe."""
    if (
        type(charts) is not tuple
        or not charts
        or len(charts) > 32
        or any(type(item) is not HelmUniverseChart for item in charts)
    ):
        raise DomainError("Helm universe requires one to 32 exact chart requests")
    keys = [item.universe_key for item in charts]
    if len(keys) != len(set(keys)):
        raise DomainError("Helm universe chart keys must be unique")

    protected_compatibility = {
        (
            item.specification.helm_executable,
            item.specification.kube_version,
            item.specification.api_versions,
        )
        for item in charts
    }
    if len(protected_compatibility) != 1:
        raise DomainError(
            "Helm universe charts require one executable, kube version, and API set"
        )

    with tempfile.TemporaryDirectory(prefix="iacgv-helm-universe-") as temporary:
        root = Path(temporary)
        materialized: list[tuple[str, HelmMaterializationEvidence]] = []
        ownership: list[tuple[str, HelmRenderedDocument]] = []
        bundles: list[bytes] = []
        for index, item in enumerate(charts, start=1):
            chart_root = root / "charts" / f"{index:02d}-{item.universe_key}"
            evidence = materialize_helm(item.specification, chart_root)
            materialized.append((item.universe_key, evidence))
            ownership.extend(
                (item.universe_key, document) for document in evidence.documents
            )
            bundles.append((chart_root / "rendered.yaml").read_bytes())

        identities = [document.resource_identity for _key, document in ownership]
        if len(identities) != len(set(identities)):
            raise HelmMaterializationError(
                "DUPLICATE_RENDERED_IDENTITY",
                "multiple charts render the same canonical Kubernetes resource",
            )
        api_identities = [
            _api_resource_identity(document) for _key, document in ownership
        ]
        if len(api_identities) != len(set(api_identities)):
            raise HelmMaterializationError(
                "DUPLICATE_RENDERED_IDENTITY",
                "multiple charts render resources with the same Kubernetes API identity",
            )

        fragments = []
        for bundle in bundles:
            fragment = bundle.strip()
            if not fragment.startswith(b"---"):
                fragment = b"---\n" + fragment
            fragments.append(fragment)
        combined_bytes = b"\n".join(fragments) + b"\n"
        if len(combined_bytes) > _MAX_RENDER_BYTES:
            raise HelmMaterializationError(
                "HELM_OUTPUT_LIMIT_EXCEEDED",
                "combined Helm universe exceeds its rendered byte limit",
            )
        scanner_root = root / "combined"
        scanner_root.mkdir(mode=0o700)
        rendered = scanner_root / "rendered.yaml"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(rendered, flags, 0o600)
        try:
            offset = 0
            while offset < len(combined_bytes):
                written = os.write(descriptor, combined_bytes[offset:])
                if written <= 0:
                    raise HelmMaterializationError(
                        "HELM_STATE_NOT_ISOLATED",
                        "combined rendered bundle write did not complete",
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        ownership_payload = [
            {"universe_key": key, "document": document.canonical_dict()}
            for key, document in ownership
        ]
        combined_output = {
            "rendered_bundle_path": "rendered.yaml",
            "rendered_bundle_sha256": _sha256(combined_bytes),
            "rendered_bundle_bytes": len(combined_bytes),
            "document_inventory_sha256": _canonical_sha(ownership_payload),
            "chart_count": len(materialized),
            "resource_count": len(ownership),
        }
        identity_body = {
            "ordered_materialization_ids": [
                {"universe_key": key, "materialization_identity": evidence.materialization_identity}
                for key, evidence in materialized
            ],
            "combined_output": combined_output,
            "resource_ownership": ownership_payload,
        }
        yield HelmMaterializedUniverse(
            scanner_root,
            tuple(materialized),
            MappingProxyType(combined_output),
            tuple(ownership),
            _canonical_sha(identity_body),
        )


__all__ = [
    "HELM_MATERIALIZATION_CONTRACT",
    "HELM_UNIVERSE_CONTRACT",
    "HelmMaterializationError",
    "HelmMaterializationEvidence",
    "HelmMaterializedPair",
    "HelmMaterializedUniverse",
    "HelmRenderSpec",
    "HelmUniverseChart",
    "materialize_helm",
    "materialize_helm_comparison",
    "materialize_helm_universe",
]
