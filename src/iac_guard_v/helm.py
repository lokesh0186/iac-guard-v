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
import shlex
import stat
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Iterator

import yaml

from .enums import Status
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
class _TemplateActionScope:
    source_path: str
    actions: tuple[str, ...]


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
        if (
            type(locked) is not list
            or tuple(_dependency_key(item) for item in locked) != dependencies
        ):
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
        lock_relevance = "PARTICIPATING"
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
    declared_entries = {
        value
        for name, version, _repository in dependencies
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
        artifacts.append({
            "name": child_name,
            "version": str(child_version),
            "form": "directory",
            "expanded_files": [],
        })
    return {
        "count": len(artifacts),
        "chart_lock_sha256": lock_hash,
        "chart_lock_relevance": lock_relevance,
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
) -> dict[str, dict[str, _ProtectedTplFile]]:
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
    for artifact in dependencies["artifacts"]:
        context = f"charts/{artifact['name']}"
        if artifact["form"] == "directory":
            child_root = root / context
            _child_inventory, child_hash = _inventory(child_root)
            result[context] = _protected_directory_files(
                child_root,
                chart_context=context,
                chart_name=artifact["name"],
                inventory_root_sha256=child_hash,
            )
            continue
        archive_path = root / "charts" / f"{artifact['name']}-{artifact['version']}.tgz"
        expanded_root = _canonical_sha(artifact["expanded_files"])
        chart_identity = _canonical_sha({
            "chart_context": context,
            "chart_name": artifact["name"],
            "inventory_root_sha256": expanded_root,
            "archive_sha256": artifact["sha256"],
        })
        visible: dict[str, _ProtectedTplFile] = {}
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive.getmembers():
                pure = PurePosixPath(member.name)
                if not member.isfile() or len(pure.parts) < 2:
                    continue
                relative = PurePosixPath(*pure.parts[1:]).as_posix()
                if pure.parts[1] in {"templates", "charts"} or relative in {
                    "Chart.yaml", "Chart.lock", "values.yaml", "values.schema.json"
                }:
                    continue
                stream = archive.extractfile(member)
                assert stream is not None
                payload = stream.read()
                visible[relative] = _ProtectedTplFile(
                    payload,
                    context,
                    chart_identity,
                    expanded_root,
                    canonical_repo_path(f"{context}/{relative}", "protected Helm file"),
                    relative,
                    len(payload),
                    _sha256(payload),
                )
        result[context] = visible
    return result


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


def _template_actions(
    root: Path, dependencies: dict, chart_inventory_root_sha256: str
) -> _TemplateActionIndex:
    roots: dict[str, _TemplateActionScope] = {}
    definitions: dict[str, _TemplateActionScope] = {}
    sources = dict(_template_sources(root, dependencies))
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
        for action in _iter_template_actions(text):
            if _TEMPLATE_COMMENT.fullmatch(action):
                continue
            definition = _DEFINE_ACTION.match(action)
            if definition is not None:
                if current_name is not None or definition.group(1) in definitions:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_TEMPLATE_ACTION_GRAPH",
                        "named Helm template definition is duplicated or nested",
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
                        definitions[current_name] = _TemplateActionScope(
                            path, tuple(current_actions)
                        )
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
        _protected_tpl_files(root, dependencies, chart_inventory_root_sha256),
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


def _protected_values(spec: HelmRenderSpec) -> tuple[dict, str]:
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
    if charts_root.is_dir():
        for child in sorted(charts_root.iterdir(), key=lambda item: item.name):
            if not child.is_dir() or child.is_symlink():
                continue
            child_values: dict = {}
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
    if len(parts) >= 3 and parts[0] == "charts":
        context = values.get(_SUBCHART_VALUES, {}).get(parts[1])
        if type(context) is dict:
            return context
        return {_UNMODELED_VALUES: True}
    return values


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
    active: bool | None = True
    controls: list[tuple[bool | None, bool | None]] = []
    outputs: list[str] = []
    for action in scope.actions:
        code = _unquoted_action(action).strip()
        start = re.match(r"^(if|with|range)(?:\s+(.*))?$", action.strip(), re.DOTALL)
        if start is not None:
            selected = _condition((start.group(2) or "").strip(), values)
            controls.append((active, selected))
            active = _combine(active, selected)
            continue
        alternate = _CONTROL_ELSE.match(action.strip())
        if alternate is not None:
            if not controls:
                return None
            parent, selected = controls[-1]
            inverse = None if selected is None else not selected
            if alternate.group(1) is not None:
                inverse = _combine(inverse, _condition(alternate.group(1), values))
            active = _combine(parent, inverse)
            continue
        if _CONTROL_END.match(code):
            if not controls:
                return None
            active, _selected = controls.pop()
            continue
        if active is False:
            continue
        if active is None:
            return None
        compact = action.strip()
        if compact == ".Release.Namespace" or compact == "$.Release.Namespace":
            outputs.append(release_namespace)
            continue
        value = _value_at(values, compact)
        if type(value) is str:
            outputs.append(value)
            continue
        # Assignments and comments do not emit a namespace. Any other action is
        # outside this deliberately small namespace-helper evaluator.
        if re.match(r"^\$[A-Za-z0-9_]+\s*:?=", compact):
            continue
        return None
    if controls or len(outputs) != 1:
        return None
    return outputs[0]


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
) -> tuple[str, MappingProxyType]:
    if explicit_namespace == "":
        explicit_namespace = None
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
            include_match = re.fullmatch(
                r'{{-?\s*include\s+"([^"\r\n]+)"\s+[.$]\s*-?}}', compact
            )
            if release_match is not None:
                resolution = "RELEASE_NAMESPACE_EXPRESSION"
                if explicit_namespace != release_namespace:
                    contradiction = "RELEASE_NAMESPACE_EXPRESSION_CONTRADICTS_RENDER"
            elif include_match is not None:
                definition = actions.definitions.get(include_match.group(1))
                resolved = (
                    None if definition is None
                    else _namespace_helper_value(definition, values, release_namespace)
                )
                if resolved is None:
                    raise HelmMaterializationError(
                        "AMBIGUOUS_NAMESPACE_PROVENANCE",
                        "named namespace template is outside the bounded proof contract",
                    )
                if resolved != explicit_namespace:
                    raise HelmMaterializationError(
                        "CONTRADICTORY_NAMESPACE_PROVENANCE",
                        "named namespace template contradicts rendered metadata",
                    )
                resolution = "STATIC_NAMED_NAMESPACE_TEMPLATE"
                value_path = include_match.group(1)
                value_sha = _sha256(resolved.encode("utf-8"))
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


def _documents(
    stdout: bytes,
    *,
    chart_name: str,
    chart_files: tuple[HelmChartFile, ...],
    expanded_dependency_files: tuple[str, ...],
    release_namespace: str,
    template_actions: _TemplateActionIndex,
    protected_values: dict,
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
    dependencies = _validate_dependencies(spec.chart_root, chart_value)
    expanded_dependency_files = tuple(
        item["path"]
        for artifact in dependencies["artifacts"]
        for item in artifact["expanded_files"]
    )
    actions = _template_actions(spec.chart_root, dependencies, chart_root_sha)
    protected_values, protected_values_sha = _protected_values(spec)
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
            release_namespace=spec.namespace,
            template_actions=actions,
            protected_values=protected_values,
        )
        action_failure, action_reachability = _participating_action_analysis(
            actions, first_documents, protected_values, protected_values_sha
        )
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
            release_namespace=spec.namespace,
            template_actions=actions,
            protected_values=protected_values,
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
