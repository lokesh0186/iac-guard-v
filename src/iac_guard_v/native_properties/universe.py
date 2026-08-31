"""Content-bound Kubernetes and Terraform universes for native properties."""
from __future__ import annotations

import hashlib
import math
import os
import stat
from dataclasses import InitVar, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from ..fingerprints import canonicalize_kubernetes_identity
from ..models import DomainError, canonical_repo_path
from ..terraform_parser import TerraformParserError, parse_terraform_structure
from .model import NativeArtifactClass, canonical_digest


_WORKLOAD_TEMPLATE_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template"),
    "StatefulSet": ("spec", "template"),
    "DaemonSet": ("spec", "template"),
    "ReplicaSet": ("spec", "template"),
    "Job": ("spec", "template"),
    "CronJob": ("spec", "jobTemplate", "spec", "template"),
}

_CLUSTER_SCOPED_KINDS = frozenset({
    "ClusterRole",
    "ClusterRoleBinding",
    "Namespace",
    "Node",
    "PersistentVolume",
    "CustomResourceDefinition",
    "StorageClass",
    "MutatingWebhookConfiguration",
    "ValidatingWebhookConfiguration",
})
_TRUSTED_NATIVE_UNIVERSE_CONTEXT = object()


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe loader that refuses aliases and duplicate/non-string mapping keys."""

    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise ConstructorError(
                "while composing a native manifest", None,
                "YAML aliases are unsupported in protected native artifacts",
                event.start_mark,
            )
        return super().compose_node(parent, index)


def _construct_unique_mapping(
    loader: _StrictSafeLoader, node: MappingNode, deep: bool = False
) -> dict:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a YAML mapping", node.start_mark)
    loader.flatten_mapping(node)
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark,
                "YAML mapping keys must be strings", key_node.start_mark,
            )
        if key in result:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"duplicate YAML mapping key {key!r}", key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _freeze(value: Any, label: str = "manifest") -> Any:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise DomainError(f"{label} contains a non-finite number")
        return value
    if type(value) is list:
        return tuple(_freeze(item, f"{label} item") for item in value)
    if type(value) is dict:
        copied: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise DomainError(f"{label} mapping keys must be strings")
            copied[key] = _freeze(item, f"{label}.{key}")
        return MappingProxyType(dict(copied))
    raise DomainError(f"{label} contains unsupported YAML type {type(value).__name__}")


def _mapping(value: Any, label: str, *, optional: bool = False) -> Mapping[str, Any]:
    if value is None and optional:
        return MappingProxyType({})
    if type(value) not in (dict, MappingProxyType):
        raise DomainError(f"{label} must be a mapping")
    return value


def _string_map(value: Any, label: str) -> Mapping[str, str]:
    mapping = _mapping(value, label, optional=True)
    result: dict[str, str] = {}
    for key, item in mapping.items():
        if type(key) is not str or not key or type(item) is not str:
            raise DomainError(f"{label} must contain nonempty string keys and string values")
        result[key] = item
    return MappingProxyType(dict(sorted(result.items())))


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_regular_file(path: Path) -> bytes:
    """Read protected bytes without following links and detect concurrent mutation."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise DomainError("protected native input is unreadable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise DomainError("protected native input must be a regular non-symlink file")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise DomainError("protected native input could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise DomainError("protected native input changed before reading")
        content = bytearray()
        while chunk := os.read(descriptor, 64 * 1024):
            content.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        or len(content) != after.st_size
    ):
        raise DomainError("protected native input changed while reading")
    return bytes(content)


@dataclass(frozen=True, slots=True)
class NativeSourceFile:
    file_path: str
    sha256: str
    size: int

    def canonical_dict(self) -> dict[str, Any]:
        return {"file_path": self.file_path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True, slots=True)
class KubernetesResource:
    identity: str
    api_version: str
    kind: str
    namespace: str
    name: str
    labels: Mapping[str, str]
    file_path: str
    document_index: int
    list_index: int | None
    source_sha256: str
    data: Mapping[str, Any]

    def provenance_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "file_path": self.file_path,
            "document_index": self.document_index,
            "list_index": self.list_index,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True, slots=True)
class ContainerPortOccurrence:
    name: str
    number: int
    protocol: str

    def canonical_dict(self) -> dict[str, Any]:
        return {"name": self.name, "number": self.number, "protocol": self.protocol}


@dataclass(frozen=True, slots=True)
class ContainerOccurrence:
    workload_identity: str
    container_class: str
    index: int
    name: str
    ports: tuple[ContainerPortOccurrence, ...]

    @property
    def identity(self) -> str:
        return f"{self.workload_identity}#{self.container_class}[{self.index}]/{self.name}"

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "container_class": self.container_class,
            "index": self.index,
            "name": self.name,
            "ports": [item.canonical_dict() for item in self.ports],
        }


@dataclass(frozen=True, slots=True)
class WorkloadIdentity:
    resource: KubernetesResource
    pod_template_path: tuple[str, ...]
    pod_labels: Mapping[str, str]
    containers: tuple[ContainerOccurrence, ...]

    @property
    def identity(self) -> str:
        return self.resource.identity

    @property
    def namespace(self) -> str:
        return self.resource.namespace

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "namespace": self.namespace,
            "pod_template_path": list(self.pod_template_path),
            "pod_labels": dict(self.pod_labels),
            "containers": [item.canonical_dict() for item in self.containers],
            "provenance": self.resource.provenance_dict(),
        }


@dataclass(frozen=True, slots=True)
class TerraformResource:
    identity: str
    resource_type: str
    resource_name: str
    file_path: str
    source_sha256: str
    body: Mapping[str, Any]
    source_text: str

    def provenance_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "file_path": self.file_path,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True, slots=True)
class ProtectedNativeUniverse:
    root: Path
    artifact_class: NativeArtifactClass
    default_namespace: str
    source_files: tuple[NativeSourceFile, ...]
    kubernetes_resources: tuple[KubernetesResource, ...]
    workloads: tuple[WorkloadIdentity, ...]
    terraform_resources: tuple[TerraformResource, ...]
    input_manifest_digest: str
    resource_inventory_digest: str
    identity: str
    _trusted_context: InitVar[object] = None

    def __post_init__(self, _trusted_context: object) -> None:
        if _trusted_context is not _TRUSTED_NATIVE_UNIVERSE_CONTEXT:
            raise DomainError("protected native universe must come from the content loader")
        if not isinstance(self.root, Path) or not self.root.is_absolute():
            raise DomainError("native universe root must be an absolute Path")
        if type(self.artifact_class) is not NativeArtifactClass:
            raise DomainError("native universe artifact class is invalid")
        expected_inputs = canonical_digest([item.canonical_dict() for item in self.source_files])
        if self.input_manifest_digest != expected_inputs:
            raise DomainError("native input manifest digest is not canonical")
        inventory = (
            [item.identity for item in self.kubernetes_resources]
            if self.artifact_class is NativeArtifactClass.KUBERNETES_RENDERED
            else [item.identity for item in self.terraform_resources]
        )
        if self.resource_inventory_digest != canonical_digest(inventory):
            raise DomainError("native resource inventory digest is not canonical")
        expected_identity = canonical_digest({
            "artifact_class": self.artifact_class.value,
            "default_namespace": self.default_namespace,
            "input_manifest_digest": self.input_manifest_digest,
            "resource_inventory_digest": self.resource_inventory_digest,
        })
        if self.identity != expected_identity:
            raise DomainError("native protected universe identity is not canonical")

    def kubernetes_resource(self, identity: str) -> KubernetesResource:
        matches = tuple(item for item in self.kubernetes_resources if item.identity == identity)
        if len(matches) != 1:
            raise DomainError("native Kubernetes subject is missing or ambiguous")
        return matches[0]

    def workload(self, identity: str) -> WorkloadIdentity:
        matches = tuple(item for item in self.workloads if item.identity == identity)
        if len(matches) != 1:
            raise DomainError("native workload subject is missing or ambiguous")
        return matches[0]

    def terraform_resource(self, identity: str) -> TerraformResource:
        matches = tuple(item for item in self.terraform_resources if item.identity == identity)
        if len(matches) != 1:
            raise DomainError("native Terraform subject is missing or ambiguous")
        return matches[0]


def _object_namespace(kind: str, metadata: Mapping[str, Any], default_namespace: str) -> str:
    namespace = metadata.get("namespace")
    if kind in _CLUSTER_SCOPED_KINDS:
        if namespace not in (None, ""):
            raise DomainError(f"cluster-scoped {kind} must not declare metadata.namespace")
        return "_cluster"
    if namespace is None:
        return default_namespace
    if type(namespace) is not str or not namespace.strip():
        raise DomainError("Kubernetes metadata.namespace is malformed")
    return namespace


def _resource_from_object(
    raw: Any,
    *,
    file_path: str,
    source_sha256: str,
    document_index: int,
    list_index: int | None,
    default_namespace: str,
) -> KubernetesResource:
    data = _freeze(raw, "Kubernetes resource")
    mapping = _mapping(data, "Kubernetes resource")
    api_version = mapping.get("apiVersion")
    kind = mapping.get("kind")
    metadata = _mapping(mapping.get("metadata"), "Kubernetes metadata")
    name = metadata.get("name")
    if type(api_version) is not str or type(kind) is not str or type(name) is not str:
        raise DomainError("Kubernetes resource requires exact apiVersion, kind and metadata.name")
    namespace = _object_namespace(kind, metadata, default_namespace)
    identity = canonicalize_kubernetes_identity(api_version, kind, namespace, name)
    labels = _string_map(metadata.get("labels"), "Kubernetes metadata.labels")
    return KubernetesResource(
        identity,
        api_version,
        kind,
        namespace,
        name,
        labels,
        file_path,
        document_index,
        list_index,
        source_sha256,
        mapping,
    )


def _objects_from_document(document: Any) -> tuple[tuple[Any, int | None], ...]:
    if document is None:
        return ()
    if type(document) is not dict:
        raise DomainError("Kubernetes YAML document must be an object")
    if document.get("kind") == "List" and type(document.get("items")) is list:
        return tuple((item, index) for index, item in enumerate(document["items"]))
    return ((document, None),)


def _at_path(data: Mapping[str, Any], path: tuple[str, ...]) -> Mapping[str, Any]:
    current: Any = data
    for part in path:
        current = _mapping(current, f"Pod template path {'.'.join(path)}").get(part)
    return _mapping(current, f"Pod template path {'.'.join(path)}")


def _workload(resource: KubernetesResource) -> WorkloadIdentity | None:
    path = _WORKLOAD_TEMPLATE_PATHS.get(resource.kind)
    if path is None:
        return None
    pod = _at_path(resource.data, path)
    if resource.kind == "Pod":
        labels = resource.labels
        spec = pod
    else:
        metadata = _mapping(pod.get("metadata"), "Pod template metadata")
        labels = _string_map(metadata.get("labels"), "Pod template labels")
        spec = _mapping(pod.get("spec"), "Pod template spec")
    occurrences: list[ContainerOccurrence] = []
    occurrence_names: set[str] = set()
    for container_class in ("containers", "initContainers", "ephemeralContainers"):
        raw_containers = spec.get(container_class, ())
        if raw_containers is None:
            raw_containers = ()
        if type(raw_containers) not in (tuple, list):
            raise DomainError(f"Pod {container_class} must be a list")
        for index, raw_container in enumerate(raw_containers):
            container = _mapping(raw_container, f"Pod {container_class} entry")
            name = container.get("name")
            if type(name) is not str or not name:
                raise DomainError(f"Pod {container_class} entry requires a name")
            if name in occurrence_names:
                raise DomainError("Pod container names must be unique across occurrence classes")
            occurrence_names.add(name)
            ports: list[ContainerPortOccurrence] = []
            raw_ports = container.get("ports", ())
            if raw_ports is None:
                raw_ports = ()
            if type(raw_ports) not in (tuple, list):
                raise DomainError("container ports must be a list")
            for raw_port in raw_ports:
                port = _mapping(raw_port, "container port")
                number = port.get("containerPort")
                if type(number) is not int or type(number) is bool or not 1 <= number <= 65535:
                    raise DomainError("containerPort must be an integer from 1 to 65535")
                port_name = port.get("name", "")
                protocol = port.get("protocol", "TCP")
                if type(port_name) is not str or type(protocol) is not str:
                    raise DomainError("container port name/protocol is malformed")
                if protocol not in {"TCP", "UDP", "SCTP"}:
                    raise DomainError("container port protocol is unsupported")
                ports.append(ContainerPortOccurrence(port_name, number, protocol))
            occurrences.append(ContainerOccurrence(
                resource.identity,
                container_class,
                index,
                name,
                tuple(ports),
            ))
    return WorkloadIdentity(resource, path, labels, tuple(occurrences))


def _load_kubernetes(
    root: Path, default_namespace: str
) -> tuple[tuple[NativeSourceFile, ...], tuple[KubernetesResource, ...], tuple[WorkloadIdentity, ...]]:
    paths = tuple(sorted(
        (path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in {".yaml", ".yml", ".json"}),
        key=lambda item: item.relative_to(root).as_posix(),
    ))
    if not paths:
        raise DomainError("protected Kubernetes universe contains no manifest files")
    source_files: list[NativeSourceFile] = []
    resources: list[KubernetesResource] = []
    for path in paths:
        content = _read_regular_file(path)
        relative = canonical_repo_path(path.relative_to(root).as_posix())
        digest = _sha256_bytes(content)
        source_files.append(NativeSourceFile(relative, digest, len(content)))
        try:
            text = content.decode("utf-8", errors="strict")
            documents = tuple(yaml.load_all(text, Loader=_StrictSafeLoader))
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            raise DomainError(f"protected Kubernetes manifest {relative} is invalid") from exc
        for document_index, document in enumerate(documents):
            for raw, list_index in _objects_from_document(document):
                resources.append(_resource_from_object(
                    raw,
                    file_path=relative,
                    source_sha256=digest,
                    document_index=document_index,
                    list_index=list_index,
                    default_namespace=default_namespace,
                ))
    resources.sort(key=lambda item: item.identity)
    identities = [item.identity for item in resources]
    if len(identities) != len(set(identities)):
        raise DomainError("duplicate canonical Kubernetes resource identity")
    workloads = tuple(item for resource in resources if (item := _workload(resource)) is not None)
    return tuple(source_files), tuple(resources), workloads


def _load_terraform(
    root: Path,
) -> tuple[tuple[NativeSourceFile, ...], tuple[TerraformResource, ...]]:
    paths = tuple(sorted(
        (path for path in root.rglob("*.tf") if path.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    ))
    if not paths:
        raise DomainError("protected Terraform universe contains no .tf files")
    source_files: list[NativeSourceFile] = []
    resources: list[TerraformResource] = []
    for path in paths:
        content = _read_regular_file(path)
        relative = canonical_repo_path(path.relative_to(root).as_posix())
        digest = _sha256_bytes(content)
        source_files.append(NativeSourceFile(relative, digest, len(content)))
        try:
            structure = parse_terraform_structure(content)
            source_text = content.decode("utf-8", errors="strict")
        except (TerraformParserError, UnicodeDecodeError) as exc:
            raise DomainError(f"protected Terraform source {relative} is invalid") from exc
        blocks = structure.document.get("resource", [])
        for block in blocks:
            for resource_type, instances in block.items():
                for resource_name, body in instances.items():
                    address = f"{resource_type}.{resource_name}"
                    resources.append(TerraformResource(
                        address,
                        resource_type,
                        resource_name,
                        relative,
                        digest,
                        _freeze(body, f"Terraform resource {address}"),
                        source_text,
                    ))
    resources.sort(key=lambda item: item.identity)
    identities = [item.identity for item in resources]
    if len(identities) != len(set(identities)):
        raise DomainError("duplicate Terraform resource identity across protected files")
    return tuple(source_files), tuple(resources)


def load_protected_native_universe(
    root: Path,
    artifact_class: NativeArtifactClass,
    *,
    default_namespace: str = "default",
) -> ProtectedNativeUniverse:
    if not isinstance(root, Path):
        raise DomainError("native universe root must be a Path")
    if root.is_symlink():
        raise DomainError("native universe root must not be a symlink")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise DomainError("native universe root must be a directory")
    if type(artifact_class) is not NativeArtifactClass:
        raise DomainError("native artifact class must be exact")
    if type(default_namespace) is not str or not default_namespace.strip() or "/" in default_namespace:
        raise DomainError("native default namespace is malformed")
    if artifact_class is NativeArtifactClass.KUBERNETES_RENDERED:
        source_files, resources, workloads = _load_kubernetes(resolved, default_namespace)
        terraform_resources: tuple[TerraformResource, ...] = ()
        inventory = [item.identity for item in resources]
    else:
        source_files, terraform_resources = _load_terraform(resolved)
        resources = ()
        workloads = ()
        inventory = [item.identity for item in terraform_resources]
    input_digest = canonical_digest([item.canonical_dict() for item in source_files])
    inventory_digest = canonical_digest(inventory)
    identity = canonical_digest({
        "artifact_class": artifact_class.value,
        "default_namespace": default_namespace,
        "input_manifest_digest": input_digest,
        "resource_inventory_digest": inventory_digest,
    })
    return ProtectedNativeUniverse(
        resolved,
        artifact_class,
        default_namespace,
        source_files,
        resources,
        workloads,
        terraform_resources,
        input_digest,
        inventory_digest,
        identity,
        _TRUSTED_NATIVE_UNIVERSE_CONTEXT,
    )


__all__ = [
    "ContainerOccurrence",
    "ContainerPortOccurrence",
    "KubernetesResource",
    "NativeSourceFile",
    "ProtectedNativeUniverse",
    "TerraformResource",
    "WorkloadIdentity",
    "load_protected_native_universe",
]
