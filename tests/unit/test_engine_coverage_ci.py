"""Regression coverage for fail-closed engine evidence boundaries."""
from __future__ import annotations

import contextlib
import hashlib
from typing import Any

import pytest
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

import iac_guard_v.engine as engine
from iac_guard_v.engine import FilesystemArtifactEntry
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import DomainError


def _regular_entry(**changes: Any) -> FilesystemArtifactEntry:
    content = b"x"
    values: dict[str, Any] = {
        "file_path": "main.tf",
        "kind": "REGULAR_FILE",
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "symlink_target": None,
        "supported": True,
        "governed": True,
        "rejection_reason": "",
        "content": content,
    }
    values.update(changes)
    return FilesystemArtifactEntry(**values)


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"kind": "UNKNOWN"}, "kind is unsupported"),
        ({"size": -1}, "size must be nonnegative"),
        ({"supported": 1}, "scope flags must be exact bool"),
        ({"sha256": None}, "requires a content digest"),
        ({"content": "x"}, "content is only valid"),
        ({"content": b"y"}, "content contradicts"),
        ({"symlink_target": "elsewhere"}, "non-symlink artifact"),
        ({"rejection_reason": None}, "rejection reason must be a string"),
    ),
)
def test_filesystem_artifact_entry_rejects_contradictory_evidence(
    changes: dict[str, Any], message: str,
) -> None:
    with pytest.raises(DomainError, match=message):
        _regular_entry(**changes)


def test_filesystem_artifact_symlink_requires_target_text() -> None:
    with pytest.raises(DomainError, match="symlink artifact requires target text"):
        _regular_entry(
            kind="SYMLINK", size=0, sha256=None, content=None, symlink_target=None,
        )


@pytest.mark.parametrize(
    ("document", "message"),
    (
        ([], "unsupported Kubernetes identity shape"),
        ({}, "identity: apiVersion"),
        ({"apiVersion": "v1"}, "identity: kind"),
        (
            {"apiVersion": "v1", "kind": "Pod", "metadata": []},
            "identity: metadata",
        ),
        (
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": 1}},
            "complex Kubernetes metadata.name",
        ),
        (
            {
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "demo", "namespace": 1},
            },
            "complex Kubernetes metadata.namespace",
        ),
        (
            {
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "demo", "namespace": " "},
            },
            "identity shape: metadata.namespace",
        ),
    ),
)
def test_kubernetes_identity_rejects_incomplete_or_complex_values(
    document: object, message: str,
) -> None:
    with pytest.raises(DomainError, match=message):
        engine._kubernetes_identity(
            "pod.yaml", document, ArtifactKind.KUBERNETES_YAML,
        )


def test_kubernetes_identity_defaults_explicit_null_namespace() -> None:
    resource, native = engine._kubernetes_identity(
        "pod.yaml",
        {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "demo", "namespace": None},
        },
        ArtifactKind.KUBERNETES_YAML,
    )
    assert resource.resource_address == "v1/Pod/default/demo"
    assert native.namespace == "default"


def test_kubernetes_documents_skip_empty_and_non_resource_documents() -> None:
    resources, identities = engine._resources_from_kubernetes_documents(
        "pod.yaml", (None, {}), ArtifactKind.KUBERNETES_YAML,
    )
    assert resources == ()
    assert identities == ()


@pytest.mark.parametrize(
    ("documents", "message"),
    (
        (("not-a-document",), "YAML document shape"),
        (({"kind": "List", "items": []},), "Kubernetes List identity"),
        (
            ({"apiVersion": "v1", "kind": "List", "items": {}},),
            "Kubernetes List items shape",
        ),
    ),
)
def test_kubernetes_documents_reject_invalid_shapes(
    documents: tuple[object, ...], message: str,
) -> None:
    with pytest.raises(DomainError, match=message):
        engine._resources_from_kubernetes_documents(
            "pod.yaml", documents, ArtifactKind.KUBERNETES_YAML,
        )


def test_kubernetes_documents_reject_duplicate_resource_identity() -> None:
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "demo"}}
    with pytest.raises(DomainError, match="duplicate Kubernetes resource identity"):
        engine._resources_from_kubernetes_documents(
            "pod.yaml", (pod, pod), ArtifactKind.KUBERNETES_YAML,
        )


@pytest.mark.parametrize(
    ("parsed", "message"),
    (
        ([], "parser returned an invalid document"),
        ({"resource": {}}, "resource structure is invalid"),
        ({"resource": [1]}, "resource block is invalid"),
        ({"resource": [{1: {}}]}, "resource identity is invalid"),
        ({"resource": [{"aws_s3_bucket": []}]}, "resource identity is invalid"),
        ({"resource": [{"aws_s3_bucket": {1: {}}}]}, "resource name is invalid"),
    ),
)
def test_terraform_parser_rejects_invalid_return_shapes(
    monkeypatch: pytest.MonkeyPatch, parsed: object, message: str,
) -> None:
    monkeypatch.setattr(
        engine, "_isolated_hcl2_parser_cache", lambda: contextlib.nullcontext(),
    )
    monkeypatch.setattr(engine.hcl2, "loads", lambda _text: parsed)
    with pytest.raises(DomainError, match=message):
        engine._terraform_resources("main.tf", b"")


def test_yaml_mapping_constructor_rejects_non_mapping_node() -> None:
    node = ScalarNode("tag:yaml.org,2002:str", "value")
    with pytest.raises(ConstructorError, match="expected a YAML mapping"):
        engine._construct_unique_mapping(object(), node)  # type: ignore[arg-type]


def test_yaml_node_validator_rejects_non_scalar_mapping_key() -> None:
    key = SequenceNode("tag:yaml.org,2002:seq", [])
    value = ScalarNode("tag:yaml.org,2002:str", "value")
    node = MappingNode("tag:yaml.org,2002:map", [(key, value)])
    with pytest.raises(DomainError, match="mapping keys must be scalar strings"):
        engine._validate_yaml_node(node)


def test_yaml_document_and_node_limits_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    document = b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\n"
    monkeypatch.setattr(engine, "_MAX_YAML_DOCUMENTS", 0)
    with pytest.raises(DomainError, match="document limit exceeded"):
        engine._bounded_yaml_documents(document)

    monkeypatch.setattr(engine, "_MAX_YAML_DOCUMENTS", 128)
    monkeypatch.setattr(engine, "_MAX_YAML_NODES", 0)
    with pytest.raises(DomainError, match="node limit exceeded"):
        engine._bounded_yaml_documents(document)
