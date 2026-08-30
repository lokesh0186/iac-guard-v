"""A8 Helm logical dependency, duplicate helper, and namespace grammar tests."""
from __future__ import annotations

import copy
import io
from pathlib import Path
import os
import tarfile

import jsonschema
import pytest

import iac_guard_v.helm as H
import iac_guard_v.report as REPORT
from iac_guard_v.models import DomainError


def _chart(tmp_path: Path) -> Path:
    root = tmp_path / "chart"
    (root / "templates").mkdir(parents=True)
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\n", encoding="utf-8"
    )
    return root


def _child(root: Path) -> None:
    child = root / "charts" / "child"
    (child / "templates").mkdir(parents=True)
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: child\nversion: 1.2.3\n", encoding="utf-8"
    )
    (child / "templates" / "resource.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: child}\n",
        encoding="utf-8",
    )


def _archive(path: Path, name: str = "child", version: str = "1.2.3",
             *, members: dict[str, bytes] | None = None) -> None:
    content = {
        f"{name}/Chart.yaml": (
            f"apiVersion: v2\nname: {name}\nversion: {version}\n"
        ).encode(),
        f"{name}/values.yaml": b"message: protected\n",
        f"{name}/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: child}\n"
        ),
    }
    if members is not None:
        content = members
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        for member, payload in content.items():
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))


def _archive_payload(members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for member, payload in members.items():
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def _parent_for_archive(root: Path, path: Path) -> None:
    requirements = [{
        "name": "child", "version": "1.2.3",
        "repository": "https://charts.example.invalid",
    }]
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n",
        encoding="utf-8",
    )
    (root / "Chart.lock").write_text(
        "dependencies:\n- {name: child, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n"
        f"digest: {H._helm_dependency_digest(requirements, requirements)}\n",
        encoding="utf-8",
    )
    assert path == root / "charts" / "child-1.2.3.tgz"


def _valid_nested_archive_closure(tmp_path: Path) -> tuple[dict, Path]:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    nested = [{
        "name": "grand", "version": "1.0.0",
        "repository": "https://charts.example.invalid",
    }]
    _archive(path, members={
        "child": b"",
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, version: 1.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
        ),
        "child/Chart.lock": (
            b"dependencies:\n- {name: grand, version: 1.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
            + f"digest: {H._helm_dependency_digest(nested, nested)}\n".encode()
        ),
        "child/charts": b"",
        "child/charts/grand": b"",
        "child/charts/grand/Chart.yaml": (
            b"apiVersion: v2\nname: grand\nversion: 1.0.0\n"
        ),
        "child/charts/grand/templates/resource.yaml": b"kind: ConfigMap\n",
    })
    # Replace the zero-byte directory markers produced by the generic helper
    # with actual tar directory members so safe extraction's directory branch is
    # part of the regression proof.
    payloads = {
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, version: 1.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
        ),
        "child/Chart.lock": (
            b"dependencies:\n- {name: grand, version: 1.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
            + f"digest: {H._helm_dependency_digest(nested, nested)}\n".encode()
        ),
        "child/charts/grand/Chart.yaml": (
            b"apiVersion: v2\nname: grand\nversion: 1.0.0\n"
        ),
        "child/charts/grand/templates/resource.yaml": b"kind: ConfigMap\n",
    }
    with tarfile.open(path, "w:gz") as archive:
        for directory in ("child", "child/charts", "child/charts/grand"):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for member, payload in payloads.items():
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
    _parent_for_archive(root, path)
    return H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml")
    ), path


def test_alias_has_distinct_logical_identity_and_logical_sources(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    _child(root)
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, alias: renamed, version: 1.2.3, repository: 'file://child'}\n",
        encoding="utf-8",
    )
    dependencies = H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    logical = dependencies["artifacts"][0]["logical_instance"]
    assert logical["effective_name"] == "renamed"
    assert len(logical["logical_instance_identity"]) == 64
    assert "charts/renamed/templates/resource.yaml" in dict(H._template_sources(root, dependencies))
    assert "charts/child/templates/resource.yaml" not in dict(H._template_sources(root, dependencies))


def test_repeated_physical_source_retains_two_logical_instances(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    _child(root)
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, alias: first, version: 1.2.3, repository: 'file://child'}\n"
        "- {name: child, alias: second, version: 1.2.3, repository: 'file://child'}\n",
        encoding="utf-8",
    )
    dependencies = H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    identities = {
        item["logical_instance"]["logical_instance_identity"]
        for item in dependencies["artifacts"]
    }
    assert len(identities) == 2
    sources = dict(H._template_sources(root, dependencies))
    assert {path.split("/")[1] for path in sources if path.startswith("charts/")} == {"first", "second"}


def test_effective_name_collision_fails_closed(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    _child(root)
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, alias: same, version: 1.2.3, repository: 'file://child'}\n"
        "- {name: child, alias: same, version: 1.2.3, repository: 'file://child'}\n",
        encoding="utf-8",
    )
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    assert caught.value.reason_code == "HELM_DEPENDENCY_EFFECTIVE_NAME_COLLISION"


def test_equivalent_duplicate_helpers_retain_all_members(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    body = '{{ define "shared.namespace" }}{{ .Release.Namespace }}{{ end }}\n'
    (root / "templates" / "one.tpl").write_text(body, encoding="utf-8")
    (root / "templates" / "two.tpl").write_text(body, encoding="utf-8")
    inventory, digest = H._inventory(root)
    assert inventory
    actions = H._template_actions(root, {"artifacts": []}, digest)
    assert len(actions.definition_members["shared.namespace"]) == 2
    assert all(
        len(member.definition_span_sha256) == 64
        for member in actions.definition_members["shared.namespace"]
    )


def test_equivalent_duplicate_helpers_in_one_source_have_distinct_spans(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    body = '{{ define "shared.namespace" }}{{ .Release.Namespace }}{{ end }}\n'
    (root / "templates" / "both.tpl").write_text(body + body, encoding="utf-8")
    _inventory, digest = H._inventory(root)
    actions = H._template_actions(root, {"artifacts": []}, digest)
    members = actions.definition_members["shared.namespace"]
    assert [member.definition_ordinal for member in members] == [0, 1]
    assert members[0].definition_span_sha256 != members[1].definition_span_sha256


def test_non_equivalent_duplicate_helpers_fail_closed(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    (root / "templates" / "one.tpl").write_text(
        '{{ define "shared.namespace" }}{{ .Release.Namespace }}{{ end }}\n', encoding="utf-8"
    )
    (root / "templates" / "two.tpl").write_text(
        '{{ define "shared.namespace" }}{{ .Values.namespace }}{{ end }}\n', encoding="utf-8"
    )
    _inventory, digest = H._inventory(root)
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._template_actions(root, {"artifacts": []}, digest)
    assert caught.value.reason_code == "HELM_TEMPLATE_DUPLICATE_NON_EQUIVALENT"


def test_closed_namespace_calls_and_helpers() -> None:
    source = '{{- $root := . -}}\nnamespace: {{ include "shared.namespace" $root | quote }}\n'
    assert H._namespace_call('{{ include "shared.namespace" $root | quote }}', source) == (
        "shared.namespace", "$root"
    )
    assert H._namespace_call('{{ include (printf "%s.namespace" .Chart.Name) . }}', source) is None
    scope = H._TemplateActionScope(
        "helpers.tpl",
        ('default .Release.Namespace .Values.namespace | trunc 63 | trimSuffix "-"',),
    )
    assert H._namespace_helper_value(scope, {"namespace": "chosen-"}, "release") == "chosen"


def test_dependency_activation_uses_first_existing_boolean_condition() -> None:
    record = H._dependency_record({
        "name": "child", "version": "1.0.0", "repository": "file://child",
        "condition": "missing.enabled,child.enabled", "tags": ["demo"],
    })
    evidence = H._dependency_activation(
        record, {"child": {"enabled": False}, "tags": {"demo": True}}
    )
    assert evidence["result"] is False
    assert evidence["condition_inputs"][0]["found"] is False
    assert evidence["condition_inputs"][1]["value"] is False


@pytest.mark.parametrize(
    "entry",
    (
        {"name": "child", "version": "1", "repository": "file://child",
         "condition": "child[0].enabled"},
        {"name": "child", "version": "1", "repository": "file://child",
         "tags": ["same", "same"]},
        {"name": "child", "version": "1", "repository": "file://child",
         "import-values": [{"child": "exports"}]},
    ),
)
def test_dependency_metadata_adjacent_grammar_fails_closed(entry: dict) -> None:
    with pytest.raises(H.HelmMaterializationError):
        H._dependency_record(entry)


def test_dependency_activation_rejects_non_boolean_first_existing_value() -> None:
    record = H._dependency_record({
        "name": "child", "version": "1", "repository": "file://child",
        "condition": "child.enabled",
    })
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._dependency_activation(record, {"child": {"enabled": "yes"}})
    assert caught.value.reason_code == "HELM_DEPENDENCY_ACTIVATION_AMBIGUOUS"


def test_helm_lock_digest_matches_repeated_physical_source_with_alias() -> None:
    """OpenTelemetry Demo's exact dependency shape remains Helm-compatible."""
    requirements = [
        {
            "name": "opentelemetry-collector", "version": "0.165.0",
            "repository": "https://open-telemetry.github.io/opentelemetry-helm-charts",
            "condition": "opentelemetry-collector.enabled",
        },
        {
            "name": "opentelemetry-collector", "version": "0.165.0",
            "repository": "https://open-telemetry.github.io/opentelemetry-helm-charts",
            "condition": "otel-ebpf-profiler.enabled", "alias": "otel-ebpf-profiler",
        },
        {
            "name": "jaeger", "version": "4.11.1",
            "repository": "https://jaegertracing.github.io/helm-charts",
            "condition": "jaeger.enabled",
        },
        {
            "name": "prometheus", "version": "29.18.0",
            "repository": "https://prometheus-community.github.io/helm-charts",
            "condition": "prometheus.enabled",
        },
        {
            "name": "grafana", "version": "12.7.2",
            "repository": "https://grafana-community.github.io/helm-charts",
            "condition": "grafana.enabled",
        },
        {
            "name": "opensearch", "version": "3.7.0",
            "repository": "https://opensearch-project.github.io/helm-charts/",
            "condition": "opensearch.enabled",
        },
    ]
    locked = [
        {key: item[key] for key in ("name", "repository", "version")}
        for item in requirements
    ]
    assert H._helm_dependency_digest(requirements, locked) == (
        "sha256:328c862abd390ddc7f314cfdee6b2d5fee5d4fe43079c4b0b4558b9566a7c60e"
    )


def test_contained_file_dependency_is_inventoried_and_sealed(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    root = repository / "charts" / "parent"
    (root / "templates").mkdir(parents=True)
    common = repository / "charts" / "common"
    (common / "templates").mkdir(parents=True)
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: common, alias: shared, version: 2.0.0, repository: 'file://../common'}\n",
        encoding="utf-8",
    )
    (common / "Chart.yaml").write_text(
        "apiVersion: v2\nname: common\nversion: 2.0.0\n", encoding="utf-8"
    )
    (common / "templates" / "resource.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: shared}\n",
        encoding="utf-8",
    )
    dependencies = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"),
        repository_root=repository,
    )
    artifact = dependencies["artifacts"][0]
    assert artifact["form"] == "local-directory"
    assert artifact["source_repository_path"] == "charts/common"
    assert "charts/shared/templates/resource.yaml" in dict(
        H._template_sources(root, dependencies, repository)
    )


def test_file_dependency_escape_and_symlink_fail_closed(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    root = repository / "chart"
    root.mkdir(parents=True)
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: common, version: 1.0.0, repository: 'file://../../outside'}\n",
        encoding="utf-8",
    )
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(
            root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"),
            repository_root=repository,
        )
    assert caught.value.reason_code == "HELM_DEPENDENCY_PATH_ESCAPE"

    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, repository / "linked")
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: common, version: 1.0.0, repository: 'file://../linked'}\n",
        encoding="utf-8",
    )
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(
            root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"),
            repository_root=repository,
        )
    assert caught.value.reason_code == "HELM_DEPENDENCY_SYMLINK"


def test_nested_local_alias_closure_has_parented_logical_context(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    _child(root)
    child = root / "charts" / "child"
    grand = child / "charts" / "grand"
    (grand / "templates").mkdir(parents=True)
    (grand / "Chart.yaml").write_text(
        "apiVersion: v2\nname: grand\nversion: 3.0.0\n", encoding="utf-8"
    )
    (grand / "templates" / "resource.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: grand}\n",
        encoding="utf-8",
    )
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
        "- {name: grand, alias: nested, version: 3.0.0, repository: 'file://grand'}\n",
        encoding="utf-8",
    )
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, alias: first, version: 1.2.3, repository: 'file://child'}\n",
        encoding="utf-8",
    )
    dependencies = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml")
    )
    nested = dependencies["artifacts"][0]["dependencies"]["artifacts"][0]
    assert nested["logical_context"] == "charts/first/charts/nested"
    assert nested["logical_instance"]["parent_instance"] == (
        dependencies["artifacts"][0]["logical_instance"]["logical_instance_identity"]
    )
    assert "charts/first/charts/nested/templates/resource.yaml" in dict(
        H._template_sources(root, dependencies)
    )


def test_archive_backed_alias_binds_one_physical_artifact_and_logical_source(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    archive = root / "charts" / "child-1.2.3.tgz"
    _archive(archive)
    requirements = [{
        "name": "child", "alias": "renamed", "version": "1.2.3",
        "repository": "https://charts.example.invalid", "condition": "renamed.enabled",
    }]
    locked = [{
        "name": "child", "version": "1.2.3",
        "repository": "https://charts.example.invalid",
    }]
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, alias: renamed, version: 1.2.3, "
        "repository: 'https://charts.example.invalid', condition: renamed.enabled}\n",
        encoding="utf-8",
    )
    (root / "Chart.lock").write_text(
        "dependencies:\n- {name: child, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n"
        f"digest: {H._helm_dependency_digest(requirements, locked)}\n",
        encoding="utf-8",
    )
    closure = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"),
        {"renamed": {"enabled": True}},
    )
    artifact = closure["artifacts"][0]
    assert artifact["form"] == "archive"
    assert artifact["physical_dependency"]["protected_artifact_root_sha256"] == H._sha256(
        archive.read_bytes()
    )
    assert artifact["logical_instance"]["effective_name"] == "renamed"
    assert "charts/renamed/templates/resource.yaml" in dict(
        H._template_sources(root, closure)
    )


def test_two_aliases_over_one_archive_retain_distinct_effective_values(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    archive = root / "charts" / "child-1.2.3.tgz"
    _archive(archive, members={
        "child/Chart.yaml": b"apiVersion: v2\nname: child\nversion: 1.2.3\n",
        "child/values.yaml": b"namespaceOverride: ''\n",
        "child/templates/resource.yaml": b"kind: ConfigMap\n",
    })
    declared = [
        {
            "name": "child", "alias": alias, "version": "1.2.3",
            "repository": "https://charts.example.invalid",
        }
        for alias in ("first", "second")
    ]
    locked = [
        {
            "name": "child", "version": "1.2.3",
            "repository": "https://charts.example.invalid",
        }
        for _alias in ("first", "second")
    ]
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, alias: first, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n"
        "- {name: child, alias: second, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n",
        encoding="utf-8",
    )
    (root / "Chart.lock").write_text(
        "dependencies:\n"
        "- {name: child, version: 1.2.3, repository: 'https://charts.example.invalid'}\n"
        "- {name: child, version: 1.2.3, repository: 'https://charts.example.invalid'}\n"
        f"digest: {H._helm_dependency_digest(declared, locked)}\n",
        encoding="utf-8",
    )
    (root / "values.yaml").write_text(
        "first:\n  namespaceOverride: first-ns\n"
        "second:\n  namespaceOverride: second-ns\n",
        encoding="utf-8",
    )
    executable = tmp_path / "fake-helm"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    spec = H.HelmRenderSpec(
        chart_root=root, helm_executable=executable, release_name="review",
        namespace="default", kube_version="1.31.0",
    )
    root_values, _identity = H._protected_values(spec)
    closure = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"), root_values
    )
    protected, _identity = H._protected_values(spec, closure)
    first, second = closure["artifacts"]

    assert first["physical_dependency"]["physical_dependency_identity"] == (
        second["physical_dependency"]["physical_dependency_identity"]
    )
    assert first["values_provenance"]["effective_values_root_sha256"] != (
        second["values_provenance"]["effective_values_root_sha256"]
    )
    assert H._values_for_source(
        protected, "charts/first/templates/resource.yaml"
    )["namespaceOverride"] == "first-ns"
    assert H._values_for_source(
        protected, "charts/second/templates/resource.yaml"
    )["namespaceOverride"] == "second-ns"


def test_nested_archive_dependency_closure_is_accepted_without_flattening_identity(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    nested_requirements = [{
        "name": "grand", "version": "1.0.0",
        "repository": "https://charts.example.invalid",
    }]
    nested_locked = [dict(nested_requirements[0])]
    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\n"
            b"dependencies:\n- {name: grand, version: 1.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
        ),
        "child/Chart.lock": (
            b"dependencies:\n- {name: grand, version: 1.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
            + f"digest: {H._helm_dependency_digest(nested_requirements, nested_locked)}\n".encode()
        ),
        "child/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: child}\n"
        ),
        "child/charts/grand/Chart.yaml": (
            b"apiVersion: v2\nname: grand\nversion: 1.0.0\n"
        ),
        "child/charts/grand/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: grand}\n"
        ),
    })
    requirements = [{
        "name": "child", "version": "1.2.3",
        "repository": "https://charts.example.invalid",
    }]
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n",
        encoding="utf-8",
    )
    (root / "Chart.lock").write_text(
        "dependencies:\n- {name: child, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n"
        f"digest: {H._helm_dependency_digest(requirements, requirements)}\n",
        encoding="utf-8",
    )

    closure = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml")
    )

    outer = closure["artifacts"][0]
    nested = outer["dependencies"]["artifacts"][0]
    assert outer["archive_provenance"]["archive_sha256"] == H._sha256(path.read_bytes())
    assert nested["archive_member_provenance"]["outer_archive_sha256"] == H._sha256(
        path.read_bytes()
    )
    assert nested["archive_member_provenance"]["chart_member_path"] == (
        "child/charts/grand"
    )
    assert nested["physical_dependency"]["physical_dependency_identity"]
    assert nested["logical_instance"]["parent_instance"] == (
        outer["logical_instance"]["logical_instance_identity"]
    )
    assert "charts/child/charts/grand/templates/resource.yaml" in dict(
        H._template_sources(root, closure)
    )
    validator = jsonschema.Draft202012Validator(REPORT._schema()).evolve(
        schema={"$ref": "#/$defs/helmDependencyClosure"}
    )
    validator.validate(closure)
    REPORT._validate_helm_dependency_closure(closure, "candidate")


def _nested_range_fixture(
    tmp_path: Path,
    *,
    declared_version: object = "2.x.x",
    locked_version: object = "2.18.0",
    chart_version: object = "2.18.0",
    locked_name: str = "common",
) -> Path:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    declared = [{
        "name": "common", "version": declared_version,
        "repository": "oci://registry.example.invalid/charts",
    }]
    locked = [{
        "name": locked_name, "version": locked_version,
        "repository": "oci://registry.example.invalid/charts",
    }]
    digest = (
        H._helm_dependency_digest(declared, locked)
        if type(declared_version) is str and type(locked_version) is str
        else "sha256:" + "0" * 64
    )
    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            + f"- name: common\n  version: {declared_version!r}\n".encode()
            + b"  repository: 'oci://registry.example.invalid/charts'\n"
        ),
        "child/Chart.lock": (
            b"dependencies:\n"
            + f"- name: {locked_name}\n  version: {locked_version!r}\n".encode()
            + b"  repository: 'oci://registry.example.invalid/charts'\n"
            + f"digest: {digest}\n".encode()
        ),
        "child/charts/common/Chart.yaml": (
            b"apiVersion: v2\nname: common\n"
            + f"version: {chart_version!r}\n".encode()
        ),
    })
    _parent_for_archive(root, path)
    return root


def test_nested_archive_declared_constraint_binds_locked_resolved_version(
    tmp_path: Path,
) -> None:
    root = _nested_range_fixture(tmp_path)

    closure = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml")
    )
    outer = closure["artifacts"][0]
    common = outer["dependencies"]["artifacts"][0]
    binding = common["version_binding"]
    assert binding["declared_constraint"] == "2.x.x"
    assert binding["protected_lock_resolved_version"] == "2.18.0"
    assert binding["dependency_chart_version"] == "2.18.0"
    assert binding["satisfied"] is True
    assert binding["physical_dependency_identity"] == common[
        "physical_dependency"
    ]["physical_dependency_identity"]
    assert binding["logical_instance_identity"] == common[
        "logical_instance"
    ]["logical_instance_identity"]
    validator = jsonschema.Draft202012Validator(REPORT._schema()).evolve(
        schema={"$ref": "#/$defs/helmDependencyClosure"}
    )
    validator.validate(closure)
    REPORT._validate_helm_dependency_closure(closure, "candidate")

    for field, replacement in (
        ("declared_constraint", "1.x.x"),
        ("constraint_engine_identity", "0" * 64),
        ("dependency_chart_version", "2.18.1"),
    ):
        tampered = copy.deepcopy(closure)
        changed = tampered["artifacts"][0]["dependencies"]["artifacts"][0][
            "version_binding"
        ]
        changed[field] = replacement
        body = dict(changed)
        body.pop("version_binding_identity")
        changed["version_binding_identity"] = REPORT._canonical_json_digest(body)
        with pytest.raises(DomainError, match="version"):
            REPORT._validate_helm_dependency_closure(tampered, "candidate")


@pytest.mark.parametrize(
    ("declared", "locked", "chart", "locked_name", "reason"),
    (
        ("1.x.x", "2.18.0", "2.18.0", "common", "CONSTRAINT_MISMATCH"),
        (">=>2.0.0", "2.18.0", "2.18.0", "common", "CONSTRAINT_UNSUPPORTED"),
        ("2.x.x", "not-semver", "not-semver", "common", "RESOLVED_VERSION_INVALID"),
        ("2.x.x", "2.18.0", "2.18.1", "common", "UNREPRODUCIBLE_DEPENDENCIES"),
        ("2.x.x", "2.18.0", "2.18.0", "other", "UNREPRODUCIBLE_DEPENDENCIES"),
    ),
)
def test_nested_archive_version_binding_failures_remain_typed(
    tmp_path: Path,
    declared: str,
    locked: str,
    chart: str,
    locked_name: str,
    reason: str,
) -> None:
    root = _nested_range_fixture(
        tmp_path,
        declared_version=declared,
        locked_version=locked,
        chart_version=chart,
        locked_name=locked_name,
    )
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    assert reason in caught.value.reason_code


def test_dependency_version_yaml_scalar_types_fail_closed(tmp_path: Path) -> None:
    root = _nested_range_fixture(tmp_path, declared_version=2)
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    assert caught.value.reason_code == "UNREPRODUCIBLE_DEPENDENCIES"


def test_nested_archive_multiple_aliases_activation_imports_and_globals(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, alias: first, version: 1.0.0, repository: file://grand}\n"
            b"- {name: grand, alias: second, version: 1.0.0, repository: file://grand}\n"
            b"- name: other\n  version: 2.0.0\n  repository: file://other\n"
            b"  condition: other.enabled\n  tags: [nested]\n"
            b"  import-values: [{child: exports.data, parent: imported}]\n"
        ),
        "child/values.yaml": (
            b"other:\n  enabled: true\ntags:\n  nested: true\n"
            b"global:\n  region: fixture\n"
        ),
        "child/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: child}\n"
        ),
        "child/charts/grand/Chart.yaml": (
            b"apiVersion: v2\nname: grand\nversion: 1.0.0\n"
        ),
        "child/charts/grand/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: grand}\n"
        ),
        "child/charts/other/Chart.yaml": (
            b"apiVersion: v2\nname: other\nversion: 2.0.0\n"
        ),
        "child/charts/other/values.yaml": (
            b"exports:\n  data:\n    retained: true\n"
        ),
        "child/charts/other/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: other}\n"
        ),
    })
    _parent_for_archive(root, path)
    (root / "values.yaml").write_text(
        "child:\n  global:\n    owner: protected\n", encoding="utf-8"
    )
    executable = tmp_path / "fake-helm"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    spec = H.HelmRenderSpec(
        chart_root=root,
        helm_executable=executable,
        release_name="review",
        namespace="default",
        kube_version="1.31.0",
    )
    root_values, _root_values_identity = H._protected_values(spec)

    closure = H._validate_dependencies(
        root,
        H._strict_yaml(root / "Chart.yaml", "Chart.yaml"),
        root_values,
    )
    protected_values, _protected_values_identity = H._protected_values(spec, closure)
    outer = closure["artifacts"][0]
    nested = outer["dependencies"]["artifacts"]
    first, second, other = nested
    assert first["physical_dependency"]["physical_dependency_identity"] == (
        second["physical_dependency"]["physical_dependency_identity"]
    )
    assert first["logical_instance"]["logical_instance_identity"] != (
        second["logical_instance"]["logical_instance_identity"]
    )
    assert {item["logical_instance"]["effective_name"] for item in nested} == {
        "first", "second", "other",
    }
    assert other["activation"]["result"] is True
    assert other["activation"]["tag_inputs"] == [{"tag": "nested", "value": True}]
    assert other["imports"] == [{"child": "exports.data", "parent": "imported"}]
    assert other["logical_instance"]["global_values_sha256"] == H._canonical_sha({
        "region": "fixture", "owner": "protected",
    })
    child_context = H._values_for_source(
        protected_values, "charts/child/templates/resource.yaml"
    )
    assert child_context["imported"] == {"retained": True}
    assert child_context["global"] == {
        "region": "fixture", "owner": "protected",
    }
    assert outer["values_provenance"][
        "import_values_contribution_sha256"
    ] != H._canonical_sha([])
    assert outer["values_provenance"]["effective_values_root_sha256"] == (
        outer["logical_instance"]["effective_values_root_sha256"]
    )
    sources = dict(H._template_sources(root, closure))
    assert "charts/child/charts/first/templates/resource.yaml" in sources
    assert "charts/child/charts/second/templates/resource.yaml" in sources
    assert "charts/child/charts/other/templates/resource.yaml" in sources


def _archive_values_namespace_fixture(tmp_path: Path) -> tuple[Path, H.HelmRenderSpec]:
    root = _chart(tmp_path)
    dependency = root / "charts" / "child-1.2.3.tgz"
    nested = [{
        "name": "common", "version": "2.0.0",
        "repository": "https://charts.example.invalid",
    }]
    _archive(dependency, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: common, version: 2.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
        ),
        "child/Chart.lock": (
            b"dependencies:\n- {name: common, version: 2.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
            + f"digest: {H._helm_dependency_digest(nested, nested)}\n".encode()
        ),
        "child/values.yaml": b"namespaceOverride: ''\nmessage: default\n",
        "child/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: child\n"
            b"  namespace: {{ include \"common.names.namespace\" . }}\n"
        ),
        "child/charts/common/Chart.yaml": (
            b"apiVersion: v2\nname: common\nversion: 2.0.0\ntype: library\n"
        ),
        "child/charts/common/templates/_names.tpl": (
            b"{{- define \"common.names.namespace\" -}}\n"
            b"{{ default .Release.Namespace .Values.namespaceOverride "
            b"| trunc 63 | trimSuffix \"-\" }}\n{{- end -}}\n"
        ),
    })
    requirements = [{
        "name": "child", "alias": "aliased", "version": "1.2.3",
        "repository": "https://charts.example.invalid",
    }]
    locked = [{
        "name": "child", "version": "1.2.3",
        "repository": "https://charts.example.invalid",
    }]
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, alias: aliased, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n",
        encoding="utf-8",
    )
    (root / "Chart.lock").write_text(
        "dependencies:\n- {name: child, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n"
        f"digest: {H._helm_dependency_digest(requirements, locked)}\n",
        encoding="utf-8",
    )
    (root / "values.yaml").write_text(
        "aliased:\n  message: parent\n", encoding="utf-8"
    )
    (root / "rendered.fixture").write_text(
        "---\n# Source: parent/charts/aliased/templates/resource.yaml\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
        "  name: child\n  namespace: review-ns\n",
        encoding="utf-8",
    )
    executable = tmp_path / "fake-helm"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v4.2.4'; exit 0; fi\n"
        "cat rendered.fixture\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return root, H.HelmRenderSpec(
        chart_root=root,
        helm_executable=executable,
        release_name="review",
        namespace="review-ns",
        kube_version="1.31.0",
    )


def _directory_values_namespace_fixture(
    tmp_path: Path,
) -> tuple[Path, H.HelmRenderSpec]:
    root = _chart(tmp_path)
    child = root / "charts" / "child"
    common = child / "charts" / "common"
    (child / "templates").mkdir(parents=True)
    (common / "templates").mkdir(parents=True)
    nested = [{
        "name": "common", "version": "2.0.0",
        "repository": "https://charts.example.invalid",
    }]
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
        "- {name: common, version: 2.0.0, "
        "repository: 'https://charts.example.invalid'}\n",
        encoding="utf-8",
    )
    (child / "Chart.lock").write_text(
        "dependencies:\n- {name: common, version: 2.0.0, "
        "repository: 'https://charts.example.invalid'}\n"
        f"digest: {H._helm_dependency_digest(nested, nested)}\n",
        encoding="utf-8",
    )
    (child / "values.yaml").write_text(
        "namespaceOverride: ''\nmessage: default\n", encoding="utf-8"
    )
    (child / "templates" / "resource.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: child\n"
        '  namespace: {{ include "common.names.namespace" . }}\n',
        encoding="utf-8",
    )
    (common / "Chart.yaml").write_text(
        "apiVersion: v2\nname: common\nversion: 2.0.0\ntype: library\n",
        encoding="utf-8",
    )
    (common / "templates" / "_names.tpl").write_text(
        '{{- define "common.names.namespace" -}}\n'
        '{{ default .Release.Namespace .Values.namespaceOverride '
        '| trunc 63 | trimSuffix "-" }}\n{{- end -}}\n',
        encoding="utf-8",
    )
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, alias: aliased, version: 1.2.3, repository: file://child}\n",
        encoding="utf-8",
    )
    (root / "values.yaml").write_text(
        "aliased:\n  message: parent\n", encoding="utf-8"
    )
    (root / "rendered.fixture").write_text(
        "---\n# Source: parent/charts/aliased/templates/resource.yaml\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
        "  name: child\n  namespace: review-ns\n",
        encoding="utf-8",
    )
    executable = tmp_path / "fake-helm"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v4.2.4'; exit 0; fi\n"
        "cat rendered.fixture\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return root, H.HelmRenderSpec(
        chart_root=root,
        helm_executable=executable,
        release_name="review",
        namespace="review-ns",
        kube_version="1.31.0",
    )


def test_archive_backed_logical_values_reach_bounded_namespace_proof(
    tmp_path: Path,
) -> None:
    root, spec = _archive_values_namespace_fixture(tmp_path)

    evidence = H.materialize_helm(spec, tmp_path / "output")

    dependency = evidence.chart["dependencies"]["artifacts"][0]
    provenance = evidence.documents[0].namespace_provenance
    logical = dependency["logical_instance"]
    values = dependency["values_provenance"]
    assert dependency["logical_instance"]["effective_name"] == "aliased"
    assert values["dependency_defaults_source_kind"] == "ARCHIVE_MEMBER"
    assert values["parent_scoped_values_sha256"] == H._canonical_sha({
        "message": "parent"
    })
    assert values["effective_values_root_sha256"] == logical[
        "effective_values_root_sha256"
    ]
    assert provenance["resolution"] == "STATIC_NAMED_NAMESPACE_TEMPLATE"
    assert provenance["effective_namespace"] == "review-ns"
    assert provenance["logical_values_binding"]["logical_instance_identity"] == (
        logical["logical_instance_identity"]
    )
    assert provenance["logical_values_binding"][
        "effective_values_root_sha256"
    ] == values["effective_values_root_sha256"]


def test_archive_and_directory_backing_have_equivalent_values_namespace_semantics(
    tmp_path: Path,
) -> None:
    archive_root, archive_spec = _archive_values_namespace_fixture(
        tmp_path / "archive"
    )
    directory_root, directory_spec = _directory_values_namespace_fixture(
        tmp_path / "directory"
    )

    archive = H.materialize_helm(archive_spec, tmp_path / "archive-output")
    directory = H.materialize_helm(directory_spec, tmp_path / "directory-output")
    archive_dependency = archive.chart["dependencies"]["artifacts"][0]
    directory_dependency = directory.chart["dependencies"]["artifacts"][0]
    archive_values = dict(archive_dependency["values_provenance"])
    directory_values = dict(directory_dependency["values_provenance"])
    for value in (archive_values, directory_values):
        value.pop("dependency_defaults_source_kind")
        value.pop("dependency_defaults_source_path")
        value.pop("dependency_defaults_source_sha256")
        value.pop("logical_instance_identity")
        value.pop("provenance_identity")

    assert archive_values == directory_values
    assert archive.documents[0].namespace == directory.documents[0].namespace
    assert archive.documents[0].resource_identity == directory.documents[0].resource_identity
    assert archive.documents[0].namespace_provenance["resolution"] == (
        directory.documents[0].namespace_provenance["resolution"]
    )
    assert archive_dependency["physical_dependency"][
        "physical_dependency_identity"
    ] != directory_dependency["physical_dependency"]["physical_dependency_identity"]


def test_namespace_values_binding_rejects_wrong_instance_and_stale_digests(
    tmp_path: Path,
) -> None:
    _root, spec = _archive_values_namespace_fixture(tmp_path)
    evidence = H.materialize_helm(spec, tmp_path / "output").canonical_dict()
    document = evidence["documents"][0]
    dependency = evidence["chart"]["dependencies"]["artifacts"][0]

    for field, replacement in (
        ("logical_instance_identity", "0" * 64),
        ("effective_values_root_sha256", "1" * 64),
        ("values_provenance_identity", "2" * 64),
        ("source_marker_context", "charts/other"),
    ):
        tampered = copy.deepcopy(evidence)
        binding = tampered["documents"][0]["namespace_provenance"][
            "logical_values_binding"
        ]
        binding[field] = replacement
        binding_body = dict(binding)
        binding_body.pop("binding_identity")
        binding["binding_identity"] = H._canonical_sha(binding_body)
        namespace_body = dict(tampered["documents"][0]["namespace_provenance"])
        namespace_body.pop("provenance_identity")
        tampered["documents"][0]["namespace_provenance"][
            "provenance_identity"
        ] = H._canonical_sha(namespace_body)
        with pytest.raises(DomainError, match="logical Values context"):
            REPORT._validate_helm_a6_extensions(tampered, "candidate")

    assert document["namespace_provenance"]["logical_values_binding"][
        "logical_instance_identity"
    ] == dependency["logical_instance"]["logical_instance_identity"]


def test_dependency_values_provenance_rejects_scope_and_identity_substitution(
    tmp_path: Path,
) -> None:
    _root, spec = _archive_values_namespace_fixture(tmp_path)
    evidence = H.materialize_helm(spec, tmp_path / "output").canonical_dict()
    closure = evidence["chart"]["dependencies"]

    for field, replacement, message in (
        ("effective_name", "other", "Values identity"),
        ("effective_values_root_sha256", "0" * 64, "Values identity"),
        ("global_values_sha256", "1" * 64, "Values identity"),
        ("source_marker_context", "charts/other", "Values identity"),
        ("logical_instance_identity", "2" * 64, "Values identity"),
        ("dependency_defaults_source_path", "../escape", "Values path"),
    ):
        tampered = copy.deepcopy(closure)
        values = tampered["artifacts"][0]["values_provenance"]
        values[field] = replacement
        body = dict(values)
        body.pop("provenance_identity")
        values["provenance_identity"] = H._canonical_sha(body)
        with pytest.raises(DomainError, match=message):
            REPORT._validate_helm_dependency_closure(tampered, "candidate")


@pytest.mark.parametrize(
    ("dependency", "extra_members", "reason"),
    (
        (
            "- {name: grand, version: 1.0.0, repository: file://grand}\n",
            {},
            "HELM_DEPENDENCY_ARTIFACT_MISSING",
        ),
        (
            "- {name: grand, version: 1.0.0, "
            "repository: 'https://charts.example.invalid'}\n",
            {},
            "HELM_DEPENDENCY_REMOTE_RESOLUTION_REQUIRED",
        ),
        (
            "- {name: grand, version: 1.0.0, repository: file://grand}\n",
            {"child/charts/grand/Chart.yaml": b"not: [valid"},
            "UNREPRODUCIBLE_DEPENDENCIES",
        ),
    ),
)
def test_nested_archive_incomplete_or_malformed_closure_fails_closed(
    tmp_path: Path,
    dependency: str,
    extra_members: dict[str, bytes],
    reason: str,
) -> None:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    members = {
        "child/Chart.yaml": (
            "apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            + dependency
        ).encode(),
        **extra_members,
    }
    _archive(path, members=members)
    _parent_for_archive(root, path)
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(
            root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml")
        )
    assert caught.value.reason_code == reason


def test_nested_archive_lock_disagreement_and_effective_name_collision_fail_closed(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    base = {
        "child/charts/grand/Chart.yaml": (
            b"apiVersion: v2\nname: grand\nversion: 1.0.0\n"
        ),
    }
    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, version: 1.0.0, repository: file://grand}\n"
        ),
        "child/Chart.lock": (
            b"dependencies:\n- {name: other, version: 1.0.0, repository: file://grand}\n"
            + f"digest: sha256:{'0' * 64}\n".encode()
        ),
        **base,
    })
    _parent_for_archive(root, path)
    with pytest.raises(H.HelmMaterializationError, match="does not match"):
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))

    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, alias: same, version: 1.0.0, repository: file://grand}\n"
            b"- {name: grand, alias: same, version: 1.0.0, repository: file://grand}\n"
        ),
        **base,
    })
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    assert caught.value.reason_code == "HELM_DEPENDENCY_EFFECTIVE_NAME_COLLISION"


def test_archive_containing_nested_archive_retains_both_archive_layers(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    inner = _archive_payload({
        "grand/Chart.yaml": b"apiVersion: v2\nname: grand\nversion: 1.0.0\n",
        "grand/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: grand}\n"
        ),
    })
    nested = [{
        "name": "grand", "version": "1.0.0",
        "repository": "https://charts.example.invalid",
    }]
    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, version: 1.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
        ),
        "child/Chart.lock": (
            b"dependencies:\n- {name: grand, version: 1.0.0, "
            b"repository: 'https://charts.example.invalid'}\n"
            + f"digest: {H._helm_dependency_digest(nested, nested)}\n".encode()
        ),
        "child/charts/grand-1.0.0.tgz": inner,
    })
    _parent_for_archive(root, path)

    closure = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml")
    )
    outer = closure["artifacts"][0]
    grand = outer["dependencies"]["artifacts"][0]
    assert grand["form"] == "archive-member-archive"
    assert grand["archive_member_provenance"]["outer_archive_sha256"] == (
        outer["archive_provenance"]["archive_sha256"]
    )
    assert grand["archive_provenance"]["archive_sha256"] == H._sha256(inner)
    assert "charts/child/charts/grand/templates/resource.yaml" in dict(
        H._template_sources(root, closure)
    )
    REPORT._validate_helm_dependency_closure(closure, "candidate")


def test_archive_duplicate_portable_paths_links_and_special_members_fail_closed(
    tmp_path: Path,
) -> None:
    exact = tmp_path / "exact-duplicate.tgz"
    with tarfile.open(exact, "w:gz") as archive:
        for payload in (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\n",
            b"apiVersion: v2\nname: child\nversion: 1.2.3\nchanged: true\n",
        ):
            info = tarfile.TarInfo("child/Chart.yaml")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    with pytest.raises(H.HelmMaterializationError, match="duplicate portable"):
        H._inspect_archive(exact, "child", "1.2.3")

    duplicate = tmp_path / "duplicate.tgz"
    with tarfile.open(duplicate, "w:gz") as archive:
        for name, payload in (
            ("child/Chart.yaml", b"apiVersion: v2\nname: child\nversion: 1.2.3\n"),
            ("child/chart.yaml", b"different"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    with pytest.raises(H.HelmMaterializationError, match="duplicate portable"):
        H._inspect_archive(duplicate, "child", "1.2.3")

    for kind in (tarfile.LNKTYPE, tarfile.SYMTYPE, tarfile.CHRTYPE):
        unsafe = tmp_path / f"unsafe-{kind!r}.tgz"
        with tarfile.open(unsafe, "w:gz") as archive:
            member = tarfile.TarInfo("child/unsafe")
            member.type = kind
            member.linkname = "child/Chart.yaml"
            archive.addfile(member)
        with pytest.raises(H.HelmMaterializationError, match="unsafe paths"):
            H._inspect_archive(unsafe, "child", "1.2.3")


def test_archive_unicode_portable_collision_and_identity_mutation_are_bound(
    tmp_path: Path,
) -> None:
    collision = tmp_path / "unicode.tgz"
    with tarfile.open(collision, "w:gz") as archive:
        for name, payload in (
            ("child/Chart.yaml", b"apiVersion: v2\nname: child\nversion: 1.2.3\n"),
            ("child/CAFÉ", b"one"),
            ("child/cafe\u0301", b"two"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    with pytest.raises(H.HelmMaterializationError, match="duplicate portable"):
        H._inspect_archive(collision, "child", "1.2.3")

    root = _chart(tmp_path / "mutation")
    path = root / "charts" / "child-1.2.3.tgz"
    members = {
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, version: 1.0.0, repository: file://grand}\n"
        ),
        "child/charts/grand/Chart.yaml": (
            b"apiVersion: v2\nname: grand\nversion: 1.0.0\n"
        ),
    }
    _archive(path, members=members)
    _parent_for_archive(root, path)
    before = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml")
    )["artifacts"][0]
    members["child/charts/grand/templates/new.yaml"] = b"kind: ConfigMap\n"
    _archive(path, members=members)
    after = H._validate_dependencies(
        root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml")
    )["artifacts"][0]
    assert before["sha256"] != after["sha256"]
    assert before["archive_provenance"]["provenance_identity"] != (
        after["archive_provenance"]["provenance_identity"]
    )


def test_nested_archive_depth_budget_and_repeated_identity_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, version: 1.0.0, repository: file://grand}\n"
        ),
        "child/charts/grand/Chart.yaml": (
            b"apiVersion: v2\nname: grand\nversion: 1.0.0\n"
        ),
    })
    _parent_for_archive(root, path)
    monkeypatch.setattr(H, "_MAX_TEMPLATE_CALL_DEPTH", 0)
    with pytest.raises(H.HelmMaterializationError, match="depth limit"):
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    monkeypatch.setattr(H, "_MAX_TEMPLATE_CALL_DEPTH", 32)
    digest = H._sha256(path.read_bytes())
    with pytest.raises(H.HelmMaterializationError, match="repeated identity"):
        H._validate_dependencies(
            root,
            H._strict_yaml(root / "Chart.yaml", "Chart.yaml"),
            archive_ancestry=(digest,),
        )


def test_nested_archive_cumulative_member_limit_and_inactive_source_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    inner = _archive_payload({
        "grand/Chart.yaml": b"apiVersion: v2\nname: grand\nversion: 1.0.0\n",
        "grand/templates/resource.yaml": b"kind: ConfigMap\n",
    })
    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, alias: dormant, version: 1.0.0, "
            b"repository: file://grand, condition: dormant.enabled}\n"
        ),
        "child/charts/grand-1.0.0.tgz": inner,
    })
    _parent_for_archive(root, path)
    monkeypatch.setattr(H, "_MAX_ARCHIVE_MEMBERS", 3)
    with pytest.raises(H.HelmMaterializationError, match="too many members") as caught:
        H._validate_dependencies(
            root,
            H._strict_yaml(root / "Chart.yaml", "Chart.yaml"),
            {"child": {"dormant": {"enabled": False}}},
        )
    assert caught.value.reason_code == "HELM_DEPENDENCY_LIMIT_EXCEEDED"

    monkeypatch.setattr(H, "_MAX_ARCHIVE_MEMBERS", 10_000)
    closure = H._validate_dependencies(
        root,
        H._strict_yaml(root / "Chart.yaml", "Chart.yaml"),
        {"child": {"dormant": {"enabled": False}}},
    )
    assert H._inactive_dependency_contexts(closure) == (
        "charts/child/charts/dormant",
    )


def test_nested_archive_inactive_source_marker_contradiction_fails_closed(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    path = root / "charts" / "child-1.2.3.tgz"
    _archive(path, members={
        "child/Chart.yaml": (
            b"apiVersion: v2\nname: child\nversion: 1.2.3\ndependencies:\n"
            b"- {name: grand, alias: dormant, version: 1.0.0, "
            b"repository: file://grand, condition: dormant.enabled}\n"
        ),
        "child/charts/grand/Chart.yaml": (
            b"apiVersion: v2\nname: grand\nversion: 1.0.0\n"
        ),
        "child/charts/grand/templates/resource.yaml": (
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: dormant}\n"
        ),
    })
    _parent_for_archive(root, path)
    (root / "values.yaml").write_text(
        "child:\n  dormant:\n    enabled: false\n", encoding="utf-8"
    )
    (root / "rendered.fixture").write_text(
        "---\n# Source: parent/charts/child/charts/dormant/templates/resource.yaml\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: dormant}\n",
        encoding="utf-8",
    )
    executable = tmp_path / "fake-helm"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v3.16.4'; exit 0; fi\n"
        "cat rendered.fixture\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    spec = H.HelmRenderSpec(
        chart_root=root,
        helm_executable=executable,
        release_name="review",
        namespace="default",
        kube_version="1.31.0",
    )
    with pytest.raises(H.HelmMaterializationError) as caught:
        H.materialize_helm(spec, tmp_path / "output")
    assert caught.value.reason_code == "HELM_DEPENDENCY_SOURCE_MARKER_CONTRADICTION"


def test_nested_archive_safe_extraction_and_internal_guards(
    tmp_path: Path,
) -> None:
    closure, path = _valid_nested_archive_closure(tmp_path / "valid")
    outer = closure["artifacts"][0]
    inspection = H._inspect_archive(path, "child", "1.2.3")
    extracted = H._write_archive_inspection(inspection, tmp_path / "extracted")
    assert extracted == tmp_path / "extracted" / "child"
    assert (extracted / "charts" / "grand" / "Chart.yaml").is_file()
    assert H._dependency_artifact_root(
        {"form": "local-directory", "physical_root_sha256": "a" * 64}
    ) == "a" * 64

    unavailable = H._ArchiveInspection(
        archive_sha256="a" * 64,
        chart_root="child",
        chart={},
        chart_yaml_sha256="b" * 64,
        members=(H._ArchiveMember(
            path="child/Chart.yaml", kind="file", mode=0o644,
            size=1, sha256="c" * 64, payload=None,
        ),),
        member_manifest_root_sha256="d" * 64,
        chart_member_subtree_root_sha256="e" * 64,
        expanded_files=(),
    )
    with pytest.raises(H.HelmMaterializationError, match="bytes are unavailable"):
        H._write_archive_inspection(unavailable, tmp_path / "unavailable")

    malformed_root = H._ArchiveInspection(
        archive_sha256=inspection.archive_sha256,
        chart_root="missing",
        chart=inspection.chart,
        chart_yaml_sha256=inspection.chart_yaml_sha256,
        members=inspection.members,
        member_manifest_root_sha256=inspection.member_manifest_root_sha256,
        chart_member_subtree_root_sha256=(
            inspection.chart_member_subtree_root_sha256
        ),
        expanded_files=inspection.expanded_files,
    )
    with pytest.raises(H.HelmMaterializationError, match="chart root is malformed"):
        H._write_archive_inspection(malformed_root, tmp_path / "malformed-root")
    with pytest.raises(H.HelmMaterializationError, match="cannot be safely inspected"):
        H._inspect_archive(tmp_path / "absent.tgz", "child", "1.2.3")
    with pytest.raises(H.HelmMaterializationError, match="subtree is unavailable"):
        H._archive_member_provenance(
            inspection,
            artifact_member_path="child/charts/absent",
            chart_member_path="child/charts/absent",
            chart_yaml_sha256="f" * 64,
            parent_dependency_identity=(
                outer["logical_instance"]["logical_instance_identity"]
            ),
        )


def test_nested_archive_reparenting_retains_recursive_member_provenance(
    tmp_path: Path,
) -> None:
    closure, _path = _valid_nested_archive_closure(tmp_path)
    replacement_parent = "f" * 64
    H._reparent_dependency_closure(closure, replacement_parent)
    outer = closure["artifacts"][0]
    nested = outer["dependencies"]["artifacts"][0]
    assert outer["logical_instance"]["parent_instance"] == replacement_parent
    assert nested["archive_member_provenance"]["parent_dependency_identity"] == (
        outer["logical_instance"]["logical_instance_identity"]
    )
    REPORT._validate_helm_dependency_closure(
        closure, "candidate", expected_parent=replacement_parent
    )


def test_nested_archive_semantic_provenance_tampering_fails_closed(
    tmp_path: Path,
) -> None:
    closure, _path = _valid_nested_archive_closure(tmp_path)

    def recanonicalize(record: dict, identity_key: str) -> None:
        body = dict(record)
        body.pop(identity_key, None)
        record[identity_key] = H._canonical_sha(body)

    mutations = []

    missing_member = copy.deepcopy(closure)
    missing_member["artifacts"][0]["dependencies"]["artifacts"][0].pop(
        "archive_member_provenance"
    )
    mutations.append(missing_member)

    bad_member_identity = copy.deepcopy(closure)
    bad_member_identity["artifacts"][0]["dependencies"]["artifacts"][0][
        "archive_member_provenance"
    ]["provenance_identity"] = "0" * 64
    mutations.append(bad_member_identity)

    bad_parent = copy.deepcopy(closure)
    member = bad_parent["artifacts"][0]["dependencies"]["artifacts"][0][
        "archive_member_provenance"
    ]
    member["parent_dependency_identity"] = "1" * 64
    recanonicalize(member, "provenance_identity")
    mutations.append(bad_parent)

    bad_containment = copy.deepcopy(closure)
    member = bad_containment["artifacts"][0]["dependencies"]["artifacts"][0][
        "archive_member_provenance"
    ]
    member["outer_archive_sha256"] = "2" * 64
    recanonicalize(member, "provenance_identity")
    mutations.append(bad_containment)

    bad_member_path = copy.deepcopy(closure)
    member = bad_member_path["artifacts"][0]["dependencies"]["artifacts"][0][
        "archive_member_provenance"
    ]
    member["artifact_member_path"] = "../escape"
    recanonicalize(member, "provenance_identity")
    mutations.append(bad_member_path)

    bad_kind = copy.deepcopy(closure)
    nested = bad_kind["artifacts"][0]["dependencies"]["artifacts"][0]
    physical = nested["physical_dependency"]
    physical["artifact_kind"] = "archive"
    recanonicalize(physical, "physical_dependency_identity")
    logical = nested["logical_instance"]
    logical["physical_dependency_identity"] = physical["physical_dependency_identity"]
    recanonicalize(logical, "logical_instance_identity")
    mutations.append(bad_kind)

    bad_root = copy.deepcopy(closure)
    nested = bad_root["artifacts"][0]["dependencies"]["artifacts"][0]
    physical = nested["physical_dependency"]
    physical["protected_artifact_root_sha256"] = "3" * 64
    recanonicalize(physical, "physical_dependency_identity")
    logical = nested["logical_instance"]
    logical["physical_dependency_identity"] = physical["physical_dependency_identity"]
    recanonicalize(logical, "logical_instance_identity")
    mutations.append(bad_root)

    duplicate_logical = copy.deepcopy(closure)
    nested_closure = duplicate_logical["artifacts"][0]["dependencies"]
    nested_closure["artifacts"].append(copy.deepcopy(nested_closure["artifacts"][0]))
    nested_closure["count"] = 2
    mutations.append(duplicate_logical)

    duplicate_effective = copy.deepcopy(closure)
    nested_closure = duplicate_effective["artifacts"][0]["dependencies"]
    duplicate = copy.deepcopy(nested_closure["artifacts"][0])
    duplicate["logical_instance"]["ordinal"] = 1
    recanonicalize(duplicate["logical_instance"], "logical_instance_identity")
    nested_closure["artifacts"].append(duplicate)
    nested_closure["count"] = 2
    mutations.append(duplicate_effective)

    for mutated in mutations:
        with pytest.raises(DomainError, match="report-v1 semantic violation"):
            REPORT._validate_helm_dependency_closure(mutated, "candidate")


@pytest.mark.parametrize(
    ("members", "reason"),
    (
        ({"../escape": b"x"}, "UNSAFE_DEPENDENCY_ARCHIVE"),
        ({"other/Chart.yaml": b"apiVersion: v2\nname: other\nversion: 1.2.3\n"},
         "UNSAFE_DEPENDENCY_ARCHIVE"),
        ({"child/Chart.yaml": b"apiVersion: v2\nname: wrong\nversion: 1.2.3\n"},
         "UNREPRODUCIBLE_DEPENDENCIES"),
    ),
)
def test_dependency_archive_identity_and_path_adversarial_cases(
    tmp_path: Path, members: dict[str, bytes], reason: str,
) -> None:
    path = tmp_path / "child.tgz"
    _archive(path, members=members)
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._inspect_archive(path, "child", "1.2.3")
    assert caught.value.reason_code == reason


def test_dependency_archive_links_and_invalid_bytes_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "linked.tgz"
    with tarfile.open(path, "w:gz") as archive:
        link = tarfile.TarInfo("child/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        archive.addfile(link)
    with pytest.raises(H.HelmMaterializationError, match="unsafe paths"):
        H._inspect_archive(path, "child", "1.2.3")
    invalid = tmp_path / "invalid.tgz"
    invalid.write_bytes(b"not an archive")
    with pytest.raises(H.HelmMaterializationError, match="safely inspected"):
        H._inspect_archive(invalid, "child", "1.2.3")


@pytest.mark.parametrize(
    ("chart_tail", "reason"),
    (
        (
            "dependencies:\n- {name: child, version: 1.2.3, "
            "repository: 'https://charts.example.invalid'}\n",
            "HELM_DEPENDENCY_REMOTE_RESOLUTION_REQUIRED",
        ),
        (
            "dependencies:\n- {name: child, version: 1.2.3, "
            "repository: 'file://missing'}\n",
            "HELM_DEPENDENCY_ARTIFACT_MISSING",
        ),
    ),
)
def test_missing_dependency_bytes_have_exact_fail_closed_reason(
    tmp_path: Path, chart_tail: str, reason: str,
) -> None:
    root = _chart(tmp_path)
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\n" + chart_tail,
        encoding="utf-8",
    )
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    assert caught.value.reason_code == reason


def test_dependency_lock_and_artifact_identity_disagreement_fail_closed(
    tmp_path: Path,
) -> None:
    root = _chart(tmp_path)
    _child(root)
    (root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n"
        "- {name: child, version: 1.2.3, repository: 'https://charts.example.invalid'}\n",
        encoding="utf-8",
    )
    (root / "Chart.lock").write_text(
        "dependencies:\n- {name: other, version: 1.2.3, "
        "repository: 'https://charts.example.invalid'}\n"
        f"digest: sha256:{'0' * 64}\n",
        encoding="utf-8",
    )
    with pytest.raises(H.HelmMaterializationError, match="does not match"):
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))
    (root / "charts" / "child" / "Chart.yaml").write_text(
        "apiVersion: v2\nname: other\nversion: 1.2.3\n", encoding="utf-8"
    )
    (root / "Chart.lock").unlink()
    with pytest.raises(H.HelmMaterializationError, match="identity"):
        H._validate_dependencies(root, H._strict_yaml(root / "Chart.yaml", "Chart.yaml"))


@pytest.mark.parametrize(
    "entry",
    (
        None,
        {"name": "child", "version": "1", "repository": "file://child", "extra": True},
        {"name": "child", "version": "1", "repository": "file://child", "alias": "bad/name"},
        {"name": "child", "version": "1", "repository": "file://child", "condition": 1},
        {"name": "child", "version": "1", "repository": "file://child", "tags": "tag"},
        {"name": "child", "version": "1", "repository": "file://child", "enabled": "yes"},
        {"name": "child", "version": "1", "repository": "file://child", "import-values": "x"},
        {"name": "child", "version": "1", "repository": "file://child", "import-values": [1]},
        {"name": "child", "version": "1", "repository": "file://child", "import-values": [""]},
        {"name": "child", "version": "1", "repository": "file://child", "import-values": [{"child": "x", "parent": "bad/path"}]},
    ),
)
def test_dependency_record_rejects_every_adjacent_metadata_shape(entry: object) -> None:
    with pytest.raises(H.HelmMaterializationError):
        H._dependency_record(entry)


def test_dependency_record_preserves_closed_optional_metadata() -> None:
    entry = {
        "name": "child", "version": "1", "repository": "file://child",
        "condition": "child.enabled", "tags": ["demo"], "enabled": True,
        "import-values": ["exports", {"child": "exports.data", "parent": "data"}],
        "alias": "renamed",
    }
    assert H._dependency_record(entry) == entry
    with pytest.raises(H.HelmMaterializationError, match="identity is incomplete"):
        H._dependency_key({"name": "child", "version": ""})


@pytest.mark.parametrize(
    ("values", "message"),
    (({"tags": []}, "not a mapping"), ({"tags": {"demo": "yes"}}, "not Boolean")),
)
def test_dependency_tag_activation_rejects_ambiguous_values(
    values: dict, message: str,
) -> None:
    record = H._dependency_record({
        "name": "child", "version": "1", "repository": "file://child", "tags": ["demo"],
    })
    with pytest.raises(H.HelmMaterializationError, match=message):
        H._dependency_activation(record, values)


def test_dependency_tag_activation_and_inactive_context_recursion() -> None:
    record = H._dependency_record({
        "name": "child", "version": "1", "repository": "file://child", "tags": ["one", "two"],
    })
    assert H._dependency_activation(record, {"tags": {"one": False, "two": True}})["result"]
    closure = {"artifacts": [{
        "name": "child", "logical_context": "charts/alias", "activation": {"result": False},
        "dependencies": {"artifacts": [{"name": "grand", "activation": {"result": False}}]},
    }]}
    assert H._inactive_dependency_contexts(closure) == ("charts/alias", "charts/grand")


@pytest.mark.parametrize(
    "repository",
    ("https://example.invalid/chart", "file://", "file://child?x=1", "file:///absolute", "file://bad\\path"),
)
def test_local_dependency_source_rejects_nonlocal_or_nonportable_paths(
    tmp_path: Path, repository: str,
) -> None:
    with pytest.raises(H.HelmMaterializationError):
        H._local_dependency_source(tmp_path, tmp_path, repository)


def test_archive_limits_empty_archive_and_local_archive_are_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "empty.tgz"
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo("child")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        chart = tarfile.TarInfo("child/Chart.yaml")
        chart.type = tarfile.DIRTYPE
        archive.addfile(chart)
    with pytest.raises(H.HelmMaterializationError):
        H._inspect_archive(path, "child", "1.2.3")

    regular = tmp_path / "regular.tgz"
    _archive(regular)
    monkeypatch.setattr(H, "_MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(H.HelmMaterializationError, match="too many members"):
        H._inspect_archive(regular, "child", "1.2.3")
    monkeypatch.setattr(H, "_MAX_ARCHIVE_MEMBERS", 4096)
    monkeypatch.setattr(H, "_MAX_ARCHIVE_EXPANDED_BYTES", 1)
    with pytest.raises(H.HelmMaterializationError, match="expands beyond"):
        H._inspect_archive(regular, "child", "1.2.3")


def test_contained_file_archive_and_unsupported_file_shapes(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    root = _chart(repository)
    archive = repository / "child.tgz"
    _archive(archive)
    chart = {
        "dependencies": [{
            "name": "child", "version": "1.2.3", "repository": "file://../child.tgz",
            "alias": "local",
        }]
    }
    result = H._validate_dependencies(root, chart, repository_root=repository)
    assert result["artifacts"][0]["form"] == "local-archive"
    unsupported = repository / "child.txt"
    unsupported.write_text("not a chart", encoding="utf-8")
    chart["dependencies"][0]["repository"] = "file://../child.txt"
    with pytest.raises(H.HelmMaterializationError) as caught:
        H._validate_dependencies(root, chart, repository_root=repository)
    assert caught.value.reason_code == "HELM_DEPENDENCY_ARTIFACT_MISSING"


def test_logical_dependency_closure_is_schema_and_semantically_bound(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    root = _chart(repository)
    child = repository / "child"
    (child / "templates").mkdir(parents=True)
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: child\nversion: 1.2.3\n", encoding="utf-8"
    )
    (child / "templates" / "resource.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: child}\n",
        encoding="utf-8",
    )
    chart = {
        "dependencies": [{
            "name": "child", "alias": "renamed", "version": "1.2.3",
            "repository": "file://../child", "condition": "renamed.enabled",
            "import-values": [{"child": "exports.data", "parent": "data"}],
        }]
    }
    closure = H._validate_dependencies(
        root,
        chart,
        {"renamed": {"enabled": True}, "global": {"region": "test"}},
        repository_root=repository,
    )
    validator = jsonschema.Draft202012Validator(REPORT._schema()).evolve(
        schema={"$ref": "#/$defs/helmDependencyClosure"}
    )
    validator.validate(closure)
    REPORT._validate_helm_dependency_closure(closure, "candidate")
    logical_files = REPORT._helm_logical_file_sha({
        "chart": {
            "files": [{
                "path": "Chart.yaml", "sha256": H._sha256(
                    (root / "Chart.yaml").read_bytes()
                ),
            }],
            "dependencies": closure,
        },
    }, "candidate")
    assert "charts/renamed/templates/resource.yaml" in logical_files

    def recanonicalize_logical(value: dict) -> None:
        logical = value["artifacts"][0]["logical_instance"]
        body = dict(logical)
        body.pop("logical_instance_identity")
        logical["logical_instance_identity"] = REPORT._canonical_json_digest(body)

    def mutate_parent(value: dict) -> None:
        value["artifacts"][0]["logical_instance"]["parent_instance"] = "other"
        recanonicalize_logical(value)

    def mutate_activation_digest(value: dict) -> None:
        value["artifacts"][0]["logical_instance"][
            "activation_metadata_sha256"
        ] = "0" * 64
        recanonicalize_logical(value)

    mutations = (
        (lambda value: value.update(count=2), "count"),
        (lambda value: value["artifacts"][0].update(expanded_files=[{"path": "x"}]), "expanded files"),
        (lambda value: value["artifacts"][0].update(source_repository_path="../escape"), "unsafe"),
        (lambda value: value["artifacts"][0].update(physical_root_sha256="0" * 64), "physical root"),
        (lambda value: value["artifacts"][0].pop("physical_dependency"), "incomplete"),
        (lambda value: value["artifacts"][0]["physical_dependency"].update(physical_dependency_identity="0" * 64), "physical dependency identity"),
        (lambda value: value["artifacts"][0]["physical_dependency"].update(declared_name="other"), "physical dependency identity"),
        (lambda value: value["artifacts"][0]["logical_instance"].update(logical_instance_identity="0" * 64), "logical dependency identity"),
        (mutate_parent, "logical dependency identity"),
        (lambda value: value["artifacts"][0].pop("activation"), "metadata is incomplete"),
        (mutate_activation_digest, "metadata is contradictory"),
        (lambda value: value["artifacts"][0].update(logical_context="charts/other"), "source context"),
    )
    for mutation, message in mutations:
        tampered = copy.deepcopy(closure)
        mutation(tampered)
        with pytest.raises(H.DomainError, match=message):
            REPORT._validate_helm_dependency_closure(tampered, "candidate")


def test_dependency_closure_metadata_lock_and_values_fail_closed(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    with pytest.raises(H.HelmMaterializationError, match="must be a list"):
        H._validate_dependencies(root, {"dependencies": {}})
    with pytest.raises(H.HelmMaterializationError, match="depth limit"):
        H._validate_dependencies(root, {}, depth=H._MAX_TEMPLATE_CALL_DEPTH + 1)
    with pytest.raises(H.HelmMaterializationError, match="cycle"):
        H._validate_dependencies(root, {}, ancestry=(root.resolve(),))
    with pytest.raises(H.HelmMaterializationError, match="identity is incomplete"):
        H._validate_dependencies(root, {"dependencies": [{"name": "", "version": "1"}]})

    _child(root)
    chart = {"dependencies": [{
        "name": "child", "version": "1.2.3", "repository": "https://example.invalid",
    }]}
    lock = root / "Chart.lock"
    lock.write_text(
        "dependencies:\n- {name: child, version: 1.2.3, repository: 'https://example.invalid'}\n"
        "digest: malformed\n",
        encoding="utf-8",
    )
    with pytest.raises(H.HelmMaterializationError, match="malformed"):
        H._validate_dependencies(root, chart)
    lock.write_text(
        "dependencies:\n- {name: child, version: 1.2.3, repository: 'https://example.invalid'}\n"
        f"digest: sha256:{'0' * 64}\n",
        encoding="utf-8",
    )
    with pytest.raises(H.HelmMaterializationError, match="out of sync"):
        H._validate_dependencies(root, chart)

    chart["dependencies"][0].update({"repository": "file://child", "alias": "alias"})
    lock.unlink()
    with pytest.raises(H.HelmMaterializationError, match="Values roots"):
        H._validate_dependencies(root, chart, {"alias": [], "global": {}})
    chart["dependencies"][0].pop("alias")
    with pytest.raises(H.HelmMaterializationError, match="Values root is not a mapping"):
        H._validate_dependencies(root, chart, {"child": "bad"})
    with pytest.raises(H.HelmMaterializationError, match="global dependency"):
        H._validate_dependencies(root, chart, {"child": {}, "global": "bad"})


def test_lock_without_dependencies_and_undeclared_chart_entries(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    (root / "Chart.lock").write_text("protected arbitrary bytes\n", encoding="utf-8")
    result = H._validate_dependencies(root, {})
    assert result["chart_lock_relevance"] == "NON_PARTICIPATING"
    (root / "Chart.lock").unlink()

    charts = root / "charts"
    charts.mkdir()
    (charts / "stray.tgz").write_bytes(b"x")
    with pytest.raises(H.HelmMaterializationError, match="undeclared"):
        H._validate_dependencies(root, {})
    (charts / "stray.tgz").unlink()
    child = charts / "manual"
    child.mkdir()
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: wrong\nversion: 1.0.0\n", encoding="utf-8"
    )
    with pytest.raises(H.HelmMaterializationError, match="identity"):
        H._validate_dependencies(root, {})


def test_undeclared_nonregular_dependency_path_fails_closed(tmp_path: Path) -> None:
    root = _chart(tmp_path)
    charts = root / "charts"
    charts.mkdir()
    fifo = charts / "fifo"
    try:
        os.mkfifo(fifo)
        with pytest.raises(H.HelmMaterializationError, match="unsupported path type"):
            H._validate_dependencies(root, {})
    finally:
        fifo.unlink(missing_ok=True)


def test_template_node_graph_preserves_comments_trims_quotes_and_control() -> None:
    text = (
        'before {{/* protected comment */ -}} after '
        '{{ define "nested" }}{{ if .Values.enabled }}{{ "a\\\"b" }}'
        '{{ else }}fallback{{ end }}{{ end }}'
    )
    nodes = H._template_nodes(text)
    assert nodes[0] == ("text", "before ")
    graph = H._definition_graphs(text)["nested"]
    assert any(node[0] == "text" and node[1] == "fallback" for node in graph)
    assert any(node[0] == "action" for node in graph)


@pytest.mark.parametrize(
    ("text", "message"),
    (
        ("{{/* unclosed", "comment is not closed"),
        ("{{/* comment */ broken", "comment closing is ambiguous"),
        ("{{ action", "action is not closed"),
        ('{{ "unterminated }}', "action is not closed"),
    ),
)
def test_template_node_parser_fails_closed_on_ambiguous_syntax(
    text: str, message: str,
) -> None:
    with pytest.raises(H.HelmMaterializationError, match=message):
        H._template_nodes(text)


def test_definition_graph_rejects_nested_duplicate_and_unclosed_definitions() -> None:
    with pytest.raises(H.HelmMaterializationError, match="cannot be nested"):
        H._definition_graphs(
            '{{ define "one" }}{{ define "two" }}x{{ end }}{{ end }}'
        )
    with pytest.raises(H.HelmMaterializationError, match="non-equivalent"):
        H._definition_graphs(
            '{{ define "same" }}one{{ end }}{{ define "same" }}two{{ end }}'
        )
    with pytest.raises(H.HelmMaterializationError, match="not closed"):
        H._definition_graphs('{{ define "one" }}x')
    assert H._matching_parenthesis((H._ActionToken("x"),), 0) is None
    assert H._matching_parenthesis((H._ActionToken("("), H._ActionToken("x")), 0) is None


@pytest.mark.parametrize(
    ("actions", "values", "release", "expected"),
    (
        ((".Release.Namespace",), {}, "release", "release"),
        (("$.Release.Namespace",), {}, "release", "release"),
        ((".Values.namespace",), {"namespace": "chosen"}, "release", "chosen"),
        (("default .Release.Namespace .Values.namespace",), {}, "release", "release"),
        (("default .Release.Namespace .Values.namespace",), {"namespace": "chosen"}, "release", "chosen"),
        (("default .Release.Namespace .Values.namespace | trunc 63 | trimSuffix \"-\"",),
         {"namespace": "a" * 62 + "-trailing"}, "release", "a" * 62),
        (("if .Values.namespace", ".Values.namespace", "else", ".Release.Namespace", "end"),
         {"namespace": "chosen"}, "release", "chosen"),
        (("if .Values.namespace", ".Values.namespace", "else", ".Release.Namespace", "end"),
         {}, "release", "release"),
    ),
)
def test_namespace_helper_closed_positive_grammar(
    actions: tuple[str, ...], values: dict, release: str, expected: str,
) -> None:
    assert H._namespace_helper_value(H._TemplateActionScope("helper", actions), values, release) == expected


@pytest.mark.parametrize(
    ("actions", "values"),
    (
        (("default \"literal\" .Values.namespace",), {}),
        (("default .Release.Namespace .Values.missing | upper",), {}),
        (("default .Release.Namespace .Values.namespace | trunc 62",), {"namespace": "x"}),
        (("default .Release.Namespace .Values.namespace | trunc 63 | trimSuffix \"-\"",),
         {"namespace": "x" + "€" * 30}),
        (("if .Values.namespace", ".Values.other", "else", ".Release.Namespace", "end"),
         {"namespace": "x"}),
        (("if .Values.namespace", ".Values.namespace", "else", ".Values.other", "end"),
         {"namespace": "x"}),
        (("if .Values.namespace", ".Values.namespace", "else", ".Release.Namespace", "end"),
         {H._UNMODELED_VALUES: True}),
        (("if .Values.namespace", ".Values.namespace", "else", ".Release.Namespace", "end"),
         {"namespace": 3}),
        (("one", "two"), {}),
    ),
)
def test_namespace_helper_adjacent_forms_remain_unsupported(
    actions: tuple[str, ...], values: dict,
) -> None:
    assert H._namespace_helper_value(H._TemplateActionScope("helper", actions), values, "release") is None


@pytest.mark.parametrize(
    ("expression", "source", "expected"),
    (
        ('{{ template "ns" . }}', '{{ template "ns" . }}', ("ns", ".")),
        ('{{ include "ns" $ | quote }}', '{{ include "ns" $ | quote }}', ("ns", "$")),
        ('{{ include "ns" $root }}', '{{ $root := $ }}{{ include "ns" $root }}', ("ns", "$root")),
        ('{{ include "ns" $root }}', '{{ include "ns" $root }}', None),
        ('{{ include "ns" $root }}', '{{ if .Values.x }}{{ $root := . }}{{ end }}{{ include "ns" $root }}', None),
        ('{{ include "ns" $root }}', '{{ $root := . }}{{ $root = $ }}{{ include "ns" $root }}', None),
        ('{{ include "ns" $root }}', '{{ $root := . }}{{ include "ns" $root }}{{ $root := $ }}', None),
        ('{{ include "ns" . | upper }}', '{{ include "ns" . | upper }}', None),
        ('{{ include (printf "%s" "ns") . }}', '{{ include (printf "%s" "ns") . }}', None),
    ),
)
def test_namespace_call_dominance_and_adjacent_negative_grammar(
    expression: str, source: str, expected: tuple[str, str] | None,
) -> None:
    assert H._namespace_call(expression, source) == expected


def test_namespace_expression_canonicalizes_and_rejects_contradiction() -> None:
    assert H._namespace_expression("namespace: '{{ .Release.Namespace | quote }}'") == (
        "{{ .Release.Namespace }}"
    )
    assert H._namespace_expression('namespace: {{ include "ns" $ }}') == '{{ include "ns" . }}'
    assert H._namespace_expression("kind: ConfigMap\n") is None
    with pytest.raises(H.HelmMaterializationError, match="contradictory"):
        H._namespace_expression(
            "namespace: {{ .Release.Namespace }}\nnamespace: {{ .Values.namespace }}\n"
        )
