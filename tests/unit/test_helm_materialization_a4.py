"""0.1.0a4 bounded Helm materialization acceptance tests."""
from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

import iac_guard_v.helm as HELM
from iac_guard_v import api as API
from iac_guard_v.models import DomainError


DEPLOYMENT = """---
# Source: demo/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    metadata:
      labels: {app: demo}
    spec:
      containers:
      - name: app
        image: nginx
"""


def _executable(root: Path, body: str | None = None) -> Path:
    executable = root / "fake-helm"
    executable.write_text(
        body
        or "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v3.16.4'; exit 0; fi\n"
        "cat rendered.fixture\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _chart(root: Path, rendered: str = DEPLOYMENT, template: str = "") -> Path:
    chart = root / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: demo\nversion: 0.1.0\n", encoding="utf-8"
    )
    (chart / "templates" / "deployment.yaml").write_text(
        template or "{{- if .Values.enabled }}enabled{{- end }}\n", encoding="utf-8"
    )
    (chart / "rendered.fixture").write_text(rendered, encoding="utf-8")
    return chart


def _spec(root: Path, **changes) -> HELM.HelmRenderSpec:
    chart = changes.pop("chart_root", None)
    if chart is None:
        chart = _chart(root)
    executable = changes.pop("helm_executable", None)
    if executable is None:
        executable = _executable(root)
    values = {
        "chart_root": chart,
        "helm_executable": executable,
        "release_name": "review",
        "namespace": "default",
        "kube_version": "1.31.0",
    }
    values.update(changes)
    return HELM.HelmRenderSpec(**values)


def _failure(spec: HELM.HelmRenderSpec, root: Path) -> str:
    with pytest.raises(HELM.HelmMaterializationError) as caught:
        HELM.materialize_helm(spec, root / "output")
    return caught.value.reason_code


def test_h01_simple_chart_binds_deterministic_source_and_resource(tmp_path: Path) -> None:
    evidence = HELM.materialize_helm(_spec(tmp_path), tmp_path / "output")

    value = evidence.canonical_dict()
    assert value["status"] == "PASS"
    assert value["output"]["fresh_render_count"] == 2
    assert value["documents"][0]["resource_identity"] == (
        "apps/v1/Deployment/default/demo"
    )
    assert value["documents"][0]["source_template"] == "templates/deployment.yaml"
    assert (tmp_path / "output" / "rendered.yaml").read_text() == DEPLOYMENT


def test_h08_h45_multidocument_and_namespace_identity_are_exact(tmp_path: Path) -> None:
    rendered = DEPLOYMENT + """---
# Source: demo/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: demo, namespace: second}
"""
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=_chart(tmp_path, rendered)), tmp_path / "output"
    )

    assert [item.resource_identity for item in evidence.documents] == [
        "apps/v1/Deployment/default/demo",
        "apps/v1/Deployment/second/demo",
    ]
    assert [item.index for item in evidence.documents] == [1, 2]


def test_h10_yaml_map_order_changes_bytes_but_not_semantic_identity(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first_render = DEPLOYMENT.replace(
        "metadata:\n  name: demo",
        "metadata:\n  name: demo\n  namespace: default",
    )
    second_render = DEPLOYMENT.replace(
        "metadata:\n  name: demo",
        "metadata:\n  namespace: default\n  name: demo",
    )
    first = HELM.materialize_helm(
        _spec(first_root, chart_root=_chart(first_root, first_render)),
        tmp_path / "first-output",
    )
    second = HELM.materialize_helm(
        _spec(second_root, chart_root=_chart(second_root, second_render)),
        tmp_path / "second-output",
    )
    assert first.output["stdout_sha256"] != second.output["stdout_sha256"]
    assert first.documents[0].resource_identity == second.documents[0].resource_identity


def test_h20_implicit_nondefault_namespace_fails_closed(tmp_path: Path) -> None:
    assert _failure(_spec(tmp_path, namespace="monitoring"), tmp_path) == (
        "UNMODELED_RENDER_INPUT"
    )


def test_h11_h17_values_and_overrides_are_hashed_and_redacted(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    (chart / "secret-values.yaml").write_text(
        "password: do-not-publish-this\n", encoding="utf-8"
    )
    spec = _spec(
        tmp_path,
        chart_root=chart,
        values_files=("secret-values.yaml",),
        set_values=(("replicas", "2"),),
        set_strings=(("identifier", "001"),),
    )

    payload = HELM.materialize_helm(spec, tmp_path / "output").canonical_dict()
    serialized = json.dumps(payload)

    assert "do-not-publish-this" not in serialized
    assert '"001"' not in serialized
    assert payload["render_inputs"]["overrides"]["set_string"][0]["type"] == "string"
    assert payload["render_inputs"]["argv"].count("[REDACTED]") == 2


@pytest.mark.parametrize(
    "changes",
    (
        {"set_values": (("same", "one"),), "set_strings": (("same", "one"),)},
        {"api_versions": ("v1", "v1")},
        {"values_files": ("values.yaml", "values.yaml")},
    ),
)
def test_h16_duplicate_render_inputs_are_rejected(
    tmp_path: Path, changes: dict
) -> None:
    chart = _chart(tmp_path)
    (chart / "values.yaml").write_text("enabled: true\n", encoding="utf-8")
    with pytest.raises(DomainError):
        _spec(tmp_path, chart_root=chart, **changes)


def test_h13_repeated_set_key_preserves_order_and_last_value_identity(
    tmp_path: Path,
) -> None:
    evidence = HELM.materialize_helm(
        _spec(tmp_path, set_values=(("replicas", "1"), ("replicas", "2"))),
        tmp_path / "output",
    )
    overrides = evidence.render_inputs["overrides"]["set"]
    assert [item["value_sha256"] for item in overrides] == [
        HELM._sha256(b"1"),
        HELM._sha256(b"2"),
    ]
    assert evidence.render_inputs["argv"].count("[REDACTED]") == 2


def test_h18_h21_capability_inputs_change_materialization_identity(tmp_path: Path) -> None:
    first = HELM.materialize_helm(
        _spec(tmp_path, api_versions=("example.io/v1",)), tmp_path / "one"
    )
    second_root = tmp_path / "second-root"
    second_root.mkdir()
    second = HELM.materialize_helm(
        _spec(second_root, kube_version="1.32.0", api_versions=("example.io/v1",)),
        tmp_path / "two",
    )

    assert first.materialization_identity != second.materialization_identity
    assert first.render_inputs["kube_version"] == "1.31.0"


def test_h12_values_file_precedence_order_is_part_of_identity(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first_chart = _chart(first_root)
    second_chart = _chart(second_root)
    for chart in (first_chart, second_chart):
        (chart / "one.yaml").write_text("replicas: 1\n", encoding="utf-8")
        (chart / "two.yaml").write_text("replicas: 2\n", encoding="utf-8")
    first = HELM.materialize_helm(
        _spec(
            first_root,
            chart_root=first_chart,
            values_files=("one.yaml", "two.yaml"),
        ),
        tmp_path / "first-output",
    )
    second = HELM.materialize_helm(
        _spec(
            second_root,
            chart_root=second_chart,
            values_files=("two.yaml", "one.yaml"),
        ),
        tmp_path / "second-output",
    )
    assert first.render_inputs["values_files"] != second.render_inputs["values_files"]
    assert first.materialization_identity != second.materialization_identity


def test_h09_helper_bytes_are_bound_even_when_rendered_bytes_are_unchanged(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first_chart = _chart(first_root)
    second_chart = _chart(second_root)
    (first_chart / "templates" / "_helpers.tpl").write_text(
        '{{- define "demo.name" -}}demo{{- end -}}\n', encoding="utf-8"
    )
    (second_chart / "templates" / "_helpers.tpl").write_text(
        '{{- define "demo.name" -}}changed{{- end -}}\n', encoding="utf-8"
    )

    first = HELM.materialize_helm(
        _spec(first_root, chart_root=first_chart), tmp_path / "first-output"
    )
    second = HELM.materialize_helm(
        _spec(second_root, chart_root=second_chart), tmp_path / "second-output"
    )

    assert first.output["stdout_sha256"] == second.output["stdout_sha256"]
    assert first.chart["inventory_root_sha256"] != second.chart["inventory_root_sha256"]
    assert first.materialization_identity != second.materialization_identity


def test_h22_unpacked_local_subchart_is_bound(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
        "dependencies:\n- {name: child, version: 1.2.3, repository: 'file://child'}\n",
        encoding="utf-8",
    )
    child = chart / "charts" / "child"
    child.mkdir(parents=True)
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: child\nversion: 1.2.3\n", encoding="utf-8"
    )

    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )

    assert evidence.chart["dependencies"]["artifacts"] == [
        {
            "name": "child",
            "version": "1.2.3",
            "form": "directory",
            "expanded_files": [],
        }
    ]


def test_h24_vendored_archive_is_safely_bound(tmp_path: Path) -> None:
    rendered = """---
# Source: demo/charts/child/templates/child.yaml
apiVersion: v1
kind: ConfigMap
metadata: {name: child}
"""
    chart = _chart(tmp_path, rendered)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
        "dependencies:\n- {name: child, version: 1.2.3, repository: https://example.invalid}\n",
        encoding="utf-8",
    )
    dependency = {
        "name": "child", "version": "1.2.3", "repository": "https://example.invalid"
    }
    digest = HELM._helm_dependency_digest([dependency], [dependency])
    (chart / "Chart.lock").write_text(
        "dependencies:\n- {name: child, version: 1.2.3, repository: https://example.invalid}\n"
        f"digest: {digest}\ngenerated: 2026-08-24T00:00:00Z\n",
        encoding="utf-8",
    )
    charts = chart / "charts"
    charts.mkdir()
    with tarfile.open(charts / "child-1.2.3.tgz", "w:gz") as archive:
        for name, content in (
            ("child/Chart.yaml", b"apiVersion: v2\nname: child\nversion: 1.2.3\n"),
            (
                "child/templates/child.yaml",
                b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: child}\n",
            ),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))

    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )

    artifact = evidence.chart["dependencies"]["artifacts"][0]
    assert artifact["form"] == "archive"
    assert len(artifact["sha256"]) == 64
    assert {item["path"] for item in artifact["expanded_files"]} == {
        "charts/child/Chart.yaml",
        "charts/child/templates/child.yaml",
    }
    assert evidence.documents[0].source_template == "charts/child/templates/child.yaml"


def test_h24_dependency_alias_is_rejected_until_it_has_a_bound_identity_model(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
        "dependencies:\n"
        "- {name: child, alias: renamed, version: 1.2.3, repository: 'file://child'}\n",
        encoding="utf-8",
    )
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "UNREPRODUCIBLE_DEPENDENCIES"
    )


@pytest.mark.parametrize(
    ("repository", "lock", "vendor", "expected"),
    (
        ("https://example.invalid", False, False, "UNREPRODUCIBLE_DEPENDENCIES"),
        ("file://child", False, False, "UNREPRODUCIBLE_DEPENDENCIES"),
        ("https://example.invalid", True, False, "UNREPRODUCIBLE_DEPENDENCIES"),
    ),
)
def test_h25_h27_missing_or_unbound_dependencies_fail_closed(
    tmp_path: Path, repository: str, lock: bool, vendor: bool, expected: str
) -> None:
    chart = _chart(tmp_path)
    dependency = f"- {{name: child, version: 1.2.3, repository: '{repository}'}}\n"
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: demo\nversion: 0.1.0\ndependencies:\n" + dependency,
        encoding="utf-8",
    )
    if lock:
        (chart / "Chart.lock").write_text(
            "dependencies:\n" + dependency + f"digest: sha256:{'a' * 64}\n",
            encoding="utf-8",
        )
    assert vendor is False
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == expected


def test_h28_dependency_archive_traversal_is_rejected(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
        "dependencies:\n- {name: child, version: 1.2.3, repository: 'file://child'}\n",
        encoding="utf-8",
    )
    charts = chart / "charts"
    charts.mkdir()
    with tarfile.open(charts / "child-1.2.3.tgz", "w:gz") as archive:
        content = b"bad"
        member = tarfile.TarInfo("../escape")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "UNSAFE_DEPENDENCY_ARCHIVE"
    )


def test_h30_h34_crd_and_test_modes_are_explicit_and_source_bound(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path)
    (chart / "crds").mkdir()
    (chart / "crds" / "widget.yaml").write_text("bound CRD source\n", encoding="utf-8")
    (chart / "templates" / "test.yaml").write_text("bound test source\n", encoding="utf-8")
    (chart / "crd.fixture").write_text(
        "---\n# Source: demo/crds/widget.yaml\n"
        "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
        "metadata: {name: widgets.example.test}\n",
        encoding="utf-8",
    )
    (chart / "test.fixture").write_text(
        "---\n# Source: demo/templates/test.yaml\napiVersion: v1\nkind: Pod\n"
        "metadata: {name: demo-test}\n",
        encoding="utf-8",
    )
    executable = _executable(
        tmp_path,
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v3.16.4'; exit 0; fi\n"
        "cat rendered.fixture\n"
        "include_crds=false\ninclude_tests=true\n"
        "for arg in \"$@\"; do\n"
        "  [ \"$arg\" = --include-crds ] && include_crds=true\n"
        "  [ \"$arg\" = --skip-tests ] && include_tests=false\n"
        "done\n"
        "$include_crds && cat crd.fixture\n"
        "$include_tests && cat test.fixture\n"
        "exit 0\n",
    )

    excluded = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart, helm_executable=executable),
        tmp_path / "excluded",
    )
    assert excluded.render_inputs["crds"] == "exclude"
    assert excluded.render_inputs["tests"] == "exclude"
    assert excluded.output["resource_count"] == 1

    included = HELM.materialize_helm(
        _spec(
            tmp_path,
            chart_root=chart,
            helm_executable=executable,
            include_crds=True,
            include_tests=True,
        ),
        tmp_path / "included",
    )
    assert included.render_inputs["crds"] == "include"
    assert included.render_inputs["tests"] == "include"
    assert {item.source_template for item in included.documents} == {
        "templates/deployment.yaml",
        "crds/widget.yaml",
        "templates/test.yaml",
    }


def test_h32_graph_evidence_with_excluded_crds_is_incomplete() -> None:
    graph = SimpleNamespace(graph_evidence=object())
    run = SimpleNamespace(evaluations=(graph,))
    result = SimpleNamespace(
        verification=SimpleNamespace(baseline_run=run, candidate_run=run)
    )
    excluded = SimpleNamespace(
        render_inputs={"crds": "exclude"},
        chart={"files": [{"path": "crds/widget.yaml"}]},
    )
    materialization = SimpleNamespace(baseline=excluded, candidate=excluded)

    assert API._graph_verification_has_excluded_crds(result, materialization)


@pytest.mark.parametrize(
    ("function", "reason"),
    (
        ("randAlphaNum 20", "NONDETERMINISTIC_RENDER"),
        ("randAlpha 20", "NONDETERMINISTIC_RENDER"),
        ("randNumeric 20", "NONDETERMINISTIC_RENDER"),
        ("randAscii 20", "NONDETERMINISTIC_RENDER"),
        ("uuidv4", "NONDETERMINISTIC_RENDER"),
        ('lookup "v1" "Secret" .Release.Namespace "existing"', "CLUSTER_STATE_REQUIRED"),
    ),
)
def test_h35_h41_actual_participating_template_actions_fail_closed(
    tmp_path: Path, function: str, reason: str
) -> None:
    chart = _chart(tmp_path, template=f"annotation: {{{{ {function} }}}}\n")
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == reason


def test_h38_excluded_random_source_does_not_poison_emitted_resource(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    (chart / "templates" / "excluded.yaml").write_text(
        "{{- if false }}{{ randAlphaNum 20 }}{{- end }}\n", encoding="utf-8"
    )

    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )

    assert evidence.output["resource_count"] == 1


def test_h38_unreferenced_random_named_helper_does_not_poison_render(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path)
    (chart / "templates" / "helpers.tpl").write_text(
        '{{ define "demo.random" }}{{ htpasswd "user" "pass" }}{{ end }}\n',
        encoding="utf-8",
    )

    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )

    assert evidence.output["fresh_render_count"] == 2


def test_h40_plain_text_function_words_do_not_trigger_action_detection(tmp_path: Path) -> None:
    chart = _chart(
        tmp_path, template="lookup-events randAlphaNum uuidv4 are documentation words\n"
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    assert evidence.output["fresh_render_count"] == 2


def test_h40_quoted_action_string_is_not_a_function_call(tmp_path: Path) -> None:
    chart = _chart(tmp_path, template='{{ "randAlphaNum lookup" }}\n')
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    assert evidence.output["fresh_render_count"] == 2


@pytest.mark.parametrize("suffix", ("helpers.tpl", "definitions.yaml"))
def test_h39_reachable_named_helper_actions_fail_closed(
    tmp_path: Path, suffix: str
) -> None:
    chart = _chart(tmp_path)
    (chart / "templates" / "deployment.yaml").write_text(
        '{{ include "demo.random" . }}\n', encoding="utf-8"
    )
    (chart / "templates" / suffix).write_text(
        '{{ define "demo.random" }}{{ randAlphaNum 20 }}{{ end }}\n',
        encoding="utf-8",
    )
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "NONDETERMINISTIC_RENDER"
    )


def test_dynamic_named_template_call_is_ambiguous(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    (chart / "templates" / "deployment.yaml").write_text(
        '{{ include .Values.helper . }}\n', encoding="utf-8"
    )

    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"
    )


def test_known_random_source_takes_precedence_over_unrelated_dynamic_call(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path)
    (chart / "templates" / "deployment.yaml").write_text(
        '{{ include .Values.helper . }}\n', encoding="utf-8"
    )
    (chart / "templates" / "secret.yaml").write_text(
        '{{ randAlphaNum 20 }}\n', encoding="utf-8"
    )
    (chart / "rendered.fixture").write_text(
        "---\n# Source: demo/templates/deployment.yaml\n"
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo}\n"
        "---\n# Source: demo/templates/secret.yaml\n"
        "apiVersion: v1\nkind: Secret\nmetadata: {name: demo}\n",
        encoding="utf-8",
    )

    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "NONDETERMINISTIC_RENDER"
    )


@pytest.mark.parametrize(
    "helper",
    (
        '{{ define "demo.one" }}{{ end }}{{ define "demo.one" }}{{ end }}',
        '{{ define "demo.one" }}unterminated',
    ),
)
def test_named_template_definition_must_be_closed_and_unique(
    tmp_path: Path, helper: str
) -> None:
    chart = _chart(tmp_path)
    (chart / "templates" / "helpers.tpl").write_text(helper, encoding="utf-8")

    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"
    )


def test_missing_called_named_template_is_ambiguous(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    (chart / "templates" / "deployment.yaml").write_text(
        '{{ include "demo.missing" . }}\n', encoding="utf-8"
    )

    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"
    )


def test_nested_and_cyclic_named_template_call_graph_is_bounded(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    (chart / "templates" / "deployment.yaml").write_text(
        '{{ include "demo.one" . }}\n', encoding="utf-8"
    )
    (chart / "templates" / "helpers.tpl").write_text(
        '{{ define "demo.one" }}{{ if true }}{{ include "demo.two" . }}'
        '{{ end }}{{ end }}\n'
        '{{ define "demo.two" }}{{ include "demo.one" . }}{{ end }}\n',
        encoding="utf-8",
    )

    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )

    assert evidence.output["fresh_render_count"] == 2


@pytest.mark.parametrize(
    "function",
    (
        "ago .Release.Time",
        "genPrivateKey \"rsa\"",
        "genCA \"demo\" 365",
        "encryptAES \"key\" \"value\"",
        "htpasswd \"user\" \"pass\"",
    ),
)
def test_h35_additional_proven_nondeterministic_actions_fail_closed(
    tmp_path: Path, function: str
) -> None:
    chart = _chart(tmp_path, template=f"value: {{{{ {function} }}}}\n")
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "NONDETERMINISTIC_RENDER"
    )


def test_h42_fresh_render_byte_difference_is_inconclusive(tmp_path: Path) -> None:
    executable = _executable(
        tmp_path,
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v3.16.4'; exit 0; fi\n"
        "printf '%s\\n' '---' '# Source: demo/templates/deployment.yaml' "
        "'apiVersion: v1' 'kind: ConfigMap' 'metadata:' '  name: demo' "
        "\"  annotations: {state: '$HELM_CACHE_HOME'}\"\n",
    )
    assert _failure(_spec(tmp_path, helm_executable=executable), tmp_path) == (
        "NONDETERMINISTIC_RENDER"
    )


@pytest.mark.parametrize(
    ("rendered", "reason"),
    (
        (
            "---\n# Source: demo/templates/deployment.yaml\napiVersion: [bad\n",
            "RENDERED_YAML_INVALID",
        ),
        (
            "---\napiVersion: v1\nkind: Pod\nmetadata: {name: demo}\n",
            "AMBIGUOUS_SOURCE_PROVENANCE",
        ),
        (
            "---\n# Source: other/templates/deployment.yaml\n"
            "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\n",
            "AMBIGUOUS_SOURCE_PROVENANCE",
        ),
        (
            "---\n# Source: demo/templates/deployment.yaml\n"
            "apiVersion: v1\nkind: Pod\nmetadata: {generateName: demo-}\n",
            "MISSING_RENDERED_RESOURCE_IDENTITY",
        ),
    ),
)
def test_h43_h49_output_identity_and_provenance_fail_closed(
    tmp_path: Path, rendered: str, reason: str
) -> None:
    assert _failure(
        _spec(tmp_path, chart_root=_chart(tmp_path, rendered)), tmp_path
    ) == reason


def test_h44_duplicate_rendered_identity_is_inconclusive(tmp_path: Path) -> None:
    assert _failure(
        _spec(tmp_path, chart_root=_chart(tmp_path, DEPLOYMENT + DEPLOYMENT)), tmp_path
    ) == "DUPLICATE_RENDERED_IDENTITY"


@pytest.mark.parametrize(
    ("location", "contents", "reason"),
    (
        (
            "Chart.yaml",
            "apiVersion: v2\nname: demo\nname: second\nversion: 0.1.0\n",
            "UNREPRODUCIBLE_DEPENDENCIES",
        ),
        (
            "rendered.fixture",
            "---\n# Source: demo/templates/deployment.yaml\napiVersion: v1\n"
            "kind: Pod\nmetadata: {name: demo, name: second}\n",
            "RENDERED_YAML_INVALID",
        ),
    ),
)
def test_h43_duplicate_yaml_keys_fail_closed(
    tmp_path: Path, location: str, contents: str, reason: str
) -> None:
    chart = _chart(tmp_path)
    (chart / location).write_text(contents, encoding="utf-8")
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == reason


def test_h49_embedded_source_marker_is_not_provenance(tmp_path: Path) -> None:
    rendered = """---
apiVersion: v1
kind: ConfigMap
metadata: {name: demo}
data:
  text: '# Source: demo/templates/deployment.yaml'
"""
    assert _failure(
        _spec(tmp_path, chart_root=_chart(tmp_path, rendered)), tmp_path
    ) == "AMBIGUOUS_SOURCE_PROVENANCE"


def test_h50_chart_symlink_is_rejected(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    os.symlink(outside, chart / "templates" / "escape")
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == "CHART_PATH_ESCAPE"


def test_h51_chart_mutation_between_render_and_reinventory_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chart = _chart(tmp_path)
    original = HELM._render
    calls = 0

    def mutate_after_first(spec, state_root):
        nonlocal calls
        result = original(spec, state_root)
        calls += 1
        if calls == 1:
            (chart / "values.yaml").write_text("changed: true\n", encoding="utf-8")
        return result

    monkeypatch.setattr(HELM, "_render", mutate_after_first)
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "CHART_MUTATED_DURING_RENDER"
    )


def test_h52_nonzero_helm_exit_is_typed(tmp_path: Path) -> None:
    executable = _executable(
        tmp_path,
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v3.16.4'; exit 0; fi\n"
        "printf 'render refused' >&2\nexit 7\n",
    )
    assert _failure(_spec(tmp_path, helm_executable=executable), tmp_path) == (
        "HELM_RENDER_FAILED"
    )


def test_h53_zero_exit_stderr_is_retained_by_digest(tmp_path: Path) -> None:
    executable = _executable(
        tmp_path,
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v3.16.4'; exit 0; fi\n"
        "printf 'bounded warning' >&2\ncat rendered.fixture\n",
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, helm_executable=executable), tmp_path / "output"
    )
    assert evidence.output["stderr_bytes"] == len(b"bounded warning")
    assert evidence.output["stderr_sha256"] == HELM._sha256(b"bounded warning")


def test_h54_shell_metacharacters_are_one_redacted_argv_value(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    value = f"safe; touch {marker}"
    evidence = HELM.materialize_helm(
        _spec(tmp_path, set_strings=(("payload", value),)), tmp_path / "output"
    )
    assert not marker.exists()
    assert "[REDACTED]" in evidence.render_inputs["argv"]
    assert str(marker) not in json.dumps(evidence.canonical_dict())


def test_h55_h58_interface_has_no_extension_or_remote_chart_tail(tmp_path: Path) -> None:
    fields = set(HELM.HelmRenderSpec.__dataclass_fields__)
    assert fields.isdisjoint({
        "post_renderer", "plugin", "dependency_update", "server", "argv_tail"
    })
    with pytest.raises(DomainError):
        HELM.HelmRenderSpec(
            Path("https://example.invalid/chart"),
            _executable(tmp_path),
            "review",
            "default",
            "1.31.0",
        )


def test_h57_native_environment_cannot_supply_kubeconfig_or_plugins(tmp_path: Path) -> None:
    executable = _executable(
        tmp_path,
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then printf 'v3.16.4'; exit 0; fi\n"
        "[ -n \"$KUBECONFIG\" ] && exit 8\n"
        "case \"$HELM_PLUGINS\" in */plugins) ;; *) exit 9 ;; esac\n"
        "cat rendered.fixture\n",
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, helm_executable=executable), tmp_path / "output"
    )
    assert evidence.output["resource_count"] == 1


def test_h59_chart_size_limit_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chart = _chart(tmp_path)
    monkeypatch.setattr(HELM, "_MAX_CHART_FILE_BYTES", 8)
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "HELM_RESOURCE_LIMIT_EXCEEDED"
    )


def test_h60_executable_mutation_during_render_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(tmp_path)
    original = HELM._render

    def mutate_executable(spec, state_root):
        result = original(spec, state_root)
        executable.write_text(executable.read_text(encoding="utf-8") + "# changed\n")
        executable.chmod(0o755)
        return result

    monkeypatch.setattr(HELM, "_render", mutate_executable)
    assert _failure(_spec(tmp_path, helm_executable=executable), tmp_path) == (
        "HELM_ENVIRONMENT_INCOMPLETE"
    )


def test_h70_materialization_schema_is_closed_and_accepts_evidence(tmp_path: Path) -> None:
    evidence = HELM.materialize_helm(_spec(tmp_path), tmp_path / "output")
    schema = json.loads(
        (Path(__file__).parents[2] / "src/iac_guard_v/schemas/report-v1.schema.json")
        .read_text(encoding="utf-8")
    )
    validator = jsonschema.Draft202012Validator(
        {"$ref": "#/$defs/helmMaterialization", "$defs": schema["$defs"]}
    )
    payload = evidence.canonical_dict()
    validator.validate(payload)
    payload["untrusted"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(payload)


def test_pair_requires_identical_protected_render_inputs(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = _spec(first_root)
    second = _spec(second_root, namespace="other")
    with pytest.raises(DomainError, match="identical protected inputs"):
        with HELM.materialize_helm_comparison(first, second):
            pass


@pytest.mark.parametrize(
    ("reason", "detail"),
    (("bad", "detail"), (None, "detail"), ("VALID", ""), ("VALID", None)),
)
def test_typed_helm_error_rejects_open_or_blank_values(reason, detail) -> None:
    with pytest.raises(DomainError):
        HELM.HelmMaterializationError(reason, detail)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("chart_root", "chart"),
        ("helm_executable", "helm"),
        ("release_name", "Invalid_Name"),
        ("namespace", "UPPER"),
        ("kube_version", "1.31"),
        ("values_files", []),
        ("set_values", []),
        ("set_values", (("bad,key", "value"),)),
        ("set_values", (("key", ""),)),
        ("set_strings", (("key", "bad\x00value"),)),
        ("api_versions", []),
        ("api_versions", ("",)),
        ("api_versions", ("v1\n",)),
        ("include_crds", 1),
        ("include_tests", 0),
    ),
)
def test_render_spec_rejects_untyped_or_unmodeled_fields(
    tmp_path: Path, field: str, value: object
) -> None:
    chart = _chart(tmp_path)
    executable = _executable(tmp_path)
    values = {
        "chart_root": chart,
        "helm_executable": executable,
        "release_name": "review",
        "namespace": "default",
        "kube_version": "1.31.0",
    }
    values[field] = value
    with pytest.raises(DomainError):
        HELM.HelmRenderSpec(**values)


def test_render_spec_rejects_missing_non_directory_and_unexecutable_paths(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path)
    executable = _executable(tmp_path)
    with pytest.raises(DomainError, match="unavailable"):
        HELM.HelmRenderSpec(
            tmp_path / "missing", executable, "review", "default", "1.31.0"
        )
    ordinary_file = tmp_path / "ordinary"
    ordinary_file.write_text("not a chart", encoding="utf-8")
    with pytest.raises(DomainError, match="must be a directory"):
        HELM.HelmRenderSpec(
            ordinary_file, executable, "review", "default", "1.31.0"
        )
    executable.chmod(0o600)
    with pytest.raises(DomainError, match="executable regular file"):
        HELM.HelmRenderSpec(chart, executable, "review", "default", "1.31.0")


def test_render_spec_rejects_executable_and_values_path_escapes(tmp_path: Path) -> None:
    chart = _chart(tmp_path)
    inside = chart / "helm"
    inside.write_text("#!/bin/sh\n", encoding="utf-8")
    inside.chmod(0o755)
    with pytest.raises(DomainError, match="must not be inside"):
        HELM.HelmRenderSpec(chart, inside, "review", "default", "1.31.0")

    executable = _executable(tmp_path)
    with pytest.raises(DomainError, match="values file is unavailable"):
        HELM.HelmRenderSpec(
            chart, executable, "review", "default", "1.31.0", ("missing.yaml",)
        )
    outside = tmp_path / "outside-values.yaml"
    outside.write_text("enabled: true\n", encoding="utf-8")
    os.symlink(outside, chart / "linked-values.yaml")
    with pytest.raises(DomainError, match="regular file inside"):
        HELM.HelmRenderSpec(
            chart,
            executable,
            "review",
            "default",
            "1.31.0",
            ("linked-values.yaml",),
        )


@pytest.mark.parametrize(
    "value",
    (
        None,
        {"name": "child"},
        {"name": "child", "version": "1.0.0", "repository": 1},
        {"name": "child", "version": "1.0.0", "unknown": True},
        {"name": "child", "version": "1.0.0", "condition": []},
        {"name": "child", "version": "1.0.0", "tags": "bad"},
        {"name": "child", "version": "1.0.0", "enabled": "yes"},
    ),
)
def test_dependency_contract_rejects_unmodeled_records(value: object) -> None:
    with pytest.raises(HELM.HelmMaterializationError):
        HELM._dependency_record(value)


def test_dependency_record_binds_supported_optional_fields() -> None:
    value = {
        "name": "child",
        "version": "1.0.0",
        "repository": "file://child",
        "condition": "child.enabled",
        "tags": ["local"],
        "enabled": True,
        "import-values": ["exports"],
        "alias": "renamed",
    }
    assert HELM._dependency_record(value) == value


@pytest.mark.parametrize(
    ("rendered", "reason"),
    (
        (
            "---\n# Source: demo/templates/deployment.yaml\nnull\n",
            "MISSING_RENDERED_RESOURCE_IDENTITY",
        ),
        (
            "---\n# Source: demo/templates/deployment.yaml\n- one\n- two\n",
            "RENDERED_YAML_INVALID",
        ),
        (
            "---\n# Source: demo/templates/deployment.yaml\n"
            "apiVersion: v1\nkind: Pod\nmetadata: wrong\n",
            "MISSING_RENDERED_RESOURCE_IDENTITY",
        ),
        (
            "---\n# Source: demo/templates/deployment.yaml\n"
            "apiVersion: v1\nkind: Pod\nmetadata: {name: demo, namespace: 3}\n",
            "MISSING_RENDERED_RESOURCE_IDENTITY",
        ),
    ),
)
def test_rendered_document_shape_failures_are_typed(
    tmp_path: Path, rendered: str, reason: str
) -> None:
    assert _failure(
        _spec(tmp_path, chart_root=_chart(tmp_path, rendered)), tmp_path
    ) == reason


def test_empty_render_and_existing_output_are_rejected(tmp_path: Path) -> None:
    chart = _chart(tmp_path, "---\n# Source: demo/templates/deployment.yaml\nnull\n")
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "MISSING_RENDERED_RESOURCE_IDENTITY"
    )
    output = tmp_path / "already"
    output.mkdir()
    with pytest.raises(DomainError, match="must not already exist"):
        HELM.materialize_helm(_spec(tmp_path / "second"), output)


def test_materializer_and_comparison_require_exact_typed_inputs(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="exact typed inputs"):
        HELM.materialize_helm(object(), tmp_path / "output")
    spec = _spec(tmp_path)
    with pytest.raises(DomainError, match="exact render specifications"):
        with HELM.materialize_helm_comparison(spec, object()):
            pass
