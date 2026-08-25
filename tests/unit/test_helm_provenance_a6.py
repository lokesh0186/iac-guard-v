"""Security regressions for the bounded 0.1.0a6 Helm contracts."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

import iac_guard_v.helm as HELM

from test_helm_materialization_a4 import DEPLOYMENT, _chart, _executable, _failure, _spec


def _rendered(*, name: str = "demo", namespace: str | None = None, kind: str = "Deployment") -> str:
    namespace_line = "" if namespace is None else f"\n  namespace: {namespace}"
    api_version = "v1" if kind in {"Namespace", "ConfigMap"} else "apps/v1"
    return (
        "---\n# Source: demo/templates/deployment.yaml\n"
        f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: {name}{namespace_line}\n"
    )


def _action_spec(
    root: Path,
    template: str,
    *,
    values: str = "",
    rendered: str = DEPLOYMENT,
    namespace: str = "default",
) -> HELM.HelmRenderSpec:
    chart = _chart(root, rendered=rendered, template=template)
    if values:
        (chart / "values.yaml").write_text(values, encoding="utf-8")
    return _spec(root, chart_root=chart, namespace=namespace)


def test_a6_nondefault_omitted_namespace_is_release_namespace_bound(tmp_path: Path) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(tmp_path, "kind: Deployment\n", namespace="monitoring"),
        tmp_path / "output",
    )

    document = evidence.documents[0]
    assert document.namespace == "monitoring"
    assert document.namespace_provenance["resolution"] == "HELM_RELEASE_NAMESPACE_DEFAULT"
    assert document.namespace_provenance["request_namespace"] == "monitoring"
    assert document.namespace_provenance["helm_argument_namespace"] == "monitoring"
    assert document.namespace_provenance["release_namespace"] == "monitoring"
    assert document.namespace_provenance["emitted_metadata_namespace"] is None
    assert document.namespace_provenance["effective_namespace"] == "monitoring"


@pytest.mark.parametrize(
    ("template", "values", "resolution"),
    (
        ("metadata:\n  namespace: {{ .Release.Namespace }}\n", "", "RELEASE_NAMESPACE_EXPRESSION"),
        (
            "metadata:\n  namespace: {{ .Values.targetNamespace }}\n",
            "targetNamespace: monitoring\n",
            "VALUES_NAMESPACE_EXPRESSION",
        ),
        ("metadata:\n  namespace: monitoring\n", "", "LITERAL_NAMESPACE_EXPRESSION"),
    ),
)
def test_a6_explicit_namespace_provenance_is_source_bound(
    tmp_path: Path, template: str, values: str, resolution: str
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            template,
            values=values,
            rendered=_rendered(namespace="monitoring"),
            namespace="monitoring",
        ),
        tmp_path / "output",
    )
    provenance = evidence.documents[0].namespace_provenance
    assert provenance["resolution"] == resolution
    assert provenance["effective_namespace"] == "monitoring"
    assert provenance["source_template"] == "templates/deployment.yaml"
    if resolution == "VALUES_NAMESPACE_EXPRESSION":
        assert provenance["value_path"] == "targetNamespace"
        assert len(provenance["value_sha256"]) == 64


def test_a6_hardcoded_namespace_wins_and_release_contradiction_is_recorded(
    tmp_path: Path,
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "metadata:\n  namespace: kube-system\n",
            rendered=_rendered(namespace="kube-system"),
            namespace="monitoring",
        ),
        tmp_path / "output",
    )
    provenance = evidence.documents[0].namespace_provenance
    assert provenance["effective_namespace"] == "kube-system"
    assert provenance["resolution"] == "LITERAL_NAMESPACE_EXPRESSION"
    assert provenance["contradiction"] == "EXPLICIT_NAMESPACE_OVERRIDES_RELEASE_NAMESPACE"


def test_a6_dynamic_namespace_expression_remains_inconclusive(tmp_path: Path) -> None:
    spec = _action_spec(
        tmp_path,
        'metadata:\n  namespace: {{ printf "%s-%s" .Values.prefix .Values.suffix }}\n',
        values="prefix: monitor\nsuffix: ing\n",
        rendered=_rendered(namespace="monitoring"),
        namespace="monitoring",
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_NAMESPACE_PROVENANCE"


def test_a6_quoted_release_namespace_expression_is_bounded(tmp_path: Path) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "metadata:\n  namespace: '{{ .Release.Namespace }}'\n",
            rendered=_rendered(namespace="monitoring"),
            namespace="monitoring",
        ),
        tmp_path / "output",
    )
    assert evidence.documents[0].namespace_provenance["resolution"] == (
        "RELEASE_NAMESPACE_EXPRESSION"
    )


def test_a6_values_namespace_defaulting_to_release_namespace_is_bounded(
    tmp_path: Path,
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "metadata:\n  namespace: {{ .Values.namespaceOverride | default .Release.Namespace }}\n",
            values="namespaceOverride: ''\n",
            rendered=_rendered(namespace="kube-system"),
            namespace="kube-system",
        ),
        tmp_path / "output",
    )
    provenance = evidence.documents[0].namespace_provenance
    assert provenance["resolution"] == "VALUES_DEFAULT_RELEASE_NAMESPACE_EXPRESSION"
    assert provenance["value_path"] == "namespaceOverride"
    assert provenance["effective_namespace"] == "kube-system"


def test_a6_static_named_namespace_helper_uses_exact_subchart_values(
    tmp_path: Path,
) -> None:
    rendered = _rendered(namespace="monitoring").replace(
        "# Source: demo/templates/deployment.yaml",
        "# Source: demo/charts/child/templates/deployment.yaml",
    )
    chart = _chart(tmp_path, rendered=rendered)
    child = chart / "charts" / "child"
    (child / "templates").mkdir(parents=True)
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: child\nversion: 1.0.0\n", encoding="utf-8"
    )
    (child / "values.yaml").write_text("namespaceOverride: ''\n", encoding="utf-8")
    (child / "templates" / "deployment.yaml").write_text(
        'metadata:\n  namespace: {{ include "child.namespace" . }}\n', encoding="utf-8"
    )
    (child / "templates" / "_helpers.tpl").write_text(
        '{{ define "child.namespace" }}{{ if .Values.namespaceOverride }}'
        '{{ .Values.namespaceOverride }}{{ else }}{{ .Release.Namespace }}'
        '{{ end }}{{ end }}\n',
        encoding="utf-8",
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart, namespace="monitoring"), tmp_path / "output"
    )
    assert evidence.documents[0].namespace_provenance["resolution"] == (
        "STATIC_NAMED_NAMESPACE_TEMPLATE"
    )


def test_a6_cluster_scoped_resource_retains_absent_namespace_provenance(
    tmp_path: Path,
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "kind: Namespace\n",
            rendered=_rendered(name="monitoring", kind="Namespace"),
            namespace="monitoring",
        ),
        tmp_path / "output",
    )
    provenance = evidence.documents[0].namespace_provenance
    assert provenance["resolution"] == "CLUSTER_SCOPED"
    assert provenance["emitted_metadata_namespace"] is None
    assert provenance["effective_namespace"] is None


def test_a6_cluster_scoped_resource_with_namespace_is_contradictory(
    tmp_path: Path,
) -> None:
    spec = _action_spec(
        tmp_path,
        "kind: Namespace\nmetadata:\n  namespace: monitoring\n",
        rendered=_rendered(name="monitoring", namespace="monitoring", kind="Namespace"),
        namespace="monitoring",
    )
    assert _failure(spec, tmp_path) == "CONTRADICTORY_NAMESPACE_PROVENANCE"


def test_a6_local_crd_proves_custom_cluster_resource_scope(tmp_path: Path) -> None:
    rendered = (
        "---\n# Source: demo/templates/deployment.yaml\n"
        "apiVersion: example.test/v1\nkind: Widget\nmetadata:\n  name: demo\n"
    )
    chart = _chart(tmp_path, rendered=rendered, template="kind: Widget\n")
    crds = chart / "crds"
    crds.mkdir()
    (crds / "widget.yaml").write_text(
        "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
        "metadata:\n  name: widgets.example.test\n"
        "spec:\n  group: example.test\n  scope: Cluster\n"
        "  names:\n    plural: widgets\n    singular: widget\n    kind: Widget\n"
        "  versions:\n  - name: v1\n    served: true\n    storage: true\n"
        "    schema:\n      openAPIV3Schema:\n        type: object\n",
        encoding="utf-8",
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart, namespace="monitoring"), tmp_path / "output"
    )
    provenance = evidence.documents[0].namespace_provenance
    assert provenance["resolution"] == "CLUSTER_SCOPED"
    assert provenance["effective_namespace"] is None


def test_a6_unknown_custom_resource_scope_remains_inconclusive(tmp_path: Path) -> None:
    rendered = (
        "---\n# Source: demo/templates/deployment.yaml\n"
        "apiVersion: example.test/v1\nkind: Widget\nmetadata:\n  name: demo\n"
    )
    spec = _action_spec(tmp_path, "kind: Widget\n", rendered=rendered)
    assert _failure(spec, tmp_path) == "AMBIGUOUS_NAMESPACE_PROVENANCE"


def test_a6_protected_values_model_is_closed_and_precedence_aware(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path)
    (chart / "values.yaml").write_text(
        "mode: default\nnested:\n  first: one\n", encoding="utf-8"
    )
    (chart / "review.yaml").write_text(
        "mode: review\nnested:\n  second: two\n", encoding="utf-8"
    )
    values, identity = HELM._protected_values(
        _spec(
            tmp_path,
            chart_root=chart,
            values_files=("review.yaml",),
            set_values=(("nested.count", "2"),),
            set_strings=(("nested.identifier", "002"),),
        )
    )
    assert values["mode"] == "review"
    assert values["nested"] == {
        "first": "one", "second": "two", "count": 2, "identifier": "002"
    }
    assert len(identity) == 64


@pytest.mark.parametrize("content", ("- not-a-map\n", "bad: [\n"))
def test_a6_invalid_values_files_fail_closed(tmp_path: Path, content: str) -> None:
    path = tmp_path / "values.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(HELM.HelmMaterializationError, match="Helm values"):
        HELM._load_values_file(path)


def test_a6_empty_values_and_unmodeled_override_paths_are_explicit(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert HELM._load_values_file(empty) == {}
    values: dict = {"nested": "replace-me"}
    assert HELM._set_value_path(values, "nested.value", True)
    assert values == {"nested": {"value": True}}
    assert not HELM._set_value_path(values, "items[0].enabled", True)


@pytest.mark.parametrize(
    ("expression", "expected"),
    (
        ("(.Values.enabled)", True),
        ("not .Values.disabled", True),
        ('eq .Values.mode "strict"', True),
        ('ne .Values.mode "other"', True),
        ("0", False),
        ("1.5", True),
        ("nil", False),
        (".Values.missing", None),
        (".Values.enabled | default false", None),
        ('"unterminated', None),
        ("", None),
        ("unknown function call", None),
    ),
)
def test_a6_bounded_condition_contract(
    expression: str, expected: bool | None
) -> None:
    assert HELM._condition(
        expression, {"enabled": True, "disabled": False, "mode": "strict"}
    ) is expected


def test_a6_unmodeled_values_poison_branch_proof() -> None:
    values = {HELM._UNMODELED_VALUES: True, "enabled": False}
    assert HELM._value_at(values, ".Values.enabled") is HELM._UNKNOWN
    assert HELM._value_at(values, "not-a-values-path") is HELM._UNKNOWN
    assert HELM._value_at({}, ".Values") == {}


def test_a6_rich_set_paths_and_nonmapping_subchart_values_poison_proof(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path)
    child = chart / "charts" / "child"
    child.mkdir(parents=True)
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: child\nversion: 1.0.0\n", encoding="utf-8"
    )
    (chart / "values.yaml").write_text("child: disabled\n", encoding="utf-8")
    values, _identity = HELM._protected_values(
        _spec(
            tmp_path,
            chart_root=chart,
            set_values=(("items[0].enabled", "true"),),
            set_strings=(("names[0]", "demo"),),
        )
    )
    assert values[HELM._UNMODELED_VALUES] is True
    assert values[HELM._SUBCHART_VALUES]["child"][HELM._UNMODELED_VALUES] is True
    assert HELM._values_for_source(values, "charts/missing/templates/demo.yaml") == {
        HELM._UNMODELED_VALUES: True
    }


def test_a6_malformed_typed_override_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(HELM.HelmMaterializationError, match="typed Helm override"):
        HELM._protected_values(
            _spec(tmp_path, set_values=(("enabled", "["),))
        )


def _action_index(
    root_actions: tuple[str, ...],
    definitions: dict[str, tuple[str, ...]] | None = None,
) -> HELM._TemplateActionIndex:
    source = "templates/demo.yaml"
    return HELM._TemplateActionIndex(
        {source: HELM._TemplateActionScope(source, root_actions)},
        {
            name: HELM._TemplateActionScope("templates/_helpers.tpl", actions)
            for name, actions in (definitions or {}).items()
        },
        {source: "", "templates/_helpers.tpl": ""},
    )


@pytest.mark.parametrize(
    "actions",
    (
        ("else",),
        ("end",),
        ("if .Values.unknown",),
        ("if false", "else if .Values.other", "randAlphaNum 8", "end"),
    ),
)
def test_a6_malformed_or_unresolved_control_state_is_ambiguous(
    actions: tuple[str, ...],
) -> None:
    index = _action_index(actions)
    state = HELM._ActionState(set(), set(), [])
    HELM._evaluate_scope(index.roots["templates/demo.yaml"], index, {}, state)
    assert state.ambiguous


def test_a6_unknown_and_excluded_named_action_paths_remain_fail_closed() -> None:
    definitions = {
        "danger": ('randAlphaNum 8', 'include "cycle" .'),
        "cycle": ('include "danger" .',),
        "safe": ('.Release.Namespace',),
    }
    unknown = _action_index(
        ('if .Values.unknown', 'include "danger" .', 'include "missing" .', "end"),
        definitions,
    )
    state = HELM._ActionState(set(), set(), [])
    HELM._evaluate_scope(unknown.roots["templates/demo.yaml"], unknown, {}, state)
    assert state.ambiguous

    excluded = _action_index(
        ('if false', 'include "danger" .', "end"), definitions
    )
    state = HELM._ActionState(set(), set(), [])
    HELM._evaluate_scope(excluded.roots["templates/demo.yaml"], excluded, {}, state)
    assert state.excluded
    assert not state.reachable_functions

    missing = _action_index(('include "missing" .',), definitions)
    state = HELM._ActionState(set(), set(), [])
    HELM._evaluate_scope(missing.roots["templates/demo.yaml"], missing, {}, state)
    assert state.ambiguous


def test_a6_participating_action_source_must_exist() -> None:
    index = _action_index(())
    with pytest.raises(HELM.HelmMaterializationError, match="exactly provable"):
        HELM._participating_action_analysis(
            index,
            (SimpleNamespace(source_template="templates/missing.yaml"),),
            {},
            "0" * 64,
        )


def test_a6_contradictory_static_crd_scopes_fail_closed() -> None:
    cluster = (
        "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
        "spec:\n  group: example.test\n  scope: Cluster\n"
        "  names: {kind: Widget}\n"
    )
    namespaced = cluster.replace("scope: Cluster", "scope: Namespaced")
    with pytest.raises(HELM.HelmMaterializationError, match="contradict"):
        HELM._custom_resource_scopes(
            {"crds/one.yaml": cluster, "crds/two.yaml": namespaced}
        )


def _namespace_call(**changes):
    values = changes.pop("values", {})
    actions = changes.pop("actions", _action_index(()))
    arguments = {
        "api_version": "apps/v1",
        "kind": "Deployment",
        "explicit_namespace": "monitoring",
        "release_namespace": "monitoring",
        "source_template": "templates/demo.yaml",
        "source_text": "metadata:\n  namespace: monitoring\n",
        "values": values,
        "actions": actions,
        "custom_scopes": {},
    }
    arguments.update(changes)
    return HELM._namespace_provenance(**arguments)


@pytest.mark.parametrize(
    ("changes", "reason"),
    (
        ({"explicit_namespace": 3}, "MISSING_RENDERED_RESOURCE_IDENTITY"),
        (
            {"source_text": "metadata:\n  namespace: one\n---\nmetadata:\n  namespace: two\n"},
            "AMBIGUOUS_NAMESPACE_PROVENANCE",
        ),
        (
            {"source_text": 'metadata:\n  namespace: {{ include "missing" . }}\n'},
            "AMBIGUOUS_NAMESPACE_PROVENANCE",
        ),
        (
            {
                "source_text": "metadata:\n  namespace: {{ .Values.target | default .Release.Namespace }}\n",
                "values": {},
            },
            "AMBIGUOUS_NAMESPACE_PROVENANCE",
        ),
        (
            {
                "source_text": "metadata:\n  namespace: {{ .Values.target | default .Release.Namespace }}\n",
                "values": {"target": 7},
            },
            "AMBIGUOUS_NAMESPACE_PROVENANCE",
        ),
        (
            {
                "source_text": "metadata:\n  namespace: {{ .Values.target | default .Release.Namespace }}\n",
                "values": {"target": "other"},
            },
            "CONTRADICTORY_NAMESPACE_PROVENANCE",
        ),
        (
            {
                "source_text": "metadata:\n  namespace: {{ .Values.target }}\n",
                "values": {"target": 7},
            },
            "AMBIGUOUS_NAMESPACE_PROVENANCE",
        ),
        (
            {
                "source_text": "metadata:\n  namespace: {{ .Values.target }}\n",
                "values": {"target": "other"},
            },
            "CONTRADICTORY_NAMESPACE_PROVENANCE",
        ),
        ({"source_text": "metadata:\n  namespace: [\n"}, "AMBIGUOUS_NAMESPACE_PROVENANCE"),
        ({"source_text": "metadata:\n  namespace: other\n"}, "CONTRADICTORY_NAMESPACE_PROVENANCE"),
    ),
)
def test_a6_namespace_proof_adversarial_failures(
    changes: dict, reason: str
) -> None:
    with pytest.raises(HELM.HelmMaterializationError) as caught:
        _namespace_call(**changes)
    assert caught.value.reason_code == reason


def test_a6_release_namespace_contradiction_is_recorded_not_hidden() -> None:
    _namespace, proof = _namespace_call(
        explicit_namespace="other",
        source_text="metadata:\n  namespace: {{ .Release.Namespace }}\n",
    )
    assert proof["contradiction"] == "RELEASE_NAMESPACE_EXPRESSION_CONTRADICTS_RENDER"


def test_a6_same_name_in_two_release_namespaces_is_not_duplicate(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    executable = _executable(tmp_path)
    charts = (
        HELM.HelmUniverseChart(
            "left", _spec(left, helm_executable=executable, namespace="monitoring")
        ),
        HELM.HelmUniverseChart(
            "right", _spec(right, helm_executable=executable, namespace="kube-system")
        ),
    )
    with HELM.materialize_helm_universe(charts) as universe:
        assert {item.resource_identity for _, item in universe.resource_ownership} == {
            "apps/v1/Deployment/monitoring/demo",
            "apps/v1/Deployment/kube-system/demo",
        }


@pytest.mark.parametrize(
    ("template", "values", "reason"),
    (
        ("{{ if .Values.enabled }}{{ randAlphaNum 8 }}{{ end }}", "enabled: true\n", "NONDETERMINISTIC_RENDER"),
        (
            '{{ if .Values.enabled }}{{ lookup "v1" "Secret" .Release.Namespace "x" }}{{ end }}',
            "enabled: true\n",
            "CLUSTER_STATE_REQUIRED",
        ),
        (
            "{{ range .Values.items }}{{ randAlphaNum 8 }}{{ end }}",
            "items: [one]\n",
            "NONDETERMINISTIC_RENDER",
        ),
    ),
)
def test_a6_selected_dangerous_actions_keep_fail_closed_precedence(
    tmp_path: Path, template: str, values: str, reason: str
) -> None:
    assert _failure(_action_spec(tmp_path, template, values=values), tmp_path) == reason


@pytest.mark.parametrize(
    ("template", "values"),
    (
        ("{{ if .Values.enabled }}{{ randAlphaNum 8 }}{{ end }}", "enabled: false\n"),
        (
            '{{ if eq .Values.mode "generated" }}{{ randAlphaNum 8 }}{{ end }}',
            "mode: existing\n",
        ),
        ("{{ with .Values.secret }}{{ randAlphaNum 8 }}{{ end }}", "secret: null\n"),
        ("{{ range .Values.items }}{{ randAlphaNum 8 }}{{ end }}", "items: []\n"),
        (
            '{{ if false }}{{ lookup "v1" "Secret" .Release.Namespace "x" }}{{ end }}',
            "",
        ),
    ),
)
def test_a6_exact_unreachable_dangerous_actions_are_excluded(
    tmp_path: Path, template: str, values: str
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(tmp_path, template, values=values), tmp_path / "output"
    )
    proof = evidence.render_inputs["template_action_reachability"]
    assert proof["status"] == "PASS"
    assert proof["excluded_dangerous_action_count"] >= 1


def test_a6_with_present_exact_value_keeps_action_reachable(tmp_path: Path) -> None:
    spec = _action_spec(
        tmp_path,
        "{{ with .Values.secret }}{{ randAlphaNum 8 }}{{ end }}",
        values="secret: existing\n",
    )
    assert _failure(spec, tmp_path) == "NONDETERMINISTIC_RENDER"


@pytest.mark.parametrize(
    "template",
    (
        '{{ include .Values.helper . }}',
        '{{ if customPredicate .Values.mode }}{{ randAlphaNum 8 }}{{ end }}',
        '{{ if .Values.enabled }}{{ if customPredicate .Values.mode }}{{ randAlphaNum 8 }}{{ end }}{{ end }}',
    ),
)
def test_a6_unknown_or_dynamic_reachability_remains_ambiguous(
    tmp_path: Path, template: str
) -> None:
    spec = _action_spec(
        tmp_path, template, values="enabled: true\nmode: existing\nhelper: demo.safe\n"
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"


def test_a6_false_branch_literal_helper_call_does_not_activate_helper(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path, template='{{ if .Values.generated }}{{ include "demo.secret" . }}{{ end }}')
    (chart / "values.yaml").write_text("generated: false\n", encoding="utf-8")
    (chart / "templates" / "_helpers.tpl").write_text(
        '{{ define "demo.secret" }}{{ randAlphaNum 8 }}{{ end }}\n', encoding="utf-8"
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    assert evidence.render_inputs["template_action_reachability"][
        "excluded_dangerous_action_count"
    ] == 1


def test_a6_unrendered_source_cannot_activate_shared_dangerous_helper(
    tmp_path: Path,
) -> None:
    chart = _chart(tmp_path, template='{{ if false }}{{ include "demo.secret" . }}{{ end }}')
    (chart / "templates" / "unrendered.yaml").write_text(
        '{{ include "demo.secret" . }}\n', encoding="utf-8"
    )
    (chart / "templates" / "_helpers.tpl").write_text(
        '{{ define "demo.secret" }}{{ randAlphaNum 8 }}{{ end }}\n', encoding="utf-8"
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    assert evidence.output["fresh_render_count"] == 2


def test_a6_one_source_can_emit_multiple_resources_from_exact_safe_branch(
    tmp_path: Path,
) -> None:
    rendered = DEPLOYMENT + _rendered(name="second", kind="ConfigMap")
    template = "{{ if .Values.generated }}{{ randAlphaNum 8 }}{{ else }}safe{{ end }}"
    evidence = HELM.materialize_helm(
        _action_spec(tmp_path, template, values="generated: false\n", rendered=rendered),
        tmp_path / "output",
    )
    assert evidence.output["resource_count"] == 2


def test_a6_same_template_is_evaluated_against_each_charts_protected_values(
    tmp_path: Path,
) -> None:
    safe_root = tmp_path / "safe"
    unsafe_root = tmp_path / "unsafe"
    safe_root.mkdir()
    unsafe_root.mkdir()
    template = "{{ if .Values.generated }}{{ randAlphaNum 8 }}{{ end }}"
    safe = _action_spec(safe_root, template, values="generated: false\n")
    unsafe = _action_spec(unsafe_root, template, values="generated: true\n")

    assert HELM.materialize_helm(safe, tmp_path / "safe-output").output[
        "fresh_render_count"
    ] == 2
    assert _failure(unsafe, tmp_path / "unsafe-failure") == "NONDETERMINISTIC_RENDER"


def test_a6_tpl_of_plain_literal_is_digest_bound_and_safe(tmp_path: Path) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(tmp_path, '{{ tpl "literal-value" . }}'), tmp_path / "output"
    )

    records = evidence.render_inputs["template_action_reachability"]["tpl_evidence"]
    assert len(records) == 1
    assert records[0]["template_string_source"] == "LITERAL"
    assert records[0]["template_string_path"] == ""
    assert records[0]["nested_action_count"] == 0
    assert records[0]["nesting_depth"] == 1
    assert "literal-value" not in json.dumps(records)


def test_a6_tpl_of_protected_value_runs_bounded_nested_analysis(tmp_path: Path) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "{{ tpl .Values.templateText . }}",
            values="templateText: '{{ .Values.foo }}'\nfoo: bounded\n",
        ),
        tmp_path / "output",
    )

    record = evidence.render_inputs["template_action_reachability"]["tpl_evidence"][0]
    assert record["template_string_source"] == "PROTECTED_VALUES_PATH"
    assert record["template_string_path"] == "templateText"
    assert record["nested_action_count"] == 1
    assert record["reached_dangerous_actions"] == []
    assert evidence.render_inputs["template_action_reachability"]["tpl_limits"] == {
        "maximum_nesting_depth": 4,
        "maximum_expanded_template_bytes": 65536,
        "maximum_nested_actions": 256,
        "maximum_named_template_call_depth": 32,
    }

    schema = json.loads(
        (Path(__file__).parents[2] / "src/iac_guard_v/schemas/report-v1.schema.json")
        .read_text(encoding="utf-8")
    )
    validator = jsonschema.Draft202012Validator(
        {"$ref": "#/$defs/helmMaterialization", "$defs": schema["$defs"]}
    )
    validator.validate(evidence.canonical_dict())


@pytest.mark.parametrize(
    ("template", "source_kind"),
    (
        ("{{ tpl (.Values.templateText) . }}", "PROTECTED_VALUES_PATH"),
        (
            '{{ with (tpl (default "" .Values.templateText) .) }}safe{{ end }}',
            "PROTECTED_VALUES_DEFAULT",
        ),
    ),
)
def test_a6_tpl_parenthesized_and_exact_default_arguments_are_bounded(
    tmp_path: Path, template: str, source_kind: str
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(tmp_path, template, values="templateText: literal-safe\n"),
        tmp_path / "output",
    )
    record = evidence.render_inputs["template_action_reachability"]["tpl_evidence"][0]
    assert record["template_string_source"] == source_kind
    assert record["template_string_path"] == "templateText"


def test_a6_tpl_exact_missing_value_with_literal_default_is_bounded(
    tmp_path: Path,
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            '{{ with (tpl (default "" .Values.missing) .) }}unsafe{{ end }}',
        ),
        tmp_path / "output",
    )
    assert evidence.render_inputs["template_action_reachability"]["tpl_evidence"][0][
        "template_string_source"
    ] == "PROTECTED_VALUES_DEFAULT"


@pytest.mark.parametrize(
    ("content", "reason"),
    (
        ("{{ randAlphaNum 8 }}", "NONDETERMINISTIC_RENDER"),
        (
            '{{ lookup "v1" "Secret" .Release.Namespace "sample" }}',
            "CLUSTER_STATE_REQUIRED",
        ),
        ("{{ unsupportedFunction .Values.foo }}", "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"),
    ),
)
def test_a6_tpl_nested_content_preserves_fail_closed_precedence(
    tmp_path: Path, content: str, reason: str
) -> None:
    spec = _action_spec(
        tmp_path,
        "{{ tpl .Values.templateText . }}",
        values=f"templateText: {json.dumps(content)}\nfoo: sample\n",
    )
    assert _failure(spec, tmp_path) == reason


def test_a6_tpl_unknown_computed_argument_remains_ambiguous(tmp_path: Path) -> None:
    spec = _action_spec(
        tmp_path,
        '{{ tpl (printf "%s" .Values.foo) . }}',
        values="foo: sample\n",
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"


@pytest.mark.parametrize(
    ("template", "values"),
    (
        ("{{ tpl }}", ""),
        ("{{ tpl (.Values.foo . }}", "foo: safe\n"),
        ('{{ tpl .Values.foo "invalid-context" }}', "foo: safe\n"),
        ("{{ tpl 42 . }}", ""),
        ("{{ tpl .Values.number . }}", "number: 42\n"),
        (
            "{{ tpl (default .Values.fallback .Values.foo) . }}",
            "fallback: safe\nfoo: ''\n",
        ),
        ('{{ tpl (default "" true) . }}', ""),
        ('{{ tpl (default "" .Values.number) . }}', "number: 42\n"),
        ("{{ tpl 'single-quoted' . }}", ""),
        ('{{ tpl "\\q" . }}', ""),
    ),
)
def test_a6_tpl_malformed_or_unmodeled_arguments_fail_closed(
    tmp_path: Path, template: str, values: str
) -> None:
    assert _failure(_action_spec(tmp_path, template, values=values), tmp_path) == (
        "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"
    )


@pytest.mark.parametrize(
    "content",
    (
        "{{ unclosed",
        "{{/* unclosed comment",
        "{{/* comment */ unexpected }}",
        "{{ .Values.foo | quote }}",
        "{{ .Values.foo .Values.bar }}",
        "{{ block \"name\" . }}{{ end }}",
    ),
)
def test_a6_tpl_unclosed_or_unsupported_nested_syntax_fails_closed(
    tmp_path: Path, content: str
) -> None:
    spec = _action_spec(
        tmp_path,
        "{{ tpl .Values.templateText . }}",
        values=f"templateText: {json.dumps(content)}\nfoo: safe\nbar: safe\n",
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"


@pytest.mark.parametrize(
    "content",
    (
        "{{ \"literal\" }}",
        "{{ .Release.Namespace }}",
        "{{ .Values.foo }}",
        "{{ if .Values.enabled }}{{ .Values.foo }}{{ else }}safe{{ end }}",
    ),
)
def test_a6_tpl_bounded_nested_output_forms_are_safe(
    tmp_path: Path, content: str
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "{{ tpl .Values.templateText . }}",
            values=(
                f"templateText: {json.dumps(content)}\n"
                "foo: safe\nenabled: true\n"
            ),
        ),
        tmp_path / "output",
    )
    assert evidence.render_inputs["template_action_reachability"]["tpl_evidence_count"] == 1


def test_a6_nested_tpl_one_bounded_level_is_supported(tmp_path: Path) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "{{ tpl .Values.outer . }}",
            values=(
                "outer: '{{ tpl .Values.inner . }}'\n"
                "inner: literal-safe-nested-value\n"
            ),
        ),
        tmp_path / "output",
    )

    records = evidence.render_inputs["template_action_reachability"]["tpl_evidence"]
    assert [item["nesting_depth"] for item in records] == [1, 2]
    assert records[0]["parent_callsite_identity"] == ""
    assert records[1]["parent_callsite_identity"] == records[0]["callsite_identity"]
    assert all("literal-safe-nested-value" not in json.dumps(item) for item in records)


def test_a6_repeated_nested_tpl_calls_have_unique_parent_bound_callsites(
    tmp_path: Path,
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "{{ tpl .Values.outer . }}{{ tpl .Values.outer . }}",
            values="outer: '{{ tpl .Values.inner . }}'\ninner: safe\n",
        ),
        tmp_path / "output",
    )
    records = evidence.render_inputs["template_action_reachability"]["tpl_evidence"]
    assert len(records) == 4
    assert len({item["callsite_identity"] for item in records}) == 4


def test_a6_recursive_tpl_fails_closed(tmp_path: Path) -> None:
    recursive = "{{ tpl .Values.outer . }}"
    spec = _action_spec(
        tmp_path,
        recursive,
        values=f"outer: {json.dumps(recursive)}\n",
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"


@pytest.mark.parametrize(
    ("limit_name", "limit_value", "content"),
    (
        ("_MAX_TPL_EXPANDED_BYTES", 4, "five5"),
        ("_MAX_TPL_NESTED_ACTIONS", 0, "{{ .Values.foo }}"),
        ("_MAX_TPL_NESTING_DEPTH", 1, "{{ tpl .Values.inner . }}"),
    ),
)
def test_a6_tpl_resource_limits_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    limit_name: str,
    limit_value: int,
    content: str,
) -> None:
    monkeypatch.setattr(HELM, limit_name, limit_value)
    spec = _action_spec(
        tmp_path,
        "{{ tpl .Values.outer . }}",
        values=f"outer: {json.dumps(content)}\ninner: literal\nfoo: literal\n",
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"


def test_a6_template_comment_quotes_do_not_change_delimiter_parsing(
    tmp_path: Path,
) -> None:
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "{{/* comments don't execute 'tpl' or randAlphaNum */}}\n"
            '{{ tpl "literal-safe" . }}',
        ),
        tmp_path / "output",
    )
    assert evidence.render_inputs["template_action_reachability"]["tpl_evidence_count"] == 1


def test_a6_named_template_depth_limit_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(HELM, "_MAX_TEMPLATE_CALL_DEPTH", 0)
    chart = _chart(tmp_path, template='{{ include "demo.helper" . }}')
    (chart / "templates" / "_helpers.tpl").write_text(
        '{{ define "demo.helper" }}safe{{ end }}\n', encoding="utf-8"
    )
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"
    )


def test_a6_tpl_secret_value_is_never_reported(tmp_path: Path) -> None:
    secret = "private-secret-marker-491"
    evidence = HELM.materialize_helm(
        _action_spec(
            tmp_path,
            "{{ tpl .Values.secretTemplate . }}",
            values=f"secretTemplate: {secret}\n",
        ),
        tmp_path / "output",
    )

    serialized = json.dumps(evidence.canonical_dict(), sort_keys=True)
    assert secret not in serialized
    record = evidence.render_inputs["template_action_reachability"]["tpl_evidence"][0]
    assert len(record["template_string_sha256"]) == 64


def test_a6_identical_render_bytes_do_not_override_dangerous_tpl(
    tmp_path: Path,
) -> None:
    spec = _action_spec(
        tmp_path,
        "{{ tpl .Values.templateText . }}",
        values='templateText: "{{ randAlphaNum 8 }}"\n',
    )
    assert _failure(spec, tmp_path) == "NONDETERMINISTIC_RENDER"


def _dynamic_include_spec(
    root: Path,
    action: str,
    *,
    target_action: str = "literal-safe",
    values: str = "",
) -> HELM.HelmRenderSpec:
    chart = _chart(root, template=action)
    (chart / "templates" / "configmap.yaml").write_text(
        target_action, encoding="utf-8"
    )
    if values:
        (chart / "values.yaml").write_text(values, encoding="utf-8")
    return _spec(root, chart_root=chart)


def test_a6_literal_include_remains_unchanged(tmp_path: Path) -> None:
    chart = _chart(tmp_path, template='{{ include "demo.safe" . }}')
    (chart / "templates" / "_helpers.tpl").write_text(
        '{{ define "demo.safe" }}safe{{ end }}\n', encoding="utf-8"
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    proof = evidence.render_inputs["template_action_reachability"]
    assert proof["reachable_named_templates"] == ["demo.safe"]
    assert proof["dynamic_include_evidence_count"] == 0


@pytest.mark.parametrize(
    ("action", "expression_type", "target_kind"),
    (
        ('{{ include (print "demo" ".safe") . }}', "PRINT_LITERALS", "NAMED_TEMPLATE"),
        (
            '{{ include (printf "%s%s" "demo" ".safe") . }}',
            "PRINTF_LITERALS",
            "NAMED_TEMPLATE",
        ),
        (
            '{{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}',
            "PRINT_TEMPLATE_BASE_PATH",
            "SOURCE_TEMPLATE",
        ),
        (
            '{{ template (printf "%s%s" $.Template.BasePath "/configmap.yaml") . }}',
            "PRINTF_TEMPLATE_BASE_PATH",
            "SOURCE_TEMPLATE",
        ),
    ),
)
def test_a6_exact_dynamic_include_target_is_resolved(
    tmp_path: Path, action: str, expression_type: str, target_kind: str
) -> None:
    chart = _chart(tmp_path, template=action)
    (chart / "templates" / "configmap.yaml").write_text("safe", encoding="utf-8")
    (chart / "templates" / "_helpers.tpl").write_text(
        '{{ define "demo.safe" }}safe{{ end }}\n', encoding="utf-8"
    )
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    record = evidence.render_inputs["template_action_reachability"][
        "dynamic_include_evidence"
    ][0]
    assert record["resolved_expression_type"] == expression_type
    assert record["resolved_target_kind"] == target_kind
    assert record["target_source_template"] in {
        "templates/configmap.yaml", "templates/_helpers.tpl"
    }
    assert len(record["target_source_sha256"]) == 64
    assert len(record["resolution_identity"]) == 64


def test_a6_dynamic_include_whitespace_and_parentheses_resolve_same_target(
    tmp_path: Path,
) -> None:
    records = []
    for ordinal, action in enumerate((
        '{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
        '{{ include (( print  $.Template.BasePath   "/configmap.yaml" )) . }}',
    )):
        root = tmp_path / str(ordinal)
        root.mkdir()
        evidence = HELM.materialize_helm(
            _dynamic_include_spec(root, action), root / "output"
        )
        records.append(evidence.render_inputs["template_action_reachability"][
            "dynamic_include_evidence"
        ][0])
    assert records[0]["resolved_target_string"] == records[1]["resolved_target_string"]
    assert records[0]["resolved_target_identity"] == records[1]["resolved_target_identity"]


@pytest.mark.parametrize(
    "action",
    (
        '{{ include (print .Values.target) . }}',
        '{{ include (printf "%s" (custom .Values.target)) . }}',
        '{{ include (print $.Template.BasePath "/missing.yaml") . }}',
        '{{ include (print $.Template.BasePath "/../escape.yaml") . }}',
        '{{ include (print $.Template.BasePath "/configmap.yaml") . | quote }}',
    ),
)
def test_a6_unresolved_dynamic_include_target_fails_closed(
    tmp_path: Path, action: str
) -> None:
    spec = _dynamic_include_spec(
        tmp_path, action, values="target: demo/templates/configmap.yaml\n"
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"


def test_a6_duplicate_dynamic_source_target_is_ambiguous(tmp_path: Path) -> None:
    chart = _chart(
        tmp_path,
        template='{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
    )
    (chart / "templates" / "configmap.yaml").write_text("safe", encoding="utf-8")
    child = chart / "charts" / "demo"
    (child / "templates").mkdir(parents=True)
    (child / "Chart.yaml").write_text(
        "apiVersion: v2\nname: demo\nversion: 1.0.0\n", encoding="utf-8"
    )
    (child / "templates" / "configmap.yaml").write_text("safe", encoding="utf-8")
    assert _failure(_spec(tmp_path, chart_root=chart), tmp_path) == (
        "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"
    )


@pytest.mark.parametrize(
    ("target_action", "reason"),
    (
        ("{{ randAlphaNum 8 }}", "NONDETERMINISTIC_RENDER"),
        (
            '{{ lookup "v1" "Secret" .Release.Namespace "sample" }}',
            "CLUSTER_STATE_REQUIRED",
        ),
        ("{{ include .Values.dynamic . }}", "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"),
    ),
)
def test_a6_dynamic_include_propagates_target_action_outcome(
    tmp_path: Path, target_action: str, reason: str
) -> None:
    spec = _dynamic_include_spec(
        tmp_path,
        '{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
        target_action=target_action,
        values="dynamic: demo.safe\n",
    )
    assert _failure(spec, tmp_path) == reason


def test_a6_dynamic_include_target_reaches_safe_bounded_tpl(tmp_path: Path) -> None:
    evidence = HELM.materialize_helm(
        _dynamic_include_spec(
            tmp_path,
            '{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
            target_action="{{ tpl .Values.templateText . }}",
            values="templateText: '{{ .Values.safe }}'\nsafe: bounded\n",
        ),
        tmp_path / "output",
    )
    proof = evidence.render_inputs["template_action_reachability"]
    assert proof["tpl_evidence_count"] == 1
    assert proof["dynamic_include_evidence_count"] == 1


def test_a6_tpl_callsite_is_bound_to_each_dynamic_include_parent(
    tmp_path: Path,
) -> None:
    chart = _chart(
        tmp_path,
        rendered=(
            DEPLOYMENT
            + "---\n# Source: demo/templates/second.yaml\n"
            + "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: second\n"
        ),
        template='{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
    )
    (chart / "templates" / "second.yaml").write_text(
        '{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
        encoding="utf-8",
    )
    (chart / "templates" / "configmap.yaml").write_text(
        "{{ tpl .Values.templateText . }}", encoding="utf-8"
    )
    (chart / "values.yaml").write_text(
        "templateText: '{{ .Values.safe }}'\nsafe: bounded\n", encoding="utf-8"
    )

    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    proof = evidence.render_inputs["template_action_reachability"]
    dynamic_callsites = {
        item["callsite_identity"] for item in proof["dynamic_include_evidence"]
    }
    tpl_records = proof["tpl_evidence"]

    assert len(tpl_records) == 2
    assert len({item["callsite_identity"] for item in tpl_records}) == 2
    assert {item["parent_callsite_identity"] for item in tpl_records} == dynamic_callsites


def test_a6_repeated_static_helper_tpl_callsite_is_canonicalized(
    tmp_path: Path,
) -> None:
    chart = _chart(
        tmp_path,
        rendered=(
            DEPLOYMENT
            + "---\n# Source: demo/templates/second.yaml\n"
            + "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: second\n"
        ),
        template='{{ include "demo.helper" . }}',
    )
    (chart / "templates" / "second.yaml").write_text(
        '{{ include "demo.helper" . }}', encoding="utf-8"
    )
    (chart / "templates" / "_helpers.tpl").write_text(
        '{{ define "demo.helper" }}{{ tpl .Values.templateText . }}{{ end }}',
        encoding="utf-8",
    )
    (chart / "values.yaml").write_text(
        "templateText: '{{ .Values.safe }}'\nsafe: bounded\n", encoding="utf-8"
    )

    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    proof = evidence.render_inputs["template_action_reachability"]

    assert proof["tpl_evidence_count"] == 1
    assert len(proof["tpl_evidence"]) == 1


def test_a6_nested_resolvable_dynamic_include_is_bound(tmp_path: Path) -> None:
    chart = _chart(
        tmp_path,
        template='{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
    )
    (chart / "templates" / "configmap.yaml").write_text(
        '{{ include (print $.Template.BasePath "/nested.yaml") . }}', encoding="utf-8"
    )
    (chart / "templates" / "nested.yaml").write_text("safe", encoding="utf-8")
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    records = evidence.render_inputs["template_action_reachability"][
        "dynamic_include_evidence"
    ]
    assert [item["recursion_depth"] for item in records] == [1, 2]
    assert records[1]["parent_callsite_identity"] == records[0]["callsite_identity"]
    assert records[0]["child_callsite_identities"] == [records[1]["callsite_identity"]]


def test_a6_recursive_dynamic_include_cycle_fails_closed(tmp_path: Path) -> None:
    spec = _dynamic_include_spec(
        tmp_path,
        '{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
        target_action='{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"


@pytest.mark.parametrize(
    ("limit", "value"),
    (
        ("_MAX_DYNAMIC_INCLUDE_DEPTH", 0),
        ("_MAX_DYNAMIC_INCLUDE_NODES", 0),
        ("_MAX_DYNAMIC_INCLUDE_ACTION_BYTES", 0),
        ("_MAX_DYNAMIC_INCLUDE_TARGETS", 0),
    ),
)
def test_a6_dynamic_include_resource_limits_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, limit: str, value: int
) -> None:
    monkeypatch.setattr(HELM, limit, value)
    spec = _dynamic_include_spec(
        tmp_path,
        '{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
        target_action="{{ .Values.safe }}",
        values="safe: bounded\n",
    )
    assert _failure(spec, tmp_path) == "AMBIGUOUS_TEMPLATE_ACTION_GRAPH"


def test_a6_same_dynamic_expression_in_subcharts_retains_source_identity(
    tmp_path: Path,
) -> None:
    rendered = (
        "---\n# Source: demo/charts/child-a/templates/deployment.yaml\n"
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: child-a\n"
        "---\n# Source: demo/charts/child-b/templates/deployment.yaml\n"
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: child-b\n"
    )
    chart = _chart(tmp_path, rendered=rendered)
    action = '{{ include (print $.Template.BasePath "/configmap.yaml") . }}'
    for name in ("child-a", "child-b"):
        child = chart / "charts" / name
        (child / "templates").mkdir(parents=True)
        (child / "Chart.yaml").write_text(
            f"apiVersion: v2\nname: {name}\nversion: 1.0.0\n", encoding="utf-8"
        )
        (child / "templates" / "deployment.yaml").write_text(action, encoding="utf-8")
        (child / "templates" / "configmap.yaml").write_text("safe", encoding="utf-8")
    evidence = HELM.materialize_helm(
        _spec(tmp_path, chart_root=chart), tmp_path / "output"
    )
    records = evidence.render_inputs["template_action_reachability"][
        "dynamic_include_evidence"
    ]
    assert len(records) == 2
    assert len({item["resolved_target_identity"] for item in records}) == 2
    assert len({item["callsite_identity"] for item in records}) == 2


def test_a6_dynamic_include_evidence_does_not_expose_private_value(
    tmp_path: Path,
) -> None:
    secret = "private-dynamic-include-marker-972"
    evidence = HELM.materialize_helm(
        _dynamic_include_spec(
            tmp_path,
            '{{ include (print $.Template.BasePath "/configmap.yaml") . }}',
            values=f"unrelatedSecret: {secret}\n",
        ),
        tmp_path / "output",
    )
    serialized = json.dumps(evidence.canonical_dict(), sort_keys=True)
    assert secret not in serialized
    assert str(tmp_path) not in serialized
