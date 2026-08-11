"""D4.4 strict independent artifact-discovery security properties."""
from __future__ import annotations

from pathlib import Path

import pytest

from iac_guard_v.engine import attest_checkov_scan_plan

from test_checkov_adapter import request as adapter_request


def _plan(tmp_path: Path, source: str):
    raw = adapter_request(tmp_path, frameworks=("kubernetes", "terraform"))
    (raw.scan_root / "pod.yaml").write_text(source, encoding="utf-8")
    return attest_checkov_scan_plan(raw)


def test_quoted_key_kubernetes_yaml_cannot_disappear_from_scan_plan(
    tmp_path: Path,
) -> None:
    plan = _plan(
        tmp_path,
        '"apiVersion": v1\n'
        '"kind": Pod\n'
        '"metadata":\n'
        '  "name": p\n'
        '"spec":\n'
        '  containers:\n'
        '    - name: c\n'
        '      image: nginx\n'
        '      securityContext: {privileged: true}\n',
    )
    assert "pod.yaml" in plan.files_eligible
    assert any(
        item.file_path == "pod.yaml"
        and item.resource_address == "v1/Pod/default/p"
        for item in plan.resources
    )


@pytest.mark.parametrize(
    ("source", "addresses"),
    [
        (
            '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"json"}}',
            {"v1/Pod/default/json"},
        ),
        (
            "{apiVersion: v1, kind: Pod, metadata: {name: flow, namespace: ns}}",
            {"v1/Pod/ns/flow"},
        ),
        (
            "apiVersion: v1\nkind: Pod\nmetadata: {name: one}\n"
            "---\napiVersion: v1\nkind: Service\nmetadata: {name: two}\n",
            {"v1/Pod/default/one", "v1/Service/default/two"},
        ),
        (
            "apiVersion: v1\nkind: List\nitems:\n"
            "  - apiVersion: v1\n    kind: Pod\n    metadata: {name: a}\n"
            "  - apiVersion: apps/v1\n    kind: Deployment\n"
            "    metadata: {name: b, namespace: prod}\n",
            {"v1/Pod/default/a", "apps/v1/Deployment/prod/b"},
        ),
    ],
)
def test_safe_yaml_forms_have_complete_resource_identity(
    tmp_path: Path, source: str, addresses: set[str]
) -> None:
    plan = _plan(tmp_path, source)
    assert {
        item.resource_address for item in plan.resources
        if item.file_path == "pod.yaml"
    } == addresses


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (
            "apiVersion: v1\nkind: Pod\nkind: Service\nmetadata: {name: p}\n",
            "duplicate",
        ),
        ("apiVersion: !unsafe v1\nkind: Pod\nmetadata: {name: p}\n", "tag"),
        ("apiVersion: v1\nkind: Pod\nmetadata: &m {name: p}\ncopy: *m\n", "alias"),
        ("apiVersion: v1\nkind: Pod\nmetadata: {}\n", "identity"),
    ],
)
def test_ambiguous_or_unsafe_kubernetes_yaml_fails_closed(
    tmp_path: Path, source: str, reason: str
) -> None:
    with pytest.raises(Exception, match=reason):
        _plan(tmp_path, source)


def test_excessive_yaml_nesting_fails_closed(tmp_path: Path) -> None:
    nested = "{}"
    for _ in range(70):
        nested = "{x: " + nested + "}"
    with pytest.raises(Exception, match="depth"):
        _plan(tmp_path, nested)


def test_definitively_non_kubernetes_yaml_is_classified_but_not_scanned(
    tmp_path: Path,
) -> None:
    plan = _plan(tmp_path, "name: ordinary-tool-config\nsettings: {enabled: true}\n")
    assert "pod.yaml" not in plan.files_eligible
    assert all(item.file_path != "pod.yaml" for item in plan.resources)


def test_terraform_json_is_explicitly_rejected_until_supported(tmp_path: Path) -> None:
    raw = adapter_request(tmp_path, frameworks=("terraform",))
    (raw.scan_root / "main.tf.json").write_text(
        '{"resource":{"aws_x":{"json":{"value":true}}}}', encoding="utf-8"
    )
    with pytest.raises(Exception, match="Terraform JSON.*unsupported"):
        attest_checkov_scan_plan(raw)


def test_invalid_hcl_syntax_fails_independent_discovery(tmp_path: Path) -> None:
    raw = adapter_request(tmp_path, frameworks=("terraform",))
    (raw.scan_root / "main.tf").write_text(
        'resource "aws_x" "r" { invalid = }\n', encoding="utf-8"
    )
    with pytest.raises(Exception, match="Terraform.*syntax"):
        attest_checkov_scan_plan(raw)
