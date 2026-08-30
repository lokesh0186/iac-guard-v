"""A8 closed local Kustomize preflight, provenance, and reproducibility tests."""
from __future__ import annotations

import copy
import os
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import iac_guard_v.kustomize as K
import iac_guard_v.cli as CLI
import iac_guard_v.api as API
import iac_guard_v.report as REPORT
from iac_guard_v.config import (
    ExecutionIsolation,
    PublicAcceptanceProperty,
    PublicKustomizeAcceptanceRequest,
    load_public_kustomize_acceptance_config,
)
from iac_guard_v.enums import Status
from iac_guard_v.process import CommandResult, ProcessReason


def _spec(tmp_path: Path, control: str = "resources: [deployment.yaml]\n") -> K.KustomizeBuildSpec:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "kustomization.yaml").write_text(control, encoding="utf-8")
    (root / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo}\n"
        "spec: {selector: {matchLabels: {app: demo}}, template: {metadata: "
        "{labels: {app: demo}}, spec: {containers: [{name: app, image: nginx}]}}}\n",
        encoding="utf-8",
    )
    return K.KustomizeBuildSpec(root, root, Path("/bin/echo"))


def _process(stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0) -> CommandResult:
    status = Status.PASS if exit_code == 0 else Status.ERROR
    reason = (
        ProcessReason.COMPLETED_WITHIN_CONTRACT
        if status is Status.PASS else ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT
    )
    return CommandResult(
        argv=("tool",), status=status, exit_code=exit_code, stdout=stdout,
        stderr=stderr, duration_ms=1, truncated=False, timed_out=False,
        killed_signal=None, reason_code=reason, resolved_executable="/bin/echo",
        primary_execution_event=reason,
    )


def test_preflight_inventories_control_and_resource(tmp_path: Path) -> None:
    records = K.preflight_kustomize(_spec(tmp_path))
    assert [item.path for item in records] == ["deployment.yaml", "kustomization.yaml"]
    assert records[0].roles == ("resource_manifest",)
    assert records[1].roles == ("control_document",)


def test_cluster_scoped_output_uses_protected_scanner_facing_identity() -> None:
    payload = (
        b"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        b"metadata: {name: binding}\nroleRef: {apiGroup: rbac.authorization.k8s.io, "
        b"kind: ClusterRole, name: role}\nsubjects: []\n"
        b"---\napiVersion: storage.k8s.io/v1\nkind: CSIDriver\n"
        b"metadata: {name: example.csi.test}\nspec: {attachRequired: false}\n"
    )
    documents = K._documents(payload, "a" * 64)
    assert documents[0].namespace == "default"
    assert documents[0].resource_identity == (
        "rbac.authorization.k8s.io/v1/ClusterRoleBinding/default/binding"
    )
    assert documents[1].resource_identity == (
        "storage.k8s.io/v1/CSIDriver/default/example.csi.test"
    )


def test_recursive_local_base_and_generator_inputs_are_closed(tmp_path: Path) -> None:
    spec = _spec(tmp_path, "resources: [base]\nconfigMapGenerator:\n- name: cfg\n  files: [data=config.txt]\n")
    base = spec.repository_root / "base"
    base.mkdir()
    (base / "kustomization.yaml").write_text("resources: [service.yaml]\n", encoding="utf-8")
    (base / "service.yaml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata: {name: demo}\n", encoding="utf-8"
    )
    (spec.repository_root / "config.txt").write_text("private-bytes\n", encoding="utf-8")
    records = K.preflight_kustomize(spec)
    by_path = {item.path: item.roles for item in records}
    assert by_path["base/kustomization.yaml"] == ("control_document",)
    assert by_path["base/service.yaml"] == ("resource_manifest",)
    assert by_path["config.txt"] == ("generator_input",)


@pytest.mark.parametrize(
    "control",
    (
        "resources: [deployment.yaml]\nconfigMapGenerator:\n"
        "- {name: cfg, literals: [key=one, key=two]}\n",
        "resources: [deployment.yaml]\nconfigMapGenerator:\n"
        "- {name: cfg, literals: [missing-value-separator]}\n",
        "resources: [deployment.yaml]\nconfigMapGenerator:\n"
        "- {name: cfg, env: values.env, envs: [values.env]}\n",
        "resources: [deployment.yaml]\nconfigMapGenerator:\n"
        "- {name: cfg, envs: [values.env]}\n",
    ),
)
def test_generator_ambiguous_output_keys_fail_before_execution(
    tmp_path: Path, control: str,
) -> None:
    spec = _spec(tmp_path, control)
    if "values.env" in control:
        (spec.repository_root / "values.env").write_text(
            "KEY\n" if "envs: [values.env]" in control and "env:" not in control
            else "KEY=one\n",
            encoding="utf-8",
        )
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K.preflight_kustomize(spec)
    assert caught.value.reason_code == "KUSTOMIZATION_GENERATOR_INPUT_UNBOUND"


def test_portable_path_identity_collision_fails_closed(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    inventory = K._Inventory(spec.repository_root)
    relative = "deployment.yaml"
    inventory._portable_paths[relative.casefold()] = "Deployment.yaml"
    with pytest.raises(K.KustomizeMaterializationError, match="identity collision"):
        inventory.add_file(
            spec.repository_root / relative, "resource_manifest", "root:resources"
        )


def test_complete_bounded_transform_input_family_is_inventoried(tmp_path: Path) -> None:
    control = """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: [deployment.yaml]
components: [component]
namespace: research
namePrefix: pre-
nameSuffix: -post
commonLabels: {team: platform}
labels:
- pairs: {app.kubernetes.io/part-of: suite}
  includeSelectors: true
  includeTemplates: true
images: [nginx, {name: busybox, newName: registry.example/busybox, newTag: '2'}]
patchesStrategicMerge: [strategic.yaml]
patches:
- path: patch.yaml
  target: {group: apps, version: v1, kind: Deployment, name: demo}
  options: {allowNameChange: false, allowKindChange: false}
patchesJson6902:
- patch: [{op: replace, path: /spec/replicas, value: 2}]
  target: {group: apps, version: v1, kind: Deployment, name: demo}
replacements:
- path: replacement.yaml
- source: {kind: ConfigMap, name: settings, fieldPath: data.mode}
  targets:
  - select: {kind: Deployment, name: demo}
    reject: {namespace: excluded}
    fieldPaths: [spec.template.spec.containers.0.args.0]
    options: {delimiter: ':', index: 0, create: true}
configMapGenerator:
- name: settings
  files: [mode=config.txt]
  envs: [config.env]
  options: {disableNameSuffixHash: true, labels: {generated: 'true'}}
secretGenerator:
- name: credentials
  env: secret.env
  type: Opaque
  behavior: create
  literals: [user=static]
generatorOptions: {annotations: {owner: research}, immutable: true}
"""
    spec = _spec(tmp_path, control)
    component = spec.repository_root / "component"
    component.mkdir()
    (component / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\n",
        encoding="utf-8",
    )
    for name, payload in {
        "strategic.yaml": (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo}\n"
        ),
        "patch.yaml": "- {op: replace, path: /spec/replicas, value: 2}\n",
        "replacement.yaml": "source: {kind: ConfigMap, name: settings}\ntargets: []\n",
        "config.txt": "static\n", "config.env": "MODE=static\n",
        "secret.env": "PASSWORD=redacted\n",
    }.items():
        (spec.repository_root / name).write_text(payload, encoding="utf-8")
    records = K.preflight_kustomize(spec)
    roles = {item.path: item.roles for item in records}
    assert roles["component/kustomization.yaml"] == ("control_document",)
    assert roles["strategic.yaml"] == ("patch_input",)
    assert roles["patch.yaml"] == ("patch_input",)
    assert roles["replacement.yaml"] == ("replacement_input",)
    assert roles["config.txt"] == ("generator_input",)
    assert roles["config.env"] == ("generator_input",)
    assert roles["secret.env"] == ("generator_input",)


@pytest.mark.parametrize(
    ("control", "reason"),
    (
        ("resources: [https://example.invalid/base]\n", "KUSTOMIZATION_REFERENCE_REMOTE"),
        ("resources: [deployment.yaml]\nhelmCharts: []\n", "KUSTOMIZATION_UNKNOWN_KEY"),
        ("resources: [deployment.yaml]\nconfigurations: [fields.yaml]\n", "KUSTOMIZATION_CUSTOM_FIELD_SPEC_UNSUPPORTED"),
        ("resources: [deployment.yaml]\nresources: []\n", "KUSTOMIZATION_CONTROL_INVALID"),
    ),
)
def test_closed_control_grammar_fails_typed(
    tmp_path: Path, control: str, reason: str
) -> None:
    spec = _spec(tmp_path, control)
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K.preflight_kustomize(spec)
    assert caught.value.reason_code == reason


def test_duplicate_control_name_and_symlink_fail_closed(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    (spec.repository_root / "Kustomization").write_text("resources: []\n", encoding="utf-8")
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K.preflight_kustomize(spec)
    assert caught.value.reason_code == "KUSTOMIZATION_CONTROL_AMBIGUOUS"

    (spec.repository_root / "Kustomization").unlink()
    target = spec.repository_root / "real.yaml"
    target.write_text("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n", encoding="utf-8")
    (spec.repository_root / "deployment.yaml").unlink()
    os.symlink(target, spec.repository_root / "deployment.yaml")
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K.preflight_kustomize(spec)
    assert caught.value.reason_code == "KUSTOMIZATION_SYMLINK"


def test_double_build_bytes_are_required_and_secret_is_redacted_from_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    spec = _spec(tmp_path)
    engine = {
        "name": "kustomize", "version": "5.7.1", "release_tag": "kustomize/v5.7.1",
        "release_id": 1, "platform": "test/arch",
        "executable_sha256": K._sha(spec.executable.read_bytes()),
        "archive_sha256": "b" * 64, "checksums_sha256": "c" * 64,
        "implementation_registry_sha256": "d" * 64,
    }
    monkeypatch.setattr(K, "_bind_engine", lambda _spec: engine)
    output = (
        b"apiVersion: v1\nkind: Secret\nmetadata:\n  name: generated\n"
        b"data:\n  password: c2VjcmV0\n"
    )
    monkeypatch.setattr(K, "_run_build", lambda *_args: output)
    evidence = K.materialize_kustomize(spec, tmp_path / "out")
    assert evidence.documents[0].generated_secret is True
    assert "c2VjcmV0" not in str(evidence.canonical_dict())

    calls = iter((output, output + b"\n"))
    monkeypatch.setattr(K, "_run_build", lambda *_args: next(calls))
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K.materialize_kustomize(spec, tmp_path / "other")
    assert caught.value.reason_code == "KUSTOMIZE_NONDETERMINISTIC_BUILD"


def test_duplicate_rendered_identity_is_rejected() -> None:
    payload = (
        b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: same}\n---\n"
        b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: same}\n"
    )
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K._documents(payload, "a" * 64)
    assert caught.value.reason_code == "KUSTOMIZE_DUPLICATE_RENDERED_IDENTITY"


@pytest.mark.parametrize(
    "fragment",
    (
        "labels:\n- pairs: {app: demo}\n  includeSelectors: 1\n",
        "images:\n- {name: nginx, newTag: latest, digest: sha256:abc}\n",
        "generatorOptions: {disableNameSuffixHash: 'false'}\n",
        "patches:\n- patch: []\n  target: {kind: Deployment}\n  options: {allowNameChange: 1}\n",
        "replacements:\n- source: {kind: ConfigMap, fieldPath: data.x}\n  targets: []\n",
        "configMapGenerator:\n- name: cfg\n  literals: key=value\n",
    ),
)
def test_nested_closed_shapes_reject_type_confusion(
    tmp_path: Path, fragment: str
) -> None:
    spec = _spec(tmp_path, f"resources: [deployment.yaml]\n{fragment}")
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K.preflight_kustomize(spec)
    assert caught.value.reason_code in {
        "KUSTOMIZATION_FIELD_SHAPE_INVALID",
        "KUSTOMIZATION_REPLACEMENT_INPUT_UNBOUND",
    }


def test_component_reference_requires_component_identity(tmp_path: Path) -> None:
    spec = _spec(tmp_path, "resources: [deployment.yaml]\ncomponents: [component]\n")
    component = spec.repository_root / "component"
    component.mkdir()
    (component / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
        encoding="utf-8",
    )
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K.preflight_kustomize(spec)
    assert caught.value.reason_code == "KUSTOMIZATION_CONTROL_INVALID"


def test_engine_registry_self_digest_is_bound() -> None:
    lock = K._engine_lock()
    assert lock["implementation_registry_sha256"] == K._canonical_sha({
        key: value for key, value in lock.items()
        if key != "implementation_registry_sha256"
    })


def test_engine_binding_and_offline_invocation_are_exact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    digest = K._sha(spec.executable.read_bytes())
    lock = {
        "contract": "iac-guard-v-kustomize-engine-lock-v1",
        "implementation_registry_sha256": "d" * 64,
        "release": {
            "repository": "https://example.invalid", "tag": "kustomize/v5.7.1",
            "release_id": 1, "version": "5.7.1", "published_at": "now",
            "checksums_sha256": "c" * 64,
        },
        "platforms": {"test/arch": {
            "archive": "tool.tgz", "archive_sha256": "b" * 64,
            "executable_sha256": digest,
        }},
    }
    monkeypatch.setattr(K, "_engine_lock", lambda: lock)
    monkeypatch.setattr(K, "_platform_key", lambda: "test/arch")
    monkeypatch.setattr(K, "run_command", lambda _request: _process(b"v5.7.1\n"))
    assert K._bind_engine(spec)["executable_sha256"] == digest

    lock["platforms"]["test/arch"]["executable_sha256"] = "0" * 64
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K._bind_engine(spec)
    assert caught.value.reason_code == "KUSTOMIZE_ENGINE_DIGEST_MISMATCH"
    lock["platforms"]["test/arch"]["executable_sha256"] = digest
    monkeypatch.setattr(K, "run_command", lambda _request: _process(b"v5.7.0\n"))
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K._bind_engine(spec)
    assert caught.value.reason_code == "KUSTOMIZE_ENGINE_VERSION_MISMATCH"
    monkeypatch.setattr(K, "_platform_key", lambda: "missing/arch")
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K._bind_engine(spec)
    assert caught.value.reason_code == "KUSTOMIZE_ENGINE_UNAVAILABLE"

    monkeypatch.setattr(K.platform, "system", lambda: "Unknown")
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K._offline_argv(spec.executable, spec.build_root)
    assert caught.value.reason_code == "KUSTOMIZE_OFFLINE_CONTRACT_FAILED"


def test_run_build_accepts_only_success_or_deprecation_diagnostics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    records = K.preflight_kustomize(spec)
    monkeypatch.setattr(
        K, "_offline_argv",
        lambda executable, build: (str(executable), "build", str(build)),
    )
    expected = b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"
    monkeypatch.setattr(
        K, "run_command", lambda _request: _process(expected, b"field is deprecated\n")
    )
    assert K._run_build(spec, records, tmp_path / "first") == expected
    monkeypatch.setattr(
        K, "run_command", lambda _request: _process(b"", b"bad input\n", 1)
    )
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K._run_build(spec, records, tmp_path / "second")
    assert caught.value.reason_code == "KUSTOMIZE_BUILD_FAILED"
    monkeypatch.setattr(
        K, "run_command", lambda _request: _process(expected, b"unexpected warning\n")
    )
    with pytest.raises(K.KustomizeMaterializationError) as caught:
        K._run_build(spec, records, tmp_path / "third")
    assert caught.value.reason_code == "KUSTOMIZE_BUILD_FAILED"


def test_report_semantics_bind_kustomize_engine_closure_and_scanner_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    lock = copy.deepcopy(K._engine_lock())
    platform_key = next(iter(lock["platforms"]))
    platform_record = lock["platforms"][platform_key]
    platform_record["executable_sha256"] = K._sha(spec.executable.read_bytes())
    engine = {
        "name": "kustomize", "version": lock["release"]["version"],
        "release_tag": lock["release"]["tag"],
        "release_id": lock["release"]["release_id"],
        "platform": platform_key,
        "executable_sha256": platform_record["executable_sha256"],
        "archive_sha256": platform_record["archive_sha256"],
        "checksums_sha256": lock["release"]["checksums_sha256"],
        "implementation_registry_sha256": lock["implementation_registry_sha256"],
    }
    rendered = (
        b"apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo}\n"
        b"spec: {selector: {matchLabels: {app: demo}}, template: {metadata: "
        b"{labels: {app: demo}}, spec: {containers: [{name: app, image: nginx}]}}}\n"
    )
    monkeypatch.setattr(K, "_bind_engine", lambda _spec: engine)
    monkeypatch.setattr(K, "_engine_lock", lambda: lock)
    monkeypatch.setattr(K, "_run_build", lambda *_args: rendered)
    evidence = K.materialize_kustomize(spec, tmp_path / "output").canonical_dict()
    payload = {
        "materialization": evidence,
        "acceptance": {"scanner_run": {
            "input_files": [{
                "file_path": "rendered.yaml",
                "sha256": evidence["output"]["rendered_bundle_sha256"],
            }],
            "evaluations": [],
        }},
    }
    REPORT._validate_kustomize_materialization(payload)

    tampered = copy.deepcopy(payload)
    tampered["materialization"]["engine"]["archive_sha256"] = "0" * 64
    with pytest.raises(K.DomainError, match="engine evidence"):
        REPORT._validate_kustomize_materialization(tampered)
    tampered = copy.deepcopy(payload)
    tampered["materialization"]["build"]["control_graph_sha256"] = "0" * 64
    with pytest.raises(K.DomainError, match="control/transform"):
        REPORT._validate_kustomize_materialization(tampered)

    mutations = (
        (lambda value: value["materialization"]["inputs"][0].update(path="../escape"), "unsafe"),
        (lambda value: value["materialization"]["inputs"][0].update(roles=["z", "a"]), "roles/referrers"),
        (lambda value: value["materialization"]["documents"][0].update(resource_identity="v1/ConfigMap/default/other"), "resource identity"),
        (lambda value: value["materialization"]["documents"][0].update(generated_secret=True), "secret-resource"),
        (lambda value: value["materialization"]["build"].update(transitive_input_manifest_sha256="0" * 64), "input root"),
        (lambda value: value["materialization"]["documents"][0].update(provenance_root_sha256="0" * 64), "complete input closure"),
        (lambda value: value["materialization"]["output"].update(resource_count=2), "output inventory"),
        (lambda value: value["materialization"]["output"].update(fresh_build_count=1), "two-build"),
        (lambda value: value["materialization"]["build"].update(build_root="../escape"), "build root"),
        (lambda value: value["materialization"]["build"].update(repository_root_identity="0" * 64), "repository-root"),
        (lambda value: value["materialization"]["build"].update(canonical_invocation_sha256="0" * 64), "invocation"),
        (lambda value: value["materialization"]["build"].update(source_to_output_lineage_sha256="0" * 64), "lineage"),
        (lambda value: value["materialization"].update(materialization_identity="0" * 64), "materialization identity"),
        (lambda value: value["acceptance"]["scanner_run"]["input_files"][0].update(sha256="0" * 64), "exact scanner input"),
    )
    for mutation, message in mutations:
        tampered = copy.deepcopy(payload)
        mutation(tampered)
        with pytest.raises(K.DomainError, match=message):
            REPORT._validate_kustomize_materialization(tampered)

    tampered = copy.deepcopy(payload)
    tampered["acceptance"]["scanner_run"]["evaluations"] = [{
        "graph_evidence": {
            "participants": [{"resource_address": "v1/ConfigMap/default/outside"}],
        },
    }]
    with pytest.raises(K.DomainError, match="graph participant"):
        REPORT._validate_kustomize_materialization(tampered)


def test_rendered_scope_identity_handles_core_crd_and_custom_resources() -> None:
    payload = b"""apiVersion: v1
kind: Namespace
metadata: {name: research}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: widgets.example.io}
spec:
  group: example.io
  scope: Namespaced
  names: {kind: Widget, plural: widgets}
---
apiVersion: example.io/v1
kind: Widget
metadata: {name: demo, namespace: research}
"""
    documents = K._documents(payload, "a" * 64)
    assert [item.resource_identity for item in documents] == [
        "v1/Namespace/default/research",
        "apiextensions.k8s.io/v1/CustomResourceDefinition/default/widgets.example.io",
        "example.io/v1/Widget/research/demo",
    ]
    with pytest.raises(K.KustomizeMaterializationError, match="scope"):
        K._documents(
            b"apiVersion: unknown.io/v1\nkind: Thing\nmetadata: {name: x}\n",
            "a" * 64,
        )
    with pytest.raises(K.KustomizeMaterializationError, match="no resources"):
        K._documents(b"", "a" * 64)


def test_build_spec_and_error_reason_shapes_are_closed(tmp_path: Path) -> None:
    with pytest.raises(K.DomainError, match="pathlib"):
        K.KustomizeBuildSpec("repo", Path("/tmp"), Path("/bin/echo"))
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(K.DomainError, match="inside repository"):
        K.KustomizeBuildSpec(repository, outside, Path("/bin/echo"))
    executable = repository / "tool"
    executable.write_text("tool\n", encoding="utf-8")
    executable.chmod(0o700)
    with pytest.raises(K.DomainError, match="must not be inside"):
        K.KustomizeBuildSpec(repository, repository, executable)
    with pytest.raises(K.DomainError, match="unavailable"):
        K.KustomizeBuildSpec(repository, repository, tmp_path / "missing")
    with pytest.raises(K.DomainError, match="reason code"):
        K.KustomizeMaterializationError("bad-code", "detail")


def test_engine_lock_rejects_contract_digest_and_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Resource:
        def __init__(self, payload: object) -> None:
            self.payload = payload

        def joinpath(self, _name: str):
            return self

        def read_text(self, **_kwargs) -> str:
            return json.dumps(self.payload)

    resource = Resource({"contract": "wrong"})
    monkeypatch.setattr(K, "files", lambda _package: resource)
    with pytest.raises(K.KustomizeMaterializationError, match="engine lock"):
        K._engine_lock()
    resource.payload = {
        "contract": "iac-guard-v-kustomize-engine-lock-v1",
        "implementation_registry_sha256": "0" * 64,
    }
    with pytest.raises(K.KustomizeMaterializationError, match="registry digest"):
        K._engine_lock()
    body = {
        "contract": "iac-guard-v-kustomize-engine-lock-v1",
        "release": {}, "platforms": {},
    }
    resource.payload = {
        **body, "implementation_registry_sha256": K._canonical_sha(body),
    }
    with pytest.raises(K.KustomizeMaterializationError, match="registry shape"):
        K._engine_lock()


def test_inventory_path_and_file_adversarial_edges(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    inventory = K._Inventory(spec.repository_root)
    with pytest.raises(K.KustomizeMaterializationError, match="local path"):
        inventory._contained(spec.repository_root, "https://example.invalid/x", "resource")
    with pytest.raises(K.KustomizeMaterializationError, match="portable"):
        inventory._contained(spec.repository_root, "/tmp/x", "resource")
    with pytest.raises(K.KustomizeMaterializationError, match="escapes"):
        inventory._contained(spec.repository_root, "../../outside", "resource")
    with pytest.raises(K.KustomizeMaterializationError, match="unavailable"):
        inventory._contained(spec.repository_root, "missing.yaml", "resource")
    with pytest.raises(K.KustomizeMaterializationError, match="unavailable"):
        inventory.add_file(spec.repository_root / "missing.yaml", "resource", "root")
    directory = spec.repository_root / "directory"
    directory.mkdir()
    with pytest.raises(K.KustomizeMaterializationError, match="regular file"):
        inventory.add_file(directory, "resource", "root")
    hardlink = spec.repository_root / "hardlink.yaml"
    os.link(spec.repository_root / "deployment.yaml", hardlink)
    with pytest.raises(K.KustomizeMaterializationError, match="regular file"):
        inventory.add_file(hardlink, "resource", "root")
    monkeypatch.setattr(K, "_MAX_FILE_BYTES", 1)
    with pytest.raises(K.KustomizeMaterializationError, match="size limit"):
        inventory.add_file(spec.repository_root / "kustomization.yaml", "control", "root")
    with pytest.raises(K.KustomizeMaterializationError, match="no control"):
        inventory.control_path(directory)


@pytest.mark.parametrize(
    "control",
    (
        "[]\n",
        "apiVersion: kustomize.config.k8s.io/v1beta1\nresources: []\n",
        "apiVersion: other/v1\nkind: Kustomization\nresources: []\n",
        "resources: wrong\n",
        "resources: [kustomization.yaml]\n",
        "patchesStrategicMerge: wrong\nresources: [deployment.yaml]\n",
        "patchesStrategicMerge: [bad]\nresources: [deployment.yaml]\n",
        "patches: wrong\nresources: [deployment.yaml]\n",
        "patches: [{path: a, patch: b}]\nresources: [deployment.yaml]\n",
        "patches: [{patch: {bad: shape}}]\nresources: [deployment.yaml]\n",
        "patchesJson6902: [{patch: [], target: {kind: Deployment}}]\nresources: [deployment.yaml]\n",
        "patches: [{patch: x, target: {kind: 1}}]\nresources: [deployment.yaml]\n",
        "replacements: wrong\nresources: [deployment.yaml]\n",
        "replacements: [bad]\nresources: [deployment.yaml]\n",
        "replacements: [{source: {}, targets: []}]\nresources: [deployment.yaml]\n",
        "configMapGenerator: wrong\nresources: [deployment.yaml]\n",
        "configMapGenerator: [{name: ''}]\nresources: [deployment.yaml]\n",
        "configMapGenerator: [{name: x, files: wrong}]\nresources: [deployment.yaml]\n",
        "configMapGenerator: [{name: x, env: 1}]\nresources: [deployment.yaml]\n",
        "namespace: 1\nresources: [deployment.yaml]\n",
        "commonLabels: [bad]\nresources: [deployment.yaml]\n",
        "images: wrong\nresources: [deployment.yaml]\n",
    ),
)
def test_closed_grammar_negative_adjacency_corpus(
    tmp_path: Path, control: str,
) -> None:
    spec = _spec(tmp_path, control)
    with pytest.raises(K.KustomizeMaterializationError):
        K.preflight_kustomize(spec)


def test_revalidation_output_and_materialization_guards(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    records = K.preflight_kustomize(spec)
    (spec.repository_root / "deployment.yaml").write_text("changed\n", encoding="utf-8")
    with pytest.raises(K.KustomizeMaterializationError, match="changed"):
        K._revalidate(spec, records)
    with pytest.raises(TypeError, match="exact Kustomize inputs"):
        K.materialize_kustomize(object(), tmp_path / "out")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    with pytest.raises(K.DomainError, match="must not already exist"):
        K.materialize_kustomize(spec, occupied)
    with pytest.raises(TypeError, match="exact KustomizeBuildSpec"):
        K.preflight_kustomize(object())

    with pytest.raises(K.KustomizeMaterializationError, match="UTF-8"):
        K._documents(b"\xff", "a" * 64)
    with pytest.raises(K.KustomizeMaterializationError, match="invalid"):
        K._documents(b"metadata: [\n", "a" * 64)
    with pytest.raises(K.KustomizeMaterializationError, match="mapping"):
        K._documents(b"- list\n", "a" * 64)
    with pytest.raises(K.KustomizeMaterializationError, match="identity"):
        K._documents(b"apiVersion: v1\nkind: ConfigMap\n", "a" * 64)
    with pytest.raises(K.KustomizeMaterializationError, match="name"):
        K._documents(
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {}\n", "a" * 64
        )
    monkeypatch.setattr(K, "_MAX_OUTPUT_DOCUMENTS", 0)
    with pytest.raises(K.KustomizeMaterializationError, match="document limit"):
        K._documents(
            b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n", "a" * 64
        )


def test_materialized_universe_context_is_ephemeral(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    evidence = SimpleNamespace(materialization_identity="a" * 64)

    def fake_materialize(_spec, output: Path):
        output.mkdir(parents=True)
        (output / "rendered.yaml").write_text("manifest\n", encoding="utf-8")
        return evidence

    monkeypatch.setattr(K, "materialize_kustomize", fake_materialize)
    with K.materialize_kustomize_universe(spec) as universe:
        root = universe.scanner_root
        assert universe.evidence is evidence
        assert root.is_dir()
    assert not root.exists()


def test_public_kustomize_config_and_cli_entry_are_closed(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    config = tmp_path / "request.json"
    config.write_text(json.dumps({
        "schema_version": "kustomize-acceptance-v1",
        "repository_root": str(spec.repository_root),
        "build_root": str(spec.build_root),
        "kustomize_executable": "/bin/echo",
        "checkov_executable": "/bin/echo",
        "properties": [{
            "rule_id": "CKV_K8S_20",
            "resource_address": "apps/v1/Deployment/default/demo",
            "artifact_kind": "kubernetes_yaml",
        }],
    }), encoding="utf-8")
    request = load_public_kustomize_acceptance_config(config)
    assert request.build.repository_root == spec.repository_root
    parsed = CLI._parser().parse_args([
        "kustomize-accept", "--config", str(config), "--local-trusted",
    ])
    assert parsed.command == "kustomize-accept"


def test_public_kustomize_request_and_cli_fail_closed_edges(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    property_ = PublicAcceptanceProperty(
        "CKV_K8S_20", "apps/v1/Deployment/default/demo"
    )
    with pytest.raises(K.DomainError, match="build specification"):
        PublicKustomizeAcceptanceRequest(
            object(), (property_,), ExecutionIsolation.REDUCED_ISOLATION,
            Path("/bin/echo"),
        )
    with pytest.raises(K.DomainError, match="nonempty exact tuple"):
        PublicKustomizeAcceptanceRequest(
            spec, (), ExecutionIsolation.REDUCED_ISOLATION, Path("/bin/echo")
        )
    with pytest.raises(K.DomainError, match="local-trusted"):
        PublicKustomizeAcceptanceRequest(
            spec, (property_,), ExecutionIsolation.HARDENED_CONTAINER,
            Path("/bin/echo"),
        )
    with pytest.raises(K.DomainError, match="explicit Checkov"):
        PublicKustomizeAcceptanceRequest(
            spec, (property_,), ExecutionIsolation.REDUCED_ISOLATION, "echo"
        )
    with pytest.raises(K.DomainError, match="unavailable"):
        PublicKustomizeAcceptanceRequest(
            spec, (property_,), ExecutionIsolation.REDUCED_ISOLATION,
            tmp_path / "missing-checkov",
        )

    report = API.OperationalReportV1("STOP", "bounded", "review")
    monkeypatch.setattr(CLI, "_write_report", lambda value, *_a, **_k: value.exit_code)
    assert CLI.main([
        "kustomize-accept", "--config", str(tmp_path / "unused.json")
    ]) == 3
    monkeypatch.setattr(
        CLI, "load_public_kustomize_acceptance_config", lambda _path: object()
    )
    monkeypatch.setattr(CLI, "verify_kustomize_candidate", lambda _request: report)
    assert CLI.main([
        "kustomize-accept", "--config", str(tmp_path / "unused.json"),
        "--local-trusted",
    ]) == 3


@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload.update(extra=True),
        lambda payload: payload.update(schema_version="other"),
        lambda payload: payload.update(repository_root=""),
        lambda payload: payload.update(properties=[]),
    ),
)
def test_public_kustomize_config_rejects_closed_schema_edges(
    tmp_path: Path, mutation,
) -> None:
    spec = _spec(tmp_path)
    payload = {
        "schema_version": "kustomize-acceptance-v1",
        "repository_root": str(spec.repository_root),
        "build_root": str(spec.build_root),
        "kustomize_executable": "/bin/echo",
        "checkov_executable": "/bin/echo",
        "properties": [{
            "rule_id": "CKV_K8S_20",
            "resource_address": "apps/v1/Deployment/default/demo",
        }],
    }
    mutation(payload)
    config = tmp_path / "request.json"
    config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(K.DomainError):
        load_public_kustomize_acceptance_config(config)


def test_public_kustomize_candidate_api_has_closed_success_and_failure_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    config = tmp_path / "request.json"
    config.write_text(json.dumps({
        "schema_version": "kustomize-acceptance-v1",
        "repository_root": str(spec.repository_root),
        "build_root": str(spec.build_root),
        "kustomize_executable": "/bin/echo",
        "checkov_executable": "/bin/echo",
        "properties": [{
            "rule_id": "CKV_K8S_20",
            "resource_address": "apps/v1/Deployment/default/demo",
            "artifact_kind": "kubernetes_yaml",
        }],
    }), encoding="utf-8")
    request = load_public_kustomize_acceptance_config(config)
    report = object()

    with pytest.raises(TypeError, match="exact Kustomize request"):
        API.verify_kustomize_candidate(object())

    @contextmanager
    def universe_context(_build):
        yield SimpleNamespace(scanner_root=spec.repository_root, evidence=object())

    monkeypatch.setattr(API, "materialize_kustomize_universe", universe_context)
    monkeypatch.setattr(API, "_verify_candidate_request", lambda *_a, **_k: report)
    assert API.verify_kustomize_candidate(request) is report

    @contextmanager
    def refusal(_build):
        raise K.KustomizeMaterializationError(
            "KUSTOMIZE_NONDETERMINISTIC_BUILD", "changed"
        )
        yield

    monkeypatch.setattr(API, "materialize_kustomize_universe", refusal)
    result = API.verify_kustomize_candidate(request)
    assert result.reason_code == "KUSTOMIZE_NONDETERMINISTIC_BUILD"
