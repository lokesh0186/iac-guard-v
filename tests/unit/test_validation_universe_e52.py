from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import iac_guard_v.engine as engine
from iac_guard_v.engine import attest_checkov_scan_plan
from iac_guard_v.enums import ScanRole, Status
from iac_guard_v.models import BoundInputFile, DomainError
from iac_guard_v.oracles import (
    ProtectedOracleRegistry,
    create_protected_oracle_request,
    require_authoritative_oracle_precondition,
)
import iac_guard_v.oracles.base as oracle_base
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.validators.base import (
    ValidationReason,
    ValidatorExecutionEvidence,
)
from iac_guard_v.validators.universe import (
    TF_JSON_REASON,
    UNIVERSE_CONTRACT,
    TrustedValidationUniversePlan,
    ValidationUniverseFile,
    ValidationUniverseModule,
    ValidationUniverseOrchestrator,
    ValidationUniverseResult,
    _PLAN_CONTEXT,
    _RESULT_CONTEXT,
    _expected_kubernetes_scope,
    _sha,
    _aggregate_module_results,
    _validate_kubernetes_evidence,
    create_trusted_validation_universe_plan,
    revalidate_validation_universe_plan,
)

from test_checkov_adapter import request as adapter_request


EMPTY = hashlib.sha256(b"").hexdigest()


def _role_snapshot(discovery):
    return engine.SealedVerificationSnapshot(
        ScanRole.CANDIDATE, "repository_v1", ".",
        discovery.snapshot_sha256 or "a" * 64,
        discovery.artifact_manifest_sha256 or "b" * 64,
        discovery.inventory_sha256, "c" * 64, discovery.files,
        discovery.classifications, discovery.resources, discovery.governed_paths,
        discovery.filesystem_entries,
        _trusted_context=engine._TRUSTED_SCAN_PLAN_CONTEXT,
    )


def _terraform_snapshot(tmp_path: Path):
    raw = adapter_request(tmp_path, frameworks=("terraform",))
    (raw.scan_root / "main.tf").write_text('locals { root = true }\n', encoding="utf-8")
    (raw.scan_root / "sub").mkdir()
    (raw.scan_root / "sub" / "main.tf").write_text(
        'locals { child = true }\n', encoding="utf-8",
    )
    return raw.scan_root, _role_snapshot(attest_checkov_scan_plan(raw))


def _kubernetes_snapshot(tmp_path: Path, name: str = "demo"):
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(
        f"apiVersion: v1\nkind: Pod\nmetadata: {{name: {name}}}\n"
        "spec:\n  containers: [{name: app, image: example.invalid/app}]\n",
        encoding="utf-8",
    )
    return raw.scan_root, _role_snapshot(attest_checkov_scan_plan(raw))


def _windows_kubernetes_snapshot(tmp_path: Path):
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\n"
        "spec:\n  os: {name: windows}\n  containers: [{name: app}]\n",
        encoding="utf-8",
    )
    return raw.scan_root, _role_snapshot(attest_checkov_scan_plan(raw))


def _result(
    module, status: Status, reason: ValidationReason, *, plan=None,
    validator_id: str = "opentofu_validate", tool: str = "opentofu",
    advisory: bool = False,
):
    inputs = tuple(BoundInputFile(
        item.file_path, "terraform_hcl", item.size, item.sha256, 0, 0,
    ) for item in module.files)
    expected_plan = plan
    if expected_plan is None:
        expected_plan = SimpleNamespace(role=ScanRole.CANDIDATE)
    input_payload = tuple(item.canonical_dict() for item in inputs)
    module_snapshot = _sha(list(input_payload))
    scope_identity = _sha({
        "contract": "trusted-validation-scope-v1", "role": expected_plan.role.value,
        "scope_kind": "terraform-module", "module_root": module.module_root,
        "files": list(input_payload), "resource_identities": [],
    })
    scope = {
        "kind": "terraform-module", "role": expected_plan.role.value,
        "module_root": module.module_root,
        "module_snapshot_sha256": module_snapshot, "tool": tool,
    }
    if tool == "tflint":
        scope["module_execution_complete"] = "true"
    return ValidatorExecutionEvidence._from_execution(
        validator_id=validator_id, tool=tool, version="1.12.5",
        status=status, reason=reason, advisory_only=advisory, diagnostics=(),
        resource_identities=(), input_files=inputs, files_eligible=len(inputs),
        files_validated=len(inputs) if status is Status.PASS else 0,
        resources_expected=0, resources_validated=0,
        runtime_identity="1" * 64, tool_environment_identity="2" * 64,
        invocation_identity="3" * 64, sealed_snapshot_identity=scope_identity,
        materialized_view_sha256="5" * 64, stdout_sha256=EMPTY,
        stderr_sha256=EMPTY, native_output_bytes_sha256=EMPTY,
        canonical_native_output_sha256=EMPTY,
        output_directory_manifest_sha256=EMPTY, exit_code=0, duration_ms=1,
        validation_scope=tuple(sorted(scope.items())), execution_controls=("sealed-input",),
    )


def _kube_result(plan, status=Status.PASS):
    inputs = tuple(BoundInputFile(
        item.file_path, "kubernetes_yaml", item.size, item.sha256, 0, 0,
    ) for item in plan.kubernetes_files)
    _expected_inputs, scope_identity = _expected_kubernetes_scope(plan)
    resource_digest = _sha(list(plan.kubernetes_resource_identities))
    return ValidatorExecutionEvidence._from_execution(
        validator_id="kubeconform_validate", tool="kubeconform", version="0.8.0",
        status=status,
        reason=(ValidationReason.COMPLETED if status is Status.PASS else ValidationReason.MISSING_SCHEMA),
        advisory_only=False, diagnostics=(),
        resource_identities=plan.kubernetes_resource_identities,
        input_files=inputs, files_eligible=len(inputs),
        files_validated=len(inputs) if status is Status.PASS else 0,
        resources_expected=len(plan.kubernetes_resource_identities),
        resources_validated=len(plan.kubernetes_resource_identities) if status is Status.PASS else 0,
        runtime_identity="1" * 64, tool_environment_identity="2" * 64,
        invocation_identity="3" * 64, sealed_snapshot_identity=scope_identity,
        materialized_view_sha256="5" * 64, stdout_sha256=EMPTY,
        stderr_sha256=EMPTY, native_output_bytes_sha256=EMPTY,
        canonical_native_output_sha256=EMPTY,
        output_directory_manifest_sha256=EMPTY, exit_code=0, duration_ms=1,
        validation_scope=tuple(sorted({
            "kind": "kubernetes-resource-set", "role": plan.role.value,
            "expected_resources_sha256": resource_digest,
            "observed_resources_sha256": resource_digest,
        }.items())),
        execution_controls=("sealed-input",),
    )


def test_universe_derives_every_terraform_module_from_snapshot(tmp_path: Path) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    assert tuple(item.module_root for item in plan.terraform_modules) == (".", "sub")
    assert tuple(
        tuple(file.file_path for file in item.files) for item in plan.terraform_modules
    ) == (("main.tf",), ("sub/main.tf",))
    assert plan.ready


def test_late_or_removed_module_file_invalidates_universe(tmp_path: Path) -> None:
    root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    (root / "late" ).mkdir()
    (root / "late" / "main.tf").write_text("locals { late = true }\n")
    with pytest.raises(DomainError, match="SNAPSHOT_CHANGED_DURING_VALIDATION"):
        revalidate_validation_universe_plan(plan, root)


def test_every_module_requires_exact_typed_evidence(tmp_path: Path) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    passing = tuple(
        _result(item, Status.PASS, ValidationReason.COMPLETED)
        for item in plan.terraform_modules
    )
    aggregate = _aggregate_module_results(
        plan, "opentofu_validate", passing, advisory=False,
    )
    assert aggregate.status is Status.PASS
    with pytest.raises(DomainError, match="every repository module"):
        _aggregate_module_results(
            plan, "opentofu_validate", passing[:1], advisory=False,
        )


def test_module_aggregation_is_conservative(tmp_path: Path) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    failed = (
        _result(plan.terraform_modules[0], Status.PASS, ValidationReason.COMPLETED),
        _result(plan.terraform_modules[1], Status.FAIL, ValidationReason.INVALID_CONFIGURATION),
    )
    uncertain = (
        _result(plan.terraform_modules[0], Status.PASS, ValidationReason.COMPLETED),
        _result(plan.terraform_modules[1], Status.INCONCLUSIVE, ValidationReason.NEEDS_INIT),
    )
    assert _aggregate_module_results(
        plan, "opentofu_validate", failed, advisory=False,
    ).status is Status.FAIL
    assert _aggregate_module_results(
        plan, "opentofu_validate", uncertain, advisory=False,
    ).status is Status.INCONCLUSIVE


def test_universe_result_rederives_aggregate_from_children(tmp_path: Path) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    mixed = (
        _result(plan.terraform_modules[0], Status.PASS, ValidationReason.COMPLETED),
        _result(
            plan.terraform_modules[1], Status.FAIL,
            ValidationReason.INVALID_CONFIGURATION,
        ),
    )
    failed = _aggregate_module_results(
        plan, "opentofu_validate", mixed, advisory=False,
    )
    assert failed.status is Status.FAIL
    with pytest.raises(DomainError, match="aggregate contradicts child"):
        replace(
            failed, _trusted_context=_RESULT_CONTEXT, status=Status.PASS,
            reason="ALL_REQUIRED_MODULES_PASSED",
        )
    passing = tuple(
        _result(item, Status.PASS, ValidationReason.COMPLETED)
        for item in plan.terraform_modules
    )
    aggregate = _aggregate_module_results(
        plan, "opentofu_validate", passing, advisory=False,
    )
    for status, reason in (
        (Status.FAIL, "MODULE_VALIDATION_FAILED"),
        (Status.INCONCLUSIVE, "MODULE_VALIDATION_INCONCLUSIVE"),
    ):
        with pytest.raises(DomainError, match="aggregate contradicts child"):
            replace(
                aggregate, _trusted_context=_RESULT_CONTEXT,
                status=status, reason=reason,
            )


def test_validator_child_status_reason_contract_is_closed(tmp_path: Path) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    valid = _result(
        plan.terraform_modules[0], Status.FAIL,
        ValidationReason.INVALID_CONFIGURATION,
    )
    context = __import__(
        "iac_guard_v.validators.base", fromlist=["_EVIDENCE_CONTEXT"]
    )._EVIDENCE_CONTEXT
    with pytest.raises(DomainError, match="incompatible"):
        replace(
            valid, _trusted_context=context, reason=ValidationReason.NEEDS_INIT,
        )


def test_kubernetes_universe_is_snapshot_complete(tmp_path: Path) -> None:
    root, snapshot = _kubernetes_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    assert tuple(item.file_path for item in plan.kubernetes_files) == ("pod.yaml",)
    assert plan.kubernetes_resource_identities == ("pod.yaml:v1/Pod/default/demo",)
    (root / "late.json").write_text(
        '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"late"}}'
    )
    with pytest.raises(DomainError, match="SNAPSHOT_CHANGED_DURING_VALIDATION"):
        revalidate_validation_universe_plan(plan, root)


def test_authoritative_oracle_use_requires_same_passing_kubernetes_universe(
    tmp_path: Path,
) -> None:
    (tmp_path / "one").mkdir()
    _root, snapshot = _kubernetes_snapshot(tmp_path / "one")
    plan = create_trusted_validation_universe_plan(snapshot)
    evidence = _kube_result(plan)
    universe = ValidationUniverseResult(
        "kubeconform_validate", plan.role, plan.universe_sha256, Status.PASS,
        "COMPLETE_KUBERNETES_UNIVERSE_PASSED", False, (), evidence,
        _plan=plan, _trusted_context=_RESULT_CONTEXT,
    )
    oracle = ProtectedOracleRegistry().execute(create_protected_oracle_request(
        oracle_id="kubernetes_no_privileged_containers_v1", snapshot=snapshot,
        file_path="pod.yaml", artifact_kind=ArtifactKind.KUBERNETES_YAML,
        resource_identity="v1/Pod/default/demo",
    ))
    assert require_authoritative_oracle_precondition(oracle, universe) is oracle

    (tmp_path / "other").mkdir()
    _other_root, other_snapshot = _kubernetes_snapshot(tmp_path / "other", "other")
    other_plan = create_trusted_validation_universe_plan(other_snapshot)
    other_evidence = _kube_result(other_plan)
    other_universe = ValidationUniverseResult(
        "kubeconform_validate", other_plan.role, other_plan.universe_sha256,
        Status.PASS, "COMPLETE_KUBERNETES_UNIVERSE_PASSED", False, (),
        other_evidence, _plan=other_plan, _trusted_context=_RESULT_CONTEXT,
    )
    with pytest.raises(DomainError, match="validated resource universe"):
        require_authoritative_oracle_precondition(oracle, other_universe)

    for mutation in (
        {"role": ScanRole.BASELINE},
        {"resource_identity": "v1/Pod/default/other"},
        {"artifact_kind": ArtifactKind.KUBERNETES_JSON},
    ):
        forged = replace(
            oracle, _trusted_context=oracle_base._EVIDENCE_CONTEXT, **mutation,
        )
        with pytest.raises(DomainError, match="validated resource universe|artifact identity"):
            require_authoritative_oracle_precondition(forged, universe)


def test_nondecisive_oracle_is_not_authoritative_even_with_passing_universe(
    tmp_path: Path,
) -> None:
    root = tmp_path / "windows"
    root.mkdir()
    _scan_root, snapshot = _windows_kubernetes_snapshot(root)
    plan = create_trusted_validation_universe_plan(snapshot)
    evidence = _kube_result(plan)
    universe = ValidationUniverseResult(
        "kubeconform_validate", plan.role, plan.universe_sha256, Status.PASS,
        "COMPLETE_KUBERNETES_UNIVERSE_PASSED", False, (), evidence,
        _plan=plan, _trusted_context=_RESULT_CONTEXT,
    )
    oracle = ProtectedOracleRegistry().execute(create_protected_oracle_request(
        oracle_id="kubernetes_allow_privilege_escalation_false_v1",
        snapshot=snapshot, file_path="pod.yaml",
        artifact_kind=ArtifactKind.KUBERNETES_YAML,
        resource_identity="v1/Pod/default/demo",
    ))
    assert oracle.status is Status.UNSUPPORTED
    with pytest.raises(DomainError, match="non-decisive"):
        require_authoritative_oracle_precondition(oracle, universe)


def test_tf_json_is_explicitly_unsupported(tmp_path: Path) -> None:
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\n", encoding="utf-8",
    )
    (raw.scan_root / "main.tf.json").write_text("{}", encoding="utf-8")
    snapshot = _role_snapshot(attest_checkov_scan_plan(raw))
    plan = create_trusted_validation_universe_plan(snapshot)
    assert plan.unsupported_tf_json == ("main.tf.json",)
    assert not plan.ready
    assert TF_JSON_REASON == ValidationReason.TF_JSON_UNSUPPORTED.value


def test_universe_plan_cannot_be_forged(tmp_path: Path) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    with pytest.raises(DomainError, match="sealed-snapshot factory"):
        replace(plan, _trusted_context=None)


class _Registry:
    def __init__(self, results):
        self.results = iter(results)
        self.gates = []

    def execute(self, gate_id, _request):
        self.gates.append(gate_id)
        return next(self.results)


def test_closed_orchestrator_executes_every_terraform_module(tmp_path: Path) -> None:
    root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    results = tuple(
        _result(item, Status.PASS, ValidationReason.COMPLETED)
        for item in plan.terraform_modules
    )
    registry = _Registry(results)
    with patch("iac_guard_v.validators.universe.production_validator_registry", return_value=registry), patch(
        "iac_guard_v.validators.universe.create_terraform_validation_request",
        side_effect=lambda **values: values,
    ):
        aggregate = ValidationUniverseOrchestrator().validate_terraform(
            plan=plan, workspace_root=root, scan_root=root, runtime=object(),
            locked_identity=SimpleNamespace(tool="opentofu"),
        )
    assert aggregate.status is Status.PASS
    assert registry.gates == ["opentofu_validate", "opentofu_validate"]


def test_tflint_uses_same_modules_and_remains_advisory(tmp_path: Path) -> None:
    root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    results = tuple(
        _result(
            item, Status.PASS, ValidationReason.COMPLETED,
            validator_id="tflint_advisory", tool="tflint", advisory=True,
        ) for item in plan.terraform_modules
    )
    registry = _Registry(results)
    with patch("iac_guard_v.validators.universe.production_validator_registry", return_value=registry), patch(
        "iac_guard_v.validators.universe.create_tflint_validation_request",
        side_effect=lambda **values: values,
    ):
        aggregate = ValidationUniverseOrchestrator().validate_tflint(
            plan=plan, workspace_root=root, scan_root=root, runtime=object(),
            locked_identity=SimpleNamespace(tool="tflint"),
        )
    assert aggregate.status is Status.PASS
    assert aggregate.advisory_only
    assert registry.gates == ["tflint_advisory", "tflint_advisory"]


def test_universe_mutation_between_module_executions_is_rejected(tmp_path: Path) -> None:
    root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    results = tuple(
        _result(item, Status.PASS, ValidationReason.COMPLETED)
        for item in plan.terraform_modules
    )
    class MutatingRegistry(_Registry):
        def execute(self, gate_id, request):
            result = super().execute(gate_id, request)
            (root / "late.tf").write_text("locals { late = true }\n")
            return result
    with patch(
        "iac_guard_v.validators.universe.production_validator_registry",
        return_value=MutatingRegistry(results),
    ), patch(
        "iac_guard_v.validators.universe.create_terraform_validation_request",
        side_effect=lambda **values: values,
    ):
        with pytest.raises(DomainError, match="SNAPSHOT_CHANGED_DURING_VALIDATION"):
            ValidationUniverseOrchestrator().validate_terraform(
                plan=plan, workspace_root=root, scan_root=root, runtime=object(),
                locked_identity=SimpleNamespace(tool="opentofu"),
            )


def test_unsupported_tf_json_returns_typed_uncertainty_without_execution(tmp_path: Path) -> None:
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\n", encoding="utf-8",
    )
    (raw.scan_root / "main.tf.json").write_text("{}", encoding="utf-8")
    plan = create_trusted_validation_universe_plan(
        _role_snapshot(attest_checkov_scan_plan(raw))
    )
    result = ValidationUniverseOrchestrator().validate_terraform(
        plan=plan, workspace_root=raw.scan_root, scan_root=raw.scan_root,
        runtime=object(), locked_identity=SimpleNamespace(tool="opentofu"),
    )
    assert result.status is Status.INCONCLUSIVE
    assert result.reason == TF_JSON_REASON


def test_validation_universe_value_guards(tmp_path: Path) -> None:
    root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    file = plan.terraform_modules[0].files[0]
    with pytest.raises(DomainError, match="regular file"):
        ValidationUniverseFile(file.file_path, "FIFO", file.size, file.sha256)
    with pytest.raises(DomainError, match="digest"):
        ValidationUniverseFile(file.file_path, "REGULAR_FILE", file.size, "bad")
    with pytest.raises(DomainError, match="files are invalid"):
        ValidationUniverseModule(".", (), EMPTY)
    with pytest.raises(DomainError, match="sorted"):
        ValidationUniverseModule(
            ".", (ValidationUniverseFile("z.tf", "REGULAR_FILE", 0, EMPTY), file),
            "0" * 64,
        )
    with pytest.raises(DomainError, match="crosses"):
        ValidationUniverseModule("sub", (file,), _sha([file.canonical_dict()]))
    with pytest.raises(DomainError, match="not canonical"):
        ValidationUniverseModule(".", (file,), "0" * 64)
    assert plan.canonical_dict()["universe_sha256"] == plan.universe_sha256
    with pytest.raises(DomainError, match="trusted sealed snapshot"):
        create_trusted_validation_universe_plan(object())
    for changes, message in (
        ({"_snapshot": object()}, "snapshot is not trusted"),
        ({"role": ScanRole.DISCOVERY}, "role is invalid"),
        ({"contract": "wrong"}, "contract"),
        ({"physical_inventory_sha256": "bad"}, "is invalid"),
        ({"terraform_modules": ("bad",)}, "modules are invalid"),
        ({"terraform_modules": (plan.terraform_modules[0], plan.terraform_modules[0])}, "roots"),
        ({"kubernetes_files": ("bad",)}, "Kubernetes files"),
        ({"unsupported_tf_json": ("z", "z")}, "unsupported Terraform JSON"),
        ({"sealed_snapshot_identity": "0" * 64}, "disagrees"),
        ({"repository_identity": "different_repository"}, "repository identity"),
        ({"repository_relative_subpath": "different"}, "repository subpath"),
        ({"sealed_artifact_manifest_identity": "0" * 64}, "artifact manifest"),
        ({"physical_inventory_sha256": "0" * 64}, "physical inventory"),
        ({"universe_sha256": "0" * 64}, "not canonical"),
    ):
        with pytest.raises(DomainError, match=message):
            replace(plan, **changes)
    revalidate_validation_universe_plan(plan, root)
    with pytest.raises(DomainError, match="not trusted"):
        revalidate_validation_universe_plan(object(), root)
    with patch(
        "iac_guard_v.validators.universe._filesystem_inventory",
        side_effect=DomainError("bad"),
    ):
        with pytest.raises(DomainError, match="SNAPSHOT_CHANGED"):
            revalidate_validation_universe_plan(plan, root)


def _snapshot_with_unresolved_entry(snapshot):
    entry = engine.FilesystemArtifactEntry(
        "evil.tf", "FIFO", 0, None, None, True, False,
        "UNSUPPORTED_ARTIFACT_PATH_TYPE",
    )
    governed = engine.FilesystemArtifactEntry(
        ".iac-guard.yml", "SYMLINK", 0, None, "elsewhere", False, True,
        "UNSAFE_SYMLINK_ENTRY",
    )
    return engine.SealedVerificationSnapshot(
        snapshot.role, snapshot.repository_identity, snapshot.repository_relative_subpath,
        snapshot.snapshot_sha256, snapshot.artifact_manifest_sha256,
        snapshot.resource_inventory_sha256, snapshot.config_sha256,
        snapshot.files, snapshot.classifications, snapshot.resources,
        snapshot.governed_paths, (*snapshot.filesystem_entries, governed, entry),
        _trusted_context=engine._TRUSTED_SCAN_PLAN_CONTEXT,
    )


def test_unresolved_supported_and_governed_entries_block_readiness(tmp_path: Path) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(_snapshot_with_unresolved_entry(snapshot))
    assert not plan.ready
    assert "evil.tf:FIFO" in plan.unresolved_entries
    assert ".iac-guard.yml:UNSAFE_SYMLINK_ENTRY" in plan.unresolved_entries
    result = ValidationUniverseOrchestrator().validate_terraform(
        plan=plan, workspace_root=tmp_path, scan_root=tmp_path, runtime=object(),
        locked_identity=SimpleNamespace(tool="opentofu"),
    )
    assert result.status is Status.INCONCLUSIVE
    assert result.reason == "ARTIFACT_UNIVERSE_UNRESOLVED"


def test_result_and_aggregate_consistency_guards(tmp_path: Path) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    passing = tuple(_result(item, Status.PASS, ValidationReason.COMPLETED) for item in plan.terraform_modules)
    aggregate = _aggregate_module_results(plan, "opentofu_validate", passing, advisory=False)
    assert aggregate.canonical_dict()["kubernetes_result"] is None
    with pytest.raises(DomainError, match="protected orchestration"):
        replace(aggregate, _trusted_context=None)
    for changes, message in (
        ({"role": ScanRole.DISCOVERY}, "role"),
        ({"universe_sha256": "bad"}, "identity"),
        ({"status": "PASS"}, "status"),
        ({"status": Status.FAIL}, "status/reason"),
        ({"advisory_only": "false"}, "advisory"),
        ({"module_results": []}, "module results"),
    ):
        with pytest.raises(DomainError, match=message):
            replace(aggregate, _trusted_context=_RESULT_CONTEXT, **changes)
    wrong_id = replace(
        passing[0], _trusted_context=__import__(
            "iac_guard_v.validators.base", fromlist=["_EVIDENCE_CONTEXT"]
        )._EVIDENCE_CONTEXT,
        validator_id="terraform_validate",
    )
    with pytest.raises(DomainError, match="identity"):
        _aggregate_module_results(
            plan, "opentofu_validate", (wrong_id, passing[1]), advisory=False,
        )
    duplicate = replace(
        passing[1], _trusted_context=__import__(
            "iac_guard_v.validators.base", fromlist=["_EVIDENCE_CONTEXT"]
        )._EVIDENCE_CONTEXT,
        validation_scope=passing[0].validation_scope,
    )
    with pytest.raises(DomainError, match="duplicated or unbound"):
        _aggregate_module_results(
            plan, "opentofu_validate", (passing[0], duplicate), advisory=False,
        )
    changed_input = replace(
        passing[0].input_files[0], sha256="0" * 64,
    )
    changed = replace(
        passing[0], _trusted_context=__import__(
            "iac_guard_v.validators.base", fromlist=["_EVIDENCE_CONTEXT"]
        )._EVIDENCE_CONTEXT,
        input_files=(changed_input,),
    )
    with pytest.raises(DomainError, match="bytes disagree"):
        _aggregate_module_results(
            plan, "opentofu_validate", (changed, passing[1]), advisory=False,
        )


def test_module_pass_requires_exact_role_snapshot_and_complete_coverage(
    tmp_path: Path,
) -> None:
    _root, snapshot = _terraform_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    passing = tuple(
        _result(item, Status.PASS, ValidationReason.COMPLETED)
        for item in plan.terraform_modules
    )
    context = __import__(
        "iac_guard_v.validators.base", fromlist=["_EVIDENCE_CONTEXT"]
    )._EVIDENCE_CONTEXT
    mutations = (
        (
            replace(passing[0], _trusted_context=context, files_validated=0),
            "incomplete",
        ),
        (
            replace(
                passing[0], _trusted_context=context,
                validation_scope=tuple(sorted({
                    **dict(passing[0].validation_scope), "role": "baseline",
                }.items())),
            ),
            "scope contradicts",
        ),
        (
            replace(
                passing[0], _trusted_context=context,
                sealed_snapshot_identity="0" * 64,
            ),
            "snapshot identity",
        ),
    )
    for mutation, message in mutations:
        with pytest.raises(DomainError, match=message):
            _aggregate_module_results(
                plan, "opentofu_validate", (mutation, passing[1]), advisory=False,
            )


def test_kubernetes_pass_requires_exact_files_resources_role_and_scope(
    tmp_path: Path,
) -> None:
    _root, snapshot = _kubernetes_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    passing = _kube_result(plan)
    context = __import__(
        "iac_guard_v.validators.base", fromlist=["_EVIDENCE_CONTEXT"]
    )._EVIDENCE_CONTEXT
    mutations = (
        (
            replace(
                passing, _trusted_context=context, files_validated=0,
                resources_validated=0, resource_identities=(),
            ),
            "incomplete",
        ),
        (
            replace(
                passing, _trusted_context=context,
                validation_scope=tuple(sorted({
                    **dict(passing.validation_scope), "role": "baseline",
                }.items())),
            ),
            "scope is inconsistent",
        ),
        (
            replace(
                passing, _trusted_context=context,
                sealed_snapshot_identity="0" * 64,
            ),
            "snapshot identity",
        ),
        (
            replace(passing, _trusted_context=context, resource_identities=("other",)),
            "incomplete",
        ),
    )
    for mutation, message in mutations:
        with pytest.raises(DomainError, match=message):
            _validate_kubernetes_evidence(plan, mutation)


def test_empty_and_wrong_tool_orchestration_is_conservative(tmp_path: Path) -> None:
    root, snapshot = _kubernetes_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    orchestrator = ValidationUniverseOrchestrator()
    with pytest.raises(DomainError, match="OpenTofu or Terraform"):
        orchestrator.validate_terraform(
            plan=plan, workspace_root=root, scan_root=root, runtime=object(),
            locked_identity=SimpleNamespace(tool="kics"),
        )
    empty = orchestrator.validate_terraform(
        plan=plan, workspace_root=root, scan_root=root, runtime=object(),
        locked_identity=SimpleNamespace(tool="opentofu"),
    )
    assert empty.status is Status.INCONCLUSIVE
    with pytest.raises(DomainError, match="TFLint lock"):
        orchestrator.validate_tflint(
            plan=plan, workspace_root=root, scan_root=root, runtime=object(),
            locked_identity=SimpleNamespace(tool="opentofu"),
        )
    assert orchestrator.validate_tflint(
        plan=plan, workspace_root=root, scan_root=root, runtime=object(),
        locked_identity=SimpleNamespace(tool="tflint"),
    ).status is Status.INCONCLUSIVE
    with pytest.raises(DomainError, match="empty repository"):
        _aggregate_module_results(plan, "opentofu_validate", (), advisory=False)


@pytest.mark.parametrize("status", [Status.PASS, Status.INCONCLUSIVE])
def test_kubernetes_orchestration_binds_complete_evidence(tmp_path: Path, status: Status) -> None:
    root, snapshot = _kubernetes_snapshot(tmp_path)
    plan = create_trusted_validation_universe_plan(snapshot)
    evidence = _kube_result(plan, status)
    registry = _Registry((evidence,))
    with patch(
        "iac_guard_v.validators.universe.production_validator_registry",
        return_value=registry,
    ), patch(
        "iac_guard_v.validators.universe.create_kubeconform_validation_request",
        return_value=object(),
    ):
        result = ValidationUniverseOrchestrator().validate_kubernetes(
            plan=plan, workspace_root=root, scan_root=root, runtime=object(),
            locked_identity=object(), schema_identity=object(),
        )
    assert result.status is status
    assert result.kubernetes_result is evidence
    assert result.canonical_dict()["kubernetes_result"]
    with pytest.raises(DomainError, match="contradicts"):
        replace(
            result, _trusted_context=_RESULT_CONTEXT,
            validator_id="opentofu_validate",
        )
