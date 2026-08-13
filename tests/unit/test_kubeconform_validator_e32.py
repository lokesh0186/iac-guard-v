"""E3.2 pinned offline kubeconform validation contract."""
from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

import iac_guard_v.validators.kubeconform as module
from iac_guard_v.adapters.phase_e_lock import (
    ProtectedKubernetesSchemaIdentity, load_locked_container_identity,
    load_protected_phase_e_evidence,
)
from iac_guard_v.enums import ScanRole, Status
from iac_guard_v.models import DomainError
from iac_guard_v.process import CommandResult, ProcessReason
from iac_guard_v.validators import (
    KubeconformValidator, ValidationReason, create_kubeconform_validation_request,
)
from tests.phase_e_test_support import (
    execute_kubeconform_fixture, make_test_container_runtime,
    make_test_kubernetes_schema_identity,
)


ROOT = Path(__file__).parents[2]
BUNDLE = load_protected_phase_e_evidence(ROOT)


def _process(raw: bytes, exit_code: int = 0, *, status: Status = Status.PASS,
             timed_out: bool = False) -> CommandResult:
    reason = (
        ProcessReason.COMPLETED_WITHIN_CONTRACT if status is Status.PASS
        else ProcessReason.DEADLINE_EXCEEDED if timed_out
        else ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT
    )
    return CommandResult(
        argv=("docker",), status=status, exit_code=exit_code,
        stdout=raw, stderr=b"", duration_ms=4, truncated=False,
        timed_out=timed_out, killed_signal=None, reason_code=reason,
        resolved_executable="/usr/local/bin/docker" if status is Status.PASS else "",
        primary_execution_event=reason,
    )


def _native(*, valid: int = 1, invalid: int = 0, errors: int = 0,
            skipped: int = 0, resources: list | None = None) -> bytes:
    return json.dumps({
        "resources": resources or [],
        "summary": {"valid": valid, "invalid": invalid, "errors": errors, "skipped": skipped},
    }).encode()


def _request(tmp_path: Path, content: str, *, suffix: str = ".yaml",
             role: ScanRole = ScanRole.CANDIDATE, crd: bool = False):
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    path = root / f"manifest{suffix}"
    path.write_text(content, encoding="utf-8")
    locked = load_locked_container_identity(BUNDLE, "kubeconform", "linux/arm64")
    schema = make_test_kubernetes_schema_identity(tmp_path / "schema")
    runtime = make_test_container_runtime(
        locked, Path(shutil.which("docker") or "/usr/bin/true")
    )
    return create_kubeconform_validation_request(
        workspace_root=root, scan_root=root, role=role,
        files_eligible=(path.name,), container_runtime=runtime,
        locked_identity=locked, schema_identity=schema,
        protected_crd_schema=schema if crd else None,
    )


def _affirmative(request, status: str = "statusValid") -> list[dict]:
    records = []
    for identity in request.resource_identities:
        path, address = identity.split(":", 1)
        version, kind, _namespace, name = address.rsplit("/", 3)
        records.append({
            "filename": f"/iacgv-input/{path}", "kind": kind, "name": name,
            "version": version, "status": status, "msg": "",
        })
    return records


POD = """apiVersion: v1
kind: Pod
metadata: {name: demo}
spec: {containers: [{name: c, image: nginx}]}
"""


@pytest.mark.parametrize("suffix,content", [
    (".yaml", POD),
    (".json", json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "demo"}})),
])
def test_valid_yaml_and_json_pass(tmp_path: Path, suffix: str, content: str) -> None:
    request = _request(tmp_path, content, suffix=suffix)
    run = execute_kubeconform_fixture(
        request, _process(_native(resources=_affirmative(request)))
    )
    assert (run.status, run.reason) == (Status.PASS, ValidationReason.COMPLETED)
    assert run.resources_validated == 1
    assert run.tool_environment_identity
    assert run.advisory_only is False


def test_invalid_candidate_and_invalid_baseline_are_distinct(tmp_path: Path) -> None:
    resource = [{
        "filename": "/iacgv-input/manifest.yaml", "kind": "Pod", "name": "demo",
        "version": "v1", "status": "statusInvalid", "msg": "containers must be array",
        "validationErrors": [{"path": "/spec/containers", "msg": "got string"}],
    }]
    candidate = _request(tmp_path / "candidate", POD)
    run = execute_kubeconform_fixture(candidate, _process(_native(valid=0, invalid=1, resources=resource), 1))
    assert (run.status, run.reason) == (Status.FAIL, ValidationReason.INVALID_CONFIGURATION)
    baseline = _request(tmp_path / "baseline", POD, role=ScanRole.BASELINE)
    run = execute_kubeconform_fixture(baseline, _process(_native(valid=0, invalid=1, resources=resource), 1))
    assert (run.status, run.reason) == (Status.INCONCLUSIVE, ValidationReason.BASELINE_EVIDENCE_INVALID)


def test_multidoc_and_list_resource_counts_are_bound(tmp_path: Path) -> None:
    multidoc = POD + "---\n" + POD.replace("demo", "other")
    request = _request(tmp_path / "multi", multidoc)
    assert len(request.resource_identities) == 2
    run = execute_kubeconform_fixture(
        request, _process(_native(valid=2, resources=_affirmative(request)))
    )
    assert run.status is Status.PASS
    list_doc = """apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Pod
  metadata: {name: one}
- apiVersion: v1
  kind: Service
  metadata: {name: two}
  spec: {ports: [{port: 80}]}
"""
    request = _request(tmp_path / "list", list_doc)
    assert len(request.resource_identities) == 2


def test_missing_schema_and_protected_crd_schema(tmp_path: Path) -> None:
    custom = "apiVersion: example.com/v1\nkind: Widget\nmetadata: {name: demo}\n"
    error = [{
        "filename": "/iacgv-input/manifest.yaml", "kind": "Widget", "name": "demo",
        "version": "example.com/v1", "status": "statusError",
        "msg": "could not find schema for Widget",
    }]
    request = _request(tmp_path / "missing", custom)
    run = execute_kubeconform_fixture(request, _process(_native(valid=0, errors=1, resources=error), 1))
    assert run.reason is ValidationReason.CRD_SCHEMA_UNAVAILABLE
    protected = _request(tmp_path / "protected", custom, crd=True)
    run = execute_kubeconform_fixture(
        protected, _process(_native(resources=_affirmative(protected)))
    )
    assert run.status is Status.PASS
    assert run.tool_environment_identity != request.schema_identity.identity
    protected_missing = execute_kubeconform_fixture(
        protected, _process(_native(valid=0, errors=1, resources=error), 1)
    )
    assert protected_missing.reason is ValidationReason.MISSING_SCHEMA


def test_malformed_candidate_syntax_fails_without_execution(tmp_path: Path) -> None:
    request = _request(tmp_path / "candidate", "apiVersion: [\n")
    run = KubeconformValidator().validate(request)
    assert (run.status, run.reason) == (Status.FAIL, ValidationReason.INVALID_CONFIGURATION)
    baseline = _request(tmp_path / "baseline", "apiVersion: [\n", role=ScanRole.BASELINE)
    run = KubeconformValidator().validate(baseline)
    assert (run.status, run.reason) == (Status.INCONCLUSIVE, ValidationReason.BASELINE_EVIDENCE_INVALID)


def test_missing_and_incomplete_coverage_never_pass(tmp_path: Path) -> None:
    request = _request(tmp_path, POD)
    missing = [{
        "filename": "/iacgv-input/manifest.yaml", "kind": "Pod", "name": "demo",
        "version": "v1", "status": "statusSkipped", "msg": "could not find schema",
    }]
    run = execute_kubeconform_fixture(request, _process(_native(valid=0, skipped=1, resources=missing), 1))
    assert run.reason is ValidationReason.MISSING_SCHEMA
    run = execute_kubeconform_fixture(request, _process(_native(valid=0)))
    assert run.reason is ValidationReason.INCOMPLETE_COVERAGE


def test_aggregate_only_success_cannot_invent_affirmative_resources(tmp_path: Path) -> None:
    request = _request(tmp_path, POD + "---\n" + POD.replace("demo", "other"))
    run = execute_kubeconform_fixture(request, _process(_native(valid=2)))
    assert run.status is Status.INCONCLUSIVE
    assert run.reason is ValidationReason.AFFIRMATIVE_RESOURCE_COVERAGE_UNAVAILABLE
    assert run.resources_validated == 0


@pytest.mark.parametrize("raw", [b"not json", b'{"resources":[],"resources":[]}'])
def test_malformed_native_json_is_inconclusive(tmp_path: Path, raw: bytes) -> None:
    run = execute_kubeconform_fixture(_request(tmp_path, POD), _process(raw))
    assert run.status is Status.INCONCLUSIVE
    assert run.reason in {ValidationReason.MALFORMED_OUTPUT, ValidationReason.DUPLICATE_JSON_KEY}


def test_native_order_is_canonically_deterministic(tmp_path: Path) -> None:
    request = _request(tmp_path, POD + "---\n" + POD.replace("demo", "other"))
    first = [{
        "filename": "/iacgv-input/manifest.yaml", "kind": "Pod", "name": name,
        "version": "v1", "status": "statusInvalid", "msg": "bad",
    } for name in ("demo", "other")]
    one = execute_kubeconform_fixture(request, _process(_native(valid=0, invalid=2, resources=first), 1))
    two = execute_kubeconform_fixture(request, _process(_native(valid=0, invalid=2, resources=list(reversed(first))), 1))
    assert one.native_output_bytes_sha256 != two.native_output_bytes_sha256
    assert one.canonical_native_output_sha256 == two.canonical_native_output_sha256
    assert one.canonical_native_output_sha256 == execute_kubeconform_fixture(
        request, _process(_native(valid=0, invalid=2, resources=first), 1)
    ).canonical_native_output_sha256


def test_command_has_no_network_or_ignore_missing_schema(tmp_path: Path) -> None:
    request = _request(tmp_path, POD)
    observed = {}
    process = _process(_native(resources=_affirmative(request)))
    def execute(command):
        observed["argv"] = command.argv
        return replace(process, argv=command.argv)
    with patch("iac_guard_v.validators.kubeconform.run_command", execute), patch(
        "iac_guard_v.validators.kubeconform.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ), patch.object(ProtectedKubernetesSchemaIdentity, "revalidate", return_value="1" * 64):
        run = KubeconformValidator().validate(request)
    assert run.status is Status.PASS
    assert observed["argv"][observed["argv"].index("--network") + 1] == "none"
    assert "-ignore-missing-schemas" not in observed["argv"]
    assert "-verbose" in observed["argv"]


def test_schema_change_timeout_and_extra_output_are_typed(tmp_path: Path) -> None:
    request = _request(tmp_path, POD)
    with patch.object(ProtectedKubernetesSchemaIdentity, "revalidate", side_effect=DomainError("SCHEMA_BUNDLE_CHANGED")), patch(
        "iac_guard_v.validators.kubeconform.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        run = KubeconformValidator().validate(request)
    assert run.reason is ValidationReason.SCHEMA_BUNDLE_CHANGED
    timeout = _process(b"", exit_code=None, status=Status.TIMEOUT, timed_out=True)
    run = execute_kubeconform_fixture(_request(tmp_path / "timeout", POD), timeout)
    assert run.reason is ValidationReason.TIMEOUT


def test_direct_request_and_untrusted_schema_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="sealed request"):
        KubeconformValidator().validate(object())
    request = _request(tmp_path, POD)
    object.__setattr__(request.schema_identity, "_trusted_schema_evidence", False)
    with pytest.raises(DomainError, match="signed E0.3"):
        create_kubeconform_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            role=ScanRole.CANDIDATE, files_eligible=request.files_eligible,
            container_runtime=request.container_runtime, locked_identity=request.locked_identity,
            schema_identity=request.schema_identity,
        )


def test_empty_non_kubernetes_scope_is_skipped(tmp_path: Path) -> None:
    request = _request(tmp_path, "name: workflow\non: push\n")
    run = KubeconformValidator().validate(request)
    assert (run.status, run.reason) == (Status.SKIPPED, ValidationReason.EMPTY_SCOPE)


@pytest.mark.parametrize(
    "payload",
    [
        {"resources": []},
        {"resources": {}, "summary": {"valid": 1, "invalid": 0, "errors": 0, "skipped": 0}},
        {"resources": [], "summary": {"valid": -1, "invalid": 0, "errors": 0, "skipped": 0}},
        {"resources": [{}], "summary": {"valid": 0, "invalid": 1, "errors": 0, "skipped": 0}},
        {"resources": [{"filename": "/iacgv-input/manifest.yaml", "kind": "Pod", "name": "demo", "version": "v1", "status": "statusInvalid", "msg": "bad", "extra": 1}], "summary": {"valid": 0, "invalid": 1, "errors": 0, "skipped": 0}},
        {"resources": [{"filename": "/iacgv-input/manifest.yaml", "kind": 1, "name": "demo", "version": "v1", "status": "statusInvalid", "msg": "bad"}], "summary": {"valid": 0, "invalid": 1, "errors": 0, "skipped": 0}},
        {"resources": [{"filename": "/iacgv-input/manifest.yaml", "kind": "Pod", "name": "demo", "version": "v1", "status": "unknown", "msg": "bad"}], "summary": {"valid": 0, "invalid": 1, "errors": 0, "skipped": 0}},
    ],
)
def test_native_shape_mutations_fail_closed(tmp_path: Path, payload: dict) -> None:
    run = execute_kubeconform_fixture(
        _request(tmp_path, POD), _process(json.dumps(payload).encode(), 1)
    )
    assert run.status is Status.INCONCLUSIVE
    assert run.reason in {ValidationReason.MALFORMED_OUTPUT, ValidationReason.DIAGNOSTIC_CONTRADICTION}


def test_native_path_count_exit_and_error_reason_are_closed(tmp_path: Path) -> None:
    request = _request(tmp_path, POD)
    base = {
        "filename": "/other/file.yaml", "kind": "Pod", "name": "demo",
        "version": "v1", "status": "statusInvalid", "msg": "bad",
    }
    run = execute_kubeconform_fixture(
        request, _process(_native(valid=0, invalid=1, resources=[base]), 1)
    )
    assert run.reason is ValidationReason.INCOMPLETE_COVERAGE
    matching = dict(base, filename="/iacgv-input/manifest.yaml")
    run = execute_kubeconform_fixture(
        request, _process(_native(valid=0, invalid=1, resources=[matching]), 0)
    )
    assert run.reason is ValidationReason.DIAGNOSTIC_CONTRADICTION
    generic = dict(matching, status="statusError", msg="schema service failed")
    run = execute_kubeconform_fixture(
        request, _process(_native(valid=0, errors=1, resources=[generic]), 1)
    )
    assert run.reason is ValidationReason.UNSUPPORTED_CONDITION


def test_affirmative_identity_duplicates_and_status_counts_are_reconciled(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path, POD)
    valid = _affirmative(request)[0]
    wrong = dict(valid, name="another")
    run = execute_kubeconform_fixture(
        request, _process(_native(resources=[wrong]))
    )
    assert run.reason is ValidationReason.AFFIRMATIVE_RESOURCE_COVERAGE_UNAVAILABLE
    run = execute_kubeconform_fixture(
        request, _process(_native(resources=[valid, valid]))
    )
    assert run.reason is ValidationReason.DIAGNOSTIC_CONTRADICTION
    invalid = dict(valid, status="statusInvalid", msg="bad")
    run = execute_kubeconform_fixture(
        request, _process(_native(resources=[invalid]))
    )
    assert run.reason is ValidationReason.DIAGNOSTIC_CONTRADICTION


def test_namespace_ambiguous_native_identity_is_inconclusive(tmp_path: Path) -> None:
    content = """apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Pod
  metadata: {name: demo, namespace: one}
- apiVersion: v1
  kind: Pod
  metadata: {name: demo, namespace: two}
"""
    request = _request(tmp_path, content)
    assert len(request.resource_identities) == 2
    native = [{
        "filename": "/iacgv-input/manifest.yaml", "kind": "Pod",
        "name": "demo", "version": "v1", "status": "statusValid", "msg": "",
    }] * 2
    run = execute_kubeconform_fixture(
        request, _process(_native(valid=2, resources=native))
    )
    assert run.reason is ValidationReason.AFFIRMATIVE_RESOURCE_COVERAGE_UNAVAILABLE


def test_input_change_and_wrong_process_argv_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path / "changed", POD)
    (request.scan_root / "manifest.yaml").write_text(POD.replace("demo", "changed"), encoding="utf-8")
    run = execute_kubeconform_fixture(request, _process(_native()))
    assert run.reason is ValidationReason.INPUT_CHANGED_DURING_VALIDATION

    request = _request(tmp_path / "argv", POD)
    process = _process(_native())
    with patch("iac_guard_v.validators.kubeconform.run_command", lambda _: replace(process, argv=("wrong",))), patch(
        "iac_guard_v.validators.kubeconform.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ), patch.object(ProtectedKubernetesSchemaIdentity, "revalidate", return_value="1" * 64):
        run = KubeconformValidator().validate(request)
    assert run.reason is ValidationReason.RUNTIME_INTEGRITY_FAILED


def test_complete_kubernetes_scope_detects_late_file(tmp_path: Path) -> None:
    request = _request(tmp_path, POD)
    (request.scan_root / "late.yaml").write_text(
        POD.replace("demo", "late"), encoding="utf-8",
    )
    run = execute_kubeconform_fixture(
        request, _process(_native(resources=_affirmative(request))),
    )
    assert (run.status, run.reason) == (
        Status.INCONCLUSIVE, ValidationReason.SNAPSHOT_CHANGED_DURING_VALIDATION,
    )


def test_native_valid_status_cannot_carry_validation_errors(tmp_path: Path) -> None:
    request = _request(tmp_path, POD)
    record = _affirmative(request)[0]
    record["validationErrors"] = [{"path": "/spec", "msg": "bad"}]
    run = execute_kubeconform_fixture(
        request, _process(_native(resources=[record])),
    )
    assert (run.status, run.reason) == (
        Status.INCONCLUSIVE, ValidationReason.DIAGNOSTIC_CONTRADICTION,
    )


def test_native_path_requires_exact_locked_prefix(tmp_path: Path) -> None:
    request = _request(tmp_path, POD)
    record = _affirmative(request)[0]
    record["filename"] = "/totally-other/manifest.yaml"
    run = execute_kubeconform_fixture(
        request, _process(_native(resources=[record])),
    )
    assert (run.status, run.reason) == (
        Status.INCONCLUSIVE, ValidationReason.INCOMPLETE_COVERAGE,
    )

def test_input_extension_symlink_size_and_duplicate_paths_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path / "base", POD)
    root = request.scan_root
    (root / "bad.txt").write_text("x", encoding="utf-8")
    with pytest.raises(DomainError, match="only YAML"):
        create_kubeconform_validation_request(
            workspace_root=root, scan_root=root, role=ScanRole.CANDIDATE,
            files_eligible=("bad.txt",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity, schema_identity=request.schema_identity,
        )
    with pytest.raises(DomainError, match="duplicates"):
        create_kubeconform_validation_request(
            workspace_root=root, scan_root=root, role=ScanRole.CANDIDATE,
            files_eligible=("manifest.yaml", "manifest.yaml"),
            container_runtime=request.container_runtime, locked_identity=request.locked_identity,
            schema_identity=request.schema_identity,
        )
    (root / "large.yaml").write_text(POD, encoding="utf-8")
    with pytest.raises(DomainError, match="byte limit"):
        create_kubeconform_validation_request(
            workspace_root=root, scan_root=root, role=ScanRole.CANDIDATE,
            files_eligible=("large.yaml",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity, schema_identity=request.schema_identity,
            max_file_bytes=1,
        )
