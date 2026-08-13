"""E3.3 optional TFLint and closed-registry contract."""
from __future__ import annotations

import json
import shutil
from dataclasses import fields, replace
from pathlib import Path
from unittest.mock import patch

import pytest

from iac_guard_v.adapters.phase_e_lock import load_locked_container_identity, load_protected_phase_e_evidence
from iac_guard_v.enums import Status
from iac_guard_v.models import DomainError
from iac_guard_v.process import CommandResult, ProcessReason
from iac_guard_v.validators import (
    ProtectedTflintConfig, TflintValidationRequest, ValidationReason,
    create_tflint_validation_request, load_protected_tflint_config,
    production_validator_registry, require_trusted_validator_evidence,
)
from iac_guard_v.validators.registry import TrustedValidatorRegistry, ValidatorImplementationRecord
import iac_guard_v.validators.registry as registry_module
import iac_guard_v.validators.tflint as tflint_module
from tests.phase_e_test_support import execute_tflint_fixture, make_test_container_runtime


ROOT = Path(__file__).parents[2]
BUNDLE = load_protected_phase_e_evidence(ROOT)


def _process(payload: dict | bytes, exit_code: int = 0, *, status: Status = Status.PASS,
             timed_out: bool = False) -> CommandResult:
    raw = payload if type(payload) is bytes else json.dumps(payload).encode()
    reason = ProcessReason.COMPLETED_WITHIN_CONTRACT if status is Status.PASS else (
        ProcessReason.DEADLINE_EXCEEDED if timed_out else ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT
    )
    return CommandResult(
        argv=("docker",), status=status, exit_code=exit_code, stdout=raw, stderr=b"",
        duration_ms=2, truncated=False, timed_out=timed_out, killed_signal=None,
        reason_code=reason, resolved_executable="/usr/local/bin/docker" if status is Status.PASS else "",
        primary_execution_event=reason,
    )


def _request(tmp_path: Path, content: str = 'variable "name" { type = string }\n'):
    root = tmp_path / "root"
    root.mkdir(parents=True)
    (root / "main.tf").write_text(content, encoding="utf-8")
    lock = load_locked_container_identity(BUNDLE, "tflint", "linux/arm64")
    runtime = make_test_container_runtime(lock, Path(shutil.which("docker") or "/usr/bin/true"))
    return create_tflint_validation_request(
        workspace_root=root, scan_root=root, files_eligible=("main.tf",),
        container_runtime=runtime, locked_identity=lock,
        protected_config=load_protected_tflint_config(),
    )


def _issue() -> dict:
    return {
        "rule": {"name": "terraform_naming_convention", "severity": "warning", "link": "https://example.invalid/rule"},
        "message": "name should be snake case",
        "range": {"filename": "main.tf", "start": {"line": 1, "column": 1}, "end": {"line": 1, "column": 5}},
        "callers": [], "fixable": False, "fixed": False,
    }


def test_no_findings_and_diagnostic_are_trusted_but_advisory(tmp_path: Path) -> None:
    request = _request(tmp_path)
    clean = execute_tflint_fixture(request, _process({"issues": [], "errors": []}))
    assert (clean.status, clean.reason, clean.advisory_only) == (Status.PASS, ValidationReason.COMPLETED, True)
    finding = execute_tflint_fixture(request, _process({"issues": [_issue()], "errors": []}, 2))
    assert finding.status is Status.PASS and finding.advisory_only
    assert finding.diagnostics[0].summary == "terraform_naming_convention"
    assert require_trusted_validator_evidence(finding) is finding


def test_plugin_initialization_need_is_inconclusive(tmp_path: Path) -> None:
    payload = {"issues": [], "errors": [{"message": "Plugin not installed; initialize plugins", "severity": "error"}]}
    run = execute_tflint_fixture(_request(tmp_path), _process(payload, 1))
    assert (run.status, run.reason) == (Status.INCONCLUSIVE, ValidationReason.PLUGIN_INITIALIZATION_REQUIRED)


def test_candidate_config_and_transient_state_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    for name in (".tflint.hcl", ".terraform"):
        path = request.scan_root / name
        path.mkdir() if name == ".terraform" else path.write_text("plugin {}", encoding="utf-8")
        with pytest.raises(DomainError, match="candidate"):
            create_tflint_validation_request(
                workspace_root=request.workspace_root, scan_root=request.scan_root,
                files_eligible=("main.tf",), container_runtime=request.container_runtime,
                locked_identity=request.locked_identity, protected_config=request.protected_config,
            )
        path.rmdir() if path.is_dir() else path.unlink()


def test_nested_modules_are_not_overclaimed_by_one_root_invocation(tmp_path: Path) -> None:
    request = _request(tmp_path)
    nested = request.scan_root / "sub"
    nested.mkdir()
    (nested / "bad.tf").write_text("not valid hcl {", encoding="utf-8")
    with pytest.raises(DomainError, match="MODULE_SCOPE_UNRESOLVED"):
        create_tflint_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf", "sub/bad.tf"),
            container_runtime=request.container_runtime,
            locked_identity=request.locked_identity,
            protected_config=request.protected_config,
        )


def test_nested_module_candidate_configuration_is_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (request.scan_root / "main.tf").unlink()
    nested = request.scan_root / "sub"
    nested.mkdir()
    (nested / "main.tf").write_text("locals { x = 1 }\n", encoding="utf-8")
    (nested / ".tflint.hcl").write_text("config {}\n", encoding="utf-8")
    with pytest.raises(DomainError, match="candidate module"):
        create_tflint_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("sub/main.tf",),
            container_runtime=request.container_runtime,
            locked_identity=request.locked_identity,
            protected_config=request.protected_config,
        )


@pytest.mark.parametrize("raw", [b"not-json", b'{"issues":[],"issues":[]}'])
def test_malformed_output_is_inconclusive(tmp_path: Path, raw: bytes) -> None:
    run = execute_tflint_fixture(_request(tmp_path), _process(raw))
    assert run.status is Status.INCONCLUSIVE
    assert run.reason in {ValidationReason.MALFORMED_OUTPUT, ValidationReason.DUPLICATE_JSON_KEY}


def test_timeout_and_unexpected_exit_are_inconclusive(tmp_path: Path) -> None:
    process = _process(b"", None, status=Status.TIMEOUT, timed_out=True)
    run = execute_tflint_fixture(_request(tmp_path), process)
    assert (run.status, run.reason) == (Status.INCONCLUSIVE, ValidationReason.TIMEOUT)


def test_locked_command_has_no_init_network_or_candidate_config(tmp_path: Path) -> None:
    request = _request(tmp_path)
    observed = {}
    process = _process({"issues": [], "errors": []})
    def execute(command):
        observed["argv"] = command.argv
        return replace(process, argv=command.argv)
    with patch("iac_guard_v.validators.tflint.run_command", execute), patch(
        "iac_guard_v.validators.tflint.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        run = production_validator_registry().execute("tflint_advisory", request)
    argv = observed["argv"]
    assert run.status is Status.PASS and run.advisory_only
    assert argv[argv.index("--network") + 1] == "none"
    assert "--init" not in argv
    assert "/iacgv-protected/tflint.hcl" in argv
    assert str(request.scan_root / ".tflint.hcl") not in argv


def test_closed_registry_rejects_callback_wrong_gate_and_caller_process(tmp_path: Path) -> None:
    request = _request(tmp_path)
    registry = production_validator_registry()
    assert tuple(record.gate_id for record in registry.records) == (
        "kubeconform_schema", "opentofu_validate", "terraform_validate", "tflint_advisory",
    )
    with pytest.raises(TypeError):
        production_validator_registry(lambda _: Status.PASS)
    with pytest.raises(DomainError, match="outside"):
        registry.execute("fake_validator", request)
    with pytest.raises(DomainError, match="request type"):
        registry.execute("kubeconform_schema", request)
    assert "CommandResult" not in {field.name for field in fields(TflintValidationRequest)}


def test_registry_separates_terraform_family_identities(tmp_path: Path) -> None:
    request = _request(tmp_path)
    with pytest.raises(DomainError, match="request type"):
        production_validator_registry().execute("opentofu_validate", request)
    assert production_validator_registry().identity == production_validator_registry().identity


def test_input_mutation_and_extra_output_fail_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (request.scan_root / "main.tf").write_text("locals { changed = true }\n", encoding="utf-8")
    run = execute_tflint_fixture(request, _process({"issues": [], "errors": []}))
    assert run.reason is ValidationReason.INPUT_CHANGED_DURING_VALIDATION

    request = _request(tmp_path / "extra")
    process = _process({"issues": [], "errors": []})
    def execute(command):
        output_mount = next(item for item in command.argv if item.endswith(":/iacgv-output:rw"))
        (Path(output_mount.removesuffix(":/iacgv-output:rw")) / "extra").write_bytes(b"x")
        return replace(process, argv=command.argv)
    with patch("iac_guard_v.validators.tflint.run_command", execute), patch(
        "iac_guard_v.validators.tflint.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        run = production_validator_registry().execute("tflint_advisory", request)
        assert run.reason is ValidationReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED


def test_tflint_complete_module_scope_rejects_omitted_and_late_siblings(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path / "omitted")
    (request.scan_root / "bad.tf").write_text("not valid terraform", encoding="utf-8")
    with pytest.raises(DomainError, match="INCOMPLETE_MODULE_SCOPE"):
        create_tflint_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity,
            protected_config=request.protected_config,
        )

    request = _request(tmp_path / "late")
    (request.scan_root / "late.tf").write_text("not valid terraform", encoding="utf-8")
    run = execute_tflint_fixture(request, _process({"issues": [], "errors": []}))
    assert (run.status, run.reason) == (
        Status.INCONCLUSIVE, ValidationReason.SNAPSHOT_CHANGED_DURING_VALIDATION,
    )


def test_canonical_semantics_are_native_order_independent(tmp_path: Path) -> None:
    request = _request(tmp_path)
    first = _issue()
    second = replace_dict = json.loads(json.dumps(first))
    replace_dict["rule"]["name"] = "terraform_other_rule"
    one = execute_tflint_fixture(request, _process({"issues": [first, second], "errors": []}, 2))
    two = execute_tflint_fixture(request, _process({"issues": [second, first], "errors": []}, 2))
    assert one.native_output_bytes_sha256 != two.native_output_bytes_sha256
    assert one.canonical_native_output_sha256 == two.canonical_native_output_sha256


def test_protected_config_and_request_cannot_be_directly_minted(tmp_path: Path) -> None:
    config = load_protected_tflint_config()
    with pytest.raises(DomainError, match="source"):
        ProtectedTflintConfig(config.content_sha256, (), (), "caller")
    request = _request(tmp_path)
    with pytest.raises(DomainError, match="sealed factory"):
        TflintValidationRequest(
            request.workspace_root, request.scan_root, request.files_eligible,
            request.input_evidence, request.container_runtime, request.locked_identity,
            request.protected_config,
        )


def test_protected_config_rejects_digest_and_plugins() -> None:
    good = load_protected_tflint_config()
    with pytest.raises(DomainError, match="digest"):
        ProtectedTflintConfig("0" * 64, (), (), good.source_identity)
    with pytest.raises(DomainError, match="bundled"):
        ProtectedTflintConfig(good.content_sha256, ("aws",), (), good.source_identity)


def test_factory_rejects_outside_root_symlink_and_missing_input(tmp_path: Path) -> None:
    request = _request(tmp_path / "base")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.tf").write_text("locals {}", encoding="utf-8")
    with pytest.raises(DomainError, match="inside"):
        create_tflint_validation_request(
            workspace_root=request.workspace_root, scan_root=outside,
            files_eligible=("main.tf",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity, protected_config=request.protected_config,
        )
    source = request.scan_root / "main.tf"
    source.unlink()
    source.symlink_to("missing.tf")
    with pytest.raises(DomainError, match="nonsymlink"):
        create_tflint_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity, protected_config=request.protected_config,
        )
    source.unlink()
    with pytest.raises(DomainError, match="INPUT_CHANGED"):
        create_tflint_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf",), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity, protected_config=request.protected_config,
        )


def test_internal_request_invariants_fail_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    def construct(**changes):
        values = {field.name: getattr(request, field.name) for field in fields(TflintValidationRequest) if field.init and field.name != "_trusted_context"}
        values.update(changes)
        return TflintValidationRequest(**values, _trusted_context=tflint_module._REQUEST_CONTEXT)
    fake_config = object.__new__(ProtectedTflintConfig)
    object.__setattr__(fake_config, "_trusted_config", False)
    with pytest.raises(DomainError, match="protected"):
        construct(protected_config=fake_config)
    with pytest.raises(DomainError, match="nonempty"):
        construct(files_eligible=(), input_evidence=())
    with pytest.raises(DomainError, match="exactly cover"):
        construct(input_evidence=())
    with pytest.raises(DomainError, match="evidence is invalid"):
        construct(input_evidence=("main.tf",))
    with pytest.raises(DomainError, match="timeout"):
        construct(timeout_seconds=0)
    with pytest.raises(DomainError, match="output limit"):
        construct(max_output_bytes=0)


@pytest.mark.parametrize("change", [
    lambda issue: issue.update(rule={"name": "r", "severity": "fatal", "link": "x"}),
    lambda issue: issue.update(rule={"name": "", "severity": "warning", "link": "x"}),
    lambda issue: issue.update(range=[]),
    lambda issue: issue.update(range={"filename": 1, "start": {"line": 1, "column": 1}, "end": {"line": 1, "column": 2}}),
    lambda issue: issue.update(range={"filename": "main.tf", "start": {"line": 0, "column": 1}, "end": {"line": 1, "column": 2}}),
    lambda issue: issue.update(range={"filename": "main.tf", "start": {"line": 2, "column": 1}, "end": {"line": 1, "column": 2}}),
])
def test_issue_and_range_mutations_fail_closed(tmp_path: Path, change) -> None:
    issue = _issue()
    change(issue)
    run = execute_tflint_fixture(_request(tmp_path), _process({"issues": [issue], "errors": []}, 2))
    assert run.status is Status.INCONCLUSIVE


def test_notice_error_range_and_exit_contradictions(tmp_path: Path) -> None:
    request = _request(tmp_path)
    notice = _issue()
    notice["rule"]["severity"] = "notice"
    run = execute_tflint_fixture(request, _process({"issues": [notice], "errors": []}, 2))
    assert run.diagnostics[0].severity == "info"
    error = {
        "summary": "unsupported", "message": "feature unavailable", "severity": "warning",
        "range": _issue()["range"],
    }
    run = execute_tflint_fixture(request, _process({"issues": [], "errors": [error]}, 1))
    assert run.reason is ValidationReason.UNSUPPORTED_CONDITION
    run = execute_tflint_fixture(request, _process({"issues": [], "errors": [error]}, 0))
    assert run.reason is ValidationReason.DIAGNOSTIC_CONTRADICTION
    run = execute_tflint_fixture(request, _process({"issues": [], "errors": []}, 2))
    assert run.reason is ValidationReason.DIAGNOSTIC_CONTRADICTION


def test_runtime_argv_and_cleanup_failures_are_typed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    process = _process({"issues": [], "errors": []})
    with patch("iac_guard_v.validators.tflint.run_command", return_value=process), patch(
        "iac_guard_v.validators.tflint.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ):
        run = tflint_module.TflintValidator().validate(request)
    assert run.reason is ValidationReason.RUNTIME_INTEGRITY_FAILED
    with patch("iac_guard_v.validators.tflint.run_command", lambda command: replace(process, argv=command.argv)), patch(
        "iac_guard_v.validators.tflint.revalidate_trusted_container_runtime",
        return_value=request.container_runtime.identity,
    ), patch("iac_guard_v.validators.tflint.remove_private_tree", side_effect=OSError("cleanup")):
        run = tflint_module.TflintValidator().validate(request)
    assert run.reason is ValidationReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED
    with pytest.raises(DomainError, match="sealed request"):
        tflint_module.TflintValidator().validate(object())


def test_registry_record_and_graph_invariants() -> None:
    registry = production_validator_registry()
    record = registry.records[0]
    with pytest.raises(DomainError, match="digest"):
        replace(record, implementation_sha256="bad")
    with pytest.raises(DomainError, match="sorted"):
        replace(record, supported_artifact_kinds=("z", "a"))
    with pytest.raises(DomainError, match="bind its children"):
        replace(record, product_build_digest="0" * 64)
    with pytest.raises(DomainError, match="contract"):
        TrustedValidatorRegistry(registry.records, "wrong")
    with pytest.raises(DomainError, match="records"):
        TrustedValidatorRegistry((object(),), registry.contract)
    with pytest.raises(DomainError, match="complete"):
        TrustedValidatorRegistry(registry.records[:-1], registry.contract)


def test_registry_detects_substitution_and_wrong_returned_gate(tmp_path: Path) -> None:
    request = _request(tmp_path)
    original = registry_module._IMPLEMENTATIONS["tflint_advisory"]
    class WrongValidator:
        def validate(self, value):
            evidence = execute_tflint_fixture(value, _process({"issues": [], "errors": []}))
            object.__setattr__(evidence, "validator_id", "wrong_gate")
            return evidence
    registry_module._IMPLEMENTATIONS["tflint_advisory"] = (original[0], WrongValidator, *original[2:])
    try:
        with pytest.raises(DomainError, match="different gate"):
            production_validator_registry().execute("tflint_advisory", request)
    finally:
        registry_module._IMPLEMENTATIONS["tflint_advisory"] = original


@pytest.mark.parametrize("relative", [
    "validators/materialization.py",
    "validators/base.py",
    "validators/terraform.py",
    "validators/kubeconform.py",
    "validators/tflint.py",
    "engine.py",
    "process.py",
    "adapters/phase_e_runtime.py",
    "adapters/phase_e_lock.py",
])
def test_registry_identity_binds_security_relevant_source_bytes(relative: str) -> None:
    baseline = production_validator_registry().identity
    original = registry_module._read_source_bytes
    def changed(path: str) -> bytes:
        content = original(path)
        return content + b"\n# mutation probe\n" if path == relative else content
    with patch.object(registry_module, "_read_source_bytes", side_effect=changed):
        assert production_validator_registry().identity != baseline


def test_registry_identity_binds_physical_parser_dependency_evidence() -> None:
    baseline = production_validator_registry().identity
    with patch(
        "iac_guard_v.engine._verified_parser_environment",
        return_value={"python-hcl2": "0" * 64, "pyyaml": "1" * 64},
    ):
        assert production_validator_registry().identity != baseline


def test_registry_records_expose_complete_implementation_children() -> None:
    record = production_validator_registry().records[0].canonical_dict()
    assert {
        "contract_version", "implementation_sha256", "product_build_digest",
        "validator_module_sha256", "shared_code_manifest_root",
        "parser_dependency_identity", "schema_contract_identity",
        "runtime_contract_identity", "supported_artifact_kinds",
    } <= set(record)


def test_native_bytecode_cache_is_typed_registry_uncertainty(tmp_path: Path) -> None:
    request = _request(tmp_path)
    paths, unsafe = registry_module._product_source_inventory()
    assert not unsafe
    with patch.object(
        registry_module, "_product_source_inventory",
        return_value=(paths, ("BYTECODE_CACHE:validators/__pycache__",)),
    ):
        registry = production_validator_registry()
        assert registry.integrity_status is Status.INCONCLUSIVE
        assert "PYTHONDONTWRITEBYTECODE" in registry.remediation
        with pytest.raises(DomainError, match="INTEGRITY_INCONCLUSIVE"):
            registry.execute("tflint_advisory", request)


@pytest.mark.parametrize("mutation", [
    {"issues": {}},
    {"issues": [], "errors": [], "extra": True},
    {"issues": [{"rule": {}, "message": "x", "range": {}, "callers": [], "fixable": False, "fixed": False}], "errors": []},
    {"issues": [{**_issue(), "message": ""}], "errors": []},
    {"issues": [{**_issue(), "fixable": "no"}], "errors": []},
    {"issues": [{**_issue(), "range": {"filename": "other.tf", "start": {"line": 1, "column": 1}, "end": {"line": 1, "column": 2}}}], "errors": []},
    {"issues": [], "errors": [{"message": "", "severity": "error"}]},
])
def test_native_shape_mutations_fail_closed(tmp_path: Path, mutation: dict) -> None:
    if "errors" not in mutation:
        mutation["errors"] = []
    run = execute_tflint_fixture(_request(tmp_path), _process(mutation, 2 if mutation.get("issues") else 1))
    assert run.status is Status.INCONCLUSIVE


def test_invalid_extensions_duplicates_and_limits_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (request.scan_root / "main.txt").write_text("x", encoding="utf-8")
    for files, message in (("main.txt", "only Terraform"), ("main.tf", "byte limit")):
        with pytest.raises(DomainError, match=message):
            create_tflint_validation_request(
                workspace_root=request.workspace_root, scan_root=request.scan_root,
                files_eligible=(files,), container_runtime=request.container_runtime,
                locked_identity=request.locked_identity, protected_config=request.protected_config,
                max_file_bytes=1 if files == "main.tf" else 1024,
            )
    with pytest.raises(DomainError, match="duplicates"):
        create_tflint_validation_request(
            workspace_root=request.workspace_root, scan_root=request.scan_root,
            files_eligible=("main.tf", "main.tf"), container_runtime=request.container_runtime,
            locked_identity=request.locked_identity, protected_config=request.protected_config,
        )
