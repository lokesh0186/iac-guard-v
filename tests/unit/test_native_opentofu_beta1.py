from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from iac_guard_v.models import DomainError
from iac_guard_v.native_properties.engine import evaluate_native_request
from iac_guard_v.native_properties.evidence import validate_native_observation
from iac_guard_v.native_properties.model import (
    NativeArtifactClass, NativePropertyRequest, NativePropertyResult,
)
from iac_guard_v.native_properties.registry import NATIVE_PROPERTY_REGISTRY
from iac_guard_v.native_properties.opentofu import OPENTOFU_MAX_FILE_BYTES
from iac_guard_v.native_properties.universe import load_protected_native_universe
from iac_guard_v.contracts.model import ContractProvenance
from iac_guard_v.contracts.public import ContractExecutionInput, prepare_contract_run


DIGEST = "1" * 64


def _request(universe, source: str, target: str, *, complete: bool = True):
    parameters = {
        "attribute_path": ["bucket"],
        "expected_target": target,
        "mode": "DIRECT",
        "complete_expected_domain": complete,
    }
    if complete:
        parameters["reference_contract_digest"] = DIGEST
    return NativePropertyRequest.build(
        request_id="opentofu-reference",
        property_id="IACGV_OPENTOFU_REFERENCE_RESOLVES_V1",
        property_version="1",
        artifact_class=NativeArtifactClass.OPENTOFU_SOURCE,
        subject_identity=source,
        parameters=parameters,
        protected_universe_identity=universe.identity,
    )


def _custom_request(universe, source: str, parameters: dict):
    return NativePropertyRequest.build(
        request_id="opentofu-reference-custom",
        property_id="IACGV_OPENTOFU_REFERENCE_RESOLVES_V1",
        property_version="1",
        artifact_class=NativeArtifactClass.OPENTOFU_SOURCE,
        subject_identity=source,
        parameters=parameters,
        protected_universe_identity=universe.identity,
    )


def _hcl(target: str = "logs") -> str:
    return f'''resource "aws_s3_bucket" "logs" {{}}
resource "aws_s3_bucket" "other" {{}}
resource "aws_s3_bucket_notification" "events" {{
  bucket = aws_s3_bucket.{target}.id
}}
'''


def test_opentofu_property_registry_contract() -> None:
    definition = NATIVE_PROPERTY_REGISTRY["IACGV_OPENTOFU_REFERENCE_RESOLVES_V1"]
    assert definition.property_version == "1"
    assert definition.artifact_class is NativeArtifactClass.OPENTOFU_SOURCE
    assert definition.witness_type == "opentofu_reference_v1"
    assert "IACGV_TF_REFERENCE_RESOLVES_V2" not in NATIVE_PROPERTY_REGISTRY


def test_tofu_only_satisfied_witness(tmp_path: Path) -> None:
    (tmp_path / "main.tofu").write_text(_hcl(), encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observation = evaluate_native_request(
        universe, _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs")
    )
    assert observation.result is NativePropertyResult.SATISFIED
    contents = observation.witness.canonical_dict()["contents"]
    assert contents["source_mode"] == "opentofu"
    assert contents["fileset_contract"] == "opentofu-fileset-v1"
    assert contents["reference_span"]
    assert contents["protected_files"][0]["disposition"] == "EFFECTIVE"
    validate_native_observation(observation)


def test_same_basename_tofu_shadows_tf(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(_hcl("other"), encoding="utf-8")
    (tmp_path / "main.tofu").write_text(_hcl("logs"), encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observation = evaluate_native_request(
        universe, _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs")
    )
    assert observation.result is NativePropertyResult.SATISFIED
    files = observation.witness.canonical_dict()["contents"]["protected_files"]
    assert {item["file_path"]: item["disposition"] for item in files} == {
        "main.tf": "SHADOWED_BY_TOFU", "main.tofu": "EFFECTIVE"
    }
    assert next(item for item in files if item["file_path"] == "main.tf")["shadowed_by"] == "main.tofu"


def test_opentofu_json_and_json_precedence(tmp_path: Path) -> None:
    old = {
        "resource": {
            "aws_s3_bucket": {"logs": {}, "other": {}},
            "aws_s3_bucket_notification": {"events": {"bucket": "${aws_s3_bucket.other.id}"}},
        }
    }
    new = json.loads(json.dumps(old))
    new["resource"]["aws_s3_bucket_notification"]["events"]["bucket"] = "${aws_s3_bucket.logs.id}"
    (tmp_path / "main.tf.json").write_text(json.dumps(old), encoding="utf-8")
    (tmp_path / "main.tofu.json").write_text(json.dumps(new), encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observation = evaluate_native_request(
        universe, _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs")
    )
    assert observation.result is NativePropertyResult.SATISFIED
    assert observation.witness.canonical_dict()["contents"]["attribute_origin"]["source_format"] == "JSON"


@pytest.mark.parametrize("filename", ("main.tf.json", "main.tofu.json"))
def test_each_json_extension_is_effective_by_itself(tmp_path: Path, filename: str) -> None:
    payload = {"resource": {
        "aws_s3_bucket": {"logs": {}},
        "aws_s3_bucket_notification": {
            "events": {"bucket": "${aws_s3_bucket.logs.id}"}
        },
    }}
    (tmp_path / filename).write_text(json.dumps(payload), encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observed = evaluate_native_request(
        universe, _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs")
    )
    assert observed.result is NativePropertyResult.SATISFIED


def test_json_duplicate_depth_size_and_utf8_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "main.tofu.json"
    path.write_bytes(b'{"resource":{},"resource":{}}')
    with pytest.raises(DomainError, match="duplicate key"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    path.write_text('{"x":' * 130 + "0" + "}" * 130, encoding="utf-8")
    with pytest.raises(DomainError, match="nesting depth|invalid"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    path.write_bytes(b"\xff")
    with pytest.raises(DomainError, match="invalid"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    path.write_bytes(b" " * (OPENTOFU_MAX_FILE_BYTES + 1))
    with pytest.raises(DomainError, match="maximum file size"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("[]", "must contain an object"),
        ('{"value": NaN}', "contains NaN"),
        ('{"resource": "invalid"}', "resource structure is invalid"),
        ('{"resource": [1]}', "resource block is invalid"),
        ('{"resource": {"null_resource": []}}', "resource identity is invalid"),
        ('{"resource": {"null_resource": {"bad": []}}}', "resource body is invalid"),
        ('{"module": "invalid"}', "module structure is invalid"),
        ('{"module": [1]}', "module block is invalid"),
        ('{"module": {"child": []}}', "module identity is invalid"),
    ],
)
def test_opentofu_json_structure_boundaries_fail_closed(
    tmp_path: Path, payload: str, message: str,
) -> None:
    (tmp_path / "main.tofu.json").write_text(payload, encoding="utf-8")
    with pytest.raises(DomainError, match=message):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)


def test_empty_module_and_override_relationships_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="no eligible source files"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)

    (tmp_path / "override.tofu").write_text(
        'resource "null_resource" "missing" { value = true }\n', encoding="utf-8"
    )
    with pytest.raises(DomainError, match="no protected base resource"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)


def test_override_and_dynamic_module_issues_are_explicit(tmp_path: Path) -> None:
    (tmp_path / "main.tofu").write_text(
        'resource "null_resource" "base" { value = "old" }\n', encoding="utf-8"
    )
    (tmp_path / "override.tofu").write_text(
        'module "unsupported" { source = "./child" }\n'
        'resource "null_resource" "base" { value = { nested = true } }\n',
        encoding="utf-8",
    )
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    request = _custom_request(universe, "null_resource.base", {
        "attribute_path": ["value"],
        "expected_target": "null_resource.base",
    })
    observation = evaluate_native_request(universe, request)
    assert observation.result is NativePropertyResult.UNSUPPORTED
    reasons = {item["reason"] for item in observation.witness.contents["module_issues"]}
    assert reasons == {
        "OPENTOFU_COMPLEX_OVERRIDE_UNSUPPORTED",
        "OPENTOFU_MODULE_OVERRIDE_UNSUPPORTED",
    }

    (tmp_path / "override.tofu").unlink()
    (tmp_path / "main.tofu").write_text(
        'module "dynamic" { source = "${var.module_source}" }\n'
        'resource "null_resource" "base" {}\n',
        encoding="utf-8",
    )
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observation = evaluate_native_request(
        universe,
        _custom_request(universe, "null_resource.base", {
            "attribute_path": ["missing"],
            "expected_target": "null_resource.base",
        }),
    )
    assert observation.result is NativePropertyResult.UNSUPPORTED
    assert observation.witness.contents["module_issues"][0]["reason"] == (
        "OPENTOFU_DYNAMIC_MODULE_SOURCE_UNSUPPORTED"
    )


def test_mixed_nonconflicting_and_bounded_override(tmp_path: Path) -> None:
    (tmp_path / "targets.tf").write_text(
        'resource "aws_s3_bucket" "logs" {}\nresource "aws_s3_bucket" "other" {}\n',
        encoding="utf-8",
    )
    (tmp_path / "main.tofu").write_text(
        'resource "aws_s3_bucket_notification" "events" { bucket = aws_s3_bucket.other.id }\n',
        encoding="utf-8",
    )
    (tmp_path / "override.tofu").write_text(
        'resource "aws_s3_bucket_notification" "events" { bucket = aws_s3_bucket.logs.id }\n',
        encoding="utf-8",
    )
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observation = evaluate_native_request(
        universe, _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs")
    )
    assert observation.result is NativePropertyResult.SATISFIED
    assert observation.witness.canonical_dict()["contents"]["attribute_origin"]["file_path"] == "override.tofu"


def test_override_files_apply_in_lexical_order(tmp_path: Path) -> None:
    (tmp_path / "main.tofu").write_text(_hcl("other"), encoding="utf-8")
    (tmp_path / "a_override.tofu").write_text(
        'resource "aws_s3_bucket_notification" "events" { bucket = aws_s3_bucket.other.id }\n',
        encoding="utf-8",
    )
    (tmp_path / "z_override.tofu").write_text(
        'resource "aws_s3_bucket_notification" "events" { bucket = aws_s3_bucket.logs.id }\n',
        encoding="utf-8",
    )
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observed = evaluate_native_request(
        universe, _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs")
    )
    assert observed.result is NativePropertyResult.SATISFIED
    assert observed.witness.contents["attribute_origin"]["file_path"] == "z_override.tofu"


def test_local_child_module_reference(tmp_path: Path) -> None:
    (tmp_path / "main.tofu").write_text(
        'module "child" { source = "./child" }\nresource "null_resource" "root" {}\n',
        encoding="utf-8",
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "main.tofu").write_text(_hcl(), encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observation = evaluate_native_request(
        universe,
        _request(
            universe,
            "module.child::aws_s3_bucket_notification.events",
            "module.child::aws_s3_bucket.logs",
        ),
    )
    assert observation.result is NativePropertyResult.SATISFIED
    assert observation.witness.canonical_dict()["contents"]["source"]["module_identity"] == "module.child"


@pytest.mark.parametrize(
    ("module_source", "expected"),
    [
        ("./missing", NativePropertyResult.NOT_EVALUATED),
        ("registry.example/module/name", NativePropertyResult.UNSUPPORTED),
    ],
)
def test_module_boundaries_fail_closed(tmp_path: Path, module_source: str, expected) -> None:
    (tmp_path / "main.tofu").write_text(
        f'module "child" {{ source = "{module_source}" }}\n' + _hcl(), encoding="utf-8"
    )
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observation = evaluate_native_request(
        universe, _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs")
    )
    assert observation.result is expected
    assert observation.reason_code == "OPENTOFU_PROTECTED_SOURCE_CLOSURE_INCOMPLETE"


def test_malformed_winner_never_falls_back(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(_hcl(), encoding="utf-8")
    (tmp_path / "main.tofu").write_text('resource "broken"', encoding="utf-8")
    with pytest.raises(DomainError, match="protected OpenTofu source main.tofu is invalid"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)


def test_duplicate_effective_identity_fails(tmp_path: Path) -> None:
    (tmp_path / "one.tf").write_text('resource "null_resource" "same" {}\n', encoding="utf-8")
    (tmp_path / "two.tofu").write_text('resource "null_resource" "same" {}\n', encoding="utf-8")
    with pytest.raises(DomainError, match="duplicate effective OpenTofu resource identity"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)


def test_path_escape_and_symlink_fail_closed(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "main.tofu").write_text(_hcl(), encoding="utf-8")
    (tmp_path / "main.tofu").write_text(
        f'module "escape" {{ source = "../{outside.name}" }}\n' + _hcl(), encoding="utf-8"
    )
    with pytest.raises(DomainError, match="escapes"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    (tmp_path / "main.tofu").write_text(_hcl(), encoding="utf-8")
    os.symlink(outside / "main.tofu", tmp_path / "linked.tofu")
    with pytest.raises(DomainError, match="regular non-symlink"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)


def test_local_module_directory_symlink_fails_closed(tmp_path: Path) -> None:
    real = tmp_path / "real-child"
    real.mkdir()
    (real / "main.tofu").write_text(_hcl(), encoding="utf-8")
    os.symlink(real, tmp_path / "linked-child")
    (tmp_path / "main.tofu").write_text(
        'module "child" { source = "./linked-child" }\n'
        'resource "null_resource" "root" {}\n',
        encoding="utf-8",
    )
    with pytest.raises(DomainError, match="module symlink"):
        load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)


def test_effective_and_shadowed_mutations_change_identity(tmp_path: Path) -> None:
    tf = tmp_path / "main.tf"
    tofu = tmp_path / "main.tofu"
    tf.write_text(_hcl("other"), encoding="utf-8")
    tofu.write_text(_hcl(), encoding="utf-8")
    first = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    tf.write_text(_hcl("logs") + "# shadow mutation\n", encoding="utf-8")
    second = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    assert first.identity != second.identity
    tofu.write_text(_hcl("other"), encoding="utf-8")
    third = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    assert second.identity != third.identity
    violated = evaluate_native_request(
        third, _request(third, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs")
    )
    assert violated.result is NativePropertyResult.VIOLATED


def test_opentofu_reference_parameter_contract_and_unsupported_mode(tmp_path: Path) -> None:
    (tmp_path / "main.tofu").write_text(_hcl(), encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    source = "aws_s3_bucket_notification.events"
    with pytest.raises(
        DomainError,
        match=r"packaged schema: \[\] should be non-empty",
    ):
        evaluate_native_request(universe, _custom_request(universe, source, {
            "attribute_path": [], "expected_target": "aws_s3_bucket.logs",
        }))
    with pytest.raises(
        DomainError,
        match="packaged schema: 1 is not of type 'string'",
    ):
        evaluate_native_request(universe, _custom_request(universe, source, {
            "attribute_path": ["bucket"], "expected_target": 1,
        }))
    unsupported = evaluate_native_request(universe, _custom_request(universe, source, {
        "attribute_path": ["bucket"], "expected_target": "aws_s3_bucket.logs",
        "mode": "TRANSITIVE",
    }))
    assert unsupported.result is NativePropertyResult.UNSUPPORTED
    assert unsupported.reason_code == "OPENTOFU_TRANSITIVE_REFERENCE_UNSUPPORTED"
    with pytest.raises(
        DomainError,
        match="packaged schema: 'true' is not of type 'boolean'",
    ):
        evaluate_native_request(universe, _custom_request(universe, source, {
            "attribute_path": ["bucket"], "expected_target": "aws_s3_bucket.logs",
            "complete_expected_domain": "true",
        }))
    with pytest.raises(
        DomainError,
        match="packaged schema: 'reference_contract_digest' is a required property",
    ):
        evaluate_native_request(universe, _custom_request(universe, source, {
            "attribute_path": ["bucket"], "expected_target": "aws_s3_bucket.logs",
            "complete_expected_domain": True,
        }))


def test_opentofu_reference_uncertainty_and_complete_domain_results(tmp_path: Path) -> None:
    (tmp_path / "main.tofu").write_text(
        'resource "aws_s3_bucket" "logs" {}\n'
        'resource "aws_s3_bucket_notification" "counted" { count = 1 bucket = aws_s3_bucket.logs.id }\n'
        'resource "aws_s3_bucket_notification" "absent" {}\n'
        'resource "aws_s3_bucket_notification" "dynamic" { bucket = var.bucket }\n'
        'resource "aws_s3_bucket_notification" "other" { bucket = aws_s3_bucket.logs.id }\n',
        encoding="utf-8",
    )
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    target = "aws_s3_bucket.logs"

    counted = evaluate_native_request(universe, _request(
        universe, "aws_s3_bucket_notification.counted", target,
    ))
    assert counted.result is NativePropertyResult.NOT_EVALUATED
    assert counted.reason_code == "OPENTOFU_INSTANCE_IDENTITY_UNRESOLVED"

    missing_target = evaluate_native_request(universe, _request(
        universe, "aws_s3_bucket_notification.other", "aws_s3_bucket.missing",
    ))
    assert missing_target.result is NativePropertyResult.NOT_EVALUATED
    assert missing_target.reason_code == "OPENTOFU_EXPECTED_TARGET_NOT_UNIQUELY_PROTECTED"

    complete_absent = evaluate_native_request(universe, _request(
        universe, "aws_s3_bucket_notification.absent", target,
    ))
    assert complete_absent.result is NativePropertyResult.VIOLATED
    assert complete_absent.reason_code == "OPENTOFU_REFERENCE_ATTRIBUTE_ABSENT_IN_COMPLETE_DOMAIN"
    incomplete_absent = evaluate_native_request(universe, _request(
        universe, "aws_s3_bucket_notification.absent", target, complete=False,
    ))
    assert incomplete_absent.result is NativePropertyResult.NOT_EVALUATED
    assert incomplete_absent.reason_code == "OPENTOFU_REFERENCE_ATTRIBUTE_ABSENT"

    expression = evaluate_native_request(universe, _request(
        universe, "aws_s3_bucket_notification.dynamic", target,
    ))
    assert expression.result is NativePropertyResult.NOT_EVALUATED
    assert expression.reason_code == "OPENTOFU_REFERENCE_EXPRESSION_UNSUPPORTED"


def test_opentofu_reference_complete_and_incomplete_nonmatching_results(tmp_path: Path) -> None:
    (tmp_path / "main.tofu").write_text(_hcl("other"), encoding="utf-8")
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    source = "aws_s3_bucket_notification.events"
    target = "aws_s3_bucket.logs"
    complete = evaluate_native_request(universe, _request(universe, source, target))
    assert complete.result is NativePropertyResult.VIOLATED
    assert complete.reason_code == "OPENTOFU_EXPECTED_REFERENCE_ABSENT_IN_COMPLETE_DOMAIN"
    incomplete = evaluate_native_request(
        universe, _request(universe, source, target, complete=False)
    )
    assert incomplete.result is NativePropertyResult.NOT_EVALUATED
    assert incomplete.reason_code == (
        "OPENTOFU_EXPECTED_REFERENCE_NOT_OBSERVED_IN_INCOMPLETE_DOMAIN"
    )


def test_opentofu_reference_requires_unambiguous_source_span(tmp_path: Path) -> None:
    (tmp_path / "main.tofu").write_text(
        'resource "aws_s3_bucket" "logs" {}\n'
        'resource "aws_s3_bucket_notification" "events" {\n'
        '  bucket = "${aws_s3_bucket.logs.id}-${aws_s3_bucket.logs.id}"\n'
        '}\n',
        encoding="utf-8",
    )
    universe = load_protected_native_universe(tmp_path, NativeArtifactClass.OPENTOFU_SOURCE)
    observation = evaluate_native_request(
        universe,
        _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs"),
    )
    assert observation.result is NativePropertyResult.NOT_EVALUATED
    assert observation.reason_code == "OPENTOFU_REFERENCE_SOURCE_SPAN_AMBIGUOUS"


def test_opentofu_direct_and_v1alpha1_contract_results_are_identical(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source = project / "module"
    contract_dir = project / ".iac-guard-v"
    source.mkdir(parents=True)
    contract_dir.mkdir()
    (source / "main.tofu").write_text(_hcl(), encoding="utf-8")
    contract = contract_dir / "contracts.yaml"
    contract.write_text(
        """apiVersion: iac-guard-v.io/v1alpha1
kind: InfrastructureContract
metadata: {name: opentofu-reference}
spec:
  artifactClass: opentofu_source
  subjects:
    include: {identities: [aws_s3_bucket_notification.events]}
    cardinality: {min: 1, max: 1}
  responsibility: {class: PROJECT_MANAGED, reason: exact local reference}
  expect:
    - id: bucket-reference
      property:
        namespace: iac_guard_v
        id: IACGV_OPENTOFU_REFERENCE_RESOLVES_V1
        version: "1"
      parameters:
        attribute_path: [bucket]
        expected_target: aws_s3_bucket.logs
        mode: DIRECT
        complete_expected_domain: true
        reference_contract_digest: "1111111111111111111111111111111111111111111111111111111111111111"
""",
        encoding="utf-8",
    )
    universe = load_protected_native_universe(source, NativeArtifactClass.OPENTOFU_SOURCE)
    direct = evaluate_native_request(
        universe,
        _request(universe, "aws_s3_bucket_notification.events", "aws_s3_bucket.logs"),
    )
    execution = ContractExecutionInput(
        contract, project, protected_root=source,
        requested_provenance=ContractProvenance.SUGGESTED_CONTRACT,
    )
    with prepare_contract_run(execution) as run:
        assert run.report.result.value == direct.result.value == "SATISFIED"
        compiled = run.report.clauses[0].native_observations[0]
        assert compiled.witness.canonical_dict() == direct.witness.canonical_dict()
        assert run.report.contract.source.provenance is ContractProvenance.SUGGESTED_CONTRACT

    (source / "main.tofu").write_text(_hcl("other"), encoding="utf-8")
    with prepare_contract_run(execution) as run:
        assert run.report.result.value == "VIOLATED"
