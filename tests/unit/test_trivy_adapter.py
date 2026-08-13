"""E2 externally locked Trivy adapter contract and mutation probes."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

import iac_guard_v.adapters.trivy as trivy_module
from iac_guard_v.adapters.base import AdapterReason
from iac_guard_v.adapters.phase_e_lock import (
    LockedContainerIdentity,
    _create_test_protected_checks_cache_identity,
    load_locked_container_identity,
    load_protected_checks_cache_identity,
)
from iac_guard_v.adapters.trivy import TRIVY_CONTRACT, TrivyAdapter, create_trivy_scan_request
from iac_guard_v.enums import ArtifactKind, Status
from iac_guard_v.models import BoundInputFile, DomainError, ExpectedResource
from iac_guard_v.process import CommandResult, ProcessReason


LOCK = Path(__file__).parents[2] / "tools/locks/phase-e-locks.json"


def _process(
    *, status: Status = Status.PASS, reason: ProcessReason = ProcessReason.COMPLETED_WITHIN_CONTRACT,
    timed_out: bool = False, external_bundle_observed: bool = True,
    argv: tuple[str, ...] = ("docker",),
) -> CommandResult:
    return CommandResult(
        argv=argv, status=status, exit_code=0 if status is Status.PASS else None,
        stdout=b"", stderr=(
            b"loading from existing cache" if external_bundle_observed else b"no bundle evidence"
        ), duration_ms=2,
        truncated=False, timed_out=timed_out, killed_signal=None,
        reason_code=reason,
        resolved_executable="/usr/local/bin/docker" if status is Status.PASS else "",
        primary_execution_event=reason,
    )


def _misconfiguration(**overrides) -> dict:
    value = {
        "Type": "Terraform Security Check",
        "ID": "AWS-0089",
        "Title": "S3 Bucket Logging",
        "Description": "Logging required",
        "Message": "Bucket has logging disabled",
        "Namespace": "builtin.aws.s3.aws0089",
        "Query": "data.builtin.aws.s3.aws0089.deny",
        "Resolution": "Enable logging",
        "Severity": "LOW",
        "PrimaryURL": "https://example.invalid/aws-0089",
        "References": [],
        "Status": "FAIL",
        "CauseMetadata": {
            "Resource": "aws_s3_bucket.demo",
            "Provider": "AWS", "Service": "s3", "StartLine": 1, "EndLine": 1,
        },
    }
    value.update(overrides)
    return value


def _document(*, items: list | None = None, successes: int = 0, include_key: bool = True, **overrides) -> dict:
    items = [] if items is None else items
    successes += sum(type(item) is dict and item.get("Status") == "PASS" for item in items)
    failures = sum(type(item) is dict and item.get("Status") == "FAIL" for item in items)
    result = {
        "Target": "main.tf", "Class": "config", "Type": "terraform",
        "MisconfSummary": {"Successes": successes, "Failures": failures},
    }
    if include_key:
        result["Misconfigurations"] = items
    value = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.73.0"},
        "ReportID": "00000000-0000-0000-0000-000000000000",
        "CreatedAt": "1970-01-01T00:00:00Z",
        "ArtifactName": ".", "ArtifactType": "filesystem",
        "Results": [result],
    }
    value.update(overrides)
    return value


def _request(tmp_path: Path, *, expected: bool = True, **overrides):
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    source = root / "main.tf"
    source.write_text('resource "aws_s3_bucket" "demo" {}\n', encoding="utf-8")
    metadata = source.stat()
    evidence = BoundInputFile(
        "main.tf", "regular_file", metadata.st_size,
        hashlib.sha256(source.read_bytes()).hexdigest(), metadata.st_dev, metadata.st_ino,
    )
    identity = load_locked_container_identity(LOCK, "trivy", "linux/arm64")
    protected = tmp_path / "protected"
    cache = protected / "runtime-v2/trivy-cache"
    (cache / "policy/content/policies").mkdir(parents=True)
    (cache / "policy/metadata.json").write_text(
        json.dumps({"Digest": identity.checks_manifest_digest, "MajorVersion": 2}),
        encoding="utf-8",
    )
    (cache / "policy/content/policies/rule.rego").write_text("package builtin\n", encoding="utf-8")
    values = {
        "workspace_root": root, "scan_root": root,
        "files_eligible": ("main.tf",), "eligible_file_evidence": (evidence,),
        "expected_resources": (ExpectedResource(
            "main.tf", "aws_s3_bucket.demo", ArtifactKind.TERRAFORM_HCL,
            "aws_s3_bucket.demo",
        ),) if expected else (),
        "docker_executable": Path(shutil.which("docker") or "/usr/bin/true"),
        "protected_checks_cache": _create_test_protected_checks_cache_identity(
            cache, identity
        ),
        "locked_identity": identity,
    }
    values.update(overrides)
    return create_trivy_scan_request(**values)


def _normalize(tmp_path: Path, document: dict, **kwargs):
    request = _request(tmp_path, **kwargs)
    return trivy_module._normalize_for_test(
        json.dumps(document).encode(), request, _process()
    )


def test_contract_is_exact_e03_selection() -> None:
    assert TRIVY_CONTRACT.supported_versions == ("0.73.0",)
    assert TRIVY_CONTRACT.expected_exit_codes == (0,)


def test_finding_result_retains_external_identity(tmp_path: Path) -> None:
    evidence = _normalize(tmp_path, _document(items=[_misconfiguration()]))
    run = evidence.scanner_run
    assert run.status is Status.PASS
    assert run.findings[0].rule_id == "AWS-0089"
    assert evidence.source == "external"
    assert evidence.fallback_used is False
    assert evidence.network_disabled and evidence.updates_disabled
    assert evidence.checks_manifest_digest.startswith("sha256:")
    assert evidence.binary_image_identity != evidence.checks_manifest_digest
    assert run.stderr_sha256 == hashlib.sha256(b"loading from existing cache").hexdigest()
    assert evidence.canonical_output_sha256 == run.raw_output_sha256
    assert evidence.protected_cache_manifest_root == "0" * 64
    assert evidence.trivy_cache_subtree_root == evidence.checks_cache_content_sha256


def test_valid_empty_result_passes_without_inventing_evaluations(tmp_path: Path) -> None:
    passed = _misconfiguration(Status="PASS")
    evidence = _normalize(tmp_path, _document(items=[passed]))
    assert evidence.scanner_run.status is Status.PASS
    assert evidence.scanner_run.findings == ()
    assert evidence.scanner_run.evaluations[0].native_result.value == "PASSED"
    assert evidence.scanner_run.coverage.evaluations_reported == 1


def test_exception_is_visible_suppressed_evidence(tmp_path: Path) -> None:
    evidence = _normalize(
        tmp_path, _document(items=[_misconfiguration(Status="EXCEPTION")])
    )
    run = evidence.scanner_run
    assert run.status is Status.PASS
    assert run.findings == ()
    assert run.evaluations[0].native_result.value == "SKIPPED"
    assert run.evaluations[0].source_bucket == "Misconfigurations/EXCEPTION"


@pytest.mark.parametrize("field", ("Title", "Severity", "CauseMetadata"))
def test_documented_omitted_fields_are_conservative(tmp_path: Path, field: str) -> None:
    item = _misconfiguration()
    item.pop(field)
    evidence = _normalize(tmp_path, _document(items=[item]))
    run = evidence.scanner_run
    assert run.status is (Status.PASS if field == "Title" else Status.PARTIAL)
    assert len(run.evaluations) == 1
    if field == "Severity":
        assert run.findings[0].severity.value == "UNKNOWN"
    if field == "CauseMetadata":
        assert AdapterReason.MISSING_RESOURCE_IDENTITY.value in run.diagnostics


def test_experimental_modified_findings_are_preserved_as_typed_detail(
    tmp_path: Path,
) -> None:
    document = _document(items=[_misconfiguration()])
    document["Results"][0]["ExperimentalModifiedFindings"] = [
        {"Type": "misconfiguration", "Status": "EXCEPTION", "ID": "AWS-0089"}
    ]
    evidence = _normalize(tmp_path, document)
    assert evidence.scanner_run.status is Status.PARTIAL
    assert any(
        item.startswith("experimental_modified_findings:1:")
        for item in evidence.scanner_run.diagnostics
    )
    assert AdapterReason.EXPERIMENTAL_MODIFIED_FINDINGS.value in (
        evidence.scanner_run.diagnostics
    )


@pytest.mark.parametrize("value", ({"not": "a list"}, ["not an object"]))
def test_experimental_modified_findings_shape_is_closed(
    tmp_path: Path, value: object,
) -> None:
    document = _document(items=[_misconfiguration()])
    document["Results"][0]["ExperimentalModifiedFindings"] = value
    evidence = _normalize(tmp_path, document)
    assert evidence.scanner_run.status is Status.ERROR
    assert AdapterReason.INVALID_RESULTS_STRUCTURE.value in evidence.scanner_run.diagnostics


def test_external_bundle_absence_and_change_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (request.protected_checks_cache.cache_root / "policy/metadata.json").unlink()
    with pytest.raises(DomainError, match=AdapterReason.EXTERNAL_CHECKS_MISSING.value):
        TrivyAdapter()._revalidate(request)
    other = _request(tmp_path / "other")
    (other.protected_checks_cache.cache_root / "policy/metadata.json").write_text(
        json.dumps({"Digest": "sha256:" + "0" * 64}), encoding="utf-8"
    )
    with pytest.raises(DomainError, match=AdapterReason.EXTERNAL_CHECKS_CHANGED.value):
        TrivyAdapter()._revalidate(other)


def test_embedded_fallback_is_distinct_nonpass_evidence(tmp_path: Path) -> None:
    request = _request(tmp_path)
    evidence = trivy_module._normalize_for_test(
        json.dumps(_document()).encode(), request,
        _process(external_bundle_observed=False),
    )
    assert evidence.scanner_run.status is Status.INCONCLUSIVE
    assert evidence.fallback_used is True
    assert evidence.source == "embedded_fallback"
    assert AdapterReason.EMBEDDED_CHECKS_FALLBACK.value in evidence.scanner_run.diagnostics


def test_missing_misconfigurations_with_failures_is_error(tmp_path: Path) -> None:
    document = _document(include_key=False)
    document["Results"][0]["MisconfSummary"]["Failures"] = 1
    evidence = _normalize(tmp_path, document)
    assert evidence.scanner_run.status is Status.ERROR
    assert AdapterReason.MISSING_MISCONFIGURATIONS.value in evidence.scanner_run.diagnostics


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"not json", AdapterReason.MALFORMED_JSON.value),
        (b"[]", AdapterReason.UNEXPECTED_TOP_LEVEL.value),
        (b'{"SchemaVersion":2,"Results":[],"Results":[]}', AdapterReason.DUPLICATE_JSON_KEY.value),
        (b"", AdapterReason.EMPTY_OUTPUT.value),
    ],
)
def test_malformed_and_duplicate_json_fail_closed(tmp_path: Path, raw: bytes, reason: str) -> None:
    request = _request(tmp_path)
    evidence = trivy_module._normalize_for_test(
        raw, request, _process(),
    )
    assert evidence.scanner_run.status is Status.ERROR
    assert reason in evidence.scanner_run.diagnostics


def test_unknown_result_category_is_partial(tmp_path: Path) -> None:
    document = _document(items=[_misconfiguration()])
    document["Results"][0]["Class"] = "secret"
    evidence = _normalize(tmp_path, document)
    assert evidence.scanner_run.status is Status.PARTIAL
    assert AdapterReason.UNKNOWN_NATIVE_CATEGORY.value in evidence.scanner_run.diagnostics


def test_incomplete_file_and_resource_coverage_is_partial(tmp_path: Path) -> None:
    document = _document(items=[_misconfiguration()])
    document["Results"][0]["Target"] = "."
    evidence = _normalize(tmp_path, document)
    assert evidence.scanner_run.status is Status.PARTIAL
    assert AdapterReason.MISSING_RESOURCE_IDENTITY.value in evidence.scanner_run.diagnostics
    resource = _document(items=[_misconfiguration(
        CauseMetadata={"Resource": "aws_s3_bucket.other", "StartLine": 1, "EndLine": 1}
    )])
    evidence = _normalize(tmp_path / "resource", resource)
    assert evidence.scanner_run.status is Status.PARTIAL
    assert evidence.scanner_run.resource_coverage.expected_resources_missing == 1


def test_binary_and_checks_drift_are_distinguishable(tmp_path: Path) -> None:
    request = _request(tmp_path)
    canonical = request.locked_identity.canonical_dict()
    canonical["image_architecture_digest"] = "sha256:" + "1" * 64
    canonical["execution_reference"] = "docker.io/aquasec/trivy@" + canonical["image_architecture_digest"]
    binary = LockedContainerIdentity(**canonical)
    with pytest.raises(DomainError, match="reviewed Phase-E lock"):
        _request(tmp_path / "binary", locked_identity=binary)
    (request.protected_checks_cache.cache_root / "policy/content/policies/rule.rego").write_text("changed\n")
    with pytest.raises(DomainError, match=AdapterReason.CACHE_CHANGED_DURING_EXECUTION.value):
        TrivyAdapter()._revalidate(request)


def test_canonical_output_is_order_independent(tmp_path: Path) -> None:
    first = _misconfiguration(ID="AWS-0001", Title="One")
    second = _misconfiguration(ID="AWS-0002", Title="Two")
    a = _normalize(tmp_path / "a", _document(items=[first, second]))
    b = _normalize(tmp_path / "b", _document(items=[second, first]))
    assert a.scanner_run.canonical_dict() == b.scanner_run.canonical_dict()


def test_volatile_report_metadata_does_not_change_semantic_hash(tmp_path: Path) -> None:
    first = _document(items=[_misconfiguration()])
    second = _document(items=[_misconfiguration()])
    second["ReportID"] = "11111111-1111-1111-1111-111111111111"
    second["CreatedAt"] = "2026-08-12T12:34:56Z"
    a = _normalize(tmp_path / "a", first)
    b = _normalize(tmp_path / "b", second)
    assert a.canonical_output_sha256 == b.canonical_output_sha256
    assert a.scanner_run.raw_output_sha256 == b.scanner_run.raw_output_sha256
    assert a.native_output_bytes_sha256 != b.native_output_bytes_sha256


def test_pass_and_fail_for_one_evaluation_identity_fail_closed(tmp_path: Path) -> None:
    failed = _misconfiguration(Status="FAIL")
    passed = _misconfiguration(Status="PASS")
    evidence = _normalize(tmp_path, _document(items=[failed, passed]))
    assert evidence.scanner_run.status is Status.ERROR
    assert evidence.scanner_run.ruleset_integrity is Status.FAIL
    assert (
        AdapterReason.CONTRADICTORY_EVALUATION_EVIDENCE.value
        in evidence.scanner_run.diagnostics
    )


def test_arbitrary_cache_cannot_be_stamped_protected(tmp_path: Path) -> None:
    arbitrary = tmp_path / "arbitrary"
    arbitrary.mkdir()
    (arbitrary / "rule.rego").write_text("package attacker\n", encoding="utf-8")
    with pytest.raises(DomainError, match="physical inventory"):
        load_protected_checks_cache_identity(LOCK, arbitrary)


def test_timeout_is_typed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    evidence = trivy_module._normalize_for_test(
        b"{}", request,
        _process(status=Status.TIMEOUT, reason=ProcessReason.DEADLINE_EXCEEDED, timed_out=True),
    )
    assert evidence.scanner_run.status is Status.TIMEOUT
    assert AdapterReason.DEADLINE_EXCEEDED.value in evidence.scanner_run.diagnostics


def test_execution_evidence_is_immutable_and_trusted(tmp_path: Path) -> None:
    evidence = _normalize(tmp_path, _document(items=[_misconfiguration()]))
    assert evidence._trusted_evidence
    with pytest.raises(DomainError, match="adapter-owned"):
        trivy_module.TrivyExecutionEvidence(
            scanner_run=object(), binary_image_identity="sha256:" + "0" * 64,
            image_index_digest="sha256:" + "0" * 64,
            checks_manifest_digest="sha256:" + "0" * 64,
            checks_layer_digest="sha256:" + "0" * 64,
            checks_cache_identity="cache", checks_cache_content_sha256="0" * 64,
            protected_cache_manifest_root="0" * 64,
            trivy_cache_subtree_root="0" * 64,
            cache_metadata_digest="0" * 64,
            cache_attestation_identity="test",
            cache_attestation_record_sha256="0" * 64,
            cache_attestation_signature_sha256="0" * 64,
            pre_run_cache_root="0" * 64, post_run_cache_root="0" * 64,
            invocation_identity="0" * 64, source="external", fallback_used=False,
            network_disabled=True, updates_disabled=True, canonical_output_sha256="0" * 64,
            native_output_bytes_sha256="0" * 64,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"files_eligible": ["main.tf"]},
        {"eligible_file_evidence": []},
        {"files_eligible": ("main.tf", "main.tf")},
        {"files_eligible": ("z.tf", "a.tf")},
        {"eligible_file_evidence": ("not evidence",)},
        {"expected_resources": []},
        {"expected_resources": ("not resource",)},
        {"timeout_seconds": 0},
        {"max_output_bytes": 0},
        {"max_file_bytes": 0},
        {"max_total_eligible_bytes": 1},
    ],
)
def test_request_contract_mutations_are_rejected(tmp_path: Path, overrides: dict) -> None:
    with pytest.raises(DomainError):
        _request(tmp_path, **overrides)


def test_direct_request_and_untrusted_adapter_inputs_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    values = {
        name: getattr(request, name)
        for name in (
            "workspace_root", "scan_root", "files_eligible", "eligible_file_evidence",
            "expected_resources", "docker_executable", "protected_checks_cache",
            "locked_identity",
        )
    }
    with pytest.raises(DomainError, match="sealed request factory"):
        trivy_module.TrivyScanRequest(**values)
    with pytest.raises(DomainError, match="actual adapter execution"):
        TrivyAdapter().normalize(b"{}", object(), _process())
    with pytest.raises(DomainError, match="actual adapter execution"):
        TrivyAdapter().normalize(b"{}", request, object())
    with pytest.raises(DomainError, match="sealed request"):
        TrivyAdapter().scan(object())
    assert TrivyAdapter().contract() is TRIVY_CONTRACT


def test_private_execution_capability_and_argv_are_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    process = _process()
    with pytest.raises(DomainError, match="capability"):
        TrivyAdapter._normalize_execution(b"{}", request, process, process.argv, object())
    with pytest.raises(DomainError, match="sealed request"):
        TrivyAdapter._normalize_execution(
            b"{}", object(), process, process.argv, trivy_module._PRIVATE_TEST_CONTEXT
        )
    with pytest.raises(DomainError, match="CommandResult"):
        TrivyAdapter._normalize_execution(
            b"{}", request, object(), process.argv, trivy_module._PRIVATE_TEST_CONTEXT
        )
    with pytest.raises(DomainError, match="locked invocation"):
        TrivyAdapter._normalize_execution(
            b"{}", request, process, ("other",), trivy_module._PRIVATE_TEST_CONTEXT
        )


def test_request_path_and_launcher_boundaries(tmp_path: Path) -> None:
    request = _request(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(DomainError, match="inside workspace"):
        create_trivy_scan_request(
            workspace_root=request.workspace_root, scan_root=outside,
            files_eligible=request.files_eligible,
            eligible_file_evidence=request.eligible_file_evidence,
            expected_resources=request.expected_resources,
            docker_executable=request.docker_executable,
            protected_checks_cache=request.protected_checks_cache,
            locked_identity=request.locked_identity,
        )
    with pytest.raises(DomainError, match="cannot be resolved"):
        _request(tmp_path / "missing", scan_root=tmp_path / "does-not-exist")
    launcher = tmp_path / "launcher"
    launcher.write_text("x", encoding="utf-8")
    with pytest.raises(DomainError, match="must be executable"):
        _request(tmp_path / "launcher-case", docker_executable=launcher)


def test_cache_rejects_symlink_and_special_entries(tmp_path: Path) -> None:
    request = _request(tmp_path)
    target = request.protected_checks_cache.cache_root / "policy/content/policies/rule.rego"
    target.unlink()
    target.symlink_to(request.scan_root / "main.tf")
    with pytest.raises(DomainError, match=AdapterReason.CACHE_CHANGED_DURING_EXECUTION.value):
        TrivyAdapter()._revalidate(request)
    other = _request(tmp_path / "fifo")
    special = other.protected_checks_cache.cache_root / "policy/content/policies/pipe"
    os.mkfifo(special)
    with pytest.raises(DomainError, match=AdapterReason.EXTERNAL_CHECKS_CHANGED.value):
        trivy_module._cache_manifest(other.protected_checks_cache.cache_root)
    link = tmp_path / "cache-link"
    link.symlink_to(other.protected_checks_cache.cache_root, target_is_directory=True)
    with pytest.raises(DomainError, match=AdapterReason.EXTERNAL_CHECKS_MISSING.value):
        trivy_module._cache_manifest(link)


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (lambda d: d.pop("Results"), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d.update(SchemaVersion=1), AdapterReason.UNSUPPORTED_VERSION.value),
        (lambda d: d.update(Trivy={"Version": "9.9.9"}), AdapterReason.VERSION_MISMATCH.value),
        (lambda d: d.update(Results={}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["Results"].append({}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["Results"][0].update(MisconfSummary=[]), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["Results"][0].update(MisconfSummary={"Successes": -1, "Failures": 0}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["Results"][0].update(Misconfigurations={}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["Results"][0]["Misconfigurations"].append({}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["Results"][0].update(MisconfSummary={"Successes": 0, "Failures": 2}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["Results"][0]["Misconfigurations"][0].update(CauseMetadata=[]), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
        (lambda d: d["Results"][0]["Misconfigurations"][0].update(CauseMetadata={"Resource": "x", "StartLine": 0, "EndLine": 1}), AdapterReason.INVALID_RESULTS_STRUCTURE.value),
    ],
)
def test_result_structure_mutations_fail_closed(tmp_path: Path, mutator, reason: str) -> None:
    document = _document(items=[_misconfiguration()])
    mutator(document)
    evidence = _normalize(tmp_path, document)
    assert evidence.scanner_run.status is Status.ERROR
    assert reason in evidence.scanner_run.diagnostics


def test_unknown_fields_status_severity_and_artifact_are_partial(tmp_path: Path) -> None:
    document = _document(items=[_misconfiguration(Status="PASS", extension="x")], extension="x")
    document["Results"][0]["extension"] = "x"
    evidence = _normalize(tmp_path, document)
    assert evidence.scanner_run.status is Status.PARTIAL
    assert AdapterReason.UNKNOWN_NATIVE_CATEGORY.value in evidence.scanner_run.diagnostics
    unknown = _document(items=[_misconfiguration(Severity="NOVEL")])
    unknown["Results"][0]["Type"] = "novel"
    evidence = _normalize(tmp_path / "unknown", unknown)
    assert evidence.scanner_run.status is Status.PARTIAL
    assert evidence.scanner_run.findings[0].severity.value == "UNKNOWN"
    novel_status = _document(items=[_misconfiguration(Status="NOVEL")])
    evidence = _normalize(tmp_path / "novel-status", novel_status)
    assert evidence.scanner_run.status is Status.PARTIAL


def test_native_path_severity_artifact_and_cause_helpers_are_closed() -> None:
    with pytest.raises(DomainError, match=AdapterReason.INVALID_RESULTS_STRUCTURE.value):
        trivy_module._native_path(None, ("main.tf",))
    with pytest.raises(DomainError, match=AdapterReason.COVERAGE_MISMATCH.value):
        trivy_module._native_path("other.tf", ("main.tf",))
    assert trivy_module._severity(None).value == "UNKNOWN"
    assert trivy_module._artifact(None, "x") is ArtifactKind.UNKNOWN
    assert trivy_module._artifact("kubernetes", "pod.json") is ArtifactKind.KUBERNETES_JSON
    assert trivy_module._artifact("yaml", "pod.yaml") is ArtifactKind.KUBERNETES_YAML
    assert trivy_module._cause(
        {"CauseMetadata": {"StartLine": 1, "EndLine": 1}}, "main.tf"
    )[0] == "trivy-file-main.tf"


def test_empty_per_file_and_global_failure_are_typed(tmp_path: Path) -> None:
    empty = _normalize(tmp_path, _document(include_key=False), expected=False)
    assert empty.scanner_run.status is Status.PASS
    global_failure = _document(items=[_misconfiguration()])
    global_failure["Results"][0]["Target"] = "."
    evidence = _normalize(tmp_path / "global", global_failure)
    assert evidence.scanner_run.status is Status.PARTIAL
    assert AdapterReason.MISSING_RESOURCE_IDENTITY.value in evidence.scanner_run.diagnostics


@pytest.mark.parametrize(
    ("status", "reason", "truncated", "signal", "expected"),
    [
        (Status.PARTIAL, ProcessReason.OUTPUT_LIMIT_EXCEEDED, True, None, AdapterReason.TRUNCATED_OUTPUT.value),
        (Status.ERROR, ProcessReason.KILLED_BY_SIGNAL, False, 9, AdapterReason.KILLED_PROCESS.value),
        (Status.ERROR, ProcessReason.EXIT_CODE_OUTSIDE_CONTRACT, False, None, AdapterReason.EXIT_CODE_OUTSIDE_CONTRACT.value),
        (Status.ERROR, ProcessReason.SPAWN_FAILED, False, None, AdapterReason.PROCESS_ERROR.value),
    ],
)
def test_process_failures_never_parse(
    tmp_path: Path, status: Status, reason: ProcessReason, truncated: bool,
    signal: int | None, expected: str,
) -> None:
    process = CommandResult(
        argv=("docker",), status=status, exit_code=-signal if signal else None,
        stdout=b"", stderr=b"", duration_ms=1, truncated=truncated,
        timed_out=False, killed_signal=signal, reason_code=reason,
        resolved_executable="", primary_execution_event=reason,
    )
    request = _request(tmp_path)
    evidence = trivy_module._normalize_for_test(
        b"{}", request, process,
    )
    assert evidence.scanner_run.status is not Status.PASS
    assert expected in evidence.scanner_run.diagnostics


def test_empty_scope_is_skipped_without_spawn(tmp_path: Path) -> None:
    request = _request(
        tmp_path, files_eligible=(), eligible_file_evidence=(), expected_resources=(),
    )
    evidence = TrivyAdapter().scan(request)
    assert evidence.scanner_run.status is Status.SKIPPED
    assert AdapterReason.EMPTY_ELIGIBLE_SCOPE.value in evidence.scanner_run.diagnostics


def _mock_container_run(monkeypatch, document: dict, *, mutate_cache: Path | None = None) -> None:
    def execute(command):
        assert ("--network", "none") == command.argv[command.argv.index("--network"):command.argv.index("--network") + 2]
        assert "--skip-check-update" in command.argv
        assert "--include-non-failures" in command.argv
        assert "--pull" in command.argv and command.argv[command.argv.index("--pull") + 1] == "never"
        output_mount = next(item for item in command.argv if item.endswith(":/out:rw"))
        output = Path(output_mount.removesuffix(":/out:rw"))
        (output / "results.json").write_text(json.dumps(document), encoding="utf-8")
        if mutate_cache is not None:
            (mutate_cache / "policy/content/policies/rule.rego").write_text("mutated\n")
        return _process(argv=command.argv)
    monkeypatch.setattr(trivy_module, "run_command", execute)


def test_scan_builds_private_view_and_revalidates_cache(tmp_path: Path, monkeypatch) -> None:
    request = _request(tmp_path)
    _mock_container_run(monkeypatch, _document(items=[_misconfiguration()]))
    evidence = TrivyAdapter().scan(request)
    assert evidence.scanner_run.status is Status.PASS
    assert evidence.checks_cache_content_sha256 == request._cache_content_sha256

    changed = _request(tmp_path / "changed")
    _mock_container_run(
        monkeypatch, _document(items=[_misconfiguration()]),
            mutate_cache=changed.protected_checks_cache.cache_root,
    )
    evidence = TrivyAdapter().scan(changed)
    assert evidence.scanner_run.status is Status.ERROR
    assert AdapterReason.CACHE_CHANGED_DURING_EXECUTION.value in evidence.scanner_run.diagnostics


def test_scan_rejects_command_result_for_another_argv(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(trivy_module, "run_command", lambda command: _process())
    evidence = TrivyAdapter().scan(_request(tmp_path))
    assert evidence.scanner_run.status is Status.ERROR
    assert AdapterReason.SCAN_VIEW_PREPARATION_FAILED.value in evidence.scanner_run.diagnostics


def test_scan_input_change_missing_output_and_cleanup_failure_are_typed(
    tmp_path: Path, monkeypatch,
) -> None:
    changed = _request(tmp_path / "changed")
    (changed.scan_root / "main.tf").write_text("changed\n", encoding="utf-8")
    evidence = TrivyAdapter().scan(changed)
    assert AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value in evidence.scanner_run.diagnostics

    missing = _request(tmp_path / "missing")
    monkeypatch.setattr(
        trivy_module, "run_command", lambda command: _process(argv=command.argv)
    )
    evidence = TrivyAdapter().scan(missing)
    assert AdapterReason.SCAN_VIEW_PREPARATION_FAILED.value in evidence.scanner_run.diagnostics

    cleanup = _request(tmp_path / "cleanup")
    _mock_container_run(monkeypatch, _document(items=[_misconfiguration()]))
    monkeypatch.setattr(trivy_module.shutil, "rmtree", lambda path: (_ for _ in ()).throw(OSError("no")))
    evidence = TrivyAdapter().scan(cleanup)
    assert AdapterReason.OUTPUT_CLEANUP_FAILED.value in evidence.scanner_run.diagnostics


def test_execution_evidence_contract_mutations_are_rejected(tmp_path: Path) -> None:
    evidence = _normalize(tmp_path, _document(items=[_misconfiguration()]))
    values = evidence.canonical_dict()
    values["scanner_run"] = evidence.scanner_run
    for field, invalid in (
        ("checks_cache_identity", "cache"),
        ("canonical_output_sha256", "bad"),
        ("source", "candidate"),
    ):
        changed = dict(values)
        changed[field] = invalid
        with pytest.raises(DomainError):
            trivy_module.TrivyExecutionEvidence(**changed)
    for field, invalid in (
        ("binary_image_identity", "bad"),
        ("network_disabled", 1),
    ):
        changed = dict(values)
        changed[field] = invalid
        with pytest.raises(DomainError):
            trivy_module.TrivyExecutionEvidence(**changed)
    fallback = dict(values)
    fallback["fallback_used"] = True
    with pytest.raises(DomainError, match="disagree"):
        trivy_module.TrivyExecutionEvidence(**fallback)
    changed_root = dict(values)
    changed_root["pre_run_cache_root"] = "1" * 64
    changed_root["post_run_cache_root"] = "1" * 64
    with pytest.raises(DomainError, match="one attested subtree"):
        trivy_module.TrivyExecutionEvidence(**changed_root)
    unequal_roots = dict(values)
    unequal_roots["post_run_cache_root"] = "1" * 64
    with pytest.raises(DomainError, match="changed during execution"):
        trivy_module.TrivyExecutionEvidence(**unequal_roots)
    no_attestation = dict(values)
    no_attestation["cache_attestation_identity"] = ""
    with pytest.raises(DomainError, match="attestation_identity"):
        trivy_module.TrivyExecutionEvidence(**no_attestation)
