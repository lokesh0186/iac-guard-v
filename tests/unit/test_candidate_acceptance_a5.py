"""0.1.0a5 candidate-acceptance and multi-chart universe contracts."""
from __future__ import annotations

import hashlib
import json
import copy
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
import jsonschema

import iac_guard_v.api as API
import iac_guard_v.cli as CLI
import iac_guard_v.helm as HELM
import iac_guard_v.adapters.checkov as CHECKOV
from iac_guard_v.acceptance import build_conservative_evidence_universes
from iac_guard_v.config import (
    ExecutionIsolation,
    PublicAcceptanceProperty,
    PublicCandidateAcceptanceRequest,
    PublicHelmAcceptanceRequest,
    load_public_helm_acceptance_config,
)
from iac_guard_v.engine import attest_checkov_scan_plan
from iac_guard_v.enums import ArtifactKind, CheckEvaluationResult, Status
from iac_guard_v.models import (
    CheckEvaluation,
    CoverageCounters,
    DomainError,
    ExpectedResource,
    GraphCheckEvidence,
    GraphEdgeEvidence,
    GraphParticipant,
    ResourceCoverage,
    ScannerRun,
)
from iac_guard_v.report import (
    CandidateAcceptancePropertyEvidence,
    CandidateAcceptanceReportV1,
    ExecutionIsolationEvidence,
    render_console,
    validate_report_payload,
)

from test_checkov_adapter import request as adapter_request
from test_helm_materialization_a4 import _chart, _executable, _spec


ROOT = Path(__file__).parents[2]
HELM_ACCEPTANCE_SCHEMA = json.loads(
    (ROOT / "src/iac_guard_v/schemas/helm-acceptance-v1.schema.json").read_text(
        encoding="utf-8"
    )
)


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _orphan_first_helm_resource(value: dict) -> None:
    ownership = value["materialization"]["resource_ownership"]
    ownership[0]["universe_key"] = "missing"
    value["materialization"]["combined_output"]["document_inventory_sha256"] = (
        _canonical_digest(ownership)
    )


def _omit_first_owned_resource(value: dict) -> None:
    ownership = value["materialization"]["resource_ownership"]
    del ownership[0]
    output = value["materialization"]["combined_output"]
    output["resource_count"] = len(ownership)
    output["document_inventory_sha256"] = _canonical_digest(ownership)


def _acceptance_plan(tmp_path: Path):
    return attest_checkov_scan_plan(adapter_request(tmp_path))


def _scanner_identity(plan) -> dict:
    distribution = plan.request._distribution_identity
    return {
        "launcher_digest": plan.request._executable_sha256,
        "scanner_environment_digest": distribution.scanner_environment_digest,
        "policy_inventory_digest": distribution.policy_inventory_digest,
        "invocation_config_digest": CHECKOV._invocation_config_digest(plan.request),
    }


def _run(plan, result: CheckEvaluationResult = CheckEvaluationResult.PASSED) -> ScannerRun:
    digest = "a" * 64
    resource = plan.resources[0]
    evaluation = CheckEvaluation(
        "checkov",
        "3.3.0",
        "CKV_TEST_1",
        resource.resource_address,
        resource.file_path,
        result,
        (),
        "passed_checks" if result is CheckEvaluationResult.PASSED else "failed_checks",
    )
    return ScannerRun._from_adapter(
        scanner="checkov",
        scanner_version="3.3.0",
        status=Status.PASS,
        findings=(),
        coverage=CoverageCounters(1, 1, 1, 0, 1, 0, 0),
        resource_coverage=ResourceCoverage(1, 1, 1, 0, 0, 1),
        exit_code=0,
        stdout_sha256=digest,
        stderr_sha256=digest,
        raw_output_sha256=digest,
        resolved_launcher_path="/protected/checkov",
        **_scanner_identity(plan),
        ruleset_integrity=Status.PASS,
        evaluations=(evaluation,),
        input_files=plan.request.eligible_file_evidence,
        diagnostics=("COMPLETED",),
    )


def _install_run(monkeypatch: pytest.MonkeyPatch, plan, run: ScannerRun) -> None:
    monkeypatch.setattr(API, "_untrusted_scan_request", lambda *_args: object())
    monkeypatch.setattr(API, "attest_checkov_scan_plan", lambda _raw: plan)

    class Adapter:
        def scan(self, request):
            assert request is plan.request
            return run

    monkeypatch.setattr(API, "CheckovAdapter", Adapter)


def _candidate_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    result: CheckEvaluationResult = CheckEvaluationResult.PASSED,
) -> CandidateAcceptanceReportV1:
    plan = _acceptance_plan(tmp_path)
    _install_run(monkeypatch, plan, _run(plan, result))
    request = PublicCandidateAcceptanceRequest(
        plan.scan_root,
        (PublicAcceptanceProperty("CKV_TEST_1", "aws_s3_bucket.bad", "main.tf"),),
        ExecutionIsolation.REDUCED_ISOLATION,
        plan.executable,
        ("terraform",),
    )
    report = API.verify_candidate(request)
    assert type(report) is CandidateAcceptanceReportV1
    return report


@pytest.mark.parametrize(
    ("native", "outcome", "verdict", "exit_code"),
    (
        (CheckEvaluationResult.PASSED, "SATISFIED", "VERIFIED", 0),
        (CheckEvaluationResult.FAILED, "VIOLATED", "FAILED", 1),
    ),
)
def test_candidate_acceptance_never_claims_fixed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    native: CheckEvaluationResult,
    outcome: str,
    verdict: str,
    exit_code: int,
) -> None:
    plan = _acceptance_plan(tmp_path)
    _install_run(monkeypatch, plan, _run(plan, native))
    request = PublicCandidateAcceptanceRequest(
        plan.scan_root,
        (PublicAcceptanceProperty("CKV_TEST_1", "aws_s3_bucket.bad", "main.tf"),),
        ExecutionIsolation.REDUCED_ISOLATION,
        plan.executable,
        ("terraform",),
    )

    report = API.verify_candidate(request)
    assert type(report) is CandidateAcceptanceReportV1
    value = report.canonical_dict()
    assert value["verification_mode"] == "candidate_acceptance"
    assert value["acceptance"]["properties"][0]["outcome"] == outcome
    assert value["verdict"] == verdict
    assert value["exit_code"] == exit_code
    assert "FIXED" not in report.canonical_json()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda value: value.update(verdict="FAILED", exit_code=1), "verdict"),
        (
            lambda value: value["acceptance"]["scope_accounting"].update(
                requested_property_count=2
            ),
            "property count",
        ),
        (
            lambda value: value["acceptance"]["candidate_snapshot"].update(
                resource_inventory_sha256="0" * 64
            ),
            "inventory identity",
        ),
        (
            lambda value: value["acceptance"]["scope_accounting"].update(
                selected_resource_count=0
            ),
            "selected resource count",
        ),
        (
            lambda value: value["acceptance"]["scope_accounting"].update(
                unselected_failed_finding_count=1
            ),
            "remaining-finding accounting",
        ),
        (
            lambda value: value["acceptance"]["scanner_integrity"].update(
                status="INCONCLUSIVE"
            ),
            "scanner integrity gate",
        ),
        (
            lambda value: value["acceptance"]["parser_gates"][0].update(
                status="INCONCLUSIVE"
            ),
            "parser evidence",
        ),
        (
            lambda value: value["acceptance"]["evidence_universes"][
                "governed_resource_universe"
            ].update(count=2),
            "governed resource universe",
        ),
        (
            lambda value: value["acceptance"]["evidence_universes"][
                "scanner_addressable_universe"
            ].update(resource_accounting=[]),
            "does not account for every governed resource",
        ),
        (
            lambda value: value["acceptance"]["evidence_universes"][
                "scanner_addressable_universe"
            ].update(primary_count=2),
            "primary addressability identity",
        ),
        (
            lambda value: value["acceptance"]["evidence_universes"][
                "scanner_addressable_universe"
            ].update(missing_standalone_evaluation_count=1),
            "missing standalone evaluation accounting",
        ),
        (
            lambda value: value["acceptance"]["evidence_universes"].update(
                target_relevant_evidence_universe=(
                    value["acceptance"]["evidence_universes"][
                        "target_relevant_evidence_universe"
                    ] * 2
                )
            ),
            "target-relevant universe count",
        ),
        (
            lambda value: value["acceptance"]["evidence_universes"][
                "target_relevant_evidence_universe"
            ][0].update(primary=None),
            "does not bind its requested property",
        ),
        (
            lambda value: value["acceptance"]["evidence_universes"][
                "target_relevant_evidence_universe"
            ][0].update(
                relationship_resource_count=1,
                unresolved_relationship_resource_count=1,
            ),
            "complete target universe",
        ),
        (
            lambda value: value["acceptance"]["evidence_universes"][
                "target_relevant_evidence_universe"
            ][0].update(relationship_resource_count=1),
            "target relationship universe accounting",
        ),
        (
            lambda value: value["acceptance"]["scanner_run"][
                "resource_coverage"
            ].update(expected_resources_missing=1),
            "scanner missing-resource count",
        ),
    ),
)
def test_candidate_report_semantics_reject_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    payload = copy.deepcopy(_candidate_report(monkeypatch, tmp_path).canonical_dict())
    mutation(payload)
    with pytest.raises(DomainError, match=message):
        validate_report_payload(payload)


def test_candidate_semantics_reject_property_contradictions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload = copy.deepcopy(_candidate_report(monkeypatch, tmp_path).canonical_dict())
    payload["acceptance"]["properties"][0]["resource"]["resource_address"] = "outside"
    with pytest.raises(DomainError, match="escapes resource inventory"):
        validate_report_payload(payload)

    payload = copy.deepcopy(_candidate_report(monkeypatch, tmp_path).canonical_dict())
    payload["acceptance"]["properties"][0]["evaluation"]["native_result"] = "FAILED"
    with pytest.raises(DomainError, match="SATISFIED lacks"):
        validate_report_payload(payload)

    violated_root = tmp_path / "violated"
    violated_root.mkdir()
    violated = copy.deepcopy(
        _candidate_report(
            monkeypatch, violated_root, CheckEvaluationResult.FAILED
        ).canonical_dict()
    )
    violated["acceptance"]["properties"][0]["evaluation"]["native_result"] = "PASSED"
    with pytest.raises(DomainError, match="VIOLATED lacks"):
        validate_report_payload(violated)


def test_candidate_evidence_models_reject_contradictory_or_foreign_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _candidate_report(monkeypatch, tmp_path)
    property_ = report.properties[0]
    evaluation = property_.evaluation
    resource = property_.resource
    assert evaluation is not None and resource is not None

    with pytest.raises(DomainError, match="resource address"):
        CandidateAcceptancePropertyEvidence("CKV_X", None, "", "", "INCONCLUSIVE", "WHY")
    with pytest.raises(DomainError, match="file path"):
        CandidateAcceptancePropertyEvidence(
            "CKV_X", None, "resource", object(), "INCONCLUSIVE", "WHY"
        )
    with pytest.raises(DomainError, match="unsupported"):
        CandidateAcceptancePropertyEvidence(
            "CKV_X", resource, "resource", "", "FIXED", "WHY", evaluation
        )
    with pytest.raises(DomainError, match="native passed"):
        CandidateAcceptancePropertyEvidence(
            "CKV_X", resource, "resource", "", "SATISFIED", "WHY", None
        )
    with pytest.raises(DomainError, match="native failed"):
        CandidateAcceptancePropertyEvidence(
            "CKV_X", resource, "resource", "", "VIOLATED", "WHY", evaluation
        )
    with pytest.raises(DomainError, match="exact scanner evidence"):
        CandidateAcceptancePropertyEvidence(
            "CKV_X", resource, "resource", "", "INCONCLUSIVE", "WHY", object()
        )
    with pytest.raises(DomainError, match="independently bound"):
        CandidateAcceptancePropertyEvidence(
            "CKV_X", object(), "resource", "", "INCONCLUSIVE", "WHY"
        )
    with pytest.raises(DomainError, match="complete graph evidence"):
        CandidateAcceptancePropertyEvidence(
            "CKV2_X", resource, "resource", "", "SATISFIED", "WHY", evaluation
        )

    untrusted_plan = copy.copy(report.plan)
    object.__setattr__(untrusted_plan, "_trusted", False)
    with pytest.raises(DomainError, match="protected scan plan"):
        replace(report, plan=untrusted_plan)
    with pytest.raises(DomainError, match="typed property"):
        replace(report, properties=(object(),))
    with pytest.raises(DomainError, match="isolation evidence"):
        replace(report, execution_isolation=object())
    with pytest.raises(DomainError, match="unsupported"):
        replace(report, materialization=object())

    foreign_resource = ExpectedResource(
        "other.tf", "aws_s3_bucket.other", ArtifactKind.TERRAFORM_HCL,
        "aws_s3_bucket.other",
    )
    foreign_property = CandidateAcceptancePropertyEvidence(
        "CKV_X", foreign_resource, foreign_resource.resource_address, "other.tf",
        "INCONCLUSIVE", "WHY",
    )
    with pytest.raises(DomainError, match="resource universe"):
        replace(report, properties=(foreign_property,))

    foreign_evaluation = CheckEvaluation(
        "checkov", "3.3.0", "CKV_OTHER", resource.resource_address,
        resource.file_path, CheckEvaluationResult.PASSED, (), "passed_checks",
    )
    foreign_property = CandidateAcceptancePropertyEvidence(
        "CKV_OTHER", resource, resource.resource_address, resource.file_path,
        "SATISFIED", "WHY", foreign_evaluation,
    )
    with pytest.raises(DomainError, match="scanner run"):
        replace(report, properties=(foreign_property,))


def test_candidate_acceptance_missing_and_ambiguous_targets_are_inconclusive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan = _acceptance_plan(tmp_path)
    _install_run(monkeypatch, plan, _run(plan))
    missing = PublicCandidateAcceptanceRequest(
        plan.scan_root,
        (PublicAcceptanceProperty("CKV_TEST_1", "aws_s3_bucket.missing"),),
        ExecutionIsolation.REDUCED_ISOLATION,
        plan.executable,
        ("terraform",),
    )
    report = API.verify_candidate(missing)
    assert report.verdict.value == "INCONCLUSIVE"
    assert report.properties[0].reason_code == "CANDIDATE_TARGET_MISSING"

    property_ = PublicAcceptanceProperty("CKV_TEST_1", "aws_s3_bucket.bad")
    with pytest.raises(DomainError, match="unique"):
        PublicCandidateAcceptanceRequest(
            plan.scan_root,
            (property_, property_),
            ExecutionIsolation.REDUCED_ISOLATION,
            plan.executable,
            ("terraform",),
        )

    (plan.scan_root / "other.tf").write_text(
        'resource "aws_s3_bucket" "bad" {}\n', encoding="utf-8"
    )
    ambiguous_plan = attest_checkov_scan_plan(adapter_request(tmp_path))
    _install_run(monkeypatch, ambiguous_plan, _run(ambiguous_plan))
    ambiguous = PublicCandidateAcceptanceRequest(
        ambiguous_plan.scan_root,
        (PublicAcceptanceProperty("CKV_TEST_1", "aws_s3_bucket.bad"),),
        ExecutionIsolation.REDUCED_ISOLATION,
        ambiguous_plan.executable,
        ("terraform",),
    )
    report = API.verify_candidate(ambiguous)
    assert report.properties[0].reason_code == "CANDIDATE_TARGET_AMBIGUOUS"


def test_candidate_scanner_failure_is_typed_operational_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan = _acceptance_plan(tmp_path)
    monkeypatch.setattr(API, "_untrusted_scan_request", lambda *_args: object())
    monkeypatch.setattr(API, "attest_checkov_scan_plan", lambda _raw: plan)

    class RefusingAdapter:
        def scan(self, _request):
            raise DomainError("protected scanner failed")

    monkeypatch.setattr(API, "CheckovAdapter", RefusingAdapter)
    request = PublicCandidateAcceptanceRequest(
        plan.scan_root,
        (PublicAcceptanceProperty("CKV_TEST_1", "aws_s3_bucket.bad"),),
        ExecutionIsolation.REDUCED_ISOLATION,
        plan.executable,
        ("terraform",),
    )
    result = API.verify_candidate(request)
    assert type(result) is API.OperationalReportV1
    assert result.reason_code == "CANDIDATE_EVIDENCE_UNAVAILABLE"


def test_candidate_api_type_hardened_and_incomplete_evidence_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with pytest.raises(TypeError, match="exact acceptance request"):
        API.verify_candidate(object())

    candidate = tmp_path / "hardened"
    candidate.mkdir()
    hardened = PublicCandidateAcceptanceRequest(
        candidate,
        (PublicAcceptanceProperty("CKV_X", "resource"),),
    )
    result = API.verify_candidate(hardened)
    assert result.reason_code == "HARDENED_CONTAINER_UNAVAILABLE"

    reduced_root = tmp_path / "reduced"
    reduced_root.mkdir()
    plan = _acceptance_plan(reduced_root)
    request = PublicCandidateAcceptanceRequest(
        plan.scan_root,
        (PublicAcceptanceProperty("CKV_TEST_1", "aws_s3_bucket.bad"),),
        ExecutionIsolation.REDUCED_ISOLATION,
        plan.executable,
        ("terraform",),
    )
    run = _run(plan)
    incomplete = copy.copy(run)
    object.__setattr__(
        incomplete, "coverage", CoverageCounters(1, 1, 1, 0, 1, 1, 0)
    )
    _install_run(monkeypatch, plan, incomplete)
    report = API.verify_candidate(request)
    assert report.properties[0].reason_code == "SCANNER_EVIDENCE_INCOMPLETE"

    missing = copy.copy(run)
    object.__setattr__(missing, "evaluations", ())
    _install_run(monkeypatch, plan, missing)
    report = API.verify_candidate(request)
    assert report.properties[0].reason_code == "CANDIDATE_EVALUATION_MISSING"

    ambiguous = copy.copy(run)
    object.__setattr__(ambiguous, "evaluations", run.evaluations * 2)
    _install_run(monkeypatch, plan, ambiguous)
    report = API.verify_candidate(request)
    assert report.properties[0].reason_code == "CANDIDATE_EVALUATION_AMBIGUOUS"

    skipped_evaluation = replace(
        run.evaluations[0],
        native_result=CheckEvaluationResult.SKIPPED,
        source_bucket="skipped_checks",
    )
    skipped = copy.copy(run)
    object.__setattr__(skipped, "evaluations", (skipped_evaluation,))
    _install_run(monkeypatch, plan, skipped)
    report = API.verify_candidate(request)
    assert report.properties[0].reason_code == "CANDIDATE_EVALUATION_UNDECIDED"


def test_direct_kubernetes_candidate_has_exact_resource_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw = adapter_request(tmp_path, frameworks=("kubernetes",))
    (raw.scan_root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\n"
        "spec: {containers: [{name: app, image: nginx}]}\n",
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    resource = plan.resources[0]
    digest = "a" * 64
    evaluation = CheckEvaluation(
        "checkov", "3.3.0", "CKV_K8S_16", resource.resource_address,
        resource.file_path, CheckEvaluationResult.PASSED, (), "passed_checks",
    )
    run = ScannerRun._from_adapter(
        scanner="checkov", scanner_version="3.3.0", status=Status.PASS,
        findings=(), coverage=CoverageCounters(1, 1, 1, 0, 1, 0, 0),
        resource_coverage=ResourceCoverage(1, 1, 1, 0, 0, 1), exit_code=0,
        stdout_sha256=digest, stderr_sha256=digest, raw_output_sha256=digest,
        resolved_launcher_path="/protected/checkov", **_scanner_identity(plan),
        ruleset_integrity=Status.PASS,
        evaluations=(evaluation,), input_files=plan.request.eligible_file_evidence,
        diagnostics=("COMPLETED",),
    )
    _install_run(monkeypatch, plan, run)
    request = PublicCandidateAcceptanceRequest(
        plan.scan_root,
        (PublicAcceptanceProperty(
            "CKV_K8S_16", "v1/Pod/default/demo", "pod.yaml"
        ),),
        ExecutionIsolation.REDUCED_ISOLATION,
        plan.executable,
        ("kubernetes",),
    )
    result = API.verify_candidate(request)
    assert result.properties[0].outcome == "SATISFIED"
    assert result.verdict.value == "VERIFIED"


def test_candidate_graph_acceptance_requires_complete_relationship_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw = adapter_request(tmp_path)
    (raw.scan_root / "main.tf").write_text(
        'resource "aws_s3_bucket" "bad" {}\n'
        'resource "aws_s3_bucket_public_access_block" "bad" {\n'
        '  bucket = aws_s3_bucket.bad.id\n'
        '}\n',
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    resources = {item.resource_address: item for item in plan.resources}
    bucket = GraphParticipant(
        "main.tf", "aws_s3_bucket.bad", ArtifactKind.TERRAFORM_HCL, "aws_s3_bucket"
    )
    block = GraphParticipant(
        "main.tf",
        "aws_s3_bucket_public_access_block.bad",
        ArtifactKind.TERRAFORM_HCL,
        "aws_s3_bucket_public_access_block",
    )
    graph = GraphCheckEvidence(
        Status.PASS,
        "GRAPH_EVIDENCE_COMPLETE",
        bucket,
        (bucket, block),
        (GraphEdgeEvidence(block, bucket, "attribute_reference", "bucket"),),
        "b" * 64,
        plan.request.source_snapshot_sha256,
        _scanner_identity(plan)["policy_inventory_digest"],
        "c" * 64,
        "d" * 64,
    )
    evaluation = CheckEvaluation(
        "checkov",
        "3.3.0",
        "CKV2_TEST_1",
        resources["aws_s3_bucket.bad"].resource_address,
        "main.tf",
        CheckEvaluationResult.PASSED,
        (),
        "passed_checks",
        graph_evidence=graph,
    )
    digest = "a" * 64
    run = ScannerRun._from_adapter(
        scanner="checkov",
        scanner_version="3.3.0",
        status=Status.PASS,
        findings=(),
        coverage=CoverageCounters(1, 1, 1, 0, 1, 0, 0),
        resource_coverage=ResourceCoverage(2, 2, 2, 0, 0, 2),
        exit_code=0,
        stdout_sha256=digest,
        stderr_sha256=digest,
        raw_output_sha256=digest,
        resolved_launcher_path="/protected/checkov",
        **_scanner_identity(plan),
        ruleset_integrity=Status.PASS,
        evaluations=(evaluation,),
        input_files=plan.request.eligible_file_evidence,
        diagnostics=("COMPLETED",),
    )
    _install_run(monkeypatch, plan, run)
    request = PublicCandidateAcceptanceRequest(
        plan.scan_root,
        (PublicAcceptanceProperty("CKV2_TEST_1", "aws_s3_bucket.bad", "main.tf"),),
        ExecutionIsolation.REDUCED_ISOLATION,
        plan.executable,
        ("terraform",),
    )
    result = API.verify_candidate(request)
    assert result.verdict.value == "VERIFIED"
    assert result.properties[0].outcome == "SATISFIED"
    assert result.properties[0].evaluation.graph_evidence.edges == graph.edges

    incomplete = CheckEvaluation(
        "checkov",
        "3.3.0",
        "CKV2_TEST_1",
        "aws_s3_bucket.bad",
        "main.tf",
        CheckEvaluationResult.PASSED,
        (),
        "passed_checks",
    )
    incomplete_run = ScannerRun._from_adapter(
        scanner="checkov",
        scanner_version="3.3.0",
        status=Status.PASS,
        findings=(),
        coverage=CoverageCounters(1, 1, 1, 0, 1, 0, 0),
        resource_coverage=ResourceCoverage(2, 2, 2, 0, 0, 2),
        exit_code=0,
        stdout_sha256=digest,
        stderr_sha256=digest,
        raw_output_sha256=digest,
        resolved_launcher_path="/protected/checkov",
        **_scanner_identity(plan),
        ruleset_integrity=Status.PASS,
        evaluations=(incomplete,),
        input_files=plan.request.eligible_file_evidence,
        diagnostics=("COMPLETED",),
    )
    _install_run(monkeypatch, plan, incomplete_run)
    result = API.verify_candidate(request)
    assert result.verdict.value == "INCONCLUSIVE"
    assert result.properties[0].reason_code == "GRAPH_EVIDENCE_INCOMPLETE"


def _universe_chart(
    root: Path,
    shared_helm: Path,
    rendered: str,
    key: str,
) -> HELM.HelmUniverseChart:
    root.mkdir()
    return HELM.HelmUniverseChart(
        key,
        _spec(
            root,
            chart_root=_chart(root, rendered),
            helm_executable=shared_helm,
        ),
    )


def test_multi_chart_universe_preserves_ownership_and_cross_chart_resources(
    tmp_path: Path,
) -> None:
    shared_helm = _executable(tmp_path)
    deployment = """---
# Source: demo/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: web, image: nginx}]}
"""
    policy = """---
# Source: demo/templates/deployment.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: web}
spec:
  podSelector: {matchLabels: {app: web}}
"""
    charts = (
        _universe_chart(tmp_path / "app", shared_helm, deployment, "app"),
        _universe_chart(tmp_path / "infra", shared_helm, policy, "infra"),
    )

    with HELM.materialize_helm_universe(charts) as universe:
        value = universe.canonical_dict()
        assert value["combined_output"]["chart_count"] == 2
        assert value["combined_output"]["resource_count"] == 2
        assert [item["universe_key"] for item in value["resource_ownership"]] == [
            "app", "infra"
        ]
        assert (universe.scanner_root / "rendered.yaml").is_file()
        assert len(universe.universe_identity) == 64


def _universe_candidate_report(
    tmp_path: Path,
) -> CandidateAcceptanceReportV1:
    tmp_path.mkdir(parents=True, exist_ok=True)
    shared_helm = _executable(tmp_path)
    deployment = """---
# Source: demo/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: web, image: nginx}]}
"""
    policy = """---
# Source: demo/templates/deployment.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: web}
spec:
  podSelector: {matchLabels: {app: web}}
"""
    charts = (
        _universe_chart(tmp_path / "app", shared_helm, deployment, "app"),
        _universe_chart(tmp_path / "infra", shared_helm, policy, "infra"),
    )
    trusted_root = tmp_path / "trusted"
    trusted_root.mkdir()
    trusted = _acceptance_plan(trusted_root)
    with HELM.materialize_helm_universe(charts) as universe:
        raw = API._untrusted_scan_request(
            universe.scanner_root,
            universe.scanner_root,
            trusted.executable,
            ("kubernetes",),
        )
        plan = attest_checkov_scan_plan(raw)
        resources = {item.resource_address: item for item in plan.resources}
        workload = resources["apps/v1/Deployment/default/web"]
        policy_resource = resources[
            "networking.k8s.io/v1/NetworkPolicy/default/web"
        ]
        primary = GraphParticipant(
            "rendered.yaml", workload.resource_address,
            ArtifactKind.KUBERNETES_YAML, "Deployment",
        )
        policy_participant = GraphParticipant(
            "rendered.yaml", policy_resource.resource_address,
            ArtifactKind.KUBERNETES_YAML, "NetworkPolicy",
        )
        digest = "a" * 64
        graph = GraphCheckEvidence(
            Status.PASS, "GRAPH_EVIDENCE_COMPLETE", primary,
            (primary, policy_participant),
            (GraphEdgeEvidence(policy_participant, primary, "selector", "podSelector"),),
            "b" * 64, plan.request.source_snapshot_sha256,
            _scanner_identity(plan)["policy_inventory_digest"], "c" * 64, "d" * 64,
        )
        evaluation = CheckEvaluation(
            "checkov", "3.3.0", "CKV2_K8S_6", workload.scanner_native_lookup,
            "rendered.yaml", CheckEvaluationResult.PASSED, (), "passed_checks",
            graph_evidence=graph,
        )
        run = ScannerRun._from_adapter(
            scanner="checkov", scanner_version="3.3.0", status=Status.PASS,
            findings=(), coverage=CoverageCounters(1, 1, 1, 0, 1, 0, 0),
            resource_coverage=ResourceCoverage(2, 2, 2, 0, 0, 2), exit_code=0,
            stdout_sha256=digest, stderr_sha256=digest, raw_output_sha256=digest,
            resolved_launcher_path="/protected/checkov", **_scanner_identity(plan),
            ruleset_integrity=Status.PASS,
            evaluations=(evaluation,), input_files=plan.request.eligible_file_evidence,
            diagnostics=("COMPLETED",),
        )
        property_ = CandidateAcceptancePropertyEvidence(
            "CKV2_K8S_6", workload, workload.resource_address, "rendered.yaml",
            "SATISFIED", "CANDIDATE_PROPERTY_SATISFIED", evaluation,
        )
        evidence_universes = build_conservative_evidence_universes(
            plan,
            run,
            (PublicAcceptanceProperty(
                "CKV2_K8S_6", workload.resource_address, "rendered.yaml",
                ArtifactKind.KUBERNETES_YAML,
            ),),
        )
        report = CandidateAcceptanceReportV1(
            plan, run, (property_,), ExecutionIsolationEvidence.reduced_verified(),
            universe, evidence_universes,
        )
        report.canonical_dict()
        return report


def test_cross_chart_candidate_report_binds_graph_and_materialization(
    tmp_path: Path,
) -> None:
    report = _universe_candidate_report(tmp_path)
    payload = report.canonical_dict()
    assert payload["verdict"] == "VERIFIED"
    assert payload["materialization"]["combined_output"]["chart_count"] == 2
    assert report.report_sha256 == hashlib.sha256(
        report.canonical_json().encode("utf-8")
    ).hexdigest()
    assert "mode: candidate_acceptance" in render_console(report)
    assert "interpretation: VERIFIED means only" in CLI._explain_report(payload)


def test_graph_acceptance_rejects_incomplete_or_mismatched_provenance(
    tmp_path: Path,
) -> None:
    payload = copy.deepcopy(_universe_candidate_report(tmp_path).canonical_dict())
    graph = payload["acceptance"]["properties"][0]["evaluation"]["graph_evidence"]
    graph["status"] = "INCONCLUSIVE"
    with pytest.raises(DomainError, match="lacks complete graph evidence"):
        validate_report_payload(payload)

    payload = copy.deepcopy(
        _universe_candidate_report(tmp_path / "snapshot").canonical_dict()
    )
    graph = payload["acceptance"]["properties"][0]["evaluation"]["graph_evidence"]
    graph["source_snapshot_sha256"] = "0" * 64
    with pytest.raises(DomainError, match="graph provenance"):
        validate_report_payload(payload)

    payload = copy.deepcopy(
        _universe_candidate_report(tmp_path / "participant").canonical_dict()
    )
    graph = payload["acceptance"]["properties"][0]["evaluation"]["graph_evidence"]
    graph["participants"][0]["resource_address"] = "v1/Pod/default/outside"
    scanner_graph = payload["acceptance"]["scanner_run"]["evaluations"][0][
        "graph_evidence"
    ]
    scanner_graph["participants"][0]["resource_address"] = "v1/Pod/default/outside"
    with pytest.raises(DomainError, match="graph participant is not rendered"):
        validate_report_payload(payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (
            lambda value: value["materialization"]["combined_output"].update(
                chart_count=3
            ),
            "chart count",
        ),
        (
            lambda value: value["materialization"]["combined_output"].update(
                resource_count=3
            ),
            "resource count",
        ),
        (
            lambda value: value["materialization"]["combined_output"].update(
                document_inventory_sha256="0" * 64
            ),
            "document inventory",
        ),
        (
            _orphan_first_helm_resource,
            "no participating chart owner",
        ),
        (
            _omit_first_owned_resource,
            "resource ownership is incomplete",
        ),
        (
            lambda value: value["materialization"]["charts"][0]["materialization"][
                "chart"
            ].update(inventory_root_sha256="0" * 64),
            "chart inventory root",
        ),
        (
            lambda value: value["materialization"]["charts"][0]["materialization"][
                "output"
            ].update(document_inventory_sha256="0" * 64),
            "chart document inventory",
        ),
        (
            lambda value: value["materialization"]["charts"][0]["materialization"].update(
                materialization_identity="0" * 64
            ),
            "chart materialization",
        ),
        (
            lambda value: value["materialization"].update(universe_identity="0" * 64),
            "universe identity",
        ),
        (
            lambda value: value["acceptance"]["scanner_run"]["input_files"][0].update(
                sha256="0" * 64
            ),
            "exact scanner input",
        ),
    ),
)
def test_helm_universe_report_rejects_provenance_mutation(
    tmp_path: Path, mutation, message: str
) -> None:
    payload = copy.deepcopy(_universe_candidate_report(tmp_path).canonical_dict())
    mutation(payload)
    with pytest.raises(DomainError, match=message):
        validate_report_payload(payload)


def test_verify_helm_candidate_closed_success_and_failure_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _universe_candidate_report(tmp_path / "report")
    request_root = tmp_path / "request"
    request_root.mkdir()
    checkov = _executable(request_root)
    chart = _universe_chart(
        request_root / "chart", checkov, HELM_DEPLOYMENT, "chart"
    )
    request = PublicHelmAcceptanceRequest(
        (chart,),
        (PublicAcceptanceProperty(
            "CKV_K8S_16", "apps/v1/Deployment/default/duplicate"
        ),),
        ExecutionIsolation.REDUCED_ISOLATION,
        checkov,
    )

    with pytest.raises(TypeError, match="exact Helm acceptance"):
        API.verify_helm_candidate(object())

    @contextmanager
    def universe_context(_charts):
        yield SimpleNamespace(
            scanner_root=request_root,
            charts=(),
        )

    monkeypatch.setattr(API, "materialize_helm_universe", universe_context)
    monkeypatch.setattr(API, "_verify_candidate_request", lambda *_a, **_k: report)
    assert API.verify_helm_candidate(request) is report

    graph_report = report

    @contextmanager
    def excluded_crd_context(_charts):
        evidence = SimpleNamespace(
            render_inputs={"crds": "exclude"},
            chart={"files": [{"path": "crds/type.yaml"}]},
        )
        yield SimpleNamespace(scanner_root=request_root, charts=(("chart", evidence),))

    monkeypatch.setattr(API, "materialize_helm_universe", excluded_crd_context)
    result = API.verify_helm_candidate(request)
    assert result.reason_code == "INCOMPLETE_RENDERED_COVERAGE"

    @contextmanager
    def refusal(_charts):
        raise HELM.HelmMaterializationError("NONDETERMINISTIC_RENDER", "changed")
        yield

    monkeypatch.setattr(API, "materialize_helm_universe", refusal)
    result = API.verify_helm_candidate(request)
    assert result.reason_code == "NONDETERMINISTIC_RENDER"


def test_candidate_report_object_rejects_unbound_helm_bytes_and_graph(
    tmp_path: Path,
) -> None:
    report = _universe_candidate_report(tmp_path)
    output = dict(report.materialization.combined_output)
    output["rendered_bundle_sha256"] = "0" * 64
    mismatched = replace(
        report.materialization,
        combined_output=MappingProxyType(output),
    )
    with pytest.raises(DomainError, match="exact scanner input bytes"):
        replace(report, materialization=mismatched)

    evaluation = report.properties[0].evaluation
    assert evaluation is not None and evaluation.graph_evidence is not None
    graph = evaluation.graph_evidence
    outside = GraphParticipant(
        "rendered.yaml", "v1/Pod/default/outside",
        ArtifactKind.KUBERNETES_YAML, "Pod",
    )
    policy = graph.participants[1]
    changed_graph = GraphCheckEvidence(
        Status.PASS, "GRAPH_EVIDENCE_COMPLETE", outside, (outside, policy),
        (GraphEdgeEvidence(policy, outside, "selector", "podSelector"),),
        graph.input_manifest_sha256, graph.source_snapshot_sha256,
        graph.policy_inventory_sha256, graph.policy_definition_sha256,
        graph.query_identity_sha256,
    )
    changed_evaluation = replace(evaluation, graph_evidence=changed_graph)
    changed_run = copy.copy(report.scanner_run)
    object.__setattr__(changed_run, "evaluations", (changed_evaluation,))
    changed_property = replace(report.properties[0], evaluation=changed_evaluation)
    with pytest.raises(DomainError, match="escapes rendered resources"):
        CandidateAcceptanceReportV1(
            report.plan, changed_run, (changed_property,), report.execution_isolation,
            report.materialization, report.evidence_universes,
        )


def test_multi_chart_universe_rejects_duplicate_identity(tmp_path: Path) -> None:
    shared_helm = _executable(tmp_path)
    charts = (
        _universe_chart(tmp_path / "one", shared_helm, HELM_DEPLOYMENT, "one"),
        _universe_chart(tmp_path / "two", shared_helm, HELM_DEPLOYMENT, "two"),
    )
    with pytest.raises(HELM.HelmMaterializationError) as caught:
        with HELM.materialize_helm_universe(charts):
            pass
    assert caught.value.reason_code == "DUPLICATE_RENDERED_IDENTITY"


def test_multi_chart_universe_rejects_unclosed_or_incompatible_requests(
    tmp_path: Path,
) -> None:
    with pytest.raises(DomainError, match="one to 32"):
        with HELM.materialize_helm_universe([]):
            pass

    shared_helm = _executable(tmp_path)
    one = _universe_chart(
        tmp_path / "one", shared_helm,
        HELM_DEPLOYMENT.replace("duplicate", "one"), "one",
    )
    duplicate = HELM.HelmUniverseChart("one", one.specification)
    with pytest.raises(DomainError, match="keys must be unique"):
        with HELM.materialize_helm_universe((one, duplicate)):
            pass

    other_root = tmp_path / "other"
    other_root.mkdir()
    incompatible = HELM.HelmUniverseChart(
        "other",
        _spec(
            other_root,
            chart_root=_chart(
                other_root, HELM_DEPLOYMENT.replace("duplicate", "other")
            ),
            helm_executable=shared_helm,
            kube_version="1.30.0",
        ),
    )
    with pytest.raises(DomainError, match="one executable, kube version"):
        with HELM.materialize_helm_universe((one, incompatible)):
            pass


def test_multi_chart_same_name_in_distinct_namespaces_is_not_ambiguous(
    tmp_path: Path,
) -> None:
    shared_helm = _executable(tmp_path)
    first = HELM_DEPLOYMENT.replace("duplicate", "shared")
    second = first.replace("metadata: {name: shared}", "metadata: {name: shared, namespace: other}")
    charts = (
        _universe_chart(tmp_path / "one", shared_helm, first, "one"),
        _universe_chart(tmp_path / "two", shared_helm, second, "two"),
    )
    with HELM.materialize_helm_universe(charts) as universe:
        assert [item.resource_identity for _key, item in universe.resource_ownership] == [
            "apps/v1/Deployment/default/shared",
            "apps/v1/Deployment/other/shared",
        ]


@pytest.mark.parametrize(
    ("action", "reason"),
    (
        ("{{ randAlphaNum 8 }}", "NONDETERMINISTIC_RENDER"),
        ('{{ lookup "v1" "Secret" "default" "name" }}', "CLUSTER_STATE_REQUIRED"),
    ),
)
def test_one_unreproducible_chart_blocks_the_combined_universe(
    tmp_path: Path, action: str, reason: str
) -> None:
    shared_helm = _executable(tmp_path)
    good = _universe_chart(tmp_path / "good", shared_helm, HELM_DEPLOYMENT, "good")
    bad_root = tmp_path / "bad"
    bad_root.mkdir()
    bad = HELM.HelmUniverseChart(
        "bad",
        _spec(
            bad_root,
            chart_root=_chart(
                bad_root,
                HELM_DEPLOYMENT.replace("duplicate", "other"),
                template=action,
            ),
            helm_executable=shared_helm,
        ),
    )
    with pytest.raises(HELM.HelmMaterializationError) as caught:
        with HELM.materialize_helm_universe((good, bad)):
            pass
    assert caught.value.reason_code == reason


HELM_DEPLOYMENT = """---
# Source: demo/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: duplicate}
spec:
  template:
    spec: {containers: [{name: app, image: nginx}]}
"""


def test_multi_chart_universe_identity_changes_with_chart_order(tmp_path: Path) -> None:
    shared_helm = _executable(tmp_path)
    one = _universe_chart(
        tmp_path / "one",
        shared_helm,
        HELM_DEPLOYMENT.replace("duplicate", "one"),
        "one",
    )
    two = _universe_chart(
        tmp_path / "two",
        shared_helm,
        HELM_DEPLOYMENT.replace("duplicate", "two"),
        "two",
    )
    with HELM.materialize_helm_universe((one, two)) as first:
        first_identity = first.universe_identity
    with HELM.materialize_helm_universe((two, one)) as second:
        second_identity = second.universe_identity
    assert first_identity != second_identity


def test_universe_combined_bundle_digest_is_byte_bound(tmp_path: Path) -> None:
    shared_helm = _executable(tmp_path)
    chart = _universe_chart(tmp_path / "one", shared_helm, HELM_DEPLOYMENT, "one")
    with HELM.materialize_helm_universe((chart,)) as universe:
        rendered = (universe.scanner_root / "rendered.yaml").read_bytes()
        assert hashlib.sha256(rendered).hexdigest() == universe.combined_output[
            "rendered_bundle_sha256"
        ]


def test_closed_helm_acceptance_config_loads_distinct_chart_inputs(
    tmp_path: Path,
) -> None:
    shared_helm = _executable(tmp_path)
    first = _chart(tmp_path / "first", HELM_DEPLOYMENT.replace("duplicate", "first"))
    second = _chart(tmp_path / "second", HELM_DEPLOYMENT.replace("duplicate", "second"))
    checkov = tmp_path / "checkov"
    checkov.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    checkov.chmod(0o755)
    config = tmp_path / "helm-acceptance.json"
    payload = {
        "schema_version": "helm-acceptance-v1",
        "checkov_executable": str(checkov),
        "charts": [
            {
                "universe_key": key,
                "chart_root": str(chart),
                "helm_executable": str(shared_helm),
                "release_name": key,
                "namespace": "default",
                "kube_version": "1.31.0",
                "values_files": [],
                "set": [],
                "set_string": [],
                "api_versions": [],
                "include_crds": False,
                "include_tests": False,
            }
            for key, chart in (("first", first), ("second", second))
        ],
        "properties": [{
            "rule_id": "CKV_K8S_16",
            "resource_address": "apps/v1/Deployment/default/first",
            "file_path": "rendered.yaml",
        }],
    }
    jsonschema.validate(payload, HELM_ACCEPTANCE_SCHEMA)
    config.write_text(json.dumps(payload), encoding="utf-8")

    request = load_public_helm_acceptance_config(config)
    assert type(request) is PublicHelmAcceptanceRequest
    assert [item.universe_key for item in request.charts] == ["first", "second"]
    assert request.properties[0].rule_id == "CKV_K8S_16"


def _helm_config_payload(tmp_path: Path) -> dict:
    helm = _executable(tmp_path)
    chart = _chart(tmp_path)
    checkov = tmp_path / "checkov"
    checkov.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    checkov.chmod(0o755)
    return {
        "schema_version": "helm-acceptance-v1",
        "checkov_executable": str(checkov),
        "charts": [{
            "universe_key": "app",
            "chart_root": str(chart),
            "helm_executable": str(helm),
            "release_name": "app",
            "namespace": "default",
            "kube_version": "1.31.0",
        }],
        "properties": [{
            "rule_id": "CKV_K8S_16",
            "resource_address": "apps/v1/Deployment/default/app",
        }],
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda value: value.update(extra=True), "unknown fields"),
        (lambda value: value.update(schema_version="other"), "schema_version"),
        (lambda value: value.update(checkov_executable=1), "checkov_executable"),
        (lambda value: value.update(charts=[]), "nonempty array"),
        (lambda value: value["charts"][0].update(extra=True), "unknown fields"),
        (lambda value: value["charts"][0].pop("namespace"), "missing required"),
        (lambda value: value["charts"][0].update(namespace=""), "must be nonblank"),
        (lambda value: value["charts"][0].update(include_crds="yes"), "Boolean"),
        (lambda value: value["charts"][0].update(values_files="bad"), "string array"),
        (lambda value: value["charts"][0].update(set="bad"), "JSON array"),
        (
            lambda value: value["charts"][0].update(set=[{"key": "x"}]),
            "only key and value",
        ),
        (
            lambda value: value["charts"][0].update(set=[{"key": 1, "value": "x"}]),
            "must be strings",
        ),
        (lambda value: value.update(properties=[]), "nonempty array"),
        (lambda value: value.update(properties=[{"extra": True}]), "unknown fields"),
        (
            lambda value: value.update(properties=[{"rule_id": "CKV_X"}]),
            "requires rule_id and resource_address",
        ),
        (
            lambda value: value.update(properties=[{
                "rule_id": 1, "resource_address": "resource"
            }]),
            "must be a string",
        ),
        (
            lambda value: value.update(properties=[{
                "rule_id": "CKV_X", "resource_address": "resource",
                "artifact_kind": "unsupported",
            }]),
            "artifact_kind is unsupported",
        ),
    ),
)
def test_helm_acceptance_loader_rejects_unclosed_input(
    tmp_path: Path, mutation, message: str
) -> None:
    case = tmp_path / "case"
    case.mkdir()
    payload = _helm_config_payload(case)
    mutation(payload)
    path = case / "request.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DomainError, match=message):
        load_public_helm_acceptance_config(path)


def test_helm_acceptance_schema_is_closed() -> None:
    payload = {
        "schema_version": "helm-acceptance-v1",
        "checkov_executable": "/protected/checkov",
        "charts": [{
            "universe_key": "app",
            "chart_root": "/protected/chart",
            "helm_executable": "/protected/helm",
            "release_name": "app",
            "namespace": "default",
            "kube_version": "1.31.0",
        }],
        "properties": [{
            "rule_id": "CKV_K8S_16",
            "resource_address": "apps/v1/Deployment/default/app",
        }],
    }
    jsonschema.validate(payload, HELM_ACCEPTANCE_SCHEMA)
    payload["arbitrary_command"] = "sh -c unsafe"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, HELM_ACCEPTANCE_SCHEMA)


def test_cli_exposes_distinct_candidate_acceptance_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    checkov = tmp_path / "checkov"
    checkov.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    checkov.chmod(0o755)
    args = CLI._parser().parse_args([
        "accept",
        "--candidate", str(candidate),
        "--property", "CKV_TEST_1=aws_s3_bucket.bad@main.tf",
        "--framework", "terraform",
        "--local-trusted",
        "--checkov-executable", str(checkov),
    ])
    request = CLI._acceptance_request(args)
    assert type(request) is PublicCandidateAcceptanceRequest
    assert request.properties[0].resource_address == "aws_s3_bucket.bad"

    operational = API.OperationalReportV1("STOP", "bounded", "review")
    monkeypatch.setattr(CLI, "load_public_helm_acceptance_config", lambda _path: object())
    monkeypatch.setattr(CLI, "verify_helm_candidate", lambda _request: operational)
    monkeypatch.setattr(CLI, "_write_report", lambda report, *_a, **_k: report.exit_code)
    assert CLI.main([
        "helm-accept", "--config", str(tmp_path / "request.json"), "--local-trusted"
    ]) == 3
