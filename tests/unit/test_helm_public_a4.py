"""0.1.0a4 public Helm request, API, CLI, and report boundaries."""
from __future__ import annotations

import copy
import hashlib
import io
import tarfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import iac_guard_v.api as API
import iac_guard_v.cli as CLI
import iac_guard_v.helm as HELM
import iac_guard_v.report as REPORT
from iac_guard_v.config import (
    ExecutionIsolation,
    PublicHelmVerificationRequest,
    PublicTarget,
)
from iac_guard_v.models import DomainError
from iac_guard_v.enums import Verdict
from iac_guard_v.report import OperationalReportV1, VerificationReportV1

from test_helm_materialization_a4 import _chart, _executable, _spec
from test_policy import _verdict, verified_engine  # noqa: F401


def _request(tmp_path: Path) -> PublicHelmVerificationRequest:
    index = sum(1 for item in tmp_path.iterdir() if item.name.startswith("request-"))
    request_root = tmp_path / f"request-{index}"
    request_root.mkdir()
    baseline_root = request_root / "baseline"
    candidate_root = request_root / "candidate"
    baseline_root.mkdir()
    candidate_root.mkdir()
    baseline = _spec(baseline_root)
    candidate = _spec(candidate_root)
    checkov = request_root / "checkov"
    checkov.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    checkov.chmod(0o755)
    return PublicHelmVerificationRequest(
        baseline,
        candidate,
        (("CKV_K8S_16", "apps/v1/Deployment/default/demo", "rendered.yaml"),),
        False,
        ExecutionIsolation.REDUCED_ISOLATION,
        checkov,
    )


@pytest.mark.parametrize(
    "change",
    (
        {"baseline": object()},
        {"selectors": []},
        {"selectors": (("only", "two"),)},
        {"all_baseline_findings": "false"},
        {"selectors": (), "all_baseline_findings": False},
        {"all_baseline_findings": True},
        {"execution_isolation": ExecutionIsolation.HARDENED_CONTAINER},
        {"checkov_executable": "checkov"},
        {"checkov_executable": Path("missing-checkov")},
    ),
)
def test_public_helm_request_rejects_untyped_or_ambiguous_input(
    tmp_path: Path, change: dict
) -> None:
    request = _request(tmp_path)
    values = {
        name: getattr(request, name)
        for name in PublicHelmVerificationRequest.__dataclass_fields__
    }
    values.update(change)
    with pytest.raises(DomainError):
        PublicHelmVerificationRequest(**values)


def test_public_helm_request_accepts_all_baseline_mode(tmp_path: Path) -> None:
    request = _request(tmp_path)
    value = PublicHelmVerificationRequest(
        request.baseline,
        request.candidate,
        (),
        True,
        request.execution_isolation,
        request.checkov_executable,
    )
    assert value.all_baseline_findings is True


def test_verify_helm_requires_exact_request() -> None:
    with pytest.raises(TypeError, match="exact PublicHelmVerificationRequest"):
        API.verify_helm(object())


@contextmanager
def _yield_materialization(value):
    yield value


def test_verify_helm_maps_materialization_refusal_to_operational_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    @contextmanager
    def refuse(*_args):
        raise HELM.HelmMaterializationError("NONDETERMINISTIC_RENDER", "changed")
        yield

    monkeypatch.setattr(API, "materialize_helm_comparison", refuse)
    result = API.verify_helm(_request(tmp_path))
    assert type(result) is OperationalReportV1
    assert result.reason_code == "NONDETERMINISTIC_RENDER"


def test_verify_helm_maps_discovery_refusal_and_empty_targets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pair = SimpleNamespace(baseline_root=tmp_path, candidate_root=tmp_path)
    monkeypatch.setattr(
        API, "materialize_helm_comparison", lambda *_: _yield_materialization(pair)
    )

    def unavailable(*_args, **_kwargs):
        raise API.BaselineDiscoveryUnavailable("scanner unavailable")

    monkeypatch.setattr(API, "discover_baseline_targets", unavailable)
    result = API.verify_helm(_request(tmp_path))
    assert result.reason_code == "BASELINE_TARGET_DISCOVERY_UNAVAILABLE"

    monkeypatch.setattr(API, "discover_baseline_targets", lambda *_a, **_k: ())
    result = API.verify_helm(_request(tmp_path))
    assert result.reason_code == "NO_BASELINE_TARGETS"


def test_verify_helm_wraps_verified_result_and_preserves_operational_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, verified_engine
) -> None:
    baseline_root = tmp_path / "rendered-baseline"
    candidate_root = tmp_path / "rendered-candidate"
    baseline_root.mkdir()
    candidate_root.mkdir()
    pair = SimpleNamespace(
        baseline_root=baseline_root,
        candidate_root=candidate_root,
    )
    monkeypatch.setattr(
        API, "materialize_helm_comparison", lambda *_: _yield_materialization(pair)
    )
    monkeypatch.setattr(
        API,
        "discover_baseline_targets",
        lambda *_a, **_k: (PublicTarget("CKV_X", "Pod.default.demo"),),
    )
    operational = OperationalReportV1("NO_RESULT", "none", "retry")
    monkeypatch.setattr(API, "_verify_request", lambda *_: operational)
    assert API.verify_helm(_request(tmp_path)) is operational

    policy = _verdict(verified_engine)
    verification = VerificationReportV1(verified_engine, policy)
    monkeypatch.setattr(API, "_verify_request", lambda *_: verification)
    monkeypatch.setattr(API, "_graph_verification_has_excluded_crds", lambda *_: False)
    sentinel = object()
    monkeypatch.setattr(API, "HelmVerificationReportV1", lambda *_: sentinel)
    assert API.verify_helm(_request(tmp_path)) is sentinel

    monkeypatch.setattr(API, "_graph_verification_has_excluded_crds", lambda *_: True)
    result = API.verify_helm(_request(tmp_path))
    assert result.reason_code == "INCOMPLETE_RENDERED_COVERAGE"


@pytest.mark.parametrize("value", (None, "key", "=value", "key="))
def test_helm_override_parser_rejects_noncanonical_values(value: object) -> None:
    with pytest.raises(DomainError):
        CLI._parse_helm_override(value)


def test_helm_override_parser_preserves_exact_value() -> None:
    assert CLI._parse_helm_override("name=a=b") == ("name", "a=b")


def _helm_args(
    tmp_path: Path,
    *extra: str,
    request: PublicHelmVerificationRequest | None = None,
):
    request = request or _request(tmp_path)
    return CLI._parser().parse_args([
        "helm-verify",
        "--before-chart", str(request.baseline.chart_root),
        "--after-chart", str(request.candidate.chart_root),
        "--target", "CKV_K8S_16=apps/v1/Deployment/default/demo@rendered.yaml",
        "--helm-kube-version", "1.31.0",
        *extra,
    ])


def test_helm_cli_requires_explicit_local_mode_for_executables(tmp_path: Path) -> None:
    args = _helm_args(tmp_path)
    result = CLI._helm_request(args)
    assert result.reason_code == "HARDENED_HELM_UNAVAILABLE"

    args = _helm_args(tmp_path, "--helm-executable", str(_executable(tmp_path)))
    with pytest.raises(DomainError, match="require --local-trusted"):
        CLI._helm_request(args)


def test_helm_cli_reports_missing_discovered_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(CLI.shutil, "which", lambda _name: None)
    result = CLI._helm_request(_helm_args(tmp_path, "--local-trusted"))
    assert result.reason_code == "HELM_ENVIRONMENT_INCOMPLETE"

    helm = _executable(tmp_path)
    monkeypatch.setattr(
        CLI.shutil, "which", lambda name: str(helm) if name == "helm" else None
    )
    result = CLI._helm_request(_helm_args(tmp_path, "--local-trusted"))
    assert result.reason_code == "CHECKOV_NOT_FOUND"


def test_helm_cli_builds_closed_typed_request(tmp_path: Path) -> None:
    request = _request(tmp_path)
    args = _helm_args(
        tmp_path,
        "--local-trusted",
        "--helm-executable", str(request.baseline.helm_executable),
        "--checkov-executable", str(request.checkov_executable),
        "--helm-release-name", "review",
        "--helm-namespace", "default",
        "--helm-values", "values.yaml",
        "--helm-set", "replicas=2",
        "--helm-set-string", "identifier=001",
        "--helm-api-version", "example.io/v1",
        "--helm-include-crds",
        "--helm-include-tests",
        request=request,
    )
    for chart in (request.baseline.chart_root, request.candidate.chart_root):
        (chart / "values.yaml").write_text("enabled: true\n", encoding="utf-8")
    result = CLI._helm_request(args)
    assert type(result) is PublicHelmVerificationRequest
    assert result.baseline.set_values == (("replicas", "2"),)
    assert result.baseline.set_strings == (("identifier", "001"),)
    assert result.baseline.api_versions == ("example.io/v1",)
    assert result.baseline.include_crds and result.baseline.include_tests


def test_main_dispatches_helm_operational_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    operational = OperationalReportV1("HELM_STOP", "stopped", "repair")
    monkeypatch.setattr(CLI, "_helm_request", lambda _args: operational)
    monkeypatch.setattr(
        CLI, "_write_report", lambda report, *_args, **_kwargs: report.exit_code
    )
    assert CLI.main([
        "helm-verify",
        "--before-chart", str(tmp_path),
        "--after-chart", str(tmp_path),
        "--target", "CKV_X=Pod.default.demo",
        "--helm-kube-version", "1.31.0",
    ]) == 3


def _dependency_chart(root: Path) -> Path:
    chart = _chart(root)
    dependency = {
        "name": "child",
        "version": "1.2.3",
        "repository": "https://example.invalid",
    }
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
        "dependencies:\n"
        "- {name: child, version: 1.2.3, repository: https://example.invalid}\n",
        encoding="utf-8",
    )
    digest = HELM._helm_dependency_digest([dependency], [dependency])
    (chart / "Chart.lock").write_text(
        "dependencies:\n"
        "- {name: child, version: 1.2.3, repository: https://example.invalid}\n"
        f"digest: {digest}\ngenerated: 2026-08-24T00:00:00Z\n",
        encoding="utf-8",
    )
    charts = chart / "charts"
    charts.mkdir()
    with tarfile.open(charts / "child-1.2.3.tgz", "w:gz") as archive:
        content = b"apiVersion: v2\nname: child\nversion: 1.2.3\n"
        member = tarfile.TarInfo("child/Chart.yaml")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return chart


def _semantic_payload(
    tmp_path: Path, *, dependencies: bool = False, tpl: bool = False,
    dynamic_include: bool = False,
) -> dict:
    index = sum(1 for item in tmp_path.iterdir() if item.name.startswith("semantic-"))
    semantic_root = tmp_path / f"semantic-{index}"
    semantic_root.mkdir()
    baseline_root = semantic_root / "baseline"
    candidate_root = semantic_root / "candidate"
    baseline_root.mkdir()
    candidate_root.mkdir()
    if dependencies:
        baseline = _spec(baseline_root, chart_root=_dependency_chart(baseline_root))
        candidate = _spec(candidate_root, chart_root=_dependency_chart(candidate_root))
    elif tpl:
        baseline_chart = _chart(
            baseline_root, template="{{ tpl .Values.templateText . }}"
        )
        candidate_chart = _chart(
            candidate_root, template="{{ tpl .Values.templateText . }}"
        )
        for chart in (baseline_chart, candidate_chart):
            (chart / "values.yaml").write_text(
                "templateText: '{{ .Values.value }}'\nvalue: safe\n",
                encoding="utf-8",
            )
        baseline = _spec(baseline_root, chart_root=baseline_chart)
        candidate = _spec(candidate_root, chart_root=candidate_chart)
    elif dynamic_include:
        action = '{{ include (print $.Template.BasePath "/configmap.yaml") . }}'
        baseline_chart = _chart(baseline_root, template=action)
        candidate_chart = _chart(candidate_root, template=action)
        for chart in (baseline_chart, candidate_chart):
            (chart / "templates" / "configmap.yaml").write_text(
                "{{ tpl .Values.templateText . }}", encoding="utf-8"
            )
            (chart / "values.yaml").write_text(
                "templateText: '{{ .Values.value }}'\nvalue: safe\n",
                encoding="utf-8",
            )
        baseline = _spec(baseline_root, chart_root=baseline_chart)
        candidate = _spec(candidate_root, chart_root=candidate_chart)
    else:
        baseline = _spec(baseline_root)
        candidate = _spec(candidate_root)
    with HELM.materialize_helm_comparison(baseline, candidate) as pair:
        comparison = pair.canonical_dict()
    verification = {}
    for role in ("baseline", "candidate"):
        evidence = comparison[role]
        verification[f"{role}_run"] = {
            "input_files": [{
                "file_path": "rendered.yaml",
                "sha256": evidence["output"]["rendered_bundle_sha256"],
            }],
            "evaluations": [],
        }
    return {"materialization": comparison, "verification": verification}


def test_helm_semantic_validator_recomputes_complete_identity(tmp_path: Path) -> None:
    payload = _semantic_payload(tmp_path)
    REPORT._validate_helm_materialization(payload)


def test_helm_semantic_validator_binds_archive_and_expanded_dependency_bytes(
    tmp_path: Path,
) -> None:
    payload = _semantic_payload(tmp_path, dependencies=True)
    REPORT._validate_helm_materialization(payload)


def test_helm_semantic_validator_binds_bounded_tpl_evidence(tmp_path: Path) -> None:
    payload = _semantic_payload(tmp_path, tpl=True)
    REPORT._validate_helm_materialization(payload)


def test_helm_semantic_validator_binds_dynamic_include_evidence(
    tmp_path: Path,
) -> None:
    payload = _semantic_payload(tmp_path, dynamic_include=True)
    REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("callsite_identity", "0" * 64, "dynamic include callsite identity"),
        ("resolution_identity", "0" * 64, "dynamic include resolution"),
        ("target_source_sha256", "0" * 64, "target hash"),
        ("target_source_template", "templates/escape.yaml", "escapes chart inventory"),
    ),
)
def test_helm_semantic_validator_rejects_dynamic_include_mutation(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path, dynamic_include=True))
    proof = payload["materialization"]["baseline"]["render_inputs"][
        "template_action_reachability"
    ]
    proof["dynamic_include_evidence"][0][field] = value
    body = dict(proof)
    body.pop("analysis_identity")
    proof["analysis_identity"] = REPORT._canonical_json_digest(body)
    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("count", "dynamic-include evidence count"),
        ("duplicate", "callsite identity is duplicated"),
        ("orphan", "callsite identity is not canonical"),
        ("children", "resolution is not canonical"),
        ("operand", "literal include operand contains extra evidence"),
    ),
)
def test_helm_semantic_validator_rejects_dynamic_include_structure_mutation(
    tmp_path: Path, mutation: str, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path, dynamic_include=True))
    proof = payload["materialization"]["baseline"]["render_inputs"][
        "template_action_reachability"
    ]
    record = proof["dynamic_include_evidence"][0]
    if mutation == "count":
        proof["dynamic_include_evidence_count"] += 1
    elif mutation == "duplicate":
        proof["dynamic_include_evidence"].append(copy.deepcopy(record))
        proof["dynamic_include_evidence_count"] += 1
    elif mutation == "orphan":
        record["parent_callsite_identity"] = "1" * 64
    elif mutation == "children":
        record["child_callsite_identities"] = ["1" * 64]
    else:
        literal = next(
            item for item in record["operand_identities"] if item["kind"] == "LITERAL"
        )
        literal["protected_path"] = "templates"
    body = dict(proof)
    body.pop("analysis_identity")
    proof["analysis_identity"] = REPORT._canonical_json_digest(body)
    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("callsite_identity", "0" * 64, "tpl callsite identity"),
        ("nested_action_graph_identity", "0" * 64, "tpl action graph"),
        ("protected_values_sha256", "0" * 64, "tpl values identity"),
    ),
)
def test_helm_semantic_validator_rejects_tpl_evidence_mutation(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path, tpl=True))
    proof = payload["materialization"]["baseline"]["render_inputs"][
        "template_action_reachability"
    ]
    proof["tpl_evidence"][0][field] = value
    body = dict(proof)
    body.pop("analysis_identity")
    proof["analysis_identity"] = REPORT._canonical_json_digest(body)

    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("count", "tpl-evidence count"),
        ("source", "tpl callsite escapes"),
        ("nested-count", "nested-action count"),
        ("nested-digest", "nested action digest"),
        ("duplicate", "tpl callsite identity is duplicated"),
    ),
)
def test_helm_semantic_validator_rejects_tpl_structure_mutation(
    tmp_path: Path, mutation: str, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path, tpl=True))
    proof = payload["materialization"]["baseline"]["render_inputs"][
        "template_action_reachability"
    ]
    record = proof["tpl_evidence"][0]
    if mutation == "count":
        proof["tpl_evidence_count"] = 2
    elif mutation == "source":
        record["source_template"] = "templates/escape.yaml"
    elif mutation == "nested-count":
        record["nested_action_count"] += 1
    elif mutation == "nested-digest":
        record["nested_action_sha256"][0] = "not-a-digest"
    else:
        proof["tpl_evidence"].append(copy.deepcopy(record))
        proof["tpl_evidence_count"] = 2
    body = dict(proof)
    body.pop("analysis_identity")
    proof["analysis_identity"] = REPORT._canonical_json_digest(body)

    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("field", "message"),
    (
        ("analysis_identity", "action analysis identity"),
        ("protected_values_sha256", "action analysis identity"),
    ),
)
def test_helm_semantic_validator_rejects_a6_action_proof_mutation(
    tmp_path: Path, field: str, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path))
    proof = payload["materialization"]["baseline"]["render_inputs"][
        "template_action_reachability"
    ]
    proof[field] = "0" * 64

    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("excluded_dangerous_action_count", 1, "excluded-action count"),
        ("participating_source_templates", [], "do not bind rendered documents"),
        ("reachable_named_templates", ["same", "same"], "not canonical"),
    ),
)
def test_helm_semantic_validator_rejects_a6_action_structure_mutation(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path))
    proof = payload["materialization"]["baseline"]["render_inputs"][
        "template_action_reachability"
    ]
    proof[field] = value

    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("provenance_identity", "0" * 64, "namespace provenance"),
        ("effective_namespace", "escape", "effective namespace"),
        ("source_template", "templates/escape.yaml", "namespace source"),
    ),
)
def test_helm_semantic_validator_rejects_a6_namespace_proof_mutation(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path))
    proof = payload["materialization"]["baseline"]["documents"][0][
        "namespace_provenance"
    ]
    proof[field] = value
    baseline = payload["materialization"]["baseline"]
    baseline["output"]["document_inventory_sha256"] = REPORT._canonical_json_digest(
        baseline["documents"]
    )

    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("request_namespace", "escape", "namespace inputs"),
        ("resolution", "CLUSTER_SCOPED", "cluster-scoped namespace"),
    ),
)
def test_helm_semantic_validator_rejects_a6_namespace_structure_mutation(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path))
    baseline = payload["materialization"]["baseline"]
    baseline["documents"][0]["namespace_provenance"][field] = value
    baseline["output"]["document_inventory_sha256"] = REPORT._canonical_json_digest(
        baseline["documents"]
    )

    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    (
        (("baseline", "chart", "inventory_root_sha256"), "0" * 64, "inventory root"),
        (("baseline", "output", "rendered_bundle_sha256"), "0" * 64, "stdout and bundle"),
        (("comparison_identity",), "0" * 64, "comparison identity"),
    ),
)
def test_helm_semantic_validator_rejects_tampering(
    tmp_path: Path, path: tuple, value: str, message: str
) -> None:
    payload = copy.deepcopy(_semantic_payload(tmp_path))
    current = payload["materialization"]
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value
    with pytest.raises(DomainError, match=message):
        REPORT._validate_helm_materialization(payload)


def test_helm_semantic_validator_rejects_uninventoried_source(tmp_path: Path) -> None:
    payload = _semantic_payload(tmp_path)
    baseline = payload["materialization"]["baseline"]
    baseline["documents"][0]["source_template"] = "missing.yaml"
    baseline["output"]["document_inventory_sha256"] = REPORT._canonical_json_digest(
        baseline["documents"]
    )
    with pytest.raises(DomainError, match="outside chart inventory"):
        REPORT._validate_helm_materialization(payload)


def test_helm_semantic_validator_rejects_scanner_and_graph_escape(
    tmp_path: Path,
) -> None:
    payload = _semantic_payload(tmp_path)
    graph_payload = copy.deepcopy(payload)
    payload["verification"]["baseline_run"]["input_files"][0]["sha256"] = "0" * 64
    with pytest.raises(DomainError, match="exact scanner input"):
        REPORT._validate_helm_materialization(payload)

    graph_payload["verification"]["candidate_run"]["evaluations"] = [{
        "graph_evidence": {
            "participants": [{"resource_address": "v1/Pod/default/escape"}]
        }
    }]
    with pytest.raises(DomainError, match="graph participant is not rendered"):
        REPORT._validate_helm_materialization(graph_payload)


def _unconstructed_verification_report(pair, *, escape: bool = False):
    runs = []
    for evidence in (pair.baseline, pair.candidate):
        participant = SimpleNamespace(
            resource_address=(
                "v1/Pod/default/escape"
                if escape
                else evidence.documents[0].resource_identity
            )
        )
        graph = SimpleNamespace(participants=(participant,))
        runs.append(SimpleNamespace(
            input_files=(SimpleNamespace(
                file_path="rendered.yaml",
                sha256=evidence.output["rendered_bundle_sha256"],
            ),),
            evaluations=(SimpleNamespace(graph_evidence=graph),),
        ))
    verification = SimpleNamespace(
        baseline_run=runs[0],
        candidate_run=runs[1],
    )
    policy = SimpleNamespace(verdict=Verdict.VERIFIED, exit_code=0)
    report = object.__new__(VerificationReportV1)
    object.__setattr__(report, "verification", verification)
    object.__setattr__(report, "policy_result", policy)
    object.__setattr__(report, "execution_isolation", object())
    return report


def test_helm_report_binds_scanner_inputs_graph_and_public_projection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = tmp_path / "report-baseline"
    second = tmp_path / "report-candidate"
    first.mkdir()
    second.mkdir()
    with HELM.materialize_helm_comparison(_spec(first), _spec(second)) as pair:
        verification = _unconstructed_verification_report(pair)
        report = REPORT.HelmVerificationReportV1(verification, pair)
        monkeypatch.setattr(
            VerificationReportV1,
            "canonical_dict",
            lambda _self: {
                "schema_version": "report-v1",
                "result_kind": "verification",
                "verdict": "VERIFIED",
                "exit_code": 0,
            },
        )
        monkeypatch.setattr(REPORT, "validate_report_payload", lambda _payload: None)
        assert report.verdict is Verdict.VERIFIED
        assert report.exit_code == 0
        assert report.canonical_dict()["materialization"]["contract"] == (
            "helm-comparison-v1"
        )
        canonical = report.canonical_json()
        assert canonical.endswith("\n")
        assert report.report_sha256 == hashlib.sha256(canonical.encode()).hexdigest()


def test_helm_report_rejects_wrong_types_unbound_input_and_graph_escape(
    tmp_path: Path,
) -> None:
    first = tmp_path / "report-baseline"
    second = tmp_path / "report-candidate"
    first.mkdir()
    second.mkdir()
    with HELM.materialize_helm_comparison(_spec(first), _spec(second)) as pair:
        with pytest.raises(DomainError, match="exact verification report"):
            REPORT.HelmVerificationReportV1(object(), pair)
        verification = _unconstructed_verification_report(pair)
        with pytest.raises(DomainError, match="protected comparison evidence"):
            REPORT.HelmVerificationReportV1(verification, object())

        bad_input = _unconstructed_verification_report(pair)
        bad_input.verification.baseline_run.input_files[0].sha256 = "0" * 64
        with pytest.raises(DomainError, match="does not bind scanner input"):
            REPORT.HelmVerificationReportV1(bad_input, pair)

        escape = _unconstructed_verification_report(pair, escape=True)
        with pytest.raises(DomainError, match="escapes rendered resources"):
            REPORT.HelmVerificationReportV1(escape, pair)
