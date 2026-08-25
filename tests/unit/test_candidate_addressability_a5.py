"""Adversarial scanner-addressability and target-relevance contracts for a5."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

import iac_guard_v.acceptance as ACCEPTANCE
import iac_guard_v.graph_evidence as GRAPH
from iac_guard_v.adapters.checkov import CheckovKubernetesIdentity
from iac_guard_v.config import PublicAcceptanceProperty
from iac_guard_v.engine import attest_checkov_scan_plan
from iac_guard_v.enums import ArtifactKind, CheckEvaluationResult, Status
from iac_guard_v.models import (
    CheckEvaluation,
    CoverageCounters,
    DomainError,
    ExpectedResource,
    GraphCheckEvidence,
    ResourceCoverage,
    ScannerRun,
)

from test_checkov_adapter import request as adapter_request


POLICY = {
    "metadata": {"id": "CKV2_K8S_6"},
    "definition": {
        "and": [
            {
                "cond_type": "filter",
                "attribute": "resource_type",
                "operator": "within",
                "value": ["Pod"],
            },
            {
                "cond_type": "connection",
                "operator": "exists",
                "resource_types": ["Pod"],
                "connected_resource_types": ["NetworkPolicy"],
            },
        ]
    },
}


def _deployment(name: str, namespace: str = "default", label: str | None = None) -> dict:
    label = label or name
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "template": {
                "metadata": {"labels": {"app": label}},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            }
        },
    }


def _policy(name: str, selector: object, namespace: str = "default") -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"podSelector": selector, "policyTypes": ["Ingress"]},
    }


def _resource(document: dict) -> ExpectedResource:
    metadata = document["metadata"]
    namespace = metadata.get("namespace", "default") or "default"
    address = f"{document['apiVersion']}/{document['kind']}/{namespace}/{metadata['name']}"
    native = f"{document['kind']}.{namespace}.{metadata['name']}"
    return ExpectedResource("pod.yaml", address, ArtifactKind.KUBERNETES_YAML, native)


def _scenario(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    documents: tuple[dict, ...],
    *,
    emitted_workloads: tuple[str, ...] = ("app",),
    corrupt_graph: bool = False,
    parse_error: bool = False,
) -> tuple:
    base_request = adapter_request(tmp_path, frameworks=("kubernetes",))
    payload = "---\n".join(yaml.safe_dump(item, sort_keys=True) for item in documents)
    (base_request.scan_root / "pod.yaml").write_text(payload, encoding="utf-8")
    resources = tuple(_resource(item) for item in documents)
    identities = tuple(
        CheckovKubernetesIdentity(
            resource.file_path,
            resource.scanner_native_lookup,
            document["apiVersion"],
            document["kind"],
            document["metadata"].get("namespace", "default") or "default",
            document["metadata"]["name"],
        )
        for resource, document in zip(resources, documents, strict=True)
    )
    request = replace(
        base_request,
        expected_resources=resources,
        kubernetes_identities=identities,
    )
    plan = attest_checkov_scan_plan(request)
    policy_root = tmp_path / "policies"
    path = policy_root / "kubernetes/checks/graph_checks/network-policy.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(POLICY), encoding="utf-8")
    monkeypatch.setattr(GRAPH, "_installation_roots", lambda _executable: (policy_root,))
    context = GRAPH.build_graph_evidence_context(
        executable=request.executable,
        scan_root=request.scan_root,
        frameworks=request.frameworks,
        expected_resources=plan.resources,
        input_files=request.eligible_file_evidence,
        source_snapshot_sha256=request.source_snapshot_sha256,
        policy_inventory_sha256=request.expected_policy_inventory_sha256,
    )
    monkeypatch.setattr(
        ACCEPTANCE, "build_graph_evidence_context", lambda **_kwargs: context
    )
    evaluations = []
    for workload_name in emitted_workloads:
        workload = next(
            item for item in resources
            if item.resource_address.endswith(f"/Deployment/default/{workload_name}")
        )
        evidence = context.evidence_for(
            framework="kubernetes",
            file_path=workload.file_path,
            native_resource=workload.scanner_native_lookup,
            rule_id="CKV2_K8S_6",
            check_class=GRAPH._GRAPH_CHECK_CLASS,
            native_result=CheckEvaluationResult.PASSED,
        )
        assert evidence is not None
        if corrupt_graph and evidence.status is Status.PASS and len(evidence.participants) > 2:
            evidence = GraphCheckEvidence(
                Status.PASS,
                "GRAPH_EVIDENCE_COMPLETE",
                evidence.primary,
                evidence.participants[:-1],
                evidence.edges[:-1],
                evidence.input_manifest_sha256,
                evidence.source_snapshot_sha256,
                evidence.policy_inventory_sha256,
                evidence.policy_definition_sha256,
                evidence.query_identity_sha256,
            )
        evaluations.append(CheckEvaluation(
            "checkov", "3.3.0", "CKV2_K8S_6", workload.scanner_native_lookup,
            workload.file_path, CheckEvaluationResult.PASSED, (), "passed_checks",
            graph_evidence=evidence,
        ))
    observed = set()
    for evaluation in evaluations:
        workload = next(
            item for item in resources
            if item.file_path == evaluation.file_path
            and item.scanner_native_lookup == evaluation.resource_address
        )
        observed.add(workload.canonical_key)
        if evaluation.graph_evidence is not None:
            for participant in evaluation.graph_evidence.participants:
                match = next(
                    item for item in resources
                    if item.file_path == participant.file_path
                    and item.resource_address == participant.resource_address
                )
                observed.add(match.canonical_key)
    missing = tuple(item for item in resources if item.canonical_key not in observed)
    diagnostics = (
        ("COVERAGE_MISMATCH",) + tuple(
            f"missing evaluation resource: {item.file_path}@{item.resource_address}"
            for item in missing
        )
        if missing else ("COMPLETED",)
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    run = ScannerRun._from_adapter(
        scanner="checkov",
        scanner_version="3.3.0",
        status=Status.PARTIAL if missing or parse_error else Status.PASS,
        findings=(),
        coverage=CoverageCounters(
            1, 1, 0 if parse_error else 1, 1 if parse_error else 0,
            len(evaluations), 0, 1 if parse_error else 0,
        ),
        resource_coverage=ResourceCoverage(
            len(resources), len(observed), len(observed), len(missing), 0,
            len(observed), ("kubernetes_graph_primary_aliases",),
        ),
        exit_code=1 if parse_error else 0,
        stdout_sha256=digest,
        stderr_sha256=digest,
        raw_output_sha256=digest,
        resolved_launcher_path="/protected/checkov",
        launcher_digest=digest,
        scanner_environment_digest=digest,
        policy_inventory_digest=request.expected_policy_inventory_sha256,
        invocation_config_digest=digest,
        ruleset_integrity=Status.PASS,
        evaluations=tuple(evaluations),
        input_files=request.eligible_file_evidence,
        diagnostics=diagnostics,
    )
    return plan, run, resources


def _build(plan, run, target: ExpectedResource, executable: Path):
    property_ = PublicAcceptanceProperty(
        "CKV2_K8S_6", target.resource_address, target.file_path,
        ArtifactKind.KUBERNETES_YAML,
    )
    return ACCEPTANCE.build_candidate_evidence_universes(
        plan=plan, run=run, properties=(property_,), executable=executable
    )


def test_target_can_verify_with_selecting_and_external_unaddressed_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    documents = (
        _deployment("app"),
        _policy("app", {"matchLabels": {"app": "app"}}),
        _policy("solver", {"matchLabels": {"acme.cert-manager.io/http01-solver": "true"}}),
    )
    plan, run, resources = _scenario(monkeypatch, tmp_path, documents)
    universes = _build(plan, run, resources[0], plan.executable)

    assert universes.status is Status.PASS
    assert universes.raw_scanner_status_accepted is True
    assert universes.missing_standalone_evaluations == (resources[2],)
    assert universes.addressability[2].classification == (
        "GOVERNED_NON_TARGET_SCANNER_UNADDRESSED"
    )
    target = universes.targets[0]
    assert target.participants == (resources[1],)
    assert target.irrelevant_relationship_resources[0].resource == resources[2]
    assert target.irrelevant_relationship_resources[0].reason_code == "SELECTOR_DISJOINT"


@pytest.mark.parametrize(
    ("policy", "reason"),
    (
        (_policy("other-namespace", {"matchLabels": {"app": "app"}}, "other"),
         "NAMESPACE_DISJOINT"),
        (_policy("other-label", {"matchLabels": {"app": "other"}}),
         "SELECTOR_DISJOINT"),
    ),
)
def test_irrelevance_requires_namespace_or_selector_proof(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy: dict, reason: str
) -> None:
    documents = (
        _deployment("app"),
        _policy("app", {"matchLabels": {"app": "app"}}),
        policy,
    )
    plan, run, resources = _scenario(monkeypatch, tmp_path, documents)
    universes = _build(plan, run, resources[0], plan.executable)
    assert universes.status is Status.PASS
    assert universes.targets[0].irrelevant_relationship_resources[0].reason_code == reason


def test_second_selecting_policy_cannot_be_omitted_from_graph_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    documents = (
        _deployment("app"),
        _policy("first", {"matchLabels": {"app": "app"}}),
        _policy("second", {"matchLabels": {"app": "app"}}),
    )
    plan, run, resources = _scenario(
        monkeypatch, tmp_path, documents, corrupt_graph=True
    )
    universes = _build(plan, run, resources[0], plan.executable)
    assert universes.status is Status.INCONCLUSIVE
    assert universes.targets[0].status is Status.INCONCLUSIVE


def test_unknown_selector_remains_inconclusive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    documents = (
        _deployment("app"),
        _policy("unknown", {"matchExpressions": [{"key": "app", "operator": "Future"}]}),
    )
    plan, run, resources = _scenario(monkeypatch, tmp_path, documents)
    universes = _build(plan, run, resources[0], plan.executable)
    assert universes.status is Status.INCONCLUSIVE
    assert universes.targets[0].unresolved_relationship_resource_count == 1


def test_policy_selecting_multiple_workloads_is_relevant_to_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    documents = (
        _deployment("app", label="shared"),
        _deployment("peer", label="shared"),
        _policy("shared", {"matchLabels": {"app": "shared"}}),
    )
    plan, run, resources = _scenario(
        monkeypatch, tmp_path, documents, emitted_workloads=("app", "peer")
    )
    universes = _build(plan, run, resources[0], plan.executable)
    assert universes.status is Status.PASS
    assert universes.targets[0].participants == (resources[2],)


def test_missing_primary_evaluation_and_parser_failure_remain_inconclusive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    documents = (
        _deployment("app"),
        _policy("app", {"matchLabels": {"app": "app"}}),
    )
    plan, run, resources = _scenario(
        monkeypatch, tmp_path, documents, emitted_workloads=()
    )
    assert _build(plan, run, resources[0], plan.executable).status is Status.INCONCLUSIVE

    other = tmp_path / "parser"
    other.mkdir()
    plan, run, resources = _scenario(
        monkeypatch, other, documents, parse_error=True
    )
    assert _build(plan, run, resources[0], plan.executable).status is Status.INCONCLUSIVE


def test_non_graph_target_without_evaluation_retains_conservative_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan, run, resources = _scenario(
        monkeypatch,
        tmp_path,
        (_deployment("app"),),
        emitted_workloads=(),
    )
    property_ = PublicAcceptanceProperty(
        "CKV_K8S_20", resources[0].resource_address, resources[0].file_path,
        ArtifactKind.KUBERNETES_YAML,
    )
    universes = ACCEPTANCE.build_candidate_evidence_universes(
        plan=plan, run=run, properties=(property_,), executable=plan.executable
    )
    assert universes.status is Status.INCONCLUSIVE
    assert universes.addressability[0].classification == "CONSERVATIVE_SCANNER_ADDRESSABLE"


def test_addressability_evidence_models_reject_untrusted_or_incomplete_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    documents = (
        _deployment("app"),
        _policy("app", {"matchLabels": {"app": "app"}}),
        _policy("other", {"matchLabels": {"app": "other"}}),
    )
    plan, run, resources = _scenario(monkeypatch, tmp_path, documents)
    universes = _build(plan, run, resources[0], plan.executable)
    address = universes.addressability[0]
    proof = universes.targets[0].irrelevant_relationship_resources[0]
    target = universes.targets[0]

    for kwargs, message in (
        ({"resource": object()}, "independently governed"),
        ({"classification": "IGNORED"}, "unsupported"),
        ({"rule_ids": ()}, "requires selected"),
        ({"rule_ids": ("CKV_X", "CKV_X")}, "duplicate rules"),
    ):
        with pytest.raises(DomainError, match=message):
            replace(address, **kwargs)
    for kwargs, message in (
        ({"target": object()}, "bind governed"),
        ({"reason_code": "FILENAME"}, "unsupported"),
        ({"selector_sha256": "bad"}, "lowercase SHA-256"),
    ):
        with pytest.raises(DomainError, match=message):
            replace(proof, **kwargs)
    for kwargs, message in (
        ({"selector": {}}, "selector is invalid"),
        ({"primary": object()}, "primary must be governed"),
        ({"participants": (object(),)}, "participants must be governed"),
        ({"participants": (resources[1], resources[1])}, "participants are duplicated"),
        ({"irrelevant_relationship_resources": (object(),)}, "exact records"),
        ({"irrelevant_relationship_resources": (proof, proof)}, "evidence is duplicated"),
        ({"relationship_resource_count": -1}, "must be nonnegative"),
        ({"unresolved_relationship_resource_count": -1}, "must be nonnegative"),
        ({"relationship_resource_count": 99}, "accounting is incomplete"),
        ({"policy_definition_sha256": "bad"}, "lowercase SHA-256"),
        ({"status": "PASS"}, "status must be closed"),
    ):
        with pytest.raises(DomainError, match=message):
            replace(target, **kwargs)

    trusted = ACCEPTANCE._TRUSTED_UNIVERSE_CONTEXT
    for kwargs, message in (
        ({"governed_resources": (object(),)}, "must be exact"),
        ({"governed_resources": (resources[0], resources[0])}, "is duplicated"),
        ({"addressability": (object(),)}, "must be exact"),
        ({"addressability": universes.addressability[:-1]}, "classify every"),
        ({"targets": ()}, "must be nonempty"),
        ({"missing_standalone_evaluations": (object(),)}, "must bind governed"),
        ({"missing_standalone_evaluations": (resources[2], resources[2])},
         "identity is invalid"),
        ({"status": "PASS"}, "status must be closed"),
        ({"raw_scanner_status_accepted": 1}, "must be Boolean"),
    ):
        with pytest.raises(DomainError, match=message):
            replace(universes, _trusted_context=trusted, **kwargs)
    incomplete_target = replace(target, status=Status.INCONCLUSIVE)
    with pytest.raises(DomainError, match="cannot contain an incomplete target"):
        replace(
            universes, targets=(incomplete_target,), status=Status.PASS,
            _trusted_context=trusted,
        )
    with pytest.raises(DomainError, match="protected derivation"):
        replace(universes)
    with pytest.raises(DomainError, match="no unique target"):
        universes.target_for(PublicAcceptanceProperty("CKV2_K8S_6", "outside"))


def test_graph_contract_fallbacks_and_missing_target_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    documents = (
        _deployment("app"),
        _policy("app", {"matchLabels": {"app": "app"}}),
    )
    plan, run, resources = _scenario(monkeypatch, tmp_path, documents)
    property_ = PublicAcceptanceProperty(
        "CKV2_K8S_6", resources[0].resource_address, resources[0].file_path,
        ArtifactKind.KUBERNETES_YAML,
    )
    original = ACCEPTANCE.build_graph_evidence_context()

    def build_with(context):
        monkeypatch.setattr(
            ACCEPTANCE, "build_graph_evidence_context", lambda **_kwargs: context
        )
        return ACCEPTANCE.build_candidate_evidence_universes(
            plan=plan, run=run, properties=(property_,), executable=plan.executable
        )

    monkeypatch.setattr(
        ACCEPTANCE,
        "build_graph_evidence_context",
        lambda **_kwargs: (_ for _ in ()).throw(DomainError("unavailable")),
    )
    assert ACCEPTANCE.build_candidate_evidence_universes(
        plan=plan, run=run, properties=(property_,), executable=plan.executable
    ).reason_code.startswith("CONSERVATIVE_")

    assert build_with(replace(original, queries=())).reason_code.startswith("CONSERVATIVE_")
    query = original.queries[0][2]
    assert query is not None
    unsupported_query = replace(query, primary_types=("Deployment",))
    unsupported_context = replace(
        original, queries=(("kubernetes", "CKV2_K8S_6", unsupported_query),)
    )
    assert build_with(unsupported_context).reason_code.startswith("CONSERVATIVE_")

    missing = PublicAcceptanceProperty(
        "CKV2_K8S_6", "apps/v1/Deployment/default/missing", "pod.yaml",
        ArtifactKind.KUBERNETES_YAML,
    )
    monkeypatch.setattr(
        ACCEPTANCE, "build_graph_evidence_context", lambda **_kwargs: original
    )
    universes = ACCEPTANCE.build_candidate_evidence_universes(
        plan=plan, run=run, properties=(missing,), executable=plan.executable
    )
    assert universes.status is Status.INCONCLUSIVE
    assert universes.targets[0].reason_code == "TARGET_GRAPH_IDENTITY_INCOMPLETE"


def test_structurally_matching_policy_without_bound_edge_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    documents = (
        _deployment("app"),
        _policy("app", {"matchLabels": {"app": "app"}}),
    )
    plan, run, resources = _scenario(monkeypatch, tmp_path, documents)
    context = ACCEPTANCE.build_graph_evidence_context()
    monkeypatch.setattr(
        ACCEPTANCE,
        "build_graph_evidence_context",
        lambda **_kwargs: replace(context, edges=()),
    )
    universes = _build(plan, run, resources[0], plan.executable)
    assert universes.status is Status.INCONCLUSIVE
    assert universes.targets[0].unresolved_relationship_resource_count == 1
