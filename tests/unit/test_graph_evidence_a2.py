"""0.1.0a2 bounded graph-evidence regressions."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import iac_guard_v.graph_evidence as GRAPH
import iac_guard_v.report as REPORT
import iac_guard_v.terraform_parser as TERRAFORM_PARSER
from iac_guard_v.adapters.checkov import checkov_occurrence_token
from iac_guard_v.enums import ArtifactKind, CheckEvaluationResult, Status
from iac_guard_v.models import BoundInputFile, DomainError, ExpectedResource
from iac_guard_v.models import GraphEdgeEvidence, GraphParticipant


AWS_POLICY = {
    "metadata": {"id": "CKV2_AWS_TEST"},
    "definition": {
        "and": [
            {
                "cond_type": "connection",
                "operator": "exists",
                "resource_types": ["aws_s3_bucket"],
                "connected_resource_types": ["aws_s3_bucket_public_access_block"],
            },
            {
                "cond_type": "filter",
                "attribute": "resource_type",
                "operator": "within",
                "value": ["aws_s3_bucket"],
            },
            {
                "cond_type": "attribute",
                "attribute": "block_public_acls",
                "operator": "equals",
                "value": True,
                "resource_types": ["aws_s3_bucket_public_access_block"],
            },
            {
                "cond_type": "attribute",
                "attribute": "block_public_policy",
                "operator": "equals",
                "value": True,
                "resource_types": ["aws_s3_bucket_public_access_block"],
            },
        ]
    },
}

KUBERNETES_POLICY = {
    "metadata": {"id": "CKV2_K8S_TEST"},
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
                "resource_types": ["Pod", "Deployment"],
                "connected_resource_types": ["NetworkPolicy"],
            },
        ]
    },
}


def _write_policy(root: Path, framework: str, name: str, value: dict) -> None:
    path = root / framework / "checks" / "graph_checks" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _bound_file(root: Path, relative: str) -> BoundInputFile:
    path = root / relative
    metadata = path.stat()
    payload = path.read_bytes()
    return BoundInputFile(
        relative,
        "terraform_hcl" if relative.endswith(".tf") else "kubernetes_yaml",
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        metadata.st_dev,
        metadata.st_ino,
    )


def _terraform_resource(path: str, address: str) -> ExpectedResource:
    return ExpectedResource(path, address, ArtifactKind.TERRAFORM_HCL, address)


def _context(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    policies: Path,
    frameworks: tuple[str, ...],
    resources: tuple[ExpectedResource, ...],
) -> GRAPH.GraphEvidenceContext:
    monkeypatch.setattr(GRAPH, "_installation_roots", lambda _executable: (policies,))
    return GRAPH.build_graph_evidence_context(
        executable=Path("/protected/checkov"),
        scan_root=root,
        frameworks=frameworks,
        expected_resources=resources,
        input_files=tuple(_bound_file(root, item) for item in sorted({r.file_path for r in resources})),
        source_snapshot_sha256="b" * 64,
        policy_inventory_sha256="a" * 64,
    )


def test_terraform_graph_failure_and_cross_file_repair_are_exactly_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "terraform", "aws/policy.json", AWS_POLICY)
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "bucket.tf").write_text(
        'resource "aws_s3_bucket" "data" { bucket = "example" }\n',
        encoding="utf-8",
    )
    baseline_resources = (_terraform_resource("bucket.tf", "aws_s3_bucket.data"),)
    before = _context(monkeypatch, baseline, policies, ("terraform",), baseline_resources)
    failed = before.evidence_for(
        framework="terraform",
        file_path="bucket.tf",
        native_resource="aws_s3_bucket.data",
        rule_id="CKV2_AWS_TEST",
        check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.FAILED,
    )

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "bucket.tf").write_text(
        'resource "aws_s3_bucket" "data" { bucket = "example" }\n',
        encoding="utf-8",
    )
    (candidate / "access.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "data" {\n'
        '  bucket = aws_s3_bucket.data.id\n'
        '  block_public_acls = true\n'
        '  block_public_policy = true\n'
        '}\n',
        encoding="utf-8",
    )
    candidate_resources = (
        _terraform_resource("bucket.tf", "aws_s3_bucket.data"),
        _terraform_resource(
            "access.tf", "aws_s3_bucket_public_access_block.data"
        ),
    )
    after = _context(monkeypatch, candidate, policies, ("terraform",), candidate_resources)
    passed = after.evidence_for(
        framework="terraform",
        file_path="bucket.tf",
        native_resource="aws_s3_bucket.data",
        rule_id="CKV2_AWS_TEST",
        check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )

    assert failed is not None and failed.status is Status.PASS
    assert failed.participants == (failed.primary,)
    assert failed.edges == ()
    assert passed is not None and passed.status is Status.PASS
    assert {item.resource_address for item in passed.participants} == {
        "aws_s3_bucket.data",
        "aws_s3_bucket_public_access_block.data",
    }
    assert len(passed.edges) == 1
    assert passed.edges[0].relation_type == "terraform_reference"
    assert failed.canonical_sha256 != passed.canonical_sha256

    stable_before = checkov_occurrence_token(
        "3.3.0", ArtifactKind.TERRAFORM_HCL, "bucket.tf",
        "CKV2_AWS_TEST", "aws_s3_bucket.data", (), "native-fingerprint",
    )
    stable_after = checkov_occurrence_token(
        "3.3.0", ArtifactKind.TERRAFORM_HCL, "bucket.tf",
        "CKV2_AWS_TEST", "aws_s3_bucket.data", (), "native-fingerprint",
    )
    assert stable_before == stable_after


def test_graph_pass_cannot_be_proven_from_one_textual_resource(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "terraform", "aws/policy.json", AWS_POLICY)
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" {}\n', encoding="utf-8"
    )
    context = _context(
        monkeypatch,
        root,
        policies,
        ("terraform",),
        (_terraform_resource("main.tf", "aws_s3_bucket.data"),),
    )

    evidence = context.evidence_for(
        framework="terraform",
        file_path="main.tf",
        native_resource="aws_s3_bucket.data",
        rule_id="CKV2_AWS_TEST",
        check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )

    assert evidence is not None
    assert evidence.status is Status.INCONCLUSIVE
    assert evidence.reason_code == "GRAPH_RESULT_MISMATCH"


def test_multiple_exact_relationships_are_preserved_without_false_ambiguity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "terraform", "aws/policy.json", AWS_POLICY)
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" {}\n'
        'resource "aws_s3_bucket_public_access_block" "first" {\n'
        '  bucket = aws_s3_bucket.data.id\n'
        '  block_public_acls = true\n'
        '  block_public_policy = true\n'
        '}\n'
        'resource "aws_s3_bucket_public_access_block" "second" {\n'
        '  bucket = aws_s3_bucket.data.id\n'
        '  block_public_acls = true\n'
        '  block_public_policy = true\n'
        '}\n',
        encoding="utf-8",
    )
    resources = tuple(
        _terraform_resource("main.tf", address)
        for address in (
            "aws_s3_bucket.data",
            "aws_s3_bucket_public_access_block.first",
            "aws_s3_bucket_public_access_block.second",
        )
    )
    context = _context(monkeypatch, root, policies, ("terraform",), resources)

    evidence = context.evidence_for(
        framework="terraform",
        file_path="main.tf",
        native_resource="aws_s3_bucket.data",
        rule_id="CKV2_AWS_TEST",
        check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )

    assert evidence is not None and evidence.status is Status.PASS
    assert len(evidence.participants) == 3
    assert len(evidence.edges) == 2


def test_ambiguous_duplicate_address_and_unresolved_edge_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "terraform", "aws/policy.json", AWS_POLICY)
    root = tmp_path / "source"
    root.mkdir()
    (root / "a.tf").write_text(
        'resource "aws_s3_bucket" "data" {}\n', encoding="utf-8"
    )
    (root / "b.tf").write_text(
        'resource "aws_s3_bucket" "data" {}\n'
        'resource "aws_s3_bucket_public_access_block" "data" {\n'
        '  bucket = aws_s3_bucket.data[0].id\n'
        '  block_public_acls = true\n'
        '  block_public_policy = true\n'
        '}\n',
        encoding="utf-8",
    )
    resources = (
        _terraform_resource("a.tf", "aws_s3_bucket.data"),
        _terraform_resource("b.tf", "aws_s3_bucket.data"),
        _terraform_resource("b.tf", "aws_s3_bucket_public_access_block.data"),
    )
    context = _context(monkeypatch, root, policies, ("terraform",), resources)

    evidence = context.evidence_for(
        framework="terraform",
        file_path="a.tf",
        native_resource="aws_s3_bucket.data",
        rule_id="CKV2_AWS_TEST",
        check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )

    assert evidence is not None
    assert evidence.status is Status.INCONCLUSIVE
    assert evidence.reason_code in {
        "GRAPH_PRIMARY_IDENTITY_AMBIGUOUS",
        "GRAPH_RELATIONSHIP_AMBIGUOUS",
    }


def test_kubernetes_generated_pod_alias_binds_controller_and_network_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "kubernetes", "policy.json", KUBERNETES_POLICY)
    root = tmp_path / "source"
    root.mkdir()
    (root / "resources.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n"
        "spec:\n  template:\n    metadata:\n      labels:\n        app: demo\n"
        "    spec:\n      containers:\n      - name: app\n        image: nginx\n"
        "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
        "metadata:\n  name: app\nspec:\n  podSelector:\n    matchLabels:\n"
        "      app: demo\n",
        encoding="utf-8",
    )
    resources = (
        ExpectedResource(
            "resources.yaml",
            "apps/v1/Deployment/default/app",
            ArtifactKind.KUBERNETES_YAML,
            "Deployment.default.app",
        ),
        ExpectedResource(
            "resources.yaml",
            "networking.k8s.io/v1/NetworkPolicy/default/app",
            ArtifactKind.KUBERNETES_YAML,
            "NetworkPolicy.default.app",
        ),
    )
    context = _context(monkeypatch, root, policies, ("kubernetes",), resources)

    evidence = context.evidence_for(
        framework="kubernetes",
        file_path="resources.yaml",
        native_resource="Pod.default.app.app-demo",
        rule_id="CKV2_K8S_TEST",
        check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )

    assert evidence is not None and evidence.status is Status.PASS
    assert evidence.primary.resource_address == "apps/v1/Deployment/default/app"
    assert {item.resource_type for item in evidence.participants} == {
        "Deployment", "NetworkPolicy",
    }
    assert evidence.edges[0].relation_type == "kubernetes_network_policy_selector"


def test_kubernetes_generated_pod_alias_preserves_declared_label_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "kubernetes", "policy.json", KUBERNETES_POLICY)
    root = tmp_path / "source"
    root.mkdir()
    (root / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n"
        "spec:\n  template:\n    metadata:\n      labels:\n"
        "        z.example/first: one\n        app: demo\n"
        "    spec:\n      containers:\n      - name: app\n        image: nginx\n",
        encoding="utf-8",
    )
    resources = (
        ExpectedResource(
            "deployment.yaml",
            "apps/v1/Deployment/default/app",
            ArtifactKind.KUBERNETES_YAML,
            "Deployment.default.app",
        ),
    )
    context = _context(monkeypatch, root, policies, ("kubernetes",), resources)

    evidence = context.evidence_for(
        framework="kubernetes",
        file_path="deployment.yaml",
        native_resource="Pod.default.app.z.example/first-one.app-demo",
        rule_id="CKV2_K8S_TEST",
        check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.FAILED,
    )

    assert evidence is not None and evidence.status is Status.PASS
    assert evidence.primary.resource_address == "apps/v1/Deployment/default/app"


@pytest.mark.parametrize(
    ("namespace", "name", "pod_name", "labels", "expected"),
    (
        (
            "monitoring",
            "mysql-exporter",
            "mysql-exporter",
            {"k8s-app": "mysql-exporter"},
            ("Pod.monitoring.mysql-exporter",),
        ),
        (
            "default",
            "worker",
            None,
            {"z": "last", "app": "worker"},
            (
                "Pod.default.worker.app-worker.z-last",
                "Pod.default.worker.z-last.app-worker",
            ),
        ),
        ("default", "worker", None, None, ()),
    ),
)
def test_synthetic_pod_aliases_bind_structure_and_treat_labels_as_compatibility(
    namespace: str,
    name: str,
    pod_name: str | None,
    labels: dict[str, str] | None,
    expected: tuple[str, ...],
) -> None:
    assert GRAPH._synthetic_pod_aliases(
        namespace=namespace, workload_name=name, pod_name=pod_name, labels=labels
    ) == tuple(sorted(expected))


def test_synthetic_pod_aliases_do_not_equate_same_labels_across_namespaces_or_names(
) -> None:
    labels = {"app": "shared"}
    first = set(GRAPH._synthetic_pod_aliases(
        namespace="first", workload_name="one", pod_name=None, labels=labels
    ))
    different_namespace = set(GRAPH._synthetic_pod_aliases(
        namespace="second", workload_name="one", pod_name=None, labels=labels
    ))
    different_name = set(GRAPH._synthetic_pod_aliases(
        namespace="first", workload_name="two", pod_name=None, labels=labels
    ))

    assert first.isdisjoint(different_namespace)
    assert first.isdisjoint(different_name)


def test_kubernetes_structural_synthetic_pod_alias_survives_label_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "kubernetes", "policy.json", KUBERNETES_POLICY)
    resources = (
        ExpectedResource(
            "deployment.yaml",
            "apps/v1/Deployment/monitoring/mysql-exporter",
            ArtifactKind.KUBERNETES_YAML,
            "Deployment.monitoring.mysql-exporter",
        ),
        ExpectedResource(
            "deployment.yaml",
            "networking.k8s.io/v1/NetworkPolicy/monitoring/mysql-exporter",
            ArtifactKind.KUBERNETES_YAML,
            "NetworkPolicy.monitoring.mysql-exporter",
        ),
    )
    for suffix, label in (("base", "old"), ("candidate", "new")):
        root = tmp_path / suffix
        root.mkdir()
        (root / "deployment.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\n"
            "metadata: {name: mysql-exporter, namespace: monitoring}\n"
            "spec:\n  template:\n    metadata:\n      labels:\n"
            f"        app: {label}\n"
            "      name: mysql-exporter\n"
            "    spec:\n      containers:\n"
            "      - {name: exporter, image: exporter}\n"
            "      - {name: sidecar, image: sidecar}\n"
            "      initContainers:\n      - {name: init, image: init}\n"
            "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
            "metadata: {name: mysql-exporter, namespace: monitoring}\n"
            "spec:\n  podSelector:\n    matchLabels:\n"
            f"      app: {label}\n",
            encoding="utf-8",
        )
        context = _context(
            monkeypatch, root, policies, ("kubernetes",), resources
        )
        evidence = context.evidence_for(
            framework="kubernetes",
            file_path="deployment.yaml",
            native_resource="Pod.monitoring.mysql-exporter",
            rule_id="CKV2_K8S_TEST",
            check_class=GRAPH._GRAPH_CHECK_CLASS,
            native_result=CheckEvaluationResult.PASSED,
        )

        assert evidence is not None and evidence.status is Status.PASS
        assert evidence.primary.resource_address == (
            "apps/v1/Deployment/monitoring/mysql-exporter"
        )
        assert len(evidence.edges) == 1


@pytest.mark.parametrize(
    ("api_version", "kind", "spec"),
    (
        ("apps/v1", "Deployment", "template"),
        ("apps/v1", "StatefulSet", "template"),
        ("apps/v1", "DaemonSet", "template"),
        ("apps/v1", "ReplicaSet", "template"),
        ("batch/v1", "Job", "template"),
        ("v1", "ReplicationController", "template"),
        ("apps.openshift.io/v1", "DeploymentConfig", "template"),
    ),
)
def test_supported_controller_kinds_bind_exact_structural_synthetic_pod_alias(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    api_version: str,
    kind: str,
    spec: str,
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "kubernetes", "policy.json", KUBERNETES_POLICY)
    root = tmp_path / "source"
    root.mkdir()
    if spec == "jobTemplate":
        nested = (
            "  jobTemplate:\n    spec:\n      template:\n        metadata: {}\n"
            "        spec:\n          containers:\n          - {name: app, image: app}\n"
            "          restartPolicy: Never\n"
        )
    else:
        nested = (
            "  template:\n    metadata: {name: worker}\n"
            "    spec:\n      containers:\n"
            "      - {name: app, image: app}\n      restartPolicy: Never\n"
        )
    (root / "workload.yaml").write_text(
        f"apiVersion: {api_version}\nkind: {kind}\n"
        "metadata: {name: worker, namespace: jobs}\n"
        f"spec:\n{nested}",
        encoding="utf-8",
    )
    resource = ExpectedResource(
        "workload.yaml",
        f"{api_version}/{kind}/jobs/worker",
        ArtifactKind.KUBERNETES_YAML,
        f"{kind}.jobs.worker",
    )
    context = _context(
        monkeypatch, root, policies, ("kubernetes",), (resource,)
    )

    resolved = context._resolve("workload.yaml", "Pod.jobs.worker")

    assert resolved is not None
    assert resolved.participant.resource_address == resource.resource_address
    assert resolved.participant.resource_type == kind


def test_cronjob_is_not_promoted_to_a_checkov_330_synthetic_pod(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "kubernetes", "policy.json", KUBERNETES_POLICY)
    root = tmp_path / "source"
    root.mkdir()
    (root / "cronjob.yaml").write_text(
        "apiVersion: batch/v1\nkind: CronJob\n"
        "metadata: {name: worker, namespace: jobs}\n"
        "spec:\n  jobTemplate:\n    spec:\n      template:\n"
        "        metadata: {labels: {app: worker}}\n"
        "        spec:\n          containers:\n"
        "          - {name: app, image: app}\n          restartPolicy: Never\n",
        encoding="utf-8",
    )
    resource = ExpectedResource(
        "cronjob.yaml",
        "batch/v1/CronJob/jobs/worker",
        ArtifactKind.KUBERNETES_YAML,
        "CronJob.jobs.worker",
    )
    context = _context(monkeypatch, root, policies, ("kubernetes",), (resource,))

    assert context._resolve("cronjob.yaml", "Pod.jobs.worker") is None


def test_structural_synthetic_pod_alias_is_inconclusive_when_two_workloads_collide(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    _write_policy(policies, "kubernetes", "policy.json", KUBERNETES_POLICY)
    root = tmp_path / "source"
    root.mkdir()
    documents = []
    resources = []
    for kind in ("Deployment", "StatefulSet"):
        documents.append(
            f"apiVersion: apps/v1\nkind: {kind}\n"
            "metadata: {name: shared, namespace: same}\n"
            "spec:\n  template:\n    metadata: {labels: {app: shared}}\n"
            "    spec:\n      containers:\n      - {name: app, image: app}\n"
        )
        resources.append(ExpectedResource(
            "workloads.yaml",
            f"apps/v1/{kind}/same/shared",
            ArtifactKind.KUBERNETES_YAML,
            f"{kind}.same.shared",
        ))
    (root / "workloads.yaml").write_text(
        "---\n".join(documents), encoding="utf-8"
    )
    context = _context(
        monkeypatch, root, policies, ("kubernetes",), tuple(resources)
    )

    with pytest.raises(DomainError, match="missing or ambiguous"):
        context._resolve("workloads.yaml", "Pod.same.shared.app-shared")


def test_unsupported_graph_policy_is_typed_inconclusive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policies = tmp_path / "policies"
    unsupported = {
        "metadata": {"id": "CKV2_AWS_UNSUPPORTED"},
        "definition": {"or": []},
    }
    _write_policy(policies, "terraform", "aws/policy.json", unsupported)
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" {}\n', encoding="utf-8"
    )
    context = _context(
        monkeypatch,
        root,
        policies,
        ("terraform",),
        (_terraform_resource("main.tf", "aws_s3_bucket.data"),),
    )

    evidence = context.evidence_for(
        framework="terraform",
        file_path="main.tf",
        native_resource="aws_s3_bucket.data",
        rule_id="CKV2_AWS_UNSUPPORTED",
        check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.FAILED,
    )

    assert evidence is not None
    assert evidence.status is Status.INCONCLUSIVE
    assert evidence.reason_code == "GRAPH_POLICY_OR_CLASS_UNSUPPORTED"


def test_kubernetes_notin_requires_the_selector_key_to_exist() -> None:
    selector = {
        "matchExpressions": [
            {"key": "tier", "operator": "NotIn", "values": ["external"]}
        ]
    }

    assert GRAPH._selector_matches(selector, {}) is False
    assert GRAPH._selector_matches(selector, {"tier": "internal"}) is True
    assert GRAPH._selector_matches(selector, {"tier": "external"}) is False


@pytest.mark.parametrize(
    "selector,labels,expected",
    [
        (None, {}, None),
        ({"matchLabels": []}, {}, None),
        ({"matchLabels": {"app": "a"}}, {"app": "b"}, False),
        ({"matchExpressions": [None]}, {}, None),
        ({"matchExpressions": [{"key": "x", "operator": "In", "values": "a"}]}, {}, None),
        ({"matchExpressions": [{"key": "x", "operator": "In", "values": ["a"]}]}, {}, False),
        ({"matchExpressions": [{"key": "x", "operator": "Exists"}]}, {}, False),
        ({"matchExpressions": [{"key": "x", "operator": "DoesNotExist"}]}, {"x": "a"}, False),
        ({"matchExpressions": [{"key": "x", "operator": "Other"}]}, {}, None),
        ({"matchExpressions": [{"key": "x", "operator": "Exists"}]}, {"x": "a"}, True),
    ],
)
def test_kubernetes_selector_boundaries(selector, labels, expected) -> None:
    assert GRAPH._selector_matches(selector, labels) is expected


def test_workload_label_paths_and_invalid_shapes() -> None:
    assert GRAPH._workload_labels({"metadata": {"labels": {"app": "a"}}}, "Pod") == {
        "app": "a"
    }
    cron = {
        "spec": {"jobTemplate": {"spec": {"template": {"metadata": {
            "labels": {"app": "cron"}
        }}}}}
    }
    assert GRAPH._workload_labels(cron, "CronJob") == {"app": "cron"}
    assert GRAPH._workload_labels({"spec": {"template": {}}}, "Deployment") is None
    assert GRAPH._workload_labels(
        {"metadata": {"labels": {"app": 1}}}, "Pod"
    ) is None


@pytest.mark.parametrize(
    "definition",
    [
        [],
        {"or": []},
        {"and": []},
        {"and": [None]},
        {"and": [{"cond_type": "connection", "operator": "not_exists"}]},
        {"and": [{"cond_type": "connection", "operator": "exists", "resource_types": [], "connected_resource_types": ["b"]}]},
        {"and": [{"cond_type": "filter", "attribute": "wrong", "operator": "within", "value": ["a"]}]},
        {"and": [{"cond_type": "attribute", "operator": "regex", "resource_types": ["a"], "attribute": "x"}]},
        {"and": [{"cond_type": "unknown"}]},
        {"and": [
            {"cond_type": "connection", "operator": "exists", "resource_types": ["a"], "connected_resource_types": ["b"]},
            {"cond_type": "connection", "operator": "exists", "resource_types": ["a"], "connected_resource_types": ["c"]},
        ]},
        {"and": [
            {"cond_type": "connection", "operator": "exists", "resource_types": ["a"], "connected_resource_types": ["b"]},
            {"cond_type": "filter", "attribute": "resource_type", "operator": "within", "value": ["other"]},
        ]},
    ],
)
def test_graph_query_parser_rejects_every_unbounded_shape(definition) -> None:
    policy = {"metadata": {"id": "CKV2_TEST"}, "definition": definition}
    raw = json.dumps(policy).encode()
    assert GRAPH._parse_graph_query(raw, policy, "CKV2_TEST") is None


def test_graph_context_fail_closed_boundaries_and_reverse_edge() -> None:
    primary = GraphParticipant(
        "main.tf", "aws_a.primary", ArtifactKind.TERRAFORM_HCL, "aws_a"
    )
    connected = GraphParticipant(
        "other.tf", "aws_b.connected", ArtifactKind.TERRAFORM_HCL, "aws_b"
    )
    primary_node = GRAPH._GraphNode(primary, ("aws_a",), ("native.primary",), {})
    connected_node = GRAPH._GraphNode(
        connected, ("aws_b",), ("native.connected",), {"enabled": [True]}
    )
    edge = GraphEdgeEvidence(
        connected, primary, "terraform_reference", "resource.x:aws_a.primary"
    )
    query = GRAPH._GraphQuery(
        ("aws_a",), ("aws_b",), (("enabled", ("aws_b",), True),),
        "1" * 64, "2" * 64,
    )
    context = GRAPH.GraphEvidenceContext(
        (primary_node, connected_node), (edge,), (), (), "3" * 64, "4" * 64,
        True, "5" * 64, (("terraform", "CKV2_TEST", query),), (),
        ("terraform",),
    )
    assert context.evidence_for(
        framework="terraform", file_path="main.tf", native_resource="native.primary",
        rule_id="CKV_AWS_1", check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    ) is None
    assert context.evidence_for(
        framework="terraform", file_path="main.tf", native_resource="missing",
        rule_id="CKV2_TEST", check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    ) is None
    complete = context.evidence_for(
        framework="terraform", file_path="main.tf", native_resource="native.primary",
        rule_id="CKV2_TEST", check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )
    assert complete is not None and complete.status is Status.PASS
    skipped = context.evidence_for(
        framework="terraform", file_path="main.tf", native_resource="native.primary",
        rule_id="CKV2_TEST", check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.SKIPPED,
    )
    assert skipped is not None and skipped.status is Status.PASS
    unbound = GRAPH.GraphEvidenceContext(
        context.nodes, context.edges, (), (), context.manifest_sha256,
        context.source_snapshot_sha256, False, context.policy_inventory_sha256,
        context.queries, (), context.frameworks,
    )
    evidence = unbound.evidence_for(
        framework="terraform", file_path="main.tf", native_resource="native.primary",
        rule_id="CKV2_TEST", check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )
    assert evidence is not None and evidence.reason_code == "GRAPH_SNAPSHOT_IDENTITY_UNBOUND"
    wrong_type = GRAPH.GraphEvidenceContext(
        context.nodes, context.edges, (), (), context.manifest_sha256,
        context.source_snapshot_sha256, True, context.policy_inventory_sha256,
        (("terraform", "CKV2_TEST", GRAPH._GraphQuery(
            ("other",), ("aws_b",), (), "1" * 64, "2" * 64
        )),), (), context.frameworks,
    )
    evidence = wrong_type.evidence_for(
        framework="terraform", file_path="main.tf", native_resource="native.primary",
        rule_id="CKV2_TEST", check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )
    assert evidence is not None and evidence.reason_code == "GRAPH_PRIMARY_TYPE_MISMATCH"
    ambiguous = GRAPH.GraphEvidenceContext(
        context.nodes, context.edges, (), (("aws_a.primary", "unresolved"),),
        context.manifest_sha256, context.source_snapshot_sha256, True,
        context.policy_inventory_sha256, context.queries, (), context.frameworks,
    )
    evidence = ambiguous.evidence_for(
        framework="terraform", file_path="main.tf", native_resource="native.primary",
        rule_id="CKV2_TEST", check_class=GRAPH._GRAPH_CHECK_CLASS,
        native_result=CheckEvaluationResult.PASSED,
    )
    assert evidence is not None and evidence.reason_code == "GRAPH_RELATIONSHIP_AMBIGUOUS"


def test_graph_node_and_resolution_invariants() -> None:
    participant = GraphParticipant(
        "a.tf", "aws_a.one", ArtifactKind.TERRAFORM_HCL, "aws_a"
    )
    for args in (
        (object(), ("a",), ("a",), {}),
        (participant, (), ("a",), {}),
        (participant, ("a",), (), {}),
        (participant, ("a",), ("a",), []),
    ):
        with pytest.raises(DomainError):
            GRAPH._GraphNode(*args)
    first = GRAPH._GraphNode(participant, ("aws_a",), ("same",), {})
    second_participant = GraphParticipant(
        "a.tf", "aws_a.two", ArtifactKind.TERRAFORM_HCL, "aws_a"
    )
    second = GRAPH._GraphNode(second_participant, ("aws_a",), ("same",), {})
    context = GRAPH.GraphEvidenceContext(
        (first, second), (), (), (), "1" * 64, "2" * 64, True, "3" * 64,
        (), (), ("terraform",),
    )
    with pytest.raises(DomainError, match="ambiguous"):
        context._resolve("a.tf", "same")


def test_attribute_requirements_are_exact() -> None:
    participant = GraphParticipant(
        "a.tf", "aws_a.one", ArtifactKind.TERRAFORM_HCL, "aws_a"
    )
    node = GRAPH._GraphNode(participant, ("aws_a",), ("a",), {"nested": {"value": 1}})
    assert GRAPH._attributes_satisfy(node, (("missing", ("other",), 1),))
    assert not GRAPH._attributes_satisfy(node, (("nested.missing", ("aws_a",), 1),))
    assert not GRAPH._attributes_satisfy(node, (("nested.value", ("aws_a",), 2),))


def test_policy_discovery_and_launcher_boundaries(tmp_path: Path) -> None:
    launcher_root = tmp_path / "scanner"
    interpreter = launcher_root / "venv" / "bin" / "python"
    launcher = launcher_root / "bin" / "checkov"
    interpreter.parent.mkdir(parents=True)
    launcher.parent.mkdir(parents=True)
    launcher.write_text(f"#!{interpreter}\n", encoding="utf-8")
    package = launcher_root / "venv" / "lib" / "python3.13" / "site-packages" / "checkov"
    package.mkdir(parents=True)
    assert GRAPH._installation_roots(launcher) == (package.resolve(),)
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    with pytest.raises(DomainError, match="launcher"):
        GRAPH._installation_roots(empty)

    policies = tmp_path / "policies"
    graph_root = policies / "terraform" / "checks" / "graph_checks"
    graph_root.mkdir(parents=True)
    (graph_root / "ignored.json").write_text("[]", encoding="utf-8")
    (graph_root / "metadata.json").write_text("{}", encoding="utf-8")
    assert GRAPH._load_graph_queries((policies,), ("other",)) == ()
    assert GRAPH._load_graph_queries((policies,), ("terraform",)) == ()
    malformed = graph_root / "bad.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(DomainError, match="malformed"):
        GRAPH._load_graph_queries((policies,), ("terraform",))
    malformed.unlink()
    oversized = graph_root / "large.json"
    oversized.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(DomainError, match="size"):
        GRAPH._load_graph_queries((policies,), ("terraform",))
    oversized.unlink()
    target = graph_root / "target.json"
    target.write_text(json.dumps(AWS_POLICY), encoding="utf-8")
    link = graph_root / "link.json"
    link.symlink_to(target)
    with pytest.raises(DomainError, match="nonsymlink"):
        GRAPH._load_graph_queries((policies,), ("terraform",))


@pytest.mark.parametrize(
    "document,message",
    [
        ([], "parser returned"),
        ({"data": {}}, "data structure"),
        ({"data": [None]}, "data block"),
        ({"data": [{1: {}}]}, "data identity"),
        ({"data": [{"aws_x": {1: {}}}]}, "data identity"),
        ({"provider": {}}, "provider structure"),
        ({"provider": [None]}, "provider block"),
        ({"provider": [{1: {}}]}, "provider identity"),
        ({"provider": [{"aws": {"alias": 1}}]}, "alias"),
        ({"resource": {}}, "resource structure"),
        ({"resource": [None]}, "resource block"),
        ({"resource": [{1: {}}]}, "resource identity"),
        ({"resource": [{"aws_s3_bucket": {"data": []}}]}, "disagrees"),
    ],
)
def test_terraform_graph_inventory_rejects_malformed_parser_shapes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, document, message: str
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.tf").write_text('resource "aws_s3_bucket" "data" {}\n')
    monkeypatch.setattr(GRAPH.hcl2, "loads", lambda _text: document)
    with pytest.raises(DomainError, match=message):
        GRAPH._terraform_nodes_and_edges(
            root, (_terraform_resource("main.tf", "aws_s3_bucket.data"),)
        )


def test_terraform_auxiliary_inventory_and_recursive_references(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.tf").write_text(
        'provider "aws" { alias = "west" }\n'
        'data "aws_iam_policy_document" "doc" {}\n'
        'resource "aws_s3_bucket" "data" {}\n'
        'resource "aws_s3_bucket_public_access_block" "data" {\n'
        '  bucket = [aws_s3_bucket.data.id]\n'
        '}\n',
        encoding="utf-8",
    )
    resources = (
        _terraform_resource("main.tf", "aws_s3_bucket.data"),
        _terraform_resource("main.tf", "aws_s3_bucket_public_access_block.data"),
    )
    _nodes, edges, _ambiguous, auxiliary = GRAPH._terraform_nodes_and_edges(root, resources)
    assert len(edges) == 1
    assert auxiliary == [
        ("main.tf", "aws.west"),
        ("main.tf", "aws_iam_policy_document.doc"),
    ]


def test_kubernetes_document_shapes(tmp_path: Path) -> None:
    path = tmp_path / "items.json"
    path.write_text(json.dumps({"kind": "List", "items": [{"kind": "Pod"}]}))
    assert GRAPH._kubernetes_documents(path) == ({"kind": "Pod"},)
    path.write_text("{")
    with pytest.raises(DomainError, match="could not parse"):
        GRAPH._kubernetes_documents(path)
    yaml_path = tmp_path / "items.yaml"
    yaml_path.write_text("---\n---\n- not-a-map\n")
    with pytest.raises(DomainError, match="mapping"):
        GRAPH._kubernetes_documents(yaml_path)
    yaml_path.write_text("kind: List\nitems: wrong\n")
    with pytest.raises(DomainError, match="List items"):
        GRAPH._kubernetes_documents(yaml_path)


def test_graph_parser_never_writes_lark_cache_into_verified_distribution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import hcl2.parser as parser_module

    package_cache = tmp_path / "verified-package" / ".lark_cache.bin"
    package_cache.parent.mkdir()
    monkeypatch.setattr(TERRAFORM_PARSER, "_HCL2_SECURE_CACHE_READY", False)
    monkeypatch.setattr(parser_module, "PARSER_FILE", package_cache)
    parser_module.parser.cache_clear()

    with TERRAFORM_PARSER.isolated_hcl2_parser_cache():
        document = GRAPH.hcl2.loads('resource "aws_s3_bucket" "data" {}')

    assert type(document) is dict
    assert parser_module.PARSER_FILE == package_cache
    assert not package_cache.exists()


def test_locked_checkov_legacy_parser_layout_needs_no_package_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hcl2.parser as parser_module

    class LegacyParser:
        def parse(self, text: str) -> dict:
            return {"text": text}

    monkeypatch.setattr(TERRAFORM_PARSER, "_HCL2_SECURE_CACHE_READY", False)
    monkeypatch.delattr(parser_module, "PARSER_FILE")
    monkeypatch.setattr(parser_module, "hcl2", LegacyParser(), raising=False)

    with TERRAFORM_PARSER.isolated_hcl2_parser_cache():
        pass

    assert TERRAFORM_PARSER._HCL2_SECURE_CACHE_READY is True


def test_unknown_parser_cache_layout_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hcl2.parser as parser_module

    monkeypatch.setattr(TERRAFORM_PARSER, "_HCL2_SECURE_CACHE_READY", False)
    monkeypatch.delattr(parser_module, "PARSER_FILE")
    monkeypatch.delattr(parser_module, "hcl2", raising=False)

    with pytest.raises(RuntimeError, match="unsupported python-hcl2"):
        with TERRAFORM_PARSER.isolated_hcl2_parser_cache():
            pass


def _semantic_graph_payload() -> tuple[dict, dict, dict]:
    participant = {
        "file_path": "main.tf",
        "resource_address": "aws_s3_bucket.data",
        "artifact_kind": "terraform_hcl",
        "resource_type": "aws_s3_bucket",
    }
    input_files = [{
        "file_path": "main.tf",
        "artifact_kind": "terraform_hcl",
        "size_bytes": 20,
        "sha256": "1" * 64,
        "device": 1,
        "inode": 2,
    }]
    evaluation = {
        "rule_id": "CKV2_AWS_6",
        "file_path": "main.tf",
        "resource_address": "aws_s3_bucket.data",
        "graph_evidence": {
            "status": "PASS",
            "reason_code": "GRAPH_EVIDENCE_COMPLETE",
            "primary": copy.deepcopy(participant),
            "participants": [copy.deepcopy(participant)],
            "edges": [],
            "input_manifest_sha256": REPORT._canonical_json_digest(input_files),
            "source_snapshot_sha256": "5" * 64,
            "policy_inventory_sha256": "2" * 64,
            "policy_definition_sha256": "3" * 64,
            "query_identity_sha256": "4" * 64,
        },
    }
    run = {
        "input_files": input_files,
        "policy_inventory_digest": "2" * 64,
        "status": "PASS",
    }
    snapshot = {
        "snapshot_sha256": "5" * 64,
        "resources": [{
            "file_path": "main.tf",
            "resource_address": "aws_s3_bucket.data",
            "artifact_kind": "terraform_hcl",
            "scanner_native_lookup": "aws_s3_bucket.data",
        }],
    }
    return evaluation, run, snapshot


def test_report_semantics_bind_graph_evidence_to_snapshot_and_run() -> None:
    evaluation, run, snapshot = _semantic_graph_payload()

    REPORT._validate_graph_evidence(evaluation, run, snapshot, "candidate")

    mutations = []
    bad = copy.deepcopy(evaluation)
    bad["graph_evidence"]["input_manifest_sha256"] = "9" * 64
    mutations.append(bad)
    bad = copy.deepcopy(evaluation)
    bad["graph_evidence"]["participants"][0]["file_path"] = "other.tf"
    mutations.append(bad)
    bad = copy.deepcopy(evaluation)
    bad["graph_evidence"]["participants"][0]["resource_type"] = "aws_iam_role"
    mutations.append(bad)

    for bad in mutations:
        with pytest.raises(DomainError):
            REPORT._validate_graph_evidence(bad, run, snapshot, "candidate")


def test_unrelated_ckv2_evaluation_may_remain_unbound_until_target_selection() -> None:
    evaluation, run, snapshot = _semantic_graph_payload()
    del evaluation["graph_evidence"]

    REPORT._validate_graph_evidence(evaluation, run, snapshot, "candidate")
