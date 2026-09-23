"""Executable external-case compatibility manifest for the 1.0 release gate."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from iac_guard_v.contracts.report import validate_contract_report_payload
from iac_guard_v.native_properties.registry import NATIVE_PROPERTY_REGISTRY
from iac_guard_v.native_properties.report import validate_native_report_payload
from iac_guard_v.report import validate_report_payload


@dataclass(frozen=True, slots=True)
class ExternalCase:
    case_id: str
    public_url: str
    evidence_paths: tuple[str, ...]
    report_globs: tuple[str, ...] = ()
    semantic_tests: tuple[str, ...] = ()
    property_ids: tuple[str, ...] = ()
    required_outcomes: tuple[str, ...] = ()
    dependency_kind: str = "EVIDENCE_METHOD_REPLAY"


_MONITOR_TESTS = (
    "tests/unit/test_native_kubernetes_a9.py",
    "tests/unit/test_native_adversarial_a9.py",
    "tests/unit/test_contract_core_a10.py",
)
_RBAC_TESTS = (
    "tests/unit/test_native_rbac_scope_a9.py",
    "tests/unit/test_native_adversarial_a9.py",
)
_OPENTOFU_TESTS = (
    "tests/unit/test_native_opentofu_beta1.py",
    "tests/unit/test_native_adversarial_a9.py",
)
_NETWORK_TESTS = (
    "tests/unit/test_native_kubernetes_a9.py",
    "tests/unit/test_native_adversarial_a9.py",
    "tests/unit/test_contract_real_world_a10.py",
)

CASES = (
    ExternalCase(
        "k8sgpt-operator-846", "https://github.com/k8sgpt-ai/k8sgpt-operator/pull/846",
        ("beta1-adoption/k8sgpt-operator/base-update-d27dd21/validation/semantic-summary.json",),
        ("beta1-adoption/k8sgpt-operator/base-update-d27dd21/validation/**/report.json",),
        _MONITOR_TESTS, ("IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1",),
        ("SATISFIED", "VIOLATED", "NOT_EVALUATED"), "DIRECT_CONTRACT_CONSUMER",
    ),
    ExternalCase(
        "iacsecbench-88", "https://github.com/mchittineni/iacsecbench/pull/88",
        ("tmp/iacsecbench-upstream-integration/evaluation/paired_verification.py", "tmp/iacsecbench-upstream-integration/evaluation/tests/test_paired_verification.py"),
        semantic_tests=("tests/unit/test_beta1_api_ux.py", "tests/unit/test_cli_ux1.py"),
        dependency_kind="EXTERNAL_REPORT_AND_EXIT_CODE_CONSUMER",
    ),
    ExternalCase(
        "iacsecbench-86", "https://github.com/mchittineni/iacsecbench/issues/86",
        ("tmp/ocms-fmd-draft/live-github/iacsecbench_issue_86.json",),
        semantic_tests=("tests/unit/test_beta1_api_ux.py", "tests/unit/test_cli_ux1.py"),
        dependency_kind="DIRECT_CONTRACT_PROPOSAL",
    ),
    ExternalCase(
        "argo-helm-4075", "https://github.com/argoproj/argo-helm/pull/4075",
        ("tmp/beta1-next-adoption-screen/argo-helm-pr-4075/pr-final.json",),
        ("tmp/beta1-next-adoption-screen/argo-helm-pr-4075/baseline.json", "tmp/beta1-next-adoption-screen/argo-helm-pr-4075/mutation-*.json"),
        _MONITOR_TESTS, ("IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1",),
        ("SATISFIED", "VIOLATED", "NOT_EVALUATED"), "DIRECT_CONTRACT_PROPOSAL",
    ),
    ExternalCase(
        "cloudnative-pg-1025", "https://github.com/cloudnative-pg/charts/issues/1025",
        ("tmp/cnpg-1025-readiness/validation/cnpg-a-plan.json",),
        ("tmp/cnpg-1025-readiness/validation/cnpg-a-*.json",), _MONITOR_TESTS,
        ("IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1",),
        ("SATISFIED", "VIOLATED", "NOT_EVALUATED"), "DIRECT_CONTRACT_PROPOSAL",
    ),
    ExternalCase(
        "cert-manager-9366-9367", "https://github.com/cert-manager/cert-manager/pull/9367",
        ("tmp/cert-manager-9366-evidence/contract.yaml",),
        ("tmp/cert-manager-9366-evidence/*report.json",), _MONITOR_TESTS,
        ("IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1",),
        ("SATISFIED", "VIOLATED", "NOT_EVALUATED"),
    ),
    ExternalCase(
        "dflook-ghsa-jx2g-vpm3-9627", "https://github.com/dflook/terraform-github-actions/security/advisories/GHSA-jx2g-vpm3-9627",
        ("tmp/dflook-private-security-report/SUBMISSION_MANIFEST.sha256",),
        semantic_tests=_OPENTOFU_TESTS,
    ),
    ExternalCase(
        "pre-commit-terraform-1013-1014", "https://github.com/antonbabenko/pre-commit-terraform/pull/1014",
        ("PRE_COMMIT_TERRAFORM_1013_FIX_VERIFICATION.md",), semantic_tests=_OPENTOFU_TESTS,
        property_ids=("IACGV_OPENTOFU_REFERENCE_RESOLVES_V1",),
    ),
    ExternalCase(
        "kubescape-805-806", "https://github.com/kubescape/regolibrary/pull/806",
        ("beta1-adoption/kubescape-unresolved-targetport/contracts.yaml",),
        ("beta1-adoption/kubescape-unresolved-targetport/*report.json",), _MONITOR_TESTS,
        ("IACGV_K8S_SERVICE_PORT_RESOLVES_TO_CONTAINER_PORT_V1",),
        ("SATISFIED", "VIOLATED", "NOT_EVALUATED"),
    ),
    ExternalCase(
        "kube-linter-1255", "https://github.com/stackrox/kube-linter/pull/1255",
        ("KUBE_LINTER_RBAC_CLUSTERROLE_PR_BODY.md",), semantic_tests=_RBAC_TESTS,
        property_ids=("IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1", "IACGV_K8S_RBAC_BINDING_SCOPE_CONSISTENT_V1"),
    ),
    ExternalCase(
        "kube-linter-1256", "https://github.com/stackrox/kube-linter/issues/1256",
        ("beta1-adoption/kube-linter-servicemonitor-namespace/contracts.yaml",),
        ("beta1-adoption/kube-linter-servicemonitor-namespace/*report.json",), _MONITOR_TESTS,
        ("IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1",), ("SATISFIED", "VIOLATED"),
    ),
    ExternalCase(
        "trivy-11181-11192-11193", "https://github.com/aquasecurity/trivy/pull/11193",
        ("external-impact-evidence/trivy-opentofu-precedence-private/json-request.json",),
        semantic_tests=_OPENTOFU_TESTS, property_ids=("IACGV_OPENTOFU_REFERENCE_RESOLVES_V1",),
    ),
    ExternalCase(
        "checkov-7668", "https://github.com/bridgecrewio/checkov/issues/7668",
        ("tmp/checkov-networkpolicy-differential/positive-request.json",),
        semantic_tests=("tests/unit/test_scanner_neutral_a8.py", "tests/unit/test_native_kubernetes_a9.py"),
    ),
    ExternalCase(
        "kics-8107", "https://github.com/Checkmarx/kics/issues/8107",
        ("BETA1_EXTERNAL_IMPACT_CAMPAIGN_1.md",),
        semantic_tests=(
            "tests/unit/test_scanner_neutral_a8.py",
            "tests/unit/test_native_kubernetes_a9.py",
            "tests/unit/test_native_adversarial_a9.py",
        ),
        property_ids=("IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1",),
    ),
    ExternalCase(
        "tofu-ls-187", "https://github.com/opentofu/tofu-ls/issues/187",
        ("TOFU_LS_PUBLIC_DEFECT_REPORT_RECORD.md",), semantic_tests=_OPENTOFU_TESTS,
        property_ids=("IACGV_OPENTOFU_REFERENCE_RESOLVES_V1",),
    ),
    ExternalCase(
        "kueue-14816", "https://github.com/kubernetes-sigs/kueue/pull/14816",
        ("tmp/ocms-fmd-draft/live-github/kueue_14816_pr_view.json",), semantic_tests=_RBAC_TESTS,
    ),
    ExternalCase(
        "coredns-helm-274", "https://github.com/coredns/helm/issues/274",
        ("tmp/ocms-fmd-draft/live-github/coredns_helm_issue_274.json",), semantic_tests=_MONITOR_TESTS,
    ),
    ExternalCase(
        "falco-helm-1053", "https://github.com/falcosecurity/charts/issues/1053",
        ("tmp/ocms-fmd-draft/live-github/falco_charts_issue_1053.json",), semantic_tests=_MONITOR_TESTS,
    ),
    ExternalCase(
        "external-secrets-6987", "https://github.com/external-secrets/external-secrets/issues/6987",
        ("evidence/external-secrets-6987/api/issue-6987.json", "tmp/private-flagship-search/external-secrets-contract.yaml"),
        semantic_tests=_MONITOR_TESTS,
    ),
    ExternalCase(
        "polaris-1240", "https://github.com/FairwindsOps/polaris/issues/1240",
        ("tmp/polaris-rolebinding-namespace/evidence/iac-guard-v-candidate.json",),
        ("tmp/polaris-rolebinding-namespace/evidence/iac-guard-v-*.json",), _RBAC_TESTS,
        ("IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1",), ("SATISFIED", "VIOLATED"),
    ),
    ExternalCase(
        "prometheus-helm-7308", "https://github.com/prometheus-community/helm-charts/pull/7308",
        ("evidence/kube-prometheus-stack-7308/api/pull-final.json",),
        ("evidence/kube-prometheus-stack-7308/validation/*.json",), _MONITOR_TESTS + _RBAC_TESTS,
        ("IACGV_PROM_SERVICEMONITOR_RESOLVES_SERVICE_PORT_V1", "IACGV_K8S_RBAC_ROLE_REF_RESOLVES_V1"),
        ("SATISFIED", "VIOLATED", "NOT_EVALUATED"), "DIRECT_CONTRACT_PROPOSAL_DECLINED",
    ),
    ExternalCase(
        "quay-operator-1322", "https://github.com/Quay/quay-operator/issues/1322",
        ("external-impact-evidence/quay-operator-1322-a9-path-study/NATIVE_REPORT.json",),
        ("external-impact-evidence/quay-operator-1322-a9-path-study/NATIVE_REPORT.json",), _NETWORK_TESTS,
    ),
    ExternalCase(
        "dgraph-charts-146", "https://github.com/dgraph-io/charts/pull/146",
        ("examples/public-reproductions/dgraph-charts-146/rendered",), semantic_tests=_NETWORK_TESTS,
    ),
    ExternalCase(
        "supabase-253", "https://github.com/supabase-community/supabase-kubernetes/pull/253",
        ("tmp/ocms-fmd-draft/live-github/supabase_253_pr_view.json",), semantic_tests=_NETWORK_TESTS,
    ),
    ExternalCase(
        "checkov-7655", "https://github.com/bridgecrewio/checkov/pull/7655",
        ("tmp/ocms-fmd-draft/live-github/checkov_7655_pr_view.json",),
        semantic_tests=("tests/unit/test_kustomize_materialization_a8.py",),
    ),
    ExternalCase(
        "terraform-docs-960", "https://github.com/terraform-docs/terraform-docs/issues/960",
        ("tmp/terraform-docs-recursive-opentofu/iacgv-request.json",), semantic_tests=_OPENTOFU_TESTS,
    ),
    ExternalCase(
        "terramate-2386", "https://github.com/terramate-io/terramate/issues/2386",
        ("tmp/terramate-opentofu-json/request.json",), semantic_tests=_OPENTOFU_TESTS,
    ),
    ExternalCase(
        "kueue-14978", "https://github.com/kubernetes-sigs/kueue/issues/14978",
        ("tmp/ocms-fmd-draft/live-github/kueue_issue_14978.json",), semantic_tests=_MONITOR_TESTS,
    ),
    ExternalCase(
        "thanos-operator-630", "https://github.com/banzaicloud/thanos-operator/issues/630",
        ("tmp/ocms-fmd-draft/live-github/thanos_operator_issue_630.json",), semantic_tests=_MONITOR_TESTS,
    ),
    ExternalCase(
        "kaito-2313", "https://github.com/kaito-project/kaito/pull/2313",
        ("tmp/ocms-fmd-draft/live-github/kaito_2313_pr_view.json",), semantic_tests=_MONITOR_TESTS,
    ),
    ExternalCase(
        "vehagn-homelab-564", "https://github.com/vehagn/homelab/issues/564",
        ("tmp/ocms-fmd-draft/live-github/vehagn_homelab_issue_564.json",), semantic_tests=_MONITOR_TESTS,
    ),
    ExternalCase(
        "hetzner-ccm-1353", "https://github.com/hetznercloud/hcloud-cloud-controller-manager/issues/1353",
        ("tmp/beta1-next-adoption-screen/hcloud-baseline/report.json",),
        (
            "tmp/beta1-next-adoption-screen/hcloud-baseline/report.json",
            "tmp/beta1-next-adoption-screen/hcloud-daemonset-baseline/report*.json",
            "tmp/beta1-next-adoption-screen/hcloud-helm-matrix-reports/*.json",
            "tmp/beta1-next-adoption-screen/hcloud-pinned-mutations/*.json",
            "tmp/beta1-next-adoption-screen/hcloud-current-mutations/*.json",
        ), _MONITOR_TESTS,
        ("IACGV_PROM_PODMONITOR_RESOLVES_CONTAINER_PORT_V1",),
        ("SATISFIED", "VIOLATED", "NOT_EVALUATED"), "DIRECT_CONTRACT_PROPOSAL_DECLINED",
    ),
)


def _evidence_binding(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    if path.is_file():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"path": relative, "kind": "file", "sha256": digest}
    if path.is_dir():
        members = []
        for child in sorted(item for item in path.rglob("*") if item.is_file()):
            members.append({
                "path": child.relative_to(path).as_posix(),
                "sha256": hashlib.sha256(child.read_bytes()).hexdigest(),
            })
        encoded = json.dumps(
            members, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        return {
            "path": relative, "kind": "directory", "members": len(members),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    return {"path": relative, "kind": "missing", "sha256": None}


def _report_outcomes(payload: object) -> set[str]:
    if type(payload) is not dict:
        return set()
    schema_version = payload.get("schema_version")
    if schema_version in {
        "infrastructure-contract-report-v1alpha1", "infrastructure-contract-report-v1"
    }:
        validate_contract_report_payload(payload)
        return {payload["result"]}
    if schema_version == "native-property-report-v1":
        validate_native_report_payload(payload)
        return {item["result"] for item in payload["observations"]}
    if schema_version == "report-v1":
        validate_report_payload(payload)
        return {payload["verdict"]}
    return set()


def replay_external_cases(root: Path) -> dict:
    if len(CASES) != len({item.case_id for item in CASES}):
        raise RuntimeError("external compatibility case IDs are not unique")
    records = []
    for case in CASES:
        missing = [path for path in case.evidence_paths if not (root / path).exists()]
        missing.extend(path for path in case.semantic_tests if not (root / path).is_file())
        evidence_bindings = [
            _evidence_binding(root, path) for path in case.evidence_paths
        ]
        report_paths: set[Path] = set()
        for pattern in case.report_globs:
            report_paths.update(path for path in root.glob(pattern) if path.is_file())
        outcomes: set[str] = set()
        validated_reports = 0
        error = None
        if case.report_globs and not report_paths:
            missing.append(f"report glob: {case.report_globs}")
        try:
            for path in sorted(report_paths):
                payload = json.loads(path.read_text(encoding="utf-8"))
                observed = _report_outcomes(payload)
                if observed:
                    validated_reports += 1
                    outcomes.update(observed)
            if case.required_outcomes and not set(case.required_outcomes) <= outcomes:
                error = f"required outcomes {case.required_outcomes!r} not present in {sorted(outcomes)!r}"
            unknown = set(case.property_ids) - set(NATIVE_PROPERTY_REGISTRY)
            if unknown:
                error = f"unknown property IDs: {sorted(unknown)!r}"
        except Exception as exc:  # release evidence records the exact typed failure
            error = f"{type(exc).__name__}: {exc}"
        classification = "UNCHANGED" if not missing and error is None else "BLOCKED_BY_EXTERNAL_DRIFT"
        records.append({
            "case_id": case.case_id,
            "public_url": case.public_url,
            "dependency_kind": case.dependency_kind,
            "classification": classification,
            "validated_reports": validated_reports,
            "outcomes": sorted(outcomes),
            "evidence_bindings": evidence_bindings,
            "semantic_tests": list(case.semantic_tests),
            "missing": missing,
            "error": error,
        })
    counts = {
        key: sum(item["classification"] == key for item in records)
        for key in (
            "UNCHANGED", "STRICTER_BUT_COMPATIBLE", "BREAKING",
            "NEWLY_UNSUPPORTED", "BLOCKED_BY_EXTERNAL_DRIFT",
        )
    }
    return {
        "schema_version": "iac-guard-v-external-compatibility-replay-v1",
        "case_total": len(records),
        "counts": counts,
        "records": records,
    }


__all__ = ["CASES", "ExternalCase", "replay_external_cases"]
