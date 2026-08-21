"""D4.5 Kubernetes JSON adapter contract and defensive branch mutations."""
from __future__ import annotations

from pathlib import Path

import pytest

import iac_guard_v.adapters.checkov as CHECKOV
from iac_guard_v.adapters.checkov import (
    CheckovDistributionIdentity,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
    CheckovTargetEvidence,
)
from iac_guard_v.enums import (
    ArtifactKind,
    CheckEvaluationResult,
    CheckTargetReason,
    Status,
)
from iac_guard_v.models import CheckEvaluation, DomainError, ExpectedResource

from test_checkov_adapter import request


def _evaluation() -> CheckEvaluation:
    return CheckEvaluation(
        "checkov", "3.3.0", "CKV_X", "v1/Pod/default/p", "pod.json",
        CheckEvaluationResult.PASSED, (), "passed_checks",
    )


def test_json_file_type_is_distinct_and_terraform_json_stays_rejected() -> None:
    assert CHECKOV._file_type("pod.json") == ArtifactKind.KUBERNETES_JSON.value
    with pytest.raises(Exception, match="unsupported artifact"):
        CHECKOV._file_type("main.tf.json")
    with pytest.raises(Exception, match="unsupported artifact"):
        CHECKOV._file_type("README.txt")


def test_kubernetes_json_expected_resource_contract(tmp_path: Path) -> None:
    request(tmp_path, frameworks=("kubernetes",))
    (tmp_path / "repo" / "pod.json").write_text(
        '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"}}',
        encoding="utf-8",
    )
    identity = CheckovKubernetesIdentity(
        "pod.json", "Pod.default.p", "v1", "Pod", "default", "p"
    )
    resource = ExpectedResource(
        "pod.json", "v1/Pod/default/p", ArtifactKind.KUBERNETES_JSON,
        "Pod.default.p",
    )
    value = request(
        tmp_path,
        frameworks=("kubernetes",),
        files_eligible=("pod.json",),
        kubernetes_identities=(identity,),
        expected_resources=(resource,),
    )
    assert value.eligible_file_evidence[0].file_type == "kubernetes_json"
    assert value.expected_resources == (resource,)
    wrong = ExpectedResource(
        "pod.json", "v1/Pod/default/other", ArtifactKind.KUBERNETES_JSON,
        "Pod.default.p",
    )
    with pytest.raises(Exception, match="identity mapping"):
        request(
            tmp_path,
            frameworks=("kubernetes",),
            files_eligible=("pod.json",),
            kubernetes_identities=(identity,),
            expected_resources=(wrong,),
        )


@pytest.mark.parametrize(
    "values",
    [
        ("x", "0" * 64),
        ("0" * 64, "X" * 64),
    ],
)
def test_distribution_identity_digest_mutations_are_rejected(values) -> None:
    with pytest.raises(Exception, match="lowercase SHA-256"):
        CheckovDistributionIdentity(values[0], values[1], "installed-tree-test")


@pytest.mark.parametrize(
    "args, message",
    [
        (("PASS", CheckTargetReason.AFFIRMATIVE_TARGET_PASS, ()), "exact Status"),
        ((Status.PASS, "PASS", ()), "exact CheckTargetReason"),
        ((Status.PASS, CheckTargetReason.AFFIRMATIVE_TARGET_PASS, []), "exact tuple"),
        ((Status.PASS, CheckTargetReason.AFFIRMATIVE_TARGET_PASS, (object(),)), "CheckEvaluation"),
    ],
)
def test_target_evidence_shape_mutations_are_rejected(args, message) -> None:
    with pytest.raises(Exception, match=message):
        CheckovTargetEvidence(*args)


def test_caller_target_evidence_is_not_trusted() -> None:
    caller = CheckovTargetEvidence(
        Status.PASS, CheckTargetReason.AFFIRMATIVE_TARGET_PASS, (_evaluation(),)
    )
    with pytest.raises(Exception, match="caller-authored"):
        CHECKOV.require_trusted_checkov_target_evidence(caller)
    with pytest.raises(Exception, match="exact CheckovTargetEvidence"):
        CHECKOV.require_trusted_checkov_target_evidence(object())


def test_filesystem_helper_failures_are_typed(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(Exception, match="cannot be resolved"):
        CHECKOV._identity(missing, "probe", directory=False)
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(Exception, match="regular file"):
        CHECKOV._identity(directory, "probe", directory=False)
    with pytest.raises(Exception, match="cannot be hashed"):
        CHECKOV._file_sha256(directory)
    with pytest.raises(Exception, match="pathlib.Path"):
        CHECKOV._safe_directory("not-a-path", "probe")


def test_request_resource_shape_mutations_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="exact tuple"):
        request(tmp_path, expected_resources=[])
    with pytest.raises(Exception, match="exact ExpectedResource"):
        request(tmp_path, expected_resources=(object(),))
    with pytest.raises(Exception, match="eligible file"):
        request(
            tmp_path,
            expected_resources=(ExpectedResource(
                "other.tf", "aws_x.r", ArtifactKind.TERRAFORM_HCL, "aws_x.r"
            ),),
        )
    with pytest.raises(Exception, match="native lookup"):
        request(
            tmp_path,
            expected_resources=(ExpectedResource(
                "main.tf", "aws_x.r", ArtifactKind.TERRAFORM_HCL, "aws_x.other"
            ),),
        )
    with pytest.raises(Exception, match="unsupported artifact kind"):
        request(
            tmp_path,
            expected_resources=(ExpectedResource(
                "main.tf", "aws_x.r", ArtifactKind.CLOUDFORMATION, "aws_x.r"
            ),),
        )
