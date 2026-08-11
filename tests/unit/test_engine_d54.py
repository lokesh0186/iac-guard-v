"""D5.4 sealed snapshots, final revalidation, and portable report evidence."""
from __future__ import annotations

import hashlib
import inspect
import os
from pathlib import Path

import pytest

import iac_guard_v.engine as ENGINE
from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.engine import (
    VerificationRequest,
    load_operator_verification_config,
    run_checkov_verification,
)
from iac_guard_v.enums import CheckEvaluationResult, Status, Verdict
from iac_guard_v.models import RequiredGates, Target

from test_engine import IDENTITY, _config, _executable, _scan_request
from test_engine_d51 import evaluation, finding, scanner_run, verdict


def _request_and_runs(tmp_path: Path, *, frameworks=("terraform",), gates=None):
    executable = _executable(tmp_path)
    baseline = _scan_request(tmp_path / "baseline", executable)
    candidate = _scan_request(tmp_path / "candidate", executable)
    required = gates or RequiredGates(("terraform_hcl_parse",))
    config = _config(
        baseline, candidate, required, executor=None, frameworks=frameworks
    )
    request = VerificationRequest(
        baseline, candidate, (Target(IDENTITY, 1),), config
    )
    baseline_run = scanner_run(
        request.baseline_scan,
        findings=(finding("aws_x.r"),),
        evaluations=(evaluation(CheckEvaluationResult.FAILED),),
    )
    candidate_run = scanner_run(
        request.candidate_scan,
        findings=(),
        evaluations=(evaluation(CheckEvaluationResult.PASSED),),
    )
    return request, baseline_run, candidate_run


def _execute(monkeypatch, request, baseline_run, candidate_run):
    monkeypatch.setattr(
        CheckovAdapter,
        "scan",
        lambda _self, value: (
            baseline_run
            if value.scan_root == request.baseline_scan.scan_root
            else candidate_run
        ),
    )
    return run_checkov_verification(request)


def test_live_file_change_after_scanner_evidence_never_verifies(
    monkeypatch, tmp_path: Path
) -> None:
    request, baseline_run, candidate_run = _request_and_runs(tmp_path)
    source = request.candidate_scan.scan_root / "main.tf"
    source.write_text(
        'resource "aws_x" "r" {\n  changed = true\n}\n', encoding="utf-8"
    )

    result = _execute(monkeypatch, request, baseline_run, candidate_run)

    assert result.validator_results[0].status is Status.PASS
    assert result.preflight.status is Status.ERROR
    assert result.preflight.reason_code == "SNAPSHOT_CHANGED_DURING_VERIFICATION"
    assert verdict(result).verdict is Verdict.INCONCLUSIVE


@pytest.mark.parametrize(
    "name,payload",
    [
        ("late-pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: late}\n"),
        (
            "late-pod.json",
            '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"late"}}',
        ),
    ],
)
def test_late_supported_artifact_never_verifies(
    monkeypatch, tmp_path: Path, name: str, payload: str
) -> None:
    gates = RequiredGates(("kubernetes_yaml_parse", "terraform_hcl_parse"))
    request, baseline_run, candidate_run = _request_and_runs(
        tmp_path, frameworks=("terraform", "kubernetes"), gates=gates
    )
    (request.candidate_scan.scan_root / name).write_text(payload, encoding="utf-8")

    result = _execute(monkeypatch, request, baseline_run, candidate_run)

    assert name not in request.candidate_scan.files_eligible
    assert result.preflight.reason_code == "SNAPSHOT_CHANGED_DURING_VERIFICATION"
    assert verdict(result).verdict is Verdict.INCONCLUSIVE


def test_production_validator_consumes_sealed_bytes_not_live_root(
    tmp_path: Path,
) -> None:
    request, _baseline_run, _candidate_run = _request_and_runs(tmp_path)
    source = request.candidate_scan.scan_root / "main.tf"
    source.write_text('resource "aws_x" "r" { invalid = }\n', encoding="utf-8")
    snapshot = request.candidate_scan.sealed_snapshot

    result = request.config.gate_registry.execute(
        "validator", "terraform_hcl_parse", snapshot
    )
    assert result.status is Status.PASS
    assert result.detail == "files=1"


def test_equivalent_roots_have_portable_config_identity(tmp_path: Path) -> None:
    configs = []
    executable = _executable(tmp_path / "shared-scanner")
    for name in ("machine-a", "machine-b"):
        root = tmp_path / name
        root.mkdir()
        baseline = _scan_request(root / "baseline", executable)
        candidate = _scan_request(root / "candidate", executable)
        configs.append(load_operator_verification_config(
            baseline.request,
            candidate.request,
            required_gates=RequiredGates(("terraform_hcl_parse",)),
        ))

    assert configs[0].config_sha256 == configs[1].config_sha256
    assert configs[0].canonical_dict() == configs[1].canonical_dict()
    assert str(tmp_path) not in str(configs[0].canonical_dict())


def test_gate_identity_binds_parser_helpers(monkeypatch) -> None:
    original = ENGINE.production_gate_registry()
    dispatcher_only = hashlib.sha256(
        inspect.getsource(ENGINE._production_gate_executor).encode("utf-8")
    ).hexdigest()
    assert all(item.code_sha256 != dispatcher_only for item in original.implementations)

    real_getsource = inspect.getsource

    def changed_source(value):
        source = real_getsource(value)
        if value is ENGINE._terraform_resources:
            return source + "\n# security-relevant parser mutation\n"
        return source

    monkeypatch.setattr(inspect, "getsource", changed_source)
    changed = ENGINE.production_gate_registry()
    assert original.implementations[0].code_sha256 != changed.implementations[0].code_sha256


def test_canonical_result_contains_complete_snapshot_evidence(
    monkeypatch, tmp_path: Path
) -> None:
    request, baseline_run, candidate_run = _request_and_runs(tmp_path)
    result = _execute(monkeypatch, request, baseline_run, candidate_run)
    canonical = result.canonical_dict()

    for role in ("baseline_snapshot", "candidate_snapshot"):
        snapshot = canonical[role]
        assert len(snapshot["snapshot_sha256"]) == 64
        assert snapshot["classifications"]
        assert snapshot["files"]
        assert snapshot["resources"]
        assert snapshot["repository_relative_subpath"] == "."
    assert canonical["candidate_snapshot"]["role"] == "candidate"
    assert canonical["baseline_snapshot"]["role"] == "baseline"


@pytest.mark.parametrize("field", ["files", "classifications", "resources", "governed_paths"])
def test_sealed_snapshot_collection_mutations_are_rejected(
    tmp_path: Path, field: str
) -> None:
    request, _baseline_run, _candidate_run = _request_and_runs(tmp_path)
    snapshot = request.candidate_scan.sealed_snapshot
    values = {
        name: getattr(snapshot, name)
        for name in (
            "role", "repository_identity", "repository_relative_subpath",
            "snapshot_sha256", "artifact_manifest_sha256",
            "resource_inventory_sha256", "config_sha256", "files",
            "classifications", "resources", "governed_paths",
        )
    }
    values[field] = list(values[field])
    with pytest.raises(Exception, match="exact typed tuple"):
        ENGINE.SealedVerificationSnapshot(
            **values, _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT
        )


@pytest.mark.parametrize(
    "values",
    [
        ("INVALID", "0" * 64, 0),
        ("REGULAR_FILE", "0" * 64, -1),
        ("REGULAR_FILE", None, 0),
        ("REGULAR_FILE", "bad", 0),
    ],
)
def test_governed_path_record_mutations_are_rejected(values) -> None:
    with pytest.raises(Exception):
        ENGINE.GovernedPathRecord("policy.json", *values)


@pytest.mark.parametrize(
    "before,after,state",
    [
        (None, "1" * 64, "added"),
        ("0" * 64, None, "removed"),
        ("0" * 64, "1" * 64, "changed"),
        ("0" * 64, "0" * 64, "stable"),
    ],
)
def test_governed_config_state_table(before, after, state) -> None:
    value = ENGINE.GovernedConfigEvidence(".iac-guard.json", before, after, state)
    assert value.state == state
    with pytest.raises(Exception, match="contradicts"):
        ENGINE.GovernedConfigEvidence(
            ".iac-guard.json", before, after,
            "stable" if state != "stable" else "changed",
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"trusted_kind": "INVALID"},
        {"candidate_kind": "INVALID"},
        {"trusted_size": -1},
        {"candidate_size": True},
    ],
)
def test_governed_config_shape_mutations_are_rejected(changes) -> None:
    values = dict(
        file_path=".iac-guard.json",
        trusted_sha256="0" * 64,
        candidate_sha256="0" * 64,
        state="stable",
    )
    values.update(changes)
    with pytest.raises(Exception):
        ENGINE.GovernedConfigEvidence(**values)


def test_governed_inventory_types_files_directories_symlinks_and_other(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    governed = root / ".iac-guard"
    governed.mkdir()
    (governed / "policy.json").write_text("{}", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "custom_checks").symlink_to(outside, target_is_directory=True)
    fifo = governed / "pipe"
    os.mkfifo(fifo)

    inventory = ENGINE._governed_inventory(root)
    assert inventory[".iac-guard"].kind == "REAL_DIRECTORY"
    assert inventory[".iac-guard/policy.json"].kind == "REGULAR_FILE"
    assert inventory["custom_checks"].kind == "SYMLINK"
    assert inventory[".iac-guard/pipe"].kind == "OTHER"
    assert inventory[".iac-guard"].sha256 != hashlib.sha256(b"directory").hexdigest()


def test_governed_comparison_retains_type_changes(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    (baseline / ".iac-guard").mkdir()
    (candidate / ".iac-guard").write_text("not a directory", encoding="utf-8")
    evidence = ENGINE._governed_comparison(baseline, candidate)
    assert evidence[0].state == "type_changed"
    assert evidence[0].trusted_kind == "REAL_DIRECTORY"
    assert evidence[0].candidate_kind == "REGULAR_FILE"


def test_governed_inventory_limits_and_git_exclusion(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".iac-guard.json").write_text("{}", encoding="utf-8")
    git = root / ".git"
    git.mkdir()
    (git / ".iac-guard.json").write_text("ignored", encoding="utf-8")
    inventory = ENGINE._governed_inventory(root)
    assert tuple(inventory) == (".iac-guard.json",)

    monkeypatch.setattr(ENGINE, "_MAX_GOVERNED_FILES", 0)
    with pytest.raises(Exception, match="file-count"):
        ENGINE._governed_inventory(root)
    monkeypatch.setattr(ENGINE, "_MAX_GOVERNED_FILES", 10)
    monkeypatch.setattr(ENGINE, "_MAX_GOVERNED_TOTAL_BYTES", 1)
    with pytest.raises(Exception, match="total-byte"):
        ENGINE._governed_inventory(root)


def test_source_snapshot_records_symlink_and_enforces_limits(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = tmp_path / "outside.tf"
    target.write_text("resource {}", encoding="utf-8")
    (root / "linked.tf").symlink_to(target)
    digest, _governed = ENGINE._source_snapshot_state(
        root, max_files=1, max_file_bytes=64, max_total_bytes=64
    )
    assert len(digest) == 64
    (root / "other.tf").write_text("resource {}", encoding="utf-8")
    with pytest.raises(Exception, match="file count"):
        ENGINE._source_snapshot_state(
            root, max_files=1, max_file_bytes=64, max_total_bytes=64
        )
    (root / "linked.tf").unlink()
    with pytest.raises(Exception, match="byte limit"):
        ENGINE._source_snapshot_state(
            root, max_files=2, max_file_bytes=64, max_total_bytes=1
        )


def test_source_snapshot_ignores_supported_named_directory_and_types_other(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "directory.tf").mkdir()
    fifo = root / "pipe.json"
    os.mkfifo(fifo)
    digest, governed = ENGINE._source_snapshot_state(
        root, max_files=2, max_file_bytes=64, max_total_bytes=64
    )
    assert len(digest) == 64
    assert governed == ()


def test_sealed_snapshot_role_subpath_duplicate_and_provenance_guards(
    tmp_path: Path,
) -> None:
    request, _baseline_run, _candidate_run = _request_and_runs(tmp_path)
    snapshot = request.candidate_scan.sealed_snapshot
    values = {
        name: getattr(snapshot, name)
        for name in (
            "role", "repository_identity", "repository_relative_subpath",
            "snapshot_sha256", "artifact_manifest_sha256",
            "resource_inventory_sha256", "config_sha256", "files",
            "classifications", "resources", "governed_paths",
        )
    }
    with pytest.raises(Exception, match="requires baseline/candidate"):
        ENGINE.SealedVerificationSnapshot(
            **{**values, "role": ENGINE.ScanRole.DISCOVERY},
            _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
        )
    nested = ENGINE.SealedVerificationSnapshot(
        **{**values, "repository_relative_subpath": "services/team-a"},
        _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
    )
    assert nested.repository_relative_subpath == "services/team-a"
    with pytest.raises(Exception, match="duplicate paths"):
        ENGINE.SealedVerificationSnapshot(
            **{**values, "files": snapshot.files + (snapshot.files[0],)},
            _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
        )
    with pytest.raises(Exception, match="factory provenance"):
        ENGINE.SealedVerificationSnapshot(**values)


def test_scan_plan_manifest_and_source_mutation_guards(tmp_path: Path) -> None:
    request, _baseline_run, _candidate_run = _request_and_runs(tmp_path)
    plan = request.candidate_scan
    values = {
        name: getattr(plan, name)
        for name in ENGINE.TrustedScanPlan.__dataclass_fields__
        if not name.startswith("_") and name != "sealed_snapshot"
    }
    with pytest.raises(Exception, match="artifact manifest"):
        ENGINE.TrustedScanPlan(
            **{**values, "artifact_manifest_sha256": "0" * 64},
            _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
        )
    with pytest.raises(Exception, match="snapshot digest"):
        ENGINE.TrustedScanPlan(
            **{**values, "snapshot_sha256": "0" * 64},
            _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
        )


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"classifications": []}, "classifications"),
        ({"inspected_files": []}, "inspected files"),
        ({"governed_paths": []}, "governed paths"),
    ],
)
def test_scan_plan_typed_collection_guards(tmp_path: Path, changes, message) -> None:
    request, _baseline_run, _candidate_run = _request_and_runs(tmp_path)
    plan = request.candidate_scan
    values = {
        name: getattr(plan, name)
        for name in ENGINE.TrustedScanPlan.__dataclass_fields__
        if not name.startswith("_") and name != "sealed_snapshot"
    }
    values.update(changes)
    with pytest.raises(Exception, match=message):
        ENGINE.TrustedScanPlan(
            **values, _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT
        )


def test_scan_plan_cross_evidence_mutations_are_rejected(tmp_path: Path) -> None:
    request, _baseline_run, _candidate_run = _request_and_runs(tmp_path)
    plan = request.candidate_scan
    values = {
        name: getattr(plan, name)
        for name in ENGINE.TrustedScanPlan.__dataclass_fields__
        if not name.startswith("_") and name != "sealed_snapshot"
    }
    with pytest.raises(Exception, match="eligible scan-plan files"):
        ENGINE.TrustedScanPlan(
            **{**values, "files": ()},
            _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
        )
    with pytest.raises(Exception, match="resources disagree"):
        ENGINE.TrustedScanPlan(
            **{**values, "resources": ()},
            _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
        )
    discovery = _scan_request(tmp_path / "discovery-extra", _executable(tmp_path / "scanner-extra"))
    discovery_values = {
        name: getattr(discovery, name)
        for name in ENGINE.TrustedScanPlan.__dataclass_fields__
        if not name.startswith("_") and name != "sealed_snapshot"
    }
    with pytest.raises(Exception, match="discovery scan plan"):
        ENGINE.TrustedScanPlan(
            **{**discovery_values, "config_sha256": "0" * 64},
            _trusted_context=ENGINE._TRUSTED_SCAN_PLAN_CONTEXT,
        )
