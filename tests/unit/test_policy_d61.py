"""Review-3 D6 loader provenance and integrated exception properties."""
from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

import iac_guard_v.policy as POLICY
from iac_guard_v.enums import ExceptionOrigin, Outcome, Status, Verdict
from iac_guard_v.models import ExceptionPolicy, TargetIdentity

from test_policy import (
    TODAY,
    _bundle,
    _outcome,
    _policy_payload,
    _record,
    _replace_engine,
    verified_engine,
)
from iac_guard_v.models import GateResult


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=repository, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _git_policy_source(
    tmp_path: Path,
    name: str,
    content: bytes,
    *,
    governed_path: str = ".iac-guard.json",
) -> tuple[Path, str, POLICY.TrustedGitSource]:
    repository = tmp_path / name
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    policy_path = repository / governed_path
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_bytes(content)
    _git(repository, "add", governed_path)
    _git(repository, "commit", "-q", "-m", "trusted policy")
    commit = _git(repository, "rev-parse", "HEAD")
    source = POLICY.attest_git_source(
        repository, commit, repository, (governed_path,)
    )
    return repository, commit, source


def test_raw_self_declared_trusted_record_is_not_policy_material(verified_engine) -> None:
    run = _outcome(verified_engine, Outcome.RESOURCE_DELETED)
    forged = ExceptionPolicy((
        _record(Outcome.RESOURCE_DELETED, origin=ExceptionOrigin.TRUSTED_BASE),
    ))
    with pytest.raises(Exception, match="TrustedPolicyBundle"):
        POLICY.PolicyRequest(run, forged)


def test_policy_request_has_no_caller_time_or_optionality_fields() -> None:
    fields = set(POLICY.PolicyRequest.__dataclass_fields__)
    assert "evaluation_date" not in fields
    assert "optional_gates" not in fields
    assert "optional_gates_origin" not in fields


def test_production_policy_loaders_exist() -> None:
    assert callable(POLICY.load_trusted_exception)
    assert callable(POLICY.load_candidate_exception)
    assert callable(POLICY.load_base_commit_policy)
    assert callable(POLICY.load_protected_policy_repository)
    assert callable(POLICY.load_operator_policy)
    assert callable(POLICY.load_candidate_policy)


def test_self_declared_record_old_behavior_was_verifiable(verified_engine) -> None:
    """The old API's exact exploit is retained as a negative mutation check."""
    run = _outcome(verified_engine, Outcome.RESOURCE_DELETED)
    forged = ExceptionPolicy((
        _record(Outcome.RESOURCE_DELETED, origin=ExceptionOrigin.TRUSTED_BASE),
    ))
    old_style_request = lambda: POLICY.PolicyRequest(  # noqa: E731
        run, date(2026, 8, 11), exceptions=forged
    )
    with pytest.raises((TypeError, ValueError)):
        old_style_request()


def test_loader_stamps_origin_and_ignores_serialized_claim() -> None:
    payload = _policy_payload(exceptions=(
        _record(Outcome.SUPPRESSED, origin=ExceptionOrigin.TRUSTED_BASE),
    ))
    record_payload = payload["exceptions"][0]
    trusted = POLICY.load_trusted_exception(record_payload, ExceptionOrigin.OPERATOR)
    candidate = POLICY.load_candidate_exception(record_payload)
    assert trusted.origin is ExceptionOrigin.OPERATOR
    assert candidate.origin is ExceptionOrigin.CANDIDATE_HEAD
    with pytest.raises(Exception, match="protected"):
        POLICY.load_trusted_exception(record_payload, ExceptionOrigin.CANDIDATE_HEAD)


def test_direct_bundle_construction_cannot_create_loader_provenance() -> None:
    bundle = _bundle()
    with pytest.raises(Exception, match="production loader provenance"):
        POLICY.TrustedPolicyBundle(
            bundle.policy,
            bundle.optional_gates,
            bundle.source_origin,
            bundle.source_identity,
            bundle.trusted_policy_sha256,
            bundle.candidate_policy_sha256,
            bundle.candidate_policy_state,
            bundle.differing_governed_paths,
            bundle.evaluation_date,
            bundle.evaluation_timezone,
            bundle.evaluation_time_provenance,
        )


def test_base_loader_binds_bytes_source_and_governed_path(tmp_path) -> None:
    payload = _policy_payload()
    trusted_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    repository, commit, source = _git_policy_source(
        tmp_path, "base-loader", trusted_bytes, governed_path="config/policy.json"
    )
    bundle = POLICY.load_base_commit_policy(
        source,
        governed_path="config/policy.json",
        _clock=lambda: datetime(2026, 8, 11, tzinfo=timezone.utc),
    )
    assert bundle.policy_drift is False
    assert bundle.source_origin is ExceptionOrigin.TRUSTED_BASE
    assert bundle.source_identity == f"git_commit_{commit}"
    assert bundle.evaluation_date == TODAY
    assert bundle.evaluation_timezone == "UTC"

    (repository / "config/policy.json").write_text(
        json.dumps({**payload, "optional_gates": ["regression"]}), encoding="utf-8"
    )
    drift = POLICY.load_base_commit_policy(
        source,
        governed_path="config/policy.json",
        _clock=lambda: datetime(2026, 8, 11, tzinfo=timezone.utc),
    )
    assert drift.policy_drift is True
    assert drift.differing_governed_paths == ("config/policy.json",)
    assert drift.trusted_policy_sha256 != drift.candidate_policy_sha256


def test_missing_candidate_policy_is_visible_drift(tmp_path) -> None:
    repository, commit, _source = _git_policy_source(
        tmp_path, "protected-policy", json.dumps(_policy_payload()).encode("utf-8")
    )
    workspace = tmp_path / "candidate-workspace"
    workspace.mkdir()
    source = POLICY.attest_protected_policy_repository(
        repository, commit, workspace, (".iac-guard.json",)
    )
    bundle = POLICY.load_protected_policy_repository(
        source,
        _clock=lambda: datetime(2026, 8, 11, tzinfo=timezone.utc),
    )
    assert bundle.policy_drift
    assert bundle.candidate_policy_state == "missing"
    assert bundle.candidate_policy_sha256 is None
    assert bundle.differing_governed_paths == (".iac-guard.json",)


def test_policy_drift_from_loader_is_reported_and_fails(verified_engine) -> None:
    trusted = _policy_payload()
    candidate = {**trusted, "optional_gates": ["regression"]}
    bundle = POLICY.load_operator_policy(
        trusted,
        candidate_payload=candidate,
        source_identity="protected-workflow-input",
        governed_path="policy/iac-guard.json",
        _clock=lambda: datetime(2026, 8, 11, tzinfo=timezone.utc),
    )
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(verified_engine, bundle))
    assert result.verdict is Verdict.FAILED
    evidence = result.canonical_dict()["policy_evidence"]
    assert evidence["source_identity"] == "protected-workflow-input"
    assert evidence["trusted_policy_sha256"] != evidence["candidate_policy_sha256"]
    assert evidence["differing_governed_paths"] == ["policy/iac-guard.json"]
    assert evidence["evaluation_timezone"] == "UTC"
    assert evidence["evaluation_time_provenance"] == "trusted_execution_clock"


def test_applied_exception_retains_exact_loader_source(verified_engine) -> None:
    run = _outcome(verified_engine, Outcome.SUPPRESSED)
    payload = _policy_payload(exceptions=(_record(Outcome.SUPPRESSED),))
    bundle = POLICY.load_operator_policy(
        payload,
        source_identity="protected-operator-policy-v7",
        _clock=lambda: datetime(2026, 8, 11, tzinfo=timezone.utc),
    )
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(run, bundle))
    assert result.verdict is Verdict.VERIFIED
    assert result.decisions[0].exception_id == "EX-1"
    source = result.policy_evidence.applied_exception_sources[0]
    assert source.exception_id == "EX-1"
    assert source.source_origin is ExceptionOrigin.OPERATOR
    assert source.source_identity == "protected-operator-policy-v7"


def test_wrong_target_loader_record_remains_unpermitted(verified_engine) -> None:
    wrong = _record(
        Outcome.SUPPRESSED,
        identity=TargetIdentity("checkov", "CKV_X", "aws_x.other"),
    )
    bundle = POLICY.load_operator_policy(
        _policy_payload(exceptions=(wrong,)),
        source_identity="operator-wrong-target-test",
        _clock=lambda: datetime(2026, 8, 11, tzinfo=timezone.utc),
    )
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(
        _outcome(verified_engine, Outcome.SUPPRESSED), bundle
    ))
    assert result.verdict is Verdict.FAILED
    assert result.decisions[0].policy_permitted is False


@pytest.mark.parametrize("boundary", ["created", "expires"])
def test_loader_clock_applies_inclusive_exception_window(verified_engine, boundary) -> None:
    record = _record(Outcome.SUPPRESSED)
    payload = _policy_payload(exceptions=(record,))
    instant = record.created if boundary == "created" else record.expires
    bundle = POLICY.load_operator_policy(
        payload,
        source_identity="operator-window-test",
        _clock=lambda: datetime(instant.year, instant.month, instant.day, tzinfo=timezone.utc),
    )
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(
        _outcome(verified_engine, Outcome.SUPPRESSED), bundle
    ))
    assert result.verdict is Verdict.VERIFIED


def test_candidate_optionality_cannot_govern_policy(verified_engine) -> None:
    skipped = _replace_engine(
        verified_engine, regression=GateResult("regression", Status.SKIPPED)
    )
    trusted = _policy_payload()
    candidate = {**trusted, "optional_gates": ["regression"]}
    bundle = POLICY.load_operator_policy(
        trusted,
        candidate_payload=candidate,
        source_identity="protected-workflow-input",
        _clock=lambda: datetime(2026, 8, 11, tzinfo=timezone.utc),
    )
    assert POLICY.evaluate_policy(POLICY.PolicyRequest(skipped, bundle)).verdict is not Verdict.VERIFIED


def test_policy_payload_cannot_supply_evaluation_time() -> None:
    with pytest.raises(Exception, match="unknown policy fields"):
        POLICY.load_operator_policy(
            {**_policy_payload(), "evaluation_date": "2099-01-01"},
            source_identity="operator-time-test",
        )
    with pytest.raises(Exception, match="timezone-aware"):
        POLICY.load_operator_policy(
            _policy_payload(),
            source_identity="operator-time-test",
            _clock=lambda: datetime(2026, 8, 11),
        )


def test_file_loader_rejects_duplicate_keys_depth_and_symlink(tmp_path) -> None:
    _repo, _commit, duplicate = _git_policy_source(
        tmp_path, "duplicate", b'{"exceptions":[],"exceptions":[]}'
    )
    with pytest.raises(Exception, match="duplicate"):
        POLICY.load_base_commit_policy(duplicate)

    _repo, _commit, deep = _git_policy_source(
        tmp_path, "deep", ("[" * 65 + "]" * 65).encode("utf-8")
    )
    with pytest.raises(Exception, match="depth"):
        POLICY.load_base_commit_policy(deep)

    repository, _commit, linked_source = _git_policy_source(
        tmp_path, "symlink", json.dumps(_policy_payload()).encode("utf-8")
    )
    real = tmp_path / "candidate-real.json"
    real.write_text(json.dumps(_policy_payload()), encoding="utf-8")
    (repository / ".iac-guard.json").unlink()
    (repository / ".iac-guard.json").symlink_to(real)
    with pytest.raises(Exception, match="no-follow"):
        POLICY.load_base_commit_policy(linked_source)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ({"exceptions": "bad"}, "exceptions"),
        ({"optional_gates": "bad"}, "optional_gates"),
        ({"optional_gates": ["regression", "regression"]}, "duplicates"),
        ({"optional_gates": ["unknown"]}, "unknown optional"),
        ({"surprise": True}, "unknown policy fields"),
    ],
)
def test_policy_document_shape_mutations_are_rejected(mutation, message) -> None:
    with pytest.raises(Exception, match=message):
        POLICY.load_operator_policy(
            {**_policy_payload(), **mutation}, source_identity="operator-shape-test"
        )


@pytest.mark.parametrize(
    "mutation, message",
    [
        ({"created": None}, "ISO date"),
        ({"created": "not-a-date"}, "ISO date"),
        ({"permitted_outcomes": []}, "nonempty"),
        ({"permitted_outcomes": [1]}, "exact strings"),
        ({"permitted_outcomes": ["SUPPRESSED", "SUPPRESSED"]}, "duplicates"),
        ({"permitted_outcomes": ["NOT_AN_OUTCOME"]}, "unknown outcome"),
        ({"target": {"scanner": "checkov"}}, "target"),
        ({"surprise": True}, "unknown exception fields"),
    ],
)
def test_exception_payload_mutations_are_rejected(mutation, message) -> None:
    record = _policy_payload(exceptions=(_record(Outcome.SUPPRESSED),))["exceptions"][0]
    with pytest.raises(Exception, match=message):
        POLICY.load_operator_policy(
            {"exceptions": [{**record, **mutation}], "optional_gates": []},
            source_identity="operator-record-test",
        )


def test_policy_source_type_size_and_json_shape_guards(tmp_path) -> None:
    with pytest.raises(Exception, match="TrustedGitSource"):
        POLICY.load_base_commit_policy("not-an-attested-source")
    _repo, _commit, oversized = _git_policy_source(
        tmp_path, "oversized", b" " * (1024 * 1024 + 1)
    )
    with pytest.raises(Exception, match="byte limit"):
        POLICY.load_base_commit_policy(oversized)
    for name, content, message in (
        ("empty.json", b"", "nonempty"),
        ("malformed.json", b"{", "strict JSON"),
        ("array.json", b"[]", "JSON object"),
        ("unbalanced.json", b"}", "unbalanced"),
    ):
        _repo, _commit, source = _git_policy_source(tmp_path, name, content)
        with pytest.raises(Exception, match=message):
            POLICY.load_base_commit_policy(source)


def test_candidate_policy_path_and_source_type_are_typed(tmp_path) -> None:
    path = tmp_path / "candidate.json"
    payload = _policy_payload(exceptions=(
        _record(Outcome.SUPPRESSED, origin=ExceptionOrigin.TRUSTED_BASE),
    ))
    path.write_text(json.dumps(payload), encoding="utf-8")
    candidate = POLICY.load_candidate_policy(path)
    assert candidate.records[0].origin is ExceptionOrigin.CANDIDATE_HEAD
    with pytest.raises(Exception, match="dict or pathlib.Path"):
        POLICY.load_candidate_policy([])
    with pytest.raises(Exception, match="exact dict"):
        POLICY.load_operator_policy([], source_identity="operator-type-test")
    with pytest.raises(Exception, match="JSON values"):
        POLICY.load_operator_policy(
            {"exceptions": set()}, source_identity="operator-value-test"
        )


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"optional_gates": {"regression"}}, "optional gates"),
        ({"source_origin": ExceptionOrigin.CANDIDATE_HEAD}, "protected source"),
        ({"trusted_policy_sha256": "bad"}, "SHA-256"),
        ({"differing_governed_paths": []}, "exact tuple"),
        ({"candidate_policy_state": "present", "candidate_policy_sha256": "f" * 64}, "contradict"),
        ({"evaluation_timezone": "local"}, "timezone"),
    ],
)
def test_trusted_bundle_invariant_mutations_are_rejected(changes, message) -> None:
    bundle = _bundle()
    with pytest.raises(Exception, match=message):
        replace(
            bundle,
            **changes,
            _trusted_context=POLICY._TRUSTED_BUNDLE_CONTEXT,
        )


def test_policy_evidence_rejects_caller_and_duplicate_sources() -> None:
    bundle = _bundle()
    source = POLICY.AppliedExceptionSource(
        "EX-1", ExceptionOrigin.OPERATOR, "operator-test-fixture"
    )
    with pytest.raises(Exception, match="trusted policy evaluation"):
        POLICY.PolicyEvidence(bundle, ())
    with pytest.raises(Exception, match="unique"):
        POLICY.PolicyEvidence(
            bundle,
            (source, source),
            _trusted_context=POLICY._TRUSTED_POLICY_EVIDENCE_CONTEXT,
        )
