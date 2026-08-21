"""Review-3 D6 loader provenance and integrated exception properties."""
from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

import iac_guard_v.policy as POLICY
from iac_guard_v.enums import ExecutionMode, ExceptionOrigin, Outcome, Status, Verdict
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


def _base_context(
    source: POLICY.TrustedGitSource,
    when: datetime = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
    candidate_commit: str | None = None,
) -> POLICY.TrustedExecutionContext:
    return POLICY.TrustedExecutionContext(
        ExecutionMode.PR_BASE,
        source.repository_root,
        POLICY._portable_repository_identity(source.repository_root),
        source.commit_sha,
        source.candidate_root,
        candidate_commit or source.commit_sha,
        None, "", "",
        source.governed_paths,
        "a" * 64,
        "protected_test_context",
        when,
        "private_test_clock",
        ".", "b" * 64,
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )


def _protected_context(source: POLICY.TrustedGitSource) -> POLICY.TrustedExecutionContext:
    workspace = source.candidate_root
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.name", "Test")
    _git(workspace, "config", "user.email", "test@example.invalid")
    marker = workspace / "README"
    marker.write_text("candidate\n", encoding="utf-8")
    _git(workspace, "add", "README")
    _git(workspace, "commit", "-q", "-m", "candidate")
    candidate_commit = _git(workspace, "rev-parse", "HEAD")
    return POLICY.TrustedExecutionContext(
        ExecutionMode.PROTECTED_POLICY_REPOSITORY,
        workspace,
        POLICY._portable_repository_identity(workspace),
        candidate_commit,
        workspace,
        candidate_commit,
        source.repository_root,
        POLICY._portable_repository_identity(source.repository_root),
        source.commit_sha,
        source.governed_paths,
        "a" * 64,
        "protected_repository_test_context",
        datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
        "private_test_clock",
        ".", "b" * 64,
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )


def test_absent_base_policy_uses_closed_no_exception_default(tmp_path: Path) -> None:
    repository = tmp_path / "absent-policy"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / "main.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    _git(repository, "add", "main.tf")
    _git(repository, "commit", "-q", "-m", "candidate without policy")
    commit = _git(repository, "rev-parse", "HEAD")
    source = POLICY.attest_git_source(
        repository, commit, repository, (".iac-guard.json",)
    )
    bundle = POLICY.load_base_commit_policy(_base_context(source))
    assert len(bundle.policy) == 0
    assert bundle.optional_gates == frozenset()
    assert bundle.source_origin is ExceptionOrigin.TRUSTED_BASE
    assert bundle.candidate_policy_state == "not_compared"
    assert bundle.policy_drift is False


def _operator_context(config, when=None) -> POLICY.TrustedExecutionContext:
    return POLICY.TrustedExecutionContext(
        ExecutionMode.EXPLICIT_OPERATOR, None, "", "", config.candidate_root, "",
        None, "", "", (".iac-guard.json",), config.config_sha256,
        config.policy_source_authorization.context_identity,
        when or datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
        "private_test_clock",
        ".", config.candidate_source_snapshot_sha256,
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )


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


def test_direct_bundle_construction_cannot_create_loader_provenance(verified_engine) -> None:
    bundle = _bundle(config=verified_engine.verification_config)
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
        _base_context(source), governed_path="config/policy.json"
    )
    assert bundle.policy_drift is False
    assert bundle.source_origin is ExceptionOrigin.TRUSTED_BASE
    assert bundle.source_identity == f"git_commit_{commit}"
    assert bundle.evaluation_date == TODAY
    assert bundle.evaluation_timezone == "UTC"

    (repository / "config/policy.json").write_text(
        json.dumps({**payload, "optional_gates": ["regression"]}), encoding="utf-8"
    )
    with pytest.raises(Exception, match="checkout differs"):
        POLICY.load_base_commit_policy(
            _base_context(source), governed_path="config/policy.json"
        )


def test_missing_candidate_policy_is_visible_drift(tmp_path) -> None:
    repository, commit, _source = _git_policy_source(
        tmp_path, "protected-policy", json.dumps(_policy_payload()).encode("utf-8")
    )
    workspace = tmp_path / "candidate-workspace"
    workspace.mkdir()
    source = POLICY.attest_protected_policy_repository(
        repository, commit, workspace, (".iac-guard.json",)
    )
    bundle = POLICY.load_protected_policy_repository(_protected_context(source))
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
        context=_operator_context(verified_engine.verification_config),
        governed_path="policy/iac-guard.json",
    )
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(verified_engine, bundle))
    assert result.verdict is Verdict.FAILED
    evidence = result.canonical_dict()["policy_evidence"]
    assert evidence["source_identity"] == (
        verified_engine.verification_config.policy_source_authorization.context_identity
    )
    assert evidence["trusted_policy_sha256"] != evidence["candidate_policy_sha256"]
    assert evidence["differing_governed_paths"] == ["policy/iac-guard.json"]
    assert evidence["evaluation_timezone"] == "UTC"
    assert evidence["evaluation_time_provenance"] == "private_test_clock"


def test_applied_exception_retains_exact_loader_source(verified_engine) -> None:
    run = _outcome(verified_engine, Outcome.SUPPRESSED)
    payload = _policy_payload(exceptions=(_record(Outcome.SUPPRESSED),))
    bundle = POLICY.load_operator_policy(
        payload,
        context=_operator_context(verified_engine.verification_config),
    )
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(run, bundle))
    assert result.verdict is Verdict.VERIFIED
    assert result.decisions[0].exception_id == "EX-1"
    source = result.policy_evidence.applied_exception_sources[0]
    assert source.exception_id == "EX-1"
    assert source.source_origin is ExceptionOrigin.OPERATOR
    assert source.source_identity == bundle.source_identity


def test_wrong_target_loader_record_remains_unpermitted(verified_engine) -> None:
    wrong = _record(
        Outcome.SUPPRESSED,
        identity=TargetIdentity("checkov", "CKV_X", "aws_x.other"),
    )
    bundle = POLICY.load_operator_policy(
        _policy_payload(exceptions=(wrong,)),
        context=_operator_context(verified_engine.verification_config),
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
        context=_operator_context(
            verified_engine.verification_config,
            datetime(instant.year, instant.month, instant.day, tzinfo=timezone.utc),
        ),
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
        context=_operator_context(verified_engine.verification_config),
    )
    assert POLICY.evaluate_policy(POLICY.PolicyRequest(skipped, bundle)).verdict is not Verdict.VERIFIED


def test_policy_payload_cannot_supply_evaluation_time(verified_engine) -> None:
    context = _operator_context(verified_engine.verification_config)
    with pytest.raises(Exception, match="unknown policy fields"):
        POLICY.load_operator_policy(
            {**_policy_payload(), "evaluation_date": "2099-01-01"},
            context=context,
        )
    with pytest.raises(TypeError):
        POLICY.load_operator_policy(
            _policy_payload(), context=context,
            _clock=lambda: datetime(2026, 8, 11),
        )


def test_file_loader_rejects_duplicate_keys_depth_and_symlink(tmp_path) -> None:
    _repo, _commit, duplicate = _git_policy_source(
        tmp_path, "duplicate", b'{"exceptions":[],"exceptions":[]}'
    )
    with pytest.raises(Exception, match="duplicate"):
        POLICY.load_base_commit_policy(_base_context(duplicate))

    _repo, _commit, deep = _git_policy_source(
        tmp_path, "deep", ("[" * 65 + "]" * 65).encode("utf-8")
    )
    with pytest.raises(Exception, match="depth"):
        POLICY.load_base_commit_policy(_base_context(deep))

    repository, _commit, linked_source = _git_policy_source(
        tmp_path, "symlink", json.dumps(_policy_payload()).encode("utf-8")
    )
    real = tmp_path / "candidate-real.json"
    real.write_text(json.dumps(_policy_payload()), encoding="utf-8")
    (repository / ".iac-guard.json").unlink()
    (repository / ".iac-guard.json").symlink_to(real)
    with pytest.raises(Exception, match="checkout differs"):
        POLICY.load_base_commit_policy(_base_context(linked_source))


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
def test_policy_document_shape_mutations_are_rejected(
    mutation, message, verified_engine
) -> None:
    with pytest.raises(Exception, match=message):
        POLICY.load_operator_policy(
            {**_policy_payload(), **mutation},
            context=_operator_context(verified_engine.verification_config),
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
def test_exception_payload_mutations_are_rejected(
    mutation, message, verified_engine
) -> None:
    record = _policy_payload(exceptions=(_record(Outcome.SUPPRESSED),))["exceptions"][0]
    with pytest.raises(Exception, match=message):
        POLICY.load_operator_policy(
            {"exceptions": [{**record, **mutation}], "optional_gates": []},
            context=_operator_context(verified_engine.verification_config),
        )


def test_policy_source_type_size_and_json_shape_guards(tmp_path) -> None:
    with pytest.raises(Exception, match="trusted execution context"):
        POLICY.load_base_commit_policy("not-an-attested-source")
    _repo, _commit, oversized = _git_policy_source(
        tmp_path, "oversized", b" " * (1024 * 1024 + 1)
    )
    with pytest.raises(Exception, match="byte limit"):
        POLICY.load_base_commit_policy(_base_context(oversized))
    for name, content, message in (
        ("empty.json", b"", "nonempty"),
        ("malformed.json", b"{", "strict JSON"),
        ("array.json", b"[]", "JSON object"),
        ("unbalanced.json", b"}", "unbalanced"),
    ):
        _repo, _commit, source = _git_policy_source(tmp_path, name, content)
        with pytest.raises(Exception, match=message):
            POLICY.load_base_commit_policy(_base_context(source))


def test_candidate_policy_path_and_source_type_are_typed(tmp_path, verified_engine) -> None:
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
        POLICY.load_operator_policy(
            [], context=_operator_context(verified_engine.verification_config)
        )
    with pytest.raises(Exception, match="JSON values"):
        POLICY.load_operator_policy(
            {"exceptions": set()},
            context=_operator_context(verified_engine.verification_config),
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
        ({"candidate_snapshot_sha256": "bad"}, "snapshot digest"),
        ({"candidate_tree_sha": "bad"}, "tree identity"),
        ({"candidate_tree_sha": "a" * 40}, "cannot claim a Git candidate tree"),
        ({"repository_relative_candidate_prefix": "services/a"}, "cannot claim a Git candidate tree"),
        ({"execution_mode": ExecutionMode.PR_BASE}, "exact candidate tree"),
    ],
)
def test_trusted_bundle_invariant_mutations_are_rejected(changes, message, verified_engine) -> None:
    bundle = _bundle(config=verified_engine.verification_config)
    with pytest.raises(Exception, match=message):
        replace(
            bundle,
            **changes,
            _trusted_context=POLICY._TRUSTED_BUNDLE_CONTEXT,
        )


def test_policy_evidence_rejects_caller_and_duplicate_sources(verified_engine) -> None:
    bundle = _bundle(config=verified_engine.verification_config)
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
