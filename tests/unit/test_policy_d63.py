"""D6.3 authorized source-context and trusted-clock regressions."""
from __future__ import annotations

import inspect
import json
import subprocess
from dataclasses import replace
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

import iac_guard_v.engine as ENGINE
import iac_guard_v.policy as POLICY
from iac_guard_v.enums import ExecutionMode, ExceptionOrigin, Outcome, Verdict
from iac_guard_v.engine import PolicySourceAuthorization, TrustedVerificationConfigBundle

from test_policy import _outcome, _policy_payload, _record, _replace_engine, verified_engine


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=repository, check=True,
        capture_output=True, text=True,
    )
    return result.stdout.strip()


def _repository_with_candidate_policy(
    root: Path, payload: dict
) -> tuple[Path, str, str]:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    (root / ".iac-guard.json").write_text(
        json.dumps(_policy_payload(), sort_keys=True), encoding="utf-8"
    )
    (root / "REPOSITORY_ID").write_text(root.name, encoding="utf-8")
    _git(root, "add", ".iac-guard.json", "REPOSITORY_ID")
    _git(root, "commit", "-q", "-m", "actual base")
    base = _git(root, "rev-parse", "HEAD")
    (root / ".iac-guard.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )
    _git(root, "add", ".iac-guard.json")
    _git(root, "commit", "-q", "--allow-empty", "-m", "candidate policy")
    candidate = _git(root, "rev-parse", "HEAD")
    return root, base, candidate


def _pr_config(
    original, repository: Path, base: str, candidate: str, identity: str
):
    authorization = PolicySourceAuthorization(
        ExecutionMode.PR_BASE,
        POLICY._portable_repository_identity(repository),
        base,
        f"git_candidate_{candidate}",
        identity,
        _trusted_context=ENGINE._TRUSTED_POLICY_AUTHORIZATION_CONTEXT,
    )
    return TrustedVerificationConfigBundle(
        original.baseline_root, repository, original.scanner_executable,
        original.frameworks, original.expected_version,
        original.expected_executable_sha256,
        original.expected_scanner_environment_sha256,
        original.expected_policy_inventory_sha256, original.required_gates,
        original.severity_floor, original.fail_on_location_change,
        original.timeout_seconds, original.max_output_bytes,
        original.max_eligible_files, original.max_file_bytes,
        original.max_total_eligible_bytes, original.governed_config,
        identity, "pr_base", authorization, original.gate_registry,
        _trusted_context=ENGINE._TRUSTED_CONFIG_CONTEXT,
    )


def _pr_context(config, repository: Path, base: str, candidate: str, when=None):
    return POLICY.TrustedExecutionContext(
        ExecutionMode.PR_BASE, repository,
        POLICY._portable_repository_identity(repository), base,
        repository, candidate, None, "", "", (".iac-guard.json",),
        config.config_sha256, config.policy_source_authorization.context_identity,
        when or datetime.now(timezone.utc), "protected_workflow_utc_clock",
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )


def test_candidate_commit_cannot_be_selected_as_authorized_base(
    tmp_path: Path, verified_engine
) -> None:
    permissive = _policy_payload(exceptions=(_record(Outcome.SUPPRESSED),))
    repository, actual_base, candidate = _repository_with_candidate_policy(
        tmp_path / "policy-repository", permissive
    )
    config = _pr_config(
        verified_engine.verification_config, repository, actual_base, candidate,
        "protected_pr_context",
    )
    run = _replace_engine(
        _outcome(verified_engine, Outcome.SUPPRESSED), verification_config=config
    )
    context = _pr_context(config, repository, actual_base, candidate)
    bundle = POLICY.load_base_commit_policy(context)
    assert bundle.source_commit == actual_base
    assert bundle.policy.records == ()
    assert bundle.policy_drift is True
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(run, bundle))
    assert result.verdict is Verdict.FAILED

    caller_selected = POLICY.attest_git_source(
        repository, candidate, repository, (".iac-guard.json",)
    )
    with pytest.raises(Exception, match="trusted execution context"):
        POLICY.load_base_commit_policy(caller_selected)


def test_policy_bundle_from_unrelated_repository_is_rejected(
    tmp_path: Path, verified_engine
) -> None:
    repo_a, base_a, candidate_a = _repository_with_candidate_policy(
        tmp_path / "repo-a", _policy_payload()
    )
    repo_b, base_b, candidate_b = _repository_with_candidate_policy(
        tmp_path / "repo-b", _policy_payload()
    )
    config = _pr_config(
        verified_engine.verification_config, repo_a, base_a, candidate_a,
        "shared_context"
    )
    run = _replace_engine(verified_engine, verification_config=config)
    # A private runtime context for another repository cannot satisfy config A's
    # repository authorization even if its context/config strings are copied.
    foreign = POLICY.TrustedExecutionContext(
        ExecutionMode.PR_BASE, repo_b,
        POLICY._portable_repository_identity(repo_b), base_b,
        repo_b, candidate_b, None, "", "", (".iac-guard.json",),
        config.config_sha256, "shared_context", datetime.now(timezone.utc),
        "protected_workflow_utc_clock",
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    foreign_bundle = POLICY.load_base_commit_policy(foreign)
    with pytest.raises(Exception, match="not authorized"):
        POLICY.PolicyRequest(run, foreign_bundle)


def test_public_loader_cannot_revive_expired_exception_with_caller_clock(
    verified_engine,
) -> None:
    expired = _record(
        Outcome.SUPPRESSED, created=date(2025, 1, 1), expires=date(2025, 12, 31)
    )
    context = POLICY.load_operator_execution_context(
        verified_engine.verification_config
    )
    assert context.evaluated_at.tzinfo is not None
    bundle = POLICY.load_operator_policy(
        _policy_payload(exceptions=(expired,)), context=context
    )
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(
        _outcome(verified_engine, Outcome.SUPPRESSED), bundle
    ))
    assert result.verdict is Verdict.FAILED
    assert "_clock" not in inspect.signature(POLICY.load_operator_policy).parameters
    with pytest.raises(TypeError):
        POLICY.load_operator_policy(
            _policy_payload(exceptions=(expired,)), context=context,
            _clock=lambda: datetime(2025, 6, 1, tzinfo=timezone.utc),
        )


def test_execution_context_cannot_be_publicly_self_attested(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    with pytest.raises(Exception, match="protected runtime provenance"):
        POLICY.TrustedExecutionContext(
            ExecutionMode.EXPLICIT_OPERATOR, None, "", "", candidate, "",
            None, "", "", (".iac-guard.json",), "a" * 64, "caller_context",
            datetime.now(timezone.utc), "caller_clock",
        )


def test_candidate_policy_parent_symlink_is_rejected(
    tmp_path: Path, verified_engine
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / "policy").mkdir()
    (repository / "policy/iac.json").write_text(
        json.dumps(_policy_payload()), encoding="utf-8"
    )
    _git(repository, "add", "policy/iac.json")
    _git(repository, "commit", "-q", "-m", "base")
    base = _git(repository, "rev-parse", "HEAD")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "iac.json").write_text(json.dumps(_policy_payload()), encoding="utf-8")
    (repository / "policy/iac.json").unlink()
    (repository / "policy").rmdir()
    (repository / "policy").symlink_to(outside, target_is_directory=True)
    candidate = _git(repository, "rev-parse", "HEAD")
    config = _pr_config(
        verified_engine.verification_config, repository, base, candidate,
        "symlink_context"
    )
    context = POLICY.TrustedExecutionContext(
        ExecutionMode.PR_BASE, repository,
        POLICY._portable_repository_identity(repository), base,
        repository, candidate, None, "", "", ("policy/iac.json",),
        config.config_sha256, "symlink_context", datetime.now(timezone.utc),
        "protected_workflow_utc_clock",
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    with pytest.raises(Exception, match="symlinked parent"):
        POLICY.load_base_commit_policy(context, governed_path="policy/iac.json")


@pytest.mark.parametrize(
    "changes",
    [
        {"evaluated_at": datetime(2026, 1, 1)},
        {"verification_config_sha256": "bad"},
        {"governed_paths": []},
        {"mode": "pr_base"},
    ],
)
def test_execution_context_mutation_guards(tmp_path: Path, changes) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    values = dict(
        mode=ExecutionMode.EXPLICIT_OPERATOR, repository_root=None,
        repository_identity="", authorized_base_commit="",
        candidate_root=candidate, candidate_commit="",
        protected_policy_repository=None,
        protected_policy_repository_identity="", protected_policy_commit="",
        governed_paths=(".iac-guard.json",), verification_config_sha256="a" * 64,
        context_identity="test_context", evaluated_at=datetime.now(timezone.utc),
        clock_source="test_clock",
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    values.update(changes)
    with pytest.raises(Exception):
        POLICY.TrustedExecutionContext(**values)


def test_protected_context_and_repository_loader_are_executable(tmp_path: Path) -> None:
    evaluated, base, candidate = _repository_with_candidate_policy(
        tmp_path / "evaluated", _policy_payload()
    )
    protected, protected_base, _protected_head = _repository_with_candidate_policy(
        tmp_path / "protected", _policy_payload()
    )
    context = POLICY.TrustedExecutionContext(
        ExecutionMode.PROTECTED_POLICY_REPOSITORY,
        evaluated, POLICY._portable_repository_identity(evaluated), base,
        evaluated, candidate,
        protected, POLICY._portable_repository_identity(protected), protected_base,
        (".iac-guard.json",), "a" * 64, "protected_repo_context",
        datetime.now(timezone.utc), "protected_workflow_utc_clock",
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    bundle = POLICY.load_protected_policy_repository(context)
    assert bundle.source_origin is ExceptionOrigin.PROTECTED_POLICY_REPO
    assert bundle.source_repository == POLICY._portable_repository_identity(protected)


def test_protected_execution_context_role_mutations(tmp_path: Path) -> None:
    evaluated, base, candidate = _repository_with_candidate_policy(
        tmp_path / "evaluated", _policy_payload()
    )
    protected, protected_base, _protected_head = _repository_with_candidate_policy(
        tmp_path / "protected", _policy_payload()
    )
    common = dict(
        mode=ExecutionMode.PR_BASE, repository_root=evaluated,
        repository_identity=POLICY._portable_repository_identity(evaluated),
        authorized_base_commit=base, candidate_root=evaluated,
        candidate_commit=candidate, protected_policy_repository=None,
        protected_policy_repository_identity="", protected_policy_commit="",
        governed_paths=(".iac-guard.json",), verification_config_sha256="a" * 64,
        context_identity="role_mutation", evaluated_at=datetime.now(timezone.utc),
        clock_source="protected_clock",
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    mutations = (
        {"candidate_root": "not-a-path"},
        {"repository_root": None},
        {"repository_identity": "wrong_repo"},
        {"authorized_base_commit": "0" * 40},
        {"candidate_commit": "0" * 40},
        {"candidate_root": tmp_path},
        {
            "protected_policy_repository": protected,
            "protected_policy_repository_identity":
                POLICY._portable_repository_identity(protected),
            "protected_policy_commit": protected_base,
        },
    )
    for changes in mutations:
        values = {**common, **changes}
        with pytest.raises(Exception):
            POLICY.TrustedExecutionContext(**values)


def test_operator_context_cannot_claim_git_role(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    with pytest.raises(Exception, match="cannot claim"):
        POLICY.TrustedExecutionContext(
            ExecutionMode.EXPLICIT_OPERATOR, tmp_path, "repo", "a" * 40,
            candidate, "a" * 40, None, "", "", (".iac-guard.json",),
            "a" * 64, "operator_context", datetime.now(timezone.utc),
            "system_clock",
            _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
        )


def test_operator_loader_rejects_pr_context(tmp_path: Path) -> None:
    repository, base, candidate = _repository_with_candidate_policy(
        tmp_path / "repository", _policy_payload()
    )
    # The digest does not need a D5 bundle for this loader-mode guard.
    context = POLICY.TrustedExecutionContext(
        ExecutionMode.PR_BASE, repository,
        POLICY._portable_repository_identity(repository), base,
        repository, candidate, None, "", "", (".iac-guard.json",),
        "a" * 64, "pr_context", datetime.now(timezone.utc), "protected_clock",
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    with pytest.raises(Exception, match="explicit operator"):
        POLICY.load_operator_policy(_policy_payload(), context=context)
    with pytest.raises(Exception, match="PR_BASE"):
        POLICY.load_base_commit_policy(
            POLICY.TrustedExecutionContext(
                ExecutionMode.EXPLICIT_OPERATOR, None, "", "", repository, "",
                None, "", "", (".iac-guard.json",), "a" * 64,
                "operator_context", datetime.now(timezone.utc), "system_clock",
                _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
            )
        )


def test_protected_repository_context_rejects_role_confusion(tmp_path: Path) -> None:
    evaluated, base, candidate = _repository_with_candidate_policy(
        tmp_path / "evaluated", _policy_payload()
    )
    protected, protected_base, _head = _repository_with_candidate_policy(
        tmp_path / "protected", _policy_payload()
    )
    common = dict(
        mode=ExecutionMode.PROTECTED_POLICY_REPOSITORY,
        repository_root=evaluated,
        repository_identity=POLICY._portable_repository_identity(evaluated),
        authorized_base_commit=base, candidate_root=evaluated,
        candidate_commit=candidate, protected_policy_repository=protected,
        protected_policy_repository_identity=
            POLICY._portable_repository_identity(protected),
        protected_policy_commit=protected_base,
        governed_paths=(".iac-guard.json",), verification_config_sha256="a" * 64,
        context_identity="protected_context", evaluated_at=datetime.now(timezone.utc),
        clock_source="protected_clock",
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    for changes in (
        {"protected_policy_repository": None},
        {
            "protected_policy_repository": evaluated,
            "protected_policy_repository_identity":
                POLICY._portable_repository_identity(evaluated),
            "protected_policy_commit": base,
        },
        {"protected_policy_repository_identity": "wrong_identity"},
        {"protected_policy_commit": "0" * 40},
    ):
        with pytest.raises(Exception):
            POLICY.TrustedExecutionContext(**{**common, **changes})


def test_policy_request_rejects_context_and_origin_substitution(verified_engine) -> None:
    context = POLICY.load_operator_execution_context(
        verified_engine.verification_config
    )
    bundle = POLICY.load_operator_policy(_policy_payload(), context=context)
    wrong_context = replace(
        bundle, execution_context_identity="another_context",
        _trusted_context=POLICY._TRUSTED_BUNDLE_CONTEXT,
    )
    with pytest.raises(Exception, match="not authorized"):
        POLICY.PolicyRequest(verified_engine, wrong_context)
    wrong_origin = replace(
        bundle, source_origin=ExceptionOrigin.TRUSTED_BASE,
        _trusted_context=POLICY._TRUSTED_BUNDLE_CONTEXT,
    )
    with pytest.raises(Exception, match="origin"):
        POLICY.PolicyRequest(verified_engine, wrong_origin)


def test_operator_context_rejects_pr_authorized_config(
    tmp_path: Path, verified_engine
) -> None:
    repository, base, _candidate = _repository_with_candidate_policy(
        tmp_path / "repository", _policy_payload()
    )
    config = _pr_config(
        verified_engine.verification_config, repository, base, _candidate, "pr_context"
    )
    with pytest.raises(Exception, match="explicit-operator"):
        POLICY.load_operator_execution_context(config)
