"""D6.2 mechanically attested policy-source and exact-permission regressions."""
from __future__ import annotations

import inspect
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

import iac_guard_v.policy as POLICY
from iac_guard_v.enums import ExceptionOrigin, Outcome, Verdict
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import ResolvedTargetBinding
from test_engine import IDENTITY

from test_policy import _outcome, _policy_payload, _record, verified_engine


NOW = lambda: datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)  # noqa: E731


def test_base_loader_no_longer_accepts_arbitrary_trusted_paths_or_identity() -> None:
    parameters = inspect.signature(POLICY.load_base_commit_policy).parameters
    assert "trusted_path" not in parameters
    assert "candidate_path" not in parameters
    assert "source_identity" not in parameters


def test_candidate_file_cannot_be_presented_as_its_own_base(
    tmp_path: Path,
) -> None:
    payload = _policy_payload(exceptions=(_record(Outcome.SUPPRESSED),))
    candidate = tmp_path / "candidate-policy.json"
    candidate.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(TypeError):
        POLICY.load_base_commit_policy(
            candidate,
            candidate,
            source_identity="claimed-base",
            _clock=NOW,
        )


def test_coarse_exception_without_resolved_target_cannot_authorise(
    verified_engine,
) -> None:
    run = _outcome(verified_engine, Outcome.SUPPRESSED)
    payload = _policy_payload(exceptions=(_record(Outcome.SUPPRESSED),))
    target = payload["exceptions"][0]["target"]
    for field in ("file_path", "artifact_kind", "scanner_native_lookup"):
        target.pop(field)
    with pytest.raises(Exception, match="exact"):
        POLICY.load_operator_policy(
            payload, source_identity="operator-coarse-record", _clock=NOW
        )


def test_same_coarse_identity_wrong_file_exception_is_not_permission(
    verified_engine,
) -> None:
    run = _outcome(verified_engine, Outcome.SUPPRESSED)
    wrong = ResolvedTargetBinding(
        IDENTITY, "other/main.tf", ArtifactKind.TERRAFORM_HCL, "aws_x.r"
    )
    bundle = POLICY.load_operator_policy(
        _policy_payload(exceptions=(
            _record(Outcome.SUPPRESSED, resolved_target=wrong),
        )),
        source_identity="operator-wrong-file",
        _clock=NOW,
    )
    result = POLICY.evaluate_policy(POLICY.PolicyRequest(run, bundle))
    assert result.decisions[0].policy_permitted is False
    assert result.verdict is Verdict.FAILED


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def git_policy_repository(tmp_path: Path) -> tuple[Path, str, dict]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    payload = _policy_payload()
    (repo / ".iac-guard.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )
    _git(repo, "add", ".iac-guard.json")
    _git(repo, "commit", "-q", "-m", "base policy")
    return repo, _git(repo, "rev-parse", "HEAD"), payload


def test_git_base_loader_reads_committed_object_not_candidate_bytes(
    tmp_path: Path,
) -> None:
    repo, base_sha, payload = git_policy_repository(tmp_path)
    candidate = {
        **payload,
        "exceptions": _policy_payload(
            exceptions=(_record(Outcome.SUPPRESSED),)
        )["exceptions"],
    }
    (repo / ".iac-guard.json").write_text(json.dumps(candidate), encoding="utf-8")
    source = POLICY.attest_git_source(
        repo,
        base_sha,
        repo,
        (".iac-guard.json",),
    )
    bundle = POLICY.load_base_commit_policy(
        source, governed_path=".iac-guard.json", _clock=NOW
    )
    assert bundle.source_origin is ExceptionOrigin.TRUSTED_BASE
    assert bundle.source_commit == base_sha
    assert bundle.source_identity == f"git_commit_{base_sha}"
    assert bundle.policy_drift is True
    assert len(bundle.policy.records) == 0


def test_protected_policy_source_must_be_pinned_and_outside_workspace(
    tmp_path: Path,
) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    workspace = repo / "candidate"
    workspace.mkdir()
    with pytest.raises(Exception, match="outside"):
        POLICY.attest_protected_policy_repository(
            repo, commit, workspace, (".iac-guard.json",)
        )
    outside_workspace = tmp_path / "evaluated"
    outside_workspace.mkdir()
    with pytest.raises(Exception, match="pinned"):
        POLICY.attest_protected_policy_repository(
            repo, "0" * 40, outside_workspace, (".iac-guard.json",)
        )


def test_git_bundle_retains_path_by_path_governed_policy_evidence(
    tmp_path: Path,
) -> None:
    repo, _old_commit, _payload = git_policy_repository(tmp_path)
    governed = repo / "config" / "severity-policy.json"
    governed.parent.mkdir()
    governed.write_text('{"severity_floor":"HIGH"}', encoding="utf-8")
    _git(repo, "add", "config/severity-policy.json")
    _git(repo, "commit", "-q", "-m", "governed policy")
    base_commit = _git(repo, "rev-parse", "HEAD")
    governed.write_text('{"severity_floor":"CRITICAL"}', encoding="utf-8")
    source = POLICY.attest_git_source(
        repo,
        base_commit,
        repo,
        (".iac-guard.json", "config/severity-policy.json"),
    )
    bundle = POLICY.load_base_commit_policy(source, _clock=NOW)
    assert bundle.policy_drift is True
    assert bundle.differing_governed_paths == ("config/severity-policy.json",)
    by_path = {
        item.file_path: item for item in bundle.governed_config_evidence
    }
    assert by_path[".iac-guard.json"].state == "stable"
    assert by_path["config/severity-policy.json"].state == "changed"
    canonical = bundle.canonical_dict()
    assert canonical["source_commit"] == base_commit
    assert canonical["source_repository"].startswith("git_repo_")


def test_git_policy_tree_entry_must_be_regular_not_symlink(tmp_path: Path) -> None:
    repo = tmp_path / "symlink-repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    outside = repo / "actual.json"
    outside.write_text(json.dumps(_policy_payload()), encoding="utf-8")
    (repo / ".iac-guard.json").symlink_to(outside.name)
    _git(repo, "add", ".iac-guard.json", "actual.json")
    _git(repo, "commit", "-q", "-m", "symlink policy")
    commit = _git(repo, "rev-parse", "HEAD")
    source = POLICY.attest_git_source(
        repo, commit, repo, (".iac-guard.json",)
    )
    with pytest.raises(Exception, match="regular repository file"):
        POLICY.load_base_commit_policy(source, _clock=NOW)


@pytest.mark.parametrize("bad_ref", ["", "-HEAD", "bad\nref", 1])
def test_git_ref_grammar_is_fail_closed(tmp_path: Path, bad_ref) -> None:
    repo, _commit, _payload = git_policy_repository(tmp_path)
    with pytest.raises(Exception, match="malformed"):
        POLICY.attest_git_source(
            repo, bad_ref, repo, (".iac-guard.json",)
        )


def test_git_source_attestation_rejects_untrusted_shapes(tmp_path: Path) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(Exception, match="pathlib.Path"):
        POLICY.attest_git_source("repo", commit, repo, (".iac-guard.json",))
    with pytest.raises(Exception, match="strictly resolved"):
        POLICY.attest_git_source(
            tmp_path / "missing", commit, repo, (".iac-guard.json",)
        )
    with pytest.raises(Exception, match="inside"):
        POLICY.attest_git_source(repo, commit, outside, (".iac-guard.json",))
    subdirectory = repo / "subdirectory"
    subdirectory.mkdir()
    with pytest.raises(Exception, match="canonical repository root"):
        POLICY.attest_git_source(
            subdirectory, commit, subdirectory, (".iac-guard.json",)
        )
    with pytest.raises(Exception, match="mechanical attestation"):
        POLICY.TrustedGitSource(
            repo, commit, repo, (".iac-guard.json",), ExceptionOrigin.TRUSTED_BASE
        )


@pytest.mark.parametrize(
    "paths, origin, message",
    [
        ((), ExceptionOrigin.TRUSTED_BASE, "nonempty tuple"),
        ((".iac-guard.json", ".iac-guard.json"), ExceptionOrigin.TRUSTED_BASE, "duplicates"),
        ((".iac-guard.json",), ExceptionOrigin.OPERATOR, "not protected"),
    ],
)
def test_trusted_git_source_internal_invariants(
    tmp_path: Path, paths: tuple, origin: ExceptionOrigin, message: str
) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    with pytest.raises(Exception, match=message):
        POLICY.TrustedGitSource(
            repo,
            commit,
            repo,
            paths,
            origin,
            _trusted_context=POLICY._TRUSTED_GIT_SOURCE_CONTEXT,
        )


def test_git_loader_rejects_wrong_origin_or_unattested_path(tmp_path: Path) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    source = POLICY.attest_git_source(
        repo, commit, repo, (".iac-guard.json",)
    )
    with pytest.raises(Exception, match="provenance"):
        POLICY.load_protected_policy_repository(source, _clock=NOW)
    with pytest.raises(Exception, match="outside the attested"):
        POLICY.load_base_commit_policy(
            source, governed_path="other.json", _clock=NOW
        )


def test_candidate_only_governed_file_is_added_policy_drift(tmp_path: Path) -> None:
    repo, base_commit, _payload = git_policy_repository(tmp_path)
    added = repo / ".checkov.yml"
    added.write_text("skip-check: CKV_X\n", encoding="utf-8")
    source = POLICY.attest_git_source(
        repo, base_commit, repo, (".iac-guard.json", ".checkov.yml")
    )
    bundle = POLICY.load_base_commit_policy(source, _clock=NOW)
    assert bundle.differing_governed_paths == (".checkov.yml",)
    checkov = next(
        item for item in bundle.governed_config_evidence
        if item.file_path == ".checkov.yml"
    )
    assert checkov.state == "added"
    assert checkov.trusted_sha256 is None
    assert checkov.candidate_sha256 is not None


def test_git_command_execution_failures_are_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    monkeypatch.setattr(POLICY.shutil, "which", lambda _name: None)
    with pytest.raises(Exception, match="unavailable"):
        POLICY.attest_git_source(repo, commit, repo, (".iac-guard.json",))
    monkeypatch.setattr(POLICY.shutil, "which", lambda _name: "/usr/bin/git")

    def fail_run(*_args, **_kwargs):
        raise OSError("execution blocked")

    monkeypatch.setattr(POLICY.subprocess, "run", fail_run)
    with pytest.raises(Exception, match="attestation failed"):
        POLICY.attest_git_source(repo, commit, repo, (".iac-guard.json",))


def test_protected_attestation_rejects_bad_source_shapes(tmp_path: Path) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(Exception, match="pathlib.Path"):
        POLICY.attest_protected_policy_repository(
            "repo", commit, workspace, (".iac-guard.json",)
        )
    with pytest.raises(Exception, match="strictly resolved"):
        POLICY.attest_protected_policy_repository(
            tmp_path / "missing", commit, workspace, (".iac-guard.json",)
        )
    with pytest.raises(Exception, match="pinned full SHA"):
        POLICY.attest_protected_policy_repository(
            repo, "HEAD", workspace, (".iac-guard.json",)
        )


def test_corrupt_git_plumbing_results_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    def corrupt_commit(_repository, arguments):
        if arguments == ("rev-parse", "--show-toplevel"):
            return (str(repo) + "\n").encode("utf-8")
        return b"not-a-sha\n"

    monkeypatch.setattr(POLICY, "_git_command", corrupt_commit)
    with pytest.raises(Exception, match="commit SHA"):
        POLICY.attest_git_source(repo, commit, repo, (".iac-guard.json",))

    monkeypatch.setattr(POLICY, "_git_command", lambda *_args: b"")
    with pytest.raises(Exception, match="no exact tree entry"):
        POLICY._git_object_bytes(repo, commit, ".iac-guard.json")

    def malformed_size(_repository, arguments):
        if arguments[0] == "ls-tree":
            return b"100644 blob deadbeef\t.iac-guard.json\x00"
        return b"not-a-size"

    monkeypatch.setattr(POLICY, "_git_command", malformed_size)
    with pytest.raises(Exception, match="size is malformed"):
        POLICY._git_object_bytes(repo, commit, ".iac-guard.json")

    def changed_size(_repository, arguments):
        if arguments[0] == "ls-tree":
            return b"100644 blob deadbeef\t.iac-guard.json\x00"
        if arguments[:2] == ("cat-file", "-s"):
            return b"2\n"
        return b"x"

    monkeypatch.setattr(POLICY, "_git_command", changed_size)
    with pytest.raises(Exception, match="size changed"):
        POLICY._git_object_bytes(repo, commit, ".iac-guard.json")


def test_trusted_git_source_rejects_bad_internal_paths_and_commit(
    tmp_path: Path,
) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    context = POLICY._TRUSTED_GIT_SOURCE_CONTEXT
    with pytest.raises(Exception, match="pathlib.Path"):
        POLICY.TrustedGitSource(
            "repo", commit, repo, (".iac-guard.json",),
            ExceptionOrigin.TRUSTED_BASE, _trusted_context=context,
        )
    with pytest.raises(Exception, match="full commit SHA"):
        POLICY.TrustedGitSource(
            repo, "bad-sha", repo, (".iac-guard.json",),
            ExceptionOrigin.TRUSTED_BASE, _trusted_context=context,
        )


def test_governed_path_absent_on_both_sides_does_not_invent_drift(
    tmp_path: Path,
) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    source = POLICY.attest_git_source(
        repo, commit, repo, (".iac-guard.json", "optional-missing.json")
    )
    bundle = POLICY.load_base_commit_policy(source, _clock=NOW)
    assert bundle.policy_drift is False
    assert tuple(
        item.file_path for item in bundle.governed_config_evidence
    ) == (".iac-guard.json",)


def test_protected_resolved_commit_must_equal_pinned_sha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    workspace = tmp_path / "workspace-pin"
    workspace.mkdir()
    replacement = "f" * 40 if commit != "f" * 40 else "e" * 40
    monkeypatch.setattr(POLICY, "_resolve_git_commit", lambda *_args: replacement)
    with pytest.raises(Exception, match="did not resolve the pinned commit"):
        POLICY.attest_protected_policy_repository(
            repo, commit, workspace, (".iac-guard.json",)
        )


def test_optional_git_object_inspection_error_is_not_treated_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, commit, _payload = git_policy_repository(tmp_path)
    source = POLICY.attest_git_source(
        repo, commit, repo, (".iac-guard.json", "optional.json")
    )

    def inspection_failure(*_args):
        raise POLICY.DomainError("inspection unavailable")

    monkeypatch.setattr(POLICY, "_git_command", inspection_failure)
    with pytest.raises(Exception, match="inspection unavailable"):
        POLICY._optional_git_object(source, "optional.json")
