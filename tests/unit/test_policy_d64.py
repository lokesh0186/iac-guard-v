"""D6.4 candidate-tree, governed-directory, and snapshot-binding regressions."""
from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import iac_guard_v.engine as ENGINE
import iac_guard_v.policy as POLICY
from iac_guard_v.enums import ExecutionMode
from iac_guard_v.engine import PolicySourceAuthorization, TrustedVerificationConfigBundle

from test_policy import _bundle, _policy_payload, _replace_engine, verified_engine


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=repository, check=True,
        capture_output=True, text=True,
    )
    return result.stdout.strip()


def _repository(root: Path, *, prefix: str = ".") -> tuple[Path, str, str, Path]:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    candidate_root = root if prefix == "." else root / prefix
    candidate_root.mkdir(parents=True, exist_ok=True)
    (candidate_root / ".iac-guard.json").write_text(
        json.dumps(_policy_payload(), sort_keys=True), encoding="utf-8"
    )
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "candidate-marker").write_text("candidate\n", encoding="utf-8")
    _git(root, "add", "candidate-marker")
    _git(root, "commit", "-q", "-m", "candidate")
    candidate = _git(root, "rev-parse", "HEAD")
    return root, base, candidate, candidate_root


def _config(original, repository: Path, candidate_root: Path, base: str, candidate: str):
    identity = "protected_d64_context"
    authorization = PolicySourceAuthorization(
        ExecutionMode.PR_BASE,
        POLICY._portable_repository_identity(repository),
        base,
        f"git_candidate_{candidate}",
        identity,
        _trusted_context=ENGINE._TRUSTED_POLICY_AUTHORIZATION_CONTEXT,
    )
    return TrustedVerificationConfigBundle(
        original.baseline_root, candidate_root, original.scanner_executable,
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


def _context(config, repository: Path, candidate_root: Path, base: str, candidate: str,
             governed_paths: tuple = (".iac-guard.json",)):
    prefix = candidate_root.relative_to(repository).as_posix() or "."
    return POLICY.TrustedExecutionContext(
        ExecutionMode.PR_BASE, repository,
        POLICY._portable_repository_identity(repository), base,
        candidate_root, candidate, None, "", "", governed_paths,
        config.config_sha256, config.policy_source_authorization.context_identity,
        datetime.now(timezone.utc), "protected_workflow_utc_clock",
        prefix, config.candidate_source_snapshot_sha256,
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )


def test_candidate_worktree_must_equal_authorized_commit(tmp_path, verified_engine) -> None:
    repository, base, candidate, root = _repository(tmp_path / "repository")
    config = _config(verified_engine.verification_config, repository, root, base, candidate)
    (root / ".iac-guard.json").write_text("{}", encoding="utf-8")
    with pytest.raises(Exception, match="checkout differs"):
        _context(config, repository, root, base, candidate)


def test_context_rejects_head_prefix_and_snapshot_substitution(
    tmp_path, verified_engine
) -> None:
    repository, base, candidate, root = _repository(tmp_path / "repository")
    config = _config(verified_engine.verification_config, repository, root, base, candidate)
    common = dict(
        mode=ExecutionMode.PR_BASE,
        repository_root=repository,
        repository_identity=POLICY._portable_repository_identity(repository),
        authorized_base_commit=base,
        candidate_root=root,
        candidate_commit=candidate,
        protected_policy_repository=None,
        protected_policy_repository_identity="",
        protected_policy_commit="",
        governed_paths=(".iac-guard.json",),
        verification_config_sha256=config.config_sha256,
        context_identity=config.policy_source_authorization.context_identity,
        evaluated_at=datetime.now(timezone.utc),
        clock_source="protected_workflow_utc_clock",
        repository_relative_candidate_prefix=".",
        candidate_snapshot_sha256=config.candidate_source_snapshot_sha256,
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    with pytest.raises(Exception, match="HEAD"):
        POLICY.TrustedExecutionContext(**{**common, "candidate_commit": base})
    with pytest.raises(Exception, match="prefix"):
        POLICY.TrustedExecutionContext(**{
            **common, "repository_relative_candidate_prefix": "wrong",
        })
    with pytest.raises(Exception, match="snapshot digest"):
        POLICY.TrustedExecutionContext(**{
            **common, "candidate_snapshot_sha256": "bad",
        })


def test_context_is_revalidated_before_policy_bytes_are_loaded(
    tmp_path, verified_engine
) -> None:
    repository, base, candidate, root = _repository(tmp_path / "repository")
    config = _config(verified_engine.verification_config, repository, root, base, candidate)
    context = _context(config, repository, root, base, candidate)
    (root / "late.tf").write_text("resource \"x\" \"y\" {}\n", encoding="utf-8")
    with pytest.raises(Exception, match="checkout differs"):
        POLICY.load_base_commit_policy(context)


def test_ignored_untracked_supported_file_is_not_hidden(
    tmp_path, verified_engine
) -> None:
    repository, base, _candidate, root = _repository(tmp_path / "repository")
    (repository / ".gitignore").write_text("*.tf\n", encoding="utf-8")
    _git(repository, "add", ".gitignore")
    _git(repository, "commit", "-q", "-m", "ignore")
    candidate = _git(repository, "rev-parse", "HEAD")
    config = _config(verified_engine.verification_config, repository, root, base, candidate)
    (root / "ignored.tf").write_text("resource \"x\" \"y\" {}\n", encoding="utf-8")
    with pytest.raises(Exception, match="ignored supported or governed"):
        _context(config, repository, root, base, candidate)


@pytest.mark.parametrize("governed_directory", [".iac-guard", "custom_checks"])
def test_committed_governed_symlink_directory_is_explicit_drift(
    tmp_path, verified_engine, governed_directory
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / ".iac-guard.json").write_text(
        json.dumps(_policy_payload(), sort_keys=True), encoding="utf-8"
    )
    directory = repository / governed_directory
    directory.mkdir()
    (directory / "policy.txt").write_text("base\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "base")
    base = _git(repository, "rev-parse", "HEAD")
    _git(repository, "rm", "-q", "-r", governed_directory)
    directory.symlink_to("outside-policy", target_is_directory=True)
    _git(repository, "add", governed_directory)
    _git(repository, "commit", "-q", "-m", "symlink governed directory")
    candidate = _git(repository, "rev-parse", "HEAD")
    config = _config(
        verified_engine.verification_config, repository, repository, base, candidate
    )
    context = _context(
        config, repository, repository, base, candidate,
        (".iac-guard.json", governed_directory),
    )
    bundle = POLICY.load_base_commit_policy(context)
    evidence = {item.file_path: item for item in bundle.governed_config_evidence}
    assert evidence[governed_directory].candidate_kind == "SYMLINK"
    assert evidence[governed_directory].state == "type_changed"
    assert governed_directory in bundle.differing_governed_paths


def test_monorepo_prefix_applies_to_base_and_candidate_objects(
    tmp_path, verified_engine
) -> None:
    repository, base, candidate, root = _repository(
        tmp_path / "repository", prefix="services/team-a"
    )
    config = _config(verified_engine.verification_config, repository, root, base, candidate)
    context = _context(config, repository, root, base, candidate)
    bundle = POLICY.load_base_commit_policy(context)
    assert bundle.policy_drift is False
    assert bundle.repository_relative_candidate_prefix == "services/team-a"
    assert bundle.candidate_tree_sha == context.candidate_tree_sha
    assert "services/team-a" in bundle.canonical_dict()[
        "repository_relative_candidate_prefix"
    ]


def test_policy_request_rejects_snapshot_digest_substitution(
    tmp_path, verified_engine
) -> None:
    repository, base, candidate, root = _repository(tmp_path / "repository")
    config = _config(verified_engine.verification_config, repository, root, base, candidate)
    context = POLICY.TrustedExecutionContext(
        ExecutionMode.PR_BASE, repository,
        POLICY._portable_repository_identity(repository), base,
        root, candidate, None, "", "", (".iac-guard.json",),
        config.config_sha256, config.policy_source_authorization.context_identity,
        datetime.now(timezone.utc), "protected_workflow_utc_clock",
        ".", "f" * 64,
        _trusted_context=POLICY._TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )
    bundle = POLICY.load_base_commit_policy(context)
    run = _replace_engine(verified_engine, verification_config=config)
    # Even private runtime plumbing cannot attach policy from a different D5 snapshot.
    with pytest.raises(Exception, match="not authorized"):
        POLICY.PolicyRequest(run, bundle)


def test_no_follow_policy_reader_mutations_are_typed(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(Exception, match="pathlib.Path"):
        POLICY._read_policy_bytes("bad", required=True)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(Exception, match="outside"):
        POLICY._read_policy_bytes(outside, required=True, trusted_root=root)
    with pytest.raises(Exception, match="parent path"):
        POLICY._read_policy_bytes(
            root / "missing" / "policy.json", required=True, trusted_root=root
        )
    nondirectory = root / "file"
    nondirectory.write_text("x", encoding="utf-8")
    with pytest.raises(Exception, match="not a directory"):
        POLICY._read_policy_bytes(
            nondirectory / "policy.json", required=True, trusted_root=root
        )
    assert POLICY._read_policy_bytes(root / "absent.json", required=False) is None
    with pytest.raises(Exception, match="does not exist"):
        POLICY._read_policy_bytes(root / "absent.json", required=True)
    with pytest.raises(Exception, match="regular file"):
        POLICY._read_policy_bytes(root, required=True)
    oversized = root / "oversized.json"
    oversized.write_bytes(b"x" * (POLICY._MAX_POLICY_BYTES + 1))
    with pytest.raises(Exception, match="byte limit"):
        POLICY._read_policy_bytes(oversized, required=True)


def test_json_lexer_and_canonical_date_mutations_are_executable() -> None:
    POLICY._json_depth(b'{"escaped":"a\\\\b\\\"c"}')
    with pytest.raises(Exception, match="nonempty"):
        POLICY._parse_policy_bytes(b"")
    # CPython 3.11+ parses compact ISO dates before our canonical-form guard;
    # 3.10 rejects the same input in the standard parser. Both must reject it.
    with pytest.raises(Exception):
        POLICY._parse_date("20260811", "created")


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"candidate_policy_state": "present", "candidate_policy_sha256": "bad"}, "bind present"),
        ({"candidate_policy_state": "missing", "candidate_policy_sha256": "a" * 64}, "no byte digest"),
        ({"governed_config_evidence": []}, "typed tuple"),
        ({"source_commit": "bad"}, "full Git SHA"),
        ({"source_repository": "git_repo", "source_commit": ""}, "non-Git"),
        ({"source_commit": "a" * 40, "source_repository": ""}, "repository identity"),
        ({"verification_config_sha256": "bad"}, "config digest"),
    ],
)
def test_policy_bundle_additional_mutation_guards(
    verified_engine, changes, message
) -> None:
    bundle = _bundle(config=verified_engine.verification_config)
    with pytest.raises(Exception, match=message):
        replace(
            bundle,
            **changes,
            _trusted_context=POLICY._TRUSTED_BUNDLE_CONTEXT,
        )
