"""UX.2 exact Git-object workflow and target-binding tests."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import iac_guard_v.cli as CLI
from iac_guard_v.config import PublicTarget
from iac_guard_v.enums import ArtifactKind
from iac_guard_v.report import OperationalReportV1
from iac_guard_v.workflow import materialize_git_comparison


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    source = root / "main.tf"
    source.write_text('resource "aws_x" "r" { value = false }\n', encoding="utf-8")
    _git(root, "add", "main.tf")
    _git(root, "commit", "-q", "-m", "baseline")
    baseline = _git(root, "rev-parse", "HEAD")
    source.write_text('resource "aws_x" "r" { value = true }\n', encoding="utf-8")
    _git(root, "add", "main.tf")
    _git(root, "commit", "-q", "-m", "candidate")
    candidate = _git(root, "rev-parse", "HEAD")
    return root, baseline, candidate


def _target() -> PublicTarget:
    return PublicTarget(
        "CKV_X", "aws_x.r", "main.tf", ArtifactKind.TERRAFORM_HCL, "aws_x.r",
    )


def test_git_materialization_reads_exact_objects_without_touching_checkout(
    tmp_path: Path,
) -> None:
    repository, baseline, candidate = _repository(tmp_path)
    (repository / "untracked.txt").write_text("operator state\n", encoding="utf-8")
    head_before = _git(repository, "rev-parse", "HEAD")
    index_before = _git(repository, "write-tree")
    status_before = _git(repository, "status", "--porcelain=v1", "-uall")
    temporary_root = None
    with materialize_git_comparison(repository, baseline, candidate) as materialized:
        temporary_root = materialized.baseline_root.parent
        assert materialized.base_commit == baseline
        assert materialized.head_commit == candidate
        assert materialized.changed_paths == ("main.tf",)
        assert "value = false" in (materialized.baseline_root / "main.tf").read_text()
        assert "value = true" in (materialized.candidate_root / "main.tf").read_text()
        assert not (materialized.candidate_root / "untracked.txt").exists()
        assert materialized.repository_identity.startswith("git_repository_v1_")
    assert temporary_root is not None and not temporary_root.exists()
    assert _git(repository, "rev-parse", "HEAD") == head_before
    assert _git(repository, "write-tree") == index_before
    assert _git(repository, "status", "--porcelain=v1", "-uall") == status_before


def test_git_pr_changed_only_filters_selection_but_verifies_complete_trees(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    repository, baseline, candidate = _repository(tmp_path)
    checkov = tmp_path / "checkov"
    checkov.write_bytes(b"launcher")
    checkov.chmod(0o700)
    seen = {}

    def discover(root, executable, frameworks, selectors, **options):
        seen["discovery_root"] = root
        seen["executable"] = executable
        seen["frameworks"] = frameworks
        seen["selectors"] = selectors
        seen["eligible_paths"] = options["eligible_paths"]
        return (_target(),)

    def verify_git(request, materialization):
        seen["request"] = request
        seen["materialization"] = materialization
        assert (request.baseline_root / "main.tf").exists()
        assert (request.candidate_root / "main.tf").exists()
        return OperationalReportV1("EXPECTED", "detail", "remediation")

    monkeypatch.setattr(CLI, "discover_baseline_targets", discover)
    monkeypatch.setattr(CLI, "_verify_git", verify_git)
    output = tmp_path / "report.json"
    assert CLI.main([
        "pr", "--repository", str(repository), "--base-ref", baseline,
        "--head-ref", candidate, "--all-baseline-findings", "--changed-only",
        "--framework", "terraform", "--local-trusted",
        "--checkov-executable", str(checkov), "--format", "json",
        "--output", str(output),
    ]) == 3
    assert json.loads(capsys.readouterr().out)["verdict"] == "INCONCLUSIVE"
    assert json.loads(output.read_text())["verdict"] == "INCONCLUSIVE"
    assert seen["eligible_paths"] == ("main.tf",)
    assert seen["frameworks"] == ("terraform",)
    assert seen["materialization"]._trusted is True
    assert not seen["request"].baseline_root.exists()
    assert not seen["request"].candidate_root.exists()


def test_init_binds_simple_selector_and_generated_config_works_with_pr(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    (baseline / "main.tf").write_text('resource "aws_x" "r" {}\n', encoding="utf-8")
    (candidate / "main.tf").write_text(
        'resource "aws_x" "r" {}\n# changed\n', encoding="utf-8"
    )
    config = tmp_path / "config.json"
    assert CLI.main([
        "init", "--baseline", str(baseline), "--candidate", str(candidate),
        "--target", "CKV_X=aws_x.r", "--framework", "terraform",
        "--output", str(config), "--format", "json",
    ]) == 0
    capsys.readouterr()
    target = json.loads(config.read_text())["targets"][0]
    assert target["file_path"] == "main.tf"
    assert target["artifact_kind"] == "terraform_hcl"
    assert target["scanner_native_lookup"] == "aws_x.r"
    monkeypatch.setattr(
        CLI, "verify", lambda _request: OperationalReportV1("EXPECTED", "detail", "fix")
    )
    assert CLI.main([
        "pr", "--config", str(config), "--changed-only", "--format", "json",
    ]) == 3
    assert json.loads(capsys.readouterr().out)["verdict"] == "INCONCLUSIVE"


def test_git_pr_rejects_unsafe_ref_and_never_executes_verifier(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    repository, _baseline, candidate = _repository(tmp_path)
    checkov = tmp_path / "checkov"
    checkov.write_bytes(b"launcher")
    checkov.chmod(0o700)
    monkeypatch.setattr(CLI, "_verify_git", lambda *_: (_ for _ in ()).throw(
        AssertionError("unsafe ref must not reach verification")
    ))
    assert CLI.main([
        "pr", "--repository", str(repository), "--base-ref=--upload-pack=bad",
        "--head-ref", candidate, "--target", "CKV_X=aws_x.r",
        "--local-trusted", "--checkov-executable", str(checkov),
    ]) == 2
    assert "safe Git ref" in json.loads(capsys.readouterr().err)["detail"]


def test_git_pr_hardened_mode_does_not_materialize_or_downgrade(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    repository, baseline, candidate = _repository(tmp_path)
    monkeypatch.setattr(
        CLI, "materialize_git_comparison", lambda *_: (_ for _ in ()).throw(
            AssertionError("unavailable hardened mode must not use local Git trees")
        )
    )
    assert CLI.main([
        "pr", "--repository", str(repository), "--base-ref", baseline,
        "--head-ref", candidate, "--all-baseline-findings", "--format", "json",
    ]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["diagnostic"]["reason_code"] == "HARDENED_CONTAINER_UNAVAILABLE"
