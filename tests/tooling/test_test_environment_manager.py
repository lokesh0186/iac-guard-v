"""Adversarial tests for the local persistent-environment harness."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tools.testing import env_manager
from tools.testing.env_manager import HarnessError
from tools.testing.results import RunSummary


def _inputs(root: Path) -> None:
    (root / "tools/testing").mkdir(parents=True)
    (root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (root / "tools/testing/requirements-nox.txt").write_text(
        "nox==2026.8.17\n", encoding="utf-8"
    )
    (root / "tools/testing/requirements-checkov-3.3.0.txt").write_text(
        "checkov==3.3.0\n", encoding="utf-8"
    )


def _expected(root: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    monkeypatch.setattr(
        env_manager,
        "python_identity",
        lambda *_args, **_kwargs: {
            "implementation": "CPython",
            "version": "3.12.4",
            "machine": env_manager.platform.machine(),
            "platform": sys.platform,
            "executable": {
                "kind": "system",
                "display": "/opt/python3.12",
                "path_sha256": "a" * 64,
                "file_sha256": "b" * 64,
            },
        },
    )
    return env_manager.expected_environment(
        root=root,
        python=Path(sys.executable),
        kind="compat",
        session_name="tests-3.12",
    )


def test_fingerprint_is_stable_for_same_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    first = _expected(tmp_path, monkeypatch)
    second = _expected(tmp_path, monkeypatch)
    assert first == second
    assert first["environment_fingerprint"] == second["environment_fingerprint"]


def test_dependency_change_invalidates_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    first = _expected(tmp_path, monkeypatch)["environment_fingerprint"]
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='changed'\n", encoding="utf-8"
    )
    second = _expected(tmp_path, monkeypatch)["environment_fingerprint"]
    assert first != second


def test_python_identity_change_invalidates_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    first = _expected(tmp_path, monkeypatch)
    changed = dict(first)
    python = dict(changed["python"])
    python["version"] = "3.12.5"
    changed["python"] = python
    changed.pop("environment_fingerprint")
    assert env_manager.sha256_bytes(env_manager.canonical_json(changed)) != (
        first["environment_fingerprint"]
    )


def test_session_refuses_wrong_python_minor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    _expected(tmp_path, monkeypatch)
    monkeypatch.setattr(
        env_manager,
        "python_identity",
        lambda *_args, **_kwargs: {
            "implementation": "CPython",
            "version": "3.11.9",
            "machine": env_manager.platform.machine(),
            "platform": sys.platform,
            "executable": {},
        },
    )
    with pytest.raises(HarnessError, match="PYTHON_INTERPRETER_MISSING"):
        env_manager.expected_environment(
            root=tmp_path,
            python=Path(sys.executable),
            kind="compat",
            session_name="tests-3.12",
        )


def test_architecture_change_invalidates_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    first = _expected(tmp_path, monkeypatch)
    changed = dict(first)
    changed["architecture"] = "synthetic-other-architecture"
    changed.pop("environment_fingerprint")
    assert env_manager.sha256_bytes(env_manager.canonical_json(changed)) != (
        first["environment_fingerprint"]
    )


def test_host_interpreter_architecture_mismatch_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    monkeypatch.setattr(env_manager.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(
        env_manager,
        "python_identity",
        lambda *_args, **_kwargs: {
            "implementation": "CPython",
            "version": "3.12.4",
            "machine": "x86_64",
            "platform": "darwin",
            "executable": {},
        },
    )
    with pytest.raises(HarnessError, match="PYTHON_ARCHITECTURE_MISMATCH"):
        env_manager.expected_environment(
            root=tmp_path,
            python=Path(sys.executable),
            kind="compat",
            session_name="tests-3.12",
        )


def test_install_contract_change_invalidates_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    first = _expected(tmp_path, monkeypatch)
    changed = dict(first)
    changed["no_compile"] = False
    changed.pop("environment_fingerprint")
    assert env_manager.sha256_bytes(env_manager.canonical_json(changed)) != (
        first["environment_fingerprint"]
    )


def test_stale_metadata_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    expected = _expected(tmp_path, monkeypatch)
    actual = {**expected, "environment_fingerprint": "0" * 64}
    with pytest.raises(HarnessError, match="TEST_ENVIRONMENT_STALE"):
        env_manager._assert_metadata(expected, actual)


def test_product_bytecode_contamination_is_rejected_before_suite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "src/iac_guard_v/__pycache__"
    package.mkdir(parents=True)
    (package / "unsafe.cpython-312.pyc").write_bytes(b"not trusted")
    purelib = tmp_path / "empty-site-packages"
    purelib.mkdir()
    monkeypatch.setattr(env_manager, "_site_packages", lambda *_args: purelib)
    with pytest.raises(HarnessError, match="prohibited product bytecode"):
        env_manager._assert_no_product_bytecode(tmp_path, Path(sys.executable))


@pytest.mark.parametrize(
    "target",
    (Path("/"), Path(".."), Path.home(), Path.cwd()),
)
def test_cleanup_refuses_unsafe_paths(tmp_path: Path, target: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    with pytest.raises(HarnessError, match="UNSAFE_CLEANUP_REFUSED"):
        env_manager.assert_managed_path(root, target)


def test_cleanup_accepts_only_managed_descendants(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    target = root / ".testenvs/scanners/checkov"
    target.mkdir(parents=True)
    assert env_manager.assert_managed_path(root, target) == target.resolve()
    env_manager.clean_managed_path(root, target)
    assert not target.exists()


def test_cleanup_refuses_managed_root_symlink(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "must-survive.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    managed = root / ".nox"
    managed.symlink_to(outside, target_is_directory=True)

    with pytest.raises(HarnessError, match="managed root is a symlink"):
        env_manager.clean_managed_path(root, managed)

    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_cleanup_refuses_nested_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    managed = root / ".testenvs"
    managed.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "must-survive.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    link = managed / "scanner"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(HarnessError, match="contains a symlink"):
        env_manager.clean_managed_path(root, link / "child")

    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_release_environment_reuse_is_refused(tmp_path: Path) -> None:
    environment = tmp_path / "release-env"
    environment.mkdir()
    marker = env_manager.claim_fresh_release_environment(environment)
    assert json.loads(marker.read_text(encoding="utf-8"))["schema"] == (
        "iacgv-fresh-release-run-v1"
    )
    with pytest.raises(HarnessError, match="RELEASE_REUSE_FORBIDDEN"):
        env_manager.claim_fresh_release_environment(environment)


def test_nox_release_reuse_override_is_refused_before_marker(tmp_path: Path) -> None:
    environment = tmp_path / "release-env"
    environment.mkdir()
    with pytest.raises(HarnessError, match="Nox reports"):
        env_manager.claim_fresh_release_environment(environment, nox_reused=True)


def test_canonical_metadata_excludes_timestamp_from_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs(tmp_path)
    expected = _expected(tmp_path, monkeypatch)
    first = env_manager._metadata_payload(expected)
    second = env_manager._metadata_payload(expected)
    assert first["environment_fingerprint"] == second["environment_fingerprint"]
    assert "created_utc" not in {
        key for key in expected if key == "created_utc"
    }


def test_safe_environment_removes_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GH_TOKEN", "must-not-pass")
    monkeypatch.setenv("EXAMPLE_API_KEY", "must-not-pass")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    environment = env_manager._safe_environment()
    assert "GH_TOKEN" not in environment
    assert "EXAMPLE_API_KEY" not in environment
    assert environment["PATH"] == "/usr/bin:/bin"


def test_result_summary_refuses_symlink_root(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (repository / ".test-results").symlink_to(outside, target_is_directory=True)
    summary = RunSummary(repository, "matrix")
    with pytest.raises(HarnessError, match="TEST_RESULT_PATH_UNSAFE"):
        _ = summary.directory


def test_result_summary_aggregates_coverage_without_source_paths(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".git").mkdir()
    coverage = repository / "coverage.json"
    coverage.write_text(
        json.dumps({
            "meta": {"branch_coverage": True},
            "files": {"/private/source.py": {"summary": {}}},
            "totals": {
                "covered_lines": 91,
                "num_statements": 100,
                "percent_covered": 91.0,
                "percent_covered_display": "91",
                "missing_lines": 9,
                "excluded_lines": 0,
                "num_branches": 10,
                "covered_branches": 9,
                "missing_branches": 1,
            },
        }),
        encoding="utf-8",
    )
    summary = RunSummary(repository, "coverage")
    summary.add_coverage("d5-engine", coverage)
    encoded = json.dumps(summary.coverage)
    assert summary.coverage["d5-engine"]["percent_covered"] == 91.0
    assert "/private/source.py" not in encoded


def test_parent_summary_aggregates_child_counts_coverage_and_qrs(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    child = repository / "child.json"
    child.write_text(
        json.dumps({
            "test_counts": {"tests": 7, "failures": 0, "errors": 0, "skipped": 1},
            "coverage": {"helm": {"percent_covered": 93.5}},
            "qrs": {"replay": "630/630"},
        }),
        encoding="utf-8",
    )
    summary = RunSummary(repository, "pr")
    summary.add_child_summary(
        child,
        identity="child",
        returncode=0,
        duration_seconds=1.25,
    )
    assert summary.commands[0]["counts"]["tests"] == 7
    assert summary.coverage == {"helm": {"percent_covered": 93.5}}
    assert summary.qrs == {"replay": "630/630"}
