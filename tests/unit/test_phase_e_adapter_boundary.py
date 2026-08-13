"""Shared E1/E2 production-boundary and portability regressions."""
from __future__ import annotations

from pathlib import Path

import iac_guard_v.adapters as adapters
import iac_guard_v.adapters.kics as kics_module
import iac_guard_v.adapters.phase_e_lock as lock_module
import iac_guard_v.adapters.trivy as trivy_module
import pytest

from iac_guard_v.adapters.base import require_hardened_docker_argv
from iac_guard_v.adapters.base import AdapterReason, read_locked_output_directory
from iac_guard_v.models import DomainError


ROOT = Path(__file__).parents[2]


def test_private_normalizers_and_test_cache_factory_are_not_public() -> None:
    assert "_normalize_for_test" not in kics_module.__all__
    assert "_normalize_for_test" not in trivy_module.__all__
    assert "_create_test_protected_checks_cache_identity" not in lock_module.__all__
    assert not hasattr(adapters, "_normalize_for_test")
    assert not hasattr(adapters, "_create_test_protected_checks_cache_identity")
    assert not hasattr(kics_module, "_normalize_for_test")
    assert not hasattr(kics_module, "_PRIVATE_TEST_CONTEXT")
    assert not hasattr(trivy_module, "_normalize_for_test")
    assert not hasattr(trivy_module, "_PRIVATE_TEST_CONTEXT")
    assert not hasattr(lock_module, "_create_test_protected_checks_cache_identity")
    for path in (ROOT / "src/iac_guard_v").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "_normalize_for_test" not in text
        assert "_PRIVATE_TEST_CONTEXT" not in text
        assert "_create_test_protected_checks_cache_identity" not in text


def test_no_committed_developer_cache_or_workspace_path() -> None:
    forbidden = (
        "iacgv-" + "e01-cache",
        "garima" + "chauhan/Downloads/iac-guard-v-work",
    )
    roots = (ROOT / "src", ROOT / "tests", ROOT / "docs", ROOT / ".github")
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert not any(value in text for value in forbidden), path


@pytest.mark.parametrize(
    "removed",
    (
        "--pull", "--network", "--read-only", "--cap-drop", "--security-opt",
        "--pids-limit", "--memory", "--cpus", "--user",
    ),
)
def test_each_hardened_docker_guard_is_mandatory(removed: str) -> None:
    values = [
        "docker", "run", "--pull", "never", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "512m", "--cpus", "1.0",
        "--user", "65532:65532", "image@sha256:" + "0" * 64,
    ]
    index = values.index(removed)
    del values[index:index + (1 if removed == "--read-only" else 2)]
    with pytest.raises(DomainError, match="locked Docker"):
        require_hardened_docker_argv(
            tuple(values), pids_limit="128", memory="512m", cpus="1.0",
            user="65532:65532",
        )


@pytest.mark.parametrize("kind", ("symlink", "fifo", "extra"))
def test_complete_output_directory_rejects_non_allowlisted_entries(
    tmp_path: Path, kind: str,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    result = output / "results.json"
    result.write_text("{}", encoding="utf-8")
    if kind == "symlink":
        (output / "unexpected").symlink_to(result)
    elif kind == "fifo":
        import os
        os.mkfifo(output / "unexpected")
    else:
        (output / "unexpected").write_bytes(b"x")
    with pytest.raises(
        DomainError, match=AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value
    ):
        read_locked_output_directory(
            output, allowed_files=("results.json",),
            max_file_bytes=16, max_total_bytes=16,
        )
