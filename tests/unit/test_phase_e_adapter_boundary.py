"""Shared E1/E2 production-boundary and portability regressions."""
from __future__ import annotations

from pathlib import Path

import iac_guard_v.adapters as adapters
import iac_guard_v.adapters.kics as kics_module
import iac_guard_v.adapters.phase_e_lock as lock_module
import iac_guard_v.adapters.trivy as trivy_module


ROOT = Path(__file__).parents[2]


def test_private_normalizers_and_test_cache_factory_are_not_public() -> None:
    assert "_normalize_for_test" not in kics_module.__all__
    assert "_normalize_for_test" not in trivy_module.__all__
    assert "_create_test_protected_checks_cache_identity" not in lock_module.__all__
    assert not hasattr(adapters, "_normalize_for_test")
    assert not hasattr(adapters, "_create_test_protected_checks_cache_identity")


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
