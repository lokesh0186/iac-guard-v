"""Exact locked offline optional TFLint integration."""
from __future__ import annotations

import hashlib
import platform
import shutil
from pathlib import Path

from iac_guard_v.adapters.phase_e_lock import load_locked_container_identity, load_protected_phase_e_evidence
from iac_guard_v.adapters.phase_e_runtime import attest_container_runtime
from iac_guard_v.enums import Status
from iac_guard_v.validators import (
    TflintValidator, ValidationReason, create_tflint_validation_request,
    load_protected_tflint_config,
)


def test_exact_locked_offline_tflint(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "main.tf").write_text('variable "name" { type = string }\n', encoding="utf-8")
    repository = Path(__file__).parents[2]
    bundle = load_protected_phase_e_evidence(repository)
    architecture = "linux/arm64" if platform.machine() in {"arm64", "aarch64"} else "linux/amd64"
    locked = load_locked_container_identity(bundle, "tflint", architecture)
    runtime = attest_container_runtime(
        Path(shutil.which("docker") or "docker").resolve(strict=True),
        protected_execution_context_identity=hashlib.sha256(b"e3.3").hexdigest(),
        protected_evidence=bundle, evaluated_workspaces=(root,),
    )
    request = create_tflint_validation_request(
        workspace_root=root, scan_root=root, files_eligible=("main.tf",),
        container_runtime=runtime, locked_identity=locked,
        protected_config=load_protected_tflint_config(),
    )
    result = TflintValidator().validate(request)
    assert (result.status, result.reason) == (Status.PASS, ValidationReason.COMPLETED)
    assert result.advisory_only is True
    assert result.tool_environment_identity != locked.environment_digest
