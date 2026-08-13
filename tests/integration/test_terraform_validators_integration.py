"""Locked offline OpenTofu/Terraform validate integrations."""
from __future__ import annotations

import hashlib
import platform
import shutil
from pathlib import Path

import pytest

from iac_guard_v.adapters.phase_e_lock import (
    load_locked_container_identity, load_protected_phase_e_evidence,
)
from iac_guard_v.adapters.phase_e_runtime import attest_container_runtime
from iac_guard_v.enums import Status
from iac_guard_v.validators import (
    TerraformValidator, ValidationReason, create_terraform_validation_request,
)


@pytest.mark.parametrize("tool", ["opentofu", "terraform"])
def test_exact_locked_offline_validate(tool: str, tmp_path: Path) -> None:
    root = tmp_path / tool
    root.mkdir()
    (root / "main.tf").write_text("locals { answer = 42 }\n", encoding="utf-8")
    repository = Path(__file__).parents[2]
    bundle = load_protected_phase_e_evidence(repository)
    architecture = (
        "linux/arm64" if platform.machine() in {"arm64", "aarch64"} else "linux/amd64"
    )
    locked = load_locked_container_identity(bundle, tool, architecture)
    runtime = attest_container_runtime(
        Path(shutil.which("docker") or "docker").resolve(strict=True),
        protected_execution_context_identity=hashlib.sha256(
            f"e3.1-{tool}".encode()
        ).hexdigest(),
        protected_evidence=bundle, evaluated_workspaces=(root,),
    )
    request = create_terraform_validation_request(
        workspace_root=root, scan_root=root, files_eligible=("main.tf",),
        container_runtime=runtime, locked_identity=locked,
    )
    result = TerraformValidator().validate(request)
    assert (result.status, result.reason) == (Status.PASS, ValidationReason.COMPLETED)
    assert result.tool_environment_identity == locked.environment_digest
    assert result.runtime_identity == runtime.identity
    assert result.files_validated == 1
