"""Locked offline OpenTofu/Terraform validate integrations."""
from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
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
from iac_guard_v.validators.materialization import (
    bind_source_file, materialize_view, prepare_writable_output_directory,
    seal_readonly_tree, verified_write,
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


@pytest.mark.skipif(platform.system() != "Linux", reason="native Linux bind-mount contract")
def test_locked_nonroot_uid_reads_only_trusted_mounts(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.tf").write_text("locals { answer = 42 }\n", encoding="utf-8")
    sealed, _ = bind_source_file(source, "main.tf", 4096, (".tf",), "test input")
    view = tmp_path / "private" / "view"
    view.parent.mkdir(mode=0o700)
    materialize_view(source, (sealed,), view, 4096)
    protected = tmp_path / "private" / "protected"
    protected.mkdir(mode=0o755)
    verified_write(protected / "terraform.rc", b"provider_installation {}\n")
    seal_readonly_tree(protected)
    output = tmp_path / "private" / "output"
    prepare_writable_output_directory(output)
    bundle = load_protected_phase_e_evidence(Path(__file__).parents[2])
    architecture = "linux/arm64" if platform.machine() in {"arm64", "aarch64"} else "linux/amd64"
    locked = load_locked_container_identity(bundle, "opentofu", architecture)
    command = (
        shutil.which("docker") or "docker", "run", "--rm", "--pull", "never",
        "--network", "none", "--read-only", "--user", "65532:65532",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-v", f"{view}:/input:ro", "-v", f"{protected}:/protected:ro",
        "-v", f"{output}:/output:rw", "--entrypoint", "/bin/sh",
        locked.execution_reference, "-ec",
        "cat /input/main.tf >/dev/null; cat /protected/terraform.rc >/dev/null; "
        "! touch /input/denied; ! touch /protected/denied; touch /output/allowed",
    )
    completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0, completed.stderr
    assert (output / "allowed").is_file()
