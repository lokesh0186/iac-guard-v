"""Exact locked offline kubeconform/schema integration."""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
from pathlib import Path

from iac_guard_v.adapters.phase_e_lock import (
    load_locked_container_identity, load_protected_kubernetes_schema_identity,
    load_protected_phase_e_evidence,
)
from iac_guard_v.adapters.phase_e_runtime import attest_container_runtime
from iac_guard_v.enums import ScanRole, Status
from iac_guard_v.validators import (
    KubeconformValidator, ValidationReason, create_kubeconform_validation_request,
)


def test_exact_locked_offline_kubeconform(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\n"
        "spec: {containers: [{name: c, image: nginx}]}\n", encoding="utf-8",
    )
    repository = Path(__file__).parents[2]
    cache = Path(os.environ["IACGV_PHASE_E_CACHE"])
    bundle = load_protected_phase_e_evidence(repository)
    architecture = "linux/arm64" if platform.machine() in {"arm64", "aarch64"} else "linux/amd64"
    locked = load_locked_container_identity(bundle, "kubeconform", architecture)
    schema = load_protected_kubernetes_schema_identity(bundle, cache)
    runtime = attest_container_runtime(
        Path(shutil.which("docker") or "docker").resolve(strict=True),
        protected_execution_context_identity=hashlib.sha256(b"e3.2").hexdigest(),
        protected_evidence=bundle, evaluated_workspaces=(root,),
    )
    request = create_kubeconform_validation_request(
        workspace_root=root, scan_root=root, role=ScanRole.CANDIDATE,
        files_eligible=("pod.yaml",), container_runtime=runtime,
        locked_identity=locked, schema_identity=schema,
    )
    result = KubeconformValidator().validate(request)
    assert (result.status, result.reason) == (Status.PASS, ValidationReason.COMPLETED)
    assert result.resources_validated == 1
    assert schema.license_id == "NOASSERTION"
