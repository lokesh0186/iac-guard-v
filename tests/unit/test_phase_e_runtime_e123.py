"""E1E2.3 protected runtime and portable evidence boundary probes."""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

import iac_guard_v.adapters.phase_e_runtime as runtime_module
from iac_guard_v.adapters.kics import create_kics_scan_request
from iac_guard_v.adapters.phase_e_lock import (
    load_locked_container_identity,
    load_protected_phase_e_evidence,
)
from iac_guard_v.adapters.phase_e_runtime import (
    attest_container_runtime, revalidate_trusted_container_runtime,
)
from iac_guard_v.models import DomainError


ROOT = Path(__file__).parents[2]


def _probe(*, context: str = "a") -> dict:
    return {
        "client_version": "29.6.2",
        "client_identity": hashlib.sha256(b"client").hexdigest(),
        "server_version": "29.6.2",
        "daemon_identity": hashlib.sha256(b"daemon").hexdigest(),
        "context_identity": hashlib.sha256(context.encode()).hexdigest(),
        "platform": "linux",
        "architecture": "arm64",
    }


def _executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_fake_docker_cannot_be_selected_by_kics_request(tmp_path: Path) -> None:
    fake = _executable(
        tmp_path / "fake-docker",
        "#!/bin/sh\nprintf '%s' '{\"kics_version\":\"v2.1.20\"}'\nexit 50\n",
    )
    with pytest.raises(TypeError, match="docker_executable"):
        create_kics_scan_request(docker_executable=fake)
    bundle = load_protected_phase_e_evidence(ROOT)
    with pytest.raises(DomainError, match="CONTAINER_RUNTIME_INTEGRITY_INCONCLUSIVE"):
        attest_container_runtime(
            fake,
            protected_execution_context_identity="1" * 64,
            protected_evidence=bundle,
        )


def test_fake_docker_cannot_be_selected_by_trivy_request() -> None:
    from iac_guard_v.adapters.trivy import create_trivy_scan_request

    with pytest.raises(TypeError, match="docker_executable"):
        create_trivy_scan_request(docker_executable=Path("/tmp/fake-docker"))


def test_runtime_binary_change_is_detected_before_spawn(
    tmp_path: Path, monkeypatch,
) -> None:
    bundle = load_protected_phase_e_evidence(ROOT)
    executable = _executable(tmp_path / "docker")
    monkeypatch.setattr(runtime_module, "_run_probe", lambda _: _probe())
    runtime = attest_container_runtime(
        executable,
        protected_execution_context_identity="2" * 64,
        protected_evidence=bundle,
    )
    executable.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    executable.chmod(0o755)
    with pytest.raises(DomainError, match="CONTAINER_RUNTIME_CHANGED"):
        revalidate_trusted_container_runtime(runtime, workspace_root=tmp_path / "workspace")


def test_runtime_context_or_daemon_change_is_detected(
    tmp_path: Path, monkeypatch,
) -> None:
    bundle = load_protected_phase_e_evidence(ROOT)
    executable = _executable(tmp_path / "docker")
    monkeypatch.setattr(runtime_module, "_run_probe", lambda _: _probe(context="first"))
    runtime = attest_container_runtime(
        executable,
        protected_execution_context_identity="3" * 64,
        protected_evidence=bundle,
    )
    monkeypatch.setattr(runtime_module, "_run_probe", lambda _: _probe(context="second"))
    with pytest.raises(DomainError, match="CONTAINER_RUNTIME_CONTEXT_CHANGED"):
        revalidate_trusted_container_runtime(runtime, workspace_root=tmp_path / "workspace")


def test_explicit_portable_evidence_bundle_has_no_checkout_dependency(
    tmp_path: Path,
) -> None:
    portable = tmp_path / "protected-evidence"
    shutil.copytree(ROOT / "tools", portable / "tools")
    bundle = load_protected_phase_e_evidence(portable)
    identity = load_locked_container_identity(bundle, "kics", "linux/arm64")
    assert identity.protected_evidence_identity == bundle.identity
    source = (ROOT / "src/iac_guard_v/adapters/phase_e_lock.py").read_text()
    assert "Path(__file__)" not in source


def test_bundle_identity_is_portable_between_absolute_roots(tmp_path: Path) -> None:
    roots = [tmp_path / "a", tmp_path / "b"]
    for root in roots:
        shutil.copytree(ROOT / "tools", root / "tools")
    first = load_protected_phase_e_evidence(roots[0])
    second = load_protected_phase_e_evidence(roots[1])
    assert first.canonical_dict() == second.canonical_dict()
    assert first.identity == second.identity


def test_runtime_identity_contains_no_local_executable_path(
    tmp_path: Path, monkeypatch,
) -> None:
    bundle = load_protected_phase_e_evidence(ROOT)
    executable = _executable(tmp_path / "docker")
    monkeypatch.setattr(runtime_module, "_run_probe", lambda _: _probe())
    runtime = attest_container_runtime(
        executable,
        protected_execution_context_identity="5" * 64,
        protected_evidence=bundle,
    )
    canonical = json.dumps(runtime.canonical_dict(), sort_keys=True)
    assert str(tmp_path) not in canonical

