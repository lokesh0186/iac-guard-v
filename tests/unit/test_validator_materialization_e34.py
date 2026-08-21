"""E3.4 no-follow source and verified private-view regressions."""
from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from iac_guard_v.adapters.phase_e_lock import load_locked_container_identity, load_protected_phase_e_evidence
from iac_guard_v.enums import ScanRole, Status
from iac_guard_v.models import DomainError
from iac_guard_v.process import CommandResult, ProcessReason
from iac_guard_v.validators import (
    ValidationReason, create_kubeconform_validation_request,
    create_terraform_validation_request, create_tflint_validation_request,
    load_protected_tflint_config,
)
from iac_guard_v.validators.materialization import (
    MATERIALIZATION_FAILURE, READ_ONLY_DIRECTORY_MODE, READ_ONLY_FILE_MODE,
    WRITABLE_OUTPUT_DIRECTORY_MODE, bind_source_file, materialize_view,
    prepare_writable_output_directory, revalidate_materialized_view,
    revalidate_readonly_file, seal_readonly_tree, verified_write, write_all,
)
from tests.phase_e_test_support import (
    execute_terraform_validator_fixture, make_test_container_runtime,
    make_test_kubernetes_schema_identity,
)


ROOT = Path(__file__).parents[2]
BUNDLE = load_protected_phase_e_evidence(ROOT)


def _runtime(tool: str):
    lock = load_locked_container_identity(BUNDLE, tool, "linux/arm64")
    return lock, make_test_container_runtime(lock, Path(shutil.which("docker") or "/usr/bin/true"))


def _factory(tool: str, workspace: Path, relative: str):
    lock, runtime = _runtime(tool)
    if tool == "kubeconform":
        return create_kubeconform_validation_request(
            workspace_root=workspace, scan_root=workspace, role=ScanRole.CANDIDATE,
            files_eligible=(relative,), container_runtime=runtime, locked_identity=lock,
            schema_identity=make_test_kubernetes_schema_identity(workspace.parent / "schema"),
        )
    if tool == "tflint":
        return create_tflint_validation_request(
            workspace_root=workspace, scan_root=workspace, files_eligible=(relative,),
            container_runtime=runtime, locked_identity=lock,
            protected_config=load_protected_tflint_config(),
        )
    return create_terraform_validation_request(
        workspace_root=workspace, scan_root=workspace, files_eligible=(relative,),
        container_runtime=runtime, locked_identity=lock,
    )


@pytest.mark.parametrize(
    ("tool", "filename", "content"),
    [
        ("opentofu", "main.tf", "locals { x = 1 }\n"),
        ("kubeconform", "pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n"),
        ("tflint", "main.tf", "locals { x = 1 }\n"),
    ],
)
@pytest.mark.parametrize("target_kind", ["external", "internal", "broken", "cycle"])
def test_every_parent_symlink_shape_is_rejected(
    tmp_path: Path, tool: str, filename: str, content: str, target_kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / filename).write_text(content, encoding="utf-8")
    internal = workspace / "real"
    internal.mkdir()
    (internal / filename).write_text(content, encoding="utf-8")
    link = workspace / "link"
    if target_kind == "external":
        link.symlink_to(outside, target_is_directory=True)
    elif target_kind == "internal":
        link.symlink_to(internal, target_is_directory=True)
    elif target_kind == "broken":
        link.symlink_to(workspace / "missing", target_is_directory=True)
    else:
        link.symlink_to(link, target_is_directory=True)
    with pytest.raises(DomainError, match="nonsymlink"):
        _factory(tool, workspace, f"link/{filename}")


def test_parent_replacement_after_sealing_is_detected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    module = workspace / "module"
    module.mkdir(parents=True)
    raw = "locals { answer = 42 }\n"
    (module / "main.tf").write_text(raw, encoding="utf-8")
    request = _factory("opentofu", workspace, "module/main.tf")
    module.rename(workspace / "old-module")
    module.mkdir()
    (module / "main.tf").write_text(raw, encoding="utf-8")
    process = CommandResult(
        argv=("docker",), status=Status.PASS, exit_code=0,
        stdout=json.dumps({"format_version": "1.0", "valid": True, "error_count": 0,
                           "warning_count": 0, "diagnostics": []}).encode(),
        stderr=b"", duration_ms=1, truncated=False, timed_out=False,
        killed_signal=None, reason_code=ProcessReason.COMPLETED_WITHIN_CONTRACT,
        resolved_executable="/usr/local/bin/docker",
        primary_execution_event=ProcessReason.COMPLETED_WITHIN_CONTRACT,
    )
    result = execute_terraform_validator_fixture(request, process)
    assert (result.status, result.reason) == (
        Status.INCONCLUSIVE, ValidationReason.INPUT_CHANGED_DURING_VALIDATION,
    )


def test_partial_writes_are_completed_and_destination_is_verified(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    raw = b"x" * 1018
    (source / "main.tf").write_bytes(raw)
    sealed, _ = bind_source_file(source, "main.tf", 2048, (".tf",), "test input")
    real_write = os.write

    def partial(descriptor: int, value) -> int:
        data = bytes(value)
        return real_write(descriptor, data[:max(1, len(data) // 2)])

    with patch("iac_guard_v.validators.materialization.os.write", side_effect=partial):
        manifest = materialize_view(source, (sealed,), tmp_path / "view", 2048)
    assert (tmp_path / "view/main.tf").read_bytes() == raw
    assert len(manifest) == 64


def test_zero_length_write_fails_before_any_execution(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.tf").write_text("locals { x = 1 }\n", encoding="utf-8")
    sealed, _ = bind_source_file(source, "main.tf", 1024, (".tf",), "test input")
    with patch("iac_guard_v.validators.materialization.os.write", return_value=0):
        with pytest.raises(DomainError, match=MATERIALIZATION_FAILURE):
            materialize_view(source, (sealed,), tmp_path / "view", 1024)


def test_write_all_retries_eintr(tmp_path: Path) -> None:
    destination = tmp_path / "out"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    real_write = os.write
    calls = 0
    def interrupted(fd: int, value) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InterruptedError()
        return real_write(fd, value)
    try:
        with patch("iac_guard_v.validators.materialization.os.write", side_effect=interrupted):
            write_all(descriptor, b"complete")
    finally:
        os.close(descriptor)
    assert destination.read_bytes() == b"complete"


def test_bind_mounted_subtrees_are_nonroot_readable_but_immutable(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    raw = b"locals { answer = 42 }\n"
    (source / "main.tf").write_bytes(raw)
    sealed, _ = bind_source_file(source, "main.tf", 1024, (".tf",), "test input")
    view = tmp_path / "private" / "view"
    view.parent.mkdir(mode=0o700)
    materialize_view(source, (sealed,), view, 1024)

    protected = tmp_path / "private" / "protected"
    protected.mkdir(mode=0o755)
    config_raw = b"config {}\n"
    config = protected / "terraform.rc"
    verified_write(config, config_raw)
    seal_readonly_tree(protected)
    output = tmp_path / "private" / "output"
    prepare_writable_output_directory(output)

    assert stat.S_IMODE(view.stat().st_mode) == READ_ONLY_DIRECTORY_MODE
    assert stat.S_IMODE((view / "main.tf").stat().st_mode) == READ_ONLY_FILE_MODE
    assert stat.S_IMODE(protected.stat().st_mode) == READ_ONLY_DIRECTORY_MODE
    assert stat.S_IMODE(config.stat().st_mode) == READ_ONLY_FILE_MODE
    assert stat.S_IMODE(output.stat().st_mode) == WRITABLE_OUTPUT_DIRECTORY_MODE
    assert READ_ONLY_DIRECTORY_MODE & stat.S_IXOTH
    assert READ_ONLY_FILE_MODE & stat.S_IROTH
    assert not READ_ONLY_FILE_MODE & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    assert WRITABLE_OUTPUT_DIRECTORY_MODE & stat.S_IWOTH
    revalidate_materialized_view(view, (sealed.evidence,), 1024)
    revalidate_readonly_file(config, config_raw)


def test_materialized_mode_change_is_detected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.tf").write_text("locals {}\n", encoding="utf-8")
    sealed, _ = bind_source_file(source, "main.tf", 1024, (".tf",), "test input")
    view = tmp_path / "view"
    materialize_view(source, (sealed,), view, 1024)
    os.chmod(view / "main.tf", 0o644)
    with pytest.raises(DomainError, match=MATERIALIZATION_FAILURE):
        revalidate_materialized_view(view, (sealed.evidence,), 1024)
