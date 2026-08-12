"""D4.6 scanner-environment and mixed-repository classification closure."""
from __future__ import annotations

import base64
import hashlib
import inspect
from pathlib import Path

import pytest

import iac_guard_v.adapters.checkov as CHECKOV
import iac_guard_v.engine as ENGINE
from iac_guard_v.enums import Status

from test_engine import _executable, _scan_request


def test_external_symlink_in_checkov_policy_tree_is_rejected(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    package = (
        tmp_path
        / "trusted/libexec/lib/python3.11/site-packages/checkov/checks"
    )
    outside = tmp_path / "outside-rule.py"
    outside.write_text("RULE = 'A'\n", encoding="utf-8")
    (package / "linked.py").symlink_to(outside)

    with pytest.raises(Exception, match="must not contain symlinks"):
        CHECKOV.checkov_distribution_identity(executable, "3.3.0")


def test_distribution_identity_records_separate_contracts(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    identity = CHECKOV.checkov_distribution_identity(executable, "3.3.0")

    assert len(identity.installed_distribution_digest) == 64
    assert len(identity.dependency_lock_digest) == 64
    assert len(identity.policy_inventory_digest) == 64
    assert len(identity.custom_check_digest) == 64
    assert len({
        identity.installed_distribution_digest,
        identity.dependency_lock_digest,
        identity.policy_inventory_digest,
        identity.custom_check_digest,
    }) > 1
    assert identity.source.startswith("verified-wheel-record-manifest-v3-")


def test_dependency_record_changes_only_dependency_environment_identity(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path)
    metadata = (
        tmp_path
        / "trusted/libexec/lib/python3.11/site-packages/checkov-3.3.0.dist-info"
    )
    metadata = metadata.parent / "foreign-1.0.dist-info"
    metadata.mkdir()
    data = metadata.parent / "foreign" / "data.txt"
    data.parent.mkdir()
    data.write_text("one", encoding="utf-8")
    record = metadata / "RECORD"
    def write_record() -> None:
        payload = data.read_bytes()
        encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        record.write_text(
            f"foreign/data.txt,sha256={encoded},{len(payload)}\n"
            "foreign-1.0.dist-info/RECORD,,\n",
            encoding="utf-8",
        )
    write_record()
    before = CHECKOV.checkov_distribution_identity(executable, "3.3.0")
    data.write_text("two", encoding="utf-8")
    write_record()
    after = CHECKOV.checkov_distribution_identity(executable, "3.3.0")
    assert before.installed_distribution_digest == after.installed_distribution_digest
    assert before.policy_inventory_digest == after.policy_inventory_digest
    assert before.dependency_lock_digest != after.dependency_lock_digest
    assert before.scanner_environment_digest != after.scanner_environment_digest


def test_distribution_shape_failures_are_rejected(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    policy = next(
        (tmp_path / "trusted/libexec").glob(
            "lib/python*/site-packages/checkov/checks/rule.py"
        )
    )
    policy.unlink()
    with pytest.raises(Exception, match="inventory is empty"):
        CHECKOV.checkov_distribution_identity(executable, "3.3.0")

    missing = tmp_path / "standalone"
    missing.write_text("#!/bin/sh\n", encoding="utf-8")
    missing.chmod(0o755)
    with pytest.raises(Exception, match="cannot be established"):
        CHECKOV.checkov_distribution_identity(missing, "3.3.0")

    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    with pytest.raises(Exception, match="cannot identify"):
        CHECKOV.checkov_distribution_identity(empty, "3.3.0")


def test_symlinked_dependency_metadata_and_interpreter_are_rejected(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path)
    site_packages = tmp_path / "trusted/libexec/lib/python3.11/site-packages"
    outside = tmp_path / "metadata"
    outside.mkdir()
    (site_packages / "foreign.dist-info").symlink_to(outside, target_is_directory=True)
    with pytest.raises(Exception, match="metadata must not be symlinked"):
        CHECKOV.checkov_distribution_identity(executable, "3.3.0")
    (site_packages / "foreign.dist-info").unlink()

    interpreter = tmp_path / "trusted/libexec/bin/python"
    target = tmp_path / "python-real"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)
    interpreter.unlink()
    interpreter.symlink_to(target)
    with pytest.raises(Exception, match="interpreter must not be a symlink"):
        CHECKOV.checkov_distribution_identity(executable, "3.3.0")


def test_bytecode_cache_is_rejected_from_distribution_identity(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    before = CHECKOV.checkov_distribution_identity(executable, "3.3.0")
    cache = (
        tmp_path
        / "trusted/libexec/lib/python3.11/site-packages/checkov/__pycache__"
    )
    cache.mkdir()
    (cache / "rule.cpython-313.pyc").write_bytes(b"mutable cache")
    with pytest.raises(Exception, match="bytecode/cache"):
        CHECKOV.checkov_distribution_identity(executable, "3.3.0")


def test_current_adapter_contract_replaces_stale_phase_label(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    plan = _scan_request(tmp_path / "repo", executable)
    source = inspect.getsource(CHECKOV._invocation_config_digest)
    assert "checkov-adapter-contract-v3" in source
    assert "checkov-d4.2" not in source
    assert len(CHECKOV._invocation_config_digest(plan.request)) == 64


@pytest.mark.parametrize(
    "payload",
    [
        b"defaults: &defaults\n  image: nginx\njob:\n  <<: *defaults\n",
        (
            b"openapi: 3.0.0\ncomponents:\n  schemas:\n    Pet:\n"
            b"      type: object\n      properties:\n        kind:\n"
            b"          type: string\n"
        ),
        b"Resources:\n  Bucket: !Custom\n    Value: sample\n",
    ],
)
def test_non_kubernetes_yaml_features_are_classified_not_rejected(
    tmp_path: Path, payload: bytes
) -> None:
    resources, identities = ENGINE._kubernetes_resources("document.yaml", payload)
    assert resources == ()
    assert identities == ()


def test_root_kubernetes_identity_with_alias_fails_closed() -> None:
    payload = (
        b"apiVersion: v1\nkind: Pod\nmetadata: &metadata\n"
        b"  name: demo\nspec:\n  template:\n    metadata: *metadata\n"
    )
    with pytest.raises(Exception, match="aliases are unsupported"):
        ENGINE._kubernetes_resources("pod.yaml", payload)


def test_adapter_run_reports_separate_distribution_identities(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path)
    plan = _scan_request(tmp_path / "repo", executable)
    run = CHECKOV._reason_run(plan.request, CHECKOV.AdapterReason.PROCESS_ERROR)
    canonical = run.canonical_dict()
    assert canonical["installed_distribution_digest"]
    assert canonical["dependency_lock_digest"]
    assert canonical["custom_check_digest"]
    assert run.status is Status.ERROR
