"""D5.5 complete gate implementation and canonical report provenance."""
from __future__ import annotations

import inspect

import pytest

import iac_guard_v.engine as ENGINE
from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.engine import run_checkov_verification

from test_engine_d54 import _execute, _request_and_runs


@pytest.mark.parametrize(
    "helper_name",
    [
        "_validate_yaml_node",
        "_construct_unique_mapping",
        "_yaml_root_has_identity",
        "_strict_json_document",
        "_terraform_resources",
        "_read_detector_file",
    ],
)
def test_every_security_relevant_gate_helper_changes_identity(
    monkeypatch, helper_name: str
) -> None:
    original = ENGINE.production_gate_registry()
    real_getsource = inspect.getsource
    helper = getattr(ENGINE, helper_name)

    def changed_source(value):
        source = real_getsource(value)
        if value is helper:
            return source + "\n# D5.5 implementation mutation\n"
        return source

    monkeypatch.setattr(inspect, "getsource", changed_source)
    changed = ENGINE.production_gate_registry()
    assert original.implementations != changed.implementations


def test_config_and_result_expose_complete_gate_records(
    monkeypatch, tmp_path
) -> None:
    request, baseline_run, candidate_run = _request_and_runs(tmp_path)
    result = _execute(monkeypatch, request, baseline_run, candidate_run)
    config = result.verification_config.canonical_dict()
    canonical = result.canonical_dict()
    assert config["gate_implementations"]
    assert canonical["gate_implementations"] == config["gate_implementations"]
    for record in canonical["gate_implementations"]:
        assert set(record) >= {
            "gate_id", "kind", "version", "code_sha256",
            "dependency_identity", "artifact_kinds",
        }
    for role in ("baseline_snapshot", "candidate_snapshot"):
        assert "filesystem_entries" in canonical[role]
