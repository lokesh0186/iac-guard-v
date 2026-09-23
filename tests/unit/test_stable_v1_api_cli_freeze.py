from __future__ import annotations

import hashlib
from importlib.resources import files

import iac_guard_v
import iac_guard_v.contracts as contract_api
import iac_guard_v.native_properties as native_api

from iac_guard_v.beta_api import public_api_snapshot
from iac_guard_v.contracts.model import ContractProvenance, ContractResult
from iac_guard_v.native_properties.model import NativePropertyResult
from iac_guard_v.stable_api import (
    BETA1_PUBLIC_API_DIGEST,
    CLI_SURFACE_DIGEST,
    SCHEMA_FILE_DIGESTS,
    cli_surface_digest,
    validate_stable_api_freeze,
)


EXPECTED_TOP_LEVEL_EXPORTS = {
    "__version__", "adapters", "api", "config", "contracts", "diffing",
    "engine", "enums", "fingerprints", "kustomize", "matching", "models",
    "native_properties", "normalisation", "policy", "process", "redaction",
    "report", "scanner_core",
}


def test_beta1_api_and_complete_cli_argument_tree_are_frozen() -> None:
    validate_stable_api_freeze()
    assert public_api_snapshot()["snapshot_digest"] == BETA1_PUBLIC_API_DIGEST
    assert cli_surface_digest() == CLI_SURFACE_DIGEST


def test_all_existing_wire_schema_files_are_byte_frozen() -> None:
    schema_root = files("iac_guard_v").joinpath("schemas")
    observed = {
        name: hashlib.sha256(schema_root.joinpath(name).read_bytes()).hexdigest()
        for name in SCHEMA_FILE_DIGESTS
    }
    assert observed == SCHEMA_FILE_DIGESTS


def test_public_python_exports_remain_importable_and_closed() -> None:
    snapshot = public_api_snapshot()["python_exports"]
    assert set(iac_guard_v.__all__) == EXPECTED_TOP_LEVEL_EXPORTS
    assert set(native_api.__all__) == set(snapshot["iac_guard_v.native_properties"])
    assert set(contract_api.__all__) == set(snapshot["iac_guard_v.contracts"])
    for name in EXPECTED_TOP_LEVEL_EXPORTS:
        assert hasattr(iac_guard_v, name)
    for name in native_api.__all__:
        assert hasattr(native_api, name)
    for name in contract_api.__all__:
        assert hasattr(contract_api, name)


def test_provenance_result_and_exit_vocabularies_are_frozen() -> None:
    assert tuple(item.value for item in ContractProvenance) == (
        "PROJECT_AUTHORED", "USER_AUTHORED", "RESEARCH_HYPOTHESIS",
        "SUGGESTED_CONTRACT",
    )
    assert tuple(item.value for item in NativePropertyResult) == (
        "SATISFIED", "VIOLATED", "NOT_EVALUATED", "UNSUPPORTED", "ERROR",
    )
    assert tuple(item.value for item in ContractResult) == (
        "SATISFIED", "VIOLATED", "NOT_EVALUATED", "UNSUPPORTED", "ERROR",
    )
    assert public_api_snapshot()["contract_exit_codes"] == {
        "SATISFIED": 0,
        "VIOLATED": 10,
        "NOT_EVALUATED": 11,
        "UNSUPPORTED": 12,
        "INVALID": 20,
        "ERROR": 21,
    }
