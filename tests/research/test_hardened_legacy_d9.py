"""D9 is offline, conservative, deterministic, and never rewrites frozen evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from research.compat.compare_legacy_hardened import (
    MISSING_HARDENED_EVIDENCE,
    compare_frozen_runs,
)


REPO = Path(__file__).parents[2]


def _frozen_hashes() -> dict[str, str]:
    result = {}
    for root in ("benchmark", "runs", "results", "prompts", "scanners", "scripts"):
        for path in sorted((REPO / root).rglob("*")):
            if path.is_file():
                result[path.relative_to(REPO).as_posix()] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    return result


def test_d9_compares_all_frozen_runs_without_claiming_hardened_verified() -> None:
    result = compare_frozen_runs()
    assert result["runs_compared"] == 630
    assert result["transition_counts"] == {
        "LEGACY_FAILED_TO_HARDENED_INCONCLUSIVE": 223,
        "LEGACY_VERIFIED_TO_HARDENED_INCONCLUSIVE": 407,
    }
    assert result["hardened_verified"] == 0
    assert result["new_benchmark_inference_runs"] == 0
    assert result["model_provider_calls"] == 0
    assert result["scanner_executions"] == 0
    assert tuple(result["hardened_limitations"]) == MISSING_HARDENED_EVIDENCE


def test_d9_local_parser_evidence_is_honest_and_records_every_run() -> None:
    result = compare_frozen_runs()
    assert result["candidate_syntax_counts"] == {"FAIL": 53, "PASS": 577}
    assert len(result["records"]) == 630
    assert all(item["hardened_classification"] == "INCONCLUSIVE" for item in result["records"])
    assert all(item["hardened_blockers"] for item in result["records"])
    assert any(
        item["legacy_classification"] == "VERIFIED"
        and item["candidate_syntax_status"] == "FAIL"
        for item in result["records"]
    )


def test_d9_is_byte_deterministic_and_does_not_modify_frozen_inputs() -> None:
    before = _frozen_hashes()
    first = compare_frozen_runs()
    second = compare_frozen_runs()
    assert json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(
        second, sort_keys=True, separators=(",", ":")
    )
    assert _frozen_hashes() == before
