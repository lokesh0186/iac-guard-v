"""D9 is offline, conservative, deterministic, and never rewrites frozen evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from research.compat.compare_legacy_hardened import (
    MISSING_HARDENED_EVIDENCE,
    compare_frozen_runs,
    render_markdown,
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
    assert result["result_label"] == "HISTORICAL_HARDENED_EVIDENCE_SUFFICIENCY_COMPARISON"
    assert result["analysis_contract_version"] == "historical-hardened-evidence-sufficiency-v2"
    assert len(result["iac_guard_v_implementation_digest"]) == 64
    assert set(result["parser_provenance"]) == {"PyYAML", "python-hcl2"}


def test_d9_local_parser_evidence_is_honest_and_records_every_run() -> None:
    result = compare_frozen_runs()
    assert result["candidate_syntax_counts"] == {
        "ERROR": 0, "FAIL": 53, "PASS": 577, "UNSUPPORTED": 0,
    }
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


def test_d91_parser_failures_are_typed(monkeypatch) -> None:
    import iac_guard_v.engine as engine
    from iac_guard_v.models import DomainError
    from research.compat.compare_legacy_hardened import _local_candidate_evidence

    monkeypatch.setattr(engine, "_terraform_resources", lambda *_: (_ for _ in ()).throw(DomainError("bad")))
    assert _local_candidate_evidence("x", "terraform", b"x")[0] == "FAIL"
    monkeypatch.setattr(engine, "_terraform_resources", lambda *_: (_ for _ in ()).throw(RuntimeError("bug")))
    assert _local_candidate_evidence("x", "terraform", b"x")[0] == "ERROR"
    assert _local_candidate_evidence("x", "other", b"x")[0] == "UNSUPPORTED"


def test_markdown_deliverable_matches_canonical_analysis() -> None:
    result = compare_frozen_runs()
    markdown = render_markdown(result)
    committed = (REPO / "docs/spec/LEGACY_VS_HARDENED.md").read_text(encoding="utf-8")
    assert committed == markdown
    for text in (
        "historical hardened-evidence sufficiency comparison",
        "407 legacy `VERIFIED`", "223 legacy `FAILED`",
        "Hardened `VERIFIED` claims: 0", "Scanner executions: 0",
        "Model-provider calls: 0", "Paper and historical tables changed: no",
    ):
        assert text.lower() in markdown.lower()
        assert text.lower() in committed.lower()
