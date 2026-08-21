#!/usr/bin/env python3
"""Offline D9 comparison over frozen outputs; performs no scanner or model calls.

The historical runs do not retain the affirmative per-target Checkov evaluation,
execution identity, coverage inventory, sealed source snapshot, or trusted policy
provenance required by hardened semantics. This tool therefore recomputes only evidence
that the frozen bytes can prove (independent syntax/resource parsing and baseline target
occurrence counts) and reports every hardened final classification as INCONCLUSIVE.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import platform
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNS = REPO / "runs" / "raw"
PATCHES = REPO / "runs" / "patches"
BASELINES = REPO / "scanners" / "outputs" / "baseline"
EXPECTED_RUNS = 630
ENVIRONMENT = REPO / "research" / "D9_ENVIRONMENT.json"
CANONICAL_ANALYSIS = REPO / "research" / "D9_ANALYSIS.json"
CANONICAL_MARKDOWN = REPO / "docs" / "spec" / "LEGACY_VS_HARDENED.md"
MAX_RECORD_BYTES = 10 * 1024 * 1024
MISSING_HARDENED_EVIDENCE = (
    "AFFIRMATIVE_CANDIDATE_TARGET_EVALUATION_MISSING",
    "CANDIDATE_SCANNER_EXECUTION_IDENTITY_MISSING",
    "CANDIDATE_COVERAGE_INVENTORY_MISSING",
    "HISTORICAL_SEALED_SNAPSHOT_MISSING",
    "HISTORICAL_TRUSTED_POLICY_PROVENANCE_MISSING",
)
ANALYSIS_CONTRACT = "historical-hardened-evidence-sufficiency-v3"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json(path: Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError(f"stored record exceeds limit: {path.name}")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError(f"stored record is not an object: {path.name}")
    return value, raw


def _manifest_digest(records: list[tuple[str, str]]) -> str:
    return _sha256(json.dumps(
        sorted(records), separators=(",", ":"), ensure_ascii=True
    ).encode("ascii"))


def _pinned_environment() -> tuple[dict, str]:
    value, raw = _strict_json(ENVIRONMENT)
    if value.get("analysis_contract_version") != ANALYSIS_CONTRACT:
        raise ValueError("D9 environment contract does not match the analysis")
    distributions = value.get("distributions")
    if type(distributions) is not dict or not distributions:
        raise ValueError("D9 environment has no pinned distributions")
    return value, _sha256(raw)


def verify_pinned_environment() -> None:
    """Prove that execution uses the exact selected linux/amd64 D9 environment."""
    import importlib.metadata
    from iac_guard_v.engine import _verified_parser_distribution_digest

    environment, _digest = _pinned_environment()
    expected_python = environment["base_image"]["python_version"]
    if platform.python_version() != expected_python:
        raise ValueError("D9 Python version differs from the pinned environment")
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ValueError("D9 canonical reproduction requires pinned linux/amd64")
    for name, expected in sorted(environment["distributions"].items()):
        if importlib.metadata.version(name) != expected["version"]:
            raise ValueError(f"D9 distribution version mismatch: {name}")
        actual = _verified_parser_distribution_digest(name)
        if actual != expected["installed_code_digest"]:
            raise ValueError(f"D9 installed-code digest mismatch: {name}")


def _baseline_failures(payload: dict) -> tuple:
    result = payload.get("results", {})
    failures = result.get("failed_checks", []) if type(result) is dict else []
    if type(failures) is not list:
        raise ValueError("baseline failed_checks is not an array")
    return tuple(item for item in failures if type(item) is dict)


def _local_candidate_evidence(
    artifact_id: str, check_type: str, content: bytes
) -> tuple[str, int, str]:
    # Importing packaged deterministic parsers does not execute Checkov or a provider.
    from iac_guard_v.engine import _kubernetes_resources, _terraform_resources
    from iac_guard_v.models import DomainError

    try:
        if check_type == "terraform":
            resources = _terraform_resources(f"{artifact_id}.tf", content)
        elif check_type == "kubernetes":
            resources, _identities = _kubernetes_resources(
                f"{artifact_id}.yaml", content
            )
        else:
            return "UNSUPPORTED", 0, "HISTORICAL_ARTIFACT_KIND_UNSUPPORTED"
    except DomainError as exc:
        return "FAIL", 0, type(exc).__name__
    except (ImportError, ModuleNotFoundError):
        return "UNSUPPORTED", 0, "PARSER_DEPENDENCY_UNAVAILABLE"
    except Exception as exc:
        return "ERROR", 0, type(exc).__name__
    return "PASS", len(resources), "LOCAL_INDEPENDENT_PARSE_COMPLETED"


@dataclass(frozen=True, slots=True)
class ComparisonRecord:
    run_id: str
    artifact_id: str
    model: str
    method: str
    legacy_classification: str
    hardened_classification: str
    transition: str
    candidate_syntax_status: str
    candidate_resource_count: int
    baseline_target_occurrences: int
    patch_sha256: str
    stored_run_sha256: str
    local_reason: str
    hardened_blockers: tuple

    def canonical_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "artifact_id": self.artifact_id,
            "model": self.model,
            "method": self.method,
            "legacy_classification": self.legacy_classification,
            "hardened_classification": self.hardened_classification,
            "transition": self.transition,
            "candidate_syntax_status": self.candidate_syntax_status,
            "candidate_resource_count": self.candidate_resource_count,
            "baseline_target_occurrences": self.baseline_target_occurrences,
            "patch_sha256": self.patch_sha256,
            "stored_run_sha256": self.stored_run_sha256,
            "local_reason": self.local_reason,
            "hardened_blockers": list(self.hardened_blockers),
        }


def compare_frozen_runs() -> dict:
    from iac_guard_v.engine import (
        _kubernetes_resources, _terraform_resources,
    )
    from iac_guard_v import __version__

    run_paths = sorted(RUNS.glob("*.json"))
    patch_paths = sorted(PATCHES.glob("*.tf"))
    if len(run_paths) != EXPECTED_RUNS or len(patch_paths) != EXPECTED_RUNS:
        raise ValueError("frozen D9 input cardinality is not 630 runs and 630 patches")
    patches = {path.stem: path for path in patch_paths}
    records: list[ComparisonRecord] = []
    run_manifest: list[tuple[str, str]] = []
    patch_manifest: list[tuple[str, str]] = []
    baseline_manifest: dict[str, str] = {}
    for path in run_paths:
        payload, raw = _strict_json(path)
        run_id = path.stem
        patch = patches.get(run_id)
        if patch is None:
            raise ValueError(f"stored run has no exact patch: {run_id}")
        content = patch.read_bytes()
        if len(content) > MAX_RECORD_BYTES:
            raise ValueError(f"stored patch exceeds limit: {patch.name}")
        artifact_id = payload.get("artifact_id")
        target_rule = payload.get("checkov_rule_id")
        if type(artifact_id) is not str or type(target_rule) is not str:
            raise ValueError(f"stored run identity is malformed: {path.name}")
        baseline_path = BASELINES / f"{artifact_id}_baseline.json"
        baseline, baseline_raw = _strict_json(baseline_path)
        check_type = baseline.get("check_type")
        syntax, resource_count, local_reason = _local_candidate_evidence(
            artifact_id, check_type, content
        )
        baseline_count = sum(
            item.get("check_id") == target_rule for item in _baseline_failures(baseline)
        )
        legacy = "VERIFIED" if payload.get("overall_verified_fix") is True else "FAILED"
        hardened = "INCONCLUSIVE"
        records.append(ComparisonRecord(
            run_id, artifact_id, str(payload.get("model", "")),
            str(payload.get("method", "")), legacy, hardened,
            f"LEGACY_{legacy}_TO_HARDENED_{hardened}", syntax,
            resource_count, baseline_count, _sha256(content), _sha256(raw),
            local_reason, MISSING_HARDENED_EVIDENCE,
        ))
        run_manifest.append((path.name, _sha256(raw)))
        patch_manifest.append((patch.name, _sha256(content)))
        baseline_manifest[baseline_path.name] = _sha256(baseline_raw)
    counts = Counter(item.transition for item in records)
    syntax_counts = Counter(item.candidate_syntax_status for item in records)
    for status in ("PASS", "FAIL", "UNSUPPORTED", "ERROR"):
        syntax_counts.setdefault(status, 0)
    environment, environment_digest = _pinned_environment()
    parser_provenance = {
        name: {
            "version": environment["distributions"][name]["version"],
            "installed_code_digest": environment["distributions"][name][
                "installed_code_digest"
            ],
            "wheel_sha256": environment["distributions"][name]["wheel_sha256"],
        }
        for name in ("python-hcl2", "PyYAML")
    }
    implementation_digest = _sha256(json.dumps({
        "comparison": inspect.getsource(compare_frozen_runs),
        "local_parser": inspect.getsource(_local_candidate_evidence),
        "terraform": inspect.getsource(_terraform_resources),
        "kubernetes": inspect.getsource(_kubernetes_resources),
    }, sort_keys=True, separators=(",", ":")).encode())
    return {
        "schema_version": "legacy-hardened-comparison-v3",
        "result_label": "HISTORICAL_HARDENED_EVIDENCE_SUFFICIENCY_COMPARISON",
        "analysis_contract_version": ANALYSIS_CONTRACT,
        "is_production_verdict": False,
        "input_mode": "FROZEN_STORED_OUTPUTS_AND_LOCAL_DETERMINISTIC_PARSERS",
        "new_benchmark_inference_runs": 0,
        "model_provider_calls": 0,
        "scanner_executions": 0,
        "runs_compared": len(records),
        "transition_counts": dict(sorted(counts.items())),
        "candidate_syntax_counts": dict(sorted(syntax_counts.items())),
        "hardened_verified": 0,
        "hardened_limitations": list(MISSING_HARDENED_EVIDENCE),
        "parser_provenance": parser_provenance,
        "environment_contract": environment["environment_contract"],
        "environment_manifest_sha256": environment_digest,
        "base_image": environment["base_image"],
        "iac_guard_v_version": __version__,
        "iac_guard_v_implementation_digest": implementation_digest,
        "input_digests": {
            "stored_runs_manifest_sha256": _manifest_digest(run_manifest),
            "stored_patches_manifest_sha256": _manifest_digest(patch_manifest),
            "stored_baselines_manifest_sha256": _manifest_digest(list(baseline_manifest.items())),
        },
        "records": [item.canonical_dict() for item in records],
    }


def render_markdown(result: dict) -> str:
    transitions = result["transition_counts"]
    syntax = result["candidate_syntax_counts"]
    lines = [
        "# Historical hardened-evidence sufficiency comparison",
        "",
        "This is an evidence-sufficiency analysis over frozen stored outputs. It is not a",
        "production hardened-engine execution and makes zero hardened `VERIFIED` claims.",
        "",
        "## Results",
        "",
        *(
            f"- {transitions.get(f'LEGACY_{legacy}_TO_HARDENED_INCONCLUSIVE', 0)} "
            f"legacy `{legacy}` records → hardened evidence `INCONCLUSIVE`"
            for legacy in ("VERIFIED", "FAILED")
        ),
        f"- Hardened `VERIFIED` claims: {result['hardened_verified']}",
        "- Local parser outcomes: "
        + ", ".join(f"`{name}={syntax.get(name, 0)}`" for name in (
            "PASS", "FAIL", "UNSUPPORTED", "ERROR"
        )),
        "",
        "## Missing evidence",
        "",
    ]
    lines.extend(f"- `{item}`" for item in result["hardened_limitations"])
    lines.extend([
        "",
        "## Provenance and execution",
        "",
        f"- Analysis contract: `{result['analysis_contract_version']}`",
        f"- Environment contract: `{result['environment_contract']}`",
        f"- Environment manifest digest: `{result['environment_manifest_sha256']}`",
        f"- Base image manifest: `{result['base_image']['manifest_digest']}`",
        f"- IaC-Guard-V implementation digest: `{result['iac_guard_v_implementation_digest']}`",
    ])
    lines.extend(
        f"- Parser `{name}` {record['version']} installed-code digest: "
        f"`{record['installed_code_digest']}`"
        for name, record in sorted(result["parser_provenance"].items())
    )
    lines.extend(
        f"- {name}: `{digest}`" for name, digest in sorted(result["input_digests"].items())
    )
    lines.extend([
        f"- Scanner executions: {result['scanner_executions']}",
        f"- Model-provider calls: {result['model_provider_calls']}",
        f"- New benchmark inference runs: {result['new_benchmark_inference_runs']}",
        "- Paper and historical tables changed: no",
        "",
        "`PASS`, `FAIL`, `UNSUPPORTED`, and `ERROR` describe only the local independent",
        "parser attempt. They are not production verification verdicts. Domain syntax",
        "failure is `FAIL`; missing parser capability is `UNSUPPORTED`; internal or",
        "operational parser failure is `ERROR`.",
        "",
        "This file is generated from the canonical analysis values by",
        "`research/compat/compare_legacy_hardened.py`; byte equality is tested.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary-only", action="store_true")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--verify-environment", action="store_true")
    parser.add_argument("--assert-canonical", action="store_true")
    parser.add_argument("--write-canonical", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    if args.verify_environment:
        verify_pinned_environment()
    result = compare_frozen_runs()
    canonical_json = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    markdown = render_markdown(result)
    if args.write_canonical:
        CANONICAL_ANALYSIS.write_text(canonical_json, encoding="utf-8")
        CANONICAL_MARKDOWN.write_text(markdown, encoding="utf-8")
    if args.assert_canonical:
        if CANONICAL_ANALYSIS.read_text(encoding="utf-8") != canonical_json:
            raise ValueError("committed D9 canonical JSON differs from recomputation")
        if CANONICAL_MARKDOWN.read_text(encoding="utf-8") != markdown:
            raise ValueError("committed D9 Markdown differs from recomputation")
    if args.summary_only:
        result = {key: value for key, value in result.items() if key != "records"}
    if not args.quiet:
        print(render_markdown(result) if args.markdown else json.dumps(
            result, sort_keys=True, separators=(",", ":")
        ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
