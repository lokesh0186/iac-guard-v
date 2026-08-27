"""Declarative local copies of the current public coverage gates.

PR A deliberately leaves GitHub Actions unchanged.  These definitions are consumed
by Nox and are the equivalence input for a later, separately reviewed CI cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True, slots=True)
class CoverageGate:
    name: str
    tests: tuple[str, ...]
    modules: tuple[str, ...]
    branch: bool = False
    threshold: int = 90

    def pytest_argv(self) -> list[str]:
        arguments = [*self.tests]
        arguments.extend(f"--cov={module}" for module in self.modules)
        if self.branch:
            arguments.append("--cov-branch")
        arguments.extend(("--cov-report=term-missing", f"--cov-fail-under={self.threshold}", "-q"))
        return arguments


D3_TESTS = (
    "tests/unit/test_fingerprints.py",
    "tests/unit/test_matching.py",
    "tests/unit/test_matching_d32.py",
    "tests/unit/test_diffing.py",
)

D4_TESTS = (
    "tests/unit/test_adapter_base.py",
    "tests/unit/test_checkov_adapter.py",
    "tests/unit/test_checkov_adapter_d41.py",
    "tests/unit/test_checkov_adapter_d42.py",
    "tests/unit/test_checkov_adapter_d45.py",
    "tests/unit/test_checkov_adapter_d46.py",
    "tests/unit/test_checkov_adapter_d48.py",
    "tests/unit/test_engine_d47.py",
    "tests/unit/test_graph_evidence_a2.py",
    "tests/unit/test_terraform_coverage_contract_a3.py",
)

D5_TESTS = (
    "tests/unit/test_engine.py",
    "tests/unit/test_engine_coverage_ci.py",
    "tests/unit/test_engine_d44.py",
    "tests/unit/test_engine_d45.py",
    "tests/unit/test_engine_d47.py",
    "tests/unit/test_engine_d51.py",
    "tests/unit/test_engine_d52.py",
    "tests/unit/test_engine_d53.py",
    "tests/unit/test_engine_d54.py",
    "tests/unit/test_engine_d55.py",
    "tests/unit/test_engine_d56.py",
    "tests/unit/test_engine_d57.py",
    "tests/unit/test_public_d7.py",
    "tests/unit/test_terraform_coverage_contract_a3.py",
)

D6_TESTS = (
    "tests/unit/test_policy.py",
    "tests/unit/test_policy_d61.py",
    "tests/unit/test_policy_d62.py",
    "tests/unit/test_policy_d63.py",
    "tests/unit/test_policy_d64.py",
    "tests/unit/test_engine_d51.py",
)

D7_TESTS = (
    "tests/unit/test_api_adoption.py",
    "tests/unit/test_candidate_acceptance_a5.py",
    "tests/unit/test_candidate_addressability_a5.py",
    "tests/unit/test_cli_adoption_branches.py",
    "tests/unit/test_cli_ux1.py",
    "tests/unit/test_cli_ux2.py",
    "tests/unit/test_cli_ux3.py",
    "tests/unit/test_public_d7.py",
    "tests/unit/test_public_d71.py",
    "tests/unit/test_public_d72.py",
    "tests/unit/test_public_d73.py",
    "tests/unit/test_public_d74.py",
    "tests/unit/test_public_d75.py",
    "tests/unit/test_reporters_e61.py",
    "tests/unit/test_workflow_adoption_branches.py",
    "tests/unit/test_workflow_commands_e62.py",
    "tests/unit/test_terraform_coverage_contract_a3.py",
    "tests/unit/test_helm_materialization_a4.py",
    "tests/unit/test_helm_provenance_a6.py",
    "tests/unit/test_helm_public_a4.py",
)

HELM_TESTS = (
    "tests/unit/test_candidate_acceptance_a5.py",
    "tests/unit/test_helm_materialization_a4.py",
    "tests/unit/test_helm_provenance_a6.py",
    "tests/unit/test_helm_public_a4.py",
)

COVERAGE_GATES = (
    CoverageGate("d3-fingerprints", D3_TESTS, ("iac_guard_v.fingerprints",)),
    CoverageGate("d3-matching", D3_TESTS, ("iac_guard_v.matching",)),
    CoverageGate("d3-diffing", D3_TESTS, ("iac_guard_v.diffing",)),
    CoverageGate(
        "d4-adapters-parser-graph",
        D4_TESTS,
        (
            "iac_guard_v.adapters.base",
            "iac_guard_v.adapters.checkov",
            "iac_guard_v.graph_evidence",
            "iac_guard_v.terraform_parser",
        ),
        branch=True,
    ),
    CoverageGate("d5-engine", D5_TESTS, ("iac_guard_v.engine",), branch=True),
    CoverageGate("d6-policy", D6_TESTS, ("iac_guard_v.policy",), branch=True),
    CoverageGate(
        "d7-public-boundary",
        D7_TESTS,
        (
            "iac_guard_v.acceptance",
            "iac_guard_v.api",
            "iac_guard_v.cli",
            "iac_guard_v.config",
            "iac_guard_v.report",
        ),
        branch=True,
    ),
    CoverageGate("helm-materializer", HELM_TESTS, ("iac_guard_v.helm",), branch=True),
)

SMOKE_TESTS = (
    "tests/unit/test_fingerprints.py::test_fingerprint_has_visible_algorithm_and_golden_value",
    "tests/unit/test_terraform_coverage_contract_a3.py::test_native_parser_preserves_terraform_lexical_context",
    "tests/unit/test_candidate_acceptance_a5.py::test_direct_kubernetes_candidate_has_exact_resource_identity",
    "tests/unit/test_helm_materialization_a4.py::test_h01_simple_chart_binds_deterministic_source_and_resource",
    "tests/unit/test_reporters_e61.py::test_reporters_are_byte_deterministic_and_do_not_retain_input",
)

CHECKOV_TESTS = (
    "tests/integration/test_checkov_integration.py",
    "tests/integration/test_alpha_golden_quickstart.py",
)

QRS_TESTS = (
    "tests/research/test_qrs_regression.py",
)

PACKAGE_TESTS = (
    "tests/packaging",
)


def gate_by_name(name: str) -> CoverageGate:
    for gate in COVERAGE_GATES:
        if gate.name == name:
            return gate
    raise KeyError(name)


def validate_paths(root: Path) -> None:
    for path in {
        item for gate in COVERAGE_GATES for item in gate.tests
    } | set(SMOKE_TESTS) | set(CHECKOV_TESTS) | set(QRS_TESTS) | set(PACKAGE_TESTS):
        candidate = path.split("::", 1)[0]
        if not (root / candidate).exists():
            raise RuntimeError(f"test gate path does not exist: {candidate}")


def validate_focused_selection(root: Path, selection: Sequence[str]) -> None:
    """Allow selectors and a small safe pytest filter surface, not arbitrary options."""
    if not selection or len(selection) > 128:
        raise RuntimeError("FOCUSED_SELECTION_INVALID: provide 1 to 128 test selectors")
    tests_root = (root / "tests").resolve(strict=True)
    expect_keyword = False
    for token in selection:
        if not token or "\x00" in token:
            raise RuntimeError("FOCUSED_SELECTION_INVALID: empty selector")
        if expect_keyword:
            if len(token) > 512 or token.startswith("-"):
                raise RuntimeError("FOCUSED_SELECTION_INVALID: invalid -k expression")
            expect_keyword = False
            continue
        if token == "-k":
            expect_keyword = True
            continue
        if token in {"--lf", "--ff"}:
            continue
        if token.startswith("-k=") and 3 < len(token) <= 515:
            continue
        if token.startswith("-"):
            raise RuntimeError(
                "FOCUSED_SELECTION_INVALID: only -k, --lf, and --ff are allowed"
            )
        selected_path = token.split("::", 1)[0]
        try:
            candidate = (root / selected_path).resolve(strict=True)
        except OSError as exc:
            raise RuntimeError(
                "FOCUSED_SELECTION_INVALID: selector path is unavailable"
            ) from exc
        try:
            candidate.relative_to(tests_root)
        except ValueError as exc:
            raise RuntimeError(
                "FOCUSED_SELECTION_INVALID: selector must be under tests/"
            ) from exc
        if not (candidate.is_file() or candidate.is_dir()):
            raise RuntimeError("FOCUSED_SELECTION_INVALID: selector path is unavailable")
    if expect_keyword:
        raise RuntimeError("FOCUSED_SELECTION_INVALID: -k requires an expression")
