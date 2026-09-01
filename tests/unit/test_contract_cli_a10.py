from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from iac_guard_v.cli import _contract_execution_input, _parse_helm_override, main
from iac_guard_v.models import DomainError

from test_contract_core_a10 import _project


def _args(project: Path, values: Path) -> list[str]:
    return [
        "--project-root", str(project),
        "--contract-root", str(project / "rendered"),
        "--activation-values", str(values),
        "--contract-provenance", "RESEARCH_HYPOTHESIS",
        "--source-commit", "d" * 40,
    ]


def test_contract_lint_plan_verify_and_explain(tmp_path: Path, capsys, monkeypatch) -> None:
    project, values = _project(tmp_path)
    contract = project / ".iac-guard-v/contracts.yaml"
    assert main([
        "contract", "lint", "--contract", str(contract),
        "--format", "json",
    ]) == 0
    linted = json.loads(capsys.readouterr().out)
    assert linted["status"] == "VALID"
    assert linted["provenance"] == "NOT_EVALUATED_BY_LINT"
    def forbidden(*_args, **_kwargs):
        raise AssertionError("contract plan evaluated a native property")
    monkeypatch.setattr("iac_guard_v.contracts.evaluator.evaluate_native_requests", forbidden)
    assert main([
        "contract", "plan", "--contract", str(contract),
        *_args(project, values), "--format", "json",
    ]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["plan"]["clauses"][0]["requests"][0]["property_id"].startswith("IACGV_")
    monkeypatch.undo()
    report = tmp_path / "contract-report.json"
    assert main([
        "verify", "--contract", str(contract), *_args(project, values),
        "--format", "json", "--output", str(report),
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["result"] == "SATISFIED"
    assert main(["explain", str(report), "--format", "console"]) == 0
    assert "not an automatic project defect" in capsys.readouterr().out


def test_contract_cli_exit_codes_for_violation_inactive_and_invalid(tmp_path: Path, capsys) -> None:
    project, values = _project(tmp_path, service=False)
    contract = project / ".iac-guard-v/contracts.yaml"
    assert main([
        "verify", "--contract", str(contract), *_args(project, values), "--format", "console",
    ]) == 10
    assert "VIOLATED" in capsys.readouterr().out
    values.write_text("serviceMonitor: {create: false}\nmetrics: {enabled: false}\n", encoding="utf-8")
    assert main([
        "verify", "--contract", str(contract), *_args(project, values), "--format", "console",
    ]) == 11
    assert "NOT_EVALUATED" in capsys.readouterr().out
    contract.write_text("not: a contract\n", encoding="utf-8")
    assert main([
        "contract", "lint", "--contract", str(contract),
    ]) == 20
    assert json.loads(capsys.readouterr().err)["reason_code"] == "INVALID_CONTRACT"


def test_contract_cli_internal_error_has_contract_specific_exit(tmp_path: Path, capsys, monkeypatch) -> None:
    project, values = _project(tmp_path)
    monkeypatch.setattr(
        "iac_guard_v.cli.prepare_contract_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("private detail")),
    )
    assert main([
        "verify", "--contract", str(project / ".iac-guard-v/contracts.yaml"),
        *_args(project, values), "--format", "json",
    ]) == 21
    payload = json.loads(capsys.readouterr().err)
    assert payload == {
        "schema_version": "request-error-v1",
        "exit_code": 21,
        "reason_code": "UNEXPECTED_INTERNAL_ERROR",
    }


def test_contract_cli_console_plan_lint_outputs_and_plan_exit_codes(tmp_path: Path, capsys) -> None:
    project, values = _project(tmp_path)
    contract = project / ".iac-guard-v/contracts.yaml"
    assert main(["contract", "lint", "--contract", str(contract)]) == 0
    assert "provenance: NOT_EVALUATED_BY_LINT" in capsys.readouterr().out

    plan_output = tmp_path / "plan.txt"
    assert main([
        "contract", "plan", "--contract", str(contract), *_args(project, values),
        "--format", "console", "--output", str(plan_output), "--quiet",
    ]) == 0
    assert capsys.readouterr().out == ""
    assert "native requests: 1" in plan_output.read_text(encoding="utf-8")

    values.write_text(
        "serviceMonitor: {create: false}\nmetrics: {enabled: true}\n", encoding="utf-8"
    )
    assert main([
        "contract", "plan", "--contract", str(contract), *_args(project, values),
        "--format", "console",
    ]) == 11
    assert "CONTRACT_INACTIVE" in capsys.readouterr().out

    contract.write_text(
        contract.read_text(encoding="utf-8").replace(
            "monitoring.coreos.com/v1/ServiceMonitor/falco/falco",
            "monitoring.coreos.com/v1/ServiceMonitor/falco/missing",
        ), encoding="utf-8",
    )
    values.write_text(
        "serviceMonitor: {create: true}\nmetrics: {enabled: true}\n", encoding="utf-8"
    )
    assert main([
        "contract", "plan", "--contract", str(contract), *_args(project, values),
        "--format", "console",
    ]) == 11  # unresolved exact identity is uncertainty, not a fabricated violation
    assert "SUBJECT_IDENTITY_UNRESOLVED" in capsys.readouterr().out


def test_contract_cli_explain_formats_output_and_rejects_scanner_combinations(
    tmp_path: Path, capsys,
) -> None:
    project, values = _project(tmp_path)
    contract = project / ".iac-guard-v/contracts.yaml"
    report = tmp_path / "report.json"
    assert main([
        "verify", "--contract", str(contract), *_args(project, values),
        "--format", "console", "--output", str(report), "--quiet",
    ]) == 0
    assert capsys.readouterr().out == ""
    explained = tmp_path / "explained.json"
    assert main([
        "explain", str(report), "--format", "json", "--output", str(explained), "--quiet",
    ]) == 0
    assert capsys.readouterr().out == ""
    assert json.loads(explained.read_text(encoding="utf-8"))["result"] == "SATISFIED"
    assert main(["explain", str(report), "--format", "sarif"]) == 2
    assert json.loads(capsys.readouterr().err)["reason_code"] == "INVALID_REQUEST"
    assert main([
        "verify", "--contract", str(contract), *_args(project, values),
        "--all-baseline-findings",
    ]) == 20
    assert "cannot be combined" in json.loads(capsys.readouterr().err)["detail"]
    assert main([
        "verify", "--contract", str(contract), *_args(project, values), "--format", "sarif",
    ]) == 20
    assert "JSON or console" in json.loads(capsys.readouterr().err)["detail"]


def test_contract_helm_cli_argument_boundary(tmp_path: Path, monkeypatch) -> None:
    project, _values = _project(tmp_path)
    chart = project / "chart"
    chart.mkdir()
    (chart / "values.yaml").write_text("feature: {enabled: false}\n", encoding="utf-8")
    executable = project / "helm"
    executable.write_text("", encoding="utf-8")
    executable.chmod(0o755)
    base = dict(
        project_root=project,
        contract_provenance="RESEARCH_HYPOTHESIS",
        contract_root=None,
        contract_helm_chart=chart,
        contract_helm_executable=executable,
        contract_helm_release_name="release",
        contract_helm_namespace="demo",
        contract_helm_kube_version="1.31.0",
        contract_helm_values=["values.yaml"],
        contract_helm_set=["feature.enabled=true"],
        contract_helm_set_string=["feature.mode=strict"],
        contract_helm_api_version=["monitoring.coreos.com/v1"],
        contract_helm_include_crds=True,
        contract_helm_include_tests=True,
        activation_values=None,
        source_commit="1" * 40,
        default_namespace="demo",
    )
    value = _contract_execution_input(
        SimpleNamespace(**base), project / ".iac-guard-v/contracts.yaml"
    )
    assert value.helm_spec is not None
    assert value.helm_spec.set_values == (("feature.enabled", "true"),)
    assert value.helm_spec.set_strings == (("feature.mode", "strict"),)
    assert value.requested_provenance.value == "RESEARCH_HYPOTHESIS"

    with pytest.raises(DomainError, match="project-root"):
        _contract_execution_input(
            SimpleNamespace(**{**base, "project_root": None}),
            project / ".iac-guard-v/contracts.yaml",
        )
    with pytest.raises(DomainError, match="kube-version"):
        _contract_execution_input(
            SimpleNamespace(**{**base, "contract_helm_kube_version": None}),
            project / ".iac-guard-v/contracts.yaml",
        )
    with pytest.raises(DomainError, match="requires --contract-root"):
        _contract_execution_input(
            SimpleNamespace(**{
                **base, "contract_helm_chart": None, "contract_helm_executable": None,
            }),
            project / ".iac-guard-v/contracts.yaml",
        )
    monkeypatch.setattr("iac_guard_v.cli.shutil.which", lambda _name: None)
    with pytest.raises(DomainError, match="could not find Helm"):
        _contract_execution_input(
            SimpleNamespace(**{**base, "contract_helm_executable": None}),
            project / ".iac-guard-v/contracts.yaml",
        )
    assert _parse_helm_override("a=b") == ("a", "b")
    for malformed in ("bad", "=bad", "bad="):
        with pytest.raises(DomainError, match="override"):
            _parse_helm_override(malformed)
