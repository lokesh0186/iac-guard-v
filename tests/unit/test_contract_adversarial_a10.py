from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from iac_guard_v.contracts import ContractExecutionInput, load_contract, prepare_contract_run
from iac_guard_v.contracts.activation import evaluate_activation, requested_activation_paths
from iac_guard_v.contracts.helm_values import (
    EffectiveValueFact,
    EffectiveValueUniverse,
    direct_effective_values,
)
from iac_guard_v.contracts.model import (
    ActivationEvidence,
    ActivationStatus,
    ContractProvenance,
    InfrastructureContract,
    ContractSourceIdentity,
    contract_canonical_json,
    contract_digest,
)
from iac_guard_v.contracts.parser import _parse_contract_content, lint_contract
from iac_guard_v.contracts.provenance import derive_contract_source
from iac_guard_v.contracts.public import _read_direct_values, prepare_contract_plan
from iac_guard_v.contracts.report import validate_contract_report_payload
from iac_guard_v.contracts.report import (
    _expected_aggregate,
    _expected_clause_result,
    _validate_activation,
    _validate_contract_and_plan,
)
from iac_guard_v.models import DomainError
from iac_guard_v.native_properties.model import canonical_digest

from test_contract_core_a10 import MONITOR, _project, _run
from test_contract_differential_a10 import _write_contract
from test_native_kubernetes_a9 import API, FIXTURE


def test_activation_any_presence_origin_and_malformed_fail_closed() -> None:
    paths = ((".", "a"), (".", "b"))
    values = direct_effective_values({"a": False}, input_identity="a" * 64, requested_paths=paths)
    expression = {"any": [
        {"value": {"path": "a", "equals": True}},
        {"value": {"path": "b", "present": False}},
    ]}
    assert evaluate_activation(expression, values).status is ActivationStatus.ACTIVE
    origin = {"value": {"path": "a", "present": True, "requireOrigin": "DEFAULT"}}
    assert evaluate_activation(origin, values).status is ActivationStatus.ACTIVATION_NOT_EVALUATED
    absent = {"value": {"path": "b", "equals": False}}
    assert evaluate_activation(absent, values).status is ActivationStatus.ACTIVATION_NOT_EVALUATED
    unavailable = EffectiveValueUniverse("X", "b" * 64, "b" * 64, ())
    assert evaluate_activation({"value": {"path": "z", "present": True}}, unavailable).status is ActivationStatus.ACTIVATION_NOT_EVALUATED
    with pytest.raises(DomainError, match="malformed"):
        requested_activation_paths({"bogus": []})
    with pytest.raises(DomainError, match="malformed"):
        evaluate_activation({"bogus": []}, values)
    with pytest.raises(DomainError, match="secret-bearing"):
        requested_activation_paths({"value": {"path": "database.password", "present": True}})


def test_decimal_numeric_activation_is_typed_without_changing_native_json(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    path = project / ".iac-guard-v/contracts.yaml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace("serviceMonitor.create, equals: true", "threshold, equals: 0.75")
        .replace("      - value: {path: metrics.enabled, equals: true}\n", ""),
        encoding="utf-8",
    )
    contract = load_contract(
        path, project_root=project,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
    )
    universe = direct_effective_values(
        {"threshold": 0.75}, input_identity="9" * 64,
        requested_paths=((".", "threshold"),),
    )
    evidence = evaluate_activation(contract.when, universe)
    assert evidence.status is ActivationStatus.ACTIVE
    assert evidence.facts[0]["observed"]["value"] == 0.75


def test_effective_value_models_reject_duplicates_bad_origins_and_nonscalars() -> None:
    fact = EffectiveValueFact.build(
        context=".", path="a", present=True, value=1,
        origin="DIRECT_INPUT", origin_evidence={"input": "x"},
    )
    with pytest.raises(DomainError, match="unique"):
        EffectiveValueUniverse("X", "c" * 64, "c" * 64, (fact, fact))
    with pytest.raises(DomainError, match="origin"):
        EffectiveValueFact.build(
            context=".", path="a", present=True, value=1,
            origin="UNKNOWN", origin_evidence={},
        )
    with pytest.raises(DomainError, match="mapping"):
        direct_effective_values([], input_identity="d" * 64, requested_paths=())
    with pytest.raises(DomainError, match="root context"):
        direct_effective_values({}, input_identity="d" * 64, requested_paths=(("charts/x", "a"),))
    with pytest.raises(DomainError, match="scalar"):
        direct_effective_values({"a": []}, input_identity="d" * 64, requested_paths=((".", "a"),))


def test_selector_include_exclude_and_cardinality_are_visible(tmp_path: Path) -> None:
    project = tmp_path / "project"
    rendered = project / "rendered"
    rendered.mkdir(parents=True)
    (rendered / "all.yaml").write_text(FIXTURE, encoding="utf-8")
    contract = _write_contract(
        project, artifact="kubernetes_rendered", subject=API,
        property_id="IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1",
    )
    path = contract
    payload = __import__("yaml").safe_load(path.read_text(encoding="utf-8"))
    payload["spec"]["subjects"] = {
        "include": {"selector": {
            "apiVersions": ["apps/v1", "batch/v1"],
            "kinds": ["Deployment", "Job"],
            "namespaces": ["apps"],
            "labelSelector": {"matchExpressions": [{
                "key": "app", "operator": "Exists",
            }]},
        }},
        "exclude": {"identities": ["batch/v1/Job/apps/migrate"]},
        "cardinality": {"min": 1, "max": 1},
    }
    path.write_text(__import__("yaml").safe_dump(payload, sort_keys=True), encoding="utf-8")
    with prepare_contract_run(ContractExecutionInput(
        path, project, protected_root=rendered, source_commit="2" * 40,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
    )) as run:
        assert run.plan.subjects.selected == (API,)
        assert run.plan.subjects.excluded == ("batch/v1/Job/apps/migrate",)
        assert any(item["matched"] for item in run.plan.subjects.candidates)


def test_unmatched_explicit_exclusion_remains_visible(tmp_path: Path) -> None:
    project = tmp_path / "project"
    rendered = project / "rendered"
    rendered.mkdir(parents=True)
    (rendered / "all.yaml").write_text(FIXTURE, encoding="utf-8")
    contract = _write_contract(
        project, artifact="kubernetes_rendered", subject=API,
        property_id="IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1",
    )
    payload = __import__("yaml").safe_load(contract.read_text(encoding="utf-8"))
    payload["spec"]["subjects"]["exclude"] = {
        "identities": ["batch/v1/Job/apps/not-present"]
    }
    contract.write_text(__import__("yaml").safe_dump(payload, sort_keys=True), encoding="utf-8")
    with prepare_contract_run(ContractExecutionInput(
        contract, project, protected_root=rendered, source_commit="4" * 40,
        requested_provenance=ContractProvenance.RESEARCH_HYPOTHESIS,
    )) as run:
        assert run.plan.subjects.excluded == ("batch/v1/Job/apps/not-present",)
        assert run.plan.subjects.selected == (API,)


def test_subject_cardinality_above_and_below_are_violations(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    path = project / ".iac-guard-v/contracts.yaml"
    text = path.read_text(encoding="utf-8")
    text = text.replace(f"identities: [{MONITOR}]", f"identities: [{MONITOR}, v1/Service/falco/falco-metrics]")
    path.write_text(text, encoding="utf-8")
    with _run(project, values) as run:
        assert run.plan.reason_code == "SUBJECT_CARDINALITY_ABOVE_MAXIMUM"
    path.write_text(text.replace("min: 1, max: 1", "min: 3, max: 3"), encoding="utf-8")
    with _run(project, values) as run:
        assert run.plan.reason_code == "SUBJECT_CARDINALITY_BELOW_MINIMUM"


def test_provenance_boundary_rejects_symlink_external_forgery_and_bad_models(tmp_path: Path) -> None:
    project, _ = _project(tmp_path)
    source = project / ".iac-guard-v/contracts.yaml"
    link = project / "link.yaml"
    link.symlink_to(source)
    with pytest.raises(DomainError):
        derive_contract_source(link, project, ContractProvenance.USER_AUTHORED)
    outside = tmp_path / "outside.yaml"
    outside.write_bytes(source.read_bytes())
    with pytest.raises(DomainError, match="external"):
        derive_contract_source(outside, project, ContractProvenance.PROJECT_AUTHORED)
    external, _ = derive_contract_source(
        outside, project, ContractProvenance.USER_AUTHORED, source_commit="3" * 40
    )
    assert external.path == "external/outside.yaml"
    with pytest.raises(DomainError, match="paths"):
        derive_contract_source("bad", project, None)  # type: ignore[arg-type]
    with pytest.raises(DomainError):
        ContractSourceIdentity("x", "bad", "x", "0" * 64, ContractProvenance.USER_AUTHORED)
    with pytest.raises(DomainError):
        ActivationEvidence(ActivationStatus.ACTIVE, "unknown", (), "0" * 64)


def _rehash_report(payload: dict) -> None:
    body = dict(payload)
    body.pop("report_digest", None)
    body.pop("exit_code", None)
    payload["report_digest"] = canonical_digest(body)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("native_registry_identity", "0" * 64, "registry"),
        ("compiler_identity", "0" * 64, "compiler"),
    ],
)
def test_contract_report_rejects_stale_bound_identities(
    tmp_path: Path, field: str, value: str, message: str,
) -> None:
    project, values = _project(tmp_path)
    with _run(project, values) as run:
        payload = json.loads(run.report.canonical_json())
    payload[field] = value
    _rehash_report(payload)
    with pytest.raises(DomainError, match=message):
        validate_contract_report_payload(payload)


def test_contract_report_rejects_summary_plan_subject_and_exit_tamper(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    with _run(project, values) as run:
        original = json.loads(run.report.canonical_json())
    for mutate, message in (
        (lambda p: p["summary"].__setitem__("TOTAL", 9), "summary"),
        (lambda p: p["plan"].__setitem__("reason_code", "FORGED"), "plan"),
        (lambda p: p["plan"]["subjects"].__setitem__("selected", []), "plan|subject"),
        (lambda p: p.__setitem__("exit_code", 10), "exit code"),
    ):
        payload = json.loads(json.dumps(original))
        mutate(payload)
        _rehash_report(payload)
        with pytest.raises(DomainError, match=message):
            validate_contract_report_payload(payload)


def test_report_validator_recomputes_activation_truth_and_rejects_malformed_evidence(
    tmp_path: Path,
) -> None:
    project, values = _project(tmp_path)
    with _run(project, values) as run:
        payload = json.loads(run.report.canonical_json())
    expression = payload["contract"]["canonical_payload"]["spec"]["when"]
    activation = payload["activation"]
    _validate_activation(expression, activation)

    mutations = (
        ({**activation, "input_identity": "bad"}, "identity"),
        ({**activation, "facts": activation["facts"][:-1]}, "fact is missing"),
        ({**activation, "facts": [*activation["facts"], activation["facts"][0]]}, "extra"),
        ({**activation, "facts": [None, *activation["facts"][1:]]}, "fact is invalid"),
    )
    for mutated, message in mutations:
        with pytest.raises(DomainError, match=message):
            _validate_activation(expression, mutated)

    malformed_fact = json.loads(json.dumps(activation))
    malformed_fact["facts"][0]["observed"]["fact_digest"] = "0" * 64
    with pytest.raises(DomainError, match="effective value digest"):
        _validate_activation(expression, malformed_fact)


def test_report_result_reconstruction_covers_native_precedence_and_cardinality() -> None:
    plan = {"target_minimum": 1, "target_maximum": 1}

    def observation(result: str, count: int | None = None) -> dict:
        contents = {} if count is None else {"matched_services": [str(i) for i in range(count)]}
        return {"result": result, "witness": {"contents": contents}}

    assert _expected_clause_result(plan, [observation("ERROR")])[:2] == (
        "ERROR", "NATIVE_PROPERTY_ERROR",
    )
    assert _expected_clause_result(plan, [observation("VIOLATED")])[:2] == (
        "VIOLATED", "NATIVE_PROPERTY_VIOLATED",
    )
    assert _expected_clause_result(plan, [observation("UNSUPPORTED")])[:2] == (
        "UNSUPPORTED", "NATIVE_PROPERTY_UNSUPPORTED",
    )
    assert _expected_clause_result(plan, [observation("NOT_EVALUATED")])[:2] == (
        "NOT_EVALUATED", "NATIVE_PROPERTY_NOT_EVALUATED",
    )
    assert _expected_clause_result(plan, [observation("SATISFIED", 0)])[:2] == (
        "VIOLATED", "TARGET_CARDINALITY_BELOW_MINIMUM",
    )
    assert _expected_clause_result(plan, [observation("SATISFIED", 2)])[:2] == (
        "VIOLATED", "TARGET_CARDINALITY_ABOVE_MAXIMUM",
    )
    assert _expected_clause_result(plan, []) == (
        "SATISFIED", "EMPTY_SUBJECT_SET_EXPLICITLY_ALLOWED", 0,
    )

    for result, reason in (
        ("ERROR", "REQUIRED_CLAUSE_ERROR"),
        ("VIOLATED", "REQUIRED_CLAUSE_VIOLATED"),
        ("UNSUPPORTED", "REQUIRED_CLAUSE_UNSUPPORTED"),
        ("NOT_EVALUATED", "REQUIRED_CLAUSE_NOT_EVALUATED"),
    ):
        assert _expected_aggregate(
            {"plan_result": "SATISFIED", "reason_code": "CONTRACT_PLAN_COMPILED"},
            [{"required": True, "result": result}],
        ) == (result, reason)
    assert _expected_aggregate(
        {"plan_result": "VIOLATED", "reason_code": "ZERO_SUBJECT_MATCH"}, [],
    ) == ("VIOLATED", "ZERO_SUBJECT_MATCH")


def test_contract_public_input_and_direct_activation_file_boundaries(tmp_path: Path) -> None:
    project, _ = _project(tmp_path)
    contract = project / ".iac-guard-v/contracts.yaml"
    rendered = project / "rendered"
    with pytest.raises(DomainError, match="contract_path"):
        ContractExecutionInput("bad", project, protected_root=rendered)  # type: ignore[arg-type]
    with pytest.raises(DomainError, match="exactly one"):
        ContractExecutionInput(contract, project)
    with pytest.raises(DomainError, match="protected root"):
        ContractExecutionInput(contract, project, protected_root="bad")  # type: ignore[arg-type]
    with pytest.raises(DomainError, match="activation values path"):
        ContractExecutionInput(
            contract, project, protected_root=rendered,
            activation_values_path="bad",  # type: ignore[arg-type]
        )
    with pytest.raises(DomainError, match="execution input"):
        with prepare_contract_plan("bad"):  # type: ignore[arg-type]
            pass

    outside = tmp_path / "outside.yaml"
    outside.write_text("enabled: true\n", encoding="utf-8")
    with pytest.raises(DomainError, match="escape"):
        _read_direct_values(outside, project)
    link = project / "linked-values.yaml"
    link.symlink_to(outside)
    with pytest.raises(DomainError, match="escape|symlink"):
        _read_direct_values(link, project)
    values = project / "values.yaml"
    values.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(DomainError, match="mapping"):
        _read_direct_values(values, project)
    values.write_bytes(b"\xff")
    with pytest.raises(DomainError, match="strict UTF-8 YAML"):
        _read_direct_values(values, project)
    values.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(DomainError, match="1 MiB"):
        _read_direct_values(values, project)


def test_contract_parser_and_canonical_json_adversarial_boundaries(tmp_path: Path) -> None:
    with pytest.raises(DomainError, match="pathlib.Path"):
        lint_contract("bad")  # type: ignore[arg-type]
    with pytest.raises(DomainError, match="mapping"):
        _parse_contract_content(b"[]\n")
    nested = "x: " + "[" * 18 + "0" + "]" * 18
    with pytest.raises(DomainError, match="nesting"):
        _parse_contract_content(nested.encode("utf-8"))
    with pytest.raises(DomainError, match="keys"):
        contract_canonical_json({1: "bad"})
    with pytest.raises(DomainError, match="unsupported JSON type"):
        contract_canonical_json({"bad"})
    with pytest.raises(DomainError, match="non-finite"):
        contract_canonical_json(float("inf"))


def test_contract_source_size_root_and_git_identity_boundaries(tmp_path: Path) -> None:
    project, _ = _project(tmp_path)
    source = project / ".iac-guard-v/contracts.yaml"
    source.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(DomainError, match="1 MiB"):
        derive_contract_source(
            source, project, ContractProvenance.RESEARCH_HYPOTHESIS,
        )

    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    external = tmp_path / "external.yaml"
    external.write_text("x: true\n", encoding="utf-8")
    with pytest.raises(DomainError, match="regular directory"):
        derive_contract_source(
            external, linked_root, ContractProvenance.USER_AUTHORED,
        )

    repo = tmp_path / "repo"
    contract_dir = repo / ".iac-guard-v"
    contract_dir.mkdir(parents=True)
    canonical = contract_dir / "contracts.yaml"
    canonical.write_text("x: true\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q", str(repo)), check=True)
    unrelated = repo / "README.md"
    unrelated.write_text("test\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(repo), "add", "README.md"), check=True)
    subprocess.run((
        "git", "-C", str(repo), "-c", "user.name=Test", "-c",
        "user.email=test@example.invalid", "commit", "-q", "-m", "without contract",
    ), check=True)
    commit = subprocess.run(
        ("git", "-C", str(repo), "rev-parse", "HEAD"), check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    with pytest.raises(DomainError, match="absent"):
        derive_contract_source(canonical, repo, None, source_commit=commit)
    with pytest.raises(DomainError, match="unavailable"):
        derive_contract_source(canonical, repo, None, source_commit="f" * 40)


def test_contract_model_invariants_reject_forged_semantic_objects() -> None:
    source = ContractSourceIdentity(
        "contract.yaml", "0" * 64, "a" * 40, "1" * 64,
        ContractProvenance.USER_AUTHORED,
    )
    payload = {
        "apiVersion": "iac-guard-v.io/v1alpha1", "kind": "InfrastructureContract",
        "metadata": {"name": "valid"}, "spec": {},
    }
    for name, artifact, digest, identity, message in (
        ("INVALID_NAME", "kubernetes_rendered", contract_digest(payload), source, "name"),
        ("valid", "cloud_runtime", contract_digest(payload), source, "artifact class"),
        ("valid", "kubernetes_rendered", "0" * 64, source, "digest"),
        ("valid", "kubernetes_rendered", contract_digest(payload), object(), "source identity"),
    ):
        with pytest.raises(DomainError, match=message):
            InfrastructureContract(
                name, artifact, None, {}, {}, (), payload, digest, identity,  # type: ignore[arg-type]
            )
    with pytest.raises(DomainError, match="source commit"):
        ContractSourceIdentity(
            "contract.yaml", "0" * 64, "main", "1" * 64,
            ContractProvenance.USER_AUTHORED,
        )
    with pytest.raises(DomainError, match="provenance"):
        ContractSourceIdentity(
            "contract.yaml", "0" * 64, "WORKTREE", "1" * 64, "USER_AUTHORED",  # type: ignore[arg-type]
        )
    with pytest.raises(DomainError, match="status"):
        ActivationEvidence("ACTIVE", "VALID", (), "0" * 64)  # type: ignore[arg-type]
    with pytest.raises(DomainError, match="input identity"):
        ActivationEvidence(ActivationStatus.ACTIVE, "VALID", (), "bad")


def test_parser_rejects_duplicate_clause_ids_and_vacuous_cardinality(tmp_path: Path) -> None:
    project, values = _project(tmp_path)
    original = __import__("yaml").safe_load(
        (project / ".iac-guard-v/contracts.yaml").read_text(encoding="utf-8")
    )
    duplicate = json.loads(json.dumps(original))
    duplicate["spec"]["expect"].append(
        json.loads(json.dumps(duplicate["spec"]["expect"][0]))
    )
    with pytest.raises(DomainError, match="clause IDs"):
        _parse_contract_content(__import__("yaml").safe_dump(duplicate).encode())
    empty = json.loads(json.dumps(original))
    empty["spec"]["subjects"]["cardinality"] = {"min": 1, "allowEmpty": True}
    with pytest.raises(DomainError, match="allowEmpty"):
        _parse_contract_content(__import__("yaml").safe_dump(empty).encode())
    target = json.loads(json.dumps(original))
    target["spec"]["expect"][0]["relationCardinality"] = {
        "targetMin": 2, "targetMax": 1,
    }
    with pytest.raises(DomainError, match="target maximum"):
        _parse_contract_content(__import__("yaml").safe_dump(target).encode())

    diagnostic_only = json.loads(json.dumps(original))
    diagnostic_only["spec"]["expect"][0]["required"] = False
    with pytest.raises(DomainError, match="at least one required clause"):
        _parse_contract_content(__import__("yaml").safe_dump(diagnostic_only).encode())

    with _run(project, values) as run:
        project_payload = run.report.canonical_dict()
    project_payload["contract"]["canonical_payload"]["spec"]["expect"][0][
        "required"
    ] = False
    with pytest.raises(DomainError, match="no required clause"):
        _validate_contract_and_plan(project_payload)


def test_direct_activation_values_reject_symlink_and_read_complete_file(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    target = project / "values-target.yaml"
    target.write_text("feature:\n  enabled: true\n", encoding="utf-8")
    link = project / "values.yaml"
    link.symlink_to(target)
    with pytest.raises(DomainError, match="non-symlink"):
        _read_direct_values(link, project)

    link.unlink()
    link.write_text(
        "#" + ("x" * (70 * 1024)) + "\nfeature:\n  enabled: true\n",
        encoding="utf-8",
    )
    value, identity = _read_direct_values(link, project)
    assert value == {"feature": {"enabled": True}}
    assert len(identity) == 64


def test_report_activation_unconditional_unavailable_any_and_origin_boundaries() -> None:
    unconditional = evaluate_activation(None, None).canonical_dict()
    _validate_activation(None, unconditional)
    with pytest.raises(DomainError, match="unconditional"):
        _validate_activation(None, {**unconditional, "reason_code": "FORGED"})

    expression = {"value": {"path": "missing", "equals": True}}
    unavailable = evaluate_activation(expression, None).canonical_dict()
    _validate_activation(expression, unavailable)
    with pytest.raises(DomainError, match="unavailable activation identity"):
        _validate_activation(expression, {**unavailable, "input_identity": "0" * 64})

    paths = ((".", "a"), (".", "b"))
    values = direct_effective_values(
        {"a": False, "b": False}, input_identity="2" * 64, requested_paths=paths,
    )
    any_expression = {"any": [
        {"value": {"path": "a", "equals": True}},
        {"value": {"path": "b", "equals": True}},
    ]}
    any_evidence = evaluate_activation(any_expression, values).canonical_dict()
    _validate_activation(any_expression, any_evidence)
    assert any_evidence["status"] == "INACTIVE_CONDITION_FALSE"

    origin_expression = {
        "value": {"path": "a", "present": True, "requireOrigin": "DEFAULT"},
    }
    origin_evidence = evaluate_activation(origin_expression, values).canonical_dict()
    _validate_activation(origin_expression, origin_evidence)
    assert origin_evidence["status"] == "ACTIVATION_NOT_EVALUATED"
