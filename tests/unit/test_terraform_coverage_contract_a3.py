"""Post-a2 Terraform parser unification and complete-file coverage contract."""
from __future__ import annotations

import contextlib
import importlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from iac_guard_v.config import PublicTarget
from iac_guard_v.adapters.checkov import CheckovAdapter
from iac_guard_v.engine import attest_checkov_scan_plan
from iac_guard_v.models import DomainError
from iac_guard_v.report import validate_report_payload
from iac_guard_v.terraform_parser import (
    SCAN_EVIDENCE_BEARING,
    STRUCTURAL_ONLY,
    parse_terraform_structure,
)
import iac_guard_v.terraform_parser as TERRAFORM_PARSER
from iac_guard_v.workflow import bind_inventory_targets

from test_checkov_adapter import request as adapter_request


@pytest.mark.parametrize(
    "source",
    (
        'resource "aws_s3_bucket" "x" { tags = { marker = "/*" } }\n',
        'resource "aws_s3_bucket" "x" { tags = { marker = "*/" } }\n',
        'resource "aws_s3_bucket" "x" { tags = { marker = "\\\"/*\\\"" } }\n',
        'resource "aws_s3_bucket" "x" {\n'
        '  policy = <<-EOT\n/* literal */\nEOT\n}\n',
        'resource "aws_s3_bucket" "x" { bucket = "${var.prefix}-bucket" }\n',
        '/* actual comment */\nresource "aws_s3_bucket" "x" {}\n',
    ),
)
def test_native_parser_preserves_terraform_lexical_context(source: str) -> None:
    structure = parse_terraform_structure(source.encode("utf-8"))
    assert structure.resource_addresses == ("aws_s3_bucket.x",)
    assert structure.coverage_kind == SCAN_EVIDENCE_BEARING


@pytest.mark.parametrize(
    "source",
    (
        'variable "name" { type = string }\n',
        'output "name" { value = var.name }\n',
        'terraform { required_version = ">= 1.6" }\n',
        'locals { name = "demo" }\n',
        "",
        "# comment only\n/* block comment only */\n",
    ),
)
def test_support_only_terraform_is_structural(source: str) -> None:
    structure = parse_terraform_structure(source.encode("utf-8"))
    assert structure.resource_addresses == ()
    assert structure.coverage_kind == STRUCTURAL_ONLY


@pytest.mark.parametrize(
    "source",
    (
        'resource "aws_s3_bucket" "x" {}\n',
        'data "aws_caller_identity" "current" {}\n',
        'module "child" { source = "./child" }\n',
        'provider "aws" { region = "us-east-1" }\n',
    ),
)
def test_scanner_or_graph_relevant_constructs_are_evidence_bearing(
    source: str,
) -> None:
    assert (
        parse_terraform_structure(source.encode("utf-8")).coverage_kind
        == SCAN_EVIDENCE_BEARING
    )


def test_parsed_structure_not_filename_controls_coverage(tmp_path: Path) -> None:
    raw = adapter_request(tmp_path)
    root = raw.scan_root
    (root / "variables.tf").write_text(
        'resource "aws_s3_bucket" "inside_variables" {}\n', encoding="utf-8"
    )
    (root / "outputs.tf").write_text(
        'module "inside_outputs" { source = "./child" }\n', encoding="utf-8"
    )
    (root / "versions.tf").write_text(
        'data "aws_caller_identity" "inside_versions" {}\n', encoding="utf-8"
    )
    (root / "support.tf").write_text(
        'variable "x" { type = string }\noutput "x" { value = var.x }\n',
        encoding="utf-8",
    )
    plan = attest_checkov_scan_plan(raw)
    by_path = {item.file_path: item for item in plan.classifications}
    assert set(plan.files_eligible) == {
        "main.tf", "outputs.tf", "variables.tf", "versions.tf",
    }
    assert plan.request.supporting_files == ("support.tf",)
    assert by_path["variables.tf"].coverage_kind == SCAN_EVIDENCE_BEARING
    assert by_path["outputs.tf"].coverage_kind == SCAN_EVIDENCE_BEARING
    assert by_path["versions.tf"].coverage_kind == SCAN_EVIDENCE_BEARING
    assert by_path["support.tf"].coverage_kind == STRUCTURAL_ONLY
    assert by_path["support.tf"].classification == "TERRAFORM_STRUCTURE"


def test_supporting_files_are_byte_bound_but_not_scanner_coverage_targets(
    tmp_path: Path,
) -> None:
    raw = adapter_request(tmp_path)
    root = raw.scan_root
    for name, source in {
        "outputs.tf": 'output "bucket" { value = aws_s3_bucket.bad.id }\n',
        "variables.tf": 'variable "name" { type = string }\n',
        "versions.tf": 'terraform { required_version = ">= 1.6" }\n',
        "empty.tf": "",
        "comments.tf": "# support only\n",
    }.items():
        (root / name).write_text(source, encoding="utf-8")
    plan = attest_checkov_scan_plan(raw)
    assert plan.files_eligible == ("main.tf",)
    assert plan.request.supporting_files == (
        "comments.tf", "empty.tf", "outputs.tf", "variables.tf", "versions.tf",
    )
    assert {
        item.file_path for item in plan.request.supporting_file_evidence
    } == set(plan.request.supporting_files)
    assert {
        item.file_path for item in plan.inspected_files
    }.issuperset(plan.request.supporting_files)


def test_unknown_top_level_construct_is_ambiguous_and_fails_closed(
    tmp_path: Path,
) -> None:
    raw = adapter_request(tmp_path)
    (raw.scan_root / "checks.tf").write_text(
        'check "health" { assert { condition = true error_message = "x" } }\n',
        encoding="utf-8",
    )
    with pytest.raises(DomainError, match="coverage is ambiguous"):
        attest_checkov_scan_plan(raw)


def test_init_uses_same_quoted_comment_parser_as_verification(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.tf").write_text(
        'resource "aws_iam_policy" "quoted" {\n'
        '  name = "policy"\n'
        '  policy = "${var.prefix}/*"\n'
        '}\n',
        encoding="utf-8",
    )
    target = PublicTarget("CKV_AWS_TEST", "aws_iam_policy.quoted")
    bound = bind_inventory_targets(root, (target,), ("terraform",))
    assert bound[0].file_path == "main.tf"


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (b"\xff", "UTF-8"),
        (b'variable "x" { default = "unterminated }', "unterminated Terraform string"),
        (b"/* unterminated", "unterminated Terraform block comment"),
        (b'resource "x"', "syntax is invalid"),
    ),
)
def test_parser_failure_diagnostics_remain_typed(
    payload: bytes, message: str,
) -> None:
    with pytest.raises(Exception, match=message):
        parse_terraform_structure(payload)


@pytest.mark.parametrize(
    ("document", "message"),
    (
        ({1: []}, "top-level block identity"),
        ({"resource": {}}, "resource structure"),
        ({"resource": [1]}, "resource block"),
        ({"resource": [{1: {}}]}, "resource identity"),
        ({"resource": [{"aws_x": []}]}, "resource identity"),
        ({"resource": [{"aws_x": {1: {}}}]}, "resource name"),
        (
            {"resource": [
                {"aws_x": {"same": {}}}, {"aws_x": {"same": {}}},
            ]},
            "duplicate Terraform resource",
        ),
    ),
)
def test_shared_parser_rejects_malformed_native_shapes(
    monkeypatch: pytest.MonkeyPatch, document: object, message: str,
) -> None:
    monkeypatch.setattr(
        TERRAFORM_PARSER, "isolated_hcl2_parser_cache",
        lambda: contextlib.nullcontext(),
    )
    monkeypatch.setattr(TERRAFORM_PARSER.hcl2, "loads", lambda _text: document)
    with pytest.raises(Exception, match=message):
        parse_terraform_structure(b"")


def test_parser_cache_rejects_unrecognized_modern_layout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser_module = importlib.import_module("hcl2.parser")
    monkeypatch.setattr(TERRAFORM_PARSER, "_HCL2_SECURE_CACHE_READY", False)
    monkeypatch.setattr(parser_module, "PARSER_FILE", Path("cache.bin"), raising=False)
    monkeypatch.setattr(parser_module, "parser", object(), raising=False)
    with pytest.raises(RuntimeError, match="unsupported python-hcl2"):
        with TERRAFORM_PARSER.isolated_hcl2_parser_cache():
            pass


def test_supporting_file_request_contract_is_closed(tmp_path: Path) -> None:
    raw = adapter_request(tmp_path)
    support = raw.scan_root / "variables.tf"
    support.write_text('variable "x" { type = string }\n', encoding="utf-8")
    request = replace(raw, supporting_files=("variables.tf",))
    assert request.supporting_files == ("variables.tf",)

    with pytest.raises(DomainError, match="exact tuple"):
        replace(raw, supporting_files=["variables.tf"])
    with pytest.raises(DomainError, match="INPUT_FILE_COUNT_EXCEEDED"):
        replace(raw, supporting_files=("variables.tf",), max_eligible_files=1)
    with pytest.raises(DomainError, match="duplicates"):
        replace(raw, supporting_files=("variables.tf", "variables.tf"))
    with pytest.raises(DomainError, match="disjoint"):
        replace(raw, supporting_files=("main.tf",))
    with pytest.raises(DomainError, match="INPUT_TOTAL_BYTES_EXCEEDED"):
        replace(raw, supporting_files=("variables.tf",), max_total_eligible_bytes=1)


def test_supporting_file_is_revalidated_and_copied_exactly(tmp_path: Path) -> None:
    raw = adapter_request(tmp_path)
    support = raw.scan_root / "variables.tf"
    content = b'variable "x" { type = string }\n'
    support.write_bytes(content)
    request = replace(raw, supporting_files=("variables.tf",))
    destination = tmp_path / "view"
    CheckovAdapter._build_scan_view(request, destination)
    assert (destination / "variables.tf").read_bytes() == content

    support.write_bytes(b'variable "changed" { type = string }\n')
    with pytest.raises(DomainError, match="INPUT_CHANGED_DURING_SCAN_PREPARATION"):
        CheckovAdapter._revalidate_inputs(request)


def test_pre_a3_public_report_remains_semantically_valid() -> None:
    path = Path(
        "examples/public-reproductions/coder-demo-env-templates-180/report.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert all(
        "coverage_kind" not in classification
        for role in ("baseline", "candidate")
        for classification in payload["verification"][f"{role}_snapshot"][
            "classifications"
        ]
    )
    validate_report_payload(payload)
