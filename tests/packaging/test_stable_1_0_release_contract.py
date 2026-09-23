from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from iac_guard_v import __version__
from iac_guard_v.native_properties.__main__ import main as native_main
from iac_guard_v.native_properties.stable_v1 import STABLE_V1_PROPERTY_DIGESTS
from tools.release_candidate import sensitive_markers


ROOT = Path(__file__).parents[2]


def test_release_candidate_sensitive_markers_do_not_match_their_own_source() -> None:
    source = (ROOT / "tools" / "release_candidate.py").read_bytes()
    assert all(marker not in source for marker in sensitive_markers())


RELEASE_DOCUMENTS = (
    "README.md",
    "SUPPORTED_SCOPE.md",
    "SECURITY_MODEL.md",
    "COMPATIBILITY.md",
    "NATIVE_PROPERTIES.md",
    "SCANNER_AUTHORITY.md",
    "MIGRATION_0_1_0B1_TO_1_0.md",
    "RELEASE_NOTES_1_0.md",
    "SUPPORT_POLICY.md",
)


def test_stable_version_and_release_documents_are_coherent() -> None:
    assert __version__ == "1.0.0"
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "1.0.0"' in pyproject
    assert 'requires-python = ">=3.10,<3.14"' in pyproject
    assert "Development Status :: 5 - Production/Stable" in pyproject
    for relative in RELEASE_DOCUMENTS:
        content = (ROOT / relative).read_text(encoding="utf-8")
        assert content.startswith("# ")
        assert "/Users/" not in content
        assert "EB-1A" not in content
        assert "USCIS" not in content
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert "version: 1.0.0" in citation
    assert "date-released:" not in citation


def test_native_property_documentation_covers_exact_frozen_surface() -> None:
    content = (ROOT / "NATIVE_PROPERTIES.md").read_text(encoding="utf-8")
    documented = {
        token.strip("`")
        for token in content.replace("|", " ").split()
        if token.strip("`") in STABLE_V1_PROPERTY_DIGESTS
    }
    assert documented == set(STABLE_V1_PROPERTY_DIGESTS)
    assert len(documented) == 18
    for result in ("SATISFIED", "VIOLATED", "NOT_EVALUATED", "UNSUPPORTED", "ERROR"):
        assert f"`{result}`" in content


@pytest.mark.parametrize(
    ("relative", "expected_exit", "expected_result"),
    (
        ("kubernetes/satisfied/native-request.json", 0, "SATISFIED"),
        ("kubernetes/violated/native-request.json", 1, "VIOLATED"),
        ("kubernetes/not-evaluated/native-request.json", 3, "NOT_EVALUATED"),
        ("terraform/native-request.json", 0, "SATISFIED"),
    ),
)
def test_packaged_quickstarts_have_declared_results(
    relative: str,
    expected_exit: int,
    expected_result: str,
    tmp_path: Path,
) -> None:
    output = tmp_path / "report.json"
    code = native_main([
        "--config", str(ROOT / "examples/quickstart" / relative),
        "--format", "json", "--output", str(output), "--quiet",
    ])
    assert code == expected_exit
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["observations"][0]["result"] == expected_result
    assert payload["observations"][0]["reason_code"]
    assert payload["observations"][0]["witness"]


def test_product_has_no_hidden_network_client_or_dynamic_plugin_surface() -> None:
    network_modules = {"requests", "httpx", "aiohttp", "socket", "urllib.request"}
    dynamic_calls: list[tuple[str, int, str]] = []
    for path in (ROOT / "src/iac_guard_v").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {alias.name for alias in node.names} & network_modules
            elif isinstance(node, ast.ImportFrom):
                assert node.module not in network_modules
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in {"entry_points", "load_module"}:
                    dynamic_calls.append((path.name, node.lineno, node.func.attr))
                if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                    assert (
                        len(node.args) == 1
                        and isinstance(node.args[0], ast.Constant)
                        and node.args[0].value == "hcl2.parser"
                    )
    assert dynamic_calls == []


def test_release_facing_docs_do_not_describe_1_0_as_beta() -> None:
    current = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in RELEASE_DOCUMENTS
        if relative not in {"MIGRATION_0_1_0B1_TO_1_0.md", "RELEASE_NOTES_1_0.md"}
    )
    for stale in ("current beta", "Beta 1 prerelease", "latest published prerelease"):
        assert stale not in current
    assert "universal IaC" in current
    assert "Python 3.14" in current
    assert "missing output" in current.lower()
