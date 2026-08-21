"""Publication workflow boundary for the reviewed 0.1.0a1 artifacts."""
from pathlib import Path


ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yml"


def test_release_workflow_promotes_only_reviewed_artifacts() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert "environment:\n      name: pypi" in workflow
    assert "id-token: write" in workflow
    assert "contents: read" in workflow
    assert "v0.1.0-alpha.1" in workflow
    assert "8e654ab7e58aaa3e4010a4accc58e1f8e0352a10" in workflow
    assert "cef195ecd950f12b8ef40c5f30c6d72761aa346902df3fc91c7e17b65ff5ce49" in workflow
    assert "2237087355d580c3d14a2a73d8bea21a958e6a4f31e9dbbb5e9684570d3db904" in workflow
    assert "sha256sum --check --strict" in workflow
    assert "find dist -maxdepth 1 -type f" in workflow
    assert "python -m build" not in workflow
    assert "skip-existing" not in workflow


def test_release_workflow_pins_the_publisher_action() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert (
        "pypa/gh-action-pypi-publish@"
        "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
    ) in workflow
    assert "pypa/gh-action-pypi-publish@release/" not in workflow
    assert "pypa/gh-action-pypi-publish@v" not in workflow
