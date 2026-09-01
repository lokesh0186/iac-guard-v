"""Publication workflow boundary for the reviewed 0.1.0a10 artifacts."""
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
    assert "v0.1.0-alpha.10" in workflow
    assert "038bf38256706ffc83485bf5f33eb3c4992e3857" in workflow
    assert "6ff89229083c88b3d9c35b9be21646e722dfccaf2e6b2ccf3d215bb4c2a3b57e" in workflow
    assert "0df0104985e202c176d3f66cd1231334b03585c72b6870dc5db3379c3b932b47" in workflow
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
