"""Publication workflow boundary for the reviewed 0.1.0b1 artifacts."""
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
    assert "v0.1.0-beta.1" in workflow
    assert "b538ad931f193aa7786694080a0beca2a04bbd76" in workflow
    assert "4d5418ba9b4bb1cb9306eeb857732da19de37d896d9a932c4a54a5cb5a751244" in workflow
    assert "7be64ff19d16b58e434737c0369ca0d300bdd195f2141c260e984851dbf90c37" in workflow
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
