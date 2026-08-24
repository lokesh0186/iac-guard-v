"""Publication workflow boundary for the reviewed 0.1.0a3 artifacts."""
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
    assert "v0.1.0-alpha.3" in workflow
    assert "874e5316eb822ed5726605b84f66b7a96120dc21" in workflow
    assert "7de633ff85595052c04a9fad2aa156a2e3f77062ba7d118f5a35fb15fd08405b" in workflow
    assert "a0aa406752013cc574e4d40ba23826ec472eb28db0a751af06f5196b839d33cf" in workflow
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
