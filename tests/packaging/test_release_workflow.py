"""Publication workflow boundary for the reviewed 0.1.0a6 artifacts."""
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
    assert "v0.1.0-alpha.6" in workflow
    assert "a8202a94720ff88cdb6f8115aa0208cff6538082" in workflow
    assert "5f39e41478fc30c5f2a7af1e2008059178d7eaadeb91dea67ac9446fd472b256" in workflow
    assert "84de430505f33acdcdc4e61fe022b1cb666348cbe6bbb7a7fbcb17a26d8af104" in workflow
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
