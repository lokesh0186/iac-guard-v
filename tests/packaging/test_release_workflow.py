"""Publication workflow boundary for reviewed IaC-Guard-V 1.0 artifacts."""
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
    assert "attestations: write" in workflow
    assert "contents: read" in workflow
    assert "RELEASE_TAG: v1.0.0" in workflow
    assert "inputs.release_commit" in workflow
    assert "inputs.wheel_sha256" in workflow
    assert "inputs.sdist_sha256" in workflow
    assert "iac_guard_v-1.0.0-py3-none-any.whl" in workflow
    assert "iac_guard_v-1.0.0.tar.gz" in workflow
    assert "sha256sum --check --strict SHA256SUMS" in workflow
    assert "PROVENANCE.intoto.json" in workflow
    assert "SOURCE_MANIFEST.sha256" in workflow
    assert "python -m build" not in workflow
    assert "skip-existing" not in workflow


def test_release_workflow_pins_publication_and_attestation_actions() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert (
        "actions/attest@"
        "508db95dd578ae2727ebd6217d5ba78e4fbda05d"
    ) in workflow
    assert (
        "pypa/gh-action-pypi-publish@"
        "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
    ) in workflow
    assert "actions/attest@v" not in workflow
    assert "pypa/gh-action-pypi-publish@v" not in workflow
