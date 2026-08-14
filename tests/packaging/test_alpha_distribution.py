"""Public 0.1.0a1 distribution and clean-install boundary."""
from __future__ import annotations

import email
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet


ROOT = Path(__file__).parents[2]
VERSION = "0.1.0a1"
FORBIDDEN_DISTRIBUTION_PARTS = {
    "benchmark",
    "runs",
    "results",
    "prompts",
    "scanners",
    "scripts",
    "research",
    "tests",
    "tools",
    "controls",
    "paper.pdf",
}
TEST_CAPABILITY_MARKERS = (
    b"phase_e_test_support",
    b"make_test_container_runtime",
    b"execute_tflint_fixture",
    b"_normalize_for_test",
    b"_create_test_protected_checks_cache_identity",
    b"def create_oracle_result",
)


@pytest.fixture(scope="module")
def alpha_artifacts(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    output = tmp_path_factory.mktemp("alpha-dist")
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    return (
        next(output.glob(f"iac_guard_v-{VERSION}-py3-none-any.whl")),
        next(output.glob(f"iac_guard_v-{VERSION}.tar.gz")),
    )


def _forbidden_path(name: str) -> bool:
    parts = Path(name).parts
    # sdists have one versioned root directory; wheels do not.
    relative = parts[1:] if parts and parts[0].startswith("iac_guard_v-") else parts
    return bool(relative and relative[0] in FORBIDDEN_DISTRIBUTION_PARTS)


def test_alpha_metadata_and_version_are_consistent(alpha_artifacts) -> None:
    wheel, _sdist = alpha_artifacts
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = email.message_from_bytes(archive.read(metadata_name))
    assert metadata["Name"] == "iac-guard-v"
    assert metadata["Version"] == VERSION
    assert SpecifierSet(metadata["Requires-Python"]) == SpecifierSet(">=3.10,<3.14")
    assert "Development Status :: 3 - Alpha" in metadata.get_all("Classifier")
    assert f'__version__ = "{VERSION}"' in (
        ROOT / "src/iac_guard_v/__init__.py"
    ).read_text(encoding="utf-8")


def test_wheel_and_sdist_are_public_product_only(alpha_artifacts) -> None:
    wheel, sdist = alpha_artifacts
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = tuple(archive.namelist())
        product_python = b"\n".join(
            archive.read(name) for name in wheel_names if name.endswith(".py")
        )
    with tarfile.open(sdist, "r:gz") as archive:
        members = tuple(archive.getmembers())
        sdist_names = tuple(member.name for member in members)
        product_python += b"\n".join(
            archive.extractfile(member).read()
            for member in members
            if member.isfile() and member.name.endswith(".py")
        )

    assert not any(_forbidden_path(name) for name in (*wheel_names, *sdist_names))
    assert not any(marker in product_python for marker in TEST_CAPABILITY_MARKERS)
    assert "iac_guard_v/oracles/policies.json" in wheel_names
    assert "iac_guard_v/schemas/report-v1.schema.json" in wheel_names
    assert "iac_guard_v/schemas/config-v1.schema.json" in wheel_names
    assert "iac_guard_v/oracles/preconditions.py" in wheel_names
    assert "iac_guard_v/workflow.py" in wheel_names
    assert "iac_guard_v/reporters/sarif.py" in wheel_names
    assert "iac_guard_v/reporters/markdown.py" in wheel_names
    assert "iac_guard_v/reporters/junit.py" in wheel_names

    public_sdist_files = {
        Path(name).name for name in sdist_names if not name.endswith("/")
    }
    assert {
        "README.md",
        "RESEARCH_SNAPSHOT.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "ROADMAP.md",
        "CHANGELOG.md",
        "NOTICE",
        "CITATION.cff",
        "before.tf",
        "after.tf",
    } <= public_sdist_files
    assert any(name.endswith("docs/spec/THREAT_MODEL.md") for name in sdist_names)


def test_wheel_installs_and_runs_outside_source_checkout(
    alpha_artifacts, tmp_path: Path,
) -> None:
    wheel, _sdist = alpha_artifacts
    installed = tmp_path / "installed"
    install = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-compile",
            "--target",
            str(installed),
            str(wheel),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert install.returncode == 0, install.stderr
    environment = {
        **os.environ,
        "PATH": "",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    def run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        script = (
            "import sys;"
            f"sys.path.insert(0,{str(installed)!r});"
            "from iac_guard_v.cli import main;"
            f"raise SystemExit(main({arguments!r}))"
        )
        return subprocess.run(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    version = run(["--version"])
    assert version.returncode == 0, version.stderr
    assert version.stdout.strip() == f"iac-guard {VERSION}"

    help_result = run(["--help"])
    assert help_result.returncode == 0, help_result.stderr
    for command in ("scan", "differential", "lock", "init", "pr"):
        assert command in help_result.stdout

    demo = run(["demo", "--format", "json"])
    assert demo.returncode == 0, demo.stderr
    payload = json.loads(demo.stdout)
    assert payload["verdict"] == "INCONCLUSIVE"
    assert payload["diagnostic"]["reason_code"] == "OFFLINE_DEMO_ONLY"

    doctor = run(["doctor", "--format", "json"])
    assert doctor.returncode == 3, doctor.stderr
    diagnosis = json.loads(doctor.stdout)
    assert diagnosis["product_version"] == VERSION
    assert diagnosis["checkov"]["reason_code"] == "CHECKOV_NOT_FOUND"
    assert diagnosis["hardened_container"]["status"] == "INCONCLUSIVE"
    assert not tuple(installed.rglob("__pycache__"))


def test_public_alpha_docs_state_current_boundaries() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for statement in (
        "Checkov-focused alpha",
        "reduced-isolation",
        "Hardened production container",
        "There are no external-adoption",
        "zero `EXACT` mappings",
        "No arXiv identifier",
    ):
        assert statement in readme
    assert "arXiv:ADD" not in readme
    assert "XXXX.XXXXX" not in readme


def test_checkov_before_after_fixture_is_one_narrow_repair() -> None:
    before = (ROOT / "examples/checkov-before-after/before.tf").read_text(encoding="utf-8")
    after = (ROOT / "examples/checkov-before-after/after.tf").read_text(encoding="utf-8")
    assert 'resource "aws_s3_bucket_public_access_block" "example"' in before
    assert before.replace("block_public_acls       = false", "block_public_acls       = true") == after
