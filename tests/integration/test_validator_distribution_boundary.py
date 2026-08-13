"""Built distributions exclude every private validator test capability."""
from __future__ import annotations

import subprocess
import sys
import os
import tarfile
import zipfile
from pathlib import Path


def test_wheel_and_sdist_contain_no_validator_test_capability(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    output = tmp_path / "dist"
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(output)],
        cwd=root, capture_output=True, text=True, check=False, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    wheel = next(output.glob("*.whl"))
    sdist = next(output.glob("*.tar.gz"))
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = tuple(archive.namelist())
        wheel_bytes = b"\n".join(archive.read(name) for name in wheel_names if name.endswith(".py"))
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_names = tuple(member.name for member in archive.getmembers())
        sdist_bytes = b"\n".join(
            archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile() and member.name.endswith(".py")
        )
    for names in (wheel_names, sdist_names):
        assert not any("tests/" in name or "phase_e_test_support" in name for name in names)
    for payload in (wheel_bytes, sdist_bytes):
        assert b"execute_tflint_fixture" not in payload
        assert b"make_test_container_runtime" not in payload
        assert b"_normalize_for_test" not in payload
        assert b"def create_oracle_result" not in payload

    installed = tmp_path / "installed"
    install = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--no-compile",
         "--target", str(installed), str(wheel)],
        capture_output=True, text=True, check=False, timeout=120,
    )
    assert install.returncode == 0, install.stderr
    environment = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(installed),
    }
    command = [
        sys.executable, "-c",
        "from iac_guard_v.validators.registry import _product_source_inventory; "
        "print('PASS' if not _product_source_inventory()[1] else 'INCONCLUSIVE')",
    ]
    for _attempt in range(2):
        invocation = subprocess.run(
            command, cwd=tmp_path, env=environment, capture_output=True, text=True,
            check=False, timeout=60,
        )
        assert invocation.returncode == 0, invocation.stderr
        assert invocation.stdout.strip() == "PASS"
    assert not tuple(installed.rglob("__pycache__"))
