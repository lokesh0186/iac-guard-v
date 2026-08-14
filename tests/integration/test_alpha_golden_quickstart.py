"""Installed-wheel, real-Checkov golden adoption path for the public alpha."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[2]
VERSION = "0.1.0a1"


def _run(
    argv: list[str | Path], *, cwd: Path, environment: dict[str, str], timeout: int = 600,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(item) for item in argv], cwd=cwd, env=environment,
        capture_output=True, text=True, check=False, timeout=timeout,
    )


def _semantic_execution_view(payload: dict) -> dict:
    """Exclude only exact per-process provenance from cross-run comparison.

    Raw stdout/result hashes and measured duration must remain in report-v1. Checkov
    emits a fresh private output path on each execution, so those exact byte identities
    are intentionally run-specific even when its canonical semantic result is stable.
    """
    result = copy.deepcopy(payload)
    for name in ("baseline_run", "candidate_run"):
        run = result["verification"][name]
        for field in ("duration_ms", "raw_output_sha256", "stdout_sha256"):
            run.pop(field)
    return result


def test_installed_wheel_real_checkov_golden_path(tmp_path: Path) -> None:
    external = tmp_path / "outside-source-checkout"
    external.mkdir()
    environment_root = external / ".venv-iac-guard"
    scanner_root = external / ".venv-checkov330"
    for root in (environment_root, scanner_root):
        created = _run(
            [sys.executable, "-m", "venv", "--copies", "--without-pip", root],
            cwd=external, environment=os.environ.copy(),
        )
        assert created.returncode == 0, created.stderr
    binary_dir = environment_root / ("Scripts" if os.name == "nt" else "bin")
    scanner_binary_dir = scanner_root / ("Scripts" if os.name == "nt" else "bin")
    python = binary_dir / ("python.exe" if os.name == "nt" else "python")
    scanner_python = scanner_binary_dir / ("python.exe" if os.name == "nt" else "python")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    build = _run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", artifacts],
        cwd=ROOT, environment={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert build.returncode == 0, build.stderr
    wheel = next(artifacts.glob(f"iac_guard_v-{VERSION}-py3-none-any.whl"))
    product_install = _run(
        [
            sys.executable, "-m", "pip", "--python", python,
            "install", "--no-compile", wheel,
        ],
        cwd=external, environment=os.environ.copy(),
    )
    assert product_install.returncode == 0, product_install.stderr
    scanner_install = _run(
        [
            sys.executable, "-m", "pip", "--python", scanner_python,
            "install", "--no-compile", "checkov==3.3.0",
        ],
        cwd=external, environment=os.environ.copy(),
    )
    assert scanner_install.returncode == 0, scanner_install.stderr

    baseline = external / "baseline"
    candidate = external / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    shutil.copyfile(ROOT / "examples/checkov-before-after/before.tf", baseline / "main.tf")
    shutil.copyfile(ROOT / "examples/checkov-before-after/after.tf", candidate / "main.tf")
    home = external / "home"
    home.mkdir()
    environment = {
        key: value for key, value in os.environ.items()
        if key not in {
            "PYTHONPATH", "PYTHONHOME", "PYTHONDONTWRITEBYTECODE",
            "PYTHONNOUSERSITE", "VIRTUAL_ENV",
        }
    }
    environment.update({
        "HOME": str(home),
        "PATH": os.pathsep.join(
            (str(binary_dir), str(scanner_binary_dir), "/usr/bin", "/bin")
        ),
        "VIRTUAL_ENV": str(environment_root),
    })
    command = binary_dir / ("iac-guard.exe" if os.name == "nt" else "iac-guard")
    checkov = scanner_binary_dir / ("checkov.exe" if os.name == "nt" else "checkov")

    version = _run([command, "--version"], cwd=external, environment=environment)
    assert version.returncode == 0, version.stderr
    assert version.stdout.strip() == f"iac-guard {VERSION}"
    doctor = _run(
        [command, "doctor", "--mode", "local-trusted", "--format", "json"],
        cwd=external, environment=environment,
    )
    assert doctor.returncode == 0, doctor.stderr
    diagnosis = json.loads(doctor.stdout)
    assert diagnosis["checkov"]["status"] == "PASS"
    assert diagnosis["validator_registry"]["status"] == "PASS"
    assert diagnosis["hardened_container"]["status"] == "INCONCLUSIVE"
    reports: list[dict] = []
    report_paths: list[Path] = []
    console_outputs: list[str] = []
    for iteration in (1, 2):
        report_path = external / f"report-{iteration}.json"
        completed = _run(
            [
                command, "verify", "--before", baseline, "--after", candidate,
                "--target", "CKV_AWS_53=aws_s3_bucket_public_access_block.example",
                "--framework", "terraform", "--local-trusted",
                "--checkov-executable", checkov, "--format", "console",
                "--output", report_path,
            ],
            cwd=external, environment=environment,
        )
        assert completed.returncode == 0, completed.stderr
        assert "IaC-Guard-V: VERIFIED" in completed.stdout
        assert "CKV_AWS_53 aws_s3_bucket_public_access_block.example: FIXED" in completed.stdout
        assert "scanner integrity: PASS" in completed.stdout
        assert "regressions: none" in completed.stdout
        assert "policy: VERIFIED" in completed.stdout
        console_outputs.append(completed.stdout)
        validated = _run([
            python, "-c",
            "import json,sys; from iac_guard_v.report import validate_report_payload; "
            "validate_report_payload(json.load(open(sys.argv[1], encoding='utf-8')))",
            report_path,
        ], cwd=external, environment=environment)
        assert validated.returncode == 0, validated.stderr
        reports.append(json.loads(report_path.read_text(encoding="utf-8")))
        report_paths.append(report_path)

    for report in reports:
        assert report["verdict"] == "VERIFIED"
        assert report["exit_code"] == 0
        assert report["execution_isolation"]["mode"] == "reduced-isolation"
        binding = report["verification"]["targets"][0]["binding"]
        assert binding["identity"]["rule_id"] == "CKV_AWS_53"
        assert binding["file_path"] == "main.tf"
        assert binding["scanner_native_lookup"] == (
            "aws_s3_bucket_public_access_block.example"
        )
        assert binding["identity"]["scope"] == (
            "aws_s3_bucket_public_access_block.example"
        )
        serialized = json.dumps(report, sort_keys=True)
        assert str(tmp_path) not in serialized
        assert str(environment_root) not in serialized
        assert str(scanner_root) not in serialized
        assert str(home) not in serialized

    assert _semantic_execution_view(reports[0]) == _semantic_execution_view(reports[1])
    assert console_outputs[0] == console_outputs[1]

    doctor_again = _run(
        [command, "doctor", "--mode", "local-trusted", "--format", "json"],
        cwd=external, environment=environment,
    )
    assert doctor_again.returncode == 0, doctor_again.stderr

    rendered = [
        _run(
            [command, "explain", path, "--format", "markdown"],
            cwd=external, environment=environment,
        )
        for path in report_paths
    ]
    assert all(item.returncode == 0 for item in rendered)
    assert rendered[0].stdout == rendered[1].stdout
    assert "VERIFIED" in rendered[0].stdout
    assert not tuple(environment_root.rglob("__pycache__"))
    assert not tuple(scanner_root.rglob("__pycache__"))
