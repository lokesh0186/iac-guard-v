"""Installed-wheel, real-Checkov golden adoption path for the public alpha."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).parents[2]
VERSION = "0.1.0a8"


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
    acceptance_started = time.monotonic()
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
    pip_upgrade = _run(
        [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
        cwd=external, environment=os.environ.copy(),
    )
    assert pip_upgrade.returncode == 0, pip_upgrade.stderr
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
    with zipfile.ZipFile(wheel) as archive:
        (baseline / "main.tf").write_bytes(archive.read(
            "iac_guard_v/examples/checkov-before-after/before.tf"
        ))
        (candidate / "main.tf").write_bytes(archive.read(
            "iac_guard_v/examples/checkov-before-after/after.tf"
        ))
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
        "PATH": os.pathsep.join((str(binary_dir), "/usr/bin", "/bin")),
        "VIRTUAL_ENV": str(environment_root),
    })
    command = binary_dir / ("iac-guard.exe" if os.name == "nt" else "iac-guard")
    checkov = scanner_binary_dir / ("checkov.exe" if os.name == "nt" else "checkov")
    run_directory = external / "empty-run-directory"
    run_directory.mkdir()
    assert tuple(run_directory.iterdir()) == ()

    version = _run([command, "--version"], cwd=run_directory, environment=environment)
    assert version.returncode == 0, version.stderr
    assert version.stdout.strip() == f"iac-guard {VERSION}"
    doctor = _run(
        [
            command, "doctor", "--mode", "local-trusted",
            "--checkov-executable", checkov, "--format", "json",
        ],
        cwd=run_directory, environment=environment,
    )
    assert doctor.returncode == 0, doctor.stdout + doctor.stderr
    diagnosis = json.loads(doctor.stdout)
    assert diagnosis["checkov"]["status"] == "PASS"
    assert diagnosis["validator_registry"]["status"] == "PASS"
    assert diagnosis["hardened_container"]["status"] == "INCONCLUSIVE"

    demo_reports: list[dict] = []
    first_verified_seconds = 0.0
    for iteration in (1, 2):
        demo_path = run_directory / f"installed-demo-{iteration}.json"
        demo = _run(
            [
                command, "demo", "--real", "--local-trusted",
                "--checkov-executable", checkov, "--format", "console",
                "--output", demo_path,
            ],
            cwd=run_directory, environment=environment,
        )
        assert demo.returncode == 0, demo.stderr
        assert "IaC-Guard-V: VERIFIED" in demo.stdout
        assert "CKV_AWS_53 aws_s3_bucket_public_access_block.example: FIXED" in demo.stdout
        validated = _run([
            python, "-c",
            "import json,sys; from iac_guard_v.report import validate_report_payload; "
            "validate_report_payload(json.load(open(sys.argv[1], encoding='utf-8')))",
            demo_path,
        ], cwd=run_directory, environment=environment)
        assert validated.returncode == 0, validated.stderr
        payload = json.loads(demo_path.read_text(encoding="utf-8"))
        assert payload["verdict"] == "VERIFIED"
        assert payload["exit_code"] == 0
        assert payload["execution_isolation"]["mode"] == "reduced-isolation"
        serialized = json.dumps(payload, sort_keys=True)
        assert str(tmp_path) not in serialized
        assert str(environment_root) not in serialized
        assert str(scanner_root) not in serialized
        demo_reports.append(payload)
        if iteration == 1:
            first_verified_seconds = time.monotonic() - acceptance_started
    assert _semantic_execution_view(demo_reports[0]) == _semantic_execution_view(
        demo_reports[1]
    )

    reports: list[dict] = []
    report_paths: list[Path] = []
    console_outputs: list[str] = []
    for iteration in (1, 2):
        report_path = external / f"report-{iteration}.json"
        completed = _run(
            [
                command, "verify", "--before", baseline, "--after", candidate,
                "--all-baseline-findings",
                "--framework", "terraform", "--local-trusted",
                "--checkov-executable", checkov, "--format", "console",
                "--output", report_path,
            ],
            cwd=run_directory, environment=environment,
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
        ], cwd=run_directory, environment=environment)
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
        [
            command, "doctor", "--mode", "local-trusted",
            "--checkov-executable", checkov, "--format", "json",
        ],
        cwd=run_directory, environment=environment,
    )
    assert doctor_again.returncode == 0, doctor_again.stderr

    rendered = [
        _run(
            [command, "explain", path, "--format", "markdown"],
            cwd=run_directory, environment=environment,
        )
        for path in report_paths
    ]
    assert all(item.returncode == 0 for item in rendered)
    assert rendered[0].stdout == rendered[1].stdout
    assert "VERIFIED" in rendered[0].stdout

    repository = external / "repository"
    repository.mkdir()
    shutil.copyfile(baseline / "main.tf", repository / "main.tf")
    git = shutil.which("git")
    assert git is not None
    git_environment = os.environ.copy()
    for arguments in (
        ("init", "-q"),
        ("config", "user.name", "IaC-Guard-V alpha test"),
        ("config", "user.email", "alpha@example.invalid"),
        ("add", "main.tf"),
        ("commit", "-q", "-m", "baseline"),
    ):
        completed = _run([git, *arguments], cwd=repository, environment=git_environment)
        assert completed.returncode == 0, completed.stderr
    base = _run([git, "rev-parse", "HEAD"], cwd=repository, environment=git_environment)
    assert base.returncode == 0, base.stderr
    base_commit = base.stdout.strip()
    shutil.copyfile(candidate / "main.tf", repository / "main.tf")
    for arguments in (
        ("add", "main.tf"),
        ("commit", "-q", "-m", "candidate"),
        ("update-ref", "refs/remotes/origin/main", base_commit),
    ):
        completed = _run([git, *arguments], cwd=repository, environment=git_environment)
        assert completed.returncode == 0, completed.stderr
    head_before = _run(
        [git, "rev-parse", "HEAD"], cwd=repository, environment=git_environment,
    ).stdout.strip()
    status_before = _run(
        [git, "status", "--porcelain=v1", "-uall"],
        cwd=repository, environment=git_environment,
    ).stdout
    sarif_path = external / "iac-guard.sarif"
    pr = _run(
        [
            command, "pr", "--repository", repository,
            "--base-ref", "origin/main", "--head-ref", "HEAD",
            "--all-baseline-findings", "--changed-only",
            "--framework", "terraform", "--local-trusted",
            "--checkov-executable", checkov, "--format", "sarif",
            "--output", sarif_path,
        ],
        cwd=run_directory, environment=environment,
    )
    assert pr.returncode == 0, pr.stderr
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert any(
        result["ruleId"] == "checkov:CKV_AWS_53"
        for run in sarif["runs"] for result in run["results"]
    )
    assert str(tmp_path) not in json.dumps(sarif, sort_keys=True)
    assert _run(
        [git, "rev-parse", "HEAD"], cwd=repository, environment=git_environment,
    ).stdout.strip() == head_before
    assert _run(
        [git, "status", "--porcelain=v1", "-uall"],
        cwd=repository, environment=git_environment,
    ).stdout == status_before
    assert not tuple(environment_root.rglob("__pycache__"))
    assert not tuple(scanner_root.rglob("__pycache__"))
    full_acceptance_seconds = time.monotonic() - acceptance_started
    print(f"TIME_TO_FIRST_VERIFIED_SECONDS={first_verified_seconds:.2f}")
    print(f"FULL_GOLDEN_ACCEPTANCE_SECONDS={full_acceptance_seconds:.2f}")
