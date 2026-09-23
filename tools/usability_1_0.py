#!/usr/bin/env python3
"""Source-independent 1.0 wheel usability gate."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(
    arguments: list[str], *, cwd: Path, environment: dict[str, str], expected: int
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=240,
    )
    if completed.returncode != expected:
        raise RuntimeError(
            f"unexpected exit {completed.returncode}, expected {expected}: "
            f"{' '.join(arguments)}\n{completed.stdout}\n{completed.stderr}"
        )
    return completed


def run_usability(wheel: Path) -> dict[str, object]:
    started = time.monotonic()
    if not wheel.is_file() or wheel.name != "iac_guard_v-1.0.0-py3-none-any.whl":
        raise RuntimeError("expected the exact 1.0.0 candidate wheel")
    records: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="iacgv-1.0-clean-user-") as temporary:
        root = Path(temporary)
        environment_root = root / "venv"
        subprocess.run(
            ["python3.12", "-m", "venv", "--copies", str(environment_root)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        binary = environment_root / "bin"
        python = binary / "python"
        executable = binary / "iac-guard"
        environment = {
            "HOME": str(root / "home"),
            "PATH": os.pathsep.join((str(binary), "/usr/bin", "/bin")),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }
        Path(environment["HOME"]).mkdir()
        install = _run(
            [str(python), "-m", "pip", "install", "--no-compile", str(wheel)],
            cwd=root,
            environment=environment,
            expected=0,
        )
        records.append({"step": "install_candidate_wheel", "result": "PASS"})
        version = _run([str(executable), "--version"], cwd=root, environment=environment, expected=0)
        if version.stdout.strip() != "iac-guard 1.0.0":
            raise RuntimeError("installed command reported the wrong version")
        doctor = _run(
            [str(executable), "doctor", "--mode", "native", "--format", "json"],
            cwd=root,
            environment=environment,
            expected=0,
        )
        doctor_payload = json.loads(doctor.stdout)
        if doctor_payload.get("overall_status") != "PASS":
            raise RuntimeError("native doctor did not report PASS")
        records.append({"step": "native_doctor", "result": "PASS"})

        examples = root / "examples"
        shutil.copytree(ROOT / "examples/quickstart", examples)
        cases = (
            ("kubernetes_satisfied", examples / "kubernetes/satisfied/native-request.json", 0, "SATISFIED"),
            ("kubernetes_violated", examples / "kubernetes/violated/native-request.json", 1, "VIOLATED"),
            ("kubernetes_not_evaluated", examples / "kubernetes/not-evaluated/native-request.json", 3, "NOT_EVALUATED"),
            ("terraform_satisfied", examples / "terraform/native-request.json", 0, "SATISFIED"),
        )
        for name, config, expected_exit, expected_result in cases:
            report = root / f"{name}.json"
            _run(
                [
                    str(python), "-m", "iac_guard_v.native_properties",
                    "--config", str(config), "--format", "json",
                    "--output", str(report), "--quiet",
                ],
                cwd=root,
                environment=environment,
                expected=expected_exit,
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            observation = payload["observations"][0]
            if observation["result"] != expected_result:
                raise RuntimeError(f"{name} produced {observation['result']}")
            for field in ("reason_code", "witness", "definition", "request"):
                if field not in observation:
                    raise RuntimeError(f"{name} report lacks understandable field {field}")
            if not payload.get("product_semantics"):
                raise RuntimeError(f"{name} report does not explain its semantic boundary")
            records.append({
                "step": name,
                "result": expected_result,
                "exit_code": expected_exit,
                "reason_code": observation["reason_code"],
            })
        if tuple(environment_root.rglob("iac_guard_v-work")):
            raise RuntimeError("source checkout leaked into the installed environment")
        if "Successfully installed" not in install.stdout:
            records.append({"step": "pip_output", "result": "PASS_WITH_CACHED_OUTPUT_VARIANT"})

    duration = time.monotonic() - started
    if duration > 900:
        raise RuntimeError(f"clean-user workflow exceeded 15 minutes: {duration:.2f}s")
    return {
        "schema": "iac-guard-v-clean-user-usability-v1",
        "status": "PASS",
        "source_independent_product_install": True,
        "candidate_wheel": wheel.name,
        "duration_seconds": round(duration, 3),
        "target_seconds": 900,
        "steps": records,
        "documentation_defects": [],
        "installation_friction": [],
        "terminology_ambiguity": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    result = run_usability(arguments.wheel.resolve())
    arguments.output.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
