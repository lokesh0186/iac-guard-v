"""Integrity and lifecycle support for repository-owned test environments.

This module intentionally uses only the Python standard library.  It manages
developer caches, not product verification evidence.  Release proof remains
fresh and disposable.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence


SCHEMA = "iacgv-test-env-v1"
RESULT_SCHEMA = "iacgv-test-run-v1"
NOX_VERSION = "2026.8.17"
CHECKOV_VERSION = "3.3.0"
COMPAT_INSTALL_CONTRACT = "pip-no-compile-editable-copies-v1"
SCANNER_INSTALL_CONTRACT = "pip-no-compile-checkov-copies-v1"
METADATA_NAME = ".iacgv-test-env.json"
RELEASE_MARKER_NAME = ".iacgv-fresh-release-run.json"
ENVIRONMENT_FLAGS = {
    "no_compile": True,
    "pythondontwritebytecode": True,
    "venv_backend": "venv",
    "venv_copies": True,
}


class HarnessError(RuntimeError):
    """Typed operator-facing test-harness failure."""


@dataclass(frozen=True, slots=True)
class EnvironmentState:
    expected: Mapping[str, object]
    metadata_path: Path
    needs_install: bool


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise HarnessError(f"TEST_ENVIRONMENT_INTEGRITY_FAILED: unsafe input {path.name}")
    return sha256_bytes(path.read_bytes())


def _run(
    argv: Sequence[str | os.PathLike[str]], *, cwd: Path, env: Mapping[str, str] | None = None,
    timeout: int = 600, capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    command = [os.fspath(item) for item in argv]
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        text=True,
        capture_output=capture,
        timeout=timeout,
        check=False,
    )
    return completed


def sensitive_environment_name(name: str) -> bool:
    upper = name.upper()
    return (
        upper in {
            "ALL_PROXY", "DOCKER_AUTH_CONFIG", "GH_CONFIG_DIR", "GH_TOKEN",
            "GITHUB_TOKEN", "HF_TOKEN", "HTTP_PROXY", "HTTPS_PROXY", "KUBECONFIG",
            "NETRC", "NO_PROXY", "SSH_AUTH_SOCK",
        }
        or upper.startswith(("PIP_", "UV_"))
        or upper.endswith(("_API_KEY", "_PASSWORD", "_SECRET", "_TOKEN"))
    )


def _safe_environment(
    extra: Mapping[str, str] | None = None, *, allow_package_credentials: bool = False,
) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"}
        and (allow_package_credentials or not sensitive_environment_name(key))
    }
    environment.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    })
    if extra:
        environment.update(extra)
    return environment


def _protected_executable_path(path: Path) -> dict[str, str]:
    resolved = path.resolve(strict=True)
    home = Path.home().resolve()
    try:
        resolved.relative_to(home)
    except ValueError:
        rendered = str(resolved)
        kind = "system"
    else:
        rendered = f"home-relative:{resolved.name}"
        kind = "redacted-home"
    return {
        "kind": kind,
        "display": rendered,
        "path_sha256": sha256_bytes(str(resolved).encode()),
        "file_sha256": sha256_file(resolved),
    }


def _protected_directory_path(path: str) -> dict[str, str]:
    resolved = Path(path).resolve(strict=True)
    home = Path.home().resolve()
    root = repository_root()
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        try:
            resolved.relative_to(home)
        except ValueError:
            display = str(resolved)
            kind = "system"
        else:
            display = f"home-relative:{resolved.name}"
            kind = "redacted-home"
    else:
        display = f"repository-relative:{relative.as_posix()}"
        kind = "repository"
    return {
        "kind": kind,
        "display": display,
        "path_sha256": sha256_bytes(str(resolved).encode()),
    }


def python_identity(python: Path, *, root: Path | None = None) -> dict[str, object]:
    python = python.resolve(strict=True)
    script = (
        "import json,platform,sys;"
        "print(json.dumps({'implementation':platform.python_implementation(),"
        "'version':platform.python_version(),'machine':platform.machine(),"
        "'platform':sys.platform,'prefix':sys.prefix,'base_prefix':sys.base_prefix}))"
    )
    completed = _run(
        [python, "-I", "-c", script],
        cwd=(root or repository_root()),
        env=_safe_environment(),
        timeout=30,
    )
    if completed.returncode:
        raise HarnessError("TEST_ENVIRONMENT_INTEGRITY_FAILED: Python identity probe failed")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise HarnessError("TEST_ENVIRONMENT_INTEGRITY_FAILED: malformed Python identity") from exc
    result["executable"] = _protected_executable_path(python)
    result["prefix"] = _protected_directory_path(str(result["prefix"]))
    result["base_prefix"] = _protected_directory_path(str(result["base_prefix"]))
    return result


def _dependency_inputs(root: Path, kind: str) -> dict[str, str]:
    paths = [root / "pyproject.toml", root / "tools/testing/requirements-nox.txt"]
    if kind == "checkov":
        paths.append(root / "tools/testing/requirements-checkov-3.3.0.txt")
    return {path.relative_to(root).as_posix(): sha256_file(path) for path in paths}


def expected_environment(
    *, root: Path, python: Path, kind: str, session_name: str,
) -> dict[str, object]:
    if kind not in {"compat", "checkov"}:
        raise HarnessError("TEST_ENVIRONMENT_INTEGRITY_FAILED: unsupported environment kind")
    identity = python_identity(python, root=root)
    host_architecture = platform.machine()
    if identity.get("machine") != host_architecture:
        raise HarnessError(
            "PYTHON_ARCHITECTURE_MISMATCH: interpreter architecture "
            + str(identity.get("machine")) + " does not match host " + host_architecture
        )
    expected_minor = (
        session_name.removeprefix("tests-")
        if session_name.startswith("tests-")
        else "3.12" if kind == "checkov" else ""
    )
    if expected_minor and not str(identity["version"]).startswith(expected_minor + "."):
        raise HarnessError(
            "PYTHON_INTERPRETER_MISSING: session " + session_name
            + " resolved Python " + str(identity["version"])
        )
    payload: dict[str, object] = {
        "schema": SCHEMA,
        "kind": kind,
        "session": session_name,
        "python": identity,
        "architecture": host_architecture,
        "platform": sys.platform,
        "dependency_inputs": _dependency_inputs(root, kind),
        "nox_version": NOX_VERSION,
        "installer": "pip",
        "install_contract": (
            COMPAT_INSTALL_CONTRACT if kind == "compat" else SCANNER_INSTALL_CONTRACT
        ),
        **ENVIRONMENT_FLAGS,
    }
    if kind == "checkov":
        payload["scanner"] = {"name": "checkov", "version": CHECKOV_VERSION}
    payload["environment_fingerprint"] = sha256_bytes(canonical_json(payload))
    return payload


def _metadata_payload(expected: Mapping[str, object], **extra: object) -> dict[str, object]:
    return {
        **expected,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        **extra,
    }


def write_metadata(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".iacgv-metadata-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            Path(temporary).unlink()


def read_metadata(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise HarnessError("TEST_ENVIRONMENT_MISSING: environment metadata is unavailable")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HarnessError("TEST_ENVIRONMENT_INTEGRITY_FAILED: metadata is malformed") from exc
    if type(value) is not dict:
        raise HarnessError("TEST_ENVIRONMENT_INTEGRITY_FAILED: metadata must be an object")
    return value


def _assert_metadata(expected: Mapping[str, object], actual: Mapping[str, object]) -> None:
    expected_fingerprint = expected["environment_fingerprint"]
    if actual.get("schema") != SCHEMA or actual.get("environment_fingerprint") != expected_fingerprint:
        raise HarnessError(
            "TEST_ENVIRONMENT_STALE: fingerprint changed; run "
            "`nox -s clean_test_envs` and retry"
        )


def _environment_python(environment_root: Path) -> Path:
    candidate = environment_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not candidate.is_file() or candidate.is_symlink():
        raise HarnessError("TEST_ENVIRONMENT_MISSING: managed Python is unavailable")
    return candidate


def _site_packages(python: Path, root: Path) -> Path:
    completed = _run(
        [python, "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        cwd=root,
        env=_safe_environment(),
        timeout=30,
    )
    if completed.returncode:
        raise HarnessError("TEST_ENVIRONMENT_INTEGRITY_FAILED: site-packages probe failed")
    result = Path(completed.stdout.strip()).resolve(strict=True)
    return result


def _project_is_installed(python: Path, root: Path) -> bool:
    site_packages = _site_packages(python, root)
    return any(site_packages.glob("iac_guard_v-*.dist-info"))


def _assert_no_product_bytecode(root: Path, python: Path) -> None:
    locations = [root / "src/iac_guard_v"]
    site_packages = _site_packages(python, root)
    installed = site_packages / "iac_guard_v"
    if installed.exists():
        locations.append(installed)
    offenders: list[str] = []
    for location in locations:
        if not location.exists():
            continue
        for candidate in location.rglob("*"):
            if candidate.is_file() and (
                candidate.suffix.lower() in {".pyc", ".pyo"}
                or "__pycache__" in candidate.parts
            ):
                offenders.append(candidate.name)
                if len(offenders) == 5:
                    break
    if offenders:
        raise HarnessError(
            "TEST_ENVIRONMENT_INTEGRITY_FAILED: prohibited product bytecode detected "
            "before the test suite"
        )


def _pip_check(installer_python: Path, target_python: Path, root: Path) -> None:
    completed = _run(
        [installer_python, "-m", "pip", "--python", target_python, "check"],
        cwd=root,
        env=_safe_environment(),
        timeout=180,
    )
    if completed.returncode:
        raise HarnessError(
            "TEST_ENVIRONMENT_INTEGRITY_FAILED: pip check failed: "
            + (completed.stdout or completed.stderr).strip()[:500]
        )


def _assert_project_record(python: Path, root: Path) -> None:
    script = r'''
import base64
import hashlib
import importlib.metadata as metadata
import pathlib

distribution = metadata.distribution("iac-guard-v")
files = distribution.files
assert files, "distribution has no RECORD-backed files"
record_seen = False
for entry in files:
    relative = entry.as_posix()
    target = pathlib.Path(distribution.locate_file(entry))
    if relative.endswith(".dist-info/RECORD"):
        record_seen = True
        assert target.is_file() and not target.is_symlink()
        continue
    assert entry.hash is not None, f"unhashed RECORD entry: {relative}"
    assert target.is_file() and not target.is_symlink(), f"unsafe RECORD target: {relative}"
    data = target.read_bytes()
    assert entry.size == len(data), f"RECORD size mismatch: {relative}"
    digest = hashlib.new(entry.hash.mode, data).digest()
    observed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert observed == entry.hash.value, f"RECORD digest mismatch: {relative}"
assert record_seen, "distribution RECORD is unavailable"
'''
    completed = _run(
        [python, "-I", "-c", script], cwd=root, env=_safe_environment(), timeout=60,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip().splitlines()[-1:]
        raise HarnessError(
            "TEST_ENVIRONMENT_INTEGRITY_FAILED: project RECORD verification failed"
            + (": " + detail[0][:300] if detail else "")
        )


def inspect_compat_environment(
    *, root: Path, environment_root: Path, session_name: str,
) -> EnvironmentState:
    python = _environment_python(environment_root)
    expected = expected_environment(
        root=root, python=python, kind="compat", session_name=session_name,
    )
    metadata_path = environment_root / METADATA_NAME
    if not metadata_path.exists():
        if _project_is_installed(python, root):
            raise HarnessError(
                "TEST_ENVIRONMENT_STALE: installed environment lacks governed metadata; "
                "run `nox -s clean_test_envs` and retry"
            )
        return EnvironmentState(expected, metadata_path, True)
    _assert_metadata(expected, read_metadata(metadata_path))
    return EnvironmentState(expected, metadata_path, False)


def seal_compat_environment(
    *, root: Path, environment_root: Path, session_name: str,
) -> dict[str, object]:
    python = _environment_python(environment_root)
    expected = expected_environment(
        root=root, python=python, kind="compat", session_name=session_name,
    )
    payload = _metadata_payload(expected)
    write_metadata(environment_root / METADATA_NAME, payload)
    return payload


def preflight_compat_environment(
    *, root: Path, environment_root: Path, session_name: str,
    installer_python: Path,
) -> dict[str, object]:
    python = _environment_python(environment_root)
    expected = expected_environment(
        root=root, python=python, kind="compat", session_name=session_name,
    )
    actual = read_metadata(environment_root / METADATA_NAME)
    _assert_metadata(expected, actual)
    _assert_no_product_bytecode(root, python)
    _pip_check(installer_python, python, root)
    _assert_project_record(python, root)
    completed = _run(
        [python, "-I", "-c", (
            "import importlib.metadata as m;"
            "assert m.version('iac-guard-v'); print('PASS')"
        )],
        cwd=root,
        env=_safe_environment(),
        timeout=30,
    )
    if completed.returncode:
        raise HarnessError("TEST_ENVIRONMENT_INTEGRITY_FAILED: editable product is unavailable")
    return actual


def _managed_roots(root: Path) -> tuple[Path, ...]:
    repository = root.resolve(strict=True)
    return tuple(repository / name for name in (".nox", ".testenvs", ".test-results"))


def _absolute_without_symlink_resolution(path: Path) -> Path:
    """Normalize lexical components without following a potentially hostile symlink."""
    return Path(os.path.abspath(os.fspath(path)))


def _assert_no_symlink_components(base: Path, target: Path) -> None:
    current = base
    if current.is_symlink():
        raise HarnessError("UNSAFE_CLEANUP_REFUSED: managed root is a symlink")
    for component in target.relative_to(base).parts:
        current /= component
        if current.is_symlink():
            raise HarnessError("UNSAFE_CLEANUP_REFUSED: managed path contains a symlink")


def assert_managed_path(root: Path, target: Path) -> Path:
    root = root.resolve(strict=True)
    resolved = _absolute_without_symlink_resolution(target)
    forbidden = {Path("/").resolve(), Path.home().resolve(), root, root.parent}
    if resolved in forbidden:
        raise HarnessError("UNSAFE_CLEANUP_REFUSED: target is not a managed cache")
    for managed_root in _managed_roots(root):
        if resolved == managed_root:
            _assert_no_symlink_components(managed_root, resolved)
            return resolved
        try:
            resolved.relative_to(managed_root)
        except ValueError:
            continue
        _assert_no_symlink_components(managed_root, resolved)
        return resolved
    raise HarnessError("UNSAFE_CLEANUP_REFUSED: target is outside managed cache roots")


def clean_managed_path(root: Path, target: Path) -> None:
    resolved = assert_managed_path(root, target)
    if not resolved.exists():
        return
    if resolved.is_symlink():
        raise HarnessError("UNSAFE_CLEANUP_REFUSED: managed target is a symlink")
    if resolved.is_dir():
        shutil.rmtree(resolved)
    else:
        resolved.unlink()


def clean_all(root: Path) -> tuple[str, ...]:
    removed: list[str] = []
    for managed in _managed_roots(root):
        if managed.exists() or managed.is_symlink():
            clean_managed_path(root, managed)
            removed.append(managed.name)
    for candidate in root.glob(".coverage*"):
        if candidate.is_file() and not candidate.is_symlink():
            candidate.unlink()
            removed.append(candidate.name)
    return tuple(sorted(removed))


@contextlib.contextmanager
def _scanner_lock(root: Path) -> Iterator[None]:
    lock_root = root / ".testenvs/.locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    lock_path = lock_root / "checkov-3.3.0.lock"
    with lock_path.open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _checkov_doctor(root: Path, scanner_python: Path, executable: Path) -> dict[str, object]:
    code = (
        "import json; from pathlib import Path; from iac_guard_v.cli import doctor;"
        "print(doctor('local-trusted', Path(" + repr(str(executable)) + ")).canonical_json(), end='')"
    )
    completed = _run(
        [scanner_python, "-c", code],
        cwd=root,
        env=_safe_environment({"PYTHONPATH": str(root / "src")}),
        timeout=300,
    )
    if completed.returncode:
        raise HarnessError(
            "CHECKOV_ENVIRONMENT_INTEGRITY_FAILED: doctor failed: "
            + (completed.stdout or completed.stderr).strip()[:500]
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise HarnessError("CHECKOV_ENVIRONMENT_INTEGRITY_FAILED: malformed doctor result") from exc
    if report.get("checkov", {}).get("status") != "PASS":
        reason = report.get("checkov", {}).get("reason_code", "UNKNOWN")
        raise HarnessError(f"CHECKOV_ENVIRONMENT_INTEGRITY_FAILED: {reason}")
    return report["checkov"]


def _build_checkov_environment(
    *, root: Path, environment_root: Path, python: Path, installer_python: Path,
) -> dict[str, object]:
    environment_root.parent.mkdir(parents=True, exist_ok=True)
    created = _run(
        [python, "-m", "venv", "--copies", "--without-pip", environment_root],
        cwd=root,
        env=_safe_environment(),
        timeout=180,
    )
    if created.returncode:
        raise HarnessError("CHECKOV_ENVIRONMENT_INTEGRITY_FAILED: venv creation failed")
    scanner_python = _environment_python(environment_root)
    installed = _run(
        [
            installer_python, "-m", "pip", "--python", scanner_python,
            "install", "--disable-pip-version-check", "--no-compile", "-r",
            root / "tools/testing/requirements-checkov-3.3.0.txt",
        ],
        cwd=root,
        env=_safe_environment(allow_package_credentials=True),
        timeout=1800,
        capture=False,
    )
    if installed.returncode:
        raise HarnessError("CHECKOV_ENVIRONMENT_INTEGRITY_FAILED: installation failed")
    _pip_check(installer_python, scanner_python, root)
    executable = environment_root / ("Scripts/checkov.exe" if os.name == "nt" else "bin/checkov")
    checkov = _checkov_doctor(root, scanner_python, executable)
    expected = expected_environment(
        root=root, python=scanner_python, kind="checkov",
        session_name="checkov-3.3.0-py312",
    )
    payload = _metadata_payload(
        expected,
        scanner_identity={
            "launcher_sha256": sha256_file(executable),
            "scanner_environment_digest": checkov["scanner_environment_digest"],
            "installed_distribution_digest": checkov["installed_distribution_digest"],
            "dependency_lock_digest": checkov["dependency_lock_digest"],
        },
    )
    write_metadata(environment_root / METADATA_NAME, payload)
    return payload


def preflight_checkov_environment(
    *, root: Path, environment_root: Path, installer_python: Path,
) -> dict[str, object]:
    scanner_python = _environment_python(environment_root)
    expected = expected_environment(
        root=root, python=scanner_python, kind="checkov",
        session_name="checkov-3.3.0-py312",
    )
    actual = read_metadata(environment_root / METADATA_NAME)
    _assert_metadata(expected, actual)
    _pip_check(installer_python, scanner_python, root)
    executable = environment_root / ("Scripts/checkov.exe" if os.name == "nt" else "bin/checkov")
    checkov = _checkov_doctor(root, scanner_python, executable)
    recorded = actual.get("scanner_identity", {})
    observed = {
        "launcher_sha256": sha256_file(executable),
        "scanner_environment_digest": checkov["scanner_environment_digest"],
        "installed_distribution_digest": checkov["installed_distribution_digest"],
        "dependency_lock_digest": checkov["dependency_lock_digest"],
    }
    if recorded != observed:
        raise HarnessError("CHECKOV_ENVIRONMENT_INTEGRITY_FAILED: scanner identity changed")
    return actual


def ensure_checkov_environment(
    *, root: Path, python: Path, installer_python: Path,
) -> tuple[Path, dict[str, object], bool]:
    environment_root = root / ".testenvs/scanners/checkov-3.3.0-py312"
    with _scanner_lock(root):
        reused = False
        if environment_root.exists():
            try:
                metadata = preflight_checkov_environment(
                    root=root, environment_root=environment_root,
                    installer_python=installer_python,
                )
                reused = True
                return environment_root, metadata, reused
            except HarnessError as exc:
                print(f"REBUILD_MANAGED_TEST_ENVIRONMENT: {exc}", file=sys.stderr)
                clean_managed_path(root, environment_root)
        metadata = _build_checkov_environment(
            root=root,
            environment_root=environment_root,
            python=python,
            installer_python=installer_python,
        )
        preflight_checkov_environment(
            root=root, environment_root=environment_root,
            installer_python=installer_python,
        )
        return environment_root, metadata, reused


def claim_fresh_release_environment(
    environment_root: Path, *, nox_reused: bool = False,
) -> Path:
    if nox_reused:
        raise HarnessError(
            "RELEASE_REUSE_FORBIDDEN: Nox reports that the release environment was reused"
        )
    marker = environment_root / RELEASE_MARKER_NAME
    if marker.exists():
        raise HarnessError(
            "RELEASE_REUSE_FORBIDDEN: release session reused an existing environment"
        )
    write_metadata(marker, {
        "schema": "iacgv-fresh-release-run-v1",
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    return marker


def _doctor(root: Path) -> int:
    rows = []
    for executable in ("python3.10", "python3.11", "python3.12", "python3.13"):
        found = shutil.which(executable)
        if found is None:
            rows.append({"name": executable, "status": "MISSING"})
            continue
        identity = python_identity(Path(found), root=root)
        rows.append({"name": executable, "status": "PASS", "identity": identity})
    print(json.dumps({
        "schema": "iacgv-test-doctor-v1",
        "nox_required": NOX_VERSION,
        "host_architecture": platform.machine(),
        "interpreters": rows,
        "managed_roots": [path.name for path in _managed_roots(root)],
    }, sort_keys=True, indent=2))
    return 0 if all(row["status"] == "PASS" for row in rows) else 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IaC-Guard-V local test-environment manager")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("doctor")
    subcommands.add_parser("clean")
    args = parser.parse_args(argv)
    root = repository_root()
    try:
        if args.command == "doctor":
            return _doctor(root)
        removed = clean_all(root)
        print("CLEANED_TEST_CACHES: " + (", ".join(removed) if removed else "none"))
        return 0
    except (HarnessError, OSError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
