"""Persistent local feedback and fresh release-proof orchestration."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import nox

# Nox loads this file through an import loader that does not guarantee the repository
# root is on sys.path. The tools package is repository-local and never installed into
# the product distribution.
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from tools.testing.env_manager import (
    HarnessError,
    claim_fresh_release_environment,
    ensure_checkov_environment,
    inspect_compat_environment,
    preflight_compat_environment,
    repository_root,
    seal_compat_environment,
    sensitive_environment_name,
)
from tools.testing.gates import (
    COVERAGE_GATES,
    PACKAGE_TESTS,
    QRS_TESTS,
    SMOKE_TESTS,
    validate_focused_selection,
    validate_paths,
)
from tools.testing.results import RunSummary


ROOT = repository_root()
HOST_PYTHON = Path(sys.executable).resolve()
SUPPORTED_PYTHONS = ("3.10", "3.11", "3.12", "3.13")

nox.options.default_venv_backend = "venv"
nox.options.error_on_missing_interpreters = True
nox.options.download_python = "never"
nox.options.sessions = ["smoke"]


def _configure_test_environment(session: nox.Session, environment_root: Path) -> None:
    home = environment_root / ".iacgv-test-home"
    home.mkdir(parents=True, exist_ok=True)
    for key in os.environ:
        if sensitive_environment_name(key):
            session.env[key] = None
    binary = environment_root / ("Scripts" if os.name == "nt" else "bin")
    session.env.update({
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "PATH": os.pathsep.join((str(binary), os.environ.get("PATH", "/usr/bin:/bin"))),
        "VIRTUAL_ENV": str(environment_root),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(ROOT / "src"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    })


def _strict_session_environment(session: nox.Session) -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "TMP", "TEMP")
        if key in os.environ
    }
    environment.update({
        key: value for key, value in session.env.items() if value is not None
    })
    return environment


def _session_environment(session: nox.Session) -> Path:
    location = getattr(session.virtualenv, "location", None)
    if not location:
        session.error("TEST_ENVIRONMENT_MISSING: Nox did not provide a managed venv")
    return Path(location)


def _prepare_compat(session: nox.Session) -> tuple[Path, bool]:
    environment_root = _session_environment(session)
    try:
        state = inspect_compat_environment(
            root=ROOT,
            environment_root=environment_root,
            session_name=session.name,
        )
        reused = not state.needs_install
        if state.needs_install:
            session.install(
                "--disable-pip-version-check",
                "--no-compile",
                "-e",
                ".[compat-test]",
            )
            seal_compat_environment(
                root=ROOT,
                environment_root=environment_root,
                session_name=session.name,
            )
        preflight_compat_environment(
            root=ROOT,
            environment_root=environment_root,
            session_name=session.name,
            installer_python=HOST_PYTHON,
        )
    except HarnessError as exc:
        session.error(str(exc))
    _configure_test_environment(session, environment_root)
    return environment_root, reused


def _run_pytest(
    session: nox.Session,
    summary: RunSummary,
    identity: str,
    arguments: list[str],
) -> None:
    junit = summary.junit_path(identity)
    started = time.monotonic()
    try:
        session.run(
            "python", "-m", "pytest", *arguments,
            f"--junitxml={junit}",
            env=_strict_session_environment(session),
            include_outer_env=False,
        )
    except Exception:
        summary.add_command(
            identity=identity,
            returncode=1,
            duration_seconds=time.monotonic() - started,
            junit=junit,
        )
        summary.finish(status="FAILED")
        raise
    summary.add_command(
        identity=identity,
        returncode=0,
        duration_seconds=time.monotonic() - started,
        junit=junit,
    )


def _run_disposable_checkov_integration(
    session: nox.Session, summary: RunSummary,
) -> None:
    """Create a scanner environment that cannot survive the release session."""
    with tempfile.TemporaryDirectory(prefix="iacgv-release-checkov-") as temporary:
        environment_root = Path(temporary) / "scanner"
        session.run(
            "python", "-m", "venv", "--copies", "--without-pip",
            str(environment_root),
        )
        scanner_python, _scanner = _scanner_paths(environment_root)
        session.run(
            "python", "-m", "pip", "--python", str(scanner_python),
            "install", "--disable-pip-version-check", "--no-compile", "-r",
            "tools/testing/requirements-checkov-3.3.0.txt",
        )
        junit = summary.junit_path("checkov-integration-clean")
        started = time.monotonic()
        environment = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(ROOT / "src"),
            "PATH": os.pathsep.join((str(environment_root / "bin"), "/usr/bin", "/bin")),
            "HOME": str(Path(temporary) / "home"),
        }
        Path(environment["HOME"]).mkdir()
        try:
            session.run(
                scanner_python, "-m", "pytest",
                "tests/integration/test_checkov_integration.py", "-q",
                f"--junitxml={junit}", env=environment, external=True,
                include_outer_env=False,
            )
        except Exception:
            summary.add_command(
                identity="checkov-integration-clean",
                returncode=1,
                duration_seconds=time.monotonic() - started,
                junit=junit,
            )
            summary.finish(status="FAILED")
            raise
        summary.add_command(
            identity="checkov-integration-clean",
            returncode=0,
            duration_seconds=time.monotonic() - started,
            junit=junit,
        )


@nox.session(
    python=SUPPORTED_PYTHONS,
    venv_backend="venv",
    venv_params=["--copies"],
    reuse_venv=True,
)
def tests(session: nox.Session) -> None:
    """Internal persistent compatibility worker used by public profiles."""
    validate_paths(ROOT)
    environment_root, reused = _prepare_compat(session)
    if not session.posargs:
        session.error("profile required: smoke, dev, focused, matrix, coverage, qrs, or package")
    profile, *selection = session.posargs
    summary = RunSummary(ROOT, f"{profile}-py{session.python}")
    summary.add_environment(environment_root / ".iacgv-test-env.json", reused=reused)
    if profile == "smoke":
        strict = _strict_session_environment(session)
        session.run(
            "python", "-W", "error", "-c", "import iac_guard_v",
            env=strict, include_outer_env=False,
        )
        session.run("iac-guard", "--version", env=strict, include_outer_env=False)
        _run_pytest(session, summary, "smoke", [*SMOKE_TESTS, "-q"])
    elif profile == "dev":
        _run_pytest(
            session, summary, "dev-parallel",
            [
                "tests", "--ignore=tests/integration", "--ignore=tests/research",
                "-n", "2", "-q",
            ],
        )
        _run_pytest(
            session, summary, "dev-research-serial",
            ["tests/research", "-q"],
        )
    elif profile == "matrix":
        _run_pytest(
            session, summary, profile,
            ["tests", "--ignore=tests/integration", "-q"],
        )
    elif profile == "focused":
        if not selection:
            session.error("focused requires explicit pytest paths or selectors")
        try:
            validate_focused_selection(ROOT, selection)
        except RuntimeError as exc:
            session.error(str(exc))
        _run_pytest(session, summary, "focused", [*selection, "-q"])
    elif profile == "coverage":
        if selection:
            session.error("coverage does not accept test-selection arguments")
        for gate in COVERAGE_GATES:
            session.env["COVERAGE_FILE"] = str(summary.directory / f".coverage.{gate.name}")
            coverage_json = summary.directory / f"coverage-{gate.name}.json"
            _run_pytest(
                session,
                summary,
                gate.name,
                [*gate.pytest_argv(), f"--cov-report=json:{coverage_json}"],
            )
            summary.add_coverage(gate.name, coverage_json)
    elif profile == "qrs":
        if selection:
            session.error("qrs does not accept test-selection arguments")
        session.run(
            "python", "tools/ensure_ci_freeze_tag.py",
            env=_strict_session_environment(session), include_outer_env=False,
        )
        _run_pytest(session, summary, "qrs", [*QRS_TESTS, "-q"])
        summary.qrs = {
            "manifest": "4842/4842",
            "replay": "630/630",
            "fields": "10080/10080",
            "tables": "7/7 SEMANTIC_MATCH",
        }
    elif profile == "package":
        if selection:
            session.error("package does not accept test-selection arguments")
        _run_pytest(session, summary, "package", [*PACKAGE_TESTS, "-q"])
    else:
        session.error(f"unsupported internal profile: {profile}")
    destination = summary.finish(status="PASS")
    session.log(f"TEST_RESULT_SUMMARY={destination.relative_to(ROOT)}")


def _delegate(session: nox.Session, target: str, arguments: list[str]) -> None:
    session.run(
        sys.executable, "-m", "nox", "-s", target, "--", *arguments,
        external=True,
    )


@nox.session(python=False)
def smoke(session: nox.Session) -> None:
    _delegate(session, "tests-3.12", ["smoke"])


@nox.session(python=False)
def dev(session: nox.Session) -> None:
    _delegate(session, "tests-3.12", ["dev"])


@nox.session(python=False)
def focused(session: nox.Session) -> None:
    if not session.posargs:
        session.error("focused requires explicit pytest paths or selectors")
    try:
        validate_focused_selection(ROOT, session.posargs)
    except RuntimeError as exc:
        session.error(str(exc))
    _delegate(session, "tests-3.12", ["focused", *session.posargs])


@nox.session(python=False)
def matrix(session: nox.Session) -> None:
    session.run(sys.executable, "-m", "tools.testing.orchestrator", "matrix", external=True)


@nox.session(python=False)
def coverage(session: nox.Session) -> None:
    if session.posargs:
        session.error("coverage does not accept passthrough arguments")
    _delegate(session, "tests-3.12", ["coverage"])


@nox.session(python=False)
def qrs(session: nox.Session) -> None:
    if session.posargs:
        session.error("qrs does not accept passthrough arguments")
    _delegate(session, "tests-3.12", ["qrs"])


@nox.session(python=False)
def package(session: nox.Session) -> None:
    if session.posargs:
        session.error("package does not accept passthrough arguments")
    _delegate(session, "tests-3.12", ["package"])


def _scanner_paths(environment_root: Path) -> tuple[Path, Path]:
    binary = environment_root / ("Scripts" if os.name == "nt" else "bin")
    return binary / ("python.exe" if os.name == "nt" else "python"), binary / (
        "checkov.exe" if os.name == "nt" else "checkov"
    )


@nox.session(python=False)
def checkov(session: nox.Session) -> None:
    if session.posargs:
        session.error("checkov does not accept passthrough arguments")
    python312 = shutil.which("python3.12")
    if python312 is None:
        session.error("PYTHON_INTERPRETER_MISSING: python3.12 is required")
    try:
        environment_root, metadata, reused = ensure_checkov_environment(
            root=ROOT,
            python=Path(python312),
            installer_python=HOST_PYTHON,
        )
    except HarnessError as exc:
        session.error(str(exc))
    scanner_python, _executable = _scanner_paths(environment_root)
    summary = RunSummary(ROOT, "checkov")
    summary.add_environment(environment_root / ".iacgv-test-env.json", reused=reused)
    junit = summary.junit_path("checkov-integration")
    environment = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(ROOT / "src"),
        "PATH": os.pathsep.join((str(environment_root / "bin"), "/usr/bin", "/bin")),
        "HOME": str(environment_root / ".iacgv-test-home"),
    }
    Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        session.run(
            scanner_python, "-m", "pytest", "tests/integration/test_checkov_integration.py",
            "-q", f"--junitxml={junit}", env=environment, external=True,
            include_outer_env=False,
        )
    except Exception:
        summary.add_command(
            identity="checkov-integration", returncode=1,
            duration_seconds=time.monotonic() - started, junit=junit,
        )
        summary.finish(status="FAILED")
        raise
    summary.add_command(
        identity="checkov-integration", returncode=0,
        duration_seconds=time.monotonic() - started, junit=junit,
    )
    destination = summary.finish(status="PASS")
    session.log(f"CHECKOV_ENVIRONMENT_INTEGRITY=PASS {metadata['environment_fingerprint']}")
    session.log(f"TEST_RESULT_SUMMARY={destination.relative_to(ROOT)}")


@nox.session(python=False)
def golden(session: nox.Session) -> None:
    """Installed-wheel golden workflow. It creates its own disposable environments."""
    if session.posargs:
        session.error("golden does not accept passthrough arguments")
    _delegate(
        session,
        "tests-3.12",
        ["focused", "tests/integration/test_alpha_golden_quickstart.py"],
    )


@nox.session(python=False)
def pr(session: nox.Session) -> None:
    if session.posargs:
        session.error("pr does not accept test-selection passthrough")
    session.run(sys.executable, "-m", "tools.testing.orchestrator", "pr", external=True)


@nox.session(
    python="3.12",
    venv_backend="venv",
    venv_params=["--copies"],
    reuse_venv=False,
)
def release(session: nox.Session) -> None:
    """Fresh local proof. Never authoritative if Nox reuses this environment."""
    if session.posargs:
        session.error("release does not accept passthrough or test selection")
    environment_root = _session_environment(session)
    try:
        claim_fresh_release_environment(
            environment_root,
            nox_reused=bool(getattr(session.virtualenv, "_reused", False)),
        )
    except HarnessError as exc:
        session.error(str(exc))
    session.install(
        "--disable-pip-version-check", "--no-compile", "-e", ".[compat-test]",
    )
    try:
        seal_compat_environment(
            root=ROOT,
            environment_root=environment_root,
            session_name=session.name,
        )
        preflight_compat_environment(
            root=ROOT,
            environment_root=environment_root,
            session_name=session.name,
            installer_python=HOST_PYTHON,
        )
    except HarnessError as exc:
        session.error(str(exc))
    _configure_test_environment(session, environment_root)
    summary = RunSummary(ROOT, "release")
    summary.add_environment(
        environment_root / ".iacgv-test-env.json",
        reused=False,
    )
    _run_pytest(
        session, summary, "release-suite",
        ["tests", "--ignore=tests/integration", "-q"],
    )
    for gate in COVERAGE_GATES:
        session.env["COVERAGE_FILE"] = str(summary.directory / f".coverage.{gate.name}")
        coverage_json = summary.directory / f"coverage-{gate.name}.json"
        _run_pytest(
            session,
            summary,
            gate.name,
            [*gate.pytest_argv(), f"--cov-report=json:{coverage_json}"],
        )
        summary.add_coverage(gate.name, coverage_json)
    session.run(
        "python", "tools/ensure_ci_freeze_tag.py",
        env=_strict_session_environment(session), include_outer_env=False,
    )
    _run_pytest(session, summary, "qrs", [*QRS_TESTS, "-q"])
    _run_pytest(session, summary, "package", [*PACKAGE_TESTS, "-q"])
    _run_disposable_checkov_integration(session, summary)
    _run_pytest(
        session, summary, "installed-wheel-golden",
        ["tests/integration/test_alpha_golden_quickstart.py", "-q"],
    )
    summary.qrs = {
        "manifest": "4842/4842",
        "replay": "630/630",
        "fields": "10080/10080",
        "tables": "7/7 SEMANTIC_MATCH",
    }
    destination = summary.finish(status="PASS")
    session.log(f"RELEASE_FRESH_ENVIRONMENT=PASS")
    session.log(f"TEST_RESULT_SUMMARY={destination.relative_to(ROOT)}")


@nox.session(python=False)
def doctor(session: nox.Session) -> None:
    session.run(sys.executable, "-m", "tools.testing.env_manager", "doctor", external=True)


@nox.session(python=False)
def clean_test_envs(session: nox.Session) -> None:
    if session.posargs:
        session.error("clean_test_envs accepts no paths and removes only fixed managed roots")
    session.run(sys.executable, "-m", "tools.testing.env_manager", "clean", external=True)
