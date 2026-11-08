"""Real CLI/supervisor cancellation, owned descendants, and handler restoration."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from iac_guard_v.cancellation import Cancelled, cancellation_boundary, defer_signals

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX process-group cleanup")

SCANNER = '''
import json, os, signal, subprocess, sys, time
from pathlib import Path
if sys.argv[2] == "stubborn":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)", sys.argv[3]])
def finish(*args):
    child.terminate()
    child.wait(timeout=2)
    raise SystemExit(0)
if sys.argv[2] != "stubborn":
    signal.signal(signal.SIGTERM, finish)
Path(sys.argv[1]).write_text(json.dumps([os.getpid(), child.pid, os.getpgrp()]))
while True: time.sleep(.05)
'''

SUPERVISOR = '''
import sys
from iac_guard_v import cli
from iac_guard_v.process import CommandRequest, run_command
scanner, pids, behavior, token, mode = sys.argv[1:]
def execute(argv):
    result = run_command(CommandRequest(
        argv=(sys.executable, scanner, pids, behavior, token), timeout_seconds=1 if mode == "timeout" else 60))
    return 0 if result.status.value == "PASS" else 3
cli._main = execute
raise SystemExit(cli.main([]))
'''


def wait_for(path: Path, process: subprocess.Popen) -> list[int]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        assert process.poll() is None, "supervisor exited before scanner readiness"
        time.sleep(.02)
    pytest.fail("scanner did not become ready")


def running(pid: int, token: str) -> bool:
    result = subprocess.run(["/bin/ps", "-o", "stat=,args=", "-p", str(pid)], capture_output=True, text=True)
    return result.returncode == 0 and token in result.stdout and not result.stdout.strip().startswith("Z")


@pytest.mark.parametrize("mode", ["int", "term", "repeated", "timeout", "leader-exit"])
def test_cli_reaps_owned_scanner_and_stops_grandchild(tmp_path: Path, mode: str) -> None:
    scanner = tmp_path / "scanner.py"
    scanner.write_text(textwrap.dedent(SCANNER))
    supervisor = tmp_path / "supervisor.py"
    supervisor.write_text(textwrap.dedent(SUPERVISOR))
    pids = tmp_path / "pids.json"
    behavior = "stubborn" if mode == "repeated" else "normal"
    token = f"owned-cancellation-{tmp_path.name}"
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)", "unrelated"], start_new_session=True)
    process = subprocess.Popen([sys.executable, str(supervisor), str(scanner), str(pids), behavior, token, mode],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    identities: list[int] = []
    try:
        identities = wait_for(pids, process)
        leader, child, group = identities
        assert group == leader and group != os.getpgrp()
        if mode == "leader-exit":
            os.kill(leader, signal.SIGTERM)
            os.kill(process.pid, signal.SIGTERM)
        elif mode != "timeout":
            os.kill(process.pid, signal.SIGINT if mode == "int" else signal.SIGTERM)
            if mode == "repeated":
                time.sleep(.1)
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGINT):
                    os.kill(process.pid, signum)
                    time.sleep(.03)
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 3, (stdout, stderr)
        deadline = time.monotonic() + 3
        while (running(leader, token) or running(child, token)) and time.monotonic() < deadline:
            time.sleep(.03)
        assert not running(leader, token), "scanner still running after cancellation"
        assert not running(child, token), "scanner descendant still running after cancellation"
        assert unrelated.poll() is None, "unrelated process was signalled"
        if mode in {"int", "term", "repeated"}:
            assert json.loads(stderr.decode().splitlines()[-1])["reason_code"] == "EXECUTION_CANCELLED"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
        if identities and any(running(pid, token) for pid in identities[:2]):
            os.killpg(identities[2], signal.SIGKILL)
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_handlers_restore_and_spawn_defers_until_owned() -> None:
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    owned = False
    with pytest.raises(Cancelled) as error:
        with cancellation_boundary():
            with defer_signals():
                os.kill(os.getpid(), signal.SIGTERM)
                owned = True
    assert owned and error.value.signum == signal.SIGTERM
    assert {sig: signal.getsignal(sig) for sig in previous} == previous


def test_library_keyboard_interrupt_cleanup_and_spawn_race(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from iac_guard_v import process as module
    from iac_guard_v.process import CommandRequest, run_command
    real_popen = subprocess.Popen
    owned: list[subprocess.Popen] = []

    def interrupt_after_spawn(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        owned.append(process)
        os.kill(os.getpid(), signal.SIGINT)
        return process

    monkeypatch.setattr(module.subprocess, "Popen", interrupt_after_spawn)
    with pytest.raises(KeyboardInterrupt):
        run_command(CommandRequest(argv=(sys.executable, "-c", "import time; time.sleep(120)")))
    assert len(owned) == 1 and owned[0].poll() is not None


def test_observer_failure_still_kills_and_reaps_owned_child(monkeypatch: pytest.MonkeyPatch) -> None:
    from iac_guard_v import process as module
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], start_new_session=True)
    def failed_observation(process):
        raise OSError("observer unavailable")
    monkeypatch.setattr(module, "_peek_exit", failed_observation)
    try:
        result = module._terminate_owned_group(child)
        assert not result.success
        assert "observation failed" in result.diagnostic
        assert child.returncode is not None
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)


def test_custom_sigchld_rejected_before_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    from iac_guard_v import process as module
    real_getsignal = signal.getsignal
    monkeypatch.setattr(signal, "getsignal", lambda sig: signal.SIG_IGN if sig == signal.SIGCHLD else real_getsignal(sig))
    with pytest.raises(module.ProcessPolicyError, match="SIGCHLD"):
        module.run_command(module.CommandRequest(argv=(sys.executable, "-c", "pass")))


@pytest.mark.parametrize("body", ["pass", "import os,signal; os.kill(os.getpid(),signal.SIGKILL)"])
def test_exit_observation_never_reaps(body: str) -> None:
    from iac_guard_v.process import _peek_exit
    child = subprocess.Popen([sys.executable, "-c", body])
    try:
        deadline = time.monotonic() + 3
        time.sleep(.05)  # include exit-before-observer-registration on both hosts
        while _peek_exit(child) is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert _peek_exit(child) is not None
        assert child.returncode is None
    finally:
        child.wait(timeout=3)
