"""Cooperative CLI cancellation and bounded, interruption-safe ownership changes.

Only the CLI installs cancellation handlers. Library callers retain their handlers;
run_command still cleans up on BaseException, including KeyboardInterrupt.
"""
from __future__ import annotations

import signal
import threading
from contextlib import contextmanager
from collections.abc import Iterator
from types import FrameType


class Cancelled(BaseException):
    """A CLI interrupt; ordinary error handlers must not consume it."""

    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(f"execution cancelled by signal {signum}")


@contextmanager
def cancellation_boundary() -> Iterator[None]:
    """Convert the first SIGINT/SIGTERM to unwinding; latch later signals.

    Handlers are process-global, so embedded calls from worker threads do not
    replace them. The executable CLI runs on the main thread.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    interrupted = False

    def cancel(signum: int, _frame: FrameType | None) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise Cancelled(signum)

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig, cancel)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextmanager
def defer_signals(*, deliver: bool = True) -> Iterator[None]:
    """Defer callable interrupt handlers across spawn, or shield bounded cleanup.

    No blocked signal mask is inherited by a child. On normal scope exit the
    first deferred signal is delivered through its original handler, after the
    new Popen has been assigned to its owner. During exception cleanup signals
    are discarded so repeated interruption cannot orphan the owned group.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    pending: tuple[int, FrameType | None] | None = None
    completed = False

    def defer(signum: int, frame: FrameType | None) -> None:
        nonlocal pending
        if pending is None:
            pending = (signum, frame)

    try:
        for sig, handler in previous.items():
            if callable(handler) or not deliver:
                signal.signal(sig, defer)
        yield
        completed = True
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if completed and deliver and pending is not None:
            signum, frame = pending
            handler = previous[signal.Signals(signum)]
            if callable(handler):
                handler(signum, frame)
