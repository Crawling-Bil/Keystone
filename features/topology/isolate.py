"""Reading a large capture in a helper process that can be stopped.

Python cannot stop a function that is running: a reader that falls into a regular expression with endless backtracking (a capture with a line that no pattern of the reader expects) holds
the whole run, and the web server has to be restarted.  A helper process can be killed.  ``Isolated.call`` runs one function in it and waits at most ``limit`` seconds; when the time is
up, the process is stopped and the caller is told, so that one capture is listed as skipped (with the reason) and the others of the run are read as usual.  A helper is started once per
run (the ``spawn`` method: it works the same on Windows, macOS and Linux and does not copy a web server's threads and locks), and a stopped one is replaced for the next capture.

Python documentation: https://docs.python.org/3/library/multiprocessing.html#contexts-and-start-methods
"""

from __future__ import annotations

import multiprocessing
from typing import Any, Callable

TIMEOUT = "timeout"          # the helper did not answer in time: it was stopped
FAILED = "failed"            # the helper could not run the call (it died, or what it had to send back cannot be sent): the caller reads in its own process instead
OK = "ok"


def _serve(conn: Any) -> None:
    """The helper: runs the functions it is sent, one after the other, until it is told to stop."""
    while True:
        try:
            job = conn.recv()
        except (EOFError, OSError):
            return
        if job is None:
            return
        func, args = job
        try:
            result = (OK, func(*args))
        except BaseException as error:           # whatever the reader raised is the caller's to report
            result = ("error", f"{type(error).__name__}: {error}")
        try:
            conn.send(result)
        except Exception:                        # a result that cannot be sent (an object that cannot be pickled)
            conn.send((FAILED, "the result could not be sent back"))


class Isolated:
    def __init__(self) -> None:
        self._process: Any = None
        self._conn: Any = None

    def _start(self) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        process = context.Process(target=_serve, args=(child,), daemon=True)
        process.start()
        child.close()
        self._process, self._conn = process, parent

    def stop(self) -> None:
        process, conn = self._process, self._conn
        self._process = self._conn = None
        if process is None:
            return
        try:
            if process.is_alive():
                process.kill()
            process.join(5)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    def call(self, func: Callable[..., Any], args: tuple, limit: float) -> tuple[str, Any]:
        """``(OK, result)``, ``("error", text)`` (the function raised), ``(TIMEOUT, limit)`` (it was still running after ``limit`` seconds: the helper was stopped) or ``(FAILED, why)``."""
        try:
            if self._process is None or not self._process.is_alive():
                self.stop()
                self._start()
            self._conn.send((func, args))
        except Exception as error:
            self.stop()
            return FAILED, f"{type(error).__name__}: {error}"
        try:
            if not self._conn.poll(limit):
                self.stop()
                return TIMEOUT, limit
            return self._conn.recv()
        except (EOFError, OSError) as error:
            self.stop()
            return FAILED, f"the helper stopped ({type(error).__name__})"

    def __enter__(self) -> "Isolated":
        return self

    def __exit__(self, *_: Any) -> None:
        try:
            if self._conn is not None:
                self._conn.send(None)
        except Exception:
            pass
        self.stop()
