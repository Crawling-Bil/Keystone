"""Build progress for the Topology Builder page.

A build is one long request.  The page picks a random id, sends it with the captures and asks ``/topology/api/progress/<id>``
every half second; the build reports where it is through :func:`report` and :func:`stage`, which do nothing when nobody
listens (tests, scripts, the anonymized twin of a build that has no tracker).

The bar is one number from 0 to 100 made of stages, each with a share of the bar.  Reading the captures is by far the
slowest step on a first build (the shared Switch Analyzer parsers), so it has the biggest share and moves with the bytes
read, not with the file count: one 4 MB capture counts for more than ten small ones.  Later builds of the same captures
come from the reading cache and pass that stage in a blink.  Nothing here changes a result.
"""

from __future__ import annotations

import contextlib
import contextvars
import re
import threading
import time
from typing import Iterator

# (key, label, share of the bar); the shares add up to 100
STAGES: tuple[tuple[str, str, float], ...] = (
    ("read", "Reading captures", 66),
    ("link", "Matching the two ends of every link", 4),
    ("pages", "Placing devices and drawing the pages", 12),
    ("l3", "Building the L3 views", 6),
    ("export", "Preparing the diagram files", 5),
    ("write", "Writing the tables, workbook and pack", 7),
)
_START = {key: sum(share for _, _, share in STAGES[:i]) for i, (key, _, _) in enumerate(STAGES)}
_SHARE = {key: share for key, _, share in STAGES}
_LABEL = {key: label for key, label, _ in STAGES}

ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
KEEP = 64                  # builds remembered
EXPIRES = 30 * 60          # seconds a finished or abandoned build stays

_LOCK = threading.Lock()
_BUILDS: dict[str, "Build"] = {}
_CURRENT: contextvars.ContextVar["Tracker | None"] = contextvars.ContextVar("topology_progress", default=None)


class Build:
    """What the page can ask for: the percentage, the stage and the detail, whether the build ended."""

    def __init__(self) -> None:
        self.started = time.time()
        self.updated = self.started
        self.percent = 0.0
        self.label = "Starting"
        self.detail = ""
        self.done = False

    def snapshot(self) -> dict[str, object]:
        return {"known": True, "percent": round(self.percent, 1), "label": self.label, "detail": self.detail,
                "done": self.done, "seconds": round((self.done and self.updated or time.time()) - self.started, 1)}


class Tracker:
    """The part of the bar one pass of the build owns: ``lo`` to ``hi`` percent (the anonymized twin gets the second half)."""

    def __init__(self, build: Build, lo: float = 0.0, hi: float = 100.0, prefix: str = "") -> None:
        self.build, self.lo, self.hi, self.prefix = build, lo, hi, prefix
        self.stage = ""

    def set(self, key: str, fraction: float = 0.0, detail: str = "") -> None:
        fraction = min(max(fraction, 0.0), 1.0)
        own = (_START[key] + _SHARE[key] * fraction) / 100.0
        percent = self.lo + (self.hi - self.lo) * own
        build = self.build
        with _LOCK:
            if percent > build.percent:        # the bar never moves back
                build.percent = percent
            build.label = self.prefix + _LABEL[key]
            build.detail = detail
            build.updated = time.time()
        self.stage = key


def start(build_id: str) -> Build | None:
    """Register a build under the id the page chose (None when the id is not acceptable: the build then runs without a bar)."""
    if not ID_RE.match(build_id or ""):
        return None
    now = time.time()
    with _LOCK:
        for old in [k for k, b in _BUILDS.items() if now - b.updated > EXPIRES]:
            del _BUILDS[old]
        while len(_BUILDS) >= KEEP:
            del _BUILDS[next(iter(_BUILDS))]
        build = _BUILDS[build_id] = Build()
    return build


def finish(build: Build | None, label: str = "Done") -> None:
    if build is None:
        return
    with _LOCK:
        build.done = True
        build.updated = time.time()
        build.label = label
        build.detail = ""
        if label == "Done":
            build.percent = 100.0


def status(build_id: str) -> dict[str, object]:
    """The answer to the page's poll; an id the server has not seen yet (the first poll can arrive before the upload ends) is 'not known', not an error."""
    with _LOCK:
        build = _BUILDS.get(build_id)
        return build.snapshot() if build is not None else {"known": False, "percent": 0, "label": "Waiting for the upload", "detail": "", "done": False, "seconds": 0}


@contextlib.contextmanager
def tracking(build: Build | None, lo: float = 0.0, hi: float = 100.0, prefix: str = "") -> Iterator[Tracker | None]:
    """Everything the build reports inside this block goes to ``build``, in the part ``lo``..``hi`` of the bar."""
    if build is None:
        yield None
        return
    tracker = Tracker(build, lo, hi, prefix)
    token = _CURRENT.set(tracker)
    try:
        yield tracker
    finally:
        _CURRENT.reset(token)


def report(key: str, fraction: float = 0.0, detail: str = "") -> None:
    """Called by the build: it is now ``fraction`` through stage ``key``. No listener, no cost."""
    tracker = _CURRENT.get()
    if tracker is not None:
        tracker.set(key, fraction, detail)


