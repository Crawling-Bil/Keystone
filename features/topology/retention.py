"""Keeps ``exports/topology`` from growing without limit.

Every build writes one folder (a 32-character hex id) with the tables, the drawing and the trace file. The files are only
needed while the page that built them is open (downloads and the path trace read them) and by the Topology history panel,
which lists, downloads and compares the runs that are kept. One run is about 2 MB; a folder that is never pruned reached 785 MB.

Rules (``prune_runs``):

* only folders whose name is a run id are touched; anything else in the folder is left alone,
* the newest ``keep`` runs stay (20 by default),
* a run older than ``max_age_days`` goes, whatever the count (30 days by default),
* a pinned run (a ``_pinned`` marker file, set from the Topology history panel) is never removed and does not count towards ``keep``,
* an empty run folder (a build that stopped before it wrote anything) goes,
* the run just built (``protect``) and any run younger than ``grace_seconds`` stay, so a second build running at the same
  time never loses its files.

Nothing here raises: a file that Windows still holds open is skipped and removed by the next pass.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import time
from pathlib import Path

log = logging.getLogger(__name__)

RUN_ID = re.compile(r"^[a-f0-9]{32}$")
DEFAULT_KEEP = 20
DEFAULT_MAX_AGE_DAYS = 30
PIN_FILE = "_pinned"
GRACE_SECONDS = 600


def _make_writable(function, path, _info) -> None:
    """``rmtree`` error handler: a read-only file (Windows) is made writable and removed again; any other failure is skipped."""
    try:
        os.chmod(path, stat.S_IWRITE)
        function(path)
    except OSError:
        pass


def _remove(folder: Path) -> bool:
    shutil.rmtree(folder, onerror=_make_writable)
    return not folder.exists()


def _has_files(folder: Path) -> bool:
    for _root, _dirs, files in os.walk(folder):
        if files:
            return True
    return False


def prune_runs(export_dir: Path, keep: int = DEFAULT_KEEP, max_age_days: float = DEFAULT_MAX_AGE_DAYS,
               protect: str | None = None, grace_seconds: float = GRACE_SECONDS, now: float | None = None) -> list[str]:
    """Remove old run folders from ``export_dir``; returns the ids removed (oldest first)."""
    try:
        now = time.time() if now is None else now
        runs: list[tuple[float, str, Path]] = []
        for entry in export_dir.iterdir():
            if RUN_ID.match(entry.name) and entry.is_dir() and not entry.is_symlink():
                runs.append((entry.stat().st_mtime, entry.name, entry))
    except OSError:
        return []
    runs.sort(key=lambda run: (run[0], run[1]), reverse=True)               # newest first
    oldest_allowed = now - max_age_days * 86400
    kept = 0
    doomed: list[tuple[float, str, Path]] = []
    for mtime, name, folder in runs:
        if (folder / PIN_FILE).is_file():
            continue                                                          # pinned: kept until the person deletes it, and not counted
        if name == protect or now - mtime < grace_seconds:
            kept += 1                                                         # a young run counts as kept: it is probably a build in progress
            continue
        if not _has_files(folder):
            doomed.append((mtime, name, folder))
            continue
        if kept >= max(keep, 1) or mtime < oldest_allowed:
            doomed.append((mtime, name, folder))
        else:
            kept += 1
    removed: list[str] = []
    for _mtime, name, folder in reversed(doomed):
        try:
            if _remove(folder):
                removed.append(name)
        except OSError:
            continue
    if removed:
        log.info("Topology exports: removed %d old run(s), kept %d", len(removed), kept)
    return removed
