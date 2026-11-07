"""Old topology runs are removed: the newest few stay, anything older than a week goes, empty folders do not pile up.
Synthetic folders only (invented ids and file names)."""

from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from features.topology.retention import GRACE_SECONDS, prune_runs  # noqa: E402

DAY = 86400
NOW = 2_000_000_000.0


def _run(root: Path, number: int, age_days: float, files: int = 2) -> str:
    """A run folder named like a real one (32 hex characters) whose last change was ``age_days`` ago."""
    name = f"{number:032x}"
    folder = root / name
    folder.mkdir()
    for index in range(files):
        (folder / f"table{index}.csv").write_text("a,b\n", encoding="utf-8")
    stamp = NOW - age_days * DAY
    os.utime(folder, (stamp, stamp))
    return name


def _names(root: Path) -> set[str]:
    return {p.name for p in root.iterdir()}


def test_keeps_the_newest_runs_and_removes_the_rest(tmp_path):
    runs = [_run(tmp_path, n, age_days=0.5 + n * 0.1) for n in range(1, 8)]          # run 1 is the newest, all younger than a week
    removed = prune_runs(tmp_path, keep=3, max_age_days=7, now=NOW)
    assert _names(tmp_path) == set(runs[:3])
    assert set(removed) == set(runs[3:])


def test_runs_older_than_the_age_limit_go_even_when_few(tmp_path):
    fresh = _run(tmp_path, 1, age_days=1)
    week_and_a_bit = _run(tmp_path, 2, age_days=7.5)
    old = _run(tmp_path, 3, age_days=40)
    prune_runs(tmp_path, keep=10, max_age_days=7, now=NOW)
    assert _names(tmp_path) == {fresh}
    assert week_and_a_bit not in _names(tmp_path) and old not in _names(tmp_path)


def test_the_run_just_built_and_very_young_runs_are_never_removed(tmp_path):
    just_built = _run(tmp_path, 1, age_days=30)                                       # protected by name even though it is old
    building = _run(tmp_path, 2, age_days=(GRACE_SECONDS / 2) / DAY)                  # another build that is still writing
    newest = [_run(tmp_path, n, age_days=n * 0.01) for n in range(3, 6)]
    prune_runs(tmp_path, keep=1, max_age_days=7, protect=just_built, now=NOW)
    assert just_built in _names(tmp_path) and building in _names(tmp_path)
    assert not set(newest) & _names(tmp_path)                                         # the rest is over the limit of one


def test_a_young_run_counts_toward_the_limit(tmp_path):
    youngest = _run(tmp_path, 1, age_days=(GRACE_SECONDS / 2) / DAY)
    older = [_run(tmp_path, n, age_days=n) for n in range(2, 5)]
    prune_runs(tmp_path, keep=2, max_age_days=7, now=NOW)
    assert _names(tmp_path) == {youngest, older[0]}


def test_empty_run_folders_are_removed_and_do_not_count(tmp_path):
    empty = _run(tmp_path, 1, age_days=1, files=0)
    real = [_run(tmp_path, n, age_days=n) for n in range(2, 4)]
    prune_runs(tmp_path, keep=2, max_age_days=7, now=NOW)
    assert _names(tmp_path) == set(real)
    assert empty not in _names(tmp_path)


def test_folders_and_files_that_are_not_runs_stay(tmp_path):
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "keep.txt").write_text("x", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("x", encoding="utf-8")
    (tmp_path / ("A" * 32)).mkdir()                                                   # upper case is not a run id
    (tmp_path / ("a" * 31)).mkdir()
    for n in range(1, 4):
        _run(tmp_path, n, age_days=30)
    prune_runs(tmp_path, keep=1, max_age_days=7, now=NOW)
    assert _names(tmp_path) == {"notes", "readme.txt", "A" * 32, "a" * 31}


def test_nested_files_and_read_only_files_are_removed(tmp_path):
    name = _run(tmp_path, 1, age_days=30)
    nested = tmp_path / name / "sub" / "deeper"
    nested.mkdir(parents=True)
    locked = nested / "locked.txt"
    locked.write_text("x", encoding="utf-8")
    locked.chmod(0o444)
    os.utime(tmp_path / name, (NOW - 30 * DAY, NOW - 30 * DAY))
    assert prune_runs(tmp_path, keep=5, max_age_days=7, now=NOW) == [name]
    assert not (tmp_path / name).exists()


def test_a_missing_folder_or_a_file_in_its_place_does_not_raise(tmp_path):
    assert prune_runs(tmp_path / "nothing", now=NOW) == []
    plain = tmp_path / "plain"
    plain.write_text("x", encoding="utf-8")
    assert prune_runs(plain, now=NOW) == []


def test_keep_below_one_still_keeps_one(tmp_path):
    runs = [_run(tmp_path, n, age_days=n) for n in range(1, 4)]
    prune_runs(tmp_path, keep=0, max_age_days=7, now=NOW)
    assert _names(tmp_path) == {runs[0]}


def test_default_clock_keeps_a_run_that_was_just_written(tmp_path):
    name = f"{1:032x}"
    (tmp_path / name).mkdir()
    (tmp_path / name / "a.csv").write_text("x", encoding="utf-8")
    assert prune_runs(tmp_path, keep=1, max_age_days=0) == []
    assert (tmp_path / name).exists()


# ---- start-up sweep (app.py) -------------------------------------------------------------------------------------

def test_sweep_removes_old_files_and_the_empty_folders_they_leave(tmp_path):
    from app import _sweep_directory

    old = time.time() - 40 * DAY
    stale = tmp_path / "a" / "b"
    stale.mkdir(parents=True)
    (stale / "x.txt").write_text("x", encoding="utf-8")
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    (mixed / "old.txt").write_text("x", encoding="utf-8")
    (mixed / "new.txt").write_text("x", encoding="utf-8")
    (tmp_path / ".gitkeep").write_text("", encoding="utf-8")
    fresh_empty = tmp_path / "fresh"
    fresh_empty.mkdir()
    for path in [stale / "x.txt", stale, tmp_path / "a", mixed / "old.txt", tmp_path / ".gitkeep"]:
        os.utime(path, (old, old))
    _sweep_directory(tmp_path, time.time() - 30 * DAY)
    assert not (tmp_path / "a").exists()                                              # file gone, then both empty folders
    assert (mixed / "new.txt").exists() and not (mixed / "old.txt").exists()
    assert fresh_empty.exists()                                                       # empty but young: may belong to a running job
    assert (tmp_path / ".gitkeep").exists() and tmp_path.exists()


# ---- the build route ---------------------------------------------------------------------------------------------

def test_every_build_prunes_and_keeps_its_own_run(tmp_path, monkeypatch):
    from app import create_app
    from features.topology import routes
    from topology_samples import lab_dc

    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config.update(TESTING=True, TOPOLOGY_KEEP_RUNS=2, TOPOLOGY_MAX_AGE_DAYS=7)
    client = app.test_client()
    old = [_run_now(tmp_path, n, age_seconds=GRACE_SECONDS + 100 * n) for n in range(1, 5)]
    files = {"files": [(io.BytesIO(text.encode()), name) for name, text in lab_dc().items()], "group": "none"}
    body = client.post("/topology/api/build", data=files, content_type="multipart/form-data").get_json()
    assert body["ok"]
    left = _names(tmp_path)
    assert body["export_id"] in left and len(left) == 2                               # the new run plus the newest old one
    assert left - {body["export_id"]} == {old[0]}
    assert client.get(body["downloads"][0]["url"]).status_code == 200


def _run_now(root: Path, number: int, age_seconds: float) -> str:
    name = f"{number:032x}"
    folder = root / name
    folder.mkdir()
    (folder / "a.csv").write_text("x", encoding="utf-8")
    stamp = time.time() - age_seconds
    os.utime(folder, (stamp, stamp))
    return name
