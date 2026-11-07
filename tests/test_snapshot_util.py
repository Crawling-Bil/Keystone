"""The snapshot helper itself: it must fail on a difference and on a missing snapshot, and write only when asked."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import snapshot_util  # noqa: E402


@pytest.fixture()
def folder(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot_util, "SNAPSHOTS", tmp_path)
    monkeypatch.delenv(snapshot_util.UPDATE, raising=False)
    return tmp_path


def test_a_missing_snapshot_fails_and_writes_nothing(folder):
    with pytest.raises(AssertionError, match="No snapshot for 'x'"):
        snapshot_util.assert_snapshot("x", {"a": 1})
    assert list(folder.iterdir()) == []


def test_update_mode_writes_the_file_and_the_next_run_passes(folder, monkeypatch):
    monkeypatch.setenv(snapshot_util.UPDATE, "1")
    snapshot_util.assert_snapshot("x", {"b": [1, 2], "a": "é"})
    monkeypatch.delenv(snapshot_util.UPDATE)
    snapshot_util.assert_snapshot("x", {"a": "é", "b": [1, 2]})                  # key order does not matter
    assert (folder / "x.json").read_bytes().endswith(b"\n") and b"\r" not in (folder / "x.json").read_bytes()


def test_a_difference_fails_with_a_readable_diff(folder, monkeypatch):
    monkeypatch.setenv(snapshot_util.UPDATE, "1")
    snapshot_util.assert_snapshot("x", {"severity": "low"})
    monkeypatch.delenv(snapshot_util.UPDATE)
    with pytest.raises(AssertionError) as err:
        snapshot_util.assert_snapshot("x", {"severity": "medium"})
    assert '- "severity": "low"' in str(err.value) and '+ "severity": "medium"' in str(err.value) and "KEYSTONE_UPDATE_SNAPSHOTS=1" in str(err.value)


def test_a_snapshot_checked_out_with_windows_line_endings_still_matches(folder, monkeypatch):
    monkeypatch.setenv(snapshot_util.UPDATE, "1")
    snapshot_util.assert_snapshot("x", {"a": [1]})
    monkeypatch.delenv(snapshot_util.UPDATE)
    path = folder / "x.json"
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    snapshot_util.assert_snapshot("x", {"a": [1]})


def test_sets_are_written_sorted_and_other_objects_as_text(folder):
    assert snapshot_util.render({"s": {"b", "a"}, "p": Path("x")}) == '{\n "p": "x",\n "s": [\n  "a",\n  "b"\n ]\n}\n'


def test_update_mode_is_only_on_for_the_value_1(folder, monkeypatch):
    monkeypatch.setenv(snapshot_util.UPDATE, "yes")
    with pytest.raises(AssertionError):
        snapshot_util.assert_snapshot("x", {})
