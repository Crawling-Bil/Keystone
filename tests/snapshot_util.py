"""Frozen expected outputs ("snapshots") for the synthetic samples.

``assert_snapshot(name, data)`` writes nothing by itself: it compares ``data`` (anything JSON can hold; sets and other objects are turned into text)
with ``tests/snapshots/<name>.json`` and fails with a readable diff when they differ.  A snapshot that does not exist yet fails too, so a
new sample cannot go unchecked by accident.

To accept a change on purpose, read the diff, then run once::

    KEYSTONE_UPDATE_SNAPSHOTS=1 python -m pytest tests/test_snapshots.py

and review the changed files under tests/snapshots like any other change.
"""
from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
from typing import Any

SNAPSHOTS = Path(__file__).parent / "snapshots"
UPDATE = "KEYSTONE_UPDATE_SNAPSHOTS"


def render(data: Any) -> str:
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False, default=lambda value: sorted(value) if isinstance(value, (set, frozenset)) else str(value)) + "\n"


def assert_snapshot(name: str, data: Any) -> None:
    path = SNAPSHOTS / f"{name}.json"
    text = render(data)
    if os.environ.get(UPDATE) == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        return
    if not path.is_file():
        raise AssertionError(f"No snapshot for '{name}'. Run with {UPDATE}=1 once, read the new file under tests/snapshots and keep it.")
    expected = path.read_text(encoding="utf-8")
    if expected != text:
        diff = list(difflib.unified_diff(expected.splitlines(), text.splitlines(), "snapshot", "now", lineterm="", n=2))
        shown = "\n".join(diff[:80]) + (f"\n... {len(diff) - 80} more diff lines" if len(diff) > 80 else "")
        raise AssertionError(f"Output of '{name}' differs from tests/snapshots/{name}.json:\n{shown}\nIf the change is intended, run with {UPDATE}=1 and review the file.")
