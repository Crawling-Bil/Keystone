"""Pre-push guard: no private identifier may appear in a file that would be pushed.

The identifiers (customer names, domains, management networks, credentials) are real, so they are not listed here.  They live one per line in the gitignored
``tests/.leak_needles.local`` of the person who owns the data.  Without that file the test is skipped (CI, fresh clones); with it, every text file of the tree is
scanned, case-insensitively, and the paths of the private override files themselves are excluded.

Run it before every push:  python -m pytest tests/test_private_data_guard.py -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NEEDLES_FILE = Path(__file__).parent / ".leak_needles.local"

SKIP_DIRS = {"__pycache__", ".git", ".ruff_cache", ".pytest_cache", "local", "htmlcov", ".venv"}
SKIP_TOP = {"data", "exports", "uploads", "logs"}   # runtime folders next to the code, gitignored
SKIP_SUFFIXES = {".pyc", ".db", ".zip", ".gif", ".png", ".jpg", ".ico", ".woff", ".woff2", ".docx", ".xlsx", ".pdf"}
# Not part of this guard: the LLD Index and Document Generator, which are maintained separately.
SKIP_PREFIXES = ("static/js/lld_generator.js", "templates/lld_index.html", "core/docgen/", "tests/test_lld_generator.py")


def _needles() -> list[str]:
    return [line.strip().lower() for line in NEEDLES_FILE.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


@pytest.mark.skipif(not NEEDLES_FILE.is_file(), reason="no tests/.leak_needles.local on this machine")
def test_no_private_identifier_in_the_tree():
    needles = _needles()
    found: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES or path.name == ".coverage":
            continue
        rel = path.relative_to(ROOT).as_posix()
        parts = path.relative_to(ROOT).parts
        if any(part in SKIP_DIRS for part in parts[:-1]) or parts[0] in SKIP_TOP or rel.startswith(SKIP_PREFIXES) or rel in ("tests/.leak_needles.local", "tests/test_private_data_guard.py"):
            continue
        try:
            text = path.read_text(encoding="utf-8").lower()
        except (UnicodeDecodeError, OSError):
            continue
        for needle in needles:
            if needle in text:
                found.append(f"{rel}: {needle}")
    assert not found, "private identifiers would be pushed:\n" + "\n".join(found[:60])
