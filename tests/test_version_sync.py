"""The version a person reads must be the version the program reports.

``APP_VERSION`` in app.py is the single source of truth.  The README and the Indonesian guide both quote it, so a release
that changes one and forgets the other fails here instead of confusing the team.
"""
from __future__ import annotations

import re
from pathlib import Path

import app as keystone_app

ROOT = Path(__file__).resolve().parents[1]


def _quoted(path: Path, pattern: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(pattern, text)
    assert match, f"{path.name} does not state a version (looked for /{pattern}/)"
    return match.group(1)


def test_the_readme_quotes_the_version_the_program_reports():
    assert _quoted(ROOT / "README.md", r"Current version:\s*([0-9]+\.[0-9]+\.[0-9]+)") == keystone_app.APP_VERSION


def test_the_indonesian_guide_quotes_the_version_the_program_reports():
    assert _quoted(ROOT / "docs" / "PANDUAN.md", r"Versi saat ini:\s*([0-9]+\.[0-9]+\.[0-9]+)") == keystone_app.APP_VERSION


def test_the_version_is_a_plain_three_part_number():
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", keystone_app.APP_VERSION)
