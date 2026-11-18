"""No page of the app may carry an inline script or an inline event handler (the policy forbids both)."""
from __future__ import annotations

import re
from pathlib import Path

from core import local_guard

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = sorted(list((ROOT / "templates").rglob("*.html")) + list((ROOT / "features").rglob("*.html")))
INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)(?![^>]*type=[\"']application/(?:ld\+)?json[\"'])[^>]*>\s*\S", re.IGNORECASE)
INLINE_HANDLER = re.compile(r"\son[a-z]+\s*=\s*[\"']", re.IGNORECASE)


def test_the_policy_does_not_allow_inline_scripts():
    policy = local_guard.SECURITY_HEADERS["Content-Security-Policy"]
    script_src = re.search(r"script-src ([^;]+)", policy).group(1)
    assert script_src.split() == ["'self'"]


def test_no_template_has_an_inline_script_block():
    assert TEMPLATES
    offenders = [path.relative_to(ROOT).as_posix() for path in TEMPLATES if INLINE_SCRIPT.search(path.read_text(encoding="utf-8"))]
    assert offenders == []


def test_no_template_has_an_inline_event_handler():
    offenders = [path.relative_to(ROOT).as_posix() for path in TEMPLATES if INLINE_HANDLER.search(path.read_text(encoding="utf-8"))]
    assert offenders == []


def test_the_scripts_the_pages_load_exist():
    missing = []
    for path in TEMPLATES:
        for name in re.findall(r"filename=['\"](js/[^'\"]+)['\"]", path.read_text(encoding="utf-8")):
            homes = [ROOT / "static", *[parent / "static" for parent in path.parents if (parent / "static").is_dir()]]
            if not any((home / name).is_file() for home in homes):
                missing.append(f"{path.name}: {name}")
    assert missing == []
