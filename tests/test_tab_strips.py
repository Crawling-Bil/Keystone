"""Tab strips must not let a clicked tab shrink.

motion.js adds ``m-ripple-host`` to a button on pointerdown and motion.css gives that class
``overflow: hidden``.  A flex item with overflow hidden has a minimum width of 0, so inside a
horizontally scrolling strip the clicked tab collapsed to its padding and its label was cut
("Int", "AF", "VLAI").  Every tab button therefore has to opt out of shrinking.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "static" / "css"
JS = ROOT / "static" / "js"

STRIPS = [
    ("app.css", r"\.tab-nav button"),
    ("analyzer_kit.css", r"\.an-tab"),
    ("topology.css", r"\.tp-tabs button"),
]


def _rule(css: str, selector: str) -> str:
    """The declaration block of the first rule whose selector list is exactly ``selector``."""
    match = re.search(r"(?m)^" + selector + r"\s*\{([^}]*)\}", css)
    assert match, f"rule {selector} not found"
    return match.group(1)


@pytest.mark.parametrize("name,selector", STRIPS)
def test_tab_button_does_not_shrink(name, selector):
    body = _rule((CSS / name).read_text(encoding="utf-8"), selector)
    assert re.search(r"flex\s*:\s*0\s+0\s+auto", body), (
        f"{selector} in {name} must keep flex: 0 0 auto, otherwise a clicked tab collapses")


def test_no_later_rule_resets_flex_on_tab_buttons():
    for name, selector in STRIPS:
        css = (CSS / name).read_text(encoding="utf-8")
        for match in re.finditer(r"(?m)^" + selector + r"[^{]*\{([^}]*)\}", css):
            body = match.group(1)
            assert not re.search(r"flex(-shrink)?\s*:\s*(1|0?\.\d+)\b", body), (name, selector)


def test_switch_analyzer_scrolls_the_active_tab_into_view():
    js = (JS / "switch_analyzer.js").read_text(encoding="utf-8")
    assert "function revealTab(" in js
    switch_tab = js[js.index("function switchTab("):]
    assert "revealTab(tabName)" in switch_tab.split("\n  function ", 1)[0]
    # bounding-rect maths on the strip, never scrollIntoView (it can scroll the whole page)
    reveal = js[js.index("function revealTab("):].split("\n  }\n", 1)[0]
    assert "getBoundingClientRect" in reveal and "scrollIntoView" not in reveal
