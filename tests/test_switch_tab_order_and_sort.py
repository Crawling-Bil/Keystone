"""Switch Analyzer, Single Device: the tabs the work is done in come first (Interfaces right after Overview; Findings, Health and Coverage close the strip),
the page lists them in the same order as ``tabs.TAB_ORDER``, and the CDP/LLDP table (like the other result tables) sorts by any column."""
from __future__ import annotations

import re
from pathlib import Path

from features.switch_analyzer import tabs

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "switch_analyzer.html").read_text(encoding="utf-8")
JS = (ROOT / "static" / "js" / "switch_analyzer.js").read_text(encoding="utf-8")


def _page_tabs() -> list[str]:
    strip = HTML.split('id="switch-tabs"', 1)[1].split("</div>", 1)[0]
    return re.findall(r'data-tab="([a-z_]+)"', strip)


def test_the_page_lists_the_tabs_in_the_order_of_tab_order():
    assert _page_tabs() == [key for key, _label, _specs in tabs.TAB_ORDER]


def test_interfaces_follow_overview_and_findings_health_coverage_close_the_strip():
    keys = _page_tabs()
    assert keys[:2] == ["overview", "interfaces"] and keys[-3:] == ["findings", "health", "coverage"]


def test_the_neighbor_table_is_a_sortable_table_and_sorting_is_off_for_the_paired_compare_tables():
    assert 'renderFilterable("switch-neighbor-table"' in JS and 'renderTable("switch-neighbor-table"' not in JS
    assert 'data-sort-table' in JS and 'startsWith("switch-compare-")' in JS
    assert 'aria-sort' in JS and "cellCollator" in JS and "numeric: true" in JS


def test_sort_buttons_are_styled():
    css = (ROOT / "static" / "css" / "app.css").read_text(encoding="utf-8")
    assert ".th-sort" in css and ".th-sort-mark" in css
