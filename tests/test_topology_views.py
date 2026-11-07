"""Topology Builder page sections: Create topology, Compare two runs and Cutover runbook are tabs, so building has the whole page."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from features.topology import routes



@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "static" / "js"


def _page(client):
    return client.get("/topology").get_data(as_text=True)


def _start(page, view):
    """Index of the opening tag of one section."""
    return page.rindex("<", 0, page.index(f'data-view-panel="{view}"'))


def test_the_page_has_three_tabs_in_order(client):
    page = _page(client)
    bar = page[page.index('data-role="views"'):page.index('data-view-panel="create"')]
    views = re.findall(r'data-view="(\w+)"', bar)
    assert views == ["create", "compare", "runbook"]
    assert bar.count('role="tab"') == 3 and 'role="tablist"' in page
    assert re.search(r'data-view="create" aria-selected="true" tabindex="0"', bar)
    assert re.search(r'data-view="compare" aria-selected="false" tabindex="-1"', bar)
    assert "topology-views.js" in page and page.index("topology.js") < page.index("topology-views.js")


def test_only_the_create_section_is_visible_at_first(client):
    page = _page(client)
    panels = re.findall(r'<(?:div|section)[^>]*data-view-panel="(\w+)"[^>]*>', page)
    assert panels == ["create", "compare", "runbook"]
    tags = {m.group(1): m.group(0) for m in re.finditer(r'<(?:div|section)[^>]*data-view-panel="(\w+)"[^>]*>', page)}
    assert " hidden" not in tags["create"]
    assert " hidden" in tags["compare"] and " hidden" in tags["runbook"]
    assert all('role="tabpanel"' in tag for tag in tags.values())


def test_create_holds_the_builder_and_nothing_else(client):
    page = _page(client)
    create = page[_start(page, "create"):_start(page, "compare")]
    for role in ("form", "build", "progress", "result", "empty", "name", "history-open"):
        assert f'data-role="{role}"' in create, role
    for role in ("diff", "diff-form", "runbook", "rb-form"):
        assert f'data-role="{role}"' not in create, role


def test_compare_and_runbook_have_their_own_forms(client):
    page = _page(client)
    compare = page[_start(page, "compare"):_start(page, "runbook")]
    runbook = page[_start(page, "runbook"):page.index("<dialog")]
    assert 'data-role="diff-form"' in compare and "Compare two runs" in compare and "<details" not in compare
    assert 'data-role="rb-form"' in runbook and "Cutover runbook" in runbook and "<details" not in runbook
    assert 'data-role="rb-form"' not in compare and 'data-role="diff-form"' not in runbook


def test_the_history_dialog_stays_outside_the_sections(client):
    page = _page(client)
    assert _start(page, "runbook") < page.index("<dialog")
    assert page.count("<dialog") == 1


def test_no_section_uses_the_result_tab_attributes(client):
    # topology.js switches the result tabs with [data-tab] / [data-panel]; the page tabs must not collide with them
    bar = _page(client)
    bar = bar[bar.index('data-role="views"'):bar.index('data-view-panel="create"')]
    assert "data-tab" not in bar and "data-panel" not in bar


def test_the_panels_follow_the_tab_events():
    diff = (JS / "topology-diff.js").read_text(encoding="utf-8")
    runbook = (JS / "topology-runbook.js").read_text(encoding="utf-8")
    assert '"tp:viewshown"' in diff and 'view === "compare"' in diff and '"tp:showview"' in diff and "box.open" not in diff
    assert '"tp:viewshown"' in runbook and 'view === "runbook"' in runbook and '"tp:showview"' in runbook and "box.open" not in runbook
    views = (JS / "topology-views.js").read_text(encoding="utf-8")
    for key in ("ArrowRight", "ArrowLeft", "Home", "End", "tp:showview", "tp:viewshown", "tabIndex"):
        assert key in views, key


def test_the_sections_cannot_widen_the_page_on_a_phone():
    # a grid without an explicit column grows to its widest child (the history button row), which pushed the page sideways
    css = (ROOT / "static" / "css" / "topology.css").read_text(encoding="utf-8")
    rule = re.search(r"\.tp-view \{([^}]*)\}", css).group(1)
    assert "grid-template-columns: minmax(0, 1fr)" in rule
    assert re.search(r"\.tp-view\[hidden\], \.tp-viewpanel\[hidden\] \{ display: none; \}", css)
