"""The module registry drives the dashboard, sidebar and /api/health; keep it honest."""

from __future__ import annotations

import pytest

from app import create_app
from core.modules import GROUPS, RISK_LABELS, TOOLS, grouped_tools


@pytest.fixture
def client(monkeypatch):
    # the login gate reads this per request, and other test modules unset it
    monkeypatch.setenv("NES_DISABLE_AUTH", "1")
    app = create_app()
    app.testing = True
    return app.test_client()


def test_keys_and_hrefs_are_unique():
    assert len({t.key for t in TOOLS}) == len(TOOLS)
    assert len({t.href for t in TOOLS}) == len(TOOLS)


def test_every_tool_has_a_known_group_and_risk():
    groups = {key for key, _, _ in GROUPS}
    for tool in TOOLS:
        assert tool.group in groups, tool.key
        assert tool.risk in RISK_LABELS, tool.key


def test_grouping_keeps_every_tool_once():
    flat = [t.key for g in grouped_tools() for t in g["tools"]]
    assert sorted(flat) == sorted(t.key for t in TOOLS)


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.key)
def test_every_tool_page_opens(client, tool):
    assert client.get(tool.href).status_code == 200


def test_health_reports_every_tool(client):
    modules = client.get("/api/health").get_json()["modules"]
    assert set(modules) == {t.key for t in TOOLS}


def test_dashboard_and_sidebar_list_every_tool(client):
    html = client.get("/").get_data(as_text=True)
    for tool in TOOLS:
        assert f'href="{tool.href}"' in html, tool.key
    assert html.count('data-risk="write"') == sum(t.risk == "write" for t in TOOLS)
