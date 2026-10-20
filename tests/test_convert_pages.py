"""The five Convert pages share one layout: the same settings card, a result column, and a status panel
instead of a result column when no converter exists."""

from __future__ import annotations

import re

import pytest

from app import create_app

PAGES = ("switch", "firewall", "wireless", "router", "load-balancer")
PLANNED = ("wireless", "router", "load-balancer")
READY = ("switch", "firewall")
GROUPS = ("Source configuration", "Platforms", "Actions", "Batch conversion")


@pytest.fixture()
def client(monkeypatch):
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _html(client, name: str) -> str:
    response = client.get(f"/convert/{name}")
    assert response.status_code == 200
    return response.get_data(as_text=True)


@pytest.mark.parametrize("name", PAGES)
def test_every_page_has_the_same_four_groups_in_the_same_order(client, name):
    html = _html(client, name)
    labels = re.findall(r'<section class="cv-group[^"]*" aria-label="([^"]+)"', html)
    assert tuple(labels) == GROUPS
    assert html.count('class="cv-stack"') == 1


@pytest.mark.parametrize("name", PAGES)
def test_control_ids_exist_on_every_page(client, name):
    html = _html(client, name)
    for control in ("config-file", "config-text", "source-vendor", "target-vendor", "target-model", "convert-button", "batch-files", "batch-folder", "batch-convert-button"):
        assert f'id="{control}"' in html, control


@pytest.mark.parametrize("name", PLANNED)
def test_planned_pages_are_disabled_and_say_so(client, name):
    html = _html(client, name)
    assert '<fieldset class="cv-fieldset" disabled>' in html
    assert 'data-planned="true"' in html
    assert 'id="convert-unavailable"' in html
    assert "Not available yet" in html
    assert "js/configuration.js" not in html                 # nothing can be submitted


@pytest.mark.parametrize("name", READY)
def test_working_pages_are_enabled(client, name):
    html = _html(client, name)
    assert '<fieldset class="cv-fieldset">' in html
    assert "data-planned" not in html
    assert 'id="convert-unavailable"' not in html
    assert "js/configuration.js" in html
    assert 'id="converter-empty"' in html


def test_only_the_firewall_has_the_mapping_preview(client):
    assert 'id="preview-mapping-button"' in _html(client, "firewall")
    for name in ("switch", "wireless", "router", "load-balancer"):
        assert 'id="preview-mapping-button"' not in _html(client, name)


def test_planned_pages_point_to_their_analyzer(client):
    assert 'href="/router-analyzer"' in _html(client, "router")
    assert 'href="/wireless"' in _html(client, "wireless")
    assert 'href="/load-balancer-analyzer"' in _html(client, "load-balancer")
