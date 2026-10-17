"""Filter buttons ("facets") on the Firewall and Load Balancer analyzer tables, and the WIB column of the BIG-IP change history.

A facet button needs two things from the server: the facet declared on the section, and a column of that key holding the values to count.
The browser builds the buttons from the rows, so these tests check both halves against the synthetic fixtures.
"""

from __future__ import annotations

import io
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from features.analyzer_core.result import validate_result
from features.firewall_analyzer import service as fw_service
from features.lb_analyzer import bigip_ucs, service as lb_service
from tests import test_lb_ucs

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TODAY = date(2026, 10, 14)


def _section(result: dict, section_id: str) -> dict:
    return next(s for s in result["sections"] if s["id"] == section_id)


def _facet_values(section: dict, key: str) -> set[str]:
    assert any(f["key"] == key for f in section["facets"]), f"{section['id']} has no '{key}' facet"
    assert any(c["key"] == key for c in section["columns"])
    return {row[key] for row in section["rows"] if row.get(key)}


@pytest.fixture(scope="module")
def lb():
    return lb_service.analyze((FIXTURES / "loadbalancer" / "bigip_synthetic_weak.conf").read_text(encoding="utf-8"), "lb.conf", today=TODAY)


@pytest.fixture(scope="module")
def fw():
    return fw_service.analyze((FIXTURES / "firewall" / "fortigate_synthetic_7.2.conf").read_text(encoding="utf-8"), "fgt.conf", "fortigate")


def test_firewall_hardening_can_be_filtered_by_result(fw):
    assert validate_result(fw) == []
    values = _facet_values(_section(fw, "hardening"), "result")
    assert values and values <= {"pass", "fail", "n/a"}


def test_load_balancer_hardening_can_be_filtered_by_result(lb):
    values = _facet_values(_section(lb, "hardening"), "result")
    assert values and values <= {"pass", "fail", "n/a"}


def test_virtual_server_status_filter(lb):
    assert _facet_values(_section(lb, "virtuals"), "status") <= {"enabled", "disabled"}


def test_pool_member_and_node_state_filters(lb):
    allowed = {"enabled", "disabled", "forced down"}
    assert _facet_values(_section(lb, "members"), "state") <= allowed
    assert _facet_values(_section(lb, "nodes"), "state") <= allowed


def test_inventory_handling_filter(lb):
    section = _section(lb, "inventory")
    assert _facet_values(section, "status") >= {"analyzed"}
    assert next(f for f in section["facets"] if f["key"] == "status")["label"] == "handling"


def test_the_shared_vdom_facet_is_kept_next_to_the_result_facet(fw):
    facets = [f["key"] for f in _section(fw, "hardening")["facets"]]
    assert "result" in facets and len(facets) == len(set(facets))


@pytest.fixture(scope="module")
def ucs_result():
    text = bigip_ucs.read_upload("x.ucs", io.BytesIO(test_lb_ucs._ucs(None)))
    return lb_service.analyze(text, "x.ucs", today=TODAY)


def test_change_history_has_a_wib_column_seven_hours_after_utc(ucs_result):
    section = _section(ucs_result, "change_log")
    keys = [c["key"] for c in section["columns"]]
    assert keys.index("when_wib") == keys.index("when") + 1
    label = next(c["label"] for c in section["columns"] if c["key"] == "when_wib")
    assert "WIB" in label and "UTC+7" in label
    assert section["rows"], "the synthetic UCS carries one administrator save"
    for row in section["rows"]:
        utc = datetime.strptime(row["when"], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        assert datetime.strptime(row["when_wib"], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc) - utc == timedelta(hours=7)


# ------------------------------------------------------------------ every facet points at a real column
def _all_results():
    from features.router_analyzer import service as router_service

    for path in sorted((FIXTURES / "firewall").glob("*")):
        yield path.name, fw_service.analyze(path.read_text(encoding="utf-8", errors="replace"), path.name)
    for path in sorted((FIXTURES / "loadbalancer").glob("*")):
        yield path.name, lb_service.analyze(path.read_text(encoding="utf-8", errors="replace"), path.name, today=TODAY)
    for path in sorted((FIXTURES / "router").glob("*.txt")):
        yield path.name, router_service.analyze(path.read_text(encoding="utf-8", errors="replace"), path.name)


def test_every_facet_names_a_column_of_its_own_table():
    """A facet whose key matches no column is silently ignored by the browser, which would hide a typo."""
    checked = 0
    for name, result in _all_results():
        for section in result["sections"]:
            if section.get("kind") != "table":
                continue
            keys = {c["key"] for c in section["columns"]}
            for facet in section["facets"]:
                assert facet["key"] in keys, f"{name}: {section['id']} facet '{facet['key']}' has no column"
                checked += 1
    assert checked > 40


def test_policy_and_live_state_tables_have_their_filters(fw):
    policies = _section(fw, "policies")
    assert {"action", "status"} <= {f["key"] for f in policies["facets"]}
    assert _facet_values(policies, "action") <= {"accept", "deny"}


def test_router_hardening_and_neighbor_tables_have_filters():
    from features.router_analyzer import service as router_service

    seen = set()
    for path in sorted((FIXTURES / "router").glob("*.txt")):
        result = router_service.analyze(path.read_text(encoding="utf-8", errors="replace"), path.name)
        for section in result["sections"]:
            if section.get("kind") == "table" and section["facets"]:
                seen.add(section["id"])
    assert {"hardening", "bgp_neighbors"} & seen
    assert "hardening" in seen
