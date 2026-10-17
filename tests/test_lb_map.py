"""The Load Balancer Analyzer "Visualization" tab (a BIG-IP Network Map), the live pool-member / node parsers behind it, the generic
"map" section kind in the shared result schema, and the State filter on the Router Analyzer interfaces table.

Every capture here is synthetic: the layouts follow the documented TMSH output and were not taken from a real device.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from features.analyzer_core import compare as compare_mod
from features.analyzer_core.export import export_results
from features.analyzer_core.result import map_as_table, map_depths, map_section, validate_result
from features.lb_analyzer import bigip_map, bigip_runtime, service as lb_service
from features.router_analyzer import service as router_service

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TODAY = date(2026, 10, 18)


def _text(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text(encoding="utf-8")


def _map(result: dict) -> dict:
    return next(s for s in result["sections"] if s["kind"] == "map")


def _by(section: dict, type_: str) -> dict[str, dict]:
    return {n["name"]: n for n in section["nodes"] if n["type"] == type_}


@pytest.fixture(scope="module")
def config_only():
    return lb_service.analyze(_text("loadbalancer", "bigip_synthetic_weak.conf"), "weak.conf", today=TODAY)


@pytest.fixture(scope="module")
def live_summary():
    return lb_service.analyze(_text("loadbalancer", "bigip_capture_synthetic.txt"), "capture.txt", today=TODAY)


@pytest.fixture(scope="module")
def live_members():
    return lb_service.analyze(_text("loadbalancer", "bigip_capture_live_members_synthetic.txt"), "capture.txt", today=TODAY)


# ------------------------------------------------------------------ the tab
def test_visualization_tab_sits_right_after_the_overview(live_members):
    groups = []
    for section in live_members["sections"]:
        if section["group"] not in groups:
            groups.append(section["group"])
    assert groups[:3] == ["Visualization", "Virtual servers", "Pools & nodes"]
    assert validate_result(live_members) == []
    assert any(card["section"] == "network_map" for card in live_members["cards"])


def test_every_virtual_server_is_a_root_and_every_node_uses_declared_values(config_only):
    section = _map(config_only)
    roots = [n for n in section["nodes"] if n["parent"] == "" and n["type"] == "virtual"]
    assert roots
    virtuals = next(s for s in config_only["sections"] if s["id"] == "virtuals")
    assert len(roots) == len(virtuals["rows"])
    statuses = {s["key"] for s in section["statuses"]} | {""}
    types = {t["key"] for t in section["types"]}
    assert all(n["status"] in statuses and n["type"] in types for n in section["nodes"])
    assert section["references"] and all(r["url"].startswith("https://") for r in section["references"])


def test_config_only_map_never_claims_available(config_only):
    section = _map(config_only)
    assert section["live"]["any"] is False
    assert not [n for n in section["nodes"] if n["status"] == "available"]
    assert "no live ltm state" in " ".join(section["notes"]).lower()
    members = [n for n in section["nodes"] if n["type"] == "member"]
    assert members and {n["source"] for n in members} <= {"config", "derived"}


def test_config_states_follow_f5_semantics(live_summary):
    section = _map(live_summary)
    members = [n for n in section["nodes"] if n["type"] == "member"]
    forced = [n for n in members if n["name"] == "10.10.30.13:80"]
    assert forced and all(n["status"] == "forced down" for n in forced)                    # state user-down
    assert next(n for n in section["nodes"] if n["name"] == "vs_retired" and n["type"] == "virtual")["status"] == "disabled"
    pools = _by(section, "pool")
    assert pools["pool_empty"]["status"] == "offline" and "no members" in pools["pool_empty"]["reason"]
    nomon = [n for n in members if n["parent"] and next(p for p in section["nodes"] if p["id"] == n["parent"])["name"] == "pool_nomon"]
    assert nomon and {n["status"] for n in nomon} == {"unverified"}                        # no pool monitor, but ltm default-node-monitor applies
    empty_vs = [n for n in section["nodes"] if n["type"] == "virtual" and n["name"] == "vs_dup_a"]
    assert empty_vs[0]["status"] == "offline"                                              # follows its empty default pool


def test_live_virtual_and_pool_status_overrides_the_derivation(live_summary):
    section = _map(live_summary)
    web = next(n for n in section["nodes"] if n["type"] == "virtual" and n["name"] == "vs_web_443")
    assert (web["status"], web["source"]) == ("available", "live")
    app = next(n for n in section["nodes"] if n["type"] == "virtual" and n["name"] == "vs_app_8443")
    assert (app["status"], app["source"]) == ("offline", "live") and "pool member" in app["reason"]
    assert section["live"]["virtuals"] == 3 and section["live"]["members"] == 0


def test_live_pool_members_colour_the_members(live_members):
    section = _map(live_members)
    assert section["live"]["members"] == 5
    members = {(n["parent"], n["name"]): n for n in section["nodes"] if n["type"] == "member"}
    by_name = {}
    for (parent, name), node in members.items():
        by_name.setdefault(name, set()).add((node["status"], node["source"]))
    assert by_name["10.10.30.11:80"] == {("available", "live")}
    assert by_name["10.10.30.12:80"] == {("offline", "live")}
    assert by_name["10.10.30.13:80"] == {("forced down", "live")}                          # offline + disabled = black diamond
    assert by_name["10.10.40.22:8443"] == {("unavailable", "live")}
    web_member = next(n for n in section["nodes"] if n["type"] == "member" and n["name"] == "10.10.30.11:80")
    assert "monitor up" in web_member["badge"]
    assert any(p["label"] == "Live monitor status" and p["value"] == "up" for p in web_member["detail"])
    live_ids = {s["id"] for s in live_members["sections"]}
    assert {"pool_members_live", "nodes_live"} <= live_ids


def test_a_pool_shared_by_virtual_servers_appears_under_each_and_shares_a_ref(live_summary):
    section = _map(live_summary)
    pools = [n for n in section["nodes"] if n["type"] == "pool" and n["name"] == "pool_web"]
    assert len(pools) >= 2 and len({n["ref"] for n in pools}) == 1 and len({n["parent"] for n in pools}) == len(pools)
    orphan_group = next(n for n in section["nodes"] if n["type"] == "group")
    orphans = [n["name"] for n in section["nodes"] if n["parent"] == orphan_group["id"]]
    assert "pool_unused" in orphans


def test_monitors_hang_under_their_pool_and_carry_their_type(live_summary):
    section = _map(live_summary)
    pool = next(n for n in section["nodes"] if n["type"] == "pool" and n["name"] == "pool_web")
    monitors = [n for n in section["nodes"] if n["parent"] == pool["id"] and n["type"] == "monitor"]
    assert [m["name"] for m in monitors] == ["http"]
    assert any(p["label"] == "Scope" and p["value"] == "pool" for p in monitors[0]["detail"])


CONFIG_PARENT_DISABLED = """ltm node /Common/10.0.0.1 {
    address 10.0.0.1
    session user-disabled
    state user-down
}
ltm node /Common/10.0.0.2 {
    address 10.0.0.2
}
ltm pool /Common/p1 {
    members {
        /Common/10.0.0.1:80 {
            address 10.0.0.1
        }
        /Common/10.0.0.2:80 {
            address 10.0.0.2
        }
    }
    monitor /Common/http
}
ltm virtual /Common/vs1 {
    destination /Common/10.9.9.9:80
    ip-protocol tcp
    pool /Common/p1
    profiles {
        /Common/tcp { }
    }
}
"""


def test_member_whose_node_is_disabled_is_shown_as_parent_disabled():
    result = lb_service.analyze(CONFIG_PARENT_DISABLED, "c.conf", today=TODAY)
    section = _map(result)
    members = {n["name"]: n for n in section["nodes"] if n["type"] == "member"}
    assert members["10.0.0.1:80"]["status"] == "parent disabled"
    assert members["10.0.0.2:80"]["status"] == "unverified"
    pool = next(n for n in section["nodes"] if n["type"] == "pool")
    assert pool["status"] == "unverified" and "1 of 2" in pool["reason"]


def test_member_without_any_monitor_is_unknown_not_green():
    text = CONFIG_PARENT_DISABLED.replace("    monitor /Common/http\n", "")
    section = _map(lb_service.analyze(text, "c.conf", today=TODAY))
    members = {n["name"]: n for n in section["nodes"] if n["type"] == "member"}
    assert members["10.0.0.2:80"]["status"] == "unknown" and members["10.0.0.2:80"]["source"] == "derived"
    pool = next(n for n in section["nodes"] if n["type"] == "pool")
    assert pool["status"] == "unknown"


def test_pool_with_every_member_parked_is_offline():
    text = CONFIG_PARENT_DISABLED.replace("address 10.0.0.2\n}", "address 10.0.0.2\n    session user-disabled\n}")
    section = _map(lb_service.analyze(text, "c.conf", today=TODAY))
    pool = next(n for n in section["nodes"] if n["type"] == "pool")
    assert pool["status"] == "offline" and "disabled or forced down" in pool["reason"]
    vs = next(n for n in section["nodes"] if n["type"] == "virtual")
    assert vs["status"] == "offline"


def test_pool_selected_by_an_irule_is_listed_under_the_virtual_server(config_only):
    section = _map(config_only)
    via = [n for n in section["nodes"] if n["type"] == "pool" and "iRule" in n["badge"]]
    # the weak fixture's iRules name pools; whichever are defined must be attached to a virtual server
    for node in via:
        parent = next(p for p in section["nodes"] if p["id"] == node["parent"])
        assert parent["type"] == "virtual"


# ------------------------------------------------------------------ status mapping
@pytest.mark.parametrize("availability,state,reason,expected", [
    ("available", "enabled", "", "available"),
    ("offline", "enabled", "", "offline"),
    ("unavailable", "enabled", "", "unavailable"),
    ("unknown", "enabled", "", "unknown"),
    ("available", "disabled", "", "disabled"),
    ("unknown", "disabled", "", "disabled"),
    ("offline", "disabled", "marked down by a user", "forced down"),
    ("unavailable", "disabled", "", "forced down"),
    ("available", "disabled", "disabled by a parent object", "parent disabled"),
    ("", "", "", "unknown"),
])
def test_live_status_follows_the_f5_icon_table(availability, state, reason, expected):
    assert bigip_map.live_status(availability, state, reason) == expected


# ------------------------------------------------------------------ live parsers
@pytest.mark.parametrize("head,pool,member", [
    ("Ltm::Pool Member: 10.1.1.1:80", "ctx", "10.1.1.1:80"),
    ("Ltm::Pool Member: 10.1.1.1:80 in pool_web", "pool_web", "10.1.1.1:80"),
    ("Ltm::Pool Member: 10.1.1.1:80 in pool /Common/pool_web", "/Common/pool_web", "10.1.1.1:80"),
    ("Ltm::Pool Member: pool_web 10.1.1.1:80", "pool_web", "10.1.1.1:80"),
    ("Ltm::Pool Member: /Common/web01:8080 (10.1.1.9)", "ctx", "/Common/web01:8080"),
])
def test_pool_member_headers_of_different_releases_are_understood(head, pool, member):
    text = f"Ltm::Pool: ctx\n------\n{head}\n------\nStatus\n  Availability : available\n  State : enabled\n  Reason : ok\n  Monitor Status : up\n"
    parsed = bigip_runtime.parse_pool_members(text)
    assert len(parsed) == 1
    assert (parsed[0]["pool"], parsed[0]["member"], parsed[0]["availability"], parsed[0]["monitor_status"]) == (pool, member, "available", "up")


def test_nodes_are_parsed_by_name_and_address():
    text = "Ltm::Node: web01 (10.1.1.1)\nStatus\n  Availability : offline\n  State : enabled\n  Reason : Node address monitor failed\nLtm::Node: 10.1.1.2\nStatus\n  Availability : available\n  State : enabled\n"
    nodes = bigip_runtime.parse_nodes(text)
    assert [(n["name"], n["address"], n["availability"]) for n in nodes] == [("web01", "10.1.1.1", "offline"), ("10.1.1.2", "10.1.1.2", "available")]


def test_pool_listing_ends_at_the_first_member_so_its_reason_is_the_pools_own():
    text = "Ltm::Pool: p1\n------\nStatus\n  Availability : offline\n  State : enabled\n  Reason : The children pool member(s) are down\n------\nLtm::Pool Member: 10.1.1.1:80\nStatus\n  Availability : available\n  Reason : Pool member is available\n"
    pool = bigip_runtime.parse_pools(text)[0]
    assert (pool["availability"], pool["reason"]) == ("offline", "The children pool member(s) are down")


def test_collect_list_asks_for_the_member_and_node_state():
    commands = (Path(__file__).resolve().parents[1] / "static" / "collect-scripts" / "collect-lb-f5-bigip.txt").read_text(encoding="utf-8")
    assert "tmsh show ltm pool members" in commands and "tmsh show ltm node" in commands


# ------------------------------------------------------------------ the generic "map" section
def _tiny_map() -> dict:
    nodes = [{"id": "a", "parent": "", "type": "virtual", "name": "vs", "status": "available", "detail": [("Destination", "1.1.1.1:80"), ("Empty", "")]},
             {"id": "b", "parent": "a", "type": "pool", "name": "p", "status": "offline", "reason": "all members down"}]
    return map_section("m", "Map", nodes, statuses=[{"key": "available", "label": "available", "tone": "ok", "shape": "circle", "description": ""}, {"key": "offline", "label": "offline", "tone": "bad", "shape": "diamond", "description": ""}],
                       types=[{"key": "virtual", "label": "Virtual server"}, {"key": "pool", "label": "Pool"}], group="Visualization")


def test_map_section_validates_and_flattens_to_a_table():
    section = _tiny_map()
    result = {"schema": "keystone.analysis/1", "analyzer": "lb", "hostname": "h", "cards": [], "info": [], "findings": [], "coverage": [], "sections": [section]}
    assert validate_result(result) == []
    assert section["nodes"][0]["detail"] == [{"label": "Destination", "value": "1.1.1.1:80"}]          # empty values are dropped
    assert [(n["name"], depth, path) for n, depth, path in map_depths(section)] == [("vs", 0, "vs"), ("p", 1, "vs > p")]
    table = map_as_table(section)
    assert table["kind"] == "table" and [r["path"] for r in table["rows"]] == ["vs", "vs > p"] and table["rows"][1]["level"] == 1


def test_validator_rejects_a_broken_map():
    section = _tiny_map()
    section["nodes"].append({"id": "a", "parent": "zzz", "type": "pool", "name": "x", "status": "nonsense", "detail": []})
    result = {"schema": "keystone.analysis/1", "analyzer": "lb", "hostname": "h", "cards": [], "info": [], "findings": [], "coverage": [], "sections": [section]}
    problems = validate_result(result)
    assert any("duplicate map node ids" in p for p in problems) and any("unknown parent" in p for p in problems)


def test_excel_export_writes_the_map_as_a_sheet(live_members, tmp_path):
    from openpyxl import load_workbook

    path = export_results([live_members], tmp_path / "lb.xlsx", analyzer_label="Load Balancer")
    sheet = load_workbook(path)["Network map"]
    header = [c.value for c in sheet[1]]
    assert header[:3] == ["Device", "Path", "Level"]
    paths = [row[1] for row in sheet.iter_rows(min_row=2, values_only=True)]
    assert "vs_web_443 > pool_web > 10.10.30.12:80" in paths
    statuses = {row[header.index("Status")] for row in sheet.iter_rows(min_row=2, values_only=True)}
    assert {"available", "offline", "forced down"} <= statuses


def test_compare_notices_a_member_that_changed_state(live_members, live_summary):
    changed = compare_mod.compare_results(live_summary, live_members)
    assert validate_result(changed) == []
    text = repr(changed["sections"])
    assert "Network map" in text and "10.10.30.12:80" in text


def test_a_failing_map_never_costs_the_analysis(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(bigip_map, "sections", boom)
    result = lb_service.analyze(_text("loadbalancer", "bigip_synthetic_hardened.conf"), "h.conf", today=TODAY)
    assert not [s for s in result["sections"] if s["kind"] == "map"]
    assert any("Visualization tab could not be built" in w for w in result["warnings"])
    assert validate_result(result) == []


# ------------------------------------------------------------------ router interfaces: State filter
def test_router_interfaces_table_has_a_state_filter():
    result = router_service.analyze(_text("router", "c8300_iosxe_ospf_log_masked.txt"), "r.txt")
    section = next(s for s in result["sections"] if s["id"] == "interfaces")
    facet = next(f for f in section["facets"] if f["key"] == "state")
    assert facet["order"][:4] == ["up/up", "up/down", "down/down", "admin down"]
    states = {row["state"] for row in section["rows"]}
    assert {"up/up", "admin down", "down/down"} <= states and all(c["key"] != "state" or c["kind"] == "status" for c in section["columns"])
