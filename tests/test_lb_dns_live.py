"""BIG-IP DNS (GTM): live 'show gtm' parsing, the DNS live tables, the wide IP map and the collect lists.

The capture is synthetic.  The 'show gtm' layout follows the documented command set; it has not been taken from a real device.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from features.analyzer_core import collect
from features.analyzer_core.result import validate_result
from features.lb_analyzer import bigip_runtime, service

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "loadbalancer" / "bigip_capture_dns_synthetic.txt"
TODAY = date(2026, 10, 18)


@pytest.fixture(scope="module")
def dns():
    return service.analyze(FIXTURE.read_text(encoding="utf-8"), "dns.txt", today=TODAY)


def _section(result: dict, section_id: str) -> dict:
    return next(s for s in result["sections"] if s["id"] == section_id)


def _nodes(result: dict, type_: str) -> dict[str, dict]:
    section = next(s for s in result["sections"] if s["kind"] == "map")
    return {n["name"]: n for n in section["nodes"] if n["type"] == type_}


# ------------------------------------------------------------------ parser
def test_wideip_status_and_counters():
    text = "Gtm::WideIp: www.example.com\n----\nStatus\n  Availability : available\n  State : enabled\n  Reason : Available\nRequests\n  Total : 12\n  Resolved : 11\n  Dropped : 1\nLoad Balancing Decisions\n  Preferred : 9\n  Fallback : 2\n"
    (rec,) = bigip_runtime.parse_gtm(text)
    assert (rec["kind"], rec["name"], rec["availability"], rec["state"], rec["reason"]) == ("wideip", "www.example.com", "available", "enabled", "Available")
    assert rec["stats"] == {"requests total": "12", "requests resolved": "11", "requests dropped": "1", "decisions preferred": "9", "decisions fallback": "2"}


def test_pools_and_members_nest_under_the_wide_ip_and_the_pool():
    text = ("Gtm::WideIp: a.example.com\nStatus\n  Availability : available\n  State : enabled\n"
            "Gtm::Pool: pool_a\nStatus\n  Availability : offline\n  State : enabled\n  Reason : No members\n"
            "Gtm::Pool Member: srv1:vs1 in pool_a\nStatus\n  Availability : offline\n  State : disabled\n  Reason : Disabled by a parent object\n")
    wide, pool, member = bigip_runtime.parse_gtm(text)
    assert (pool["kind"], pool["parent"]) == ("pool", "a.example.com")
    assert (member["kind"], member["name"], member["parent"], member["state"]) == ("member", "srv1:vs1", "pool_a", "disabled")


@pytest.mark.parametrize("head,pool,name", [
    ("Gtm::Pool Member: srv1:vs1 in pool_a", "pool_a", "srv1:vs1"),
    ("Gtm::Pool Member: srv1:vs1", "ctx", "srv1:vs1"),
    ("Gtm::Pool Member: pool_a srv1:vs1", "pool_a", "srv1:vs1"),
])
def test_member_headers_of_different_releases(head, pool, name):
    text = f"Gtm::Pool: ctx\nStatus\n  Availability : available\n  State : enabled\n{head}\nStatus\n  Availability : available\n  State : enabled\n"
    member = [r for r in bigip_runtime.parse_gtm(text) if r["kind"] == "member"][0]
    assert (member["parent"], member["name"]) == (pool, name)


def test_record_type_before_the_name_is_split_off():
    (rec,) = bigip_runtime.parse_gtm("Gtm::WideIp: aaaa www.example.com\nStatus\n  Availability : available\n  State : enabled\n")
    assert (rec["type"], rec["name"]) == ("aaaa", "www.example.com")


def test_iquery_peer_without_a_status_block():
    text = "Gtm::IQuery: 10.1.1.1\n----\n  Server                 bigip_jkt\n  Data Center            dc_jkt\n  iQuery State           connected\n  Query Reconnects       2\n  Backlogs               0\n"
    (rec,) = bigip_runtime.parse_gtm(text)
    assert (rec["address"], rec["server"], rec["datacenter"], rec["iquery_state"]) == ("10.1.1.1", "bigip_jkt", "dc_jkt", "connected")
    assert rec["fields"]["query reconnects"] == "2"


def test_the_same_object_in_two_commands_keeps_the_richer_record():
    a = bigip_runtime.parse_gtm("Gtm::Pool: p\nStatus\n  Availability : available\n  State : enabled\n")
    b = bigip_runtime.parse_gtm("Gtm::Pool: p\n")
    assert len(bigip_runtime.merge_gtm(b + a)) == 1 and bigip_runtime.merge_gtm(b + a)[0]["availability"] == "available"


def test_ltm_headers_end_a_gtm_object():
    text = "Gtm::Pool: p\nStatus\n  Availability : available\n  State : enabled\nLtm::Virtual Server: v\nStatus\n  Availability : offline\n"
    (rec,) = bigip_runtime.parse_gtm(text)
    assert rec["availability"] == "available"


# ------------------------------------------------------------------ the analysis
def test_runtime_holds_every_dns_object_kind(dns):
    runtime = bigip_runtime.gather(FIXTURE.read_text(encoding="utf-8"))
    assert {k for k in runtime if k.startswith("gtm_")} == {"gtm_wideips", "gtm_pools", "gtm_members", "gtm_servers", "gtm_virtuals", "gtm_datacenters", "gtm_iquery", "gtm_listeners"}
    assert validate_result(dns) == []


def test_live_tables_are_in_the_dns_tab(dns):
    ids = {s["id"] for s in dns["sections"] if s["group"] == "DNS (GTM)"}
    assert {"gtm_wideips", "gtm_pools", "gtm_servers", "gtm_wideips_live", "gtm_pools_live", "gtm_members_live", "gtm_servers_live", "gtm_datacenters_live", "gtm_iquery_live", "gtm_listeners_live"} <= ids
    wide = {r["name"]: r for r in _section(dns, "gtm_wideips_live")["rows"]}
    assert wide["www.example.com"]["requests"] == 12500 and wide["www.example.com"]["fallback"] == 480
    assert wide["api.example.com"]["availability"] == "offline"
    peers = {r["address"]: r for r in _section(dns, "gtm_iquery_live")["rows"]}
    assert peers["10.2.1.1"]["iquery_state"] == "backlogged" and peers["10.2.1.1"]["backlogs"] == 41 and peers["10.2.1.1"]["_tones"]["iquery_state"] == "warn"
    assert peers["10.1.1.1"]["server"] == "bigip_jkt" and peers["10.1.1.1"]["_tones"]["iquery_state"] == "ok"


def test_wideip_tree_in_the_visualization(dns):
    section = next(s for s in dns["sections"] if s["kind"] == "map")
    assert {"wideip", "dnspool", "dnsmember"} <= {t["key"] for t in section["types"]}
    wide = _nodes(dns, "wideip")
    assert (wide["www.example.com"]["status"], wide["www.example.com"]["source"]) == ("available", "live")
    assert wide["api.example.com"]["status"] == "offline"
    assert wide["dead.example.com"]["status"] == "unknown" and "no pool" in wide["dead.example.com"]["reason"]
    assert wide["off.example.com"]["status"] == "forced down"                                       # disabled and offline: black diamond
    members = {}
    for node in section["nodes"]:
        if node["type"] == "dnsmember":
            members.setdefault(node["name"], set()).add(node["status"])
    assert members["bigip_jkt:vs_web"] == {"available"} and members["bigip_sby:vs_web"] == {"offline"}
    assert members["srv_off:vs1"] == {"parent disabled"}


def test_a_pool_shared_by_two_wide_ips_appears_under_both_and_unused_pools_are_grouped(dns):
    section = next(s for s in dns["sections"] if s["kind"] == "map")
    api_pool = [n for n in section["nodes"] if n["type"] == "dnspool" and n["name"] == "pool_api_a"]
    assert len(api_pool) == 2 and len({n["ref"] for n in api_pool}) == 1                           # under www (last resort) and under api
    assert any(n["badge"] == "last resort" for n in api_pool)
    group = next(n for n in section["nodes"] if n["id"] == "g-gtm-orphans")
    assert {n["name"] for n in section["nodes"] if n["parent"] == group["id"]} == {"pool_empty_a", "pool_unused_a"}


def test_pool_reason_says_when_no_enabled_member_is_available(dns):
    section = next(s for s in dns["sections"] if s["kind"] == "map")
    unused = next(n for n in section["nodes"] if n["type"] == "dnspool" and n["name"] == "pool_unused_a")
    assert unused["status"] == "offline" and unused["reason"] == "none of the 1 enabled member(s) is available"


def test_dns_findings_from_live_state(dns):
    ids = {}
    for f in dns["findings"]:
        ids.setdefault(f["id"], []).append(f)
    assert [f["object"] for f in ids["LB-GTM-020"]] == ["gtm iquery 10.2.1.1"]                    # only the backlogged peer
    assert [f["object"] for f in ids["LB-GTM-021"]] == ["gtm wideip api.example.com"]            # the disabled wide IP is silent
    assert "LB-GTM-022" not in ids
    assert all(f["reference"].startswith("https://") for k, v in ids.items() if k.startswith("LB-GTM-02") for f in v)


def test_dns_only_unit_is_not_reported_as_missing_ltm(dns):
    rows = {r["command"]: r for r in dns["coverage"]}
    assert rows["ltm (tmsh list ltm ... / bigip.conf)"]["status"] == "analyzed"                    # the DNS listener is an LTM virtual server
    text = FIXTURE.read_text(encoding="utf-8")
    only = service.analyze(text.replace("ltm virtual /Common/vs_dns_listener", "gtm listener /Common/ls_x").replace("    destination /Common/10.9.9.9:53\n    ip-protocol udp\n    profiles {\n        /Common/dns { }\n        /Common/udp { }\n    }\n", "    address 10.9.9.9\n"), "dns.txt", today=TODAY)
    row = {r["command"]: r for r in only["coverage"]}["ltm (tmsh list ltm ... / bigip.conf)"]
    assert row["status"] == "covered" and "DNS-only" in row["note"]
    assert {r["command"]: r["status"] for r in only["coverage"]}["show gtm iquery"] == "analyzed"


def test_ltm_only_capture_has_no_dns_commands_and_no_dns_map_types():
    result = service.analyze((ROOT / "tests" / "fixtures" / "loadbalancer" / "bigip_capture_live_members_synthetic.txt").read_text(encoding="utf-8"), "c.txt", today=TODAY)
    assert not [r for r in result["coverage"] if r["command"].startswith("show gtm")]
    section = next(s for s in result["sections"] if s["kind"] == "map")
    assert not {"wideip", "dnspool", "dnsmember"} & {t["key"] for t in section["types"]}
    assert not [s for s in result["sections"] if s["id"].startswith("gtm_")]


def test_configuration_only_dns_map_never_claims_available():
    text = FIXTURE.read_text(encoding="utf-8")
    config_only = text[: text.index("[admin@dns-hq-01:Active:In Sync] ~ # tmsh show gtm wideip a detail")]
    result = service.analyze(config_only, "dns.txt", today=TODAY)
    section = next(s for s in result["sections"] if s["kind"] == "map")
    dns_nodes = [n for n in section["nodes"] if n["type"] in ("wideip", "dnspool", "dnsmember")]
    assert dns_nodes and not [n for n in dns_nodes if n["status"] == "available"]
    members = {n["name"]: n for n in dns_nodes if n["type"] == "dnsmember"}
    assert members["bigip_jkt:vs_web"]["status"] == "unverified"                                  # monitored through the server's bigip monitor
    assert members["srv_off:vs1"]["status"] == "parent disabled"                                  # its server is disabled
    assert any("No 'show gtm' output" in note for note in section["notes"])


def test_a_gtm_only_configuration_file_is_recognised():
    text = "gtm datacenter /Common/dc1 { }\ngtm server /Common/s1 {\n    datacenter /Common/dc1\n    product bigip\n}\ngtm pool a /Common/p1 {\n    members {\n        /Common/s1:vs { }\n    }\n}\ngtm wideip a /Common/w.example.com {\n    pools {\n        /Common/p1 { }\n    }\n}\n"
    assert service.looks_like_bigip(text)


# ------------------------------------------------------------------ collect lists
def _commands(name: str) -> list[str]:
    lines = (ROOT / "static" / "collect-scripts" / name).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def test_both_collect_lists_are_offered():
    found = {d["file"]: d for d in collect.discover("collect-lb")}
    assert {"collect-lb-f5-bigip.txt", "collect-lb-f5-dns.txt"} <= set(found)
    assert found["collect-lb-f5-dns.txt"]["title"] == "F5 DNS" and "DNS (GTM)" in found["collect-lb-f5-dns.txt"]["description"]


def test_collect_lists_hold_only_read_commands_and_no_secret_bearing_ones():
    for name in ("collect-lb-f5-bigip.txt", "collect-lb-f5-dns.txt"):
        commands = _commands(name)
        assert commands and all(c.startswith("tmsh show ") or c.startswith("tmsh list") for c in commands), name
        assert not [c for c in commands if set(c.split()) & {"tsig-key", "master-key", "modify", "save", "load", "delete", "create", "edit", "run", "reset-stats"} or "tsig" in c], name
        assert len(commands) == len(set(commands)), name


def test_dns_list_asks_for_every_command_the_parser_reads():
    commands = " ".join(_commands("collect-lb-f5-dns.txt"))
    for command, _ in bigip_runtime.GTM_COMMANDS:
        assert "tmsh " + command in commands, command
    ltm = " ".join(_commands("collect-lb-f5-bigip.txt"))
    for command, _ in bigip_runtime.COMMANDS:
        if command not in ("show sys hardware",):
            assert "tmsh " + command in ltm, command


def test_command_reference_on_the_page_lists_the_dns_commands():
    from features.lb_analyzer import routes

    shown = {row["command"] for row in routes.SPEC.page_context["commands"]}
    assert "show gtm iquery" in shown and "show ltm pool members" in shown
