"""Sizing Tool: redundant pairs are read from what the two configurations say about each other, not from the hostname.  Invented captures only."""

from __future__ import annotations

from features.sizing_tool import pairs, plan
from features.sizing_tool.common import new_asset

VPC = "vpc domain {dom}\n  peer-keepalive destination {peer} source {me} vrf management\ninterface mgmt0\n  vrf member management\n  ip address {me}/24\n"
VSX = "vsx\n    inter-switch-link lag 256\n    role primary\n    keepalive peer {peer} source {me} vrf mgmt\ninterface mgmt\n    ip static {me}/24\n"
FGT = "config system ha\n    set group-name \"{name}\"\n    set group-id {gid}\n    set mode a-p\n    set hbdev \"port3\" 50\nend\n"
PAN = "set deviceconfig high-availability group group-id {gid}\nset deviceconfig high-availability group peer-ip {peer}\nset deviceconfig high-availability interface ha1 ip-address {me}\n"
F5 = "cm device-group /Common/dg-fo {{\n    type sync-failover\n}}\ncm device /Common/{a} {{\n}}\ncm device /Common/{b} {{\n}}\n"
ASA = "failover lan unit {unit}\nfailover interface ip FOLINK 192.168.254.1 255.255.255.252 standby 192.168.254.2\n"


def box(host, text, dtype="switch", model="N9K-C93180YC-FX3", ha="Standalone", n=1):
    asset = new_asset(hostname=host, device_type=dtype, model=model, vendor="X", ha=ha, serial=f"SER{host}")
    asset["id"] = f"d{n}"
    pairs.attach([asset], text)
    return asset


def run(*assets):
    for n, a in enumerate(assets, 1):
        a["id"] = f"d{n}"
    plan.mark_duplicates_and_units(list(assets))
    return list(assets)


def test_vpc_members_with_unrelated_names_are_paired_by_their_keepalive_addresses():
    a = box("ALPHA-SW", VPC.format(dom=10, me="10.0.0.1", peer="10.0.0.2"))
    b = box("ZULU-SW", VPC.format(dom=10, me="10.0.0.2", peer="10.0.0.1"))
    out = run(a, b)
    assert out[0]["logical_unit"] == out[1]["logical_unit"] and out[0]["pair_with"] == "d2" and out[0]["pair_source"] == "configuration"
    assert plan.logical_units(out)["pairs"] == 1


def test_names_that_look_like_a_pair_are_not_one_when_the_configurations_do_not_agree():
    a = box("SITE-CORE-1", VPC.format(dom=10, me="10.0.0.1", peer="10.0.0.2"))
    b = box("SITE-CORE-2", VPC.format(dom=10, me="10.9.9.9", peer="10.9.9.8"))
    out = run(a, b)
    assert out[0]["logical_unit"] != out[1]["logical_unit"]
    assert all(x["pair_missing"] == "vPC" and any("partner that was not captured" in n for n in x["notes"]) for x in out)


def test_a_name_pair_whose_configurations_name_nothing_is_still_grouped_as_before():
    a = new_asset(hostname="DC-CORE-1", device_type="switch", model="X1", ha="vPC pair", serial="A1B2C3D4E5")
    b = new_asset(hostname="DC-CORE-2", device_type="switch", model="X1", ha="vPC pair", serial="F6G7H8J9K0")
    out = run(a, b)
    assert out[0]["logical_unit"] == out[1]["logical_unit"] and out[0]["pair_source"] == "hostname"


def test_one_member_only_is_flagged_and_counted_as_half_a_pair():
    out = run(box("ALPHA-SW", VPC.format(dom=10, me="10.0.0.1", peer="10.0.0.2")))
    assert out[0]["pair_missing"] == "vPC"
    assert plan.logical_units(out)["kinds"] == {"one member of a pair (the other was not captured)": 1}


def test_two_pairs_that_reuse_one_domain_and_address_are_left_for_the_architect():
    members = [box(n, VPC.format(dom=1, me="10.0.0.1" if i % 2 == 0 else "10.0.0.2", peer="10.0.0.2" if i % 2 == 0 else "10.0.0.1")) for i, n in enumerate(["S1-A", "S1-B", "S2-A", "S2-B"])]
    out = run(*members)
    assert len({x["logical_unit"] for x in out}) == 4 and all("more than one other capture" in " ".join(x["notes"]) for x in out)


def test_vsx_members_are_paired_by_keepalive():
    out = run(box("AGG-NORTH", VSX.format(me="172.16.0.1", peer="172.16.0.2"), model="8325"), box("AGG-SOUTH", VSX.format(me="172.16.0.2", peer="172.16.0.1"), model="8325"))
    assert out[0]["pair_with"] == "d2"


def test_fortigate_ha_members_share_a_group_name_and_id():
    out = run(box("FW-EAST", FGT.format(name="CL1", gid=7), "firewall", "FG-100F"), box("FW-WEST", FGT.format(name="CL1", gid=7), "firewall", "FG-100F"),
              box("FW-LONE", FGT.format(name="CL2", gid=9), "firewall", "FG-100F"))
    assert out[0]["pair_with"] == "d2" and out[2].get("pair_with") in (None, "") and out[2]["pair_missing"] == "FortiGate HA"


def test_pan_os_ha_members_name_each_others_ha1_address():
    out = run(box("PA-ONE", PAN.format(gid=1, me="1.1.1.1", peer="1.1.1.2"), "firewall", "PA-3220"), box("PA-TWO", PAN.format(gid=1, me="1.1.1.2", peer="1.1.1.1"), "firewall", "PA-3220"))
    assert out[0]["pair_with"] == "d2" and out[0]["ha"].startswith("PAN-OS HA pair")


def test_f5_members_list_each_other_in_the_device_group():
    out = run(box("LB-NORTH.example.test", F5.format(a="lb-north.example.test", b="lb-south.example.test"), "load_balancer", "i5800"),
              box("LB-SOUTH.example.test", F5.format(a="lb-north.example.test", b="lb-south.example.test"), "load_balancer", "i5800"))
    assert out[0]["pair_with"] == "d2"


def test_asa_failover_needs_one_primary_and_one_secondary():
    ok = run(box("EDGE-A", ASA.format(unit="primary"), "firewall", "ASA5545"), box("EDGE-B", ASA.format(unit="secondary"), "firewall", "ASA5545"))
    assert ok[0]["pair_with"] == "d2"
    bad = run(box("EDGE-A", ASA.format(unit="primary"), "firewall", "ASA5545"), box("EDGE-B", ASA.format(unit="primary"), "firewall", "ASA5545"))
    assert not bad[0].get("pair_with")


def test_a_show_only_capture_is_paired_by_domain_and_the_neighbour_tables():
    show = "vPC domain id                     : 240\nvPC role : primary\nDevice ID:{other}.example.test(FDO1)\n"
    out = run(box("ALPHA-SW", show.format(other="ZULU-SW")), box("ZULU-SW", show.format(other="ALPHA-SW")))
    assert out[0]["pair_with"] == "d2"


def test_pair_facts_survive_saving_and_opening_a_project():
    from features.sizing_tool.project import clean_asset
    out = run(box("ALPHA-SW", VPC.format(dom=10, me="10.0.0.1", peer="10.0.0.2")), box("ZULU-SW", VPC.format(dom=10, me="10.0.0.2", peer="10.0.0.1")))
    back = clean_asset(out[0])
    assert back["ha_facts"]["kind"] == "vPC" and back["pair_with"] == "d2" and back["ha_facts"]["peer"] == ["10.0.0.2"]
