"""Switch Analyzer: Huawei VRP live state (stack, dual-active, VLAN count, ARP statistics, licence, MSTP region).

The layouts were checked against real S5735-S-V2 / S5755-H captures; the fixture here is synthetic (invented host name, MAC addresses and region name).
"""
from __future__ import annotations

from pathlib import Path

from features.switch_analyzer import huawei_live, service

FIXTURE = Path(__file__).parent / "fixtures" / "switch" / "huawei_s5735_stack_synthetic.txt"


def _result(text: str | None = None) -> dict:
    return service.analyze(text if text is not None else FIXTURE.read_text(encoding="utf-8"), filename="stack.txt", vendor="Huawei")


def _findings(result: dict) -> dict[str, dict]:
    return {item["code"]: item for item in result["health"]["findings"]}


def test_stack_members_and_topology_are_read():
    live = _result()["health"]["live"]
    assert [(m["member"], m["role"], m["priority"]) for m in live["stack"]] == [(1, "Master", 200), (2, "Slave", 100)]
    assert live["topology"]["type"] == "Link"
    assert live["topology"]["members"][0] == {"member": 1, "port1": "up", "neighbor1": "2", "port2": "down", "neighbor2": "--"}
    assert {l["port"] for l in live["topology"]["links"]} >= {"GE1/0/21", "10GE1/0/5"}


def test_stack_configuration_marks_media_mismatch_ports():
    config = _result()["health"]["live"]["stack_configuration"]
    assert [(m["member"], m["priority"]) for m in config["members"]] == [(1, 200), (2, 100)]
    first = config["stack_ports"][0]
    assert first["stack_port"] == "Stack-Port1/1"
    assert [(p["port"], p["mismatch"]) for p in first["ports"]] == [("GE1/0/21", False), ("10GE1/0/5", True)]


def test_a_stack_without_ring_standby_or_dual_active_detection_is_reported():
    codes = _findings(_result())
    assert codes["SW-STK-001"]["severity"] == "high"
    assert codes["SW-STK-002"]["severity"] == "medium" and "Only one physical stack link" in codes["SW-STK-002"]["title"]
    assert "member 1 stack-port 2" in codes["SW-STK-002"]["text"]
    assert codes["SW-STK-003"]["severity"] == "medium"
    assert codes["SW-STK-005"]["title"].startswith("2 stack troubleshooting")
    assert codes["SW-STK-002"]["doc"]["url"].startswith("https://support.huawei.cn/enterprise/en/doc/EDOC1100458710")


def test_a_healthy_ring_and_a_single_switch_raise_no_stack_finding():
    ring = FIXTURE.read_text(encoding="utf-8")
    ring = ring.replace("Slave    0200", "Standby  0200").replace("Stack Topology Type: Link", "Stack Topology Type: Ring")
    ring = ring.replace("Dual-active detect mode: --", "Dual-active detect mode: Direct").replace("Total :2", "Total :0")
    assert not [code for code in _findings(_result(ring)) if code.startswith("SW-STK")]
    single = """<SW-ONE>display stack
MemberID Role     MAC              Priority   DeviceType              Description
1        Master   0200-5e00-0050   100        S5735-S24P4XE-V2
<SW-ONE>display stack topology
Stack Topology Type: Link
               Stack-Port 1      Stack-Port 2
MemberID   Status Neighbor   Status Neighbor
1          down   --         down   --
<SW-ONE>display dual-active
Stack domainID: --
Dual-active status: --
Dual-active detect mode: --
"""
    assert not [code for code in _findings(_result(single)) if code.startswith("SW-STK")]


def test_vlan_summary_expands_ranges_and_joins_wrapped_lines():
    summary = _result()["health"]["live"]["vlan_summary"]
    assert summary["static"]["count"] == 14
    assert summary["static"]["ids"] == [1, 10, 11, 12, 13, 14, 15, 20, 25, 53, 54, 100, 102, 103]
    assert summary["dynamic"] == {"count": 0, "ids": []}


def test_a_vlan_id_list_that_disagrees_with_the_count_is_flagged():
    text = FIXTURE.read_text(encoding="utf-8").replace("Number of static VLAN: 14", "Number of static VLAN: 20")
    assert "SW-CAP-101" in _findings(_result(text))
    assert "SW-CAP-101" not in _findings(_result())


def test_arp_statistics_incomplete_entries_are_reported_as_information():
    result = _result()
    assert result["health"]["live"]["arp_statistics"] == {"dynamic": 9, "resolved": 7, "incomplete": 2, "static": 0, "redirect": 0}
    assert _findings(result)["SW-ARP-001"]["severity"] == "info"
    older = huawei_live.parse_arp_statistics(["Dynamic: 6  (Resolved: 6  Incomplete: 0)  Static: 0"])
    assert older["redirect"] is None and older["incomplete"] == 0


def test_dual_active_listing_keeps_interfaces_per_section():
    text = FIXTURE.read_text(encoding="utf-8")
    dual = huawei_live.parse_dual_active(text[text.index("display dual-active"):].splitlines()[1:])
    assert dual["mode"] == "--" and dual["status"] == "--"
    assert dual["direct"] == [] and dual["excluded_fixed"] == ["GE1/0/21", "GE1/0/22"]


def test_licence_region_and_port_link_types_are_summarised():
    display = _result()["health"]["stack"]["display"]
    assert display["licence"] == "no licence activated"
    assert display["mstp_region"] == "LAB-REGION, revision 0"
    assert display["port_link_types"] == "access 2, auto 2, trunk 1"


def test_coverage_reads_the_new_commands_and_does_not_call_a_silent_eth_trunk_missing():
    rows = {row["command"]: row for row in _result()["coverage"]["rows"]}
    for command in ("display stack topology", "display stack configuration", "display dual-active", "display vlan summary", "display arp statistics",
                    "display stp region-configuration", "display license", "display port vlan", "display lacp brief"):
        assert rows[command]["status"] == "analyzed", command
    assert rows["display eth-trunk"]["status"] == "ignored" and "no Eth-Trunk exists" in rows["display eth-trunk"]["note"]
    assert [row for row in _result()["coverage"]["rows"] if row["status"] == "missing" and row["command"] == "display eth-trunk"] == []


def test_stack_ports_last_down_reason_is_parsed():
    lines = """Stack-Port :
Stack-Port                : Stack-Port1/1
Stack-Port Protocol State : down
Member Port(s) State :
  Interface      : 10GE1/0/5
  Protocol State : down
  Physical State : down
  Down Reason    : The physical state is down.
  Down Time      : 2026-01-02 03:04:05.678
""".splitlines()
    info = huawei_live.parse_stack_port_down(lines)
    assert info["ports"] == [{"stack_port": "Stack-Port1/1", "interface": "10GE1/0/5", "reason": "The physical state is down.", "time": "2026-01-02 03:04:05.678"}]
    assert huawei_live.parse_stack_port_down(["Info: The last-down-reason record does not exist."])["none_recorded"] is True


def test_a_three_member_chain_is_reported_but_a_two_member_pair_with_two_links_is_not():
    chain = {"stack": [{"member": 1, "role": "Master"}, {"member": 2, "role": "Standby"}, {"member": 3, "role": "Slave"}],
             "topology": {"type": "Link", "members": [{"member": 1, "port1": "down", "neighbor1": "--", "port2": "up", "neighbor2": "2"}], "links": []},
             "dual_active": {"mode": "Direct", "status": "Normal"}}
    codes = {rule[0]: rule for rule in huawei_live.rules(chain)}
    assert codes["SW-STK-002"][2] == "The 3-member stack is a chain, not a ring"
    pair = {"stack": [{"member": 1, "role": "Master"}, {"member": 2, "role": "Standby"}],
            "topology": {"type": "Link", "members": [], "links": [{"status": "up"}, {"status": "up"}]},
            "dual_active": {"mode": "Direct", "status": "Normal"}}
    assert not [rule for rule in huawei_live.rules(pair) if rule[0] == "SW-STK-002"]


HISTORY_FIXTURE = Path(__file__).parent / "fixtures" / "switch" / "huawei_stack_history_synthetic.txt"


def test_stack_history_records_are_classified_across_the_80_column_wrap():
    """The device cuts the description at 80 columns, inside a word ("Sta" / "ck-Port") or between words with the space lost."""
    history = _result(HISTORY_FIXTURE.read_text(encoding="utf-8"))["health"]["live"]["stack_history"]
    assert history["total"] == 4 and len(history["records"]) == 4
    assert history["kinds"] == {"stack_port_down": 1, "member_port_down": 1, "one_link": 1, "link_threshold": 1}
    assert (history["first"], history["last"]) == ("2026-01-05 08:29:59", "2026-01-05 09:01:10")
    text = _findings(_result(HISTORY_FIXTURE.read_text(encoding="utf-8")))["SW-STK-005"]["text"]
    assert "span 2026-01-05 08:29:59 to 2026-01-05 09:01:10" in text and "1 stack port down" in text


def test_a_missing_dual_active_capture_is_not_reported_as_no_detection():
    """No `display dual-active` in the capture means unknown, not "Dual-active detect mode: --"."""
    result = _result(HISTORY_FIXTURE.read_text(encoding="utf-8"))
    assert "dual_active" not in result["health"]["live"]
    assert "SW-STK-003" not in _findings(result)
    assert huawei_live.parse_dual_active(["Error: Unrecognized command found at '^' position."]) == {}


def test_an_eth_trunk_inside_one_stack_member_is_reported_and_a_cross_member_one_is_not():
    findings = [item for item in _result(HISTORY_FIXTURE.read_text(encoding="utf-8"))["health"]["findings"] if item["code"] == "SW-STK-007"]
    assert [item["where"] for item in findings] == ["Eth-Trunk1"]          # GE1/0/4 + GE1/0/5; Eth-Trunk2 is GE1/0/6 + GE2/0/6
    assert "member 1" in findings[0]["title"]
