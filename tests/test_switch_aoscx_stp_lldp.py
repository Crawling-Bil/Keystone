"""AOS-CX: ``show spanning-tree detail`` (transitions to forwarding, topology changes), ``show lldp configuration`` and the empty
``show port-access clients`` answer. The command output is invented (names, MACs); it is appended to a masked real capture so the
switch is detected as AOS-CX."""
from __future__ import annotations

from pathlib import Path

from features.switch_analyzer import aoscx, capture_text, service

BASE = (Path(__file__).parent / "fixtures" / "real_captures" / "aoscx_vsf4_version_inventory_vsf_masked.txt").read_text(encoding="utf-8")
PROMPT = "LAB-CX-1"


def _stp(changes: int = 284, last: str = "170577 seconds ago", port_moves: int = 60, flag: str = "False") -> str:
    return f"""Spanning tree status           : Enabled Protocol: RPVST
Extended System-id             : Enabled

VLAN100
  Root ID    Priority   : 32768
             MAC-Address: 02:00:00:00:00:c0
             This bridge is the root
             Hello time(in seconds):2  Max Age(in seconds):20
             Forward Delay(in seconds):15

  Bridge ID  Priority  : 32768
             MAC-Address: 02:00:00:00:00:c0
             Hello time(in seconds):2  Max Age(in seconds):20
             Forward Delay(in seconds):15

Port         Role           State      Cost           Priority   Type       BPDU-Tx    BPDU-Rx    TCN-Tx     TCN-Rx
------------ -------------- ---------- -------------- ---------- ---------- ---------- ---------- ---------- ----------
1/1/1        Designated     Forwarding 20000          128        P2P        2077664    136        132        21
1/1/2        Disabled       Down       20000          128        Shr        0          0          0          0
lag1         Designated     Forwarding 20000          64         P2P        2077504    196        95         2

Topology change flag          : {flag}
Number of topology changes    : {changes}
Last topology change occurred : {last}

Port 1/1/1
Designated root has priority               :32768 Address: 02:00:00:00:00:c0
Designated bridge has priority             :32768 Address: 02:00:00:00:00:c0
Designated port                            :1/1/1
Number of transitions to forwarding state  : {port_moves}
Bpdus sent 2077664, received 136
TCN_Tx: 132, TCN_Rx: 21

Port 1/1/2
Designated root has priority               :32768 Address: 02:00:00:00:00:c0
Designated bridge has priority             :32768 Address: 02:00:00:00:00:c0
Designated port                            :1/1/2
Number of transitions to forwarding state  : 90
Bpdus sent 0, received 0
TCN_Tx: 0, TCN_Rx: 0

Port lag1
Designated root has priority               :32768 Address: 02:00:00:00:00:c0
Designated bridge has priority             :32768 Address: 02:00:00:00:00:c0
Designated port                            :lag1
Number of transitions to forwarding state  : 3
Bpdus sent 2077504, received 196
TCN_Tx: 95, TCN_Rx: 2
"""


def _lldp(enabled: str = "Yes", tlvs: tuple[str, ...] = ("Management Address", "Port Description", "System Name"), ports: tuple[tuple[str, str, str], ...] = (("1/1/1", "Yes", "Yes"), ("1/1/2", "Yes", "Yes"))) -> str:
    rows = "\n".join(f"{name:<14} {tx:<19} {rx:<19} Yes" for name, tx, rx in ports)
    return f"""
LLDP Global Configuration
=========================

LLDP Enabled                 : {enabled}
LLDP Transmit Interval       : 30
LLDP Hold Time Multiplier    : 4
LLDP Transmit Delay Interval : 2
LLDP Reinit Time Interval    : 2
LLDP Trap Enabled            : No

TLVs Advertised
===============

""" + "\n".join(tlvs) + f"""

LLDP Port Configuration
=======================

PORT           TX-ENABLED          RX-ENABLED          INTF-TRAP-ENABLED
--------------------------------------------------------------------------
{rows}
"""


def _lines(command: str, text: str) -> list[str]:
    return capture_text.clean_lines(f"{PROMPT}# {command}\n{text}\n{PROMPT}#\n")


def _result(command: str, text: str) -> dict:
    return service.analyze(BASE + f"\n{PROMPT}# {command}\n{text}\n{PROMPT}#\n", filename="stack.txt", vendor="Auto Detect")


def _codes(result: dict) -> dict[str, dict]:
    return {item["code"]: item for item in result["health"]["findings"]}


# ----------------------------------------------------------------------------- spanning-tree detail

def test_detail_counters_are_read_per_instance_and_per_port():
    stp = aoscx.parse_spanning_tree(_lines("show spanning-tree detail", _stp()))
    assert stp["detailed"] is True
    inst = stp["instances"][0]
    assert (inst["id"], inst["topology_changes"], inst["last_change_seconds"], inst["tc_flag"]) == ("VLAN100", 284, 170577, False)
    moves = {p["interface"]: p["forwarding_transitions"] for p in inst["ports"]}
    assert moves == {"1/1/1": 60, "1/1/2": 90, "lag1": 3}
    one = next(p for p in inst["ports"] if p["interface"] == "1/1/1")
    assert (one["bpdu_tx"], one["bpdu_rx"], one["tcn_tx"], one["tcn_rx"]) == (2077664, 136, 132, 21)
    assert (one["designated_root"], one["designated_port"]) == ("02:00:00:00:00:c0", "1/1/1")


def test_plain_show_spanning_tree_is_not_marked_detailed():
    plain = """Spanning tree status           : Enabled Protocol: RPVST
VLAN100
  Root ID    Priority   : 32768
             MAC-Address: 02:00:00:00:00:c0
             This bridge is the root
  Bridge ID  Priority  : 32768
             MAC-Address: 02:00:00:00:00:c0

Port         Role           State      Cost           Priority   Type
------------ -------------- ---------- -------------- ---------- ----------
1/1/1        Designated     Forwarding 20000          128        P2P
"""
    stp = aoscx.parse_spanning_tree(_lines("show spanning-tree", plain))
    assert not stp.get("detailed")
    assert stp["instances"][0]["ports"][0].get("forwarding_transitions") is None


def test_many_moves_to_forwarding_is_a_finding_and_disabled_ports_are_left_out():
    codes = _codes(_result("show spanning-tree detail", _stp(port_moves=60)))
    assert codes["SW-CX-021"]["severity"] == "medium"                      # 60 >= 50
    assert "1/1/1 60 times" in codes["SW-CX-021"]["text"]
    assert "1/1/2" not in codes["SW-CX-021"]["text"]                       # role Disabled: its 90 is not counted
    assert codes["SW-CX-021"]["doc"]["url"].startswith("https://arubanetworking.hpe.com/")
    low = _codes(_result("show spanning-tree detail", _stp(port_moves=12)))
    assert low["SW-CX-021"]["severity"] == "low"
    quiet = _codes(_result("show spanning-tree detail", _stp(port_moves=9)))
    assert "SW-CX-021" not in quiet


def test_topology_changes_have_a_count_threshold_and_an_age_threshold():
    old = _codes(_result("show spanning-tree detail", _stp(changes=30, last="170577 seconds ago")))
    assert old["SW-CX-022"]["severity"] == "low"
    heavy = _codes(_result("show spanning-tree detail", _stp(changes=284)))
    assert heavy["SW-CX-022"]["severity"] == "medium"                      # >= 100
    recent = _codes(_result("show spanning-tree detail", _stp(changes=5, last="120 seconds ago")))
    assert recent["SW-CX-022"]["severity"] == "medium"                     # a change within the last hour
    quiet = _codes(_result("show spanning-tree detail", _stp(changes=5, last="170577 seconds ago")))
    assert "SW-CX-022" not in quiet


# ----------------------------------------------------------------------------- lldp configuration

def test_lldp_configuration_is_read_in_full():
    config = aoscx.parse_lldp_config(_lines("show lldp configuration", _lldp(ports=(("1/1/1", "Yes", "Yes"), ("1/1/2", "Yes", "No"), ("lag1", "No", "Yes")))))
    assert (config["enabled"], config["interval"], config["hold"], config["tx_delay"], config["reinit"], config["trap"]) == (True, 30, 4, 2, 2, False)
    assert config["tlvs"] == ["Management Address", "Port Description", "System Name"]
    assert [(p["port"], p["tx"], p["rx"]) for p in config["ports"]] == [("1/1/1", True, True), ("1/1/2", True, False), ("lag1", False, True)]


def test_no_lldp_configuration_gives_an_empty_dict():
    assert aoscx.parse_lldp_config(_lines("show lldp configuration", "% Invalid input detected at '^' marker.")) == {}


def test_lldp_off_is_one_medium_finding_and_nothing_else():
    codes = _codes(_result("show lldp configuration", _lldp(enabled="No", ports=(("1/1/1", "No", "No"),))))
    assert codes["SW-CX-023"]["severity"] == "medium" and "SW-CX-024" not in codes
    assert codes["SW-CX-023"]["doc"]["url"].startswith("https://arubanetworking.hpe.com/techdocs/AOS-CX/")


def test_receive_off_on_a_port_is_a_low_finding_that_names_the_port():
    codes = _codes(_result("show lldp configuration", _lldp(ports=(("1/1/1", "Yes", "Yes"), ("1/1/2", "Yes", "No")))))
    assert codes["SW-CX-024"]["severity"] == "low"
    assert "receive is off on 1/1/2" in codes["SW-CX-024"]["text"] and "SW-CX-023" not in codes


def test_missing_management_address_tlv_is_flagged_and_present_one_is_not():
    codes = _codes(_result("show lldp configuration", _lldp(tlvs=("Port Description", "System Name"))))
    assert codes["SW-CX-025"]["severity"] == "low"
    assert "SW-CX-025" not in _codes(_result("show lldp configuration", _lldp()))


def test_a_healthy_lldp_configuration_has_the_table_and_no_finding():
    result = _result("show lldp configuration", _lldp())
    assert not {"SW-CX-023", "SW-CX-024", "SW-CX-025"} & set(_codes(result))
    table = next(t for t in result["extra_tables"] if t["id"] == "cx-lldp")
    values = {row["item"]: row["value"] for row in table["rows"]}
    assert values["LLDP enabled"] == "Yes" and "30 s x 4 = 120 s" in values["Transmit interval / hold multiplier"]
    assert values["Ports"].startswith("2 listed, 2 with transmit and receive on")
    status = {row["command"]: row["status"] for row in result["coverage"]["rows"]}
    assert status["show lldp configuration"] == "analyzed"


# ----------------------------------------------------------------------------- port-access

def test_port_access_with_no_client_is_an_empty_answer_not_unparsed():
    assert aoscx.parse_port_access_empty(_lines("show port-access clients", "No port-access clients found.")) is True
    assert aoscx.parse_port_access_empty(_lines("show port-access clients", "Port Access Client Status Details")) is False
    result = _result("show port-access clients", "No port-access clients found.")
    row = next(r for r in result["coverage"]["rows"] if r["command"] == "show port-access clients")
    assert row["status"] == "ignored" and "No port-access clients found" in row["note"]


def test_port_access_with_clients_is_still_reported_as_not_parsed():
    listing = "Port Access Client Status Details\n\nClient 02:00:00:00:00:01, user1\n=======================================\n  Session Details\n  ---------------\n  Port   : 1/1/5\n  Session Time : 40s\n"
    result = _result("show port-access clients", listing)
    row = next(r for r in result["coverage"]["rows"] if r["command"] == "show port-access clients")
    assert row["status"] == "not parsed"
