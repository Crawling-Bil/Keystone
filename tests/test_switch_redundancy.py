"""Redundancy (SSO) state, history and the CDP detail fields, on invented captures that follow the layouts of real IOS-XE 17.12 output."""

from __future__ import annotations

from features.switch_analyzer import capture_text, redundancy, runtime_parser, service

DUPLEX = """SW1#show redundancy states
       my state = 13 -ACTIVE
     peer state = 8  -STANDBY HOT
           Mode = Duplex
           Unit = Primary
        Unit ID = 1

Redundancy Mode (Operational) = sso
Redundancy Mode (Configured)  = sso
Redundancy State              = sso
     Maintenance Mode = Disabled
    Manual Swact = enabled
 Communications = Up

   client count = 121
SW1#
"""
SIMPLEX = DUPLEX.replace("8  -STANDBY HOT", "1  -DISABLED").replace("Duplex", "Simplex").replace("Operational) = sso", "Operational) = Non-redundant") \
    .replace("Communications = Up", "Communications = Down      Reason: Simplex mode")
HISTORY = """SW1#show redundancy history
00:00:07 client added: Redundancy Mode RF(29) seq=60
00:00:07 *my state = INITIALIZATION(2) peer state = DISABLED(1)
00:00:11 *my state = ACTIVE(13) peer state = DISABLED(1)
00:00:59  my state = ACTIVE(13) *peer state = STANDBY COLD(4)
Sep  3 12:43:23.042  my state = ACTIVE(13) *peer state = STANDBY HOT(8)
Sep  9 01:10:00.100  my state = ACTIVE(13) *peer state = DISABLED(1)
Sep  9 01:12:00.100  my state = ACTIVE(13) *peer state = STANDBY HOT(8)
SW1#
"""
SWITCHOVER = """SW1#show redundancy history
00:00:07 *my state = INITIALIZATION(2) peer state = DISABLED(1)
00:00:09  my state = STANDBY HOT(8) *peer state = ACTIVE(13)
Sep  9 01:10:00.100 *my state = ACTIVE(13) peer state = DISABLED(1)
SW1#
"""


def _read(text):
    return redundancy.read(capture_text.clean_lines(text))


def test_states_duplex_and_simplex():
    duplex = _read(DUPLEX)["states"]
    assert (duplex["my_state"], duplex["peer_state"], duplex["mode"], duplex["communications"]) == ("ACTIVE", "STANDBY HOT", "Duplex", "Up")
    simplex = _read(SIMPLEX)["states"]
    assert simplex["peer_state"] == "DISABLED" and simplex["operational_mode"] == "Non-redundant"
    assert (simplex["communications"], simplex["communications_reason"]) == ("Down", "Simplex mode")


def test_history_keeps_only_the_transitions_and_counts_standby_losses():
    history = _read(HISTORY)["history"]
    assert history["transitions"] == 6
    assert history["standby_losses"] == 1 and history["switchovers"] == 0
    assert [event["event"] for event in history["events"]] == [
        "Redundancy Facility started", "This unit became ACTIVE", "Standby reached STANDBY HOT", "Standby left STANDBY HOT (now DISABLED)", "Standby reached STANDBY HOT",
    ]


def test_switchover_is_counted_when_this_unit_goes_from_standby_to_active():
    history = _read(SWITCHOVER)["history"]
    assert history["switchovers"] == 1
    ids = [item["id"] for item in redundancy.findings(_read(SWITCHOVER), {"stack": {"member_count": 1}})]
    assert "SW-RED-006" in ids


def test_findings_follow_the_stack_size():
    stack2, stack1 = {"stack": {"member_count": 2}}, {"stack": {"member_count": 1}}
    simplex = _read(SIMPLEX)
    assert [(f["id"], f["severity"]) for f in redundancy.findings(simplex, stack2) if f["id"] in {"SW-RED-001", "SW-RED-002"}] == [("SW-RED-001", "high")]
    assert [(f["id"], f["severity"]) for f in redundancy.findings(simplex, stack1) if f["id"] in {"SW-RED-001", "SW-RED-002"}] == [("SW-RED-002", "info")]
    assert redundancy.findings(_read(DUPLEX), stack2) == []


def test_peer_that_is_not_hot_is_reported():
    cold = _read(DUPLEX.replace("8  -STANDBY HOT", "4  -STANDBY COLD"))
    assert [f["id"] for f in redundancy.findings(cold, {"stack": {"member_count": 2}})] == ["SW-RED-003"]


def test_full_show_redundancy_report():
    block = ["Redundant System Information :", "Available system uptime = 2 years, 5 weeks", "Switchovers system experienced = 2", "Standby failures = 1",
             "Last switchover reason = active unit failed", "Hardware Mode = Duplex", "Configured Redundancy Mode = sso", "Operating Redundancy Mode = sso",
             "Current Processor Information :", "Current Software state = ACTIVE", "Uptime in current state = 3 days"]
    full = redundancy.parse_full(block)
    assert full["switchovers"] == "2" and full["last_switchover_reason"] == "active unit failed" and full["software_state"] == "ACTIVE"


def test_analyze_wires_it_into_findings_tables_and_coverage():
    config = "hostname SW1\ninterface GigabitEthernet1/0/1\n shutdown\n"
    result = service.analyze(config + DUPLEX + HISTORY, filename="sw1.txt")
    assert result["redundancy"]["states"]["peer_state"] == "STANDBY HOT"
    assert {"redundancy-state", "redundancy-events"} <= {table["id"] for table in result["extra_tables"]}
    rows = {row["command"]: row["status"] for row in result["coverage"]["rows"]}
    assert rows["show redundancy states"] == "analyzed" and rows["show redundancy history"] == "analyzed"
    assert any(f["id"] == "SW-RED-007" for f in result["findings"])


CDP = """SW1#show cdp neig detail
-------------------------
Device ID: DS1.example.net
Entry address(es):
  IP address: 10.0.0.9
Platform: cisco C9500-48Y4C,  Capabilities: Router Switch IGMP
Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): TwentyFiveGigE2/0/2
Holdtime : 174 sec

Version :
Cisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.12.5, RELEASE SOFTWARE (fc5)

advertisement version: 2
Native VLAN: 20
Duplex: full
Management address(es):
  IP address: 10.0.0.1
SW1#
"""


def test_cdp_detail_keeps_management_address_software_and_native_vlan():
    rows = runtime_parser.parse_neighbors(capture_text.clean_lines(CDP))
    assert len(rows) == 1
    row = rows[0]
    assert (row["neighbor_id"], row["platform"], row["local_interface"]) == ("DS1.example.net", "C9500-48Y4C", "TenGigabitEthernet1/1/1")
    assert (row["management_address"], row["software"], row["native_vlan"], row["duplex"], row["holdtime"]) == ("10.0.0.1", "IOS XE 17.12.5", "20", "full", "174")


def test_incomplete_transceiver_command_gets_a_hint_not_a_guess_for_others():
    clean = capture_text.clean_lines("SW1#show inter transceiver\n% Incomplete command.\n\nSW1#show ip arp\n% Incomplete command.\n")
    rows = {row["command"]: row["note"] for row in service.coverage.build_coverage(clean, "Cisco", {})["rows"] if row["status"] == "error"}
    assert "show interfaces transceiver detail" in rows["show interface transceiver"]
    assert "transceiver" not in rows["show ip arp"]
