"""Switch Analyzer: time synchronisation (NTP) and spanning-tree inconsistent ports.

Captures are synthetic copies of the layouts seen on Catalyst 9300 (IOS XE 17.3), AOS-CX 10.16, Nexus 9000 and the Huawei V600R025C00 command reference;
host names and addresses are invented (RFC 5737).
"""

from __future__ import annotations

from features.switch_analyzer import capture_text, ntp, service, stp_inconsistent

IOS = """\
SW1#show ntp status
Clock is synchronized, stratum 4, reference is 192.0.2.10
nominal freq is 250.0000 Hz, actual freq is 249.9971 Hz, precision is 2**10
clock offset is -5.5000 msec, root delay is 14.39 msec
system poll interval is 512, last update was 349 sec ago.
SW1#
SW1#show ntp associations

  address         ref clock       st   when   poll reach  delay  offset   disp
+~192.0.2.11      192.0.2.99       3     37    512   377  0.623  -4.861  3.257
 ~198.51.100.5    .TIME.          16   434d     64     0  0.000   0.000 15937.
*~192.0.2.10      192.0.2.50       4     41    512   377  1.000  -5.500  4.414
 * sys.peer, # selected, + candidate, - outlyer, x falseticker, ~ configured
SW1#
"""

IOS_UNSYNC = """\
SW2#show ntp status
Clock is unsynchronized, stratum 16, no reference clock
clock offset is 0.0000 msec, root delay is 0.00 msec
system poll interval is 64, last update was 152392907 sec ago.
SW2#
"""

AOSCX = """\
CX1# show ntp status
NTP Status Information

NTP                        : Enabled
NTP Authentication         : Disabled

NTP Synchronization Information

NTP Server                 : 192.0.2.10 at stratum 4
Poll interval              : 1024 seconds
Time accuracy              : Within 0.009969 seconds
CX1#
CX1# show ntp associations
----------------------------------------------------------------------
 ID            NAME          REMOTE          REF-ID ST LAST POLL REACH
----------------------------------------------------------------------
* 1  192.0.2.10  192.0.2.10    192.0.2.99  4  690 1024   377
+ 2  192.0.2.11  192.0.2.11     192.0.2.98  4  940 1024   377
  3  ntp.example. 198.51.100.7          .STEP. 16    -   16     0
----------------------------------------------------------------------
CX1#
"""

NXOS = """\
NX1# show ntp peer-status
Total peers : 4
* - selected for sync, + -  peer mode(active),
- - peer mode(passive), = - polled in client mode
    remote                                 local                                   st   poll   reach delay   vrf
-----------------------------------------------------------------------------------------------------------------------
=198.51.100.5                            0.0.0.0                                 16   64       0   0.00000management
=192.0.2.11                              0.0.0.0                                  4   64     377   0.00198management
*192.0.2.10                              0.0.0.0                                  3   64     377   0.00076management
NX1#
"""

VRP = """\
<HUAWEI>display ntp status
 clock status: synchronized
 clock stratum: 2
 reference clock ID: 192.0.2.10
 clock offset: 0.5995 ms
 root delay: 0.00 ms
<HUAWEI>display ntp sessions
clock source: 192.0.2.10
 clock stratum: 2
 clock status: configured, master, sane, valid
 reference clock ID: LOCAL(0)
 reach: 255
 current poll: 1024
 now: 355
 offset: 0.5995 ms
 delay: 3.01 ms
 disper: 25.42 ms
clock source: 198.51.100.9
 clock stratum: 16
 clock status: configured, unsynced, insane, invalid
 reference clock ID: none
 reach: 0
 current poll: 64
 now: 0
 offset: 0.0000 ms
 delay: 0.00 ms
 disper: 0.00 ms
<HUAWEI>
"""


def _view(text: str) -> dict:
    return ntp.read(capture_text.clean_lines(text))


def _ids(view: dict) -> set[str]:
    return {item["id"] for item in ntp.findings(view)}


def test_ios_status_and_associations_are_read():
    view = _view(IOS)
    assert view["status"]["synchronized"] is True and view["status"]["stratum"] == 4 and view["status"]["offset_ms"] == -5.5
    states = {peer["address"]: peer["state"] for peer in view["peers"]}
    assert states["192.0.2.10"].startswith("sys.peer") and states["192.0.2.11"] == "candidate" and states["198.51.100.5"] == ""
    assert [peer["usable"] for peer in view["peers"]] == [True, False, True]


def test_ios_one_dead_server_is_a_low_finding_only():
    assert _ids(_view(IOS)) == {"SW-NTP-004"}


def test_unsynchronised_clock_is_high():
    items = ntp.findings(_view(IOS_UNSYNC))
    assert [item["id"] for item in items] == ["SW-NTP-001"] and items[0]["severity"] == "high"


def test_aoscx_layout():
    view = _view(AOSCX)
    assert view["status"]["dialect"] == "aoscx" and view["status"]["synchronized"] is True and view["status"]["stratum"] == 4
    assert [(peer["address"], peer["usable"]) for peer in view["peers"]] == [("192.0.2.10", True), ("192.0.2.11", True), ("198.51.100.7", False)]
    assert _ids(view) == {"SW-NTP-004"}


def test_nxos_peer_status_derives_the_state_from_the_selected_peer():
    view = _view(NXOS)
    assert view["status"]["synchronized"] is True and view["status"]["reference"] == "192.0.2.10"
    assert {peer["address"]: peer["vrf"] for peer in view["peers"]}["192.0.2.11"] == "management"


def test_nxos_without_a_selected_peer_is_unsynchronised():
    view = _view(NXOS.replace("*192.0.2.10 ", "=192.0.2.10 "))
    assert view["status"]["synchronized"] is False and "SW-NTP-001" in _ids(view)


def test_huawei_status_and_sessions():
    view = _view(VRP)
    assert view["status"]["dialect"] == "vrp" and view["status"]["synchronized"] is True and view["status"]["stratum"] == 2
    assert [(peer["address"], peer["usable"]) for peer in view["peers"]] == [("192.0.2.10", True), ("198.51.100.9", False)]
    assert _ids(view) == {"SW-NTP-003", "SW-NTP-004"}      # one usable of two


def test_all_servers_dead_without_a_status_line():
    view = _view(NXOS.replace("*192.0.2.10", "=192.0.2.10").replace("377", "  0"))
    assert "SW-NTP-002" in _ids(view) or "SW-NTP-001" in _ids(view)


def test_a_rejected_command_gives_nothing():
    assert _view("SW#show ntp status\n% Invalid input detected at '^' marker.\nSW#\n")["status"] == {}


def test_the_analyzer_exposes_the_tables_findings_and_coverage_counts():
    config = ("SW1#show running-config\nBuilding configuration...\nversion 17.3\nhostname SW1\n!\nvlan 10\n name USERS\n!\n"
              "interface GigabitEthernet1/0/1\n switchport access vlan 10\n switchport mode access\n!\nntp server 192.0.2.10\nend\nSW1#\n")
    result = service.analyze(config + IOS, filename="sw1.txt")
    ids = {table["id"] for table in result["extra_tables"]}
    assert {"ntp-status", "ntp-peers"} <= ids
    assert result["extras"]["ntp_status"] == 1 and result["extras"]["ntp_peers"] == 3
    assert "SW-NTP-004" in {item["id"] for item in result["findings"]}
    rows = {row["command"]: row for row in result["coverage"]["rows"]}
    assert rows["show ntp status"]["status"] != "not parsed" and rows["show ntp associations"]["status"] != "not parsed"


# ------------------------------------------------------------------------------------ inconsistent ports
CLEAN_STP = """\
SW#show spanning-tree inconsistentports

Name                 Interface                      Inconsistency
-------------------- ------------------------------ ------------------

Number of inconsistent ports (segments) in the system : 0

SW#
"""

BROKEN_STP = CLEAN_STP.replace("\nNumber", "VLAN0010             GigabitEthernet1/0/24          Root Inconsistent\n\nNumber").replace(": 0", ": 1")


def test_inconsistent_ports_all_clear_is_not_a_finding():
    view = stp_inconsistent.read(capture_text.clean_lines(CLEAN_STP))
    assert view == {"captured": True, "count": 0, "ports": []} and stp_inconsistent.findings(view) == []


def test_inconsistent_port_is_high_and_names_the_reason():
    view = stp_inconsistent.read(capture_text.clean_lines(BROKEN_STP))
    assert view["count"] == 1 and view["ports"][0]["port"] == "GigabitEthernet1/0/24"
    item = stp_inconsistent.findings(view)[0]
    assert item["id"] == "SW-STP-102" and item["severity"] == "high" and "Root Inconsistent" in item["detail"]
