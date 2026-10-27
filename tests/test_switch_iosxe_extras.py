"""Switch Analyzer: CPU, memory, interface queue drops, BGP neighbors and route counts of a Cisco IOS XE router. Synthetic captures only."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture  # noqa: E402

from features.switch_analyzer import capture_text, iosxe_extras as ix  # noqa: E402
from features.switch_analyzer.service import analyze  # noqa: E402

CPU = """CPU utilization for five seconds: 91%/40%; one minute: 88%; five minutes: 85%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
 110    15460059    38233500          0 60.66% 58.34% 55.38%   0 DBAL EVENTS
  91     4983161     5109237        975  9.71%  8.36%  7.28%   0 IOSD ipc task
   5           0           1          0  0.00%  0.00%  0.00%   0 IPC ISSU Dispatc
"""

MEMORY = """Processor Pool Total: 1000000000 Used:  920000000 Free:   80000000
 lsmpi_io Pool Total:    6295128 Used:    6294296 Free:        832

 PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process
   0   0  973457632  639319672  315177024          0          0 *Init*
 519   0   34437416      51720   34761696          0          0 SBC main process
 538   0 8358018744  710037216  998000000          0          0 BGP Router
"""

QUEUES = """
 *: interface is up
 IHQ: pkts in input hold queue     IQD: pkts dropped from input queue
 OHQ: pkts in output hold queue    OQD: pkts dropped from output queue

  Interface                   IHQ       IQD       OHQ       OQD      RXBS      RXPS      TXBS      TXPS      TRTL
-----------------------------------------------------------------------------------------------------------------
* GigabitEthernet0/0/0          0         0         0         0  43960000     25526 145001000     28926         0
* GigabitEthernet0/0/1          0         5         0      4200  16210000     31213  58751000     27761         0
  GigabitEthernet0/0/2          0         0         0        12         0         0         0         0         3
* Tunnel1                       0         0         0         0      2000         0      8000         1         0
"""

BGP = """BGP router identifier 192.0.2.1, local AS number 64512
BGP table version is 100, main routing table version 100
10 network entries using 2480 bytes of memory

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
198.51.100.9    4        65535       0       0        1    0    0 8y29w    Idle (Admin)
198.51.100.10   4        65535  103469   93148      100    0    0 1y31w         733
203.0.113.5     4        64942       0       0        1    0    0 3w5d     Idle
203.0.113.6     4        65128       0       0        1    0    0 never    Idle
2001:db8:1234:5678::1
                4        65001       9       9      100    0    0 00:01:02 Active
"""

ROUTES = """IP routing table name is default (0x0)
IP routing table maximum-paths is 32
Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
connected       0           19          0           1752        5472
static          2           16          0           2144        5184
ospf 172        1           6518        0           642048      1903548
  Intra-area: 39 Inter-area: 4 External-1: 6260 External-2: 216
bgp 64512       0           746         0           84048       214848
  External: 746 Internal: 0 Local: 0
internal        59                                              593952
Total           62          7299        0           729992      2723004
"""


def _lines(text: str) -> list[str]:
    return text.splitlines()


def test_cpu_reads_the_header_and_sorts_the_processes_by_five_minute_average():
    cpu = ix.parse_cpu(_lines(CPU))
    assert (cpu["five_sec"], cpu["interrupt"], cpu["one_min"], cpu["five_min"]) == (91, 40, 88, 85)
    assert [row["process"] for row in cpu["top"]] == ["DBAL EVENTS", "IOSD ipc task", "IPC ISSU Dispatc"]
    assert cpu["top"][0]["five_min"] == 55.38


def test_memory_pools_and_the_holding_column_not_the_freed_column():
    memory = ix.parse_memory(_lines(MEMORY))
    processor = memory["pools"][0]
    assert processor["pool"] == "Processor" and processor["used_pct"] == 92.0
    assert [row["process"] for row in memory["top"][:2]] == ["BGP Router", "*Init*"]
    assert memory["top"][0]["holding"] == 998000000                  # Holding is the fifth number; Freed (710037216) is the fourth


def test_interface_queue_rows_keep_the_up_star_and_every_counter():
    rows = {row["interface"]: row for row in ix.parse_interfaces_summary(_lines(QUEUES))}
    assert len(rows) == 4
    assert rows["GigabitEthernet0/0/1"] == {"interface": "GigabitEthernet0/0/1", "up": True, "ihq": 0, "iqd": 5, "ohq": 0, "oqd": 4200,
                                            "rxbs": 16210000, "rxps": 31213, "txbs": 58751000, "txps": 27761, "trtl": 0}
    assert rows["GigabitEthernet0/0/2"]["up"] is False and rows["GigabitEthernet0/0/2"]["trtl"] == 3


def test_bgp_summary_joins_a_wrapped_neighbor_row_and_tells_the_down_states_apart():
    bgp = ix.parse_bgp_summary(_lines(BGP))
    assert (bgp["router_id"], bgp["local_as"]) == ("192.0.2.1", "64512")
    by = {row["neighbor"]: row for row in bgp["neighbors"]}
    assert len(by) == 5
    assert by["198.51.100.10"]["state"] == "Established" and by["198.51.100.10"]["prefixes"] == 733
    assert by["2001:db8:1234:5678::1"]["state"] == "Active"          # the address was printed on its own line
    assert {n: ix.bgp_neighbor_problem(r) for n, r in by.items()} == {
        "198.51.100.9": "admin", "198.51.100.10": "", "203.0.113.5": "down", "203.0.113.6": "never", "2001:db8:1234:5678::1": "down"}


def test_route_summary_reads_every_source_including_internal_and_total():
    routes = ix.parse_route_summary(_lines(ROUTES))
    assert routes["table"] == "default"
    by = {row["source"]: row for row in routes["sources"]}
    assert by["ospf 172"] == {"source": "ospf 172", "networks": 1, "subnets": 6518, "memory": 1903548}
    assert by["internal"] == {"source": "internal", "networks": 59, "subnets": 0, "memory": 593952}
    assert by["Total"]["subnets"] == 7299


def _capture(extra: str) -> str:
    return iosxe_capture("WANR-1", "FOC00000001", "10.0.0.1", cdp=[], extra=extra)


def _commands() -> str:
    return ("WANR-1#show processes cpu sorted\n" + CPU + "WANR-1#show processes memory sorted\n" + MEMORY + "WANR-1#show interfaces summary\n" + QUEUES
            + "WANR-1#show ip bgp summary\n" + BGP + "WANR-1#show ip route summary\n" + ROUTES)


def test_the_five_findings_are_raised_with_a_cisco_page_and_the_tables_are_on_the_health_tab():
    result = analyze(_capture(_commands()), filename="wanr-1.txt")
    codes = {item["code"]: item for item in result["health"]["findings"]}
    assert {"SW-IOS-001", "SW-IOS-002", "SW-IOS-003", "SW-IOS-004", "SW-IOS-005"} <= set(codes)
    assert codes["SW-IOS-001"]["severity"] == "high" and codes["SW-IOS-002"]["severity"] == "high"
    assert codes["SW-IOS-003"]["severity"] == "medium" and codes["SW-IOS-005"]["severity"] == "low"
    assert all(codes[c]["doc"]["url"].startswith("https://www.cisco.com/") for c in codes if c.startswith("SW-IOS-"))
    assert "GigabitEthernet0/0/1 IQD 5 / OQD 4200" in codes["SW-IOS-003"]["text"]
    assert "203.0.113.6 AS 65128 Idle, never came up" in codes["SW-IOS-004"]["text"]
    ids = {table["id"] for table in result["extra_tables"]}
    assert {"ios-cpu", "ios-memory", "ios-memory-top", "ios-queues", "ios-bgp", "ios-routes"} <= ids


def test_a_healthy_router_has_the_tables_and_no_finding():
    quiet = _commands().replace("91%/40%; one minute: 88%; five minutes: 85%", "3%/1%; one minute: 3%; five minutes: 3%").replace("Used:  920000000 Free:   80000000", "Used:  100000000 Free:  900000000")
    quiet = quiet.replace("4200", "0").replace("         5         0", "         0         0").replace("Idle (Admin)", "7").replace(" Idle\n", " 5\n").replace("Active", "9")
    result = analyze(_capture(quiet), filename="wanr-1.txt")
    assert [item["code"] for item in result["health"]["findings"] if item["code"].startswith("SW-IOS-")] == []
    assert any(table["id"] == "ios-bgp" for table in result["extra_tables"])


def test_the_commands_are_analyzed_not_listed_as_unparsed():
    result = analyze(_capture(_commands()), filename="wanr-1.txt")
    status = {row["command"]: row["status"] for row in result["coverage"]["rows"]}
    for command in ("show processes cpu sorted", "show processes memory sorted", "show interfaces summary", "show ip bgp summary", "show ip route summary"):
        assert status[command] == "analyzed", command


def test_a_capture_without_these_commands_gets_no_table_and_no_finding():
    result = analyze(_capture(""), filename="wanr-1.txt")
    assert not any(table["id"].startswith("ios-") for table in result.get("extra_tables") or [])
    assert not [item for item in result["health"]["findings"] if item["code"].startswith("SW-IOS-")]


def test_the_text_of_a_rejected_command_is_not_read_as_output():
    clean = capture_text.clean_lines("R#show ip bgp summary\n% BGP not active\nR#\n")
    assert ix.analyse(clean)["tables"] == []


def test_the_nx_os_layout_of_show_ip_bgp_summary_is_read_too():
    text = """BGP summary information for VRF default, address family IPv4 Unicast
BGP router identifier 10.1.1.1, local AS number 65001
BGP table version is 5, IPv4 Unicast config peers 2, capable peers 1
1 network entries and 1 paths using 200 bytes of memory

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.1.1.2        4 65002      12      12        5    0    0 00:05:10 1
10.1.1.3        4 65003       0       0        0    0    0 never    Idle
"""
    bgp = ix.parse_bgp_summary(text.splitlines())
    assert [(r["neighbor"], r["state"], r["prefixes"]) for r in bgp["neighbors"]] == [("10.1.1.2", "Established", 1), ("10.1.1.3", "Idle", None)]
    assert ix.bgp_neighbor_problem(bgp["neighbors"][1]) == "never"
