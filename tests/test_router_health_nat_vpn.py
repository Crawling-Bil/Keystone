"""Router Analyzer: device health, logs, NAT, IPsec, OSPF and BGP correctness.

Two kinds of test live here:

* fixtures cut from real captures (``tests/fixtures/router/*_masked.txt``: a C8200L ``show tech-support``,
  an ISR4431, an ISR4331, a C8300 and a C8200L with IPsec/NAT).  They pin values that were read off real
  output, so a parser regression shows up as a wrong number, not as a crash.
* synthetic sessions (``host#command`` blocks) that cross each rule's threshold from both sides, so a
  threshold change is a conscious decision.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from features.analyzer_core import capture as cap
from features.analyzer_core.result import section_by_id, validate_result
from features.router_analyzer import context as ctxmod
from features.router_analyzer import runtime_health as rh
from features.router_analyzer import runtime_logs as rl
from features.router_analyzer import techsupport as ts
from features.router_analyzer.refs import REFS
from features.router_analyzer.rules_health import uptime_hours
from features.router_analyzer.service import analyze

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "router"
COLLECT = ROOT / "static" / "collect-scripts" / "collect-router-cisco-ios-xe.txt"


# ------------------------------------------------------------------ helpers
def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def ids(result: dict) -> list[str]:
    return [item["id"] for item in result["findings"]]


def find(result: dict, rule_id: str, contains: str = "") -> list[dict]:
    return [item for item in result["findings"] if item["id"] == rule_id and contains in (item["title"] + " " + item.get("detail", ""))]


def one(result: dict, rule_id: str, contains: str = "") -> dict:
    hits = find(result, rule_id, contains)
    assert hits, f"{rule_id} {contains!r} did not fire; got {sorted(set(ids(result)))}"
    return hits[0]


def card(result: dict, label: str) -> str:
    return str(next(item for item in result["cards"] if item["label"] == label)["value"])


def kv(result: dict, section_id: str) -> dict[str, str]:
    return {pair["label"]: str(pair["value"]) for pair in section_by_id(result, section_id)["pairs"]}


def rows(result: dict, section_id: str) -> list[dict]:
    return section_by_id(result, section_id)["rows"]


def session(steps: list[tuple[str, str]], host: str = "lab-r1") -> str:
    """A terminal session: ``host#command`` followed by its output, closed by a final prompt."""
    parts = [f"{host}#{command}\n{output.strip(chr(10))}\n" for command, output in steps]
    return "\n".join(parts) + f"\n{host}#\n"


BASE_CONFIG = """Building configuration...

Current configuration : 1200 bytes
!
version 17.9
hostname lab-r1
!
interface Loopback0
 ip address 192.0.2.1 255.255.255.255
!
interface GigabitEthernet0/0/0
 ip address 198.51.100.2 255.255.255.252
!
ip route 0.0.0.0 0.0.0.0 198.51.100.1
!
end"""


def run(extra: list[tuple[str, str]] | None = None, config: str = BASE_CONFIG) -> dict:
    result = analyze(session([("show running-config", config)] + (extra or [])), "lab-r1.txt")
    assert validate_result(result) == []
    return result


# ------------------------------------------------------------------ fixtures from real captures
@pytest.fixture(scope="module")
def tech():
    return analyze(load("c8200l_iosxe_show_tech_masked.txt"), "tech.txt")


@pytest.fixture(scope="module")
def isr4431():
    return analyze(load("isr4431_iosxe_power_license_masked.txt"), "isr4431.txt")


@pytest.fixture(scope="module")
def isr4331():
    return analyze(load("isr4331_iosxe_ospf_license_masked.txt"), "isr4331.txt")


@pytest.fixture(scope="module")
def c8300():
    return analyze(load("c8300_iosxe_ospf_log_masked.txt"), "c8300.txt")


@pytest.fixture(scope="module")
def vpn():
    return analyze(load("c8200l_iosxe_ipsec_nat_masked.txt"), "vpn.txt")


ALL_FIXTURES = ["tech", "isr4431", "isr4331", "c8300", "vpn"]


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_fixture_results_are_schema_valid_and_documented(name, request):
    result = request.getfixturevalue(name)
    assert validate_result(result) == []
    section_ids = [section["id"] for section in result["sections"]]
    assert len(section_ids) == len(set(section_ids))
    for item in result["findings"]:
        if item["id"].startswith(("RTR-HLT", "RTR-LOG-0", "RTR-NAT", "RTR-VPN", "RTR-OSPF-02", "RTR-BGP-030")) and item["severity"] != "info":
            assert item["recommendation"], item["id"]
            assert item["reference"].startswith("https://"), item["id"]


def test_show_tech_support_is_split_and_read(tech):
    """A 435-line 'show tech-support' becomes the individual commands it contains (CPU, memory, QFP, NAT, ...)."""
    assert tech["subtitle"] == "C8200L-1N-4T · IOS-XE 17.12.04b"
    assert card(tech, "CPU · memory") == "2% · 14.2%"
    assert card(tech, "QFP load") == "5%"
    assert card(tech, "NAT translations") == "57,747"
    assert card(tech, "BGP sessions") == "1/1"
    # a healthy router yields nothing above 'info'
    assert [item["severity"] for item in tech["findings"] if item["severity"] != "info"] == []
    assert sorted(ids(tech)) == ["RTR-BGP-001", "RTR-HLT-061", "RTR-NAT-034"]


def test_show_tech_support_nested_platform_banners_are_split(tech):
    """'---- show platform hardware qfp ... ----' (4 dashes) is a banner inside a tech-support dump."""
    drops = {row["counter"]: row["packets"] for row in rows(tech, "qfp_drops")}
    assert len(drops) == 15
    assert drops["Ipv4NoAdj"] == 1_249_556
    assert drops["NatOut2in"] == 14_484
    assert drops["NatIn2out"] == 9_718
    memory = {row["type"]: row for row in rows(tech, "qfp_memory")}
    assert (memory["DRAM"]["used_pct"], memory["DRAM"]["lowest_free_pct"]) == (17.3, 82.7)
    assert (memory["IRAM"]["used_pct"], memory["IRAM"]["lowest_free_pct"]) == (10.1, 89.9)


def test_show_tech_support_health_and_platform_tables(tech):
    assert len(rows(tech, "platform_resources")) == 17
    assert len(rows(tech, "control_cores")) == 4
    pools = {row["pool"]: row for row in rows(tech, "memory_pools")}
    assert pools["Processor"]["used_pct"] == 14.2
    assert pools["lsmpi_io"]["used_pct"] == 100.0 and "not a leak" in pools["lsmpi_io"]["note"]


def test_show_tech_support_nat_numbers(tech):
    nat = kv(tech, "nat_summary")
    assert "57,747" in nat["Active translations"]
    assert "91 static" in nat["Active translations"] and "57,656 dynamic" in nat["Active translations"]
    assert "57,656 of 200,000 (28.8%)" in nat["Translation limit used"] and "0 refused" in nat["Translation limit used"]
    assert "296,072,073" in nat["Hits / misses"] and "3,114,401" in nat["Hits / misses"]
    assert nat["Drops"] == "in-to-out 9,718, out-to-in 14,484"
    # No running-config in this capture: the overview must say the rules come from the live statistics instead of printing "0 / 0 / 0".
    counts = nat["Pools / dynamic rules"]
    assert counts.startswith("23 / 23") and "configuration was not captured" in counts
    assert "Pools / dynamic rules / static entries" not in nat
    assert len(rows(tech, "nat_pools")) == 23 and len(rows(tech, "nat_rules")) == 23
    assert rows(tech, "nat_static") == [] and "not captured" in section_by_id(tech, "nat_static")["empty"]   # not "no static NAT"
    first = rows(tech, "nat_pools")[0]
    assert first["name"] == "ACCESS-POOL" and first["size"] == 2 and first["allocated"] == 1 and first["pct"] == 50 and first["translations"] == 185
    # drops are counted but a share of 0.0% of the translated packets is information, not a fault
    assert one(tech, "RTR-NAT-034")["severity"] == "info"


def test_show_tech_support_bgp_neighbors(tech):
    states = {row["neighbor"]: row for row in rows(tech, "bgp_neighbors")}
    assert len(states) == 2
    assert any(row["state"] == "Established" for row in states.values())
    assert any("Admin" in row["state"] for row in states.values())
    assert one(tech, "RTR-BGP-001")["severity"] == "info"       # an operator shut it down: not a fault


def test_power_supply_failure_and_cpld_note(isr4431):
    hit = one(isr4431, "RTR-HLT-030")
    assert hit["severity"] == "medium"
    assert hit["title"] == "Power supply P1 is not delivering power"
    assert "badinput" in hit["detail"] and "0 mV" in hit["detail"]
    # ISR4431 with CPLD revision 50: above 38, so the cosmetic CPLD defect of Cisco TechNote 221177 does not explain it
    assert "above 38" in hit["detail"]
    assert hit["reference"] == REFS["power_supply_voltage"]
    assert len(rows(isr4431, "environment")) == 53


def test_isr4431_log_and_storage_findings(isr4431):
    assert one(isr4431, "RTR-LOG-031")["title"].startswith("track 1 (ip sla 1 reachability) went down 2 times")
    assert "9,999 bytes" in one(isr4431, "RTR-LOG-011")["title"]
    assert "2,673" in one(isr4431, "RTR-LOG-010")["title"]
    old = one(isr4431, "RTR-HLT-041")
    assert "isr4400-universalk9.16.09.05.SPA.bin" in old["detail"] and "17.03.03" in old["detail"]
    assert old["severity"] == "low"                            # bootflash still has 67% free
    assert len(rows(isr4431, "license_usage")) == 3


def test_smart_licensing_policy_report_never_acknowledged(isr4331):
    hit = one(isr4331, "RTR-HLT-050")
    assert hit["severity"] == "low"
    assert "last ACK none" in hit["detail"] and "transport cslu" in hit["detail"]
    assert "4 %SMART_LIC-3-COMM_FAILED" in hit["detail"]
    assert ".." not in hit["detail"]                           # the policy sentence ends with one period, not two
    assert hit["reference"] == REFS["smart_lic_troubleshoot"]


def test_bandwidth_license_events_are_read_from_the_log(isr4331):
    hit = one(isr4331, "RTR-HLT-052")
    assert "100 Mbps" in hit["title"] and "2 event(s)" in hit["title"]
    assert "shaped" in hit["detail"]
    assert len(rows(isr4331, "log_bandwidth")) == 4


def test_ospf_process_without_interface_and_unknown_spi_source(isr4331):
    assert card(isr4331, "OSPF") == "no interface"
    state = rows(isr4331, "ospf_state")
    assert len(state) == 1 and state[0]["process"] == "1" and state[0]["state"] == "no interface participates" and state[0]["interfaces"] == 0
    assert one(isr4331, "RTR-OSPF-020")["severity"] == "low"
    assert one(isr4331, "RTR-LOG-051")["severity"] == "info"   # source is not a configured peer
    assert not find(isr4331, "RTR-LOG-050")
    change = one(isr4331, "RTR-LOG-040")
    assert "3 configuration change(s)" in change["title"]


def test_ospf_participation_and_adjacency_flaps(c8300):
    assert card(c8300, "OSPF") == "running"
    state = rows(c8300, "ospf_state")
    assert len(state) == 1 and state[0]["state"] == "running" and state[0]["interfaces"] == 3 and state[0]["areas"] == ["0"]
    part = rows(c8300, "ospf_participation")
    assert len(part) == 3
    assert {row["interface"] for row in part} >= {"Loopback0", "Port-channel30", "GigabitEthernet0/0/0"}
    assert all(row["how"] == "network statement" for row in part)
    assert one(c8300, "RTR-OSPF-023")["severity"] == "low"      # one network statement matches nothing
    flap = one(c8300, "RTR-LOG-032")
    assert flap["severity"] == "medium" and "dropped 3 time(s)" in flap["title"]
    assert "Dead timer expired ×2" in flap["detail"] and "Interface down or detached ×1" in flap["detail"]
    assert len(rows(c8300, "log_flaps")) == 11


def test_ipsec_findings_on_real_configuration(vpn):
    assert card(vpn, "IPsec tunnels") == "3"
    assert card(vpn, "NAT") == "2 rules"
    assert len(find(vpn, "RTR-VPN-002")) == 4                  # four peers with a clear-text key
    assert {item["severity"] for item in find(vpn, "RTR-VPN-002")} == {"high"}
    assert len(find(vpn, "RTR-VPN-001")) == 4                  # four ISAKMP policies
    pfs = find(vpn, "RTR-VPN-024")
    assert {item["severity"] for item in pfs} == {"medium", "low"}
    weak = next(item for item in pfs if item["severity"] == "medium")
    assert "PFS group that Cisco advises against" in weak["title"] and "FRRVUB-CM" in weak["object"]
    assert weak["reference"] == REFS["ngc"]
    assert "group19" in weak["recommendation"]
    assert one(vpn, "RTR-VPN-029")["severity"] == "low"        # one key shared by two peers
    assert "A256-S1-G2" in one(vpn, "RTR-VPN-030")["detail"]
    assert one(vpn, "RTR-VPN-031")["severity"] == "low"        # no DPD
    assert "6 unused" in one(vpn, "RTR-VPN-032")["title"]
    assert one(vpn, "RTR-HLT-053")["severity"] == "info"       # 250 Mbps crypto level


def test_vpn_tunnel_table_and_ikev2_offers(vpn):
    tunnels = {row["name"]: row for row in rows(vpn, "vpn_tunnels")}
    assert set(tunnels) == {"VXN-CM 10", "FRRVUB-CM 10", "FRRVUB-CM 20"}
    row = tunnels["VXN-CM 10"]
    assert row["kind"] == "crypto map" and row["ike"] == "IKEv1" and row["key"] == "clear text"
    assert row["pfs"] == "none" and row["weak"] == ["3DES"]
    traffic = {row["name"]: row for row in rows(vpn, "vpn_traffic")}
    assert traffic["VXN-CM 10"]["proxy"] == ["ip 10.255.22.0/24 → 10.255.23.120/29", "ip 10.255.23.120/29 → 10.255.22.0/24"]
    assert traffic["VXN-CM 10"]["acl"] == "IPSEC-VXN-DC" and traffic["VXN-CM 10"]["applied_on"] == ["GigabitEthernet0/0/2.102"]
    assert len(traffic["FRRVUB-CM 10"]["proxy"]) == 6        # all selectors are shown (the old inventory cut the list at four)
    assert tunnels["FRRVUB-CM 10"]["pfs"] == "group 5 (1536-bit MODP)" and tunnels["FRRVUB-CM 10"]["weak"] == []
    offers = {row["name"]: row for row in rows(vpn, "ikev2_offered")}
    assert len(offers) == 5
    assert offers["A256-S1-G2"]["assessment"] == "DH group 2" and offers["A256-S1-G2"]["_tones"]["assessment"] == "bad"
    assert offers["A256-S256-G14"]["assessment"] == "acceptable"        # group 14 is not rated by Cisco: neither weak nor recommended
    assert rows(vpn, "psk_reuse")[0]["peers"] == ["10.255.6.109", "10.255.7.22"]


def test_nat_configuration_on_real_router(vpn):
    nat = kv(vpn, "nat_summary")
    assert nat["Pools / dynamic rules / static entries"] == "3 / 2 (2 with overload) / 11"
    assert nat["Static port-forwards"] == "10 (4 on management or database ports)"
    assert len(rows(vpn, "nat_static")) == 11
    hit = one(vpn, "RTR-NAT-020")
    assert hit["severity"] == "medium"                         # global addresses are private, one of four outside interfaces filters
    assert "FTP ×1" in hit["title"] and "SSH ×1" in hit["title"] and "RDP ×1" in hit["title"]
    assert "10.255.14.10:3389 → 10.255.15.146" in hit["object"]
    assert "private (RFC 1918)" in hit["detail"] and "1 of 4 outside interface(s) have an inbound ACL" in hit["detail"]
    assert "5535" in one(vpn, "RTR-NAT-015")["detail"] and "5355" in one(vpn, "RTR-NAT-015")["detail"]
    assert one(vpn, "RTR-NAT-003")["object"] == "NAT-ITAK"


def test_no_secret_leaves_the_analyzer(vpn):
    blob = json.dumps(vpn)
    assert "FIXTURE-PSK" not in blob
    assert not re.search(r"crypto isakmp key \S+ address", blob)


# ------------------------------------------------------------------ parsers
def _block(text: str, marker: str, count: int) -> list[str]:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if marker in line)
    return lines[start + 1:start + 1 + count]


def test_qfp_utilization_parser_on_real_output():
    text = load("c8200l_iosxe_show_tech_masked.txt")
    util = rh.parse_qfp_utilization(_block(text, "datapath utilization ---", 26))
    assert util["windows"] == ["5 secs", "1 min", "5 min", "60 min"]
    assert util["processing"] == [3, 3, 5, 5]
    assert util["input_pps"] == [2617, 2144, 2761, 2818]
    assert util["output_pps"][2] == 2730
    assert util["processing_5min"] == 5 and util["processing_peak"] == 5
    assert util["crypto_io_idle"] == [95, 95, 95, 95]


def test_qfp_drop_and_exmem_parsers_on_real_output():
    text = load("c8200l_iosxe_show_tech_masked.txt")
    drops = rh.parse_qfp_drops(_block(text, "qfp active statistics drop ----", 22))
    assert drops["rows"][0] == {"counter": "Ipv4NoAdj", "packets": 1_249_556, "octets": 83_213_277}
    exmem = rh.parse_qfp_exmem(_block(text, "exmem statistics ----", 20))
    dram = next(item for item in exmem["memories"] if item["type"] == "DRAM")
    assert dram["total"] == 536_870_912 and dram["used_pct"] == 17.3 and dram["lowest_free_pct"] == 82.7


def test_nested_tech_support_banner_has_four_dashes():
    assert ts.SECTION_BANNER.match("------------------ show version ------------------")
    assert not ts.SECTION_BANNER.match("---- show platform hardware qfp active statistics drop ----")
    assert ts.NESTED_BANNER.match("---- show platform hardware qfp active statistics drop ----")
    assert not ts.NESTED_BANNER.match("---- show version ----")           # only 'show platform ...' nests


def test_tech_support_dump_is_detected_and_expanded():
    text = load("c8200l_iosxe_show_tech_masked.txt")
    assert ts.looks_like_dump(text)
    capture = cap.split_capture(text)
    expanded = ts.expand(capture)
    commands = [block.command for block in capture.blocks]
    assert "show tech-support" in commands
    assert expanded, "show tech-support must expand into individual commands"


def test_logging_parser_counts_down_reasons_and_flaps():
    text = load("c8300_iosxe_ospf_log_masked.txt")
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.endswith("#show logging"))
    logging = rl.parse_logging(lines[start + 1:])
    ospf = next(iter(logging["flaps"]["ospf"].values()))
    assert ospf["down"] == 3 and ospf["reasons"] == {"Interface down or detached": 1, "Dead timer expired": 2}
    assert logging["settings"]["console"]["level"] == "debugging"
    assert logging["settings"]["buffer_bytes"] == 102400


def test_uptime_hours():
    assert uptime_hours("19 hours, 26 minutes") == pytest.approx(19 + 26 / 60)
    assert uptime_hours("2 years, 3 weeks, 4 days, 5 hours, 6 minutes") == pytest.approx(2 * 8760 + 3 * 168 + 4 * 24 + 5 + 0.1)
    assert uptime_hours("") is None


# ------------------------------------------------------------------ health thresholds (synthetic)
def _cpu(five: int, one_min: int | None = None) -> str:
    one_min = five if one_min is None else one_min
    return f"""CPU utilization for five seconds: {five}%/1%; one minute: {one_min}%; five minutes: {five}%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
 422       65889        8697       7576 {five}.03% {one_min}.18% {five}.09%   0 BGP Router
 131      300582     2734268        109  0.47%  0.52%  0.50%   0 IOSXE-RP Punt Se"""


@pytest.mark.parametrize("five, severity", [(69, None), (70, "medium"), (84, "medium"), (85, "high"), (99, "high")])
def test_cpu_thresholds(five, severity):
    result = run([("show process cpu sorted", _cpu(five))])
    hits = find(result, "RTR-HLT-001")
    if severity is None:
        assert not hits
    else:
        assert hits[0]["severity"] == severity
        assert f"{five}%" in hits[0]["title"]
        assert "BGP Router" in hits[0]["detail"]                     # names the busiest process
        assert hits[0]["reference"] == REFS["tac_high_cpu"]


def _memory(used: int, total: int = 1_000_000_000) -> str:
    return f"""
Processor Pool Total: {total} Used:  {used} Free: {total - used}
 lsmpi_io Pool Total:    6295128 Used:    6294296 Free:        832

 PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process
   0   0  263313000   61564144  179651704          0          0 *Init*"""


@pytest.mark.parametrize("used, severity", [(790_000_000, None), (800_000_000, "medium"), (850_000_000, "medium"), (920_000_000, "high")])
def test_memory_thresholds_ignore_the_packet_io_pool(used, severity):
    result = run([("show process memory sorted", _memory(used))])
    hits = find(result, "RTR-HLT-010")
    assert (hits[0]["severity"] if hits else None) == severity
    # lsmpi_io is 99.98% used on a healthy IOS-XE router and never produces a finding
    assert not any("lsmpi" in item["title"] for item in result["findings"])


def _resources(state: str) -> str:
    return f"""**State Acronym: H - Healthy, W - Warning, C - Critical
Resource                 Usage                 Max             Warning         Critical        State
----------------------------------------------------------------------------------------------------
RP0 (ok, active)                                                                               H
 Control Processor       42.61%                100%            80%             90%             H
  DRAM                   3300MB(87%)           3786MB          85%             93%             {state}
ESP0(ok, active)                                                                               H
 QFP                                                                                           H
  CPU Utilization        3.00%                 100%            90%             95%             H"""


@pytest.mark.parametrize("state, severity", [("H", None), ("W", "medium"), ("C", "high")])
def test_platform_resource_state_comes_from_the_device(state, severity):
    result = run([("show platform resources", _resources(state))])
    hits = find(result, "RTR-HLT-011")
    assert (hits[0]["severity"] if hits else None) == severity
    if hits:
        assert "RP0 DRAM" in hits[0]["title"] and "85%" in hits[0]["detail"] and "93%" in hits[0]["detail"]


def _qfp(load: tuple[int, int, int, int]) -> str:
    a, b, c, d = load
    return f"""
  CPP 0: Subdev 0            5 secs        1 min        5 min       60 min
Input:  Priority (pps)            0            0            0            0
                 (bps)            0            0            0            0
    Non-Priority (pps)         2617         2144         2761         2818
                 (bps)     14300000     11564912     16272792     16832360
           Total (pps)         2617         2144         2761         2818
                 (bps)     14300000     11564912     16272792     16832360
Output: Priority (pps)            0            0            0            0
                 (bps)            0            0            0            0
    Non-Priority (pps)         2558         2123         2730         2779
                 (bps)     14373664     11790288     16387264     16827528
           Total (pps)         2558         2123         2730         2779
                 (bps)     14373664     11790288     16387264     16827528
Processing: Load (pct)            {a}            {b}            {c}            {d}
"""


@pytest.mark.parametrize("load, severity", [((10, 10, 10, 10), None), ((10, 72, 60, 10), "medium"), ((90, 90, 88, 60), "high")])
def test_qfp_load_thresholds(load, severity):
    """The forwarding plane can be saturated while 'show process cpu' shows an idle router."""
    result = run([("show platform hardware qfp active datapath utilization", _qfp(load))])
    hits = find(result, "RTR-HLT-020")
    assert (hits[0]["severity"] if hits else None) == severity
    assert card(result, "QFP load") == f"{load[2]}%"
    if hits:
        assert hits[0]["reference"] == REFS["asr1000_high_cpu"]


def test_environment_power_supply_slot_failure():
    platform = """Chassis type: ISR4431/K9

Slot      Type                State                 Insert time (ago)
--------- ------------------- --------------------- -----------------
0         ISR4431/K9          ok                    1d01h
P0        Unknown             ok                    1d01h
P1        Unknown             fail, badinput        1d01h
"""
    env = """Sensor List:  Environmental Monitoring
 Sensor           Location          State             Reading
 Temp: Temp 1     P0                Normal            35 Celsius
 V: PEM Out       P1                Warning           0 mV
Number of Critical alarms:  0
Number of Major alarms:     0
Number of Minor alarms:     1
"""
    result = run([("show platform", platform), ("show environment all", env)])
    hit = one(result, "RTR-HLT-030")
    assert hit["severity"] == "medium" and "P1" in hit["title"]
    assert "redundancy" in hit["detail"]


def test_environment_critical_temperature_is_high():
    env = """Sensor List:  Environmental Monitoring
 Sensor           Location          State             Reading
 Temp: Temp 1     P0                Critical          95 Celsius
Number of Critical alarms:  1
Number of Major alarms:     0
Number of Minor alarms:     0
"""
    result = run([("show environment all", env)])
    assert one(result, "RTR-HLT-031")["severity"] == "high"


def test_bootflash_free_space_thresholds():
    def file_systems(free: int) -> str:
        return f"""File Systems:

       Size(b)       Free(b)      Type  Flags  Prefixes
*   7194652672    {free:>10}      disk     rw   bootflash: flash:
"""
    medium = one(run([("show file systems", file_systems(1_000_000_000))]), "RTR-HLT-040")      # 13.9 % free
    assert medium["severity"] == "medium" and "bootflash:" in medium["title"] and "13.9%" in medium["title"]
    assert one(run([("show file systems", file_systems(300_000_000))]), "RTR-HLT-040")["severity"] == "high"   # 4.2 % free
    assert not find(run([("show file systems", file_systems(4_000_000_000))]), "RTR-HLT-040")             # 55.6 % free
    assert medium["reference"] == REFS["install_remove_inactive"]


def test_unplanned_restart_reason_is_high_and_planned_is_not():
    def version(reason: str) -> str:
        return f"""Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.4a, RELEASE SOFTWARE (fc3)
lab-r1 uptime is 3 weeks, 2 days, 4 hours, 1 minute
System returned to ROM by {reason}
System image file is "bootflash:packages.conf"
Last reload reason: {reason}

cisco ISR4331/K9 (1RU) processor with 1795979K/6147K bytes of memory.
Processor board ID FDO1234ABCD
"""
    crash = run([("show version", version("Critical process fault"))])
    assert one(crash, "RTR-HLT-060")["severity"] == "high"
    assert not find(run([("show version", version("Reload Command"))]), "RTR-HLT-060")
    assert not find(run([("show version", version("Reload Command"))]), "RTR-HLT-061")   # 3 weeks is not a fresh reboot


# ------------------------------------------------------------------ logs (synthetic)
LOG_BODY = """
Oct  3 16:38:16.622: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to down
Oct  3 16:38:27.668: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to up
Oct  3 16:39:16.622: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to down
Oct  3 16:40:27.668: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to up
Oct  3 16:41:16.622: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to down
Oct  3 16:42:27.668: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to up
Oct  4 10:00:01.100: %TRACK-6-STATE: 1 ip sla 1 reachability Up -> Down
Oct  4 10:05:01.100: %TRACK-6-STATE: 1 ip sla 1 reachability Down -> Up
Oct  4 11:00:01.100: %TRACK-6-STATE: 1 ip sla 1 reachability Up -> Down
Oct  4 11:05:01.100: %TRACK-6-STATE: 1 ip sla 1 reachability Down -> Up
Oct  5 09:00:00.000: %OSPF-5-ADJCHG: Process 1, Nbr 192.0.2.9 on GigabitEthernet0/0/0 from FULL to DOWN, Neighbor Down: Dead timer expired
Oct  5 09:01:00.000: %BGP-5-ADJCHANGE: neighbor 198.51.100.1 Down BGP Notification sent
Oct  5 09:02:00.000: %BGP-5-ADJCHANGE: neighbor 198.51.100.9 Down Admin. shutdown
Oct  5 09:03:00.000: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 203.0.113.50] [localport: 22] [Reason: Login Authentication Failed] at 09:03:00 UTC Sun Oct 5 2026
Oct  5 09:03:01.000: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (203.0.113.7)
"""


def _logging(body: str, buffer_bytes: int = 102400, console: str = "debugging", host: str | None = None) -> str:
    count = len(body.strip().splitlines())
    trap_host = (f"        Logging to {host}  (udp port 514, audit disabled, link up), 3 message lines logged, 0 message lines rate-limited, "
                 "0 message lines dropped-by-MD, xml disabled, sequence number disabled\n") if host else ""
    return f"""Syslog logging: enabled (0 messages dropped, 3 messages rate-limited, 0 flushes, 0 overruns, xml disabled, filtering disabled)

No Active Message Discriminator.

    Console logging: level {console}, {count} messages logged, xml disabled,
                     filtering disabled
    Monitor logging: level debugging, 0 messages logged, xml disabled,
                     filtering disabled
    Buffer logging:  level debugging, {count} messages logged, xml disabled,
                    filtering disabled
    Exception Logging: size (4096 bytes)
    Count and timestamp logging messages: disabled
    Persistent logging: disabled

No active filter modules.

    Trap logging: level informational, {count} message lines logged
{trap_host}
Log Buffer ({buffer_bytes} bytes):

{body.strip()}
"""


@pytest.fixture(scope="module")
def logged():
    return run([("show logging", _logging(LOG_BODY))])


def test_interface_flaps_need_three_downs(logged):
    hit = one(logged, "RTR-LOG-030")
    assert hit["severity"] == "low" and "GigabitEthernet0/0/0: 3 down / 3 up" in hit["detail"]
    twice = LOG_BODY.replace("Oct  3 16:41:16.622: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to down\n", "").replace(
        "Oct  3 16:42:27.668: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to up\n", "")
    assert not find(run([("show logging", _logging(twice))]), "RTR-LOG-030")


def test_interface_flaps_ten_downs_is_medium():
    body = "\n".join(f"Oct  3 16:{i:02d}:16.622: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to down" for i in range(10))
    assert one(run([("show logging", _logging(body))]), "RTR-LOG-030")["severity"] == "medium"


def test_tracked_object_flaps_are_medium(logged):
    hit = one(logged, "RTR-LOG-031")
    assert hit["severity"] == "medium" and "went down 2 times" in hit["title"]
    assert hit["reference"] == REFS["ipsla"]


def test_ospf_adjacency_loss_in_the_log(logged):
    hit = one(logged, "RTR-LOG-032")
    assert hit["severity"] == "low" and "Dead timer expired ×1" in hit["detail"]


def test_bgp_session_loss_versus_administrative_shutdown(logged):
    faults = find(logged, "RTR-LOG-033", "198.51.100.1 ")
    admin = find(logged, "RTR-LOG-033", "198.51.100.9")
    assert faults[0]["severity"] == "medium" and admin[0]["severity"] == "info"
    assert "operator action" in admin[0]["detail"]


def test_failed_logins_and_configuration_changes(logged):
    failed = one(logged, "RTR-LOG-021")
    assert failed["severity"] == "low" and "203.0.113.50" in failed["title"]
    many = LOG_BODY + "\n".join(
        "Oct  5 09:04:%02d.000: %%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: root] [Source: 203.0.113.50] [localport: 22] [Reason: Login Authentication Failed] at 09:04:00 UTC Sun Oct 5 2026" % i
        for i in range(12))
    assert one(run([("show logging", _logging(many))]), "RTR-LOG-021")["severity"] == "medium"
    change = one(logged, "RTR-LOG-040")
    assert change["severity"] == "info" and "admin ×1" in change["detail"]


def test_console_debugging_is_flagged_and_critical_is_not(logged):
    assert one(logged, "RTR-LOG-010")["severity"] == "low"
    quiet = run([("show logging", _logging(LOG_BODY, console="critical"))])
    assert not find(quiet, "RTR-LOG-010")


def test_small_log_buffer_matters_only_without_a_syslog_server():
    small = run([("show logging", _logging(LOG_BODY, buffer_bytes=9999))])
    assert one(small, "RTR-LOG-011")["severity"] == "medium"
    forwarded = run([("show logging", _logging(LOG_BODY, buffer_bytes=9999, host="192.0.2.50"))])
    assert not find(forwarded, "RTR-LOG-011")
    big = run([("show logging", _logging(LOG_BODY, buffer_bytes=32000))])
    assert not find(big, "RTR-LOG-011")


def test_login_flood_needs_volume_and_share():
    logins = "\n".join(
        "Oct  5 09:%02d:%02d.000: %%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: nms] [Source: 192.0.2.77] [localport: 22] at 09:00:00 UTC Sun Oct 5 2026" % (i // 60, i % 60)
        for i in range(600))
    flood = run([("show logging", _logging(logins + "\n" + LOG_BODY))])
    hit = one(flood, "RTR-LOG-020")
    assert hit["severity"] == "low" and "192.0.2.77 (600)" in hit["detail"] and hit["reference"] == REFS["stig_login"]
    # 600 logins among 5,000 other messages are not a flood
    other = "\n".join(f"Oct  5 08:{i // 60 % 60:02d}:{i % 60:02d}.000: %SYS-5-RESTART: System restarted {i}" for i in range(5000))
    assert not find(run([("show logging", _logging(logins + "\n" + other))]), "RTR-LOG-020")
    # 60 logins in a 60-message log are a majority but below the volume floor
    assert not find(run([("show logging", _logging("\n".join(logins.splitlines()[:60])))]), "RTR-LOG-020")


IPSEC_CONFIG = """hostname lab-r1
!
crypto isakmp policy 10
 encryption aes 256
 hash sha256
 authentication pre-share
 group 14
crypto isakmp key FIXTURE-PSK-99 address 203.0.113.10
!
crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac
!
ip access-list extended VPN-A
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
!
crypto map CMAP 10 ipsec-isakmp
 set peer 203.0.113.10
 set transform-set TS
 set pfs group19
 match address VPN-A
!
interface GigabitEthernet0/0/0
 ip address 198.51.100.2 255.255.255.252
 crypto map CMAP
end"""


def _spi(source: str) -> str:
    return (f"Oct  4 09:04:00.000: %CRYPTO-4-RECVD_PKT_INV_SPI: decaps: rec'd IPSEC packet has invalid spi for destaddr=198.51.100.2, "
            f"prot=50, spi=0x12345678(305419896), srcaddr={source}, input interface=GigabitEthernet0/0/0")


def test_invalid_spi_from_configured_peer_versus_stranger():
    from_peer = run([("show logging", _logging(_spi("203.0.113.10")))], IPSEC_CONFIG)
    hit = one(from_peer, "RTR-LOG-050")
    assert hit["severity"] == "low" and "203.0.113.10" in hit["title"] and hit["reference"] == REFS["invalid_spi"]
    assert not find(from_peer, "RTR-LOG-051")
    stranger = run([("show logging", _logging(_spi("203.0.113.200")))], IPSEC_CONFIG)
    assert one(stranger, "RTR-LOG-051")["severity"] == "info"
    assert not find(stranger, "RTR-LOG-050")


# ------------------------------------------------------------------ NAT (synthetic)
NAT_CONFIG = """hostname lab-r1
!
interface GigabitEthernet0/0/0
 ip address 130.1.1.2 255.255.255.252
 ip nat outside
!
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
 ip nat inside
!
ip access-list standard LAN
 permit 10.1.1.0 0.0.0.255
!
ip nat pool PUB 130.1.1.10 130.1.1.12 netmask 255.255.255.248
ip nat pool UNUSED 130.1.1.20 130.1.1.21 netmask 255.255.255.248
ip nat inside source list LAN pool PUB
ip nat inside source list LAN pool MISSING overload
ip nat inside source static tcp 10.1.1.10 3389 130.1.1.30 3389 extended
ip nat inside source static tcp 10.1.1.11 22 130.1.1.30 22 extended
ip nat inside source static 10.1.1.20 130.1.1.31
ip nat inside source static 10.1.1.21 130.1.1.31
ip nat inside source static 10.1.1.22 130.1.1.32
ip nat inside source static 10.1.1.22 130.1.1.32
ip nat inside source static tcp 10.1.1.40 5535 130.1.1.33 5355 extended
end"""


@pytest.fixture(scope="module")
def nat_cfg():
    return run([], NAT_CONFIG)


def test_nat_rule_with_undefined_pool_is_high(nat_cfg):
    hit = one(nat_cfg, "RTR-NAT-001")
    assert hit["severity"] == "high" and "MISSING" in hit["object"]


def test_nat_unused_pool_is_low(nat_cfg):
    hit = one(nat_cfg, "RTR-NAT-003")
    assert hit["severity"] == "low" and hit["object"] == "UNUSED"


def test_static_nat_conflicts_and_duplicates(nat_cfg):
    conflict = one(nat_cfg, "RTR-NAT-012")
    assert conflict["severity"] == "high" and "130.1.1.31" in conflict["title"] and "2 different inside hosts" in conflict["title"]
    duplicate = one(nat_cfg, "RTR-NAT-013")
    assert duplicate["severity"] == "low" and "130.1.1.32" in duplicate["title"]
    # the same global address with two different ports is a normal port-forward, not a conflict
    assert not any("130.1.1.30" in item["title"] for item in find(nat_cfg, "RTR-NAT-012"))


def test_static_port_forward_with_swapped_digits(nat_cfg):
    hit = one(nat_cfg, "RTR-NAT-015")
    assert hit["severity"] == "low" and "5535" in hit["detail"] and "5355" in hit["detail"]


def test_nat_without_inside_or_outside_interface():
    config = NAT_CONFIG.replace(" ip nat outside\n", "").replace(" ip nat inside\n", "")
    result = run([], config)
    titles = [item["title"] for item in find(result, "RTR-NAT-011")]
    assert "NAT rules exist but no interface is marked 'ip nat inside'" in titles
    assert "NAT rules exist but no interface is marked 'ip nat outside'" in titles


def _publish(global_ip: str, acl: bool) -> str:
    return f"""hostname lab-r1
!
interface GigabitEthernet0/0/0
 ip address 130.1.1.2 255.255.255.252
{' ip access-group OUTSIDE-IN in' if acl else ''}
 ip nat outside
!
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
 ip nat inside
!
ip access-list extended OUTSIDE-IN
 permit tcp any any eq 443
!
ip nat inside source static tcp 10.1.1.10 3389 {global_ip} 3389 extended
end"""


@pytest.mark.parametrize(
    "global_ip, acl, severity",
    [
        ("130.1.1.30", False, "high"),     # public address, nothing filters the outside interface
        ("130.1.1.30", True, "medium"),    # public address, inbound ACL present (content not judged)
        ("172.16.5.5", False, "medium"),   # private global address: reachable only from behind another router
        ("172.16.5.5", True, "low"),
    ],
)
def test_published_management_port_severity(global_ip, acl, severity):
    result = run([], _publish(global_ip, acl))
    hit = one(result, "RTR-NAT-020")
    assert hit["severity"] == severity
    assert "1 static NAT entry publishes" in hit["title"] and "RDP ×1" in hit["title"]
    assert hit["reference"] == REFS["acl"]


def _nat_stats(*, pool_misses=0, allocated=3, used=190, missed=0, drops="Pool stats drop: 0  Mapping stats drop: 0", in_out=0, out_in=0, hits=1000, misses=5) -> str:
    return f"""Total active translations: {used} (3 static, {used - 3} dynamic; {used} extended)
Outside interfaces:
  GigabitEthernet0/0/0
Inside interfaces:
  GigabitEthernet0/0/1
Hits: {hits}  Misses: {misses}
Expired translations: 3
Dynamic mappings:
-- Inside Source
[Id: 1] access-list LAN pool PUB refcount 3
 pool PUB: id 1, netmask 255.255.255.248
start 130.1.1.10 end 130.1.1.12
type generic, total addresses 3, allocated {allocated} ({100 * allocated // 3}%), misses {pool_misses}
nat-limit statistics:
 max entry: max allowed 200, used {used}, missed {missed}
In-to-out drops: {in_out}  Out-to-in drops: {out_in}
{drops}
Port block alloc fail: 0
IP alias add fail: 0
Limit entry add fail: 0
"""


def _live(**kwargs) -> dict:
    config = NAT_CONFIG.replace("ip nat inside source list LAN pool MISSING overload\n", "")
    return run([("show ip nat statistics", _nat_stats(**kwargs))], config)


def test_nat_pool_allocation_failures_are_high():
    hit = one(_live(pool_misses=7), "RTR-NAT-030")
    assert hit["severity"] == "high" and "7 time(s)" in hit["title"] and hit["object"] == "PUB"


def test_full_pool_without_overload_is_medium_when_nothing_failed_yet():
    hit = one(_live(allocated=3), "RTR-NAT-031")
    assert hit["severity"] == "medium" and "100" in hit["title"]
    assert not find(_live(allocated=1), "RTR-NAT-031")
    # the pool already failed once: the stronger finding replaces the warning
    both = _live(pool_misses=2, allocated=3)
    assert find(both, "RTR-NAT-030") and not find(both, "RTR-NAT-031")


@pytest.mark.parametrize("used, missed, severity", [(100, 0, None), (160, 0, "medium"), (190, 0, "high"), (150, 12, "high")])
def test_nat_translation_limit(used, missed, severity):
    hits = find(_live(used=used, missed=missed), "RTR-NAT-032")
    assert (hits[0]["severity"] if hits else None) == severity
    if missed:
        assert "12 translation(s) were refused" in hits[0]["title"]


def test_nat_resource_drop_counters_are_high_and_traffic_drops_are_not():
    hard = one(_live(drops="Pool stats drop: 0  Mapping stats drop: 5"), "RTR-NAT-033")
    assert hard["severity"] == "high" and "mapping 5" in hard["detail"]
    assert not find(_live(), "RTR-NAT-033")
    share = one(_live(in_out=10, out_in=20, hits=1000, misses=5), "RTR-NAT-034")
    assert share["severity"] == "low" and "3.0%" in share["title"]            # >= 1% of translated packets
    quiet = one(_live(in_out=10, out_in=20, hits=10_000_000, misses=5), "RTR-NAT-034")
    assert quiet["severity"] == "info"


# ------------------------------------------------------------------ OSPF (synthetic)
def _ospf(router_body: str = "", loopback_extra: str = "") -> str:
    return f"""hostname lab-r1
!
interface Loopback0
 ip address 192.0.2.1 255.255.255.255
{loopback_extra}
interface GigabitEthernet0/0/0
 ip address 10.0.0.1 255.255.255.0
!
router ospf 1
 router-id 192.0.2.1
{router_body}
end"""


def test_ospf_process_with_no_participating_interface():
    assert one(run([], _ospf()), "RTR-OSPF-020")["severity"] == "low"


def test_ospf_network_statements_that_match_nothing():
    result = run([], _ospf(" network 172.31.0.0 0.0.255.255 area 0"))
    assert one(result, "RTR-OSPF-021")["severity"] == "medium"
    assert not find(result, "RTR-OSPF-020")


def test_ospf_with_only_passive_interfaces():
    result = run([], _ospf(" network 10.0.0.0 0.0.0.255 area 0\n passive-interface default"))
    assert one(result, "RTR-OSPF-022")["severity"] == "medium"


def test_ospf_one_dead_statement_among_live_ones_is_low():
    result = run([], _ospf(" network 10.0.0.0 0.0.0.255 area 0\n network 172.31.0.0 0.0.255.255 area 0"))
    hit = one(result, "RTR-OSPF-023")
    assert hit["severity"] == "low" and "172.31.0.0" in hit["object"]
    assert not find(result, "RTR-OSPF-021")


def test_ospf_interface_level_enablement_counts_as_participation():
    result = run([], _ospf("", " ip ospf 1 area 0"))
    assert not find(result, "RTR-OSPF-020")
    assert [(row["state"], row["interfaces"]) for row in rows(result, "ospf_state")] == [("running", 1)]
    assert rows(result, "ospf_participation")[0]["how"] == "interface command"


def test_ospf_secondary_address_is_matched_by_a_network_statement():
    config = _ospf(" network 10.9.9.0 0.0.0.255 area 0").replace("interface GigabitEthernet0/0/0\n ip address 10.0.0.1 255.255.255.0\n",
                                                                "interface GigabitEthernet0/0/0\n ip address 10.0.0.1 255.255.255.0\n ip address 10.9.9.1 255.255.255.0 secondary\n")
    result = run([], config)
    assert not find(result, "RTR-OSPF-021") and not find(result, "RTR-OSPF-020")
    # only the secondary address (10.9.9.1) is covered by the statement, and that is enough for the interface to participate
    assert [(row["state"], row["interfaces"]) for row in rows(result, "ospf_state")] == [("running", 1)]
    assert [(row["interface"], row["how"]) for row in rows(result, "ospf_participation")] == [("GigabitEthernet0/0/0", "network statement")]


def test_redistribute_without_subnets_is_flagged_once_per_source():
    body = " network 10.0.0.0 0.0.0.255 area 0\n redistribute connected\n redistribute static subnets"
    result = run([], _ospf(body))
    hits = find(result, "RTR-OSPF-024")
    assert len(hits) == 1 and "redistribute connected" in hits[0]["title"] and hits[0]["severity"] == "medium"
    assert hits[0]["reference"] == REFS["ospf_redistribute"]


# ------------------------------------------------------------------ BGP (synthetic)
BGP_SUMMARY = """BGP router identifier 192.0.2.1, local AS number 64500
BGP table version is 10, main routing table version 10
2 network entries using 496 bytes of memory

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
198.51.100.1    4        64501    1000    1000       10    0    0 1d02h           5
198.51.100.5    4        64502     100     100        1    0    0 00:10:00 Idle (PfxCt)
198.51.100.9    4        64503       0       0        1    0    0 never    Idle (Admin)
"""


def test_bgp_maximum_prefix_shutdown_is_high_and_cites_cisco():
    result = run([("show ip bgp summary", BGP_SUMMARY)])
    hit = one(result, "RTR-BGP-030")
    assert hit["severity"] == "high" and "198.51.100.5" in hit["title"] and "AS 64502" in hit["title"]
    assert hit["reference"] == REFS["bgp_max_prefix"]
    assert len(find(result, "RTR-BGP-030")) == 1                                  # the healthy and the admin-down peer do not match
    assert one(result, "RTR-BGP-001", "198.51.100.9")["severity"] == "info"       # operator shutdown is information


# ------------------------------------------------------------------ IPsec (synthetic)
BAD_IPSEC = """hostname lab-r1
!
crypto isakmp policy 10
 encryption 3des
 hash md5
 authentication pre-share
 group 2
crypto isakmp key FIXTURE-PSK-77 address 203.0.113.10
crypto isakmp key FIXTURE-PSK-77 address 203.0.113.11
!
crypto ipsec transform-set TS-OLD esp-3des esp-md5-hmac
crypto ipsec transform-set TS-UNUSED esp-aes 256 esp-sha256-hmac
!
ip access-list extended VPN-A
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
ip access-list extended VPN-ANY
 permit ip any any
ip access-list extended VPN-EMPTY
 remark nothing here
!
crypto map CMAP 10 ipsec-isakmp
 set peer 203.0.113.10
 set transform-set TS-OLD
 set pfs group2
 match address VPN-A
crypto map CMAP 20 ipsec-isakmp
 set peer 203.0.113.11
 set transform-set TS-MISSING
 match address VPN-ANY
crypto map CMAP 30 ipsec-isakmp
 set transform-set TS-OLD
 match address VPN-EMPTY
!
interface GigabitEthernet0/0/0
 ip address 198.51.100.2 255.255.255.252
end"""


@pytest.fixture(scope="module")
def bad_ipsec():
    return run([], BAD_IPSEC)


@pytest.mark.parametrize(
    "rule_id, severity, needle",
    [
        ("RTR-VPN-002", "high", "203.0.113.10"),                    # clear-text pre-shared key
        ("RTR-VPN-021", "high", "TS-MISSING"),                      # transform set that does not exist
        ("RTR-VPN-022", "high", "VPN-EMPTY"),                       # crypto ACL without a permit entry
        ("RTR-VPN-023", "high", "VPN-ANY"),                         # permit ip any any
        ("RTR-VPN-026", "high", "CMAP 30"),                         # no 'set peer'
        ("RTR-VPN-025", "medium", ""),                              # crypto map not applied
        ("RTR-VPN-024", "medium", "PFS group 2"),                   # weak PFS group
        ("RTR-VPN-029", "low", "203.0.113.10 / 203.0.113.11"),      # one key, two peers
        ("RTR-VPN-031", "low", ""),                                 # no DPD
        ("RTR-VPN-032", "low", "TS-UNUSED"),
    ],
)
def test_ipsec_misconfigurations(bad_ipsec, rule_id, severity, needle):
    hit = one(bad_ipsec, rule_id, needle)
    assert hit["severity"] == severity
    assert hit["recommendation"] and hit["reference"].startswith("https://")


def test_unapplied_crypto_map_is_reported_once_per_map(bad_ipsec):
    hits = find(bad_ipsec, "RTR-VPN-025")
    assert len(hits) == 1
    assert "×" not in hits[0]["title"]                             # three entries of one map are one problem


def test_pre_shared_key_reuse_is_found_without_showing_the_key(bad_ipsec):
    assert "FIXTURE-PSK-77" not in json.dumps(bad_ipsec)
    assert "FIXTURE-PSK-99" not in json.dumps(run([], IPSEC_CONFIG))


def test_clean_ipsec_configuration_raises_no_vpn_error():
    config = IPSEC_CONFIG.replace("crypto isakmp key FIXTURE-PSK-99 address 203.0.113.10", "crypto isakmp key 6 FIXTURE-TYPE6 address 203.0.113.10") + "\n"
    result = run([], config)
    high_or_medium = [item for item in result["findings"] if item["id"].startswith("RTR-VPN") and item["severity"] in ("high", "medium")]
    assert [item["id"] for item in high_or_medium] == [], high_or_medium


# ------------------------------------------------------------------ references and collect script
def test_every_new_rule_cites_a_reference_that_exists():
    from features.router_analyzer import rules_health, rules_net

    source = Path(rules_health.__file__).read_text(encoding="utf-8") + Path(rules_net.__file__).read_text(encoding="utf-8")
    used = set(re.findall(r'R\["([a-z0-9_]+)"\]', source))
    assert used, "the rule modules must cite references"
    assert used <= set(REFS), sorted(used - set(REFS))


def test_collect_script_covers_every_command_the_analyzer_reads():
    commands = [line.strip() for line in COLLECT.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith(("!", "#"))]
    assert commands[0] == "terminal length 0"
    assert len(commands) == len(set(commands)), "a command is listed twice"
    for spec in ctxmod.SPECS:
        if spec.key.startswith("sdwan_"):
            continue   # 'show sdwan ...' exists on controller-managed routers only: collect-router-cisco-sdwan.txt
        assert any(command == template or command.startswith(template) for template in spec.templates for command in commands), f"{spec.key}: {spec.templates}"
    # the collect list never changes the router
    assert not any(re.match(r"(?i)(clear|reload|configure|conf t|write|copy|debug|erase|delete|no )", command) for command in commands)


def test_collect_script_says_which_commands_are_not_yet_proven():
    text = COLLECT.read_text(encoding="utf-8")
    assert "no real capture has answered with a populated table yet" in text
    assert text.index("populated table yet") < text.index("show ip eigrp neighbors")
    # commands a real router answered with a populated table are in section 1, above the 'not yet populated' section
    section2 = text.index("!!! 2.")
    for command in ("show ip protocols", "show ip ospf neighbor", "show ip ospf interface brief", "show ntp status"):
        assert text.index(command) < section2, command


# ------------------------------------------------------------------ the masking tool used to build the fixtures
def _masker():
    import importlib.util

    spec = importlib.util.spec_from_file_location("mask_capture", ROOT / "tests" / "fixtures" / "real_captures" / "mask_capture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_masker_hides_ipsec_pre_shared_keys():
    """`crypto isakmp key KEY address X` has no 'secret'/'password' keyword; an earlier version of the masker let it through."""
    sample = """RTR-A#show running-config
crypto isakmp key Sup3rSecret address 203.0.113.9
crypto isakmp key 6 aB:cd:ef:01:23:45 hostname peer-b
crypto ikev2 keyring KR
 peer P1
  pre-shared-key local LOCALKEY123
  pre-shared-key remote REMOTEKEY456
  pre-shared-key 0 PLAINKEY789
snmp-server community public RO
"""
    module = _masker()
    masked, originals = module.mask(sample, [])
    for secret in ("Sup3rSecret", "aB:cd:ef:01:23:45", "LOCALKEY123", "REMOTEKEY456", "PLAINKEY789", "203.0.113.9"):
        assert secret not in masked
    # the structure survives: the direction keywords and the key type are kept so the parser still sees the same statements
    assert "crypto isakmp key <REDACTED> address 10.255.0.1" in masked
    assert "crypto isakmp key 6 <REDACTED> hostname" in masked
    assert "pre-shared-key local <REDACTED>" in masked and "pre-shared-key remote <REDACTED>" in masked
    assert originals["secrets"] == {"Sup3rSecret", "aB:cd:ef:01:23:45", "LOCALKEY123", "REMOTEKEY456"}
    assert module.verify(masked, originals) == []
    # and the safety net itself works: a key that is still present is reported, without printing it
    assert module.verify("crypto isakmp key Sup3rSecret address 10.255.0.1", originals) == ["secret still present (value not printed)"]
