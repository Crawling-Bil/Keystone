"""Router Analyzer: SD-WAN overlay tabs (OMP sessions / routes / TLOCs, control-plane identity, application-aware routing statistics,
pushed policy) and the honest reading of commands that answered with an empty table.

The inline cases use RFC 5737 addresses and generic names; their column layout is copied from real output of two
cEdge routers (IOS-XE 17.x, controller mode).  Numbers asserted here were counted by hand from the text of each case.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from features.router_analyzer import context as ctxmod
from features.router_analyzer import runtime_sdwan as rs
from features.router_analyzer.refs import REFS
from features.router_analyzer.service import UNVALIDATED, analyze


def lines(text: str) -> list[str]:
    return text.strip("\n").split("\n")


def capture(*blocks: tuple[str, str]) -> str:
    out = []
    for command, body in blocks:
        out.append(f"EDGE-A#{command}")
        out.append(body.strip("\n"))
        out.append("")
    return "\n".join(out) + "\n"


PEERS = """
R -> routes received
I -> routes installed
S -> routes sent

TENANT                             DOMAIN    OVERLAY   SITE      REGION
ID        PEER             TYPE    ID        ID        ID        ID        STATE    UPTIME           R/I/S
-----------------------------------------------------------------------------------------------------------------
0         192.0.2.10       vsmart  1         1         900001    None      up       37:03:21:21      12708/2175/8
0         192.0.2.11       vsmart  1         1         900002    None      down     0:00:00:00       0/0/0
"""

PEERS_NO_REGION = """
TENANT                             DOMAIN    OVERLAY   SITE
ID        PEER             TYPE    ID        ID        ID        STATE    UPTIME           R/I/S
--------------------------------------------------------------------------------------------
0         192.0.2.10       vsmart  1         1         900001    up       1:02:03:04       5/4/3
"""

ROUTES_HEAD = """
Generating output, this might take time, please wait ...
Code:
C   -> chosen
I   -> installed
Red -> redistributed
Rej -> rejected
L   -> looped
R   -> resolved
S   -> stale
Ext -> extranet
Inv -> invalid
Stg -> staged
IA  -> On-demand inactive
U   -> TLOC unresolved
BR-R -> border-router reoriginated
TGW-R -> transport-gateway reoriginated

                                                                                                                                                AFFINITY
                                                       PATH                      ATTRIBUTE                                                       GROUP
TENANT    VPN    PREFIX              FROM PEER        ID     LABEL    STATUS    TYPE       TLOC IP          COLOR            ENCAP  PREFERENCE  NUMBER      REGION ID   REGION PATH
-----------------------------------------------------------------------------------------------------------------------------------------------------
"""

# prefix 1: two usable mpls paths; prefix 2: two unresolved paths whose PATH ID wraps its last digit onto the next line;
# prefix 3: a route this router redistributes itself
ROUTES = ROUTES_HEAD + """0         1      10.1.0.0/24         192.0.2.10       30000  1004     C,I,R     installed  192.0.2.50       mpls             ipsec  -           None        None        -
                                     192.0.2.11       30001  1003     R         installed  192.0.2.50       mpls             ipsec  -           None        None        -
0         1      10.2.0.0/29         192.0.2.10       40205  1004     Inv,U     installed  192.0.2.60       private1         ipsec  -           None        None        -
                                                      2
                                     192.0.2.11       40286  1004     Inv,U     installed  192.0.2.61       private2         ipsec  -           None        None        -
                                                      7
0         1      10.3.0.0/32         192.0.2.10       873    1004     C,Red,R   installed  192.0.2.70       private1         ipsec  -           None        None        -
"""


def test_omp_peers_read_with_and_without_the_region_column():
    rows = rs.parse_omp_peers(lines(PEERS))
    assert [(r["peer"], r["site_id"], r["region_id"], r["state"], r["received"], r["installed"], r["sent"]) for r in rows] == [
        ("192.0.2.10", "900001", "None", "up", 12708, 2175, 8), ("192.0.2.11", "900002", "None", "down", 0, 0, 0)]
    old = rs.parse_omp_peers(lines(PEERS_NO_REGION))
    assert len(old) == 1 and old[0]["region_id"] == "" and old[0]["site_id"] == "900001" and old[0]["uptime"] == "1:02:03:04"


def test_omp_routes_count_paths_prefixes_and_ignore_wrapped_path_id_digits():
    data = rs.parse_omp_routes(lines(ROUTES))
    assert data["paths"] == 5 and data["prefix_count"] == 3
    assert data["by_status"] == {"C,I,R": 1, "R": 1, "Inv,U": 2, "C,Red,R": 1}
    assert data["unusable_prefixes"] == 1 and data["installed_paths"] == 1
    assert data["legend"]["U"] == "TLOC unresolved" and data["legend"]["Inv"] == "invalid"
    by_prefix = {r["prefix"]: r for r in data["prefixes"]}
    assert by_prefix["10.1.0.0/24"]["usable"] == 2 and by_prefix["10.1.0.0/24"]["best_color"] == "mpls"
    assert by_prefix["10.2.0.0/29"]["usable"] == 0 and by_prefix["10.2.0.0/29"]["best_color"] == ""
    assert by_prefix["10.3.0.0/32"]["best_color"] == "private1"
    assert data["by_color"]["private1"] == {"paths": 2, "usable": 1, "unresolved": 1, "unresolved_tlocs": 1}
    assert data["vpns"] == {"1": {"prefixes": 3, "paths": 5, "unusable_prefixes": 1}}


def test_omp_routes_of_an_empty_table_are_nothing():
    assert rs.parse_omp_routes(lines(ROUTES_HEAD)) == {}


TLOCS = """
---------------------------------------------------
tloc entries for 192.0.2.50
                 mpls
                 ipsec
---------------------------------------------------
            RECEIVED FROM:
tenant-id       0
peer            192.0.2.10
status          C,I,R
loss-reason     not set
    Attributes:
     attribute-type    installed
     encap-spi         3854
     encap-auth        sha1-hmac,ah-sha1-hmac
     encap-encrypt     aes256
     public-ip         198.51.100.50
     public-port       12426
     private-ip        192.0.2.50
     private-port      12426
     public-ip         ::
     public-port       0
     bfd-status        up
     site-id           900001
     preference        400
     weight            1
     carrier           default
     restrict          0

---------------------------------------------------
tloc entries for 192.0.2.1
                 private2
                 ipsec
---------------------------------------------------
            ADVERTISED TO:
tenant-id       0
peer            192.0.2.10
status          C,Red,R
    Attributes:
     bfd-status        down
     site-id           10001
     preference        0
"""


def test_tlocs_one_row_per_direction_and_first_address_family_wins():
    rows = rs.parse_omp_tlocs(lines(TLOCS))
    assert [(r["tloc_ip"], r["color"], r["encap"], r["direction"], r["peer"], r["status"], r["bfd_status"]) for r in rows] == [
        ("192.0.2.50", "mpls", "ipsec", "received", "192.0.2.10", "C,I,R", "up"), ("192.0.2.1", "private2", "ipsec", "advertised", "192.0.2.10", "C,Red,R", "down")]
    first = rows[0]
    assert first["public_ip"] == "198.51.100.50" and first["public_port"] == "12426" and first["encrypt"] == "aes256" and first["preference"] == "400" and first["site_id"] == "900001"


LOCAL = """
personality                       vedge
sp-organization-name              MASKED
organization-name                 MASKED
root-ca-chain-status              Installed
certificate-status                Installed
certificate-validity              Valid
certificate-not-valid-before      Jun 21 09:04:52 2025 GMT
certificate-not-valid-after       Aug  9 20:58:26 2099 GMT
dns-name                          MASKED
site-id                           10001
domain-id                         1
protocol                          dtls
system-ip                         192.0.2.1
chassis-num/unique-id             MASKED
serial-num                        MASKED
token                             MASKED
embargo-check                     success
device-role                       edge-router
number-active-wan-interfaces      3


 NAT TYPE: E -- indicates End-point independent mapping
           A -- indicates Address-port dependent mapping
           N -- indicates Not learned
           Note: Requires minimum two vbonds to learn the NAT type

                         PUBLIC          PUBLIC PRIVATE         PRIVATE                                 PRIVATE                                                        MAX   RESTRICT/           LAST         SPI TIME    NAT  VM
INTERFACE                IPv4            PORT   IPv4            IPv6                                    PORT    VS/VM COLOR                                      STATE CNTRL CONTROL/     LR/LB  CONNECTION   REMAINING   TYPE CON REG
                                                                                                                                                                  STUN                                              PRF IDs
------------------------------------------------------------------------------------------------------------------------------                          -------------------------------------------------------------------------------
GigabitEthernet0/0/0          192.0.2.21 12386  192.0.2.21 ::                                      12386    2/0  cus                          tom2          up     2      no/yes/no   No/No  13:06:44:32  0:09:10:32  N    5  Default
GigabitEthernet0/0/1          198.51.100.22 12366  192.0.2.22 ::                                      12366    2/1  mpls                                     up     2      no/yes/no   No/No  13:06:44:29  0:01:04:07  E    5  Default
GigabitEthernet0/0/2          198.51.100.23 12426  192.0.2.23 ::                                      12426    0/0  pri                          vate2         down   2      no/yes/no   No/No  14:06:06:58  0:00:00:00  A    5  Default
"""


def test_local_properties_join_a_color_printed_in_two_pieces():
    data = rs.parse_control_local_properties(lines(LOCAL))
    assert data["properties"]["site-id"] == "10001" and data["properties"]["certificate-validity"] == "Valid"
    assert data["properties"]["certificate-not-valid-after"] == "Aug  9 20:58:26 2099 GMT"
    rows = data["interfaces"]
    assert [(r["interface"], r["color"], r["state"], r["nat_type"], r["vs_vm"]) for r in rows] == [
        ("GigabitEthernet0/0/0", "custom2", "up", "N", "2/0"), ("GigabitEthernet0/0/1", "mpls", "up", "E", "2/1"), ("GigabitEthernet0/0/2", "private2", "down", "A", "0/0")]
    third = rows[2]
    assert third["public_ip"] == "198.51.100.23" and third["public_port"] == "12426" and third["private_port"] == "12426" and third["private_ipv6"] == "::"
    assert third["max_control"] == "2" and third["restrict_control_stun"] == "no/yes/no" and third["last_connection"] == "14:06:06:58" and third["reg_ids"] == "Default"


APP_ROUTE = """
app-route statistics 192.0.2.21 198.51.100.50 ipsec 12386 12426
 remote-system-ip         192.0.2.50
 local-color              custom2
 remote-color             mpls
 sla-class-index          0,1
 fallback-sla-class-index None
 app-probe-class-list     None
  mean-loss    0
  mean-latency 80
  mean-jitter  2
  interval 0
   total-packets     664
   loss              0
   average-latency   83
   average-jitter    1
   tx-data-pkts      36547
   rx-data-pkts      17758
   ipv6-tx-data-pkts 0
   ipv6-rx-data-pkts 0
  interval 1
   total-packets     663
   loss              3
   average-latency   79
   average-jitter    4
   tx-data-pkts      25346
   rx-data-pkts      13192
app-route statistics 192.0.2.22 198.51.100.51 ipsec 12366 12346
 remote-system-ip         192.0.2.51
 local-color              mpls
 remote-color             mpls
 sla-class-index          0,1
 fallback-sla-class-index None
 app-probe-class-list     None
  mean-loss    30
  mean-latency 5
  mean-jitter  0
  interval 0
   total-packets     664
   loss              40
   average-latency   5
   average-jitter    0
"""


def test_app_route_statistics_keep_the_device_means_and_every_interval():
    tunnels = rs.parse_app_route_stats(lines(APP_ROUTE))
    assert len(tunnels) == 2
    first = tunnels[0]
    assert (first["src_ip"], first["dst_ip"], first["protocol"], first["src_port"], first["dst_port"]) == ("192.0.2.21", "198.51.100.50", "ipsec", "12386", "12426")
    assert (first["remote_system_ip"], first["local_color"], first["remote_color"], first["sla_class_index"]) == ("192.0.2.50", "custom2", "mpls", "0,1")
    assert (first["mean_loss"], first["mean_latency"], first["mean_jitter"]) == (0, 80, 2)
    assert [(i["index"], i["total_packets"], i["loss"], i["latency"], i["jitter"], i["tx"], i["rx"]) for i in first["intervals"]] == [(0, 664, 0, 83, 1, 36547, 17758), (1, 663, 3, 79, 4, 25346, 13192)]
    assert tunnels[1]["mean_loss"] == 30 and len(tunnels[1]["intervals"]) == 1


POLICY = """
from-vsmart sla-class Default
 loss    25
 latency 300
 jitter  100
from-vsmart sla-class VOICE
 loss    2
 latency 45
 jitter  100
from-vsmart app-route-policy POLICY_A
 vpn-list VPN1
  sequence 1
   match
    source-data-prefix-list      LIST_A
    destination-data-prefix-list LIST_B
   action
    backup-sla-preferred-color private2
    sla-class       VOICE
    no sla-class strict
    sla-class preferred-color custom1 custom2
  sequence 11
   match
    destination-data-prefix-list LIST_C
   action
    sla-class       Default
    sla-class strict
from-vsmart lists vpn-list VPN1
 vpn 1
from-vsmart lists data-prefix-list LIST_A
 ip-prefix 10.10.0.0/16
from-vsmart lists data-prefix-list LIST_B
 ip-prefix 10.20.0.0/16
 ip-prefix 10.21.0.0/16
"""


def test_policy_reads_sla_classes_rules_and_lists():
    data = rs.parse_policy_from_vsmart(lines(POLICY))
    assert [(c["name"], c["loss"], c["latency"], c["jitter"]) for c in data["sla_classes"]] == [("Default", 25, 300, 100), ("VOICE", 2, 45, 100)]
    policy = data["policies"][0]
    assert policy["name"] == "POLICY_A" and policy["vpn_lists"][0]["name"] == "VPN1"
    first, second = policy["vpn_lists"][0]["sequences"]
    assert first["sequence"] == "1" and first["match"] == {"source-data-prefix-list": "LIST_A", "destination-data-prefix-list": "LIST_B"}
    assert first["action"] == {"sla_class": "VOICE", "strict": False, "preferred_colors": ["custom1", "custom2"], "backup_color": "private2", "other": []}
    assert second["action"]["strict"] is True and second["action"]["sla_class"] == "Default" and second["action"]["backup_color"] == ""
    assert [(item["kind"], item["name"], item["entries"]) for item in data["lists"]] == [
        ("vpn-list", "VPN1", ["vpn 1"]), ("data-prefix-list", "LIST_A", ["10.10.0.0/16"]), ("data-prefix-list", "LIST_B", ["10.20.0.0/16", "10.21.0.0/16"])]
    assert data["other"] == []


def test_policy_headings_it_does_not_interpret_are_kept_with_their_size():
    data = rs.parse_policy_from_vsmart(lines("from-vsmart data-policy DP_A\n direction from-service\n  vpn-list V\nfrom-vsmart sla-class Default\n loss 25"))
    assert data["other"] == [{"heading": "from-vsmart data-policy DP_A", "lines": 2}]
    assert len(data["sla_classes"]) == 1


# ---------------------------------------------------------------------------
# analysis: sections and findings
# ---------------------------------------------------------------------------

BFD = """
                                      SOURCE TLOC      REMOTE TLOC                                      DST PUBLIC                      DST PUBLIC         DETECT      TX
SYSTEM IP        SITE ID     STATE       COLOR            COLOR            SOURCE IP                                       IP                                              PORT        ENCAP  MULTIPLIER  INTERVAL(msec) UPTIME      TRANSITIONS
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
192.0.2.50       900001      up          custom2          mpls             192.0.2.21                                      198.51.100.50                                   12426       ipsec  7           1000           20:01:52:07 0
192.0.2.50       900001      down        private2         mpls             192.0.2.23                                      198.51.100.50                                   12426       ipsec  7           1000           0:00:00:00  3
"""

ROUTE_TABLE_VRF1 = """
Routing Table: 1
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       m - OMP

Gateway of last resort is 192.0.2.50 to network 0.0.0.0

m*    0.0.0.0/0 [251/0] via 192.0.2.50, 5w2d, Sdwan-system-intf
      10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks
m        10.1.0.0/24 [251/0] via 192.0.2.50, 5w2d, Sdwan-system-intf
"""


def overlay_capture(extra: tuple[tuple[str, str], ...] = (), policy: str = POLICY, local: str = LOCAL, app_route: str = APP_ROUTE, peers: str = PEERS) -> str:
    return capture(
        ("show clock", "20:21:00.123 WIB Mon Oct 12 2026"),
        ("show sdwan bfd sessions", BFD), ("show sdwan control local-properties", local), ("show sdwan omp peers", peers),
        ("show sdwan omp tlocs", TLOCS), ("show sdwan omp routes", ROUTES), ("show sdwan app-route stats", app_route),
        ("show sdwan policy from-vsmart", policy), ("show ip route vrf 1", ROUTE_TABLE_VRF1), *extra,
    )


@pytest.fixture(scope="module")
def result():
    return analyze(overlay_capture(), filename="overlay.txt")


def section(result: dict, section_id: str) -> dict:
    return next(s for s in result["sections"] if s["id"] == section_id)


def finding_ids(result: dict) -> list[str]:
    return [f["id"] for f in result["findings"]]


def test_every_overlay_command_is_analysed_and_the_tab_exists(result):
    rows = {c["command"]: c for c in result["coverage"]}
    for command in ("show sdwan omp peers", "show sdwan omp tlocs", "show sdwan omp routes", "show sdwan control local-properties", "show sdwan app-route stats", "show sdwan policy from-vsmart"):
        assert rows[command]["status"] == "analysed", command
    assert not result["warnings"]
    groups = {s["group"] for s in result["sections"]}
    assert "SD-WAN overlay" in groups


def test_omp_overview_counts_and_checks_the_routing_table(result):
    pairs = {p["label"]: p for p in section(result, "sdwan_omp_summary")["pairs"]}
    assert pairs["OMP sessions up"]["value"] == "1 of 2" and pairs["OMP sessions up"]["tone"] == "bad"
    assert pairs["Overlay prefixes"]["value"].startswith("3 in 1 VPN(s)") and "5 paths" in pairs["Overlay prefixes"]["value"]
    assert pairs["Prefixes with no resolved path"]["value"] == "1"
    # one prefix marked installed in OMP (10.1.0.0/24) and one OMP route in 'show ip route vrf 1' besides the default
    rib = pairs["VPN 1: installed in OMP vs routing table"]
    assert "1 OMP prefixes marked installed" in rib["value"] and "2 OMP routes" in rib["value"] and rib["tone"] == "warn"


def test_overlay_prefix_table_marks_unresolved_prefixes(result):
    table = section(result, "sdwan_omp_prefixes")
    assert table["total"] == 3 and len(table["rows"]) == 3
    unresolved = [r for r in table["rows"] if r["resolved"] == "No"]
    assert [r["prefix"] for r in unresolved] == ["10.2.0.0/29"] and unresolved[0]["_tones"]["resolved"] == "warn"
    by_color = {r["color"]: r for r in section(result, "sdwan_omp_colors")["rows"]}
    # this router's colors come from its WAN interfaces and BFD sessions: custom2, mpls, private2 (not private1)
    assert by_color["private1"]["local"] == "No" and by_color["private2"]["local"] == "Yes" and by_color["mpls"]["local"] == "Yes"
    assert by_color["mpls"]["bfd"] == 2 and by_color["mpls"]["unresolved"] == 0 and by_color["private1"]["unresolved"] == 1


def test_identity_table_hides_token_serial_and_organization(result):
    pairs = {p["label"]: p["value"] for p in section(result, "sdwan_identity")["pairs"]}
    assert pairs["Site ID"] == "10001" and pairs["Certificate validity"] == "Valid"
    assert not any("MASKED" in str(v) for v in pairs.values())
    assert not any(k in pairs for k in ("Token", "Serial number", "Organization", "Organization name"))
    wan = {r["interface"]: r for r in section(result, "sdwan_wan_interfaces")["rows"]}
    assert wan["GigabitEthernet0/0/2"]["state"] == "down" and wan["GigabitEthernet0/0/2"]["_tones"]["state"] == "bad" and wan["GigabitEthernet0/0/2"]["_tones"]["nat"] == "warn"
    assert wan["GigabitEthernet0/0/0"]["color"] == "custom2"


def test_tunnel_quality_compares_the_means_with_the_pushed_classes(result):
    rows = {(r["local_color"], r["remote_color"]): r for r in section(result, "sdwan_tunnel_quality")["rows"]}
    first, second = rows[("custom2", "mpls")], rows[("mpls", "mpls")]
    # first: loss 0 %, latency 80 ms, jitter 2 ms -> within Default (25/300/100), over VOICE (2/45/100) on latency
    assert first["fit"] == "1 of 2" and first["worst_latency"] == 83 and first["worst_loss"] == 3
    # second: loss 30 % -> over both classes
    assert second["fit"] == "meets none" and second["_tones"]["fit"] == "bad"


def test_findings_for_the_overlay(result):
    by_id = {}
    for f in result["findings"]:
        by_id.setdefault(f["id"], []).append(f)
    # OMP: one of two sessions is down, a medium finding because the other one is up
    assert by_id["RTR-SDW-040"][0]["severity"] == "medium" and "192.0.2.11" in by_id["RTR-SDW-040"][0]["title"]
    assert by_id["RTR-SDW-040"][0]["reference"] == REFS["sdwan_control_troubleshoot"]
    # 1 of 3 prefixes unresolved: low, with the colors and the documentation page
    sdw41 = by_id["RTR-SDW-041"][0]
    assert sdw41["severity"] == "low" and sdw41["title"].startswith("1 of 3 overlay prefixes") and "Inv,U" in sdw41["title"] and sdw41["reference"] == REFS["sdwan_omp_bestpath"]
    # WAN interface 0/0/2 is down and reports NAT type A while its BFD session is down
    sdw52, sdw53 = by_id["RTR-SDW-052"][0], by_id["RTR-SDW-053"][0]
    assert sdw52["severity"] == "medium" and "GigabitEthernet0/0/2 (private2)" in sdw52["title"] and "14:06:06:58" in sdw52["detail"]
    assert sdw53["severity"] == "medium" and sdw53["reference"] == REFS["sdwan_nat_types"]
    # the second tunnel meets neither SLA class, and its mean loss is 30 %
    assert by_id["RTR-SDW-060"][0]["title"].startswith("1 of 2 overlay tunnels meet none") and by_id["RTR-SDW-060"][0]["reference"] == REFS["sdwan_bfd_approute"]
    assert by_id["RTR-SDW-061"][0]["reference"] == REFS["sdwan_aar_deploy"]
    # policy: one strict rule; sequence 11 names LIST_C, which the output does not define
    assert by_id["RTR-SDW-070"][0]["severity"] == "info" and "1 application-aware routing rule" in by_id["RTR-SDW-070"][0]["title"]
    assert by_id["RTR-SDW-072"][0]["object"] == "destination-data-prefix-list LIST_C" and by_id["RTR-SDW-072"][0]["severity"] == "low"


def test_healthy_overlay_raises_no_overlay_finding():
    healthy_local = LOCAL.replace("pri                          vate2         down", "pri                          vate2         up  ").replace("  A    5", "  N    5")
    peers = PEERS.replace("down     0:00:00:00       0/0/0", "up       1:00:00:00       5/0/8")
    app_route = APP_ROUTE.replace("mean-loss    30", "mean-loss    0")
    text = overlay_capture(peers=peers, local=healthy_local, app_route=app_route, policy=POLICY.replace("    sla-class strict\n", "").replace("destination-data-prefix-list LIST_C", "destination-data-prefix-list LIST_B"))
    ids = [i for i in finding_ids(analyze(text, filename="healthy.txt")) if i.startswith(("RTR-SDW-04", "RTR-SDW-05", "RTR-SDW-06", "RTR-SDW-07"))]
    # the unresolved prefix belongs to the routes; the policy still prefers custom1, a color this router has no tunnel in
    assert ids == ["RTR-SDW-041", "RTR-SDW-071"]


def test_certificate_problem_is_a_high_finding():
    bad = LOCAL.replace("certificate-validity              Valid", "certificate-validity              Invalid").replace("root-ca-chain-status              Installed", "root-ca-chain-status              Not-Installed")
    result = analyze(overlay_capture(local=bad), filename="cert.txt")
    ids = {f["id"]: f for f in result["findings"]}
    assert ids["RTR-SDW-050"]["severity"] == "high" and "CRTVERFL" in ids["RTR-SDW-050"]["detail"]
    assert ids["RTR-SDW-051"]["severity"] == "high"
    pairs = {p["label"]: p for p in section(result, "sdwan_identity")["pairs"]}
    assert pairs["Certificate validity"]["tone"] == "bad" and pairs["Root CA chain"]["tone"] == "bad"


def test_policy_color_this_router_does_not_have_is_information_only():
    result = analyze(overlay_capture(), filename="color.txt")
    f = next(f for f in result["findings"] if f["id"] == "RTR-SDW-071")
    # the router has custom2 (WAN table), mpls (WAN table), private2; the policy prefers custom1
    assert f["severity"] == "info" and f["object"] == "custom1"


def test_every_overlay_reference_is_a_cisco_page():
    for key in ("sdwan_omp_bestpath", "sdwan_bfd_approute", "sdwan_aar_policy", "sdwan_aar_deploy", "sdwan_nat_types", "sdwan_command_reference"):
        assert REFS[key].startswith("https://www.cisco.com/c/en/us/"), key


# ---------------------------------------------------------------------------
# empty answers
# ---------------------------------------------------------------------------

ETHERCHANNEL_EMPTY = """
Flags:  D - down        P/bndl - bundled in port-channel
        I - stand-alone s/susp - suspended
        H - Hot-standby (LACP only)
        R - Layer3      S - Layer2
        U - in use      f - failed to allocate aggregator

        M - not in use, minimum links not met
        u - unsuitable for bundling
        w - waiting to be aggregated
        d - default port


Number of channel-groups in use: 0
Number of aggregators:           0

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------

RU - L3 port-channel UP State
SU - L2 port-channel UP state
P/bndl -  Bundled
S/susp  - Suspended
"""

CDP_EMPTY = """
Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge
                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone,
                  D - Remote, C - CVTA, M - Two-port Mac Relay

Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID

Total cdp entries displayed : 0
"""

VRRP_HEADER = "Interface          Grp Pri Time  Own Pre State   Master addr     Group addr"
ISAKMP_HEADERS = "IPv4 Crypto ISAKMP SA\ndst             src             state          conn-id status\n\nIPv6 Crypto ISAKMP SA"


def coverage(text: str) -> dict[str, dict]:
    ctx = ctxmod.gather(text, "empty.txt")
    return {row["command"]: row for row in ctx.coverage}


def test_commands_that_answered_with_an_empty_table_are_analysed_not_unparsed():
    rows = coverage(capture(
        ("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show etherchannel summary", ETHERCHANNEL_EMPTY), ("show cdp neighbors", CDP_EMPTY), ("show cdp neighbors detail", "\nTotal cdp entries displayed : 0"),
        ("show ip bgp neighbors", "% BGP not active"), ("show crypto ipsec sa", "No SAs found"), ("show vrrp brief", VRRP_HEADER), ("show crypto isakmp sa", ISAKMP_HEADERS),
    ))
    for command, phrase in (("show etherchannel summary", "no port-channels"), ("show cdp neighbors", "no CDP neighbors"), ("show cdp neighbors detail", "no CDP neighbors"), ("show ip bgp neighbors", "BGP is not running"),
                            ("show crypto ipsec sa", "no IPsec SAs"), ("show vrrp brief", "no VRRP groups"), ("show crypto isakmp sa", "no IKE phase-1 SAs")):
        assert rows[command]["status"] == "analysed", command
        assert phrase in rows[command]["note"], (command, rows[command]["note"])


def test_an_empty_marker_does_not_hide_a_table_the_parser_could_not_read():
    # the line below looks like a VRRP row but is not in the format the parser reads; the block must stay "not parsed"
    odd = VRRP_HEADER + "\nGi0/1   10  100   3600   Y  Y   Master  garbled"
    assert coverage(capture(("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show vrrp brief", odd)))["show vrrp brief"]["status"] == "not parsed"
    # a counter other than zero is not an empty answer either
    busy = ETHERCHANNEL_EMPTY.replace("channel-groups in use: 0", "channel-groups in use: 2")
    assert coverage(capture(("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show etherchannel summary", busy)))["show etherchannel summary"]["status"] == "not parsed"


def test_bgp_commands_are_not_missing_on_a_router_that_answered_bgp_not_active():
    text = capture(("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show ip bgp neighbors", "% BGP not active"))
    missing = [gap["command"] for gap in ctxmod.missing_commands(ctxmod.gather(text, "x.txt"))]
    assert "show ip bgp neighbors" not in missing and "show ip bgp" not in missing


def test_validation_note_lists_only_the_parsers_no_real_capture_has_confirmed():
    assert set(UNVALIDATED) == {"eigrp_neighbors", "standby", "vrrp"}
    result = analyze(capture(("show clock", "20:21:00.123 WIB Mon Oct 12 2026"), ("show ip ospf neighbor", "Neighbor ID     Pri   State           Dead Time   Address         Interface\n192.0.2.9         1   FULL/DR         00:00:35    192.0.2.9       GigabitEthernet0/0/0")), filename="ospf.txt")
    assert not [w for w in result["warnings"] if "not yet validated" in w]


# --------------------------------------------------------------------------- masked real-layout fixture
FIXTURE = Path(__file__).parent / "fixtures" / "router" / "cedge_sdwan_overlay_masked.txt"


@pytest.fixture(scope="module")
def fixture_result():
    return analyze(FIXTURE.read_text(), filename="cedge_overlay.txt")


def test_fixture_is_read_without_warnings_and_every_command_is_accounted_for(fixture_result):
    assert fixture_result["warnings"] == []
    rows = {row["command"]: row for row in fixture_result["coverage"]}
    for command in ("show sdwan bfd sessions", "show sdwan control local-properties", "show sdwan omp peers", "show sdwan omp tlocs", "show sdwan omp routes", "show sdwan app-route stats",
                    "show sdwan policy from-vsmart", "show ip route vrf 1", "show etherchannel summary", "show cdp neighbors"):
        assert rows[command]["status"] == "analysed", (command, rows[command])
    assert "no port-channels" in rows["show etherchannel summary"]["note"] and "no CDP neighbors" in rows["show cdp neighbors"]["note"]


def test_fixture_counts_match_a_hand_count_of_the_text(fixture_result):
    # counted from the file: 12 prefixes, 34 path rows; status C,I,R x5, R x5, C,Red,R x2, Inv,U x22; 22 OMP routes ('m') in the VRF 1 table
    status = {row["status"]: row["paths"] for row in section(fixture_result, "sdwan_omp_status")["rows"]}
    assert status == {"C,I,R": 5, "R": 5, "C,Red,R": 2, "Inv,U": 22}
    prefixes = section(fixture_result, "sdwan_omp_prefixes")
    assert prefixes["total"] == 12 and len(prefixes["rows"]) == 12
    summary = {pair["label"]: pair["value"] for pair in section(fixture_result, "sdwan_omp_summary")["pairs"]}
    assert summary["OMP sessions up"] == "2 of 2"
    assert summary["Overlay prefixes"] == "12 in 1 VPN(s) \u00b7 34 paths"
    assert summary["Prefixes with a resolved path"] == "6" and summary["Prefixes with no resolved path"] == "6"
    assert "5 OMP prefixes marked installed" in summary["VPN 1: installed in OMP vs routing table"] and "22 OMP routes" in summary["VPN 1: installed in OMP vs routing table"]


def test_fixture_wrapped_path_ids_do_not_create_paths(fixture_result):
    # four prefixes carry a PATH ID that the device wrapped onto a digits-only line (40205 / 2 ...); they must stay one path each
    rows = section(fixture_result, "sdwan_omp_prefixes")["rows"]
    assert sum(1 for row in rows if row.get("paths") == 4) >= 1
    assert sum(row["paths"] for row in rows) == 34


def test_fixture_colors_and_local_tlocs(fixture_result):
    colors = {row["color"]: row for row in section(fixture_result, "sdwan_omp_colors")["rows"]}
    assert set(colors) == {"private1", "mpls", "private2", "private4", "private3", "custom1", "custom2"}
    assert colors["mpls"]["bfd"] == 8 and colors["mpls"]["unresolved"] == 0 and colors["mpls"]["usable"] == 10
    assert colors["private1"]["local"] == "Yes" and colors["private4"]["local"] == "No"
    wan = {row["interface"]: row["color"] for row in section(fixture_result, "sdwan_wan_interfaces")["rows"]}
    assert wan == {"GigabitEthernet0/0/0": "private1", "GigabitEthernet0/0/1": "private2"}


def test_fixture_identity_hides_secrets_and_keeps_the_certificate(fixture_result):
    pairs = {pair["label"]: pair["value"] for pair in section(fixture_result, "sdwan_identity")["pairs"]}
    assert pairs["Certificate"] == "Installed" and pairs["Embargo check"] == "success"
    assert not [label for label in pairs if re.search(r"token|serial|chassis|organi", label, re.I)]


def test_fixture_findings_and_tunnel_quality(fixture_result):
    assert finding_ids(fixture_result) == ["RTR-SDW-041", "RTR-SDW-071"]
    quality = section(fixture_result, "sdwan_tunnel_quality")["rows"]
    assert [(row["local_color"], row["loss"], row["latency"], row["jitter"], row["worst_loss"]) for row in quality] == [("private2", 0, 2, 0, 1), ("private1", 0, 4, 1, 0)]
    assert all(row["fit"] == "1 of 1" for row in quality)
    rules = section(fixture_result, "sdwan_aar_rules")["rows"]
    assert [row["sequence"] for row in rules] == ["1", "11", "21"] and all(row["preferred"] == ["custom1", "custom2"] for row in rules)
    assert section(fixture_result, "sdwan_sla_classes")["rows"][0]["used"] == 3
