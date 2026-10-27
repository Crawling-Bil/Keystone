"""Router Analyzer 0.9: three defects found on real IOS XE / SD-WAN captures (a connection up for more than a year, GETVPN on IOS XE 16/17).
The text is invented (documentation addresses, example names) in the layouts the devices print."""

from __future__ import annotations

from features.router_analyzer import runtime_sdwan as rsd
from features.router_analyzer import runtime_vpn as rv

CONTROL = """\
                                                                                       PEER                                          PEER                                          CONTROLLER
PEER    PEER PEER            SITE       DOMAIN PEER                                    PRIV  PEER                                    PUB                                           GROUP
TYPE    PROT SYSTEM IP       ID         ID     PRIVATE IP                              PORT  PUBLIC IP                               PORT  ORGANIZATION            LOCAL COLOR     PROXY STATE UPTIME      ID
----------------------------------------------------------------------------------------------------------------------------------------------------------------
vsmart  dtls 10.0.10.2       100        1      198.51.100.6                            12746 198.51.100.6                            12746 EXAMPLE-FABRIC          mpls            No    up     1y 41:21:54:040
vsmart  dtls 10.0.20.2       200        1      203.0.113.6                             12746 203.0.113.6                             12746                         mpls            No    connect           0
vbond   dtls 0.0.0.0         0          0      198.51.100.7                            12346 198.51.100.7                            12346 EXAMPLE-FABRIC          mpls            -     up     1y 41:21:54:070
vmanage dtls 10.0.10.1       100        0      198.51.100.5                            12746 198.51.100.5                            12746 EXAMPLE-FABRIC          mpls            No    up     19:10:16:300
"""


def test_a_control_connection_that_is_up_for_more_than_a_year_keeps_its_state_and_color():
    rows = {(r["type"], r["system_ip"]): r for r in rv.parse_sdwan_control_connections(CONTROL.splitlines())}
    assert len(rows) == 4
    vsmart = rows[("vsmart", "10.0.10.2")]
    assert (vsmart["state"], vsmart["local_color"], vsmart["proxy"], vsmart["organization"]) == ("up", "mpls", "No", "EXAMPLE-FABRIC")
    assert (vsmart["uptime"], vsmart["group_id"]) == ("1y 41:21:54:04", "0")
    assert rows[("vbond", "0.0.0.0")]["state"] == "up" and rows[("vbond", "0.0.0.0")]["proxy"] == "-"
    assert rows[("vmanage", "10.0.10.1")]["uptime"] == "19:10:16:30"                  # the old glued form is unchanged
    down = rows[("vsmart", "10.0.20.2")]
    assert (down["state"], down["uptime"], down["organization"]) == ("connect", "", "")


OMP = """\
R -> routes received
I -> routes installed
S -> routes sent

TENANT                             DOMAIN    OVERLAY   SITE      REGION
ID        PEER             TYPE    ID        ID        ID        ID        STATE    UPTIME           R/I/S
-----------------------------------------------------------------------------------------------------------------
0         10.0.10.2        vsmart  1         1         100       None      up       1y 41:21:55:45   11215/9365/2180
0         10.0.20.2        vsmart  1         1         200       None      up       19:10:16:30      15/15/10
"""


def test_an_omp_session_with_a_year_in_its_uptime_is_a_row():
    rows = rsd.parse_omp_peers(OMP.splitlines())
    assert [(r["peer"], r["state"], r["uptime"], r["received"], r["installed"], r["sent"]) for r in rows] == [
        ("10.0.10.2", "up", "1y 41:21:55:45", 11215, 9365, 2180), ("10.0.20.2", "up", "19:10:16:30", 15, 15, 10)]


def test_join_years_leaves_other_lines_alone():
    assert rsd.join_years("a 1y b 12:00:00:00 c".split()) == ["a", "1y", "b", "12:00:00:00", "c"]
    assert rsd.join_years("up 2y 286:17:56:00".split()) == ["up", "2y 286:17:56:00"]


GDOI_17 = """\
GROUP INFORMATION

    Group Name               : GROUP-A
    Group Identity           : 1234
    Crypto Path              : ipv4
    Key Management Path      : ipv4
    Rekeys received          : 11713
    IPSec SA Direction       : Both

     Group Server list       : 192.0.2.21
                               192.0.2.22

    Group member             : 192.0.2.23    vrf: None
       Version               : 1.0.1
       Registration status   : Registered
       Registered with       : 192.0.2.21
       Re-registers in       : 63310 sec
       Succeeded registration: 1
       Attempted registration: 1
       Last rekey from       : 192.0.2.21
       Last rekey seq num    : 5
       Unicast rekey received: 11713
       Rekey ACKs sent       : 11713
       Rekey Rcvd(hh:mm:ss)  : 01:30:44
"""


def test_a_getvpn_member_that_prints_registered_with_has_an_active_key_server():
    info = rv.parse_gdoi(GDOI_17.splitlines())
    assert info["active_ks"] == "192.0.2.21" and info["registration"] == "Registered"
    assert (info["reregister_in"], info["last_rekey_age"], info["rekey_acks"], info["last_rekey_from"]) == ("63310 sec", "01:30:44", "11713", "192.0.2.21")


def test_a_getvpn_member_that_is_not_registered_still_has_no_key_server():
    text = GDOI_17.replace("Registered\n", "Not Registered\n", 1).replace("Registered with       : 192.0.2.21", "Registered with       :")
    assert not rv.parse_gdoi(text.splitlines()).get("active_ks")


def test_write_memory_is_an_action_not_an_unparsed_show_command():
    from features.router_analyzer import service
    capture = ("R1#write memory\nBuilding configuration...\n[OK]\nR1#show version | inc uptime\nR1 uptime is 3 weeks\nR1#show ip interface brief\n"
               "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0     192.0.2.1       YES manual up                    up\nR1#\n")
    rows = {r["command"]: r for r in service.analyze(capture, "r1.txt")["coverage"]}
    assert rows["write memory"]["status"] == "ignored" and rows["show version | inc uptime"]["status"] == "ignored"
