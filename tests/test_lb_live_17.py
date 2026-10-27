"""Live ``show`` output of TMOS 17.1: nested ``| `` objects, typed GTM headers, member names, and the system / network / traffic tables.

Every name, address and key in this file is invented; only the layout follows what a BIG-IP 17.1 prints in an interactive tmsh session.
"""

from __future__ import annotations

from datetime import date

from features.lb_analyzer import bigip_map, bigip_runtime, bigip_runtime_sys as sysout, service

TODAY = date(2026, 10, 24)
PROMPT = "ops@(lab-ltm1)(cfg-sync In Sync)(Active)(/Common)(tmos)# "


def _capture(*commands: tuple[str, str]) -> str:
    """A terminal buffer: each command is echoed behind the prompt, then its output."""
    return "\n".join(f"{PROMPT}{command}\n{output}\n" for command, output in commands)


POOL_MEMBERS = """
------------------------------------------------
Ltm::Pool: pl_web
------------------------------------------------
Status
  Availability           : available
  State                  : enabled
  Reason                 : The pool is available
  Current Active Members : 1
  Available Members      : 1
  Total Members          : 2

  -------------------------------------------------
  | Ltm::Pool Member: 192.0.2.10:443
  -------------------------------------------------
  | Status
  |   Availability   : available
  |   State          : enabled
  |   Reason         : Pool member is available
  |   Monitor Status : up
  |   Pool Name      : pl_web
  |   IP Address     : 192.0.2.10
  |
  | Traffic                                  ServerSide
  |   Current Connections                             3

  -------------------------------------------------
  | Ltm::Pool Member: 192.0.2.11:443
  -------------------------------------------------
  | Status
  |   Availability   : offline
  |   State          : enabled
  |   Reason         : Pool member has been marked down by a monitor
  |   Monitor Status : down
  |   Pool Name      : pl_web
  |   IP Address     : 192.0.2.11
"""


def test_unpipe_removes_the_nesting_prefix_only():
    assert bigip_runtime.unpipe("  | Status\n  |   State : enabled\n  |\nplain") == "Status\n  State : enabled\n\nplain"
    assert bigip_runtime.unpipe("no bars here") == "no bars here"


def test_pool_members_nested_behind_pipes_are_read():
    members = bigip_runtime.parse_pool_members(bigip_runtime.unpipe(POOL_MEMBERS))
    assert [(m["pool"], m["member"], m["availability"], m["monitor_status"]) for m in members] == [
        ("pl_web", "192.0.2.10:443", "available", "up"), ("pl_web", "192.0.2.11:443", "offline", "down")]


GTM_POOL = """
-------------------------------------------
Gtm::Pool::A www.example.test
-------------------------------------------
Status
  Availability : available
  State        : enabled
  Reason       : Available

  -----------------------------------------------------------------
  | Gtm::Pool Member: www.example.test:A srv_one:vs_https
  -----------------------------------------------------------------
  | Status
  |   Availability : offline
  |   State        : enabled
  |   Reason       : Monitor /Common/bigip : DOWN
"""


def test_typed_gtm_headers_and_member_order():
    records = bigip_runtime.merge_gtm(bigip_runtime.parse_gtm(bigip_runtime.unpipe(GTM_POOL)))
    pools = [r for r in records if r["kind"] == "pool"]
    members = [r for r in records if r["kind"] == "member"]
    assert [(p["name"], p["type"]) for p in pools] == [("www.example.test", "a")]
    assert len(members) == 1 and members[0]["availability"] == "offline" and members[0]["parent"] == "www.example.test"
    # the live name is 'virtual server : server' ('srv_one:vs_https' above is the order tmsh prints); the configuration says 'server:virtual'
    assert "vs_https" in members[0]["name"] and "srv_one" in members[0]["name"]


def test_partition_on_both_halves_of_a_config_member_name_is_dropped():
    assert bigip_map._key("/Common/srv_one:/Common/vs_https") == bigip_map._key("srv_one:vs_https")


# ----------------------------------------------------------------------------------------------- system / network
INTERFACES = """
-------------------------------------------------------------------
Net::Interface
Name  Status    Bits    Bits   Pkts    Pkts  Drops  Errs      Media
                  In     Out     In     Out
-------------------------------------------------------------------
1.1       up  343.0T  324.3T  44.8G   20.5G      0     0   1000T-FD
1.2       up    4.5T    2.7T   2.5G    1.1G     12     3   1000T-FD
1.3   uninit       0       0      0       0      0     0       none
mgmt      up    1.4T   13.4T   2.0G  611.6M      0     0   100TX-FD
"""

ARP = """
------------------------------------------------------------------------------------------------------
Net::Arp
Name             Address          HWaddress          Vlan                      Expire-in-sec  Status
------------------------------------------------------------------------------------------------------
192.0.2.1        192.0.2.1        00:00:5e:00:53:01  /Common/vl_web            297            resolved
192.0.2.77       192.0.2.77       incomplete         /Common/vl_web            0              unknown
"""

PERFORMANCE = """
Sys::Performance System
-------------------------------------------------------------------
System CPU Usage(%)  Current  Average  Max(since 10/23/26 12:21:59)
-------------------------------------------------------------------
Utilization               91       27                            93

-------------------------------------------------------------------
Memory Used(%)       Current  Average  Max(since 10/23/26 12:21:59)
-------------------------------------------------------------------
TMM Memory Used            4        4                             4
Swap Used                  0        0                             2

-----------------------------------------------------------------------------
Throughput(bits)(bits/sec)     Current  Average  Max(since 10/23/26 12:21:59)
-----------------------------------------------------------------------------
Service                          10.3M     9.7M                        170.4M
"""


def test_interfaces_arp_performance():
    ports = sysout.parse_interfaces(INTERFACES)
    assert [(p["name"], p["status"], p["media"]) for p in ports] == [("1.1", "up", "1000T-FD"), ("1.2", "up", "1000T-FD"), ("1.3", "uninit", "none"), ("mgmt", "up", "100TX-FD")]
    assert (ports[1]["drops_n"], ports[1]["errors_n"]) == (12, 3)
    arp = sysout.parse_arp(ARP)
    assert [(a["address"], a["mac"], a["vlan"]) for a in arp] == [("192.0.2.1", "00:00:5e:00:53:01", "vl_web"), ("192.0.2.77", "incomplete", "vl_web")]
    perf = {(r["group"], r["metric"]): r for r in sysout.parse_performance(PERFORMANCE)}
    assert perf[("System CPU Usage", "Utilization")]["current_n"] == 91 and perf[("System CPU Usage", "Utilization")]["unit"] == "%"
    assert perf[("Memory Used", "Swap Used")]["maximum_n"] == 2
    assert perf[("Throughput", "Service")]["current_n"] == 10.3e6 and perf[("Throughput", "Service")]["since"] == "10/23/26 12:21:59"


def test_number_suffixes():
    assert sysout.number("1.9K") == 1900 and sysout.number("10.3M") == 10.3e6 and sysout.number("7") == 7 and sysout.number("none") is None


LICENSE = """
Sys::License
Licensed Version                 13.1.3
Registration key                 AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE
Licensed On                      2020/02/11
Service Check Date               2025/09/01
Platform ID                      C115
Appliance Serial Number          lab-0001

Active Modules
  Better Bundle, i4600 (ABCDEFG-HIJKLMN)
    Rate Shaping
    DNSSEC

Time Limited Modules
  IP Intelligence, 1Yr|ABCDEFG-HIJKLMN|20201012|20261206|SUBSCRIPTION
"""

VERSION = "Sys::Version\nMain Package\n  Product     BIG-IP\n  Version     17.1.3\n  Build       0.0.11\n  Edition     Final\n  Date        Wed Oct  8 14:16:07 PDT 2025\n"


def test_license_never_keeps_the_registration_key():
    lic = sysout.parse_license(LICENSE)
    assert "AAAAA" not in repr(lic)
    assert (lic["platform"], lic["serial"], lic["service_check"]) == ("C115", "lab-0001", "2025/09/01")
    assert lic["bundles"] == [{"name": "Better Bundle, i4600", "features": ["Rate Shaping", "DNSSEC"]}]
    assert lic["limited"][0]["end_date"] == date(2026, 12, 6) and lic["limited"][0]["kind"] == "SUBSCRIPTION"


HA = """
Sys::HA Status
Feature               Key             Action                        Fail
------------------------------------------------------------------------
daemon-heartbeat      bigd            restart                       no
nic-failsafe          tmm             reboot                        yes
"""

FAILOVER = """
CM::Failover Status
Color    green
Status   ACTIVE
Summary  1/1 active

CM::Failover Connections
Local Failover Address  Remote Device  Packets  Transitions  Received Last Packet  Status
10.0.0.1:1026           peer.lab.test  1000     5            2026-Oct-23 15:16:54  Down
"""

CM_DEVICE = """
-----------------------------------------------------------
CentMgmt::Device: lab-ltm1.lab.test
-----------------------------------------------------------
Hostname                          lab-ltm1.lab.test
Mgmt IP                           192.0.2.21
Configsync IP                     10.0.0.1
Device HA State                   active

-----------------------------------------------------------
CentMgmt::Device: lab-ltm2.lab.test
-----------------------------------------------------------
Hostname                          lab-ltm2.lab.test
Mgmt IP                           192.0.2.22
Configsync IP                     10.0.0.2
Device HA State                   active
"""

SSL = """
-------------------------------------------------------------------
Ltm::ClientSSL Profile: cs_old
-------------------------------------------------------------------
Virtual Server Name                                              N/A

Connections                                                     Open   Maximum   Total
  Native                                                           0      1.6K  614.1K

Protocol
  SSL Protocol Version 3                                            0
  TLS Protocol Version 1.0                                       1000
  TLS Protocol Version 1.2                                     613.1K
-------------------------------------------------------------------
Ltm::ServerSSL Profile: ss_new
-------------------------------------------------------------------
Connections                                                     Open   Maximum   Total
  Native                                                           1        10      55
Protocol
  TLS Protocol Version 1.2                                         55
"""

RULES = """
-----------------------------------------------------
Ltm::Rule Event: /Common/redirect_http:HTTP_REQUEST
-----------------------------------------------------
Priority                 500
Executions
  Total                  12.0K
  Failures                   2
  Aborts                     0
CPU Cycles on Executing
  Average                 1.8K
  Maximum                 9.2K
  Minimum                  500
"""


def _runtime() -> dict:
    return bigip_runtime.gather(_capture(
        ("show sys version", VERSION), ("show sys license", LICENSE), ("show sys ha-status", HA), ("show cm failover-status", FAILOVER), ("show cm device-group", "CM::Device-Group\nGroup Name   lab\nMember Name  x"),
        ("show cm device", CM_DEVICE), ("show net interface", INTERFACES), ("show net arp", ARP), ("show sys performance all-stats", PERFORMANCE), ("show ltm profile client-ssl", SSL), ("show ltm rule", RULES)))


def test_gather_reads_each_command_exactly():
    runtime = _runtime()
    assert {"license", "ha_status", "cm_devices", "interfaces", "arp", "performance", "client_ssl", "rules"} <= set(runtime)
    assert [d["hostname"] for d in runtime["cm_devices"]] == ["lab-ltm1.lab.test", "lab-ltm2.lab.test"]   # 'show cm device' must not pick 'show cm device-group'
    assert runtime["failover"]["connections"][0]["status"] == "Down"
    assert runtime["rules"][0]["rule"] == "redirect_http" and runtime["rules"][0]["event"] == "HTTP_REQUEST" and runtime["rules"][0]["failures"] == 2


def test_ssl_profile_kinds_and_legacy_versions():
    profiles = {p["name"]: p for p in sysout.parse_ssl_profiles(SSL)}
    assert (profiles["cs_old"]["kind"], profiles["ss_new"]["kind"]) == ("client", "server")
    assert profiles["cs_old"]["legacy"] == 1000 and profiles["ss_new"]["legacy"] == 0
    assert profiles["cs_old"]["total"] == "614.1K"


def test_rules_fire_on_the_synthetic_capture():
    from features.lb_analyzer import bigip_rules, bigip_rules_sys
    from features.lb_analyzer.bigip_context import LCtx
    ctx = LCtx(tree=None, data={}, res=None, today=TODAY, runtime=_runtime())
    found = {(f["id"], f["severity"]) for f in bigip_rules_sys.sys_runtime_rules(ctx)}
    assert ("LB-RT-005", "high") in found            # nic-failsafe triggered
    assert ("LB-RT-006", "high") in found            # failover connection Down
    assert ("LB-RT-007", "high") in found            # two devices active
    assert ("LB-RT-008", "high") in found            # service check 2025/09/01 is older than the 2025-10-08 build
    assert ("LB-RT-009", "low") in found             # IP Intelligence ends 2026-12-06, 43 days after TODAY
    assert ("LB-RT-010", "medium") in found          # TLS 1.0 handshakes
    assert ("LB-RT-011", "medium") in found          # errors on 1.2
    assert ("LB-RT-012", "low") in found             # incomplete ARP
    assert ("LB-RT-013", "medium") in found          # CPU 91 % and swap
    assert ("LB-RT-014", "medium") in found          # iRule failures
    assert bigip_rules  # module imports cleanly with the new rule registered
    assert bigip_rules_sys.sys_runtime_rules in bigip_rules.RULES


def test_rules_are_silent_without_the_output():
    from features.lb_analyzer import bigip_rules_sys
    from features.lb_analyzer.bigip_context import LCtx
    assert list(bigip_rules_sys.sys_runtime_rules(LCtx(tree=None, data={}, res=None, today=TODAY, runtime={}))) == []


def test_a_healthy_licence_does_not_fire():
    from features.lb_analyzer import bigip_rules_sys
    from features.lb_analyzer.bigip_context import LCtx
    runtime = {"version": sysout and {"date": "Wed Oct  8 14:16:07 PDT 2025", "version": "17.1.3"}, "license": {"service_check_date": date(2026, 1, 1), "limited": [{"name": "x", "end_date": date(2030, 1, 1), "kind": "S"}]}}
    assert list(bigip_rules_sys.sys_runtime_rules(LCtx(tree=None, data={}, res=None, today=TODAY, runtime=runtime))) == []


def test_live_tabs_and_no_registration_key_in_the_result():
    config = "ltm virtual /Common/vs_lab {\n    destination /Common/192.0.2.50:443\n    ip-protocol tcp\n    mask 255.255.255.255\n    pool /Common/pl_web\n}\nltm pool /Common/pl_web {\n    members {\n        /Common/192.0.2.10:443 {\n            address 192.0.2.10\n        }\n    }\n}"
    text = _capture(("tmsh list ltm virtual", config), ("show sys license", LICENSE), ("show net interface", INTERFACES), ("show net arp", ARP), ("show sys performance all-stats", PERFORMANCE),
                    ("show ltm rule", RULES), ("show sys version", VERSION))
    result = service.analyze(text, "lab.txt", today=TODAY)
    ids = {s["id"] for s in result["sections"]}
    assert {"license_live", "interfaces_live", "arp_live", "performance_live", "rules_live"} <= ids
    assert "AAAAA-BBBBB" not in repr(result)
    assert any("TMOS 17.1" in w for w in result["warnings"])


def test_dns_only_unit_is_not_asked_for_ltm_commands():
    config = ("gtm datacenter /Common/dc1 { }\ngtm server /Common/srv1 {\n    datacenter /Common/dc1\n    product bigip\n    addresses {\n        192.0.2.5 { }\n    }\n"
              "    virtual-servers {\n        vs1 {\n            destination 192.0.2.80:443\n        }\n    }\n}\n"
              "gtm pool a /Common/gp1 {\n    members {\n        /Common/srv1:vs1 { }\n    }\n}\n"
              "gtm wideip a /Common/www.example.test {\n    pools {\n        /Common/gp1 { }\n    }\n}")
    text = _capture(("tmsh list gtm", config), ("show sys version", VERSION))
    result = service.analyze(text, "dns.txt", today=TODAY)
    commands = {c["command"] for c in result["coverage"]}
    assert "show gtm wideip a detail" in commands            # asked for
    assert "show ltm virtual" not in commands and "show ltm rule" not in commands
