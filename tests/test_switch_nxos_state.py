"""Switch Analyzer: the Nexus 9000 state commands (nxos_state) and the paste-ahead capture layout.

Layouts copied from NX-OS 10.4(5) / 10.5(4) output; host names, serials and addresses are invented (addresses from RFC 5737).
"""

from __future__ import annotations

from features.switch_analyzer import capture_text, nxos_state, service

MODULE = """\
Mod Ports                  Module-Type                            Model           Status
--- ----- ------------------------------------------------ --------------------- --------
1    54   48x1/10/25G + 6x40/100G Ethernet Module          N9K-C93180YC-FX3      ok
27   0    Virtual Supervisor Module                        N9K-C93180YC-FX3      active *

Mod  Sw                       Hw    Slot
---  ----------------------- ------ ----
1    10.4(5)                  1.0    NA
27   10.4(5)                  1.0    VSUP

Mod  MAC-Address(es)                         Serial-Num
---  --------------------------------------  ----------
1    00-00-5e-00-53-01 to 00-00-5e-00-53-50  FDO00000001
27   00-00-5e-00-53-01 to 00-00-5e-00-53-50  FDO00000001
"""

BOOT = """\
Current Boot Variables:
sup-1
NXOS variable = bootflash:/nxos64-cs.10.4.5.M.bin
Boot POAP Disabled

Boot Variables on next reload:
sup-1
NXOS variable = bootflash:/nxos64-cs.10.5.4.M.bin
Boot POAP Enabled
"""

RESET = """\
----- reset reason for module 1 (from Supervisor in slot 1) ---
1) At 115275 usecs after Thu Aug 21 15:34:39 2025
    Reason: Reset due to upgrade
    Service:
    Version: 10.2(9)
2) At 967446 usecs after Wed Sep 28 15:11:46 2022
    Reason: Kernel Panic
    Service: sysmgr
    Version: 9.3(5)
"""

COUNTERS = """\
--------------------------------------------------------------------------------
Port          Align-Err    FCS-Err   Xmit-Err    Rcv-Err  UnderSize OutDiscards
--------------------------------------------------------------------------------
mgmt0                   0          0         --         --         --          --
Eth1/1                  0          0          0          0          0           0
Eth1/6               1650          0          0          0          0           0

--------------------------------------------------------------------------------
Port         Single-Col  Multi-Col   Late-Col  Exces-Col  Carri-Sen       Runts
--------------------------------------------------------------------------------
Eth1/1                  0          0          0          0          0           0
Eth1/6                  0          0          0          0          0           3

--------------------------------------------------------------------------------
Port          Giants SQETest-Err Deferred-Tx IntMacTx-Er IntMacRx-Er Symbol-Err
--------------------------------------------------------------------------------
Eth1/1                  0          --          0          0          0          0
Eth1/6                  0          --          0          0          0          0
"""

TRANSCEIVER = """\
Ethernet1/1
    transceiver is present
    type is 10Gbase-SR
    name is VENDOR
    part number is PART-1
    serial number is SN000001

           SFP Detail Diagnostics Information (internal calibration)
  ----------------------------------------------------------------------------
                Current              Alarms                  Warnings
                Measurement     High        Low         High          Low
  ----------------------------------------------------------------------------
  Temperature   31.60 C        75.00 C     -5.00 C     70.00 C        0.00 C
  Voltage        3.30 V         3.63 V      2.97 V      3.46 V        3.13 V
  Current        8.77 mA       13.00 mA     4.00 mA    12.50 mA       5.00 mA
  Tx Power      -2.16 dBm       1.69 dBm  -11.30 dBm   -1.30 dBm     -7.30 dBm
  Rx Power     -40.00 dBm --    2.00 dBm  -13.90 dBm   -1.00 dBm     -9.90 dBm
  Transmit Fault Count = 0

Ethernet1/2
    transceiver is not applicable

Ethernet1/3
    transceiver is not present
"""

PORT_CHANNELS = """\
port-channel10
    Last membership update is successful
    2 ports in total, 2 ports up
    First operational port is Ethernet1/15
    Age of the port-channel is 423d:18h:45m:11s
    Time since last bundle is 423d:18h:45m:25s
    Last bundled member is Ethernet1/16
    Ports:   Ethernet1/15    [active ] [up] *
             Ethernet1/16    [active ] [up]

port-channel141
    Last membership update is successful
    2 ports in total, 1 ports up
    First operational port is Ethernet1/4
    Ports:   Ethernet1/3     [active ] [down]
             Ethernet1/4     [active ] [up] *
"""

ORPHANS = """\
Note:
--------::Going through port database. Please be patient.::--------

VLAN           Orphan Ports
-------        -------------------------
1              Po10
5              Po10, Eth1/21
6              Po10, Eth1/1, Eth1/2, Eth1/3,
               Eth1/4, Eth1/5
"""

STP_ROOT = """\
                                        Root  Hello Max Fwd
Vlan                   Root ID          Cost  Time  Age Dly  Root Port
---------------- -------------------- ------- ----- --- ---  ----------------
VLAN0001             0 0039.0039.0039       4    2   20  15   port-channel101
VLAN0002          4098 cced.4dcb.8f67       1    2   20  15   port-channel101
VLAN0003         32771 0000.5e00.5301       0    2   20  15   This bridge is the root
"""

VRF = """\
VRF-Name                           VRF-ID State   Reason
default                                 1 Up      --
management                              2 Up      --
"""

VRF_INTERFACE = """\
Interface                 VRF-Name                        VRF-ID  Site-of-Origin
Vlan1                     default                              1  --
mgmt0                     management                           2  --
"""

LOGGING = """\
Logging server:                 enabled
{192.0.2.10}
        server status:          No errors found
        server severity:        notifications
        server facility:        local7
        server VRF:             default
        server port:            514
{192.0.2.30}
        server status:          connection refused
        server severity:        notifications
        server facility:        local7
        server VRF:             management
        server port:            514
"""

ROUTE_SUMMARY = """\
IP Route Table for VRF "default"
Total number of routes: 15
Total number of paths:  15

Unicast paths:
Best paths per protocol:      Backup paths per protocol:
  am             : 7            None
  local          : 1
  direct         : 1
  static         : 1
  broadcast      : 5
"""


def _lines(text: str) -> list[str]:
    return text.splitlines()


# ------------------------------------------------------------------------------------------------- parsers
def test_modules_boot_and_reset_reason():
    modules = nxos_state.parse_modules(_lines(MODULE))
    assert [m["module"] for m in modules] == ["1", "27"] or [str(m["module"]) for m in modules] == ["1", "27"]
    assert modules[0]["model"] == "N9K-C93180YC-FX3" and modules[0]["software"] == "10.4(5)" and modules[0]["serial"] == "FDO00000001"
    boot = nxos_state.parse_boot(_lines(BOOT))
    assert nxos_state.image_version(boot["current"]["nxos"]) == "10.4(5)"
    assert nxos_state.image_version(boot["next"]["nxos"]) == "10.5(4)"
    resets = nxos_state.parse_reset_reason(_lines(RESET))
    assert [r["reason"] for r in resets] == ["Reset due to upgrade", "Kernel Panic"]
    assert resets[1]["service"] == "sysmgr" and resets[1]["version"] == "9.3(5)"


def test_counters_errors_merges_the_three_tables_per_port():
    rows = {r["port"]: r["counters"] for r in nxos_state.parse_counters_errors(_lines(COUNTERS))}
    assert list(rows).count("Eth1/6") == 1                                     # one row per port, not one per table
    assert rows["Eth1/6"]["Align-Err"] == 1650 and rows["Eth1/6"]["Runts"] == 3
    assert rows["Eth1/1"]["SQETest-Err"] is None                               # "--" = not supported on this port
    assert rows["mgmt0"]["Xmit-Err"] is None


def test_transceiver_details_read_dom_and_skip_ports_without_optics():
    rows = {r["port"]: r for r in nxos_state.parse_transceiver_details(_lines(TRANSCEIVER))}
    sfp = rows["Ethernet1/1"]
    assert sfp["present"] is True and sfp["type"] == "10Gbase-SR" and sfp["serial"] == "SN000001"
    rx = sfp["readings"]["rx_power"]
    assert rx["value"] == -40.0 and rx["flag"] == "--" and rx["alarm_low"] == -13.9
    assert nxos_state.dom_state(rx) != "ok"
    assert rows["Ethernet1/2"]["present"] is None and rows["Ethernet1/3"]["present"] is False


def test_port_channel_database_orphan_ports_and_stp_root():
    channels = {c["channel"]: c for c in nxos_state.parse_port_channel_database(_lines(PORT_CHANNELS))}
    assert set(channels) == {"port-channel10", "port-channel141"}
    assert channels["port-channel141"]["total"] == 2 and channels["port-channel141"]["up"] == 1
    assert [(m["port"], m["state"]) for m in channels["port-channel141"]["members"]] == [("Ethernet1/3", "down"), ("Ethernet1/4", "up")]
    orphans = nxos_state.parse_orphan_ports(_lines(ORPHANS))
    by_vlan = {str(o["vlan"]): o["ports"] for o in orphans}
    assert "Eth1/5" in by_vlan["6"] and "Eth1/21" in by_vlan["5"]              # a port list that wraps onto the next line is read whole
    roots = nxos_state.parse_stp_root(_lines(STP_ROOT))
    assert len(roots) == 3 and roots[0]["priority"] == 0 and roots[0]["root"] == "0039.0039.0039"
    assert roots[2]["local_root"] is True and roots[1]["local_root"] is False


def test_vrf_logging_and_route_summary():
    assert [v["vrf"] for v in nxos_state.parse_vrf(_lines(VRF))] == ["default", "management"]
    assert [(v["interface"], v["vrf"]) for v in nxos_state.parse_vrf_interface(_lines(VRF_INTERFACE))] == [("Vlan1", "default"), ("mgmt0", "management")]
    syslog = nxos_state.parse_logging_servers(_lines(LOGGING))
    assert syslog["enabled"] is True and [s["server"] for s in syslog["servers"]] == ["192.0.2.10", "192.0.2.30"]
    assert syslog["servers"][1]["status"] == "connection refused"
    summary = nxos_state.parse_route_summary(_lines(ROUTE_SUMMARY))
    assert summary[0]["routes"] == 15 and summary[0]["protocols"]["am"] == 7


# ------------------------------------------------------------------------------------------------- analyse
def _capture(command_output: list[tuple[str, str]], host: str = "SW-LAB-AGG1") -> list[str]:
    out: list[str] = []
    for command, text in command_output:
        out += [f"{host}# {command}", ""] + text.splitlines() + [""]
    return out


def test_analyse_reports_what_an_operator_must_look_at():
    clean = _capture([
        ("show module", MODULE), ("show boot", BOOT), ("show system reset-reason", RESET),
        ("show interface counters errors", COUNTERS), ("show interface transceiver details", TRANSCEIVER),
        ("show port-channel database", PORT_CHANNELS), ("show vpc orphan-ports", ORPHANS), ("show spanning-tree root", STP_ROOT),
        ("show vrf", VRF), ("show vrf interface", VRF_INTERFACE), ("show logging server", LOGGING), ("show ip route summary", ROUTE_SUMMARY),
    ])
    result = nxos_state.analyse(clean)
    codes = {f["code"] for f in result["findings"]}
    assert {"SW-NX-BOOT-001", "SW-NX-BOOT-002", "SW-NX-LOG-002"} <= codes          # next image differs, POAP on, syslog server in error
    assert any(c.startswith("SW-NX-STP") or c == "STP-ROOT-001" for c in codes)     # VLAN 1 / default-priority root
    assert all(f.get("title") and f.get("text") for f in result["findings"])
    for finding in result["findings"]:
        if "doc" in finding:
            assert finding["doc"]["url"].startswith("https://")                      # every reference is a real vendor document link
    assert result["counts"]["modules"] == 2 and result["counts"]["route_summary"] == 1
    assert {t["id"] for t in result["tables"]} >= {"nx-modules", "nx-boot", "nx-reset-reason", "nx-route-summary"}


def test_a_glued_command_inside_an_acl_is_reported_as_capture_damage():
    clean = [
        "SW-LAB-AGG1# show running-config",
        "ip access-list WEB-ACL",
        "  330 remark CLIENT",
        "  340 permit tcp any portgroup GPORT-WEB addrgroushow run | in route",
        "  530 permit ip 19ss-ta2.168.6.16/32 192.0.2.24/32 ",
        "  540 permit ip 198.51.100.0/24 192.0.2.24/32 ",
        "ip access-list MAC-ACL",
        "  10 permit any 0180.c200.000e 0000.0000.0000 0x8843",          # a MAC ACL is not damage
    ]
    broken = nxos_state._broken_acl_lines(clean)
    assert len(broken) == 2 and all("198.51.100.0" not in line and "0180.c200" not in line for line in broken)
    finding = [f for f in nxos_state.analyse(clean)["findings"] if f["code"] == "SW-NX-CAP-001"]
    assert finding and "2 ACL line(s)" in finding[0]["title"]


# ------------------------------------------------------------------------------------------------- paste-ahead layout
def test_typeahead_echo_far_from_its_prompt_is_still_dropped():
    # 120 commands sit between the bare echo of "show version" and its prompted twin (the DRC captures were ~100 apart).
    lines = ["SW1# show running-config", "show version", "hostname SW1"]
    for n in range(120):
        lines += [f"SW1# show interface description {n}", f"Ethernet1/{n}  up"]
    lines += ["SW1# show version", "Cisco Nexus Operating System (NX-OS) Software", "  NXOS: version 10.4(5)", "  cpu: Intel(R) Xeon(R)", "  Device name: SW1", "SW1#"]
    cleaned = capture_text._drop_typeahead_echo(lines)
    assert cleaned[1] == ""                                                    # the bare echo no longer starts a block
    assert cleaned.count("show version") == 0 and "SW1# show version" in cleaned
