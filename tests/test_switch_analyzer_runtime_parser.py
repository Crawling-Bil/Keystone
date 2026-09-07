"""Tests for the Switch Analyzer's new runtime-parser functions:
transceivers, PoE, vPC/M-LAG, and chassis inventory/stack detection.

The Cisco fixtures below (inventory, transceiver DOM table, "show
switch" stack table, CDP neighbor wrapping) are trimmed excerpts of 3
real production backups this project was given (2x Catalyst 3650, 1x
Catalyst 2960 — TAM 2026 Huawei Switch project, "Draft/backup"
folder) — not guessed or documented-format-only, actually verified
against real device output. That verification caught and fixed two
real bugs: 'show interface transceiver' on real IOS-XE prints a DOM/
optical table with no type or serial at all (an earlier version of
this parser assumed a present/type/Pid table that doesn't exist on
real hardware and silently returned zero rows every time), and 'show
inventory' can have a genuinely blank PID field that an earlier regex
required to be non-empty, silently dropping that module.

Huawei fixtures were originally built from documented CLI format only;
InventoryParsingTest's elabel/stack fixtures and the classes appended
at the end of this file (HuaweiVersionModelTest, HuaweiInventoryStackTest,
HuaweiEthTrunkTest, HuaweiTransceiverSerialTest, CiscoStackTest) were
corrected/added against real S5735 and Catalyst 2960X captures once
real Huawei/Cisco backups became available — see those classes'
docstrings for the specific real files and bugs each one fixes. Any
Huawei fixture not called out that way is still documented-format-only
and stays tolerant by design: an unmatched row is skipped, never
fabricated. Aruba fixtures are now
grounded in real ArubaOS-Switch 2540 backups from this project (see
PoeParsingTest.test_aruba_poe_brief and
KeywordPriorityRegressionTest below) — that verification caught a real
PoE-parsing bug: the "PD Pwr Draw" column was never being read at all,
with "Pre-std Detect" (an on/off flag, not a wattage) silently used as
"power_watts" instead, and a bare prompt-less "show
power-over-ethernet" command run just before the real "... brief"
table was matched in preference to it, with no boundary to stop
capture at, so parsing ran straight through the real 24-port table and
into unrelated data beyond it.
"""
from __future__ import annotations

import unittest

from features.switch_analyzer import runtime_parser
from features.switch_analyzer import runtime_parser as rp


class TransceiverParsingTest(unittest.TestCase):
    def test_cisco_inventory_and_dom_table_join(self):
        # Trimmed from a real Catalyst 3650 'show inventory' + 'show
        # interface transceiver' capture — 4-value DOM layout (no
        # Current column), one entry with a genuinely blank PID.
        lines = """
show inventory
NAME: "Switch 1", DESCR: "WS-C3650-24TS-S"
PID: WS-C3650-24TS-S   , VID: V04  , SN: FDO2218Q16C

NAME: "GigabitEthernet1/1/1", DESCR: "1000BaseSX SFP"
PID:                    , VID:      , SN: AGM1111J2PF

NAME: "GigabitEthernet1/1/2", DESCR: "1000BaseSX SFP"
PID: GLC-SX-MMD         , VID: V03  , SN: OPM255212BH

show interface transceiver
If device is externally calibrated, only calibrated values are printed.
                                 Optical   Optical
           Temperature  Voltage  Tx Power  Rx Power
Port       (Celsius)    (Volts)  (dBm)     (dBm)
---------  -----------  -------  --------  --------
Gi1/1/2      25.9       3.29      -5.6      -5.5
""".strip().splitlines()
        result = runtime_parser.parse_transceivers(lines)
        by_if = {item["interface"]: item for item in result}
        self.assertEqual(len(result), 2)
        # Blank on-device PID must not drop the whole row.
        self.assertEqual(by_if["GigabitEthernet1/1/1"]["vendor_part_number"], "")
        self.assertEqual(by_if["GigabitEthernet1/1/1"]["serial_number"], "AGM1111J2PF")
        self.assertNotIn("temperature_c", by_if["GigabitEthernet1/1/1"])  # no DOM row for this port
        joined = by_if["GigabitEthernet1/1/2"]
        self.assertEqual(joined["vendor_part_number"], "GLC-SX-MMD")
        self.assertEqual(joined["tx_power_dbm"], "-5.6")

    def test_cisco_dom_table_with_current_column_variant(self):
        # A second real 3650's DOM table inserted a Current(mA) column
        # between Voltage and Tx Power — Tx/Rx must still resolve
        # correctly from the last two columns regardless.
        lines = """
show inventory
NAME: "Gi1/1/1", DESCR: "1000BaseSX SFP"
PID: GLC-SX-MMD          , VID: V03  , SN: OPM25360KY5

show inter transceiver
           Temperature  Voltage  Current   Tx Power  Rx Power
Port       (Celsius)    (Volts)  (mA)      (dBm)     (dBm)
---------  -----------  -------  --------  --------  --------
Gi1/1/1      27.6       3.31       3.3      -6.1     -16.2
""".strip().splitlines()
        result = runtime_parser.parse_transceivers(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["tx_power_dbm"], "-6.1")
        self.assertEqual(result[0]["rx_power_dbm"], "-16.2")
        self.assertEqual(result[0]["voltage_v"], "3.31")

    def test_cisco_no_transceiver_present_message(self):
        # Real output on a switch with no SFPs installed at all.
        lines = "show interface transceiver\nNo transceiver present".splitlines()
        self.assertEqual(runtime_parser.parse_transceivers(lines), [])

    def test_huawei_block_dump(self):
        lines = """
display interface transceiver
GigabitEthernet0/0/1 transceiver information:
Transceiver Type                : SFP
Connector Type                  : LC
Wavelength(nm)                  : 850
Vendor Part Number              : none
Vendor Serial Number            : ABC1234567
""".strip().splitlines()
        result = runtime_parser.parse_transceivers(lines)
        self.assertEqual(len(result), 1)
        item = result[0]
        self.assertEqual(item["interface"], "GigabitEthernet0/0/1")
        self.assertEqual(item["type"], "SFP")
        self.assertEqual(item["vendor_part_number"], "")  # "none" is not a real value
        self.assertEqual(item["serial_number"], "ABC1234567")

    def test_aruba_flat_table(self):
        # Real command on a real ArubaOS-Switch 2540 is 'show interfaces
        # transceiver' (with "interfaces"), not the bare 'show
        # transceiver' the collect-script checklist names — both match.
        lines = """
show interfaces transceiver
Transceiver Technical Information:

                     Product      Serial             Part
 Port    Type        Number       Number             Number
 ------- ----------- ------------ ------------------ ----------
 25      1000LX      J4859D       CN13KC6CLS         1990-4414
""".strip().splitlines()
        result = runtime_parser.parse_transceivers(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["interface"], "25")
        self.assertEqual(result[0]["vendor_part_number"], "J4859D")
        self.assertEqual(result[0]["serial_number"], "CN13KC6CLS")

    def test_no_transceiver_section_returns_empty(self):
        self.assertEqual(runtime_parser.parse_transceivers(["hostname SW1"]), [])


class PoeParsingTest(unittest.TestCase):
    def test_cisco_show_power_inline(self):
        lines = """
show power inline
Interface Admin  Oper       Power(Watts) Device              Class Max
Gi1/0/1   auto   on         15.4         Ieee PD             4     30.0
Gi1/0/2   auto   off        0.0          n/a                 n/a   30.0
""".strip().splitlines()
        result = runtime_parser.parse_poe(lines)
        by_if = {item["interface"]: item for item in result}
        self.assertEqual(by_if["Gi1/0/1"]["oper_status"], "on")
        self.assertEqual(by_if["Gi1/0/1"]["power_watts"], "15.4")
        self.assertEqual(by_if["Gi1/0/2"]["oper_status"], "off")

    def test_aruba_poe_brief(self):
        # Real ArubaOS-Switch 'show power-over-ethernet brief' column
        # layout, trimmed from a real Aruba 2540 capture: Port, Pwr
        # Enab, Pwr Priority, Pre-std Detect, Alloc Cfg, Alloc Actual,
        # PSE Pwr Rsrvd (W), PD Pwr Draw (W), PoE Port Status, PLC Cls,
        # PLC Type. Also exercises the real capture's actual quirk: a
        # bare, prompt-less 'show power-over-ethernet' (no "brief")
        # summary command run just before it — this used to get
        # matched first (by raw line position) instead of the more
        # specific 'brief' keyword, and had no bare-command boundary to
        # stop at, so parsing ran straight through this real table and
        # beyond, producing 52 bogus rows and an ~8400W total on the
        # real file instead of the real 24 ports / ~41W.
        lines = """
show power-over-ethernet
 Chassis power-over-ethernet:
  Total Power Drawn      :   39 W +/- 6W
show power-over-ethernet brief
 PoE   Pwr  Pwr      Pre-std Alloc Alloc  PSE Pwr PD Pwr  PoE Port    PLC PLC
 Port  Enab Priority Detect  Cfg   Actual Rsrvd   Draw    Status      Cls Type
 ----- ---- -------- ------- ----- ------ ------- ------- ----------- --- ----
 1     Yes  low      off     usage lldp   6.8 W   6.4 W   Delivering   4   2
 2     Yes  low      off     usage usage  0.0 W   0.0 W   Searching    0   -
show power-over-ethernet all
 Status and Configuration Information for port 1
""".strip().splitlines()
        result = runtime_parser.parse_poe(lines)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["interface"], "1")
        self.assertEqual(result[0]["oper_status"], "Delivering")
        self.assertEqual(result[0]["power_watts"], "6.4")  # PD Pwr Draw, not Pre-std Detect
        self.assertEqual(result[0]["admin_status"], "Enabled")
        self.assertEqual(result[0]["class"], "4")
        self.assertEqual(result[0]["source"], "show power-over-ethernet brief")
        self.assertEqual(result[1]["power_watts"], "0.0")

    def test_no_poe_section_returns_empty(self):
        self.assertEqual(runtime_parser.parse_poe(["hostname SW1"]), [])

    def test_cdp_detail_fallback_used_when_no_live_poe_table(self):
        # Trimmed real excerpt: LXS-SWAC-GUEST-2960 never ran
        # "show power inline" at all (only a "power inline never"
        # CONFIG line on unrelated ports), so its only real PoE data
        # is each connected AP's own "Power drawn" line in
        # "show cdp neighbors detail" — your own finding.
        lines = """
LXS-SWAC-GUEST-2960#show cdp neighbors detail
-------------------------
Device ID: LXS-WLC
Platform: AIR-CT3504-K9,  Capabilities: Host
Interface: GigabitEthernet1/0/23,  Port ID (outgoing port): GigabitEthernet0/0/1
Holdtime : 152 sec
Duplex: full
-------------------------
Device ID: LXS_AP6
Platform: cisco AIR-CAP3602E-C-K9,  Capabilities: Trans-Bridge Source-Route-Bridge IGMP
Interface: GigabitEthernet1/0/6,  Port ID (outgoing port): GigabitEthernet0
Holdtime : 162 sec
Duplex: full
Power drawn: 15.400 Watts
Power request id: 63147, Power management id: 2
-------------------------
Device ID: LXS-AP7
Platform: cisco AIR-CAP2702E-C-K9,  Capabilities: Trans-Bridge Source-Route-Bridge IGMP
Interface: GigabitEthernet1/0/4,  Port ID (outgoing port): GigabitEthernet0
Holdtime : 172 sec
Duplex: full
Power drawn: 16.800 Watts
Power request id: 12345, Power management id: 2
""".strip().splitlines()
        result = runtime_parser.parse_poe(lines)
        by_if = {item["interface"]: item for item in result}
        # LXS-WLC has no "Power drawn" line at all (it's a wired
        # controller, not a powered device) — correctly excluded, not
        # reported as a 0 W row.
        self.assertNotIn("GigabitEthernet1/0/23", by_if)
        self.assertEqual(by_if["GigabitEthernet1/0/6"]["power_watts"], "15.400")
        self.assertEqual(by_if["GigabitEthernet1/0/6"]["device"], "LXS_AP6")
        self.assertEqual(by_if["GigabitEthernet1/0/6"]["source"], "cdp-detail")
        self.assertEqual(by_if["GigabitEthernet1/0/4"]["power_watts"], "16.800")

    def test_live_table_preferred_over_cdp_detail_when_both_present(self):
        lines = """
show power inline
Interface Admin  Oper       Power(Watts) Device              Class Max
Gi1/0/1   auto   on         15.4         Ieee PD             4     30.0
show cdp neighbors detail
-------------------------
Device ID: SOME-AP
Interface: GigabitEthernet1/0/6,  Port ID (outgoing port): GigabitEthernet0
Power drawn: 99.900 Watts
""".strip().splitlines()
        result = runtime_parser.parse_poe(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source"], "show power inline")


class VpcMlagParsingTest(unittest.TestCase):
    def test_nexus_vpc_brief(self):
        lines = """
show vpc brief
vPC domain id                     : 10
Peer status                       : peer adjacency formed ok
vPC keep-alive status             : peer is alive
Configuration consistency status  : success
vPC role                          : primary
Number of vPCs configured         : 2

vPC status
----------------------------------------------------------------------------
Id    Port          Status Consistency Reason                     Active vlans
----------------------------------------------------------------------------
1     Po1           up     success     success                    1,10,20
2     Po2           up     success     success                    1,10,20
""".strip().splitlines()
        result = runtime_parser.parse_vpc_mlag(lines)
        self.assertEqual(result["summary"]["domain_id"], "10")
        self.assertEqual(result["summary"]["role"], "primary")
        self.assertEqual(len(result["members"]), 2)
        self.assertEqual(result["members"][0]["port"], "Po1")
        self.assertEqual(result["members"][0]["vlans"], "1,10,20")

    def test_huawei_mlag_summary_and_brief(self):
        lines = """
display m-lag summary
DFS Group ID                : 1
Keepalive Status            : Alive
Priority                    : 32768
Consistency Check           : Consistent
display m-lag brief
Eth-Trunk1   1   up   up
""".strip().splitlines()
        result = runtime_parser.parse_vpc_mlag(lines)
        self.assertEqual(result["summary"]["domain_id"], "1")
        self.assertEqual(result["summary"]["keepalive_status"], "Alive")
        self.assertEqual(len(result["members"]), 1)
        self.assertEqual(result["members"][0]["port"], "Eth-Trunk1")

    def test_no_vpc_mlag_section_returns_empty(self):
        result = runtime_parser.parse_vpc_mlag(["hostname SW1"])
        self.assertEqual(result["summary"], {})
        self.assertEqual(result["members"], [])


class InventoryParsingTest(unittest.TestCase):
    def test_cisco_standalone_inventory(self):
        lines = [
            'NAME: "Switch 1", DESCR: "WS-C9300-48P"',
            "PID: WS-C9300-48P   , VID: V04  , SN: FCW1234A0BC",
        ]
        result = runtime_parser.parse_inventory(lines)
        self.assertEqual(len(result["modules"]), 1)
        self.assertEqual(result["modules"][0]["serial"], "FCW1234A0BC")
        self.assertEqual(result["stack"]["mode"], "Standalone")
        self.assertEqual(result["stack"]["member_count"], 1)

    def test_cisco_stack_detected(self):
        lines = """
show switch
Switch/Stack Mac Address : aaaa.bbbb.cccc
         Switch#  Role      Mac Address     Priority  Version  State
------------------------------------------------------------------
*1       Active    aaaa.bbbb.0001  1         V02      Ready
 2       Standby   aaaa.bbbb.0002  1         V02      Ready
""".strip().splitlines()
        result = runtime_parser.parse_inventory(lines)
        self.assertEqual(result["stack"]["mode"], "Stack")
        self.assertEqual(result["stack"]["member_count"], 2)

    def test_huawei_standalone_with_elabel(self):
        # Fixture corrected against real S5735 hardware this round
        # (PDC-DAYA-SWAC-05-S5735-FIX.txt, STR2-SWAC-1-HRGA-S5735-
        # FIX.txt): the real "display device elabel brief" table is 5
        # columns — SlotID / Sub / Type / SN / P/N — not the 6-column
        # "Slot/Sub/Type/BoardName/BomID/BarCode" this test previously
        # assumed (documented-format-only, never verified against real
        # output at the time it was written). Real sub-component (FAN/
        # PWR) rows also print with a blank leading SlotID.
        lines = """
display device elabel brief
SlotID     Sub    Type                     SN                       P/N
1          --     S5735-S24T4XE-V2         210235A1B2C3D4           98012016-003
           FAN1   --                       --                       --
""".strip().splitlines()
        result = runtime_parser.parse_inventory(lines)
        self.assertEqual(len(result["modules"]), 1)
        self.assertEqual(result["modules"][0]["serial"], "210235A1B2C3D4")
        self.assertEqual(result["stack"]["mode"], "Standalone")

    def test_huawei_stack_detected(self):
        # Fixture corrected against 2 real confirmed S5735 stacks this
        # round: the real "display stack" column order is MemberID /
        # Role / MAC / Priority / DeviceType / Description — Role
        # comes BEFORE the MAC, the reverse of what this test
        # previously assumed (documented-format-only, never verified).
        lines = """
display stack
MemberID Role     MAC              Priority   DeviceType              Description
1        Master   aaaa-bbbb-cccc   200        S5735-S24T4XE-V2
2        Standby  aaaa-bbbb-dddd   100        S5735-S24T4XE-V2
""".strip().splitlines()
        result = runtime_parser.parse_inventory(lines)
        self.assertEqual(result["stack"]["mode"], "Stack")
        self.assertEqual(result["stack"]["member_count"], 2)

    def test_no_inventory_data_returns_unknown_mode(self):
        result = runtime_parser.parse_inventory(["hostname SW1"])
        self.assertEqual(result["modules"], [])
        self.assertEqual(result["stack"]["mode"], "")
        self.assertEqual(result["stack"]["member_count"], 0)


class CdpNeighborWrappingRegressionTest(unittest.TestCase):
    """Regression test built from a real 'show cdp neighbors' capture
    where a long Device ID (GTOPAS-SMG-SWDI-B-C9200) wraps onto its own
    line, pushing Local Interface/Holdtime/Platform/Port ID onto the
    next — the exact real-world shape that produced a blank Local
    Interface and a garbled Neighbor ID in an earlier screenshot."""

    def test_wrapped_device_id_resolves_all_columns(self):
        lines = """
show cdp neighbors
Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge
                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone,
                  D - Remote, C - CVTA, M - Two-port Mac Relay

Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
GTOPAS-SMG-SWDI-B-C9200
                 Gig 1/1/1         172              S I   C9200L-24 Gig 2/1/1

Total cdp entries displayed : 1
""".strip().splitlines()
        result = runtime_parser.parse_neighbors(lines)
        self.assertEqual(len(result), 1)
        neighbor = result[0]
        self.assertEqual(neighbor["neighbor_id"], "GTOPAS-SMG-SWDI-B-C9200")
        self.assertEqual(neighbor["local_interface"], "Gig 1/1/1")
        self.assertEqual(neighbor["remote_interface"], "Gig 2/1/1")

    def test_detail_dump_replaces_brief_row_with_full_names(self):
        # The same neighbor also appears in 'show cdp neighbors detail'
        # with untruncated interface names and platform string — that
        # should replace the brief row, not sit alongside it.
        lines = """
SW1#show cdp neighbors
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
GTOPAS-SMG-SWDI-B-C9200
                 Gig 1/1/1         172              S I   C9200L-24 Gig 2/1/1
SW1#show cdp neighbors detail
-------------------------
Device ID: GTOPAS-SMG-SWDI-B-C9200
Entry address(es):
  IP address: 172.29.65.3
Platform: cisco C9200L-24P-4G,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/1/1,  Port ID (outgoing port): GigabitEthernet2/1/1
Holdtime : 172 sec
SW1#
""".strip().splitlines()
        result = runtime_parser.parse_neighbors(lines)
        self.assertEqual(len(result), 1)
        neighbor = result[0]
        self.assertEqual(neighbor["local_interface"], "GigabitEthernet1/1/1")
        self.assertEqual(neighbor["platform"], "C9200L-24P-4G")


class LldpBriefParsingTest(unittest.TestCase):
    """Cisco 'show lldp neighbors' (brief) — the original bug report was
    "blank platform, garbled long Device ID". Investigated both parts:

    Platform is genuinely absent from Cisco's real LLDP brief table
    format (Device ID / Local Intf / Hold-time / Capability / Port ID —
    5 columns; Platform only shows up in 'show lldp neighbors detail'),
    confirmed against Cisco's documented output — so an empty platform
    string there is correct, not a bug, the same way the PoE report
    turned out not to be a bug (Section 1q).

    The wrapped-long-Device-ID part WAS a real bug, found by direct
    code inspection: the old code had its own hand-rolled column walk
    that never handled a Device ID wrapping onto its own line at all
    (unlike CDP-brief, which already had this fixed and verified —
    Section 1q's CdpNeighborWrappingRegressionTest) and didn't walk
    past capability-code tokens correctly either. Fixed by reusing the
    exact same, already-proven _parse_neighbor_columns() wrap-handling
    used for CDP, with has_platform=False for LLDP's 5-column shape.

    IMPORTANT: still unverified against a REAL LLDP-brief capture —
    checked all 10 of the project's real device backups and LLDP is
    disabled on every single one (CDP is what's actually used site-
    wide); this fixture is built from Cisco's documented brief-table
    format, not a real device capture.
    """

    def test_short_device_id_all_columns_resolve(self):
        lines = """
SW1#show lldp neighbors
Device ID           Local Intf     Hold-time  Capability      Port ID
switch2              Gi1/0/1        120        B,R             Gi1/0/2
Total entries displayed: 1
""".strip().splitlines()
        result = runtime_parser.parse_neighbors(lines)
        lldp = [n for n in result if n["protocol"] == "LLDP"]
        self.assertEqual(len(lldp), 1)
        self.assertEqual(lldp[0]["neighbor_id"], "switch2")
        self.assertEqual(lldp[0]["local_interface"], "Gi1/0/1")
        self.assertEqual(lldp[0]["remote_interface"], "Gi1/0/2")
        # Correctly empty — LLDP's own brief table has no Platform
        # column, this isn't a dropped/failed-to-parse field.
        self.assertEqual(lldp[0]["platform"], "")

    def test_wrapped_long_device_id_resolves_all_columns(self):
        # Mirrors CdpNeighborWrappingRegressionTest's real-world shape
        # (a Device ID too long to share its line with the rest of the
        # row wraps onto its own line) applied to LLDP's column layout.
        lines = """
SW1#show lldp neighbors
Device ID           Local Intf     Hold-time  Capability      Port ID
GTOPAS-SMG-SWDI-B-C9200
                     Gi1/1/1        120        B,R             Gi2/1/1
Total entries displayed: 1
""".strip().splitlines()
        result = runtime_parser.parse_neighbors(lines)
        lldp = [n for n in result if n["protocol"] == "LLDP"]
        self.assertEqual(len(lldp), 1)
        self.assertEqual(lldp[0]["neighbor_id"], "GTOPAS-SMG-SWDI-B-C9200")
        self.assertEqual(lldp[0]["local_interface"], "Gi1/1/1")
        self.assertEqual(lldp[0]["remote_interface"], "Gi2/1/1")

    def test_lldp_not_enabled_produces_no_rows(self):
        # The actual real-world case across every backup seen so far.
        lines = """
SW1#show lldp neighbors
% LLDP is not enabled
""".strip().splitlines()
        result = runtime_parser.parse_neighbors(lines)
        self.assertEqual([n for n in result if n["protocol"] == "LLDP"], [])


class ArubaNeighborParsingTest(unittest.TestCase):
    """Fixtures trimmed from 3 real ArubaOS-Switch 2540 backups (TAM 2026
    Huawei Switch project). Verifying against them caught a real bug:
    'show cdp neighbors' is a literal prefix of 'show cdp neighbors
    detail', so a plain substring keyword match pulled the wrong (much
    longer, unrelated) section whenever only the detail command was
    captured — see EndswithSectionMatchRegressionTest below."""

    def test_lldp_detail_prefers_first_block_per_port(self):
        lines = """
SW1#show lldp info remote-device detail
 LLDP Remote Device Information Detail

  Local Port   : 3
  ChassisType  : network-address
  ChassisId    : 10.83.214.152
  PortType     : mac-address
  PortId       : 00 0e a9 40 a8 b0
  SysName      : NRP2000/W
  System Descr : 2.6.1.15545

------------------------------------------------------------------------------
  Local Port   : 3
  ChassisType  : local
  ChassisId    : NRP2000/W
  PortType     : local
  PortId       : eth0
  SysName      : Linux
SW1#
""".strip().splitlines()
        result = runtime_parser.parse_neighbors(lines)
        self.assertEqual(len(result), 1)
        # The first block (real hostname) wins over the second (generic
        # "Linux" OS name) for the same Local Port.
        self.assertEqual(result[0]["neighbor_id"], "NRP2000/W")
        self.assertEqual(result[0]["local_interface"], "3")

    def test_cdp_detail_prefers_first_block_per_port(self):
        lines = """
SW1#show cdp neighbors detail

 CDP neighbors information

  Port : 8
  Device ID : X303W
  Address Type : IP
  Address      : 10.85.214.66
  Platform     : X303W
  Capability   : Host Phone
  Device Port  : WAN PORT
  Version      : 2.12.20

------------------------------------------------------------------------------

  Port : 8
  Device ID : 10.85.214.66
  Address Type : IP
  Platform     : Version:2.12.20
  Capability   : Switch Phone
  Device Port  : WAN Port
SW1#
""".strip().splitlines()
        result = runtime_parser.parse_neighbors(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["neighbor_id"], "X303W")
        self.assertEqual(result[0]["remote_interface"], "WAN PORT")


class EndswithSectionMatchRegressionTest(unittest.TestCase):
    """A real ArubaOS-Switch backup ran ONLY 'show cdp neighbors detail'
    (no separate brief 'show cdp neighbors'). Section-matching used to
    check the keyword as a substring anywhere in the line, so the brief
    parser's "show cdp neighbors" keyword matched inside the detail
    command's own banner line too, and — since the real banner had no
    hostname/prompt prefix that _SECTION_BREAK_RE could recognize as a
    boundary — the brief section then swallowed everything up to some
    unrelated later command, producing garbage neighbor rows built from
    completely different show commands' output."""

    def test_bare_detail_command_does_not_leak_into_brief_section(self):
        lines = """
show cdp neighbors detail

 CDP neighbors information

  Port : 1
  Device ID : AA-BB-CC
  Platform     : Some Platform
  Device Port  : eth0

show sflow
Some unrelated sflow output that must not be treated as a CDP neighbor
""".strip().splitlines()
        result = runtime_parser.parse_neighbors(lines)
        # Only the real CDP-detail neighbor should come through — none
        # of the "show sflow" text should leak in as a bogus entry.
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["neighbor_id"], "AA-BB-CC")


class AbbreviatedShSectionBreakRegressionTest(unittest.TestCase):
    """A real N9108-DMZ (Nexus) capture typed the abbreviated 'sh' for
    roughly two-thirds of its commands ('sh vpc', 'sh port-channel
    summary', 'sh interface transceiver', ...) instead of the full
    'show'/'display' _SECTION_BREAK_RE used to require. Every section
    not immediately followed by a FULL 'show'/'display' command kept
    capturing straight through the next several abbreviated commands'
    output until it finally hit one typed in full — this proves the
    fix stops capture at an abbreviated 'sh' boundary too."""

    def test_section_stops_at_abbreviated_sh_boundary(self):
        lines = """
sh vpc
vPC domain id                     : 1
Peer status                       : peer adjacency formed ok

vPC status
Id    Port          Status Consistency Reason                Active vlans
--    ------------  ------ ----------- ------                ---------------
6     Po6           up     success     success               205

sh vpc role
vPC Role status
vPC role                        : secondary, operational primary
""".strip().splitlines()
        result = runtime_parser.parse_vpc_mlag(lines)
        self.assertEqual(result["summary"]["domain_id"], "1")
        # The 'sh vpc role' block's own "vPC role : ..." line must NOT
        # have leaked into the vpc_section capture and overwritten/
        # duplicated anything from the real "sh vpc" block above it.
        self.assertEqual(len(result["members"]), 1)
        self.assertEqual(result["members"][0]["port"], "Po6")


class NxosPortChannelParsingTest(unittest.TestCase):
    """Trimmed from a real N9108-DMZ 'sh port-channel summary' capture.
    NX-OS adds a 'Type' column (e.g. 'Eth') between the port-channel
    name and the Protocol column that Cisco IOS's 'show etherchannel
    summary' doesn't have, and wraps long member lists onto a
    continuation line with no leading group number."""

    def test_nxos_five_column_format_and_continuation_line(self):
        lines = """
sh port-channel summary
Group Port-       Type     Protocol  Member Ports
      Channel
1     Po1(RU)     Eth      LACP      Eth1/17(P)   Eth1/18(P)
2     Po2(SU)     Eth      LACP      Eth1/19(P)   Eth1/20(P)   Eth1/21(P)
                                     Eth1/22(P)
""".strip().splitlines()
        result = runtime_parser.parse_port_channels(lines)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], {"name": "Po1", "protocol": "LACP", "status": "RU", "members": "Eth1/17, Eth1/18"})
        # Po2's 4th member wrapped onto its own continuation line.
        self.assertEqual(result[1]["name"], "Po2")
        self.assertEqual(result[1]["protocol"], "LACP")
        self.assertEqual(result[1]["members"], "Eth1/19, Eth1/20, Eth1/21, Eth1/22")

    def test_ios_four_column_format_still_works(self):
        # Regression check: the token-based rewrite must not break the
        # plain IOS 'show etherchannel summary' layout (no Type column)
        # this was already verified against on a real Catalyst 2960.
        lines = """
show etherchannel summary
Group  Port-channel  Protocol    Ports
1      Po1(SU)         LACP      Gi1/0/25(P) Gi1/0/26(P)
""".strip().splitlines()
        result = runtime_parser.parse_port_channels(lines)
        self.assertEqual(result, [{"name": "Po1", "protocol": "LACP", "status": "SU", "members": "Gi1/0/25, Gi1/0/26"}])


class NxosTransceiverBlockParsingTest(unittest.TestCase):
    """Trimmed from a real N9108-DMZ 'sh interface transceiver' capture.
    NX-OS prints a bare interface-name header line followed by an
    indented 'field is value' block, completely unlike the Catalyst
    DOM-table row format the existing Cisco transceiver parser expects
    — a copper-only device like this one would previously show zero
    transceivers even though real SFPs/QSFPs were installed."""

    def test_present_transceiver_blocks_are_parsed(self):
        lines = """
sh interface transceiver
 Ethernet1/48
    transceiver is not applicable
 Ethernet1/49
    transceiver is present
    type is QSFP-40G-SR4
    name is CISCO-FINISAR
    part number is FTL410QE4C-C1
    serial number is FIW2619045C
 Ethernet1/50
    transceiver is not present
""".strip().splitlines()
        result = runtime_parser.parse_transceivers(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["interface"], "Ethernet1/49")
        self.assertEqual(result[0]["type"], "QSFP-40G-SR4")
        self.assertEqual(result[0]["vendor_part_number"], "FTL410QE4C-C1")
        self.assertEqual(result[0]["serial_number"], "FIW2619045C")
        self.assertTrue(result[0]["present"])


class VersionParsingRegressionTest(unittest.TestCase):
    """parse_version() had no dedicated coverage at all before this —
    both fixtures below are trimmed from real captures in this project
    and reproduce genuine, verified bugs the generic Cisco-only
    regexes (unscoped 'Version X' / 'Cisco <token>' searches over the
    WHOLE file) had on non-Catalyst content."""

    def test_aruba_model_and_version_not_confused_with_neighbor_or_license_text(self):
        # Real ArubaOS-Switch 2540: no Aruba branch existed at all, so
        # this fell through to the generic Cisco regexes, which walked
        # right past this switch's own identity and matched a nearby
        # AP's "Version" field and an unrelated "Cisco WS-..." mention
        # elsewhere in the same file instead.
        lines = """
; JL356A Configuration Editor; Created on release #YC.16.06.0006
hostname "TTC-SWAC-PABXGA1-2540"
module 1 type jl356a
show system
  Software revision  : YC.16.06.0006        Base MAC Addr      : 20677c-473b40
Platform: cisco AIR-CAP2702E-C-K9, Version: some other device's own string
""".strip().splitlines()
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["model"], "JL356A")
        self.assertEqual(result["os_version"], "YC.16.06.0006")

    def test_nxos_model_and_version_not_confused_with_license_banner_or_neighbor(self):
        # Real Nexus 93108TC-EX 'sh version': the generic "Version X"
        # search matched this SAME device's own open-source-license
        # boilerplate ("Lesser General Public License (LGPL) Version
        # 2.1"), printed just above the real "NXOS: version 9.3(5)"
        # line, reporting "2.1" as the switch's OS version; the generic
        # model search separately matched a downstream neighbor's CDP
        # platform string instead of this device's own chassis line.
        lines = """
Cisco Nexus Operating System (NX-OS) Software
Lesser General Public License (LGPL) Version 2.1 or
Software
  NXOS: version 9.3(5)
Hardware
  cisco Nexus9000 C93108TC-EX chassis
Platform: cisco C9200L-24P-4G, Capabilities: Switch IGMP Filtering
""".strip().splitlines()
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["model"], "C93108TC-EX")
        self.assertEqual(result["os_version"], "9.3(5)")

    def test_catalyst_ios_xe_still_uses_generic_branch(self):
        lines = """
Cisco IOS Software, Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.6.3, RELEASE SOFTWARE (fc4)
cisco WS-C2960X-24PS-L (APM86XXX) processor
""".strip().splitlines()
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["model"], "WS-C2960X-24PS-L")
        self.assertEqual(result["os_version"], "17.6.3")

    def test_cisco_own_identity_not_hijacked_by_huawei_neighbor_banner(self):
        # Real, currently-active bug on GTOPAS-MKS-SWCODI-C3650.txt (a
        # real Cisco Catalyst 3650 stack backup, part of this project's
        # live Cisco-to-Huawei migration): "show lldp neighbors
        # detail"'s neighbor System Description field verbatim-echoes
        # an adjacent Huawei switch's own "VRP (R) software, Version
        # ..." banner. Searching the whole file for the Huawei marker
        # let that ONE neighbor-echoed line hijack this Cisco device's
        # own identity: os_version came back as the NEIGHBOR's VRP
        # version, and the real "cisco WS-C3650-24TS (MIPS) processor"
        # line further down the file was never even reached, so Model
        # came back completely blank.
        lines = """
GTOPAS-MKS-SWCODI-C3650#show inventory
NAME: "c36xx Stack", DESCR: "c36xx Stack"
PID: WS-C3650-24TS-S   , VID: V04  , SN: FDO2218E1CQ
GTOPAS-MKS-SWCODI-C3650#show lldp neighbors detail
Local Intf: Gi1/0/22
System Name: GTOPAS-MKS-SWDI-A-S5731
System Description:
Huawei Switch S5731-S24P4X
Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 (S5731 V200R022C00SPC500)
GTOPAS-MKS-SWCODI-C3650#show version
Cisco IOS Software [Denali], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.3.6, RELEASE SOFTWARE (fc3)
cisco WS-C3650-24TS (MIPS) processor (revision R0) with 864936K/6147K bytes of memory.
""".strip().splitlines()
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["os_version"], "16.3.6")
        # Precise "show inventory" PID, not the abbreviated "show
        # version" hardware line (see the chassis-PID test below).
        self.assertEqual(result["model"], "WS-C3650-24TS-S")

    def test_cisco_model_prefers_show_inventory_chassis_pid(self):
        # 'show version's own hardware line frequently omits the SKU
        # suffix real 'show inventory' carries in its PID field —
        # confirmed on GTOPAS-PKU-SWCO-C3650.txt (stack) and
        # TTC-SWDI-C-3560.txt (standalone): "cisco WS-C3650-24TS (MIPS)
        # processor" vs. the real orderable "WS-C3650-24TS-S".
        lines = """
SW1#show inventory
NAME: "1", DESCR: "WS-C3560X-24P"
PID: WS-C3560X-24P-S   , VID: V02  , SN: FDO1637V01U
SW1#show version
Cisco IOS Software, Version 15.2(2)E5, RELEASE SOFTWARE (fc2)
cisco WS-C3560X-24P (PowerPC405) processor
""".strip().splitlines()
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["model"], "WS-C3560X-24P-S")

    def test_cisco_model_falls_back_to_generic_regex_without_show_inventory(self):
        lines = """
SW1#show version
Cisco IOS Software, Version 15.2(2)E5, RELEASE SOFTWARE (fc2)
cisco WS-C2960X-24TS-L (APM86XXX) processor
""".strip().splitlines()
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["model"], "WS-C2960X-24TS-L")


class KeywordPriorityRegressionTest(unittest.TestCase):
    """_extract_section used to pick whichever keyword happened to
    appear EARLIEST BY LINE POSITION, regardless of the caller's listed
    preference order. That's harmless when the keywords are true
    aliases of one command ("show X" / "sh X"), but every call site
    that lists two genuinely DIFFERENT commands (a generic one and a
    more specific one, e.g. PoE's bare "show power-over-ethernet" vs.
    "... brief") relies on the first-listed keyword being preferred
    whenever it's present, with the second only as a fallback if the
    first never appears at all — confirmed broken on a real Aruba 2540
    capture, which runs the bare summary command before the useful
    per-port "brief" table."""

    def test_preferred_keyword_wins_even_when_generic_appears_first(self):
        lines = """
show power-over-ethernet
 Chassis power-over-ethernet:
  Total Power Drawn      :   39 W
show power-over-ethernet brief
 1     Yes  low      off     usage lldp   6.8 W   6.4 W   Delivering   4   2
""".strip().splitlines()
        section = runtime_parser._extract_section(
            lines, ["show power-over-ethernet brief", "show power-over-ethernet"]
        )
        self.assertEqual(section, ["1     Yes  low      off     usage lldp   6.8 W   6.4 W   Delivering   4   2"])

    def test_falls_back_to_generic_keyword_when_specific_absent(self):
        lines = """
show power-over-ethernet
 Chassis power-over-ethernet:
  Total Power Drawn      :   39 W
""".strip().splitlines()
        section = runtime_parser._extract_section(
            lines, ["show power-over-ethernet brief", "show power-over-ethernet"]
        )
        self.assertEqual(section, ["Chassis power-over-ethernet:", "Total Power Drawn      :   39 W"])

    def test_bare_command_line_with_no_prompt_ends_capture(self):
        # No prompt/banner prefix at all in front of the next command —
        # _SECTION_BREAK_RE alone can't see this boundary; only the
        # bare-command check added alongside this fix can.
        lines = """
show power-over-ethernet brief
 1     Yes  low      off     usage lldp   6.8 W   6.4 W   Delivering   4   2
show power-over-ethernet all
 Status and Configuration Information for port 1
""".strip().splitlines()
        section = runtime_parser._extract_section(lines, ["show power-over-ethernet brief"])
        self.assertEqual(section, ["1     Yes  low      off     usage lldp   6.8 W   6.4 W   Delivering   4   2"])


class HuaweiVersionModelTest(unittest.TestCase):
    """Regression coverage for parse_version()'s Huawei branch — fixtures
    trimmed from 2 real S5735 stack-member captures (PDC-DAYA-SWAC-05-
    S5735-FIX.txt, STR2-SWAC-1-HRGA-S5735-FIX.txt). Previously the
    generic Cisco fallback (a bare 'Version X' search) fired FIRST and
    matched these same real banners, so the Huawei-specific branch was
    dead code and every real Huawei device came back with model="".
    """

    def test_cloudengine_banner_returns_version_and_model(self):
        lines = [
            "<SW1>display version",
            "Huawei YunShan OS",
            "Version 1.25.0.1 (S5700 V600R025C00SPC500)",
            "Copyright (C) 2021-2024 Huawei Technologies Co., Ltd.",
            "HUAWEI CloudEngine S5735-S-V2 uptime is 0 day, 1 hour, 10 minutes",
        ]
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["os_version"], "1.25.0.1 (S5700 V600R025C00SPC500)")
        self.assertEqual(result["model"], "S5735-S-V2")

    def test_classic_vrp_banner_returns_version(self):
        lines = [
            "<SW1>display version",
            "VRP (R) software, Version 5.170 (S5731 V200R022C00SPC500)",
        ]
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["os_version"], "5.170 (S5731 V200R022C00SPC500)")

    def test_cisco_version_still_wins_when_no_huawei_marker(self):
        lines = [
            "SW1#show version",
            "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(2)E5, RELEASE SOFTWARE (fc2)",
            "cisco WS-C2960X-24TS-L (APM86XXX) processor (revision L0) with 524288K bytes of memory.",
        ]
        result = runtime_parser.parse_version(lines)
        self.assertEqual(result["os_version"], "15.2(2)E5")
        self.assertEqual(result["model"], "WS-C2960X-24TS-L")


class HuaweiInventoryStackTest(unittest.TestCase):
    """Fixture trimmed from PDC-DAYA-SWAC-05-S5735-FIX.txt (a real
    confirmed 2-member stack). The old elabel-brief regex assumed 6
    columns in the wrong order (real is 5: SlotID/Sub/Type/SN/P-N) and
    the old stack-row regex had MAC before Role (real order is Role
    before MAC), so neither ever matched a real row.
    """

    LINES = [
        "<SW1>display device elabel brief",
        "Equipment SN(ESN): 4E2660124950",
        "License ESN: --",
        "--------------------------------------------------------------------------------",
        "SlotID     Sub    Type                     SN                       P/N",
        "--------------------------------------------------------------------------------",
        "1          --     S5735-S24T4XE-V2         4E2660124950             98012016-003",
        "           FAN1   --                       --                       --",
        "           PWR1   PAC80S12-CN              2102131835USS6318275     02131835",
        "2          --     S5735-S24T4XE-V2         4E2660124949             98012016-003",
        "--------------------------------------------------------------------------------",
        "<SW1>display stack",
        "--------------------------------------------------------------------------------",
        "MemberID Role     MAC              Priority   DeviceType              Description",
        "--------------------------------------------------------------------------------",
        "1        Master   a46c-24c2-4400   200        S5735-S24T4XE-V2",
        "2        Standby  a46c-24c2-4410   100        S5735-S24T4XE-V2",
        "--------------------------------------------------------------------------------",
    ]

    def test_elabel_serials_captured_with_fan_row_skipped(self):
        inv = runtime_parser.parse_inventory(self.LINES)
        serials = {m["serial"] for m in inv["modules"]}
        self.assertIn("4E2660124950", serials)
        self.assertIn("4E2660124949", serials)
        self.assertIn("2102131835USS6318275", serials)  # PWR1 sub-row
        # The FAN1 row has "--" for every field and must not become a
        # phantom module with an empty/placeholder serial.
        self.assertNotIn("--", serials)

    def test_two_member_stack_detected(self):
        inv = runtime_parser.parse_inventory(self.LINES)
        self.assertEqual(inv["stack"]["mode"], "Stack")
        self.assertEqual(inv["stack"]["member_count"], 2)
        roles = {m["role"] for m in inv["stack"]["members"]}
        self.assertEqual(roles, {"Master", "Standby"})


class CiscoStackTest(unittest.TestCase):
    """Fixture trimmed from a real Catalyst 2960X backup
    (PDC-DAYA-SWAC-05-2960.txt). Confirmed two independent real-world
    gaps: the real role value is "Master" (missing from the old
    Active/Standby/Member alternation), and the real command was typed
    abbreviated as "sh switch" (missing from the old keyword list).
    """

    def test_master_role_and_abbreviated_command_detected(self):
        lines = [
            "SW1#sh switch",
            "Switch/Stack Mac Address : 2c0b.e990.1c00",
            "Switch#  Role   Mac Address     Priority Version  State",
            "-----------------------------------------------------------",
            "*1       Master 2c0b.e990.1c00     1      4       Ready",
        ]
        inv = runtime_parser.parse_inventory(lines)
        self.assertEqual(inv["stack"]["mode"], "Standalone")
        self.assertEqual(inv["stack"]["member_count"], 1)
        self.assertEqual(inv["stack"]["members"][0]["role"], "Master")


class HuaweiEthTrunkTest(unittest.TestCase):
    """Fixture trimmed from a real STR2-SWAC-1-HRGA-S5735-FIX.txt
    'display eth-trunk' block. The old code looked for "Operate status"
    (real field is "Operating Status" — a typo) and expected member rows
    to say Up/Down (real values are Selected/Unselect), so trunk status
    and every member were silently dropped for every real device.
    """

    LINES = [
        "<SW1>display eth-trunk",
        "Eth-Trunk1's state information is:",
        "Local:",
        "LAG ID: 1                       Working Mode: Static",
        "Operating Status: down          Number Of Up Ports In Trunk: 0",
        "------------------------------------------------------------------------------------",
        "ActorPortName              Status   PortType PortPri PortNo PortKey PortState Weight",
        "10GE1/0/1                  Unselect 1GE      32768   1      305     10100010  1",
        "10GE1/0/2                  Unselect 1GE      32768   2      305     10100010  1",
        "",
        "Partner:",
        "------------------------------------------------------------------------------------",
        "ActorPortName              SysPri   SystemID        PortPri PortNo PortKey PortState",
        "10GE1/0/1                  0        0000-0000-0000  0       0      0       10100011",
    ]

    def test_status_and_members_captured_partner_table_excluded(self):
        results = runtime_parser.parse_port_channels(self.LINES)
        trunks = [r for r in results if r.get("protocol") == "Eth-Trunk"]
        self.assertEqual(len(trunks), 1)
        self.assertEqual(trunks[0]["status"], "down")
        self.assertEqual(trunks[0]["members"], "10GE1/0/1, 10GE1/0/2")


class HuaweiTransceiverSerialTest(unittest.TestCase):
    """Fixture trimmed from a real 'display interface transceiver'
    block. Real field name is "Manu. Serial Number" — the old code only
    matched "vendor serial number" or an exact "serial number".
    """

    def test_manu_serial_number_field_captured(self):
        lines = [
            " 10GE1/0/1 transceiver information:",
            " Common information:",
            "   Transceiver Type                      :1000BASE_T",
            "   Vendor Part Number                    :RTXL185-210",
            " Manufacture information:",
            "   Manu. Serial Number                   :HR260700542335",
        ]
        results = runtime_parser.parse_transceivers(lines)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["serial_number"], "HR260700542335")
        self.assertEqual(results[0]["vendor_part_number"], "RTXL185-210")




# ---------------------------------------------------------------
# Carried over from the pre-port Keystone baseline test suite (same
# filename existed in the repo before this port) so this coverage
# isn't silently dropped. Verified compatible with the module above:
# every function/class these tests call still exists with the same
# name and signature in the ported code.
# ---------------------------------------------------------------

class TestExtractSection(unittest.TestCase):
    def test_returns_empty_list_when_keyword_not_found(self):
        self.assertEqual(rp._extract_section(["nothing relevant here"], ["show ip route"]), [])

    def test_stops_at_next_command_banner(self):
        lines = [
            "switch#show ip route",
            "S* 0.0.0.0/0 [1/0] via 10.0.0.1",
            "switch#show ip arp",
            "Internet 10.0.0.2 - 0011.2233.4455 ARPA Vlan1",
        ]
        section = rp._extract_section(lines, ["show ip route"])
        self.assertEqual(section, ["S* 0.0.0.0/0 [1/0] via 10.0.0.1"])


class TestParseInterfaceBrief(unittest.TestCase):
    def test_cisco_interface_brief(self):
        lines = [
            "switch#show ip interface brief",
            "Interface              IP-Address      OK? Method Status                Protocol",
            "GigabitEthernet0/1     unassigned      YES unset   up                    up",
            "Vlan20                 unassigned      YES manual  administratively down down",
        ]
        result = rp.parse_interface_brief(lines)
        self.assertEqual(result["GigabitEthernet0/1"], {"ip_address": "", "status": "up", "protocol": "up"})
        self.assertEqual(result["Vlan20"]["status"], "administratively down")

    def test_huawei_interface_brief(self):
        lines = [
            "<SW>display ip interface brief",
            "Interface                         IP Address/Mask      Physical   Protocol",
            "Vlanif30                          10.20.30.1/24        up         up",
            "10GE1/0/1                         unassigned            up         up",
        ]
        result = rp.parse_interface_brief(lines)
        self.assertEqual(result["Vlanif30"], {"ip_address": "10.20.30.1/24", "status": "up", "protocol": "up"})
        self.assertIn("10GE1/0/1", result)


class TestParseNeighbors(unittest.TestCase):
    def test_cisco_cdp_neighbors_brief(self):
        lines = [
            "switch#show cdp neighbors",
            "Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge",
            "                  S - Switch, H - Host, I - IGMP, r - Repeater",
            "",
            "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID",
            "CORE-SW02.local  Gig 0/1           156             S I    WS-C3560  Gig 0/24",
        ]
        result = rp.parse_neighbors(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], {
            "protocol": "CDP",
            "neighbor_id": "CORE-SW02.local",
            "local_interface": "Gig 0/1",
            "remote_interface": "Gig 0/24",
            "platform": "WS-C3560",
        })

    def test_cisco_cdp_neighbors_detail_overrides_brief_entry(self):
        lines = [
            "switch#show cdp neighbors detail",
            "-------------------------",
            "Device ID: SW-CORE-01.example.local",
            "Entry address(es):",
            "Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP",
            "Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24",
            "",
            "Total cdp entries displayed : 1",
        ]
        result = rp.parse_neighbors(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["neighbor_id"], "SW-CORE-01.example.local")
        self.assertEqual(result[0]["platform"], "WS-C3850-24T")
        self.assertEqual(result[0]["local_interface"], "GigabitEthernet1/0/1")

    def test_huawei_lldp_neighbor_brief(self):
        lines = [
            "<SW>display lldp neighbor brief",
            "Local Intf              Neighbor Dev            Neighbor Intf     Exptime",
            "10GE1/0/1               ACCESS-SW03             10GE1/0/2         100",
        ]
        result = rp.parse_neighbors(lines)
        self.assertEqual(result, [{
            "protocol": "LLDP",
            "neighbor_id": "ACCESS-SW03",
            "local_interface": "10GE1/0/1",
            "remote_interface": "10GE1/0/2",
            "platform": "",
        }])


class TestParsePortChannels(unittest.TestCase):
    def test_cisco_etherchannel_summary(self):
        lines = [
            "switch#show etherchannel summary",
            "Flags:  D - down        P - bundled in port-channel",
            "Group  Port-channel  Protocol    Ports",
            "------+-------------+-----------+-----------------------------------------------------------",
            "1      Po1(SU)         LACP      Gi0/1(P) Gi0/2(P)",
        ]
        result = rp.parse_port_channels(lines)
        self.assertEqual(result, [{
            "name": "Po1", "protocol": "LACP", "status": "SU", "members": "Gi0/1, Gi0/2",
        }])

    def test_huawei_eth_trunk_multiline_block(self):
        lines = [
            "<SW>display eth-trunk 1",
            "Eth-Trunk1's state information is:",
            "Local:",
            "LAG ID: 1                      WorkingMode: NORMAL",
            "Operate status: up             Number Of Up Port In Trunk: 2",
            "------------------------------------------------------------------------------",
            "PortName                Status  Weight",
            "10GE1/0/1                Up      1",
            "10GE1/0/2                Up      1",
        ]
        result = rp.parse_port_channels(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "Eth-Trunk1")
        self.assertEqual(result[0]["status"], "up")
        self.assertEqual(result[0]["members"], "10GE1/0/1, 10GE1/0/2")

    def test_no_port_channels_returns_empty_list(self):
        self.assertEqual(rp.parse_port_channels(["hostname SW01"]), [])


class TestParseVersion(unittest.TestCase):
    def test_cisco_version_and_model(self):
        lines = [
            "Cisco IOS Software, C3850 Software, Version 16.9.4, RELEASE SOFTWARE (fc2)",
            "cisco WS-C3850-24T (MIPS) processor",
        ]
        self.assertEqual(rp.parse_version(lines), {"os_version": "16.9.4", "model": "WS-C3850-24T"})

    def test_huawei_version_and_model_not_misparsed_as_cisco(self):
        lines = [
            "Huawei Versatile Routing Platform Software",
            "VRP (R) software, Version 5.170 (S5720 V200R019C10SPC500)",
            "HUAWEI S5720-28X-LI-AC uptime is 100 days, 2 hours",
        ]
        result = rp.parse_version(lines)
        self.assertEqual(result["os_version"], "5.170 (S5720 V200R019C10SPC500)")
        self.assertEqual(result["model"], "S5720-28X-LI-AC")

    def test_unrecognized_text_returns_blank_fields(self):
        self.assertEqual(rp.parse_version(["nothing useful"]), {"os_version": "", "model": ""})


class TestParseIpRouteTable(unittest.TestCase):
    def test_cisco_directly_connected_and_static_default_route(self):
        lines = [
            "switch#show ip route",
            "Gateway of last resort is 10.10.10.254 to network 0.0.0.0",
            "",
            "C       10.10.10.0/24 is directly connected, Vlan10",
            "S*   0.0.0.0/0 [1/0] via 10.10.10.254",
        ]
        result = rp.parse_ip_route_table(lines)
        self.assertEqual(result, [
            {"protocol": "C", "destination": "10.10.10.0/24", "next_hop": "directly connected", "interface": "Vlan10"},
            {"protocol": "S*", "destination": "0.0.0.0/0", "next_hop": "10.10.10.254", "interface": ""},
        ])

    def test_cisco_variably_subnetted_summary_line_is_not_mistaken_for_a_route(self):
        # A "is subnetted" summary line applies its mask to the routes
        # that follow it, but the route lines themselves repeat only the
        # bare network (no "/mask") -- parse_ip_route_table requires an
        # inline "/mask" on the destination token, so these entries are
        # skipped rather than parsed with a wrong mask. This documents
        # that known, current limitation rather than asserting a mask
        # this parser doesn't actually have.
        lines = [
            "switch#show ip route",
            "     10.0.0.0/24 is subnetted, 1 subnets",
            "C       10.10.10.0 is directly connected, Vlan10",
        ]
        self.assertEqual(rp.parse_ip_route_table(lines), [])

    def test_huawei_routing_table(self):
        lines = [
            "<SW>display ip routing-table",
            "Route Flags: R - relay, D - download to fib",
            "Destination/Mask    Proto  Pre  Cost        Flags NextHop         Interface",
            "0.0.0.0/0           Static 60   0             RD  10.20.30.254    Vlanif30",
        ]
        result = rp.parse_ip_route_table(lines)
        self.assertEqual(result, [{
            "protocol": "Static", "destination": "0.0.0.0/0",
            "next_hop": "10.20.30.254", "interface": "Vlanif30",
        }])


class TestParseArpTable(unittest.TestCase):
    def test_cisco_arp_table(self):
        lines = [
            "switch#show ip arp",
            "Protocol  Address          Age (min)  Hardware Addr   Type   Interface",
            "Internet  10.10.10.50      10         0011.2233.4455  ARPA   Vlan10",
        ]
        result = rp.parse_arp_table(lines)
        self.assertEqual(result, [{
            "ip_address": "10.10.10.50", "mac_address": "0011.2233.4455",
            "age": "10", "interface": "Vlan10",
        }])

    def test_huawei_arp_table(self):
        lines = [
            "<SW>display arp",
            "IP ADDRESS      MAC ADDRESS     EXPIRE(M) TYPE        INTERFACE",
            "10.20.30.50     0022-3344-5566  20        DYNAMIC     Vlanif30",
        ]
        result = rp.parse_arp_table(lines)
        self.assertEqual(result, [{
            "ip_address": "10.20.30.50", "mac_address": "0022-3344-5566",
            "age": "20", "interface": "Vlanif30",
        }])


if __name__ == "__main__":
    unittest.main()
