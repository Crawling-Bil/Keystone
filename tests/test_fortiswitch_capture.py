"""FortiSwitch capture: SSH from a FortiGate into an MCLAG switch, `diagnose` commands, `diagnose debug report` and `show`.

Synthetic: dummy serials (S448ENTF00000001/2), documentation addresses, an invented administrator.  The layout copies what a real
FortiSwitchOS 7.4 capture looks like, including the rows the terminal hard-wraps in the middle of a word.
"""

from __future__ import annotations

import pytest

from features.analyzer_core.result import validate_result
from features.firewall_analyzer import forti_switch, service

SW = "S448ENTF00000001"
PEER = "S448ENTF00000002"

CAPTURE = f"""\
FGT-LAB-01 # config vdom

FGT-LAB-01 (vdom) # edit OOB
current vf=OOB:2

FGT-LAB-01 (OOB) # exec ssh admin@192.0.2.20
admin@192.0.2.20's password:
Permission denied, please try again.
admin@192.0.2.20's password:
{SW} # diagnose switch trunk summary

Trunk Name         Mode                               PSC          MAC                Status       Up Time
________________   ________________________________  ___________  _________________  ___________  __________________________
_______

G1K1FTB00000001    lacp-active(isl,mclag)            src-dst-ip   04:01:A1:00:00:84  up(1/1)       5 days,23 hours,58 mins,5
0 secs
_FlInK1_ICL0_      lacp-active(isl,icl)              src-dst-ip   04:01:A1:00:00:82  up(2/2)       0 days,0 hours,3 mins,3
5 secs

{SW} # diagnose switch mclag peer-consistency-check

    Running diagnostic, it may take sometime...

    ** Comparing "switch.global.mclag-split-brain-detect" config                 ....OK

    mclag-trunk-name    peer-config lacp-state   stp-state    local-ports             remote-ports
    __________________  ___________ __________   _________    _____________           _____________

    G1K1FTB00000001 mclag peer diagnostic timeout, Please try again!
    _FlInK1_ICL0_ mclag peer diagnostic timeout, Please try again!

{SW} # diag switch mclag icl
_FlInK1_ICL0_
    icl-ports            47-48
    egress-block-ports   49
    local-serial-number  {SW}
    peer-serial-number   {PEER}
    Local uptime         6 days  0h: 5m: 0s
    Peer uptime          0 days  3h:53m: 0s
    keepalive interval   1
    keepalive timeout    60
    dormant candidate    Peer
    split-brain          Disabled

Counters
    received keepalive packets          3003
    transmited keepalive packets        5178
    received keepalive drop packets     135
    receive keepalive miss              35

{SW} # diagnose stp instance list

MST Instance Information, primary-Channel:

Instance ID 0 (CST)
  Config         Priority 20480
                 Bridge MAC 0401a1000001
  Root           MAC 0401a1000001, Priority 20480, Path Cost 0, Remaining Hops 20
                 (This bridge is the root)

  TCN Events     Triggered 6 (5d 20h 17m 42s ago), Received 8 (5d 23h 54m 29s ago)

  Port               Speed   Cost       Priority   Role         State        HelloTime  Flags
  ________________   ______  _________  _________  ___________  __________   _________  _______________

  port1              -       200000000  128        DISABLED     DISCARDING   2          ED
  G1K1FTB00000001    10G     2000       128        DESIGNATED   FORWARDING   2          ED
  _FlInK1_ICL0_      2G      1          128        BACKUP       DISCARDING   2          EN
  >>> port47          STP state FORWARDING mismatches trunk `_FlInK1_ICL0_`: Active members in HW:  port47 port48

{SW} # diagnose debug report

----------------------------------------------------------------
  Serial Number: {SW}   Diagnose output
----------------------------------------------------------------

### get system status


Version: FortiSwitch-448E v7.4.7,build0914,250616 (GA)
Serial-Number: {SW}
Boot: Warmboot
Hostname: {SW}
System time: Sat Oct 11 01:13:16 2025

### get system performance status


CPU states: 1% user 14% system 0% nice 85% idle
Memory states: 40% used
Uptime: 6 days,  0 hours,  9 minutes

### diagnose sys psu status



Module          Status
___________________________________
PSU1            OK
PSU2            FAILED

### diagnose sys flash list


Partition  Image                                     TotalSize(KB)  Used(KB)  Use%  Active
1          S448EN-7.2.7-FW-build0479-240214                  53248     34930   65%  No
(*) 2      S448EN-7.4.7-FW-build0914-250616                  53248     35414   66%  Yes

### diagnose switch physical-ports summary


  Portname    Status  Tpid  Vlan  Duplex  Speed  Flags         Discard
  __________  ______  ____  ____  ______  _____  ____________  _________

  port1       down    8100  1     half    1G     QS,  ,        none
  port47      up      8100  4094  full    1G     QS,TL,        none
  port48      up      8100  4094  full    1G     QS,TL,        none
  port49      up      8100  4094  full    10G    QS,TL,        none

### get switch lldp neighbors-summary


  Portname    Status   Device-name                 TTL   Capability  MED-type  Port-ID
  __________  _______  __________________________  ____  __________  ________  _______
  port1       Down     -                           -     -           -         -
  port47      Up       {PEER}            120   BR          -         port47
  port49      Up       FGT-LAB-01                  120   BR          -         port13

### execute log display


10 logs found.
10 logs returned.

1: 2025-10-11 01:14:04 log_id=0106009008 tz=+0700 type=event subtype=switch_controller pri=notice vd=root msg="FortiLink: IS
L timing-out for trunk(_FlInK1_ICL0_) member port-num(46) port46 did not receive ISL pkt for(600) sec"

2: 2025-10-11 01:04:19 log_id=0100001001 tz=+0700 type=event subtype=system pri=notice vd=root msg="Physical port (port47) became active member of trunk (_FlInK1_ICL0_)"

3: 2025-10-11 01:04:07 log_id=0100001401 tz=+0700 type=event subtype=system pri=notice vd=root msg="primary switch port port47 has gone down"

4: 2025-10-11 01:00:25 log_id=0100001002 tz=+0700 type=event subtype=system pri=notice vd=root msg="Physical port (port48) became non-active member of trunk (_FlInK1_ICL0_)"

5: 2025-10-11 00:56:10 log_id=0100001401 tz=+0700 type=event subtype=system pri=notice vd=root msg="primary switch port port48 has gone down"

6: 2025-10-11 00:30:00 log_id=0100001002 tz=+0700 type=event subtype=system pri=notice vd=root msg="Physical port (port47) became non-active member of trunk (_FlInK1_ICL0_)"

7: 2025-10-11 00:25:00 log_id=0103032002 tz=+0700 type=event subtype=system pri=alert vd=root user="admin" msg="Administrator admin login failed from ssh(192.0.2.7) because of invalid password"

8: 2025-10-10 09:53:28 log_id=0106009006 tz=+0700 type=event subtype=switch_controller pri=notice vd=root msg="Switch-Controller: Restart caputp since SSL handshake failed 5 times"

9: 2025-10-10 09:43:28 log_id=0106009006 tz=+0700 type=event subtype=switch_controller pri=notice vd=root msg="Switch-Controller: Restart caputp since SSL handshake failed 5 times"

10: 2025-10-10 09:33:28 log_id=0106009006 tz=+0700 type=event subtype=switch_controller pri=notice vd=root msg="Switch-Controller: Restart caputp since SSL handshake failed 5 times"

### show


config system global
    set hostname "{SW}"
end
config switch trunk
    edit "_FlInK1_ICL0_"
        set mode lacp-active
        set mclag-icl enable
        set members "port47" "port48"
    next
end
config system interface
    edit "mgmt"
        set mode dhcp
        set allowaccess ping https ssh
        set secondary-IP enable
        config secondaryip
            edit 1
                set ip 192.168.1.99 255.255.255.0
                set allowaccess ping https ssh
            next
        end
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2examplenotarealhashexamplenotarealhashexamplenotarealhash==
    next
end
config log syslogd3 setting
    set status enable
    set server "127.0.0.1"
    set port 8514
end

{SW} #
"""


@pytest.fixture(scope="module")
def result():
    return service.analyze(CAPTURE, "fsw.txt")


def test_fortiswitch_is_not_mistaken_for_a_fortigate():
    assert forti_switch.looks_like_fortiswitch(CAPTURE)
    assert service.detect_vendor(CAPTURE) == "fortiswitch"


def test_fortigate_configuration_is_not_taken_for_a_switch():
    assert not forti_switch.looks_like_fortiswitch("config system global\n set hostname fgt\nend\nconfig firewall policy\n edit 1\n next\nend\n")


def test_result_is_valid_and_identified(result):
    assert validate_result(result) == []
    assert result["hostname"] == SW
    assert "FortiSwitch-448E" in result["platform"] and "7.4.7" in result["platform"]
    reached = next(row for row in result["info"] if row["label"] == "Reached through")
    assert reached["value"] == "FGT-LAB-01"                                   # the FortiGate hop is context, not the device


def test_expected_findings(result):
    ids = {f["id"] for f in result["findings"]}
    assert {"FSW-LOG-001", "FSW-MCLAG-001", "FSW-MCLAG-002", "FSW-MCLAG-003", "FSW-MCLAG-004", "FSW-MCLAG-005", "FSW-MCLAG-006", "FSW-STP-002", "FSW-HW-001", "FSW-SEC-001", "FSW-SEC-002", "FSW-SEC-003", "FSW-SEC-004", "FSW-SYS-004"} <= ids
    by_id = {f["id"]: f for f in result["findings"]}
    assert by_id["FSW-LOG-001"]["severity"] == "high" and "3" in by_id["FSW-LOG-001"]["detail"]
    assert "PSU2" in by_id["FSW-HW-001"]["title"]
    assert "port46" in by_id["FSW-MCLAG-002"]["detail"] and "not a configured ICL member" in by_id["FSW-MCLAG-002"]["detail"]
    assert "192.168.1.99" in by_id["FSW-SEC-001"]["title"]


def test_wrapped_trunk_uptime_is_rejoined(result):
    rows = next(s for s in result["sections"] if s["id"] == "fsw_trunks")["rows"]
    assert rows[0]["uptime"].endswith("50 secs") and rows[1]["uptime"].endswith("35 secs")


def test_wrapped_log_line_is_rejoined(result):
    events = next(s for s in result["sections"] if s["id"] == "fsw_events")["rows"]
    assert any("ISL timing-out" in row["msg"] and "ISL timing-out for trunk" in row["msg"] for row in events)


def test_every_finding_cites_documentation(result):
    for item in result["findings"]:
        assert item["reference"].startswith("https://"), item["id"]


def test_no_secret_reaches_the_result(result):
    blob = str(result)
    assert "examplenotarealhash" not in blob and "SH2" not in blob
    assert "ENC " not in blob and "SH2" not in blob


def test_missing_commands_are_reported(result):
    missing = [c["command"] for c in result["coverage"] if c["status"] == "missing"]
    assert missing == []                                                      # the synthetic capture has every expected command
    stripped = service.analyze(CAPTURE.split("### execute log display")[0] + "\n", "fsw.txt")
    assert "execute log display" in [c["command"] for c in stripped["coverage"] if c["status"] == "missing"]
