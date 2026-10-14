"""Router Analyzer: health output of a stackable Catalyst in IOS-XE routing mode (environment, platform) and licensing outputs
that earlier captures did not contain (``show license status`` under Smart Licensing Using Policy, classic right-to-use stores).

The text is copied in layout from a Catalyst 9300 (17.03) and an ASR1002-X capture; serial numbers are replaced by FOC0000A0B0-style tokens.
"""

from __future__ import annotations

from features.router_analyzer import context as ctxmod
from features.router_analyzer import runtime_health as rh
from features.router_analyzer.service import analyze

ENVIRONMENT = """\
Switch   FAN     Speed   State
---------------------------------------------------
  1       1     13760     OK
  1       2     13760     OK
  1       3     13760     OK
FAN PS-1 is OK
FAN PS-2 is OK
Switch 1: SYSTEM TEMPERATURE is OK
Inlet Temperature Value: 28 Degree Celsius
Temperature State: GREEN
Yellow Threshold : 46 Degree Celsius
Red Threshold    : 56 Degree Celsius

Outlet Temperature Value: 30 Degree Celsius
Temperature State: GREEN
Yellow Threshold : 105 Degree Celsius
Red Threshold    : 125 Degree Celsius

Hotspot Temperature Value: 42 Degree Celsius
Temperature State: GREEN
Yellow Threshold : 105 Degree Celsius
Red Threshold    : 125 Degree Celsius
SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
--  ------------------  ----------  ---------------  -------  -------  -----
1A  PWR-C1-350WAC-P     FOC0000A0B0  OK              Good     n/a      350
1B  PWR-C1-350WAC-P     FOC0000A0B1  OK              Good     n/a      350
"""
PLATFORM = """\
Switch  Ports    Model                Serial No.   MAC address     Hw Ver.       Sw Ver.
------  -----   ---------             -----------  --------------  -------       --------
 1       65     C9300-48T             FOC0000A0B0  0000.5e00.5301  V05           17.03.04
Switch/Stack Mac Address : 0000.5e00.5301 - Local Mac Address
Mac persistency wait time: Indefinite
                                   Current
Switch#   Role        Priority      State
-------------------------------------------
*1       Active          1          Ready
"""
LICENSE_STATUS_SMART = """\
Utility:
  Status: DISABLED

Smart Licensing Using Policy:
  Status: ENABLED

Data Privacy:
  Sending Hostname: yes
    Callhome hostname privacy: DISABLED
    Smart Licensing hostname privacy: DISABLED
  Version privacy: DISABLED

Transport:
  Type: cslu
  Cslu address: <empty>
  Proxy:
    Not Configured

Policy:
  Policy in use: Merged from multiple sources.
  Reporting ACK required: yes (CISCO default)

Usage Reporting:
  Last ACK received: <none>
  Next ACK deadline: Sep 06 15:23:05 2022 GMT
  Reporting push interval: 30  days
  Next ACK push check: <none>
  Next report push: Oct 12 13:14:09 2026 GMT
  Last report push: <none>
  Last report file write: <none>

Trust Code Installed: <none>
"""
LICENSE_STATUS_CLASSIC = """\
                License Type Supported
        permanent               Non-expiring node locked license
        evalRightToUse          Right to use evaluation non node locked license

                Device status
        Device Credential type: DEVICE
        Device Credential Verification: PASS
        Rehost Type: DC_OR_IC

SWIFT url status
        Swift URL set to default value : https://tools.cisco.com/SWIFT/Licensing
"""
LICENSE_ALL_CLASSIC = """\
License Store: Primary License Storage
StoreIndex: 0   Feature: ipsec                             Version: 1.0
        License Type: Permanent
        License State: Active, In Use
        License Count: Non-Counted
        License Priority: Medium
StoreIndex: 1   Feature: firewall                          Version: 1.0
        License Type: Permanent
        License State: Active, Not in Use
        License Count: Non-Counted
        License Priority: Medium
License Store: Built-In License Storage
StoreIndex: 0   Feature: ipsec                             Version: 1.0
        License Type: EvalRightToUse
        License State: Inactive
            Evaluation total period: 8  weeks 4  days
            Evaluation period left: 8  weeks 4  days
            Period used: 0  minute  0  second
        License Count: Non-Counted
        License Priority: None
StoreIndex: 1   Feature: lawful_intr                       Version: 1.0
        License Type: EvalRightToUse
        License State: Active, Not in Use, EULA not accepted
            Evaluation total period: 8  weeks 4  days
            Evaluation period left: 8  weeks 4  days
            Period used: 0  minute  0  second
        License Count: Non-Counted
        License Priority: None
"""
CLOCK = "20:21:00.123 WIB Mon Oct 12 2026"


def lines(text: str) -> list[str]:
    return text.rstrip("\n").split("\n")


def capture(*blocks: tuple[str, str]) -> str:
    return "".join(f"EDGE-A#{command}\n{body.rstrip(chr(10))}\n\n" for command, body in blocks)


def section(result: dict, section_id: str) -> dict:
    return next((s for s in result["sections"] if s["id"] == section_id), {})


def test_stack_environment_reads_fans_temperatures_and_power_supplies():
    env = rh.parse_environment(lines(ENVIRONMENT))
    by = {(s["slot"], s["sensor"]): s for s in env["sensors"]}
    assert by[("1", "Fan 2")]["value"] == 13760.0 and by[("1", "Fan 2")]["unit"] == "RPM" and by[("1", "Fan 2")]["state"] == "OK"
    assert by[("PS-1", "Power-supply fan PS-1")]["state"] == "OK" and by[("PS-1", "Power-supply fan PS-1")]["value"] is None
    assert by[("1", "System temperature")]["state"] == "OK"
    inlet = by[("1", "Inlet temperature")]
    assert (inlet["value"], inlet["unit"], inlet["state"], inlet["warning"], inlet["critical"]) == (28.0, "Celsius", "Normal", 46, 56)
    assert by[("1", "Hotspot temperature")]["critical"] == 125 and by[("1", "Outlet temperature")]["warning"] == 105
    assert by[("1B", "Power supply PWR-C1-350WAC-P")]["state"] == "OK" and by[("1B", "Power supply PWR-C1-350WAC-P")]["value"] == 350.0
    assert len(env["sensors"]) == 3 + 2 + 1 + 3 + 2
    assert "FOC0000A0B0" not in str(env), "the power-supply serial number must not be kept"


def test_stack_environment_flags_a_failed_fan_a_hot_inlet_and_a_supply_without_system_power():
    bad = (ENVIRONMENT.replace("  1       2     13760     OK", "  1       2         0     Not OK").replace("Inlet Temperature Value: 28", "Inlet Temperature Value: 53")
           .replace("1B  PWR-C1-350WAC-P     FOC0000A0B1  OK              Good ", "1B  PWR-C1-350WAC-P     FOC0000A0B1  OK              Bad  "))
    env = rh.parse_environment(lines(bad))
    states = {(s["slot"], s["sensor"]): s["state"] for s in env["sensors"]}
    assert states[("1", "Fan 2")] == "Not OK"
    assert states[("1B", "Power supply PWR-C1-350WAC-P")] == "OK, system power Bad"
    result = analyze(capture(("show clock", CLOCK), ("show environment all", bad)), filename="env.txt")
    ids = [f["id"] for f in result["findings"]]
    assert "RTR-HLT-032" in ids and "RTR-HLT-031" in ids
    hot = next(f for f in result["findings"] if f["id"] == "RTR-HLT-031")
    assert "Inlet temperature" in hot["detail"] and "critical 56" in hot["detail"]
    healthy = analyze(capture(("show clock", CLOCK), ("show environment all", ENVIRONMENT)), filename="env.txt")
    assert not [f for f in healthy["findings"] if f["id"].startswith("RTR-HLT-03")]


def test_stack_platform_lists_the_members_without_serial_or_mac():
    platform = rh.parse_platform(lines(PLATFORM))
    assert platform["stack"] is True and platform["chassis"] == "C9300-48T"
    assert platform["slots"] == [{"slot": "1", "type": "C9300-48T", "state": "Active, Ready", "uptime": "", "ports": 65, "hw": "V05", "sw": "17.03.04", "role": "Active", "priority": "1"}]
    assert "FOC0000A0B0" not in str(platform) and "5e00" not in str(platform)


def test_health_tables_for_a_stack(monkeypatch=None):
    result = analyze(capture(("show clock", CLOCK), ("show platform", PLATFORM), ("show environment all", ENVIRONMENT)), filename="stack.txt")
    members = section(result, "chassis_slots")
    assert members["title"] == "Stack members" and members["rows"][0]["state"] == "Active, Ready" and members["rows"][0]["_tones"]["state"] == "ok"
    assert [c["label"] for c in members["columns"]] == ["Switch", "Model", "Role, state", "Priority", "Ports", "Hardware", "Software"]
    sensors = section(result, "environment")
    assert sensors["total"] == 11 and all(r["_tones"]["state"] == "ok" for r in sensors["rows"])
    rows = {row["command"]: row for row in result["coverage"]}
    assert rows["show environment all"]["status"] == "analysed" and rows["show platform"]["status"] == "analysed"


def test_license_status_under_smart_licensing_feeds_the_same_check_as_license_all():
    status = rh.parse_license_status(lines(LICENSE_STATUS_SMART))
    assert (status["using_policy"], status["transport"], status["last_ack"], status["next_ack_deadline"]) == ("ENABLED", "cslu", "<none>", "Sep 06 15:23:05 2022 GMT")
    assert status["command"] == "show license status"
    result = analyze(capture(("show clock", CLOCK), ("show license status", LICENSE_STATUS_SMART)), filename="lic.txt")
    finding = next(f for f in result["findings"] if f["id"] == "RTR-HLT-050")
    assert "'show license status': last ACK none" in finding["detail"] and "Sep 06 15:23:05 2022 GMT" in finding["detail"]
    assert section(result, "licensing")["pairs"], "the Smart Licensing table shows the same fields"
    coverage = {row["command"]: row for row in result["coverage"]}
    assert coverage["show license status"]["status"] == "analysed"


def test_classic_license_status_is_a_device_credential_not_a_smart_licensing_table():
    status = rh.parse_license_status(lines(LICENSE_STATUS_CLASSIC))
    assert status == {"device_credential": "PASS", "command": "show license status"}
    result = analyze(capture(("show clock", CLOCK), ("show license status", LICENSE_STATUS_CLASSIC)), filename="lic.txt")
    assert not section(result, "licensing") and section(result, "licensing_classic")["pairs"] == [{"label": "Device credential verification", "value": "PASS"}]
    assert not [f for f in result["findings"] if f["id"] == "RTR-HLT-050"]


def test_classic_license_store_lists_every_feature_with_its_state():
    store = rh.parse_license_all(lines(LICENSE_ALL_CLASSIC))["store"]
    assert [(e["store"], e["feature"], e["type"], e["state"], e["eval_left"]) for e in store] == [
        ("Primary License Storage", "ipsec", "Permanent", "Active, In Use", ""),
        ("Primary License Storage", "firewall", "Permanent", "Active, Not in Use", ""),
        ("Built-In License Storage", "ipsec", "EvalRightToUse", "Inactive", "8 weeks 4 days"),
        ("Built-In License Storage", "lawful_intr", "EvalRightToUse", "Active, Not in Use, EULA not accepted", "8 weeks 4 days")]
    result = analyze(capture(("show clock", CLOCK), ("show license all", LICENSE_ALL_CLASSIC)), filename="lic.txt")
    table = section(result, "license_store")
    assert table["total"] == 4 and table["rows"][0]["_tones"]["state"] == "ok" and table["rows"][2]["_tones"]["state"] == "mute"
    assert not section(result, "licensing"), "no empty Smart Licensing block on a classic-licensing router"
    assert ctxmod.gather(capture(("show clock", CLOCK), ("show license all", LICENSE_ALL_CLASSIC)), "x.txt").coverage
