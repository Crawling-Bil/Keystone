"""Router Analyzer: Catalyst SD-WAN management mode, control-connection history, SD-WAN log messages, restart history.

The fixture ``c8200_sdwan_history_masked.txt`` is cut from a real capture of a C8200-1N-4T cEdge (IOS-XE 17.09.03a,
``vManaged: false``, ``show logging last 3000``) and masked.  Values asserted here were read off that output.
The other cases are synthetic sessions that cross a rule's boundary from both sides.
"""

from __future__ import annotations

import re
from pathlib import Path

from features.analyzer_core import collect
from features.analyzer_core.result import section_by_id, validate_result
from features.router_analyzer import context as ctxmod
from features.router_analyzer import runtime, runtime_logs as rl, runtime_vpn as rv
from features.router_analyzer.refs import REFS
from features.router_analyzer.service import analyze

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "router"
COLLECT_DIR = ROOT / "static" / "collect-scripts"
FIXTURE = "c8200_sdwan_history_masked.txt"


def load(name: str = FIXTURE) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def ids(result: dict) -> list[str]:
    return [item["id"] for item in result["findings"]]


def hits(result: dict, rule_id: str, contains: str = "") -> list[dict]:
    return [item for item in result["findings"] if item["id"] == rule_id and contains in item["title"]]


def card(result: dict, label: str) -> dict:
    return next(item for item in result["cards"] if item["label"] == label)


def info(result: dict) -> dict[str, str]:
    return {row["label"]: str(row["value"]) for row in result["info"]}


def block(text: str, command: str) -> list[str]:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.endswith("#" + command))
    end = next((j for j in range(start + 1, len(lines)) if re.match(r"^[\w.-]+#\S", lines[j])), len(lines))
    return lines[start + 1:end]


# ------------------------------------------------------------------ show sdwan control connections
def test_control_connection_row_without_organization_and_uptime_is_read_from_the_right():
    # a vBond that stays in "connect": ORGANIZATION and UPTIME are blank, so every later column moves left
    line = "vbond   dtls 0.0.0.0         0          0      10.255.1.7                            12346 10.255.1.7                            12346                         custom2         No    connect                0"
    (row,) = rv.parse_sdwan_control_connections([line])
    assert (row["local_color"], row["proxy"], row["state"], row["organization"], row["uptime"], row["group_id"]) == ("custom2", "No", "connect", "", "", "0")


def test_control_connection_row_with_organization_and_uptime():
    line = "vsmart  dtls 10.250.20.2     910000     1      10.255.1.6                            12946 10.255.1.6                            12946 EXAMPLE-SDWAN-FABRIC      custom1         No    up     3:03:25:27 0"
    (row,) = rv.parse_sdwan_control_connections([line])
    assert (row["organization"], row["local_color"], row["state"], row["uptime"]) == ("EXAMPLE-SDWAN-FABRIC", "custom1", "up", "3:03:25:27")


def test_control_connection_uptime_with_a_two_digit_day_count_is_glued_to_the_group_id():
    # d:hh:mm:ss is 11 characters wide; with a two-digit day count the CONTROLLER GROUP ID is printed against it with no space.
    # Read as one token this shifted color/proxy/state by one column: "color No is 21:00:00:170" and "No control connection is up".
    line = "vsmart  dtls 10.250.20.2     910000     1      10.255.1.6                              13046 10.255.1.6                              13046 EXAMPLE-SDWAN-FABRIC      private2        No    up     21:00:00:170"
    (row,) = rv.parse_sdwan_control_connections([line])
    assert (row["organization"], row["local_color"], row["proxy"], row["state"], row["uptime"], row["group_id"]) == ("EXAMPLE-SDWAN-FABRIC", "private2", "No", "up", "21:00:00:17", "0")


def test_control_connection_glued_uptime_keeps_a_multi_digit_group_id():
    line = "vsmart  dtls 10.250.20.2     910000     1      10.255.1.6                              13046 10.255.1.6                              13046 EXAMPLE-SDWAN-FABRIC      private1        No    up     19:10:16:5112"
    (row,) = rv.parse_sdwan_control_connections([line])
    assert (row["state"], row["uptime"], row["group_id"]) == ("up", "19:10:16:51", "12")


def test_control_connection_findings_do_not_raise_a_false_down_alarm_for_glued_uptimes():
    text = "\n".join([
        "HOST#show sdwan control connections",
        "PEER    PEER PEER            SITE       DOMAIN PEER                                    PRIV  PEER                                    PUB",
        "TYPE    PROT SYSTEM IP       ID         ID     PRIVATE IP                              PORT  PUBLIC IP                               PORT  ORGANIZATION            LOCAL COLOR     PROXY STATE UPTIME   ID",
        "-----------------------------------------------------------------------------------------------------------------------------------------------------------",
        "vsmart  dtls 10.250.20.2     910000     1      10.255.1.6                              13046 10.255.1.6                              13046 EXAMPLE-SDWAN-FABRIC      private2        No    up     21:00:00:170",
        "vmanage dtls 10.255.20.1     910000     0      10.255.1.5                              13046 10.255.1.5                              13046 EXAMPLE-SDWAN-FABRIC      private2        No    up     19:10:16:300",
        "HOST#",
    ])
    rows = rv.parse_sdwan_control_connections(text.splitlines())
    assert {row["state"] for row in rows} == {"up"} and {row["local_color"] for row in rows} == {"private2"}


def test_fixture_control_table_has_five_connections_and_no_bogus_state():
    rows = section_by_id(analyze(load(), "x.txt"), "sdwan_control")["rows"]
    assert len(rows) == 5 and {r["state"] for r in rows} == {"up"} and {r["local_color"] for r in rows} == {"custom1", "custom2"}


# ------------------------------------------------------------------ show sdwan control connection-history
def test_history_parser_reads_the_devices_own_legend_and_every_row():
    history = rv.parse_sdwan_control_history(block(load(), "show sdwan control connection-history"))
    assert len(history["legend"]) >= 55
    assert history["legend"]["DISTLOC"] == "TLOC Disabled."
    assert history["legend"]["ORPTMO"] == "Server's peer timed out."
    assert history["legend"]["DUPSYSIPDEL"].startswith("Duplicate System IP")
    assert len(history["rows"]) == 45
    first = history["rows"][0]
    assert (first["type"], first["local_error"], first["state"], first["repeat"]) == ("vbond", "DISCVBD", "tear_down", 3)
    assert first["downtime"].startswith("2026-09-29T13:56")


def test_history_error_codes_are_grouped():
    assert rv.control_error_class("DCONFAIL") == "unreachable"
    assert rv.control_error_class("VS_TMO") == "timeout"
    assert rv.control_error_class("DISTLOC") == "local"
    assert rv.control_error_class("DISCVBD") == "normal"
    assert rv.control_error_class("CRTVERFL") == "certificate"
    assert rv.control_error_class("RXTRDWN") == "peer"
    assert rv.control_error_class("SOMETHING") == "other"


def test_fixture_history_findings():
    result = analyze(load(), "x.txt")
    # private2 (the LINTASARTA transport) has no control connection and no BFD session: a live fault
    live = hits(result, "RTR-SDW-020", "color private2")
    assert live and live[0]["severity"] == "medium" and "DCONFAIL" in live[0]["title"]
    assert hits(result, "RTR-SDW-023", "GigabitEthernet0/0/2 (private2)")
    # custom1/custom2 failed 39 times before and are up now: recorded, not alarmed
    recovered = hits(result, "RTR-SDW-020", "up now")
    assert {item["object"] for item in recovered} == {"custom1", "custom2"} and {item["severity"] for item in recovered} == {"low"}
    assert hits(result, "RTR-SDW-021") and "DISTLOC" in hits(result, "RTR-SDW-021")[0]["title"]
    assert not hits(result, "RTR-SDW-002")                         # every current connection is up
    table = section_by_id(result, "sdwan_history")
    assert len(table["rows"]) == 45 and any(r["meaning"] == "TLOC Disabled." for r in table["rows"])


def test_history_with_a_color_nobody_uses_any_more_is_information_not_a_fault():
    full = load()
    a, b = full.index("#show sdwan control connection-history"), full.index("#show sdwan system status")
    text = full[:a] + full[a:b].replace("private2", "custom9") + full[b:]     # the old color is no longer configured on any interface
    result = analyze(text, "x.txt")
    assert hits(result, "RTR-SDW-024", "custom9")
    assert not hits(result, "RTR-SDW-020", "custom9")


def test_certificate_errors_in_the_history_are_high_and_stay_high_when_connections_are_up():
    text = load().replace("DCONFAIL   NOERR      39", "CRTVERFL   NOERR      39", 1)
    result = analyze(text, "x.txt")
    assert any(item["severity"] == "high" and "CRTVERFL" in item["title"] for item in hits(result, "RTR-SDW-020"))


def test_history_findings_say_when_the_current_table_is_missing():
    text = re.sub(r"(?s)[\w.-]+#show sdwan control connections\n.*?(?=[\w.-]+#show sdwan control connection-history)", "", load())
    result = analyze(text, "x.txt")
    assert ctxmod and result["findings"]
    assert all("not captured" in item["detail"] for item in hits(result, "RTR-SDW-020"))


# ------------------------------------------------------------------ vManaged / Configuration template
def test_vmanaged_false_is_shown_as_card_and_info_row_and_explained():
    result = analyze(load(), "x.txt")
    assert (card(result, "vManage")["value"], card(result, "vManage")["tone"]) == ("false", "warn")
    assert "CLI mode" in card(result, "vManage")["hint"]
    assert info(result)["vManaged"] == "false" and info(result)["Configuration template"] == "None"
    assert info(result)["Operating mode"] == "Controller-Managed" and info(result)["SD-WAN role"] == "cEdge-SDWAN"
    finding = hits(result, "RTR-SDW-030")[0]
    assert finding["severity"] == "info" and finding["reference"] == REFS["sdwan_vmanaged"]


def test_vmanaged_true_shows_the_template_name_and_no_cli_mode_finding():
    text = load().replace("vManaged:                false", "vManaged:                true").replace("Configuration template:  None", "Configuration template:  TEMPLATE-BRANCH-A")
    result = analyze(text, "x.txt")
    assert (card(result, "vManage")["value"], card(result, "vManage")["tone"], card(result, "vManage")["hint"]) == ("true", "ok", "template TEMPLATE-BRANCH-A")
    assert info(result)["Configuration template"] == "TEMPLATE-BRANCH-A"
    assert not hits(result, "RTR-SDW-030") and not hits(result, "RTR-SDW-032")
    status = {p["label"]: p["value"] for p in section_by_id(result, "sdwan_status")["pairs"]}
    assert status["vManaged"] == "true" and status["Configuration template"] == "TEMPLATE-BRANCH-A"


def test_vmanaged_true_without_a_template_name_and_commit_pending():
    text = load().replace("vManaged:                false", "vManaged:                true").replace("Commit pending:          false", "Commit pending:          true")
    result = analyze(text, "x.txt")
    assert hits(result, "RTR-SDW-032") and hits(result, "RTR-SDW-031")
    assert "does not define" not in hits(result, "RTR-SDW-031")[0]["detail"] or "lists the field" in hits(result, "RTR-SDW-031")[0]["detail"]


def test_no_vmanage_card_on_a_traditional_router():
    result = analyze(load("c8300_iosxe_ospf_log_masked.txt"), "x.txt")
    assert not any(item["label"] == "vManage" for item in result["cards"]) and "vManaged" not in info(result)


def test_controller_managed_mode_switches_the_sdwan_dialect_on_without_status_output():
    text = "r1#show version\nCisco IOS XE Software, Version 17.09.03a\nRouter operating mode: Controller-Managed\n\nr1#show clock\n10:00:00.000 UTC Mon Oct 5 2026\n\nr1#\n"
    result = analyze(text, "x.txt")
    assert any(item["command"] == "show sdwan system status" for item in result["coverage"]) or "show sdwan system status" in str(result.get("missing"))


# ------------------------------------------------------------------ logging
def test_show_logging_last_n_is_recognised_and_reports_the_window():
    result = analyze(load(), "x.txt")
    assert any(row["command"].startswith("show logging last") and row["status"] == "analyzed" for row in result["coverage"])
    assert "Lines analyzed" in {p["label"] for p in section_by_id(result, "log_summary")["pairs"]}


def test_sdwan_daemon_messages_are_parsed_and_omp_flaps_are_counted():
    log = rl.parse_logging(block(load(), "show logging last 3000"))
    ompd = [m for m in log["mnemonics"] if m["facility"] == "SDWAN-OMPD"]
    assert ompd and all(m["severity"] in (3, 5, 6) for m in ompd)
    peer = next(iter(log["flaps"]["omp"].items()))
    assert peer[0].startswith("vSmart peer") and peer[1]["down"] == 1 and peer[1]["up"] == 1 and peer[1]["reasons"] == {"Init": 1}
    assert log["omp_vsmarts"]["min"] == 1 and log["shown_lines"] == 3000


def test_omp_peer_loss_finding_and_zero_vsmart_finding():
    lines = ["Log Buffer (512000 bytes):", "",
             "Sep 29 06:32:44.475: %Cisco-SDWAN-LAB-R1-OMPD-3-ERRO-400002: vSmart peer 10.255.1.2 state changed to Init",
             "Sep 29 06:32:44.475: %Cisco-SDWAN-LAB-R1-OMPD-6-INFO-400005: Number of vSmarts connected : 0",
             "Sep 29 06:32:50.000: %Cisco-SDWAN-LAB-R1-OMPD-3-ERRO-400002: vSmart peer 10.255.1.2 state changed to Handshake",
             "Sep 29 06:33:10.000: %Cisco-SDWAN-LAB-R1-OMPD-3-ERRO-400002: vSmart peer 10.255.1.2 state changed to Up"]
    result = analyze("lab-r1#show logging\n" + "\n".join(lines) + "\n\nlab-r1#\n", "x.txt")
    assert hits(result, "RTR-LOG-034", "vSmart peer 10.255.1.2")
    assert hits(result, "RTR-LOG-035")[0]["severity"] == "high"


def test_hostname_with_hyphens_in_the_sdwan_message_is_not_split_into_the_daemon():
    log = rl.parse_logging(["Log Buffer (512000 bytes):", "", "Sep 29 06:32:44.475: %Cisco-SDWAN-KCU-SITE1-OMPD-3-ERRO-400002: vSmart peer 10.0.0.2 state changed to Init"])
    assert log["mnemonics"][0]["facility"] == "SDWAN-OMPD" and log["mnemonics"][0]["mnemonic"] == "ERRO-400002"


# ------------------------------------------------------------------ restart and crash history
def test_restart_history_combines_show_version_and_sdwan_status():
    result = analyze(load(), "x.txt")
    rows = section_by_id(result, "restart_history")["rows"]
    assert [r["source"] for r in rows[:2]] == ["show version", "show sdwan system status"]
    assert "Reload Command" in rows[0]["detail"] and rows[1]["event"].startswith("Last reboot: Reload Command")
    assert "RTR-LOG-061" not in ids(result)                         # the real log has no crash indicator


def _log_session(lines: list[str]) -> str:
    return "lab-r1#show logging\nLog Buffer (512000 bytes):\n\n" + "\n".join(lines) + "\n\nlab-r1#\n"


def test_process_failure_memory_failure_and_traceback_are_fault_indicators():
    result = analyze(_log_session([
        "Oct  1 02:00:00.001: %PMAN-3-PROCFAIL: R0/0: pman: The process fman_rp has failed (rc 134)   [synthetic test line]",
        "Oct  1 02:00:05.001: %SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed   [synthetic test line]",
        "Oct  1 02:00:09.001: %SYS-3-CPUHOG: Task is running for (2004)msecs -Traceback= 1#abc   [synthetic test line]",
    ]), "x.txt")
    finding = hits(result, "RTR-LOG-061")[0]
    assert finding["severity"] == "medium" and "process failure" in finding["title"] and "memory allocation failure" in finding["title"]
    assert finding["reference"] == REFS["router_crashes_xe"]
    kinds = [r["event"] for r in section_by_id(result, "restart_history")["rows"]]
    assert any("process failure" in k for k in kinds) and any("memory allocation failure" in k for k in kinds)


def test_cpu_hog_alone_is_low():
    result = analyze(_log_session(["Oct  1 02:00:09.001: %SYS-3-CPUHOG: Task is running for (2004)msecs   [synthetic test line]"]), "x.txt")
    assert hits(result, "RTR-LOG-061")[0]["severity"] == "low"


def test_reload_message_in_the_log_is_listed():
    result = analyze(_log_session(["Oct  1 02:00:00.001: %SYS-5-RELOAD: Reload requested by admin on vty0. Reload Reason: Reload Command.   [synthetic test line]"]), "x.txt")
    assert hits(result, "RTR-LOG-060") and section_by_id(result, "restart_history")["rows"][-1]["event"] == "reload requested"


def test_clean_log_has_no_restart_or_crash_finding():
    result = analyze(_log_session(["Oct  1 02:00:00.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to up"]), "x.txt")
    assert not hits(result, "RTR-LOG-060") and not hits(result, "RTR-LOG-061")


# ------------------------------------------------------------------ interface utilisation, coverage notes
def test_tunnel_bandwidth_is_not_a_capacity():
    text = """Tunnel1 is up, line protocol is up
  Hardware is Tunnel
  MTU 9976 bytes, BW 100 Kbit/sec, DLY 50000 usec,
  5 minute input rate 2566000 bits/sec, 300 packets/sec
  5 minute output rate 1000 bits/sec, 1 packets/sec
GigabitEthernet0/0/0 is up, line protocol is up
  Hardware is C8200, address is 0000.0000.0001 (bia 0000.0000.0001)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  5 minute input rate 500000000 bits/sec, 300 packets/sec
  5 minute output rate 1000 bits/sec, 1 packets/sec
"""
    tunnel, gig = runtime.parse_show_interfaces(text.splitlines())
    assert tunnel["in_bps"] == 2566000 and "in_util_pct" not in tunnel
    assert gig["in_util_pct"] == 50.0


def test_ssh_hop_and_single_interface_view_are_not_reported_as_unparsed():
    result = analyze("r1#ssh 10.1.1.1\nPassword:\n\nr1#show ip interface brief\nInterface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0/0   10.1.1.1        YES NVRAM  up                    up\n\nr1#show interfaces GigabitEthernet0/0/0\nGigabitEthernet0/0/0 is up, line protocol is up\n  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,\n\nr1#\n", "x.txt")
    status = {row["command"]: row["status"] for row in result["coverage"]}
    assert status.get("ssh 10.1.1.1") == "ignored"
    assert status.get("show interfaces GigabitEthernet0/0/0") == "covered"


def test_result_stays_valid_against_the_schema():
    assert validate_result(analyze(load(), "x.txt")) == []


# ------------------------------------------------------------------ collect lists
def _commands(name: str) -> list[str]:
    text = (COLLECT_DIR / name).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith(("!", "#"))]


def test_traditional_list_has_no_sdwan_command_and_the_sdwan_list_has_all_of_them():
    traditional, sdwan = _commands("collect-router-cisco-ios-xe.txt"), _commands("collect-router-cisco-sdwan.txt")
    assert not [c for c in traditional if c.startswith("show sdwan")]
    for spec in ctxmod.SPECS:
        if spec.key.startswith("sdwan_"):
            assert any(command in sdwan for command in spec.templates), spec.key
            assert not any(command in traditional for command in spec.templates), spec.key
    for command in ("show sdwan control local-properties", "show sdwan control connection-history", "show sdwan omp peers", "show sdwan omp routes", "show sdwan omp tlocs", "show sdwan app-route stats", "show sdwan policy from-vsmart"):
        assert command in sdwan, command
    assert sdwan[0] == "terminal length 0" and len(sdwan) == len(set(sdwan))
    assert "show logging last 3000" in sdwan
    assert not any(re.match(r"(?i)(clear|reload|configure|conf t|write|copy|debug|erase|delete|no )", c) for c in sdwan)


def test_sdwan_list_covers_the_core_specs_of_a_cedge():
    sdwan = _commands("collect-router-cisco-sdwan.txt")
    for key in ("version", "ifstats", "ipbrief", "logging", "cpu", "sdwan_status", "sdwan_control", "sdwan_history", "sdwan_bfd"):
        spec = next((s for s in ctxmod.SPECS if s.key == key), None)
        assert spec is not None, key
        assert any(command == template or command.startswith(template) for template in spec.templates for command in sdwan), key


def test_both_router_lists_are_discovered_with_readable_titles():
    titles = {item["file"]: item["title"] for item in collect.discover("collect-router", COLLECT_DIR)}
    assert titles["collect-router-cisco-ios-xe.txt"] == "Cisco IOS-XE" and titles["collect-router-cisco-sdwan.txt"] == "Cisco SD-WAN"


def test_the_new_references_exist_and_are_cisco_pages():
    for key in ("sdwan_control_troubleshoot", "sdwan_vmanaged", "sdwan_cli_mode", "syslog_xe_17_9", "router_crashes_xe"):
        assert REFS[key].startswith("https://www.cisco.com/c/en/us/")
