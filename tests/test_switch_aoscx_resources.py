"""AOS-CX: ``show module`` (member status) and ``show system resource-utilization`` (CPU, memory, flash). The command output is written here
with invented names and serial numbers; it is appended to a masked real capture so the switch is detected as AOS-CX and as a VSF stack."""
from __future__ import annotations

import re
from pathlib import Path

from features.switch_analyzer import aoscx, capture_text, service

BASE = (Path(__file__).parent / "fixtures" / "real_captures" / "aoscx_vsf4_version_inventory_vsf_masked.txt").read_text(encoding="utf-8")
PROMPT = "LAB-CX-1"

MODULES = """Management Modules
==================

     Product                                        Serial
Name Number  Description                            Number     Status
---- ------- -------------------------------------- ---------- ----------------
1/1  JL724B  6200F 24G 4SFP+ Swch                   TW00AA0001 Active (local)
2/1  JL724B  6200F 24G 4SFP+ Swch                   TW00AA0002 Ready
3/1  JL724B  6200F 24G 4SFP+ Swch                   TW00AA0003 Standby


Line Modules
============

     Product                                        Serial
Name Number  Description                            Number     Status
---- ------- -------------------------------------- ---------- ----------------
1/1  JL724B  6200F 24G 4SFP+ Swch                   TW00AA0001 Ready
2/1  JL724B  6200F 24G 4SFP+ Swch                   TW00AA0002 Ready
3/1  JL724B  6200F 24G 4SFP+ Swch                   TW00AA0003 Failed
"""

RESOURCES = """
System Resources:
Processes                         : 154
CPU usage(%)                      : 95
CPU usage(% average over 1 minute): 92
CPU usage(% average over 5 minute): 88
Memory usage(%)                   : 93
Open FD's                         : 2441
Storage 1: Endurance utilization = 80-90% (mmc-type-a), 0-10% (mmc-type-b), Health = normal

Data written to various partitions since boot
Nos         :      722 MB
Log         :      188 KB
Coredump    :        4 KB

Storage partition usage(%)
Nos         :       21
Log         :       85
Coredump    :        1

Process                 CPU Usage(%)    Memory Usage(%)   Open FD's
-------------------------------------------------------------------------
(sd-pam)                    0               0               7
atop                       45               0              14
hpe-routing                 9               1              47
ovsdb-server               14               1             290
"""


def _lines(text: str) -> list[str]:
    return capture_text.clean_lines(f"{PROMPT}# show module\n{text}\n{PROMPT}#\n")


def _result(extra: str) -> dict:
    return service.analyze(BASE + f"\n{PROMPT}# {extra}\n{PROMPT}#\n", filename="stack.txt", vendor="Auto Detect")


def test_modules_are_read_per_section_with_their_status():
    rows = aoscx.parse_modules(_lines(MODULES))
    assert len(rows) == 6
    assert rows[0] == {"kind": "management", "name": "1/1", "product_number": "JL724B", "description": "6200F 24G 4SFP+ Swch", "serial": "TW00AA0001", "status": "Active (local)"}
    assert [r["status"] for r in rows if r["kind"] == "line"] == ["Ready", "Ready", "Failed"]


def test_no_module_table_gives_no_rows():
    assert aoscx.parse_modules(_lines("Module 1/3 is not physically present.")) == []


def test_a_failed_module_is_a_high_finding_and_working_states_are_not():
    result = _result("show module\n" + MODULES)
    codes = {item["code"]: item for item in result["health"]["findings"]}
    assert codes["SW-CX-016"]["severity"] == "high" and "Line module 3/1 (JL724B) is Failed" in codes["SW-CX-016"]["text"]
    assert codes["SW-CX-016"]["doc"]["url"].startswith("https://arubanetworking.hpe.com/")
    healthy = _result("show module\n" + MODULES.replace("Failed", "Ready"))
    assert "SW-CX-016" not in {item["code"] for item in healthy["health"]["findings"]}


def test_the_module_table_is_on_the_health_tab_and_the_command_is_analyzed():
    result = _result("show module\n" + MODULES)
    table = next(t for t in result["extra_tables"] if t["id"] == "cx-modules")
    assert len(table["rows"]) == 6 and table["rows"][0]["kind"] == "Management"
    status = {row["command"]: row["status"] for row in result["coverage"]["rows"]}
    assert status["show module"] == "analyzed"


def test_resource_use_is_read_in_full():
    res = aoscx.parse_resources(capture_text.clean_lines(f"{PROMPT}# show system resource-utilization\n{RESOURCES}\n{PROMPT}#\n"))
    assert (res["cpu"], res["cpu_1m"], res["cpu_5m"], res["memory"], res["processes"], res["open_fds"]) == (95, 92, 88, 93, 154, 2441)
    assert res["partitions"] == {"Nos": 21, "Log": 85, "Coredump": 1}
    assert res["written"]["Nos"] == "722 MB"
    assert res["storage"][0]["worn_to"] == 90 and res["storage"][0]["health"] == "normal"
    assert [row["process"] for row in res["top"]] == ["atop", "ovsdb-server", "hpe-routing", "(sd-pam)"]


def test_the_four_resource_findings_each_have_a_threshold():
    result = _result("show system resource-utilization\n" + RESOURCES)
    codes = {item["code"]: item for item in result["health"]["findings"]}
    assert codes["SW-CX-017"]["severity"] == "high" and "atop 45%" in codes["SW-CX-017"]["text"]
    assert codes["SW-CX-018"]["severity"] == "high"                  # 93 % is above the 90 % line
    assert codes["SW-CX-019"]["severity"] == "medium" and "Log 85%" in codes["SW-CX-019"]["title"]
    assert codes["SW-CX-020"]["severity"] == "high" and "80-90%" in codes["SW-CX-020"]["title"]


def test_a_quiet_switch_has_the_tables_and_no_resource_finding():
    quiet = re.sub(r"(CPU usage\(%\)\s+:) 95", r"\1 5", RESOURCES)
    quiet = quiet.replace(": 92", ": 6").replace(": 88", ": 7").replace(": 93", ": 30").replace("80-90%", "0-10%")
    quiet = re.sub(r"(Log\s+:\s+)85", r"\g<1>3", quiet)
    result = _result("show system resource-utilization\n" + quiet)
    assert not [item for item in result["health"]["findings"] if item["code"] in ("SW-CX-017", "SW-CX-018", "SW-CX-019", "SW-CX-020")]
    assert {"cx-resources", "cx-processes"} <= {t["id"] for t in result["extra_tables"]}
    status = {row["command"]: row["status"] for row in result["coverage"]["rows"]}
    assert status["show system resource-utilization"] == "analyzed"


def test_the_extra_tables_reach_the_excel_workbook_as_one_long_sheet():
    from features.switch_analyzer.exporters.excel_exporter import SwitchExcelExporter
    workbook = SwitchExcelExporter([_result("show system resource-utilization\n" + RESOURCES + f"{PROMPT}# show module\n" + MODULES)]).build_workbook()
    sheet = workbook["Health Details"]
    rows = [[cell.value for cell in row] for row in sheet.iter_rows()]
    assert rows[0] == ["Hostname", "Table", "Row", "Column", "Value"]
    cells = {(r[1], r[3]): r[4] for r in rows[1:]}
    assert cells[("Modules", "Status")] in ("Active (local)", "Ready", "Standby", "Failed")
    assert any(r[1] == "Resource use" and r[3] == "Value" and "88%" in str(r[4]) for r in rows[1:])
