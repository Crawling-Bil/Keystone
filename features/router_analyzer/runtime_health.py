"""Device-health parsers for the Router Analyzer.

Every parser takes the output lines of one command and returns plain data
(dict / list); an empty result means "this is not the output I know" and the
caller treats the block as not understood.  The formats were written against
real captures of IOS-XE 17.x on C8200L / C8300 / ISR4331 / ISR4431 platforms
(``show tech-support`` and the individual commands); parsers whose layout was
only taken from Cisco documentation are listed in ``service.UNVALIDATED``.
"""

from __future__ import annotations

import re
from typing import Any

_PCT = r"(\d+(?:\.\d+)?)%"


def _int(text: str, default: int | None = None) -> int | None:
    try:
        return int(text.replace(",", ""))
    except (ValueError, AttributeError):
        return default


def _float(text: str, default: float | None = None) -> float | None:
    try:
        return float(text.rstrip("%"))
    except (ValueError, AttributeError):
        return default


# ---------------------------------------------------------------------------
# CPU
# ---------------------------------------------------------------------------

_CPU_HEAD = re.compile(
    r"CPU utilization for five seconds:\s*(\d+)%(?:/(\d+)%)?;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%", re.IGNORECASE
)
_CPU_ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%\s+(\d+)\s+(.+?)\s*$")


def parse_cpu_sorted(lines: list[str]) -> dict[str, Any]:
    """``show process cpu [sorted]``: the utilisation line plus the busiest processes."""
    text = "\n".join(lines)
    head = _CPU_HEAD.search(text)
    if not head:
        return {}
    five_sec, interrupt, one_min, five_min = head.groups()
    rows = []
    for line in lines:
        match = _CPU_ROW.match(line)
        if not match:
            continue
        pid, runtime, invoked, usecs, s5, m1, m5, tty, name = match.groups()
        rows.append({"pid": int(pid), "process": name, "runtime_ms": int(runtime), "invoked": int(invoked), "usecs": int(usecs),
                     "five_sec": float(s5), "one_min": float(m1), "five_min": float(m5)})
    rows.sort(key=lambda r: (-max(r["five_sec"], r["one_min"], r["five_min"]), -r["runtime_ms"]))
    return {
        "five_sec": int(five_sec), "interrupt": int(interrupt) if interrupt is not None else None,
        "one_min": int(one_min), "five_min": int(five_min), "processes": rows[:12], "process_count": len(rows),
    }


_HISTORY_TITLES = (
    ("second", re.compile(r"CPU% per second", re.I)),
    ("minute", re.compile(r"CPU% per minute", re.I)),
    ("hour", re.compile(r"CPU% per hour", re.I)),
)
_GRAPH_COLUMN0 = 6  # the first sample column of the ASCII graph


def parse_cpu_history(lines: list[str]) -> dict[str, Any]:
    """``show process cpu history``: peak CPU over the last 60 s / 60 min / 72 h.

    The graph prints the maximum of every sample as stacked digits above the
    ``100`` axis label (tens over ones); the digits are read back column by
    column.  Average values are only drawn as ``#`` marks, so only maxima
    are reported.
    """
    result: dict[str, Any] = {}
    axis_rows = [i for i, line in enumerate(lines) if re.match(r"^\s*100\s*$", line)]
    for axis in axis_rows:
        title = ""
        for forward in range(axis + 1, min(axis + 16, len(lines))):
            for key, pattern in _HISTORY_TITLES:
                if pattern.search(lines[forward]):
                    title = key
                    break
            if title:
                break
        if not title:
            continue
        digit_rows = []
        back = axis - 1
        while back >= 0 and lines[back].strip() and re.fullmatch(r"[\s0-9]+", lines[back]):
            digit_rows.insert(0, lines[back])
            back -= 1
            if len(digit_rows) == 3:
                break
        if not digit_rows:
            continue
        # the x axis ("0....5....1....") tells how many samples the graph holds
        columns = 0
        for forward in range(axis + 1, min(axis + 14, len(lines))):
            if re.match(r"^\s*0\.{4}5", lines[forward]):
                columns = len(lines[forward].rstrip()) - _GRAPH_COLUMN0
                break
        columns = columns or max(len(row) for row in digit_rows) - _GRAPH_COLUMN0
        values = []
        for column in range(_GRAPH_COLUMN0, _GRAPH_COLUMN0 + columns):
            digits = "".join(row[column] if column < len(row) and row[column].isdigit() else "" for row in digit_rows)
            values.append(int(digits) if digits else 0)
        if not values or not any(values):
            result[title] = {"peak": 0, "samples": columns, "mean_of_maxima": 0.0}
            continue
        result[title] = {"peak": max(values), "samples": len(values), "mean_of_maxima": round(sum(values) / len(values), 1)}
    return result


# ---------------------------------------------------------------------------
# Platform resources, control processor, memory
# ---------------------------------------------------------------------------

_RES_ROW = re.compile(
    r"^\s*(?P<name>\S.*?)\s{2,}(?P<usage>\S+)\s+(?P<max>\S+)\s+(?P<warning>\d+%)\s+(?P<critical>\d+%)\s+(?P<state>[HWC])\s*$"
)


def parse_platform_resources(lines: list[str]) -> list[dict[str, Any]]:
    """``show platform resources`` (IOS-XE): control processor, DRAM, flash, QFP."""
    rows = []
    section = ""
    for line in lines:
        if re.match(r"^(RP\d|ESP\d|SIP\d|\S+\d)\s*\(.*\)", line.strip()) or re.match(r"^(RP|ESP|SIP)\d", line.strip()):
            section = line.split("(")[0].strip().split()[0]
        match = _RES_ROW.match(line)
        if not match or match.group("name").startswith(("Resource", "-")):
            continue
        usage = match.group("usage")
        percent = re.search(r"\((\d+)%\)", usage) or re.match(r"(\d+(?:\.\d+)?)%", usage)
        rows.append({
            "scope": section, "resource": match.group("name").strip(), "usage": usage, "max": match.group("max"),
            "warning": match.group("warning"), "critical": match.group("critical"), "state": match.group("state"),
            "percent": float(percent.group(1)) if percent else None,
        })
    return rows


def parse_control_processor(lines: list[str]) -> dict[str, Any]:
    """``show platform software status control-processor brief``."""
    text = "\n".join(lines)
    if "Load Average" not in text and "Memory (kB)" not in text:
        return {}
    out: dict[str, Any] = {"load": [], "memory": [], "cpu": []}
    mode = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Load Average"):
            mode = "load"
        elif stripped.startswith("Memory (kB)"):
            mode = "memory"
        elif stripped.startswith("CPU Utilization"):
            mode = "cpu"
        elif mode == "load":
            m = re.match(r"^(\S+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)$", stripped)
            if m and m.group(1) != "Slot":
                out["load"].append({"slot": m.group(1), "status": m.group(2), "one": float(m.group(3)), "five": float(m.group(4)), "fifteen": float(m.group(5))})
        elif mode == "memory":
            m = re.match(r"^(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s*\((\d+)%\)\s+(\d+)\s*\((\d+)%\)\s+(\d+)\s*\((\d+)%\)", stripped)
            if m:
                out["memory"].append({"slot": m.group(1), "status": m.group(2), "total_kb": int(m.group(3)), "used_kb": int(m.group(4)), "used_pct": int(m.group(5)),
                                      "free_kb": int(m.group(6)), "free_pct": int(m.group(7)), "committed_pct": int(m.group(9))})
        elif mode == "cpu":
            m = re.match(r"^(?:(\S+)\s+)?(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)$", stripped)
            if m:
                out["cpu"].append({"slot": m.group(1) or "", "cpu": int(m.group(2)), "user": float(m.group(3)), "system": float(m.group(4)), "idle": float(m.group(6))})
    last_slot = ""
    for row in out["cpu"]:
        if row["slot"]:
            last_slot = row["slot"]
        else:
            row["slot"] = last_slot
    return out if out["load"] or out["memory"] or out["cpu"] else {}


_POOL_LINE = re.compile(r"^\s*(?P<name>[\w ]+?) Pool Total:\s*(?P<total>\d+)\s+Used:\s*(?P<used>\d+)\s+Free:\s*(?P<free>\d+)")
_PROC_MEM_ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$")


def parse_process_memory(lines: list[str]) -> dict[str, Any]:
    """``show process memory [sorted]``: pool totals and the biggest holders."""
    pools = []
    for line in lines:
        match = _POOL_LINE.match(line)
        if match:
            total, used, free = int(match.group("total")), int(match.group("used")), int(match.group("free"))
            pools.append({"pool": match.group("name").strip(), "total": total, "used": used, "free": free, "used_pct": round(used * 100 / total, 1) if total else 0.0})
    if not pools:
        return {}
    holders = []
    for line in lines:
        match = _PROC_MEM_ROW.match(line)
        if match:
            pid, tty, allocated, freed, holding, getbufs, retbufs, name = match.groups()
            holders.append({"pid": int(pid), "process": name, "holding": int(holding), "allocated": int(allocated), "freed": int(freed)})
    holders.sort(key=lambda r: -r["holding"])
    return {"pools": pools, "top": holders[:12], "process_count": len(holders)}


_MEMSTAT_ROW = re.compile(r"^\s*(?P<name>\S+(?: \S+)?)\s+(?P<head>[0-9A-Fa-f]{6,})\s+(?P<total>\d+)\s+(?P<used>\d+)\s+(?P<free>\d+)\s+(?P<lowest>\d+)\s+(?P<largest>\d+)")


def parse_memory_statistics(lines: list[str]) -> dict[str, Any]:
    """``show memory statistics`` (Processor pool: total, used, free, lowest free, largest block)."""
    pools = []
    for line in lines:
        match = _MEMSTAT_ROW.match(line)
        if match:
            total, used, free = int(match.group("total")), int(match.group("used")), int(match.group("free"))
            lowest, largest = int(match.group("lowest")), int(match.group("largest"))
            pools.append({"pool": match.group("name").strip(), "total": total, "used": used, "free": free, "lowest_free": lowest, "largest_block": largest,
                          "used_pct": round(used * 100 / total, 1) if total else 0.0, "lowest_free_pct": round(lowest * 100 / total, 1) if total else 0.0})
    return {"pools": pools} if pools else {}


# ---------------------------------------------------------------------------
# Environment, platform slots, redundancy, stacks
# ---------------------------------------------------------------------------

_ENV_ALARM = re.compile(r"Number of (Critical|Major|Minor) alarms:\s*(\d+)", re.I)
# show environment:   P0   Temp: Temp 1   Normal   38 Celsius  (na ,na ,48 ,na )(Celsius)
_ENV_A = re.compile(r"^\s*(?P<slot>[A-Z]?\d+(?:/\d+)?|[A-Z]\d)\s+(?P<sensor>(?:Temp|V|I|P|RPM|Fan|PS|Power)\w*:\s*.+?)\s{2,}(?P<state>[A-Za-z][\w /-]*?)\s+(?P<value>-?\d+(?:\.\d+)?)\s*(?P<unit>[A-Za-z%]+)\s*(?P<rest>.*)$")
# show environment all:   Temp: Temp 1   P0   Normal   38 Celsius
_ENV_B = re.compile(r"^\s*(?P<sensor>(?:Temp|V|I|P|RPM|Fan|PS|Power)\w*:\s*.+?)\s{2,}(?P<slot>[A-Z]?\d+(?:/\d+)?|[A-Z]\d)\s+(?P<state>[A-Za-z][\w /-]*?)\s+(?P<value>-?\d+(?:\.\d+)?)\s*(?P<unit>[A-Za-z%]+)\s*$")
_THRESHOLD = re.compile(r"\(([^)]*)\)")


_TEMP_STATE = {"GREEN": "Normal", "YELLOW": "Warning", "RED": "Critical"}
_STACK_FAN = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S.*?)\s*$")
_STACK_PS = re.compile(r"^\s*(?P<sw>\d+[A-Z])\s+(?P<pid>\S+)\s+(?P<serial>\S+)\s+(?P<status>\S.*?)\s{2,}(?P<sys>\S+)\s+(?P<poe>\S+)\s+(?P<watts>\d+|n/a)\s*$")
_STACK_IS = re.compile(r"^(?:Switch\s+(?P<sw>\d+):\s*)?(?P<what>(?:FAN\s+\S+|SYSTEM TEMPERATURE|[A-Z][A-Z ]+))\s+is\s+(?P<state>\S.*?)\s*$")
_STACK_TEMP = re.compile(r"^(?P<name>Inlet|Outlet|Hotspot)\s+Temperature Value:\s*(?P<value>-?\d+)\s+Degree Celsius", re.I)


def _stack_environment(lines: list[str]) -> list[dict[str, Any]]:
    """The layout of stackable Catalyst switches (and a Catalyst 9300 in IOS-XE routing mode): a fan table, ``Switch N: SYSTEM TEMPERATURE is OK``,
    a block per temperature sensor with its yellow and red thresholds, and a power-supply table.  A reading that is not a number stays None."""
    sensors: list[dict[str, Any]] = []
    mode = ""
    switch = ""
    temp: dict[str, Any] | None = None
    for raw in lines:
        text = raw.strip()
        if re.match(r"^Switch\s+FAN\s+Speed\s+State", text):
            mode = "fans"
            continue
        if re.match(r"^SW\s+PID\s+Serial#\s+Status\s+Sys Pwr", text):
            mode = "power"
            continue
        if not text or set(text) <= {"-", " "}:
            continue
        if mode == "fans":
            fan = _STACK_FAN.match(raw)
            if fan:
                sensors.append({"slot": fan.group(1), "sensor": f"Fan {fan.group(2)}", "state": fan.group(4), "value": float(fan.group(3)), "unit": "RPM", "critical": None})
                continue
            mode = ""
        if mode == "power":
            ps = _STACK_PS.match(raw)
            if ps:
                state = ps.group("status").strip()
                if ps.group("sys").lower() not in ("good", "n/a"):
                    state = f"{state}, system power {ps.group('sys')}"
                sensors.append({"slot": ps.group("sw"), "sensor": f"Power supply {ps.group('pid')}", "state": state, "value": float(ps.group("watts")) if ps.group("watts").isdigit() else None,
                                "unit": "W rated", "critical": None})
                continue
            mode = ""
        temperature = _STACK_TEMP.match(text)
        if temperature:
            temp = {"slot": switch, "sensor": f"{temperature.group('name').capitalize()} temperature", "state": "", "value": float(temperature.group("value")), "unit": "Celsius", "critical": None}
            sensors.append(temp)
            continue
        if temp is not None:
            state = re.match(r"^Temperature State:\s*(\S+)", text)
            red = re.match(r"^Red Threshold\s*:\s*(-?\d+)", text)
            yellow = re.match(r"^Yellow Threshold\s*:\s*(-?\d+)", text)
            if state:
                temp["state"] = _TEMP_STATE.get(state.group(1).upper(), state.group(1))
                continue
            if yellow:
                temp["warning"] = int(yellow.group(1))
                continue
            if red:
                temp["critical"] = int(red.group(1))
                temp = None
                continue
        entry = _STACK_IS.match(text)
        if entry:
            if entry.group("sw"):
                switch = entry.group("sw")
            what = entry.group("what")
            slot = switch if what == "SYSTEM TEMPERATURE" else what.split()[-1] if what.startswith("FAN ") else switch
            label = "System temperature" if what == "SYSTEM TEMPERATURE" else f"Power-supply fan {what.split()[-1]}" if what.startswith("FAN ") else what.capitalize()
            sensors.append({"slot": slot, "sensor": label, "state": entry.group("state"), "value": None, "unit": "", "critical": None})
    return sensors


def parse_environment(lines: list[str]) -> dict[str, Any]:
    """``show environment [all]``: alarm counters and every sensor with its state."""
    alarms = {name.lower(): int(count) for name, count in _ENV_ALARM.findall("\n".join(lines))}
    sensors = []
    for raw in lines:
        line = raw.replace("\t", "  ")
        match = _ENV_A.match(line) or _ENV_B.match(line)
        if not match:
            continue
        info = match.groupdict()
        critical = None
        rest = info.get("rest") or ""
        thresholds = _THRESHOLD.search(rest)
        if thresholds:
            parts = [p.strip() for p in thresholds.group(1).split(",")]
            if len(parts) >= 3 and re.fullmatch(r"-?\d+", parts[2]):
                critical = int(parts[2])
        sensors.append({
            "slot": info["slot"], "sensor": re.sub(r"\s+", " ", info["sensor"]).strip(), "state": info["state"].strip(),
            "value": float(info["value"]), "unit": info["unit"], "critical": critical,
        })
    if not sensors:
        sensors = _stack_environment(lines)
    if not sensors and not alarms:
        return {}
    return {"alarms": alarms, "sensors": sensors}


def parse_platform(lines: list[str]) -> dict[str, Any]:
    """``show platform``: chassis type, slot table and CPLD/firmware table."""
    text = "\n".join(lines)
    chassis = re.search(r"Chassis type:\s*(\S+)", text)
    slots = []
    firmware = []
    mode = ""
    for line in lines:
        if re.match(r"^Slot\s+Type\s+State", line):
            mode = "slots"
            continue
        if re.match(r"^Slot\s+CPLD Version", line):
            mode = "firmware"
            continue
        if line.startswith("---") or not line.strip():
            continue
        if mode == "slots":
            m = re.match(r"^\s*(\S+)\s+(\S+)\s+(ok(?:, \w+)?|\S+(?:, \w+)?)\s+(\S+)\s*$", line)
            if m:
                slots.append({"slot": m.group(1), "type": m.group(2), "state": m.group(3), "uptime": m.group(4)})
        elif mode == "firmware":
            m = re.match(r"^\s*(\S+)\s+(\S+)\s+(\S+)\s*$", line)
            if m:
                firmware.append({"slot": m.group(1), "cpld": m.group(2), "firmware": m.group(3)})
    if not slots and not chassis:
        stack = _stack_platform(lines)
        if stack:
            return {"chassis": stack[0]["type"], "slots": stack, "firmware": [], "stack": True}
        return {}
    return {"chassis": chassis.group(1) if chassis else "", "slots": slots, "firmware": firmware}


_STACK_MEMBER = re.compile(r"^\s*(?P<switch>\d+)\s+(?P<ports>\d+)\s+(?P<model>\S+)\s+(?P<serial>\S+)\s+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(?P<hw>\S+)\s+(?P<sw>\S+)\s*$")
_STACK_ROLE = re.compile(r"^\s*\*?(?P<switch>\d+)\s+(?P<role>Active|Standby|Member)\s+(?P<priority>\d+)\s+(?P<state>\S.*?)\s*$")


def _stack_platform(lines: list[str]) -> list[dict[str, Any]]:
    """``show platform`` of a stackable Catalyst: the member table (model, ports, hardware and software version) and the role table.  The serial number and MAC address are not kept."""
    members: dict[str, dict[str, Any]] = {}
    for line in lines:
        member = _STACK_MEMBER.match(line)
        if member:
            members[member.group("switch")] = {"slot": member.group("switch"), "type": member.group("model"), "state": "", "uptime": "", "ports": int(member.group("ports")), "hw": member.group("hw"),
                                               "sw": member.group("sw"), "role": "", "priority": ""}
            continue
        role = _STACK_ROLE.match(line)
        if role and role.group("switch") in members:
            entry = members[role.group("switch")]
            entry.update(role=role.group("role"), priority=role.group("priority"), state=f"{role.group('role')}, {role.group('state')}")
    return list(members.values())


def parse_redundancy_states(lines: list[str]) -> dict[str, Any]:
    text = "\n".join(lines)
    out: dict[str, Any] = {}
    for key, pattern in (
        ("my_state", r"my state\s*=\s*(.+)"), ("peer_state", r"peer state\s*=\s*(.+)"), ("mode", r"^\s*Mode\s*=\s*(.+)$"), ("unit", r"^\s*Unit\s*=\s*(.+)$"),
        ("operational_mode", r"Redundancy Mode \(Operational\)\s*=\s*(.+)"), ("configured_mode", r"Redundancy Mode \(Configured\)\s*=\s*(.+)"),
        ("redundancy_state", r"Redundancy State\s*=\s*(.+)"), ("communications", r"Communications\s*=\s*(.+)"),
    ):
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            out[key] = re.sub(r"\s+", " ", match.group(1)).strip()
    return out


def parse_redundancy_history(lines: list[str]) -> dict[str, Any]:
    """``show redundancy history``: only switch-over events are of interest."""
    events = [line.strip() for line in lines if re.search(r"switchover|swact|fail ?over", line, re.I)]
    if not lines:
        return {}
    return {"lines": len(lines), "switchover_events": events[:10], "switchovers": len(events)}


_STACK_ROW = re.compile(r"^\s*(\d+)/(\d+)\s+(\S.*?)\s*$")


def parse_stacks(lines: list[str]) -> dict[str, Any]:
    """``show stacks``: the minimum free space of every process stack."""
    rows = []
    for line in lines:
        match = _STACK_ROW.match(line)
        if match:
            free, size, name = int(match.group(1)), int(match.group(2)), match.group(3)
            if size:
                rows.append({"process": name, "free": free, "size": size, "free_pct": round(free * 100 / size, 1)})
    text = "\n".join(lines)
    crash = bool(re.search(r"Stack trace|Exception to IOS Thread|Unexpected exception|crashed|traceback", text, re.I))
    if not rows and not crash:
        return {}
    rows.sort(key=lambda r: r["free_pct"])
    return {"lowest": rows[:8], "processes": len(rows), "crash_mentioned": crash}


# ---------------------------------------------------------------------------
# File systems and flash contents
# ---------------------------------------------------------------------------

_FS_ROW = re.compile(r"^\s*(?P<current>\*)?\s*(?P<size>\d+|-)\s+(?P<free>\d+|-)\s+(?P<type>\S+)\s+(?P<flags>\S+)\s+(?P<prefixes>.+?)\s*$")


def parse_file_systems(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        match = _FS_ROW.match(line)
        if not match or match.group("size") == "-" or "Prefixes" in line:
            continue
        size, free = int(match.group("size")), int(match.group("free"))
        rows.append({
            "prefixes": match.group("prefixes").split(), "type": match.group("type"), "flags": match.group("flags"), "size": size, "free": free,
            "free_pct": round(free * 100 / size, 1) if size else 0.0, "current": bool(match.group("current")),
        })
    return rows


_FLASH_ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\w{3} \d{2} \d{4}) (\d{2}:\d{2}:\d{2})\S*\s+\S+\s+(\S.*?)\s*$")
_FLASH_FREE = re.compile(r"(\d+) bytes available \((\d+) bytes used\)")


def parse_flash_listing(lines: list[str]) -> dict[str, Any]:
    """``show bootflash:`` / ``dir bootflash:``: images, packages, crash and core files."""
    files = []
    for line in lines:
        match = _FLASH_ROW.match(line)
        if match:
            files.append({"size": int(match.group(2)), "date": f"{match.group(3)} {match.group(4)}", "path": match.group(5)})
    if not files:
        return {}
    free = _FLASH_FREE.search("\n".join(lines))
    images = [f for f in files if re.search(r"\.bin$", f["path"], re.I) and "/" in f["path"].strip("/") and f["path"].count("/") <= 2 and f["size"] > 50_000_000]
    packages = [f for f in files if re.search(r"\.pkg$", f["path"], re.I)]
    cores = [f for f in files if re.search(r"/core/[^/]+\.(?:core|gz|tar)|\.core(?:\.gz)?$|/crashinfo", f["path"], re.I) and f["size"] > 1000]
    versions = sorted({m.group(1) for f in packages if (m := re.search(r"\.(\d{2}\.\d{2}\.\d{2}[a-z]?)\.SPA", f["path"]))})
    return {
        "files": len(files), "images": [{"path": f["path"], "size": f["size"], "date": f["date"]} for f in images], "package_versions": versions,
        "packages": len(packages), "cores": [{"path": f["path"], "size": f["size"], "date": f["date"]} for f in cores[:10]],
        "available": int(free.group(1)) if free else None, "used": int(free.group(2)) if free else None,
        "tracelogs_bytes": sum(f["size"] for f in files if "/tracelogs/" in f["path"]),
    }


# ---------------------------------------------------------------------------
# Licensing
# ---------------------------------------------------------------------------

_LICENSE_SUMMARY_ROW = re.compile(r"^\s*(?P<name>\S.*?)\s+\((?P<tag>[^)]+)\)\s+(?P<count>\d+)\s+(?P<status>[A-Z][A-Z ]+?)\s*$")


def parse_license_summary(lines: list[str]) -> dict[str, Any]:
    text = "\n".join(lines)
    if "License Usage" not in text and "Account Information" not in text:
        return {}
    out: dict[str, Any] = {"licenses": []}
    for key, label in (("smart_account", "Smart Account"), ("virtual_account", "Virtual Account")):
        match = re.search(rf"{label}:\s*(.+)", text)
        if match:
            out[key] = match.group(1).strip()
    for line in lines:
        match = _LICENSE_SUMMARY_ROW.match(line)
        if match:
            out["licenses"].append({"license": match.group("name").strip(), "tag": match.group("tag"), "count": int(match.group("count")), "status": match.group("status").strip()})
    status = re.search(r"Status:\s*(.+)", text)
    if status:
        out["registration"] = status.group(1).strip()
    return out


def parse_license_usage(lines: list[str]) -> dict[str, Any]:
    text = "\n".join(lines)
    if "License Authorization" not in text and "Status:" not in text:
        return {}
    blocks = []
    current: dict[str, Any] | None = None
    for line in lines:
        head = re.match(r"^(\S.*?)\s+\(([^)]+)\):\s*$", line)
        if head:
            current = {"name": head.group(1).strip(), "tag": head.group(2)}
            blocks.append(current)
            continue
        if current is not None:
            kv = re.match(r"^\s+([A-Za-z ]+?):\s*(.*)$", line)
            if kv:
                current[kv.group(1).strip().lower().replace(" ", "_")] = kv.group(2).strip()
    authorization = re.search(r"License Authorization:\s*\n\s*Status:\s*(.+)", text)
    return {"authorization": authorization.group(1).strip() if authorization else "", "licenses": blocks}


_STORE_HEAD = re.compile(r"^StoreIndex:\s*(\d+)\s+Feature:\s*(\S+)\s+Version:\s*(\S+)")
_EVAL_LEFT = re.compile(r"Evaluation period left:\s*(.+?)\s*$")


def parse_license_store(lines: list[str]) -> list[dict[str, Any]]:
    """Classic (right-to-use) licensing, ``show license all``: one row per feature in each ``License Store``."""
    rows: list[dict[str, Any]] = []
    store = ""
    cur: dict[str, Any] | None = None
    for line in lines:
        text = line.strip()
        if text.startswith("License Store:"):
            store = text.split(":", 1)[1].strip()
            cur = None
            continue
        head = _STORE_HEAD.match(text)
        if head:
            cur = {"store": store, "feature": head.group(2), "version": head.group(3), "type": "", "state": "", "count": "", "priority": "", "eval_left": ""}
            rows.append(cur)
            continue
        if cur is None:
            continue
        for key, label in (("type", "License Type:"), ("state", "License State:"), ("count", "License Count:"), ("priority", "License Priority:")):
            if text.startswith(label):
                cur[key] = text.split(":", 1)[1].strip()
        left = _EVAL_LEFT.match(text)
        if left:
            cur["eval_left"] = re.sub(r"\s+", " ", left.group(1))
    return rows


def parse_license_all(lines: list[str]) -> dict[str, Any]:
    """``show license all`` / ``show license status``: Smart Licensing (using policy) fields and, on classic licensing, the licence stores."""
    text = "\n".join(lines)
    out: dict[str, Any] = {}
    if "Smart Licensing" in text:
        for key, pattern in (
            ("smart_licensing", r"Smart Licensing is (\w+)"), ("using_policy", r"Smart Licensing Using Policy:\s*\n\s*Status:\s*(\w+)"),
            ("transport", r"Transport:\s*\n\s*Type:\s*(.+)"), ("cslu_address", r"Cslu address:\s*(\S+)"), ("policy", r"Policy in use:\s*(.+)"),
            ("last_ack", r"Last ACK received:\s*(.+)"), ("next_ack_deadline", r"Next ACK deadline:\s*(.+)"), ("next_report_push", r"Next report push:\s*(.+)"),
            ("last_report_push", r"Last report push:\s*(.+)"), ("udi", r"UDI:\s*(.+)"), ("agent", r"Smart Agent for Licensing:\s*(\S+)"),
        ):
            match = re.search(pattern, text)
            if match:
                out[key] = match.group(1).strip()
    store = parse_license_store(lines) if "License Store:" in text else []
    if store:
        out["store"] = store
    return out


def parse_license_status(lines: list[str]) -> dict[str, Any]:
    """``show license status``: the same Smart Licensing fields as ``show license all``; classic licensing prints only capabilities and the device credential."""
    out = parse_license_all(lines)
    text = "\n".join(lines)
    credential = re.search(r"Device Credential Verification:\s*(\S+)", text)
    if credential and not out:
        out["device_credential"] = credential.group(1)
    if out:
        out["command"] = "show license status"
    return out


# ---------------------------------------------------------------------------
# Neighbours, sessions, bundles
# ---------------------------------------------------------------------------


def parse_cdp_neighbors(lines: list[str]) -> list[dict[str, Any]]:
    """``show cdp neighbors`` (brief): device, local interface, hold time, capability, platform, port."""
    rows = []
    started = False
    pending = ""
    for line in lines:
        if line.startswith("Device ID"):
            started = True
            continue
        if not started or not line.strip() or line.startswith("Total cdp entries"):
            continue
        if not line.startswith(" ") and not re.search(r"\s{2,}", line.strip()):
            pending = line.strip()
            continue
        text = (pending + " " + line.strip()) if pending and line.startswith(" ") else line.strip()
        match = re.match(r"^(?P<device>\S+)?\s*(?P<local>(?:Gig|Ten|Fas|Eth|Fo|Hu|Twe|Tw|Se|Lo|Po|Gi|Te)\w*\s?\S*)\s+(?P<hold>\d+)\s+(?P<cap>(?:[RTBSHIDCMrP] ?)+?)\s+(?P<platform>\S+)\s+(?P<port>\S+(?: \S+)?)$", text)
        if match:
            rows.append({"device": (match.group("device") or pending).strip(), "local": match.group("local").strip(), "hold": int(match.group("hold")),
                         "capability": match.group("cap").strip(), "platform": match.group("platform"), "port": match.group("port")})
        pending = ""
    return rows


def parse_cdp_detail(lines: list[str]) -> list[dict[str, Any]]:
    """``show cdp neighbors detail``: device, address, platform, interface, port, version/duplex."""
    entries = []
    current: dict[str, Any] | None = None
    for line in lines:
        if line.startswith("Device ID:"):
            current = {"device": line.split(":", 1)[1].strip(), "address": "", "platform": "", "interface": "", "port": "", "duplex": "", "native_vlan": ""}
            entries.append(current)
            continue
        if current is None:
            continue
        if re.match(r"^\s+IP(?:v4)? [Aa]ddress:", line) and not current["address"]:
            current["address"] = line.split(":", 1)[1].strip()
        match = re.match(r"^Platform:\s*(.+?),\s*Capabilities:\s*(.*)$", line)
        if match:
            current["platform"], current["capabilities"] = match.group(1).strip(), match.group(2).strip()
        match = re.match(r"^Interface:\s*(.+?),\s*Port ID \(outgoing port\):\s*(.+)$", line)
        if match:
            current["interface"], current["port"] = match.group(1).strip(), match.group(2).strip()
        match = re.match(r"^Duplex:\s*(\S+)", line)
        if match:
            current["duplex"] = match.group(1)
        match = re.match(r"^Native VLAN:\s*(\S+)", line)
        if match:
            current["native_vlan"] = match.group(1)
    return entries


def parse_show_user(lines: list[str]) -> list[dict[str, Any]]:
    """``show users``: one row per terminal line session (the ``*`` marks the current one)."""
    rows = []
    for line in lines:
        match = re.match(r"^(?P<me>\*)?\s*(?P<line>\d+\s+\w+\s+\d+)\s+(?P<user>\S+)\s+(?P<host>\S+)\s+(?P<idle>[\d:]+)\s*(?P<location>\S*)\s*$", line)
        if match:
            rows.append({"line": re.sub(r"\s+", " ", match.group("line")), "user": match.group("user"), "idle": match.group("idle"), "location": match.group("location"),
                         "current": bool(match.group("me"))})
    return rows


def parse_etherchannel_summary(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        match = re.match(r"^\s*(\d+)\s+(Po\d+\(\w+\))\s*(.*)$", line.replace("\t", "  "))
        if match:
            rest = match.group(3).strip()
            protocol = "-"
            first = rest.split()[0] if rest else ""
            if first and not re.search(r"\(\w+\)$", first):  # LACP / PAgP / NONE / '-' precede the member ports
                protocol, rest = first, rest[len(first):].strip()
            ports = re.findall(r"(\S+?)\((\w+)\)", rest)
            rows.append({"group": int(match.group(1)), "port_channel": match.group(2), "protocol": protocol, "ports": [{"port": p, "flag": f} for p, f in ports]})
    return rows


# ---------------------------------------------------------------------------
# QFP (forwarding plane of ASR1000 / ISR4000 / Catalyst 8000)
# ---------------------------------------------------------------------------

_QFP_WINDOWS = ("5 secs", "1 min", "5 min", "60 min")


def _four(line: str) -> list[int] | None:
    numbers = re.findall(r"(?<![\w.])(\d+)(?![\w.])", line.split(")", 1)[-1])
    return [int(n) for n in numbers[-4:]] if len(numbers) >= 4 else None


def parse_qfp_utilization(lines: list[str]) -> dict[str, Any]:
    """``show platform hardware qfp active datapath utilization [summary]``.

    Every row has four columns (5 seconds, 1 minute, 5 minutes, 60 minutes).
    ``processing`` is the load of the packet-processing engine, the number
    that says how close the forwarding plane is to its capacity.
    """
    head = next((line.strip() for line in lines if re.match(r"^\s*CPP \d+", line)), "")
    if not head:
        return {}
    out: dict[str, Any] = {"engine": head.split("5 secs")[0].strip().rstrip(":"), "windows": list(_QFP_WINDOWS)}
    direction = ""
    rows: dict[str, list[int]] = {}
    previous = ""
    for line in lines:
        text = line.strip()
        if text.startswith("Input:"):
            direction = "input"
        elif text.startswith("Output:"):
            direction = "output"
        elif text.startswith("Processing:"):
            direction = "processing"
        elif text.startswith("Crypto/IO"):
            direction = "crypto_io"
        values = _four(line) if "(pps)" in line or "(bps)" in line or "(pct)" in line else None
        if values is None:
            continue
        if "Total (pps)" in text:
            rows[f"{direction}_pps"] = values
        elif text.startswith("(bps)") and previous == "total_pps":
            rows[f"{direction}_bps"] = values
        elif "Processing: Load (pct)" in text:
            rows["processing"] = values
        elif direction == "crypto_io":
            label = text.split(":")[0].split("(")[0].strip().lower() if ":" in text else text.split("(")[0].strip().lower()
            rows[f"crypto_io_{label.replace(' ', '_')}"] = values
        previous = "total_pps" if "Total (pps)" in text else ""
    if "processing" not in rows:
        return {}
    out.update({key: rows[key] for key in rows})
    out["processing_5min"] = rows["processing"][2]
    out["processing_peak"] = max(rows["processing"])
    return out


def parse_qfp_drops(lines: list[str]) -> dict[str, Any]:
    """``show platform hardware qfp active statistics drop``: global drop counters."""
    rows = []
    cleared = ""
    for line in lines:
        match = re.match(r"^Last clearing of QFP drops statistics\s*:\s*(.+?)\s*$", line)
        if match:
            cleared = match.group(1)
            continue
        match = re.match(r"^(?P<name>[A-Za-z][\w.]*)\s+(?P<packets>\d+)\s+(?P<octets>\d+)\s*$", line)
        if match:
            rows.append({"counter": match.group("name"), "packets": int(match.group("packets")), "octets": int(match.group("octets"))})
    if not rows and "Global Drop Stats" not in "\n".join(lines):
        return {}
    rows.sort(key=lambda r: (-r["packets"], r["counter"]))
    return {"cleared": cleared, "rows": rows, "total_packets": sum(r["packets"] for r in rows)}


def parse_qfp_exmem(lines: list[str]) -> dict[str, Any]:
    """``show platform hardware qfp active infrastructure exmem statistics``: QFP DRAM / IRAM."""
    memories = []
    current: dict[str, Any] | None = None
    for line in lines:
        match = re.match(r"^Type:\s*Name:\s*(\w+),\s*QFP:\s*(\d+)", line)
        if match:
            current = {"type": match.group(1), "qfp": int(match.group(2))}
            memories.append(current)
            continue
        match = re.match(r"^\s*(Total|InUse|Free|Lowest free water mark):\s*(\d+)\s*$", line)
        if match and current is not None:
            key = {"Total": "total", "InUse": "used", "Free": "free", "Lowest free water mark": "lowest_free"}[match.group(1)]
            current[key] = int(match.group(2))
    memories = [m for m in memories if m.get("total")]
    for memory in memories:
        memory["used_pct"] = round(100 * memory.get("used", 0) / memory["total"], 1)
        memory["lowest_free_pct"] = round(100 * memory.get("lowest_free", 0) / memory["total"], 1)
    return {"memories": memories} if memories else {}
