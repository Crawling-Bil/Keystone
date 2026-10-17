"""FortiSwitch (FortiSwitchOS) capture: ``diagnose debug report``, MCLAG / trunk / STP diagnostics and ``show``.

A FortiSwitch is managed from its FortiGate (FortiLink) and most engineers reach it by SSH-ing from the FortiGate CLI -- the
capture therefore often begins with the FortiGate prompt (``config vdom`` / ``edit OOB`` / ``exec ssh admin@<switch>``) and only
then switches to the switch prompt.  The switch's own CLI uses FortiOS syntax, so a naive reader takes the ``show`` output for a
FortiGate configuration; :func:`looks_like_fortiswitch` is checked first for that reason.

What the module reads (``### <command>`` headings of ``diagnose debug report`` are treated as if the command had been typed):

    get system status / performance status      diagnose sys ntp status          diagnose sys fan|pcb|psu status
    diagnose sys flash list                     diagnose switch physical-ports summary|list
    get switch lldp neighbors-summary           diagnose switch trunk summary|list
    diagnose switch mclag icl|list|peer-consistency-check                        diagnose stp instance list
    get switch modules summary                  diagnose switch vlan list        diagnose switch mac-address list
    execute log display                         show   (full switch configuration, parsed with the FortiOS tree parser)

Secrets never reach the result: the FortiOS tree parser hides passwords and keys at parse time, and the crash log / SSH password
prompts that sometimes sit in the capture are never read.

Reference: https://docs.fortinet.com/document/fortiswitch/7.2.10/administration-guide/860027/mclag
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import date, datetime
from typing import Any

from ..analyzer_core.findings import finding, severity_counts, sort_findings
from ..analyzer_core.result import card, info_rows, kv_section, new_result, table_section
from ..analyzer_core.terminal import render
from .forti_tree import FNode, parse_forti
from .refs import FORTISWITCH as REF

_MARKERS = re.compile(
    r"FortiSwitch-\w+\s+v\d|^config switch (?:physical-port|trunk|interface|global|stp)\b|^\s*#{0,3}\s*(?:diag(?:nose)?|get) switch (?:trunk|mclag|physical-ports|lldp|stp|interface)\b|"
    r"^config switch-controller (?:fortilink-settings|managed-switch)\b(?!.*FortiGate)", re.M)
_PROMPT = re.compile(r"^(?P<host>[A-Za-z0-9][A-Za-z0-9_.\-]*)(?:\s+\((?P<mode>[^)]*)\))?\s*(?P<char>[#$])\s?(?P<cmd>.*)$")
_ABBREV = {"diag": "diagnose", "exe": "execute", "exec": "execute", "sh": "show", "conf": "config"}


def looks_like_fortiswitch(text: str) -> bool:
    sample = text[:3_000_000]
    hits = {match.group(0).strip().lower()[:40] for match in _MARKERS.finditer(sample)}
    return len(hits) >= 2 or bool(re.search(r"FortiSwitch-\w+\s+v\d", sample))


# ------------------------------------------------------------------------------------------------ helpers
def _norm(command: str) -> str:
    words = command.strip().lower().split()
    if words:
        words[0] = _ABBREV.get(words[0], words[0])
    return " ".join(words)


def _seconds(text: str) -> int | None:
    """'6 days,0 hours,4 mins,22 secs' / '6 days  0h: 5m: 0s' / '5d 20h 17m 42s' -> seconds."""
    total, found = 0, False
    for amount, unit in re.findall(r"(\d+)\s*(day|d|hour|h|min|m|sec|s)\w*", text or ""):
        found = True
        total += int(amount) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit[0] if unit != "day" else "d"]
    return total if found else None


def _human(seconds: int | None) -> str:
    if seconds is None:
        return ""
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    return (f"{days}d " if days else "") + f"{hours}h {minutes}m"


def _kv(lines: list[str], sep: str = ":") -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        if sep in line:
            key, value = line.split(sep, 1)
            if key.strip() and not key.startswith(("-", "_")):
                out.setdefault(key.strip(), value.strip())
    return out


def _spaced_kv(lines: list[str]) -> dict[str, str]:
    """``    icl-ports            47-48`` (two or more spaces between key and value)."""
    out: dict[str, str] = {}
    for line in lines:
        match = re.match(r"^\s+([A-Za-z][\w\- ]*?)\s{2,}(\S.*)$", line)
        if match:
            out.setdefault(match.group(1).strip(), match.group(2).strip())
    return out


# ------------------------------------------------------------------------------------------------ gathering
def _blocks(rendered: str) -> tuple[dict[str, list[str]], str, list[str]]:
    """(command -> output lines, switch hostname, hosts seen before it).  A command run twice keeps its longest output."""
    outputs: dict[str, list[str]] = {}
    current: str | None = None
    buffer: list[str] = []
    hosts: Counter[str] = Counter()
    first_host_order: list[str] = []
    marks: list[tuple[str, str, list[str]]] = []                  # (host, command, lines)
    host_of_current = ""

    def flush() -> None:
        if current is not None:
            marks.append((host_of_current, current, buffer[:]))

    for line in rendered.split("\n"):
        heading = re.match(r"^###\s+(.+?)\s*$", line)
        prompt = _PROMPT.match(line) if not line.startswith((" ", "\t")) else None
        if prompt and prompt.group("cmd").strip() and prompt.group("host") not in ("http", "https"):
            flush()
            current, buffer = _norm(prompt.group("cmd")), []
            host_of_current = prompt.group("host")
            hosts[host_of_current] += 1
            if host_of_current not in first_host_order:
                first_host_order.append(host_of_current)
        elif heading:
            flush()
            current, buffer = _norm(heading.group(1)), []
        elif current is not None:
            buffer.append(line)
    flush()

    def is_switch_command(command: str) -> bool:
        return bool(re.match(r"^(diagnose (switch|stp|sys|debug)|get (switch|system status|hardware)|execute (switch|log|router))", command))

    per_host: Counter[str] = Counter(host for host, command, _ in marks if host and is_switch_command(command))
    switch_host = per_host.most_common(1)[0][0] if per_host else (hosts.most_common(1)[0][0] if hosts else "")
    for host, command, lines in marks:
        if host and host != switch_host and not command.startswith("###"):
            # commands typed on the FortiGate before the SSH hop (config vdom, edit OOB, exec ssh ...)
            continue
        text = [line.rstrip() for line in lines]
        while text and not text[0].strip():
            text.pop(0)
        while text and not text[-1].strip():
            text.pop()
        if not text or re.match(r"^(command parse error|Command fail|Unknown action|Invalid)", text[0]):
            continue
        if command not in outputs or len(text) >= len(outputs[command]):
            outputs[command] = text
    via = [h for h in first_host_order if h != switch_host]
    return outputs, switch_host, via


def _parse_status(lines: list[str]) -> dict[str, str]:
    info = _kv(lines)
    version = re.search(r"FortiSwitch-(\w+)\s+v(\d+\.\d+\.\d+),build(\d+),(\d{6})", info.get("Version", ""))
    if version:
        info["_model"], info["_version"], info["_build"], info["_built"] = f"FortiSwitch-{version.group(1)}", version.group(2), version.group(3), version.group(4)
    return info


def _parse_performance(lines: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for line in lines:
        cpu = re.match(r"^CPU states:\s*(\d+)% user\s+(\d+)% system\s+(\d+)% nice\s+(\d+)% idle", line)
        if cpu:
            out.update(cpu_user=int(cpu.group(1)), cpu_system=int(cpu.group(2)), cpu_idle=int(cpu.group(4)))
        mem = re.match(r"^Memory states:\s*(\d+)% used", line)
        if mem:
            out["mem_used"] = int(mem.group(1))
        up = re.match(r"^Uptime:\s*(.+)$", line)
        if up:
            out["uptime"], out["uptime_s"] = up.group(1).strip(), _seconds(up.group(1))
    return out


def _parse_module_table(lines: list[str]) -> list[dict[str, str]]:
    return [{"module": m.group(1), "status": m.group(2).strip()} for line in lines if (m := re.match(r"^(FAN\d+|PSU\d+|Sensor\d+|\S+)\s{2,}(\S.*)$", line.strip())) and not line.startswith(("Module", "_"))]


def _parse_flash(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        match = re.match(r"^(\(\*\)\s+)?(\d)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(Yes|No)\s*$", line.strip())
        if match:
            image = match.group(3)
            version = re.search(r"-(\d+\.\d+\.\d+)-", image)
            rows.append({"partition": match.group(2), "image": image, "version": version.group(1) if version else "", "used_pct": int(match.group(6)), "active": match.group(7) == "Yes", "next_boot": bool(match.group(1))})
    return rows


def _parse_ntp(lines: list[str]) -> dict[str, Any]:
    text = "\n".join(lines)
    out: dict[str, Any] = {"synchronized": bool(re.search(r"synchronized:\s*yes", text, re.I))}
    server = re.search(r"ipv[46] server\(([^)]+)\).*?(selected|reachable|unreachable)", text)
    if server:
        out["server"], out["state"] = server.group(1), server.group(2)
    for key, pattern in (("stratum", r"stratum=(\d+)"), ("offset", r"clock offset is ([-\d.]+) sec")):
        match = re.search(pattern, text)
        if match:
            out[key] = match.group(1)
    return out


def _parse_ports(summary: list[str], listing: list[str]) -> list[dict[str, Any]]:
    ports: dict[str, dict[str, Any]] = {}
    for line in summary:
        match = re.match(r"^\s*(\S+)\s+(up|down)\s+([0-9a-f]{4})\s+(\d+)\s+(full|half)\s+(\S+)\s+(\S.*?)\s+(\S+)\s*$", line)
        if match:
            ports[match.group(1)] = {"name": match.group(1), "link": match.group(2), "pvid": int(match.group(4)), "duplex": match.group(5), "speed": match.group(6), "flags": match.group(7).replace(" ", ""), "discard": match.group(8)}
    current: dict[str, Any] | None = None
    for line in listing:
        head = re.match(r"^Port\((\S+)\) is HW Admin (\w+), SW Admin (\w+), line protocol is (\w+)", line)
        if head:
            current = ports.setdefault(head.group(1), {"name": head.group(1)})
            current.update(hw_admin=head.group(2), sw_admin=head.group(3))
            continue
        if current is None:
            continue
        rx = re.match(r"^input\s*:\s*(\d+) bytes, (\d+) packets, (\d+) errors, (\d+) drops", line)
        if rx:
            current.update(in_packets=int(rx.group(2)), in_errors=int(rx.group(3)), in_drops=int(rx.group(4)))
        tx = re.match(r"^output\s*:\s*(\d+) bytes, (\d+) packets, (\d+) errors, (\d+) drops", line)
        if tx:
            current.update(out_packets=int(tx.group(2)), out_errors=int(tx.group(3)), out_drops=int(tx.group(4)))
        extra = re.match(r"^(\d+) fragments, (\d+) undersizes, (\d+) collisions, (\d+) jabbers", line)
        if extra:
            current.update(collisions=int(extra.group(3)), jabbers=int(extra.group(4)))
    return list(ports.values())


def _parse_lldp(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        match = re.match(r"^\s*(port\d+|internal|\S+)\s+(Up|Down)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", line)
        if match and match.group(2) in ("Up", "Down"):
            rows.append({"port": match.group(1), "status": match.group(2), "device": match.group(3), "capability": match.group(5), "remote_port": match.group(7)})
    return rows


def _join_wrapped(lines: list[str], row: re.Pattern[str]) -> list[str]:
    """The terminal hard-wraps long rows at its width, in the middle of a word ('...58 mins,5' / '0 secs'); a line that is not itself
    a row start and follows a row is the tail of that row and is appended without a separator."""
    out: list[str] = []
    for line in lines:
        if out and line.strip() and not row.match(line) and not line.startswith(("_", "-")) and row.match(out[-1]):
            out[-1] = out[-1].rstrip("\n") + line.strip()
        else:
            out.append(line)
    return out


_TRUNK_ROW = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+(\S+)\s+(\S.*)$")


def _parse_trunk_summary(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in _join_wrapped(lines, _TRUNK_ROW):
        match = _TRUNK_ROW.match(line)
        if match:
            status = re.match(r"^(up|down)\((\d+)/(\d+)\)", match.group(5))
            rows.append({"name": match.group(1), "mode": match.group(2), "psc": match.group(3), "mac": match.group(4), "state": status.group(1) if status else match.group(5), "active": int(status.group(2)) if status else None,
                         "total": int(status.group(3)) if status else None, "uptime_s": _seconds(match.group(6)), "uptime": match.group(6).replace(",", " ")})
    return rows


def _parse_trunk_list(lines: list[str]) -> dict[str, dict[str, Any]]:
    trunks: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    slave: dict[str, str] | None = None
    section = ""
    for line in lines:
        text = line.strip()
        name = re.match(r"^Trunk Name:\s+(\S+)", text)
        if name:
            current = trunks.setdefault(name.group(1), {"members": [], "inactive": [], "slaves": []})
            slave, section = None, ""
            continue
        if current is None:
            continue
        if text.startswith("Mode:"):
            current["mode"] = text.split(":", 1)[1].strip()
        elif text.startswith("Active Port"):
            section = "active"
        elif text.startswith("Non-Active Port"):
            section = "inactive"
        elif text.startswith("partner MAC address"):
            current["partner_mac"] = text.split(":", 1)[1].strip()
        elif text.startswith("slave:"):
            slave = {"port": text.split(":", 1)[1].strip()}
            current["slaves"].append(slave)
            section = ""
        elif slave is not None and re.match(r"^(link failure count|actor state|partner state|status):", text):
            key, value = text.split(":", 1)
            slave[key.strip().replace(" ", "_")] = value.strip()
        elif section and re.match(r"^port\d+|^internal", text):
            (current["members"] if section == "active" else current["inactive"]).append(text.split()[0])
    return trunks


def _parse_mclag(icl: list[str], listing: list[str], check: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if icl:
        counters_at = next((i for i, line in enumerate(icl) if line.strip().lower() == "counters"), len(icl))
        values = _spaced_kv(icl[:counters_at])
        counters = _spaced_kv(icl[counters_at:])
        out["icl"] = {"name": icl[0].strip(), "values": values, "counters": counters,
                      "local_uptime_s": _seconds(values.get("Local uptime", "")), "peer_uptime_s": _seconds(values.get("Peer uptime", ""))}
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in listing:
        head = re.match(r"^(\S+?)(\(\*\))?$", line.strip())
        if head and not line.startswith(" ") and head.group(1) not in ("(*)",) and not line.startswith("("):
            current = {"name": head.group(1), "notes": []}
            entries.append(current)
            continue
        if current is None:
            continue
        kv = re.match(r"^\s+(Local system ID|Peer system ID|Current system ID|Local ports|Peer ports|Local uptime|Peer uptime|Updates sent to peer|Updates received from peer)\s{2,}(.+)$", line)
        if kv:
            current[kv.group(1)] = kv.group(2).strip()
        elif line.strip() and not line.strip().startswith("-"):
            current["notes"].append(line.strip())
    out["list"] = entries
    checks = [{"item": m.group(1), "result": m.group(2)} for line in check if (m := re.search(r'Comparing "([^"]+)" config\s+\.+(\w+)', line))]
    timeouts = [m.group(1) for line in check if (m := re.match(r"^\s*(\S+) mclag peer diagnostic timeout", line))]
    out["check"] = {"items": checks, "timeouts": timeouts, "ran": bool(check)}
    return out


def _parse_stp(lines: list[str]) -> list[dict[str, Any]]:
    instances: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines:
        head = re.match(r"^Instance ID (\d+)(?:\s+\((\w+)\))?", line)
        if head:
            current = {"id": int(head.group(1)), "kind": head.group(2) or "MST", "ports": [], "mismatch": [], "root": False}
            instances.append(current)
            continue
        if current is None:
            continue
        prio = re.search(r"Config\s+Priority (\d+)", line)
        if prio:
            current["priority"] = int(prio.group(1))
        if "This bridge is the root" in line:
            current["root"] = True
        tcn = re.search(r"TCN Events\s+Triggered (\d+) \(([^)]*) ago\), Received (\d+) \(([^)]*) ago\)", line)
        if tcn:
            current.update(tcn_triggered=int(tcn.group(1)), tcn_triggered_ago=_seconds(tcn.group(2)), tcn_received=int(tcn.group(3)), tcn_received_ago=_seconds(tcn.group(4)))
        port = re.match(r"^\s{2}(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(DISABLED|DESIGNATED|ROOT|ALTERNATE|BACKUP|MASTER)\s+(\w+)\s+(?:(\d+)\s+)?([A-Z]{2}(?:,[A-Z]{2})*)\s*$", line)
        if port:
            current["ports"].append({"port": port.group(1), "speed": port.group(2), "cost": int(port.group(3)), "role": port.group(5), "state": port.group(6), "flags": port.group(8)})
        mismatch = re.match(r"^\s*>>>\s+(\S+)\s+(.+)$", line)
        if mismatch:
            current["mismatch"].append({"port": mismatch.group(1), "text": mismatch.group(2).strip()})
    return instances


def _parse_modules(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        match = re.match(r"^\s*(port\d+)\s+(INSERT|EMPTY)\s*(.*)$", line)
        if match:
            rest = match.group(3).split()
            rows.append({"port": match.group(1), "state": match.group(2), "type": rest[0] if rest else "", "transceiver": rest[2] if len(rest) > 2 else "", "rx": rest[3] if len(rest) > 3 else "", "part": rest[5] if len(rest) > 5 else ""})
    return rows


def _parse_vlans(lines: list[str]) -> dict[int, list[str]]:
    vlans: dict[int, list[str]] = {}
    current = None
    for line in lines:
        head = re.match(r"^\s{2}(\d+)\s+(.*)$", line)
        if head:
            current = int(head.group(1))
            vlans[current] = head.group(2).split()
        elif current is not None and re.match(r"^\s{10,}\S", line):
            vlans[current] += line.split()
    return vlans


def _parse_macs(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        match = re.match(r"^MAC:\s+(\S+)\s+VLAN:\s+(\d+)\s+(Trunk|Port):\s+(\S+?)\(", line)
        if match:
            rows.append({"mac": match.group(1), "vlan": match.group(2), "via": f"{match.group(3).lower()} {match.group(4)}"})
    return rows


_LOG_HEAD = re.compile(r"^(\d+):\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+(.*)$")


def _parse_logs(lines: list[str]) -> list[dict[str, Any]]:
    entries: list[list[str]] = []
    for line in lines:
        head = _LOG_HEAD.match(line)
        if head:
            entries.append([head.group(2), head.group(3)])
        elif entries and line.strip():
            entries[-1][1] += line.strip() if line.startswith(" ") else line                # the terminal hard-wraps at its width, mid-word
    out = []
    for stamp, body in entries:
        msg = re.search(r'msg="(.*)"\s*$', body) or re.search(r'msg="([^"]*)"', body)
        out.append({"time": stamp, "id": (re.search(r"log_id=(\d+)", body) or [None, ""])[1], "level": (re.search(r"pri=(\w+)", body) or [None, ""])[1], "subtype": (re.search(r"subtype=(\w+)", body) or [None, ""])[1],
                    "msg": msg.group(1) if msg else body, "user": (re.search(r'user="([^"]*)"', body) or [None, ""])[1]})
    return out


def _parse_time(text: str) -> datetime | None:
    for fmt in ("%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(" ".join(text.split()), fmt)
        except ValueError:
            continue
    return None


def gather(text: str) -> dict[str, Any]:
    rendered = render(text)
    outputs, host, via = _blocks(rendered)
    rt: dict[str, Any] = {"outputs": outputs, "host": host, "via": via, "lines": {cmd: len(lines) for cmd, lines in outputs.items()}}
    get = lambda *names: next((outputs[n] for n in names if n in outputs), [])      # noqa: E731
    status = _parse_status(get("get system status"))
    rt["status"] = status
    rt["performance"] = _parse_performance(get("get system performance status"))
    rt["ntp"] = _parse_ntp(get("diagnose sys ntp status")) if "diagnose sys ntp status" in outputs else {}
    rt["fans"] = _parse_module_table(get("diagnose sys fan status"))
    rt["temps"] = _parse_module_table(get("diagnose sys pcb temp"))
    rt["psus"] = _parse_module_table(get("diagnose sys psu status"))
    rt["flash"] = _parse_flash(get("diagnose sys flash list"))
    rt["ports"] = _parse_ports(get("diagnose switch physical-ports summary"), get("diagnose switch physical-ports list"))
    rt["lldp"] = _parse_lldp(get("get switch lldp neighbors-summary"))
    rt["trunks"] = _parse_trunk_summary(get("diagnose switch trunk summary"))
    rt["trunk_detail"] = _parse_trunk_list(get("diagnose switch trunk list"))
    check_lines = get("diagnose switch mclag peer-consistency-check")
    rt["mclag"] = _parse_mclag(get("diagnose switch mclag icl", "diag switch mclag icl"), get("diagnose switch mclag list"), check_lines)
    rt["stp"] = _parse_stp(get("diagnose stp instance list"))
    rt["stp_settings"] = _kv(get("get switch stp settings"))
    rt["modules"] = _parse_modules(get("get switch modules summary"))
    rt["vlans"] = _parse_vlans(get("diagnose switch vlan list"))
    rt["macs"] = _parse_macs(get("diagnose switch mac-address list"))
    rt["logs"] = _parse_logs(get("execute log display"))
    rt["now"] = _parse_time(status.get("System time", ""))
    config_lines = get("show", "show full-configuration")
    rt["tree"] = parse_forti("\n".join(config_lines)) if config_lines and any(line.startswith("config ") for line in config_lines) else None
    return rt


# ------------------------------------------------------------------------------------------------ log analysis
def _normalise(message: str) -> str:
    return re.sub(r"\d+", "N", re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "IP", message))[:140]


def group_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in logs:
        key = (entry["id"], _normalise(entry["msg"]))
        group = groups.setdefault(key, {"id": entry["id"], "level": entry["level"], "msg": entry["msg"], "count": 0, "first": entry["time"], "last": entry["time"]})
        group["count"] += 1
        group["first"], group["last"] = min(group["first"], entry["time"]), max(group["last"], entry["time"])
    return sorted(groups.values(), key=lambda g: (-g["count"], g["first"]))


def _span(first: str, last: str) -> str:
    a, b = _parse_time(first), _parse_time(last)
    return f"{first} to {last} ({_human(int((b - a).total_seconds()))})" if a and b else f"{first} to {last}"


# ------------------------------------------------------------------------------------------------ findings
def _config_notes(tree: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"admins": [], "mgmt": [], "syslog": [], "snmp": False, "ntp": [], "dns": []}
    if tree is None:
        return out
    for _, admin in tree.entries("system admin"):
        out["admins"].append({"name": admin.name, "profile": admin.get("accprofile"), "trusthost": any(admin.has(f"trusthost{n}") for n in range(1, 11)), "two_factor": admin.has("two-factor")})
    for _, node in tree.entries("system interface"):
        out["mgmt"].append({"name": node.name, "mode": node.get("mode"), "allowaccess": " ".join(node.values("allowaccess")), "secondary": node.enabled("secondary-IP", False),
                            "secondary_ips": [sec.get("ip") for cfg in node.configs("secondaryip") for sec in cfg.entries()]})
    for path in ("log syslogd setting", "log syslogd2 setting", "log syslogd3 setting"):
        node = tree.first(path)
        if node is not None and node.get("status") == "enable":
            out["syslog"].append({"path": path.split()[1], "server": node.get("server"), "port": node.get("port")})
    snmp = tree.first("system snmp sysinfo")
    out["snmp"] = bool(snmp is not None and (snmp.settings or snmp.children)) or bool(tree.entries("system snmp community")) or bool(tree.entries("system snmp user"))
    out["ntp"] = [e.get("server") for _, e in tree.entries("system ntp ntpserver")] or [e.get("server") for cfg in (tree.first("system ntp"),) if cfg is not None for sub in cfg.configs("ntpserver") for e in sub.entries()]
    dns = tree.first("system dns")
    out["dns"] = [dns.get("primary"), dns.get("secondary")] if dns is not None else []
    return out


def evaluate(rt: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    mclag, trunks, stp = rt["mclag"], rt["trunk_detail"], rt["stp"]
    logs, now = rt["logs"], rt["now"]
    icl = mclag.get("icl")
    notes = _config_notes(rt["tree"])

    # --- FortiLink / switch-controller session ---------------------------------------------------------------
    restarts = [e for e in logs if e["id"] == "0106009006" and "SSL handshake failed" in e["msg"]]
    if len(restarts) >= 3:
        times = sorted(e["time"] for e in restarts)
        starts = [e for e in logs if e["id"] == "0103030700" and "cu_swtpd" in e["msg"]]
        a, b = _parse_time(times[0]), _parse_time(times[-1])
        interval = int((b - a).total_seconds() / max(1, len(restarts) - 1)) if a and b else None
        out.append(finding("FSW-LOG-001", "high", "FortiLink", f"The switch-controller daemon restarted {len(starts) or len(restarts)} times after SSL handshake failures", obj="cu_swtpd / CAPWAP",
                           detail=f"Event 0106009006 'Restart caputp since SSL handshake failed N times' appears {len(restarts)} times, from {_span(times[0], times[-1])}"
                                  + (f" - one restart about every {interval // 60} min {interval % 60} s" if interval else "") + f"; cu_swtpd was started {len(starts)} times in the same window. Every restart drops the CAPWAP/FortiLink session to the FortiGate, so the switch is repeatedly unmanaged and its configuration is re-pushed. "
                                  "Common causes of repeated DTLS/SSL handshake failure on a FortiLink are a clock difference between switch and FortiGate, a device-certificate mismatch after a replacement or restore, and a path that drops large CAPWAP/DTLS packets.",
                           recommendation="On the FortiGate check 'diagnose switch-controller' / the switch-controller event log for the same period and confirm both units share the NTP source; if the unit was replaced, re-authorise it in Switch Controller > Managed FortiSwitch. Open a TAC case with 'diagnose debug report' if it persists.",
                           reference=REF["capwap_restart"]))
    icl_ports = set(re.findall(r"port\d+", (icl or {}).get("values", {}).get("icl-ports", ""))) | {m for n, t in trunks.items() if "icl" in t.get("mode", "").lower() for m in t["members"] + t["inactive"]}
    if not icl_ports and rt["tree"] is not None:
        icl_ports = {m for _, e in rt["tree"].entries("switch trunk") if e.enabled("mclag-icl", False) for m in e.values("members")}
    expanded: set[str] = set()
    for item in (icl or {}).get("values", {}).get("icl-ports", "").split(","):
        span = re.match(r"^(\d+)-(\d+)$", item.strip())
        expanded |= {f"port{n}" for n in range(int(span.group(1)), int(span.group(2)) + 1)} if span else ({f"port{item.strip()}"} if item.strip().isdigit() else set())
    icl_ports |= expanded
    flaps = [e for e in logs if (e["id"] in ("0100001400", "0100001401") and any(re.search(rf"\b{p}\b", e["msg"]) for p in icl_ports)) or (e["id"] in ("0100001001", "0100001002") and "ICL" in e["msg"].upper())]
    if len(flaps) >= 4:
        times = sorted(e["time"] for e in flaps)
        downs = [e for e in flaps if "gone down" in e["msg"] or "non-active" in e["msg"]]
        out.append(finding("FSW-MCLAG-001", "high", "MCLAG", f"The inter-chassis link flapped {len(downs)} time(s) in the log window", obj=", ".join(sorted(icl_ports)) or "ICL",
                           detail=f"{len(flaps)} link/trunk-membership events on ICL ports {', '.join(sorted(icl_ports))}, from {_span(times[0], times[-1])}, with STP role changes on the ICL trunk and 'MCLAG: ICL ACL change' events. "
                                  "Each ICL loss makes one MCLAG peer go dormant and re-learns MACs; the FortiGate-facing trunks stay up but traffic reconverges every time.",
                           recommendation="Check the ICL cabling/optics and both ports' counters ('diagnose switch physical-ports list'); keep at least two ICL links on separate modules; correlate with the peer's own log for the same timestamps.", reference=REF["mclag_design"]))
    stale = [e for e in logs if e["id"] == "0106009008" and "ISL timing-out" in e["msg"]]
    if stale:
        ports = sorted({m.group(1) for e in stale if (m := re.search(r"member port-num\(\d+\) (port\d+)", e["msg"]))})
        longest = max((int(m.group(1)) for e in stale if (m := re.search(r"for\((\d+)\) sec", e["msg"]))), default=0)
        unexpected = [p for p in ports if p not in icl_ports]
        out.append(finding("FSW-MCLAG-002", "medium" if unexpected else "low", "MCLAG", f"ISL packets stopped on {', '.join(ports) or 'an ICL member'} ({len(stale)} timeout events)", obj=", ".join(ports),
                           detail=f"Event 0106009008 (ISL timing-out) repeats every 30 s, from {_span(min(e['time'] for e in stale), max(e['time'] for e in stale))}, counting up to {longest} s without an ISL packet."
                                  + (f" {', '.join(unexpected)} is not a configured ICL member ({', '.join(sorted(icl_ports)) or 'none'}), so this is probably state left over from an earlier ICL cabling or auto-ISL discovery." if unexpected else ""),
                           recommendation="Confirm what is plugged into that port; if the ICL was moved, clear the stale auto-ISL entry (port settings, LLDP profile) so the timeout stops flooding the log.", reference=REF["log_reference"]))

    # --- MCLAG pair state --------------------------------------------------------------------------------------
    if mclag["check"]["timeouts"]:
        out.append(finding("FSW-MCLAG-003", "medium", "MCLAG", "MCLAG peer consistency check timed out", obj=", ".join(mclag["check"]["timeouts"]),
                           detail="'diagnose switch mclag peer-consistency-check' compared the global settings but could not read the peer's LACP/STP state for " + ", ".join(mclag["check"]["timeouts"]) + ". The tool itself suggests verifying the ICL on both sides and the CPU load of the pair.",
                           recommendation="Repeat the check once the ICL has been stable for several minutes; if it still times out, compare 'diagnose switch mclag icl' on both switches and look for keepalive misses.", reference=REF["mclag_design"]))
    if icl:
        local, peer = icl.get("local_uptime_s"), icl.get("peer_uptime_s")
        if local and peer is not None and local - peer > 3600 and peer < 86400:
            out.append(finding("FSW-MCLAG-004", "medium", "MCLAG", f"The MCLAG peer restarted recently (up {_human(peer)} against {_human(local)} here)", obj=icl["values"].get("peer-serial-number", "peer"),
                               detail=f"Local uptime {icl['values'].get('Local uptime')} vs peer uptime {icl['values'].get('Peer uptime')}. A peer that is hours old after days of stable operation was reloaded or crashed; combined with the ICL events this points at an unplanned restart rather than a maintenance window. Dormant candidate: {icl['values'].get('dormant candidate', 'n/a')}.",
                               recommendation="Pull the peer's 'diagnose debug crashlog' and 'execute log display' for the reload time; verify the reload was planned.", reference=REF["mclag"]))
        counters = icl["counters"]
        miss, drop = int(re.sub(r"\D", "", counters.get("receive keepalive miss", "0")) or 0), int(re.sub(r"\D", "", counters.get("received keepalive drop packets", "0")) or 0)
        rx, tx = int(re.sub(r"\D", "", counters.get("received keepalive packets", "0")) or 0), int(re.sub(r"\D", "", counters.get("transmited keepalive packets", counters.get("transmitted keepalive packets", "0"))) or 0)
        if miss or drop:
            out.append(finding("FSW-MCLAG-005", "medium" if miss >= 10 else "low", "MCLAG", f"ICL keepalives are being missed ({miss} misses, {drop} dropped)", obj="diagnose switch mclag icl",
                               detail=f"Received {rx} keepalives, sent {tx}, {drop} received packets dropped, {miss} intervals with no keepalive (interval {icl['values'].get('keepalive interval', '?')} s, timeout {icl['values'].get('keepalive timeout', '?')} s). "
                                      + (f"The peer answered only {rx * 100 // tx}% of what this switch sent, consistent with a peer that was down for part of the window." if tx and rx < tx * 0.8 else ""),
                               recommendation="Take two readings a few minutes apart: counters that keep growing mean a live problem on the ICL, counters that stand still are history from the peer's restart.", reference=REF["mclag"]))
        if icl["values"].get("split-brain", "").lower() == "disabled":
            unstable = bool(flaps) or bool(mclag["check"]["timeouts"])
            out.append(finding("FSW-MCLAG-006", "medium" if unstable else "low", "MCLAG", "MCLAG split-brain detection is disabled", obj="switch global mclag-split-brain-detect",
                               detail="Split-brain detection is off by default and must be enabled on both peers. Without it, when the ICL is lost while both switches stay up, both keep forwarding on the shared LACP trunks. "
                                      + ("This pair has shown ICL instability, which is exactly the situation it protects against." if unstable else "The pair is currently stable."),
                               recommendation="Enable it on both peers (config switch global > set mclag-split-brain-detect enable) and set the peer priority so the intended switch stays active. The peer-consistency check already compares this setting, so changing both sides keeps it consistent.", reference=REF["mclag"]))
        members = sorted(icl_ports, key=lambda p: int(re.sub(r"\D", "", p) or 0))
        speed_of = {row["name"]: row.get("speed", "") for row in rt["ports"]}

        def gbps(text: str) -> float:
            match = re.match(r"^(\d+(?:\.\d+)?)([GM])", text or "")
            return float(match.group(1)) * (1 if match and match.group(2) == "G" else 0.001) if match else 0.0

        icl_bw = sum(gbps(speed_of.get(p, "")) for p in members)
        uplink = max((gbps(speed_of.get(m, "")) for t in trunks.values() if "mclag" in t.get("mode", "") and "icl" not in t.get("mode", "").lower() for m in t["members"]), default=0.0)
        if icl_bw and uplink and icl_bw < uplink:
            out.append(finding("FSW-MCLAG-007", "low", "MCLAG", f"ICL capacity ({icl_bw:g}G) is smaller than one FortiLink uplink ({uplink:g}G)", obj=", ".join(members),
                               detail=f"ICL members {', '.join(members)} run at {', '.join(speed_of.get(p, '?') for p in members)}. When a FortiGate-facing link fails, traffic for that side crosses the ICL; one {uplink:g}G uplink can saturate a {icl_bw:g}G ICL. At today's near-idle traffic this is a design remark, not a fault.",
                               recommendation="Size the ICL for the failure case (match or exceed one uplink) and keep at least two ICL members.", reference=REF["mclag_design"]))
        if len(members) < 2:
            out.append(finding("FSW-MCLAG-008", "medium", "MCLAG", "The ICL has a single member link", obj=", ".join(members), detail="Fortinet recommends at least two links in the ICL for redundancy.", recommendation="Add a second ICL member on a different module.", reference=REF["mclag_design"]))

    # --- trunks ---------------------------------------------------------------------------------------------------------
    for row in rt["trunks"]:
        if row["state"] != "up" or (row["active"] is not None and row["total"] is not None and row["active"] < row["total"]):
            out.append(finding("FSW-LACP-001", "medium", "Link aggregation", f"Trunk {row['name']} is {row['state']} with {row['active']}/{row['total']} members active", obj=row["name"], detail=f"Mode {row['mode']}.", recommendation="Check the member ports and the far-end LACP configuration.", reference=REF["mclag"]))
    for name, trunk in trunks.items():
        bad = [s for s in trunk["slaves"] if s.get("partner_state") and s["partner_state"] != "ASAIEE"]
        failures = [s for s in trunk["slaves"] if (s.get("link_failure_count") or "0").isdigit() and int(s["link_failure_count"])]
        if bad:
            out.append(finding("FSW-LACP-002", "medium", "Link aggregation", f"LACP partner on {name} is not in the fully-synchronised state", obj=name, detail="; ".join(f"{s['port']} partner {s['partner_state']} (expected ASAIEE: active, short, aggregatable, in sync, collecting, distributing)" for s in bad),
                               recommendation="Check the LACP mode and key on the far end.", reference=REF["mclag"]))
        if failures:
            out.append(finding("FSW-LACP-003", "low", "Link aggregation", f"Link failures counted on {name}", obj=name, detail="; ".join(f"{s['port']}: {s['link_failure_count']}" for s in failures), recommendation="Check optics and cabling.", reference=REF["mclag"]))

    # --- spanning tree ---------------------------------------------------------------------------------------------------
    if rt["stp_settings"].get("status", "").lower() == "disable":
        out.append(finding("FSW-STP-001", "high", "Spanning tree", "Spanning tree is disabled", obj="switch stp settings", detail="status disable: a cabling mistake or an MCLAG split can form a Layer-2 loop.", recommendation="Enable STP (MCLAG ICL trunks also require it).", reference=REF["stp"]))
    for instance in stp:
        if instance["mismatch"]:
            out.append(finding("FSW-STP-002", "medium", "Spanning tree", f"STP and trunk state disagree on {len(instance['mismatch'])} port(s) in instance {instance['id']}", obj=", ".join(m["port"] for m in instance["mismatch"]),
                               detail="; ".join(f"{m['port']}: {m['text']}" for m in instance["mismatch"][:4]) + ". The ICL trunk is shown as BACKUP/DISCARDING while its member ports are still FORWARDING in hardware - a transient state during ICL re-formation, or a sign the trunk was rebuilt while STP kept the old port state.",
                               recommendation="Re-run 'diagnose stp instance list' after the ICL has been stable; if the mismatch persists, bounce the ICL members one at a time in a maintenance window.", reference=REF["stp"]))
            break
    for instance in stp:
        if instance.get("tcn_triggered_ago") is not None and instance["tcn_triggered_ago"] < 3600:
            out.append(finding("FSW-STP-003", "low", "Spanning tree", f"A topology change was triggered {_human(instance['tcn_triggered_ago'])} ago in instance {instance['id']}", obj=f"instance {instance['id']}", detail=f"{instance['tcn_triggered']} triggered, {instance.get('tcn_received', 0)} received since boot.", recommendation="Find the port that changed state ('diagnose stp instance list' per port, event log).", reference=REF["stp"]))
            break

    # --- hardware and platform --------------------------------------------------------------------------------------
    for kind, rows in (("fan", rt["fans"]), ("power supply", rt["psus"])):
        for row in rows:
            if not row["status"].upper().startswith("OK"):
                out.append(finding("FSW-HW-001", "high", "Hardware", f"{kind.title()} {row['module']} reports '{row['status']}'", obj=row["module"], detail="", recommendation="Replace or re-seat the module.", reference=REF["admin"]))
    perf = rt["performance"]
    if perf.get("mem_used", 0) >= 85:
        out.append(finding("FSW-SYS-001", "medium", "Platform health", f"Memory is {perf['mem_used']}% used", obj="get system performance status", detail="", recommendation="Check 'diagnose sys top-mem' for the largest process.", reference=REF["admin"]))
    if perf.get("cpu_idle", 100) < 10:
        out.append(finding("FSW-SYS-002", "medium", "Platform health", f"CPU is {100 - perf['cpu_idle']}% busy", obj="get system performance status", detail="A busy switch CPU delays LACP, STP and MCLAG keepalives.", recommendation="Check 'fnsysctl top' for the process.", reference=REF["mclag"]))
    ntp = rt["ntp"]
    if ntp and not ntp.get("synchronized"):
        out.append(finding("FSW-SYS-003", "medium", "Platform health", "NTP is not synchronised", obj="diagnose sys ntp status", detail="Clock skew between switch and FortiGate breaks the DTLS handshake of FortiLink and makes the logs unusable for correlation.", recommendation="Fix the NTP server reachability.", reference=REF["logging"]))
    flash = rt["flash"]
    older = [row for row in flash if not row["active"] and row["version"]]
    active = next((row for row in flash if row["active"]), None)
    if active and older:
        out.append(finding("FSW-SYS-004", "info", "Firmware", f"Running {active['version']}; the other partition holds {older[0]['version']}", obj=active["image"],
                           detail=f"Active image {active['image']} (next boot: partition {next((r['partition'] for r in flash if r['next_boot']), '?')}). The second partition is the rollback image.", recommendation="Compare the running release against Fortinet's current recommended FortiSwitchOS release for this model before the next change window; the upgrade information page lists supported paths.", reference=REF["upgrade"]))
    for port in rt["ports"]:
        bad = {k: port.get(k, 0) for k in ("in_errors", "out_errors", "collisions", "jabbers") if port.get(k, 0)}
        if bad and port.get("link") == "up":
            out.append(finding("FSW-PORT-001", "medium", "Ports", "%s counts errors (%s)" % (port["name"], ", ".join("%s %s" % (k.replace("_", " "), v) for k, v in bad.items())), obj=port["name"], detail="", recommendation="Check the optic/cable and the speed/duplex at both ends.", reference=REF["admin"]))

    # --- management and logging ---------------------------------------------------------------------------------------
    for iface in notes["mgmt"]:
        if iface["secondary"] and iface["secondary_ips"]:
            out.append(finding("FSW-SEC-001", "low", "Management", f"{iface['name']} keeps the factory secondary address {', '.join(iface['secondary_ips'])}", obj=iface["name"],
                               detail=f"Management access on that address: {iface['allowaccess']}. A well-known fallback address reachable from anything on the same L2 segment is a management-plane exposure.", recommendation="Disable the secondary IP once the unit is managed through FortiLink.", reference=REF["admin"]))
    for admin in notes["admins"]:
        if not admin["trusthost"] and admin["profile"] in ("super_admin", "prof_admin"):
            out.append(finding("FSW-SEC-002", "low", "Management", f"Administrator '{admin['name']}' has full rights and no trusted-host restriction", obj=admin["name"], detail=f"Profile {admin['profile']}; SSH and HTTPS are allowed on {', '.join(i['name'] for i in notes['mgmt'] if i['allowaccess'])}.",
                               recommendation="Set trusted hosts to the FortiGate/management subnet and use a named personal administrator for day-to-day work.", reference=REF["admin"]))
    if rt["tree"] is not None and not [s for s in notes["syslog"] if s["server"] not in ("127.0.0.1", "localhost", "")]:
        out.append(finding("FSW-SEC-003", "low", "Logging", "Logs are not forwarded off the switch", obj="log syslogd", detail=f"{len(logs)} events are kept in the local buffer (about {_human(int((max(_parse_time(e['time']) for e in logs) - min(_parse_time(e['time']) for e in logs)).total_seconds())) if len(logs) > 1 else 'n/a'} of history), "
                           "and the only syslog target is the loopback used by FortiLink. After a reload or a crash the evidence for the ICL events above is gone.", recommendation="Send syslog to the central collector, or confirm the FortiGate collects the switch logs.", reference=REF["logging"]))
    failed = [e for e in logs if e["id"] == "0103032002"]
    if failed:
        out.append(finding("FSW-SEC-004", "info", "Management", f"{len(failed)} failed administrator login(s) in the log", obj="admin", detail="; ".join(f"{e['time']} {e['msg']}" for e in failed[:3]), recommendation="Confirm they were the engineer's own attempts (the capture itself begins with a rejected SSH login).", reference=REF["admin"]))
    return out


# ------------------------------------------------------------------------------------------------ sections
def sections(rt: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    status, perf, ntp, notes = rt["status"], rt["performance"], rt["ntp"], _config_notes(rt["tree"])
    pairs = [("Model", status.get("_model")), ("FortiSwitchOS", f"{status.get('_version')} build {status.get('_build')}" if status.get("_version") else ""), ("Serial number", status.get("Serial-Number")), ("Hostname", status.get("Hostname")),
             ("System time", status.get("System time")), ("Uptime", perf.get("uptime")), ("Boot", status.get("Boot")), ("Burn-in MAC", status.get("Burn in MAC")), ("Security mode", status.get("Security mode"))]
    out.append(kv_section("fsw_identity", "Switch identity (get system status)", [(k, v) for k, v in pairs if v], group="System"))
    health = []
    if perf:
        health += [("CPU idle", f"{perf.get('cpu_idle')}%  (user {perf.get('cpu_user')}%, system {perf.get('cpu_system')}%)", "warn" if perf.get("cpu_idle", 100) < 10 else ""), ("Memory used", f"{perf.get('mem_used')}%", "warn" if perf.get("mem_used", 0) >= 85 else "")]
    if ntp:
        health.append(("NTP", ("synchronized" if ntp.get("synchronized") else "NOT synchronized") + (f" · {ntp.get('server')} stratum {ntp.get('stratum', '?')} offset {ntp.get('offset', '?')} s" if ntp.get("server") else ""), "" if ntp.get("synchronized") else "bad"))
    health += [(f"Fan {r['module']}", r["status"], "" if r["status"].startswith("OK") else "bad") for r in rt["fans"]] + [(f"PSU {r['module']}", r["status"], "" if r["status"].startswith("OK") else "bad") for r in rt["psus"]] + [(f"Temperature {r['module']}", r["status"]) for r in rt["temps"]]
    if health:
        out.append(kv_section("fsw_health", "Health", health, group="System"))
    if rt["flash"]:
        out.append(table_section("fsw_flash", "Firmware partitions", [("partition", "Partition", "num"), ("image", "Image", "mono"), ("version", "Release"), ("used_pct", "Used %", "num"), ("active", "Active", "status"), ("next_boot", "Next boot", "status")],
                                 [dict(r, active="yes" if r["active"] else "no", next_boot="yes" if r["next_boot"] else "", _tone="info" if r["active"] else "") for r in rt["flash"]], group="System"))
    icl = rt["mclag"].get("icl")
    if icl:
        values, counters = icl["values"], icl["counters"]
        rows = [(k.replace("-", " ").capitalize() if k.islower() else k, v) for k, v in values.items()] + [(f"Counter: {k}", v) for k, v in counters.items()]
        out.append(kv_section("fsw_icl", f"MCLAG inter-chassis link ({icl['name']})", rows, group="MCLAG", hint="From 'diagnose switch mclag icl'. Keepalive misses that keep growing between two readings are a live problem; counters that stand still are history."))
    if rt["mclag"]["list"]:
        out.append(table_section("fsw_mclag", "MCLAG trunks (diagnose switch mclag list)", [("name", "Trunk", "mono"), ("lports", "Local ports"), ("pports", "Peer ports"), ("lup", "Local uptime"), ("pup", "Peer uptime"), ("sent", "Updates sent", "num"), ("recv", "Updates received", "num")],
                                 [{"name": e["name"], "lports": e.get("Local ports", ""), "pports": e.get("Peer ports", ""), "lup": e.get("Local uptime", ""), "pup": e.get("Peer uptime", ""), "sent": e.get("Updates sent to peer", ""), "recv": e.get("Updates received from peer", "")} for e in rt["mclag"]["list"]], group="MCLAG"))
    check = rt["mclag"]["check"]
    if check["ran"]:
        rows = [(i["item"], i["result"], "" if i["result"] == "OK" else "bad") for i in check["items"]] + [(f"Peer state of {t}", "diagnostic timeout", "warn") for t in check["timeouts"]]
        out.append(kv_section("fsw_consistency", "MCLAG peer-consistency check", rows, group="MCLAG"))
    if rt["trunks"]:
        detail = rt["trunk_detail"]
        rows = []
        for t in rt["trunks"]:
            d = detail.get(t["name"], {})
            rows.append({"name": t["name"], "mode": t["mode"], "members": f"{t['active']}/{t['total']} active" if t["active"] is not None else "", "ports": d.get("members", []), "state": t["state"], "uptime": t["uptime"], "partner": d.get("partner_mac", ""),
                         "lacp": ", ".join(sorted({s.get("partner_state", "") for s in d.get("slaves", []) if s.get("partner_state")})), "_tones": {"state": "ok" if t["state"] == "up" else "bad"}})
        out.append(table_section("fsw_trunks", "Trunks (diagnose switch trunk summary / list)", [("name", "Trunk", "mono"), ("mode", "Mode"), ("members", "Members"), ("ports", "Active ports", "list"), ("state", "State", "status"), ("uptime", "Up time"), ("partner", "Partner MAC", "mono"), ("lacp", "Partner LACP state")], rows, group="MCLAG", facets=[{"key": "state", "label": "state"}]))
    if rt["stp"]:
        rows = []
        for inst in rt["stp"]:
            rows.append({"instance": inst["id"], "kind": inst["kind"], "priority": inst.get("priority", ""), "root": "this bridge" if inst["root"] else "other", "tcn": f"{inst.get('tcn_triggered', '')} triggered ({_human(inst.get('tcn_triggered_ago'))} ago), {inst.get('tcn_received', '')} received ({_human(inst.get('tcn_received_ago'))} ago)" if "tcn_triggered" in inst else "",
                         "mismatch": len(inst["mismatch"]), "_tones": {"mismatch": "warn" if inst["mismatch"] else ""}})
        out.append(table_section("fsw_stp", "Spanning tree instances", [("instance", "Instance", "num"), ("kind", "Type"), ("priority", "Priority", "num"), ("root", "Root bridge"), ("tcn", "Topology changes", "wrap"), ("mismatch", "State mismatches", "num")], rows, group="Spanning tree"))
        ports = [dict(p, instance=i["id"], _tone="warn" if p["role"] == "BACKUP" or (p["role"] == "DISABLED") is False and p["state"] != "FORWARDING" else "") for i in rt["stp"][:1] for p in i["ports"] if p["role"] != "DISABLED" or p["port"].startswith(("port47", "port48"))]
        out.append(table_section("fsw_stp_ports", "Spanning tree ports (active only)", [("port", "Port", "mono"), ("speed", "Speed"), ("cost", "Cost", "num"), ("role", "Role", "status"), ("state", "State", "status"), ("flags", "Flags")], ports, group="Spanning tree",
                                 hint="Disabled ports are omitted. Flags: EN STP enabled, ED edge. BACKUP/DISCARDING on the ICL trunk is the normal MCLAG ICL role.", facets=[{"key": "state", "label": "state"}, {"key": "role", "label": "role"}]))
    if rt["ports"]:
        lldp = {r["port"]: r for r in rt["lldp"]}
        vlan_cfg: dict[str, str] = {}
        if rt["tree"] is not None:
            for _, e in rt["tree"].entries("switch interface"):
                untagged = e.get("untagged-vlans") or e.get("native-vlan")
                vlan_cfg[e.name] = f"untagged {untagged}" + (f" · allowed {e.get('allowed-vlans')}" if e.get("allowed-vlans") and e.get("allowed-vlans") != untagged else "") if (untagged or e.get("allowed-vlans")) else ""
        mod = {m["port"]: m for m in rt["modules"]}
        rows = []
        for p in rt["ports"]:
            n = lldp.get(p["name"], {})
            tone = "ok" if p.get("link") == "up" else "mute"
            rows.append({"name": p["name"], "link": p.get("link", ""), "speed": f"{p.get('speed', '')} {p.get('duplex', '')}".strip(), "pvid": p.get("pvid", ""), "vlans": vlan_cfg.get(p["name"], ""), "neighbor": (n.get("device", "") if n.get("device", "-") != "-" else ""),
                         "remote_port": n.get("remote_port", "") if n.get("remote_port", "-") != "-" else "", "optic": (mod.get(p["name"], {}).get("transceiver", "") if mod.get(p["name"], {}).get("state") == "INSERT" else ""),
                         "errors": (p.get("in_errors", 0) or 0) + (p.get("out_errors", 0) or 0), "drops": (p.get("in_drops", 0) or 0) + (p.get("out_drops", 0) or 0), "_tones": {"link": tone}})
        out.append(table_section("fsw_ports", "Ports", [("name", "Port", "mono"), ("link", "Link", "status"), ("speed", "Speed/duplex"), ("pvid", "PVID", "num"), ("vlans", "VLAN configuration"), ("neighbor", "LLDP neighbor"), ("remote_port", "Neighbor port", "mono"), ("optic", "Optic"), ("errors", "Errors", "num"), ("drops", "Drops", "num")],
                                 rows, group="Ports", page_size=100, hint="Join of 'diagnose switch physical-ports summary / list', 'get switch lldp neighbors-summary', 'get switch modules summary' and the VLAN settings in 'show'.", facets=[{"key": "link", "label": "link", "order": ["up", "down"]}]))
    if rt["vlans"]:
        desc = {}
        if rt["tree"] is not None:
            desc = {e.name: e.get("description") for _, e in rt["tree"].entries("switch vlan")}
        out.append(table_section("fsw_vlans", "VLANs", [("id", "VLAN", "num"), ("description", "Description"), ("ports", "Ports", "num"), ("members", "Members", "wrap")],
                                 [{"id": vid, "description": desc.get(str(vid), ""), "ports": len(members), "members": ", ".join(members[:12]) + (" ..." if len(members) > 12 else "")} for vid, members in sorted(rt["vlans"].items())], group="Ports"))
    if rt["macs"]:
        out.append(table_section("fsw_macs", "MAC address table", [("mac", "MAC", "mono"), ("vlan", "VLAN", "num"), ("via", "Learned on", "mono")], rt["macs"], group="Ports"))
    if rt["logs"]:
        groups = group_logs(rt["logs"])
        rows = [{"count": g["count"], "id": g["id"], "level": g["level"], "first": g["first"], "last": g["last"], "msg": g["msg"], "_tone": "bad" if g["count"] >= 20 and g["level"] in ("notice", "warning", "error") and g["id"] in ("0106009006", "0106009008") else ""} for g in groups]
        out.append(table_section("fsw_events", f"Event log, grouped ({len(rt['logs'])} entries)", [("count", "Count", "num"), ("id", "Log ID", "mono"), ("level", "Level"), ("first", "First seen"), ("last", "Last seen"), ("msg", "Message", "wrap")], rows, group="Events", page_size=100,
                                 hint="'execute log display' grouped by log ID and message with the numbers masked. Log ID meanings: Fortinet FortiSwitchOS log reference.", facets=[{"key": "level", "label": "level"}]))
    if notes["mgmt"] or notes["admins"]:
        rows = [(f"Interface {i['name']}", f"{i['mode'] or 'static'} · access {i['allowaccess'] or 'none'}" + (f" · secondary {', '.join(i['secondary_ips'])}" if i["secondary_ips"] else "")) for i in notes["mgmt"]]
        rows += [(f"Administrator {a['name']}", f"profile {a['profile']} · trusted hosts {'yes' if a['trusthost'] else 'none'}") for a in notes["admins"]]
        rows += [("Syslog", ", ".join(f"{s['server']}:{s['port']}" for s in notes["syslog"]) or "none"), ("SNMP", "configured" if notes["snmp"] else "not configured"), ("NTP servers", ", ".join(x for x in notes["ntp"] if x) or "none"), ("DNS", ", ".join(x for x in notes["dns"] if x) or "none")]
        out.append(kv_section("fsw_config", "Management configuration (from show)", rows, group="System", hint="Passwords and keys are never read."))
    return out


def _cards(rt: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    status, perf = rt["status"], rt["performance"]
    cards = [card("Platform", status.get("_model", "FortiSwitch"), "info", f"FortiSwitchOS {status.get('_version', '?')} · up {perf.get('uptime', '?')}", "fsw_identity")]
    ports = rt["ports"]
    if ports:
        up = [p for p in ports if p.get("link") == "up"]
        cards.append(card("Ports up", f"{len(up)}/{len(ports)}", "info", "including trunk members and internal", "fsw_ports"))
    icl = rt["mclag"].get("icl")
    if icl:
        peer, local = icl.get("peer_uptime_s"), icl.get("local_uptime_s")
        stable = not any(f["id"] in ("FSW-MCLAG-001", "FSW-MCLAG-004") for f in findings)
        cards.append(card("MCLAG pair", "stable" if stable else "unstable", "ok" if stable else "bad", f"peer up {_human(peer)} · local up {_human(local)}", "fsw_icl"))
    if rt["trunks"]:
        up = sum(t["state"] == "up" for t in rt["trunks"])
        cards.append(card("Trunks up", f"{up}/{len(rt['trunks'])}", "ok" if up == len(rt["trunks"]) else "bad", "", "fsw_trunks"))
    if rt["logs"]:
        cards.append(card("Log events", len(rt["logs"]), "info", f"{len(group_logs(rt['logs']))} distinct", "fsw_events"))
    counts = severity_counts(findings)
    cards.append(card("High findings", counts["high"], "bad" if counts["high"] else "ok", "", "findings"))
    cards.append(card("Medium findings", counts["medium"], "warn" if counts["medium"] else "ok", f"{counts['low']} low · {counts['info']} info", "findings"))
    return cards


_EXPECTED = (
    ("get system status", "identity, release"), ("get system performance status", "CPU, memory, uptime"), ("diagnose switch physical-ports summary", "port link state"), ("diagnose switch trunk summary", "trunk state"),
    ("diagnose switch mclag icl", "inter-chassis link"), ("diagnose switch mclag peer-consistency-check", "pair consistency"), ("diagnose stp instance list", "spanning tree"), ("execute log display", "event history"), ("show", "configuration"),
)


def _coverage(rt: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    seen = rt["lines"]
    for command, purpose in _EXPECTED:
        rows.append({"command": command, "status": "analyzed" if command in seen or (command == "diagnose switch mclag icl" and "diag switch mclag icl" in seen) else "missing", "lines": seen.get(command, 0), "note": "" if command in seen else f"Not in this capture - would add: {purpose}.",
                     "tone": "ok" if command in seen else "warn"})
    handled = {c for c, _ in _EXPECTED} | {"diagnose switch physical-ports list", "diagnose switch trunk list", "diagnose switch mclag list", "diagnose sys ntp status", "diagnose sys fan status", "diagnose sys pcb temp", "diagnose sys psu status", "diagnose sys flash list",
                                           "get switch lldp neighbors-summary", "get switch modules summary", "diagnose switch vlan list", "diagnose switch mac-address list", "get switch stp settings", "diag switch mclag icl"}
    others = [c for c in seen if c not in handled and not c.startswith(("exe", "execute ssh", "config vdom", "edit "))]
    rows.append({"command": f"{len(others)} other report sections", "status": "kept", "lines": sum(seen[c] for c in others), "note": "Present in the capture (IO statistics, QoS, IGMP/DHCP snooping, 802.1X, certificates, ...) and not analyzed yet.", "tone": "info"})
    if "diagnose debug crashlog get" in seen:
        rows.append({"command": "diagnose debug crashlog get", "status": "skipped", "lines": seen["diagnose debug crashlog get"], "note": "Base64-encoded crash data; not decoded. Send it to Fortinet TAC if a crash is suspected.", "tone": "info"})
    return rows


def analyze(content: str, filename: str = "", today: date | None = None) -> dict[str, Any]:
    rt = gather(content)
    if not rt["status"] and not rt["trunks"] and not rt["tree"]:
        raise ValueError("No FortiSwitch output was recognised. Capture 'diagnose debug report' on the switch (or 'get system status' with the diagnose switch commands).")
    findings = sort_findings(evaluate(rt))
    status = rt["status"]
    host = status.get("Hostname") or rt["host"] or filename.rsplit(".", 1)[0]
    model = status.get("_model", "FortiSwitch")
    version = status.get("_version", "")
    result = new_result("firewall", hostname=host, vendor="Fortinet", platform=f"{model} · FortiSwitchOS {version}".strip(" ·"), source_name=filename, title=host,
                        subtitle=" · ".join(filter(None, [model, f"FortiSwitchOS {version}" if version else "", "MCLAG" if rt["mclag"].get("icl") else "", "diagnose capture"])))
    result["sections"] = sections(rt, findings)
    result["cards"] = _cards(rt, findings)
    result["info"] = info_rows([("Hostname", host), ("Model", model), ("Serial number", status.get("Serial-Number")), ("FortiSwitchOS", f"{version} build {status.get('_build', '')}" if version else ""), ("Uptime", rt["performance"].get("uptime")),
                                ("System time", status.get("System time")), ("Reached through", ", ".join(rt["via"]) if rt["via"] else ""), ("MCLAG peer", (rt["mclag"].get("icl") or {}).get("values", {}).get("peer-serial-number")),
                                ("Commands", len(rt["outputs"])), ("Source", "terminal log, replayed through a terminal model")])
    result["findings"] = findings
    result["coverage"] = _coverage(rt)
    result["warnings"] = ["A FortiSwitch is analyzed inside the Firewall Analyzer because it is reached and managed through its FortiGate and speaks FortiOS syntax. The log window is the switch's own buffer (oldest entries first dropped), so counts are for that window, not for the lifetime of the unit."]
    result["capture"] = {"commands": len(rt["outputs"]), "lines": sum(rt["lines"].values()), "has_config": rt["tree"] is not None}
    return result
