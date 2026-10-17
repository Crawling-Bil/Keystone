"""PAN-OS runtime capture: a terminal log of ``show`` / ``request`` commands with no configuration in it.

Engineers often hand over only what they pasted into PuTTY while looking at a firewall -- ``show system info``,
``request license info``, ``show interface all``, ``show routing route`` ... -- not an export.  That is a different kind of
evidence from every other file this analyzer reads: it says nothing about rules or NAT, but it is the only source for things a
configuration can never contain -- licence expiry, content age, real link state, disk and memory pressure, which processes are
running, whether the unit can reach the Palo Alto update servers.

Everything is dated against the *capture* (``show system info`` -> ``time:``), not against today, so a log saved last month is
judged as it was then.

Commands understood (abbreviations accepted):

    show system info                     request license info              request support check
    show session info                    show system resources             show high-availability all | state
    show interface all                   show interface management         show routing route
    show arp all                         show mac all                      show system disk-space
    request system software info         show system software status      show jobs all

The HA, ARP and MAC parsers follow Palo Alto's documented output but were written without a captured sample that has them
populated; the result says so (``warnings``).

Reference: https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-device-management
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import date, datetime
from typing import Any

from ..analyzer_core.capture import PANOS_PROMPT, Capture, command_matches, split_capture
from ..analyzer_core.findings import finding, severity_counts, sort_findings
from ..analyzer_core.result import card, info_rows, kv_section, new_result, table_section
from ..analyzer_core.terminal import render
from . import panos_runtime
from .refs import PALO

# Dates below were read from Palo Alto's own lifecycle pages on 2026-10-17 (see refs.PALO["eol_software"] / ["eol_hardware"]).
SOFTWARE_EOL = {"9.0": date(2022, 3, 1), "9.1": date(2024, 6, 30), "10.0": date(2022, 7, 16)}
HARDWARE_EOL = {"PA-3020": (date(2019, 10, 31), date(2024, 10, 31), "PA-3000 Series", "PA-3400 Series"),
                "PA-3050": (date(2019, 10, 31), date(2024, 10, 31), "PA-3000 Series", "PA-3400 Series"),
                "PA-3060": (date(2019, 10, 31), date(2024, 10, 31), "PA-3000 Series", "PA-3400 Series")}

_SNIFF = re.compile(r"\S+@\S+>\s*(?:show|request)\s+\S+")
_ROUTE_FLAGS = {"A", "S", "C", "H", "R", "O", "B", "E", "M", "?", "~", "Oi", "Oo", "O1", "O2"}
_MONTHS = "January February March April May June July August September October November December".split()


# ------------------------------------------------------------------------------------------------ detection
def looks_like_runtime(text: str) -> bool:
    """A PAN-OS prompt followed by show/request commands, ``show system info`` among them, and no configuration tree.

    The cheap prompt test runs on the raw bytes; only a file that passes it is replayed (tab completion repaints the prompt word
    by word, so the complete command is only certain after the replay)."""
    sample = text[:3_000_000]
    if not _SNIFF.search(sample):
        return False
    rendered = render(sample)
    if not re.search(r"(?m)^\S+@\S+>\s*show system info\s*$", rendered):
        return False
    return not re.search(r"(?m)^config \{|^\s*deviceconfig \{|^set (?:deviceconfig|rulebase|network|zone)\b", rendered)


# ------------------------------------------------------------------------------------------------ small parsers
def _kv(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        match = re.match(r"^([\w.\-]+):\s?(.*)$", line.strip())
        if match:
            out[match.group(1)] = match.group(2).strip()
    return out


def _parse_date(text: str) -> date | None:
    text = (text or "").strip()
    for fmt in ("%B %d, %Y", "%Y/%m/%d", "%Y/%m/%d %H:%M:%S", "%a %b %d %H:%M:%S %Y", "%Y-%m-%d"):
        for candidate in (text, re.sub(r"\s+[A-Z]{2,4}$", "", text)):                 # trailing zone such as WIB
            try:
                return datetime.strptime(candidate, fmt).date()
            except ValueError:
                continue
    return None


def _licenses(lines: list[str]) -> tuple[list[dict[str, str]], str]:
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    today = ""
    for line in lines:
        text = line.strip()
        if text.startswith("Current GMT Date:"):
            today = text.split(":", 1)[1].strip()
        elif text.startswith("License entry"):
            current = {}
            entries.append(current)
        elif current is not None and ":" in text:
            key, value = text.split(":", 1)
            current[key.strip()] = value.strip()
    return entries, today


def _number(text: str) -> int | None:
    match = re.search(r"-?\d[\d,]*", text or "")
    return int(match.group(0).replace(",", "")) if match else None


def _labelled(lines: list[str]) -> dict[str, str]:
    """``Label:     value`` / ``Label            : value`` lines (show session info)."""
    out: dict[str, str] = {}
    for line in lines:
        match = re.match(r"^\s*(.+?)\s*:\s{1,}(\S.*)$", line)
        if match and not line.strip().startswith("-"):
            out.setdefault(match.group(1).strip(), match.group(2).strip())
    return out


_UNIT = {"KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3, "TiB": 1024 ** 4, "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3}


def _resources(lines: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {"processes": []}
    for line in lines:
        text = line.strip()
        top = re.match(r"^top - (\S+) up (.+?),\s+\d+ users?,\s+load average: ([\d.]+), ([\d.]+), ([\d.]+)", text)
        if top:
            out.update(clock=top.group(1), uptime=top.group(2).strip(), load=(float(top.group(3)), float(top.group(4)), float(top.group(5))))
            continue
        tasks = re.match(r"^Tasks:\s*(\d+) total,\s*(\d+) running,\s*(\d+) sleeping,\s*(\d+) stopped,\s*(\d+) zombie", text)
        if tasks:
            out["tasks"] = {"total": int(tasks.group(1)), "running": int(tasks.group(2)), "stopped": int(tasks.group(4)), "zombie": int(tasks.group(5))}
            continue
        cpu = re.match(r"^%Cpu\(s\):(.*)$", text)
        if cpu:
            parts = {m.group(2): float(m.group(1)) for m in re.finditer(r"([\d.]+)\s+(us|sy|ni|id|wa|hi|si|st)\b", cpu.group(1))}
            out["cpu"] = parts
            continue
        mem = re.match(r"^(?:KiB|MiB|GiB) (Mem|Swap)\s*:(.*)$", text)
        if mem:
            unit = _UNIT.get(text.split()[0], 1024)
            values = {m.group(2): float(m.group(1)) * unit for m in re.finditer(r"([\d.]+)\s+(total|free|used|buff/cache|avail Mem)", mem.group(2))}
            out["memory" if mem.group(1) == "Mem" else "swap"] = values
            continue
        proc = re.match(r"^(\d+)\s+(?:(\S+)\s+)?(-?\w+)\s+(-?\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([A-Z])\s+([\d.]+)\s+([\d.]+)\s+(\S+)\s+(.+)$", text)
        if proc:
            out["processes"].append({"pid": int(proc.group(1)), "user": proc.group(2) or "", "res_kb": int(proc.group(6)), "cpu": float(proc.group(9)), "mem": float(proc.group(10)), "command": proc.group(12).strip()})
    return out


def _ha(lines: list[str]) -> dict[str, Any]:
    text = "\n".join(lines)
    if re.search(r"HA not enabled", text, re.I):
        return {"enabled": False}
    out: dict[str, Any] = {"enabled": True, "pairs": []}
    scope = ""
    for line in lines:
        stripped = line.strip()
        if stripped.endswith("Information:") or stripped.endswith("information:"):
            scope = stripped.split()[0].lower()
            continue
        match = re.match(r"^([A-Za-z][A-Za-z0-9 /().\-]*?):\s*(.*)$", stripped)
        if match:
            label = (scope + " " if scope in ("local", "peer") else "") + match.group(1).strip()
            out["pairs"].append((label, match.group(2).strip()))
    return out


def _hw_state(text: str) -> tuple[str, str, str, str]:
    match = re.match(r"^([^/]+)/([^/]+)/(\w+)(?:\(([^)]*)\))?$", text)
    return (match.group(1), match.group(2), match.group(3), match.group(4) or "") if match else ("", "", text, "")


_LOGICAL = re.compile(r"^(?P<name>\S+)\s+(?P<id>\d+)\s+(?P<vsys>\d+)\s+(?P<zone>.*?)\s+(?P<fwd>\S+)\s+(?P<tag>\d+)\s+(?P<addr>.*)$")


def _interfaces(lines: list[str]) -> list[dict[str, Any]]:
    hardware: dict[str, dict[str, str]] = {}
    logical: list[dict[str, Any]] = []
    mode = ""
    last: dict[str, Any] | None = None
    for line in lines:
        text = line.strip()
        if text.startswith("name") and "speed/duplex/state" in text:
            mode = "hw"
            continue
        if text.startswith("name") and "forwarding" in text:
            mode = "logical"
            continue
        if not text or set(text) <= {"-", " "}:
            continue
        if text.startswith(("total configured", "aggregation groups")):
            mode = ""
            continue
        if mode == "hw":
            parts = text.split()
            if len(parts) >= 4:
                hardware[parts[0]] = {"id": parts[1], "state": parts[2], "mac": parts[3]}
        elif mode == "logical":
            match = _LOGICAL.match(line)
            if match:
                last = {"name": match.group("name"), "zone": match.group("zone").strip(), "forwarding": match.group("fwd"), "tag": int(match.group("tag")), "addresses": [], "vsys": match.group("vsys")}
                if match.group("addr").strip().upper() != "N/A":
                    last["addresses"].append(match.group("addr").strip())
                logical.append(last)
            elif last is not None and re.match(r"^[0-9a-fA-F.:]+(/\d+)?$", text):
                last["addresses"].append(text)                                              # secondary address on its own line
    by_name = {row["name"]: row for row in logical}
    rows: list[dict[str, Any]] = []
    for name, hw in hardware.items():
        speed, duplex, state, reason = _hw_state(hw["state"])
        row = by_name.pop(name, {})
        rows.append({"name": name, "speed": speed, "duplex": duplex, "state": state, "reason": reason, "mac": hw["mac"], "zone": row.get("zone", ""), "forwarding": row.get("forwarding", ""), "addresses": row.get("addresses", []), "tag": row.get("tag", 0), "kind": "hardware"})
    for name, row in by_name.items():                                                       # tunnel.1, ethernet1/1.100 ... exist only in the logical table
        rows.append({"name": name, "speed": "", "duplex": "", "state": "", "reason": "", "mac": "", "zone": row["zone"], "forwarding": row["forwarding"], "addresses": row["addresses"], "tag": row["tag"], "kind": "logical"})
    return rows


def _management(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        text = line.strip()
        match = re.match(r"^Runtime link speed/duplex/state:\s*(\S+)", text)
        if match:
            out["link"] = match.group(1)
        match = re.match(r"^(Ip address|Netmask|Default gateway|Ipv6 address|Ipv6 link local address|Ipv6 default gateway):\s*(.*)$", text)
        if match:
            out[match.group(1).lower()] = match.group(2).strip()
        match = re.match(r"^(receive errors|transmit errors|receive packets dropped|transmit packets dropped|bytes received|bytes transmitted)\s+(\d+)$", text)
        if match:
            out[match.group(1)] = match.group(2)
    return out


def _routes(lines: list[str]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    vr, vr_id = "", ""
    for line in lines:
        text = line.strip()
        header = re.match(r"^VIRTUAL ROUTER:\s*(\S+)(?:\s+\(id\s+(\d+)\))?", text)
        if header:
            vr, vr_id = header.group(1), header.group(2) or ""
            continue
        if not vr or not text or text.startswith(("destination", "total routes", "=", "flags")):
            continue
        parts = text.split()
        if len(parts) < 4 or not re.match(r"^[0-9a-fA-F:.]+(/\d+)?$", parts[0]) or not parts[2].isdigit():
            continue
        rest = parts[3:]
        flags = []
        while rest and rest[0] in _ROUTE_FLAGS:
            flags.append(rest.pop(0))
        age = rest.pop(0) if rest and re.match(r"^[\d:]+[dhms]?$", rest[0]) else ""
        interface = rest[0] if rest else ""
        routes.append({"vr": vr, "vr_id": vr_id, "destination": parts[0], "nexthop": parts[1], "metric": int(parts[2]), "flags": " ".join(flags), "age": age, "interface": interface})
    return routes


def _arp(lines: list[str]) -> dict[str, Any]:
    rows = []
    for line in lines:
        match = re.match(r"^(\S+)\s+([0-9a-fA-F.:]+)\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2}|\(incomplete\))\s+(\S+)?\s+([scei])\s+(\d+)\s*$", line.strip(), re.I)
        if match:
            rows.append({"interface": match.group(1), "ip": match.group(2), "mac": match.group(3), "port": match.group(4) or "", "status": match.group(5).lower(), "ttl": int(match.group(6))})
    total = next((_number(line.split(":", 1)[1]) for line in lines if line.strip().startswith("total ARP entries in table")), None)
    return {"rows": rows, "total": total if total is not None else len(rows)}


def _disk(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 6 and parts[4].endswith("%") and parts[4][:-1].isdigit():
            rows.append({"filesystem": parts[0], "size": parts[1], "used": parts[2], "avail": parts[3], "pct": int(parts[4][:-1]), "mount": parts[5]})
    return rows


def _software(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        match = re.match(r"^(\d+\.\d+\.\d+(?:-h\d+)?)\s+(\d+\w+)\s+(\d{4}/\d\d/\d\d)\s+(\S+)\s+(yes|no)\s*$", line.strip())
        if match:
            rows.append({"version": match.group(1), "size": match.group(2), "released": match.group(3), "downloaded": match.group(5) == "yes"})
    return rows


def _processes(lines: list[str]) -> list[dict[str, Any]]:
    rows, slot = [], ""
    for line in lines:
        header = re.match(r"^Slot\s+(\d+),\s*Role\s+(\S+)", line.strip())
        if header:
            slot = f"slot {header.group(1)} ({header.group(2)})"
            continue
        match = re.match(r"^(Group|Process)\s+(\S+)\s+(\S+)\s*(.*)$", line.strip())
        if match:
            pid = re.search(r"pid:\s*(\d+)", match.group(4))
            rows.append({"slot": slot, "type": match.group(1), "name": match.group(2), "state": match.group(3), "pid": pid.group(1) if pid else ""})
    return rows


def _jobs(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        match = re.match(r"^(\d{4}/\d\d/\d\d)\s+(\d\d:\d\d:\d\d)\s+(\d\d:\d\d:\d\d)?\s*(\d+)\s+(.*)$", line.strip())
        if not match:
            continue
        tokens = match.group(5).split()
        completed = tokens.pop() if tokens and re.match(r"^\d\d:\d\d:\d\d$", tokens[-1]) else ""
        result = tokens.pop() if tokens else ""
        status = tokens.pop() if tokens else ""
        job_type = tokens.pop() if tokens else ""
        rows.append({"enqueued": f"{match.group(1)} {match.group(2)}", "id": int(match.group(4)), "type": job_type, "status": status, "result": result, "completed": completed, "date": _parse_date(match.group(1))})
    return rows


# ------------------------------------------------------------------------------------------------ gathering
COMMANDS = (
    ("system_info", "show system info"), ("license", "request license info"), ("support", "request support check"), ("session", "show session info"),
    ("resources", "show system resources"), ("ha", "show high-availability all"), ("ha_state", "show high-availability state"), ("interfaces", "show interface all"),
    ("management", "show interface management"), ("routes", "show routing route"), ("arp", "show arp all"), ("mac", "show mac all"), ("disk", "show system disk-space"),
    ("software", "request system software info"), ("processes", "show system software status"), ("jobs", "show jobs all"),
)
_ERROR_LINE = re.compile(r"^(Invalid syntax|Unknown command|Server error|Error:|Failed|% )", re.I)


def gather(text: str) -> dict[str, Any]:
    """Replay the terminal log, split it into one block per command and parse each block.  Keys are absent for commands that were not run."""
    rendered = render(text)
    capture: Capture = split_capture(rendered, (PANOS_PROMPT,), min_prompt_repeats=2)
    out: dict[str, Any] = {"capture": capture, "errors": {}, "lines": {}}
    for key, command in COMMANDS:
        block = capture.first(command)
        if block is None:
            continue
        lines = block.lines
        out["lines"][key] = len(lines)
        first_error = next((line.strip() for line in lines[:3] if _ERROR_LINE.match(line.strip())), "")
        if first_error and key != "support":
            out["errors"][key] = first_error
            continue
        if key == "system_info":
            out["info"] = _kv(lines)
        elif key == "license":
            out["licenses"], out["license_date"] = _licenses(lines)
        elif key == "support":
            out["support"] = first_error or " ".join(line.strip() for line in lines if line.strip())
        elif key == "session":
            out["session"] = _labelled(lines)
        elif key == "resources":
            out["resources"] = _resources(lines)
        elif key == "ha":
            out["ha"] = _ha(lines)
        elif key == "ha_state" and "ha" not in out:
            out["ha"] = _ha(lines)
        elif key == "interfaces":
            out["interfaces"] = _interfaces(lines)
        elif key == "management":
            out["management"] = _management(lines)
        elif key == "routes":
            out["routes"] = _routes(lines)
        elif key == "arp":
            out["arp"] = _arp(lines)
        elif key == "mac":
            out["mac_entries"] = next((_number(line.split(":", 1)[1]) for line in lines if line.strip().startswith("total MAC entries in table")), 0)
        elif key == "disk":
            out["disk"] = _disk(lines)
        elif key == "software":
            out["software"] = _software(lines)
        elif key == "processes":
            out["processes"] = _processes(lines)
        elif key == "jobs":
            out["jobs"] = _jobs(lines)
    info = out.get("info", {})
    out["hostname"] = info.get("hostname") or capture.hostname()
    out["now"] = _parse_date(info.get("time", "")) or _parse_date(out.get("license_date", ""))
    return out


# ------------------------------------------------------------------------------------------------ analysis
def _age_days(stamp: str, now: date | None) -> int | None:
    parsed = _parse_date(stamp)
    return (now - parsed).days if parsed and now else None


def _years(days: int) -> str:
    return f"{days / 365.25:.1f} years" if days >= 365 else f"{days} days"


def _content_rows(info: dict[str, str], now: date | None) -> list[dict[str, Any]]:
    rows = []
    for label, vkey, dkey in (("Applications and Threats (app)", "app-version", "app-release-date"), ("Antivirus", "av-version", "av-release-date"), ("Threats (threat)", "threat-version", "threat-release-date"),
                              ("WildFire", "wildfire-version", "wildfire-release-date"), ("WildFire private", "wf-private-version", "wf-private-release-date"), ("URL filtering database", "url-filtering-version", "")):
        if vkey not in info:
            continue
        version, released = info.get(vkey, ""), info.get(dkey, "") if dkey else ""
        never = version.strip().lower() in panos_runtime.ZERO
        age = None if never else _age_days(released, now)
        tone = "warn" if never else ("bad" if age is not None and age > 365 else "warn" if age is not None and age > 90 else "ok" if age is not None else "")
        rows.append({"content": label, "version": version, "released": "never installed" if never else released, "age": "" if age is None else _years(age), "_tone": tone})
    return rows


def evaluate(rt: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    info, now = rt.get("info", {}), rt.get("now")
    when = now.isoformat() if now else "the capture"
    model, version = info.get("model", ""), info.get("sw-version", "")

    # --- licences ------------------------------------------------------------------------------------------------
    for entry in rt.get("licenses", []):
        feature = entry.get("Feature", "licence")
        expires = _parse_date(entry.get("Expires", ""))
        flagged = entry.get("Expired?", "").lower() == "yes" or (expires is not None and now is not None and expires < now)
        if flagged:
            since = (now - expires).days if expires and now else None
            high = "threat" in feature.lower() or "advanced" in feature.lower()
            detail = f"{feature} expired on {entry.get('Expires', 'an unknown date')}" + (f", {_years(since)} before {when}" if since else "") + ". "
            if "threat" in feature.lower():
                detail += "Signatures that were installed stay active, but no new signatures can be installed or rolled back, and installing an Applications-only content update deletes the existing threat signatures."
            elif "url" in feature.lower():
                detail += "Custom URL categories still work; the PAN-DB category lookup, cache updates and cloud analysis stop, so category-based URL rules lose their data."
            else:
                detail += "The licensed capability stops working or stops receiving updates."
            out.append(finding("PAN-RTC-001", "high" if high else "medium", "Licensing", f"{feature} licence expired", obj=entry.get("Description") or feature, detail=detail,
                               recommendation="Renew the subscription in the Customer Support Portal and retrieve the keys (Device > Licenses > Retrieve license keys from license server, or 'request license fetch'), then Check Now under Device > Dynamic Updates. If the unit is being retired, remove the dependent profiles from the rules instead of leaving them in place.",
                               reference=PALO["license_expiry"]))
        elif expires and now and 0 <= (expires - now).days <= 60:
            out.append(finding("PAN-RTC-002", "medium", "Licensing", f"{feature} licence expires in {(expires - now).days} days", obj=feature, detail=f"Expires {entry.get('Expires')}; the capture is dated {when}.",
                               recommendation="Renew before expiry so content updates do not lapse.", reference=PALO["activate_licenses"]))

    # --- content ---------------------------------------------------------------------------------------------------
    for row in _content_rows(info, now):
        if row["released"] == "never installed":
            if row["content"].startswith("Threats"):
                out.append(finding("PAN-RTC-003", "medium", "Content updates", "Threat content was never installed", obj="show system info", detail=f"threat-version is {row['version']}: this unit has no vulnerability or spyware signatures, so Vulnerability Protection and Anti-Spyware profiles inspect nothing.",
                                   recommendation="Needs an active Threat Prevention licence; then Device > Dynamic Updates > Check Now > download and install 'Applications and Threats'.", reference=PALO["content_updates"]))
            continue
        days = _age_days(row["released"], now)
        if days is None or days <= 90:
            continue
        severity = "high" if days > 365 and row["content"] in ("Antivirus", "Threats (threat)", "Applications and Threats (app)") else "medium"
        out.append(finding("PAN-RTC-004", severity, "Content updates", f"{row['content']} content is {_years(days)} old", obj=f"{row['content']} {row['version']}",
                           detail=f"Installed version {row['version']} was released {row['released']}; the capture is dated {when}. New malware families and applications released since are invisible to the policy. Palo Alto's guidance is weekly Applications and Threats and daily Antivirus.",
                           recommendation="Restore the update path first (service route, DNS, licence), then schedule Device > Dynamic Updates: Applications and Threats weekly, Antivirus daily, with a short threshold on Applications to let new App-IDs be reviewed.", reference=PALO["content_updates"]))

    # --- connectivity to the Palo Alto cloud -------------------------------------------------------------
    support = rt.get("support", "")
    if support and re.search(r"error|fail", support, re.I):
        mgmt = rt.get("management", {})
        out.append(finding("PAN-RTC-005", "medium", "Management plane", "The firewall cannot reach the Palo Alto support/update servers", obj="request support check", detail=f"'{support[:200]}'. Licence retrieval, content and software downloads all use the same path. "
                           + (f"Management interface {mgmt.get('ip address', 'n/a')} gateway {mgmt.get('default gateway', 'n/a')}." if mgmt else ""),
                           recommendation="Check the management default gateway and DNS (Device > Setup > Services), then the service routes (Device > Setup > Services > Service Route Configuration) if the data plane is meant to carry update traffic; allow updates.paloaltonetworks.com and the licence server outbound.", reference=PALO["service_routes"]))
    newest = max((_parse_date(row["released"]) for row in rt.get("software", []) if _parse_date(row["released"])), default=None)
    if newest and now and (now - newest).days > 400:
        out.append(finding("PAN-RTC-006", "low", "Content updates", "The software catalogue on the unit has not been refreshed for years", obj="request system software info",
                           detail=f"The newest PAN-OS release the unit knows about was published {newest.isoformat()}, {_years((now - newest).days)} before {when}; a unit that can reach the update server lists everything current. Together with the failing support check this means 'Check Now' has not succeeded since then.",
                           recommendation="Fix connectivity, run Device > Software > Check Now, and use the catalogue to plan the upgrade path.", reference=PALO["content_updates"]))

    # --- lifecycle ------------------------------------------------------------------------------------------------
    train = ".".join(version.split(".")[:2]) if version else ""
    if train in SOFTWARE_EOL and now and SOFTWARE_EOL[train] < now:
        days = (now - SOFTWARE_EOL[train]).days
        out.append(finding("PAN-RTC-007", "high", "Lifecycle", f"PAN-OS {train} is end-of-life", obj=f"PAN-OS {version}", detail=f"PAN-OS {train} reached end-of-life on {SOFTWARE_EOL[train].isoformat()}, {_years(days)} before {when}. It receives no security fixes, so every PAN-OS vulnerability published since affects this unit with no patch available."
                           + (" PAN-OS 9.1 is the last release this hardware supports and is itself end-of-life." if model in HARDWARE_EOL else ""),
                           recommendation="Plan a hardware refresh together with the software move; a supported train needs a supported platform. Until then restrict management-plane exposure (permitted IPs, no GlobalProtect/management profile on untrusted interfaces).", reference=PALO["eol_software"]))
    if model in HARDWARE_EOL and now:
        sale, eol, family, successor = HARDWARE_EOL[model]
        if eol < now:
            out.append(finding("PAN-RTC-008", "medium", "Lifecycle", f"{model} hardware is past end-of-life", obj=model, detail=f"{family}: end-of-sale {sale.isoformat()}, end-of-life {eol.isoformat()} ({_years((now - eol).days)} before {when}). Hardware replacement under support is no longer available; recommended replacement: {successor}.",
                               recommendation="Budget the replacement; a firewall that carries the production Internet edge needs hardware that can be replaced on a support contract.", reference=PALO["eol_hardware"]))

    # --- availability -----------------------------------------------------------------------------------------------
    ha = rt.get("ha")
    if ha is not None and not ha.get("enabled"):
        out.append(finding("PAN-RTC-009", "medium", "High availability", "High availability is not enabled", obj="show high-availability all", detail="'HA not enabled'. A single unit is a single point of failure for every zone behind it, and a software upgrade or reboot means an outage.",
                           recommendation="Where the service requires it, deploy an active/passive pair with link and path monitoring (the dedicated HA1/HA2 ports are already on this chassis).", reference=PALO["ha_config"]))
    elif ha and ha.get("enabled"):
        pairs = dict(ha["pairs"])
        for key, value in pairs.items():
            if re.search(r"running config|app version|threat version|av version|url version|gp version", key, re.I) and "synchronized" not in value.lower() and "match" not in value.lower():
                out.append(finding("PAN-RTC-010", "medium", "High availability", f"HA peers differ: {key}", obj=key, detail=f"{key}: {value}.", recommendation="Synchronise configuration and content before relying on failover.", reference=PALO["ha_config"]))
            if re.search(r"connection status", key, re.I) and value.lower() not in ("up", "connected"):
                out.append(finding("PAN-RTC-011", "high", "High availability", "HA peer connection is not up", obj=key, detail=f"{key}: {value}.", recommendation="Check HA1/HA2 cabling and the HA1 backup link; a split pair can both go active.", reference=PALO["ha_failover"]))

    # --- platform health --------------------------------------------------------------------------------------------
    for row in rt.get("disk", []):
        if row["mount"] == "/" and row["pct"] >= 80:
            severity = "high" if row["pct"] >= 90 else "medium"
            out.append(finding("PAN-RTC-012", severity, "Platform health", f"Root filesystem is {row['pct']}% full", obj=f"{row['filesystem']} on /", detail=f"{row['used']} of {row['size']} used, {row['avail']} free. Palo Alto raises its disk alarm and starts truncating logs at 95%; a full root partition breaks commits, software installs and content updates.",
                               recommendation="Remove rotated logs and cores (show system files, delete core ..., delete debug-log ...), follow the 'High Disk Space Usage on / root partition' KB, and remove unused software images (delete software version ...).", reference=PALO["root_disk"]))
        elif row["pct"] >= 90 and row["mount"] != "/":
            out.append(finding("PAN-RTC-013", "medium", "Platform health", f"{row['mount']} is {row['pct']}% full", obj=row["mount"], detail=f"{row['used']} of {row['size']} used.", recommendation="Review log retention and quotas for this partition.", reference=PALO["root_disk"]))
    res = rt.get("resources", {})
    swap, mem = res.get("swap"), res.get("memory")
    if swap and swap.get("total"):
        pct = swap.get("used", 0) / swap["total"] * 100
        top = sorted(res.get("processes", []), key=lambda p: -p["mem"])[:2]
        if pct >= 20:
            out.append(finding("PAN-RTC-014", "medium" if pct >= 50 else "low", "Platform health", f"Management plane swap is {pct:.0f}% used", obj="show system resources",
                               detail=f"{swap['used'] / 1024 ** 2:.0f} MiB of {swap['total'] / 1024 ** 2:.0f} MiB swap in use" + (("; largest consumers: " + ", ".join("%s %s%%" % (p["command"], p["mem"]) for p in top)) if top else "") + ". Swap use on a unit with free cache usually means a memory-heavy process (management server, log receiver) grew over a long uptime.",
                               recommendation="Watch the trend; a management-plane restart of the offending process in a maintenance window clears it, and a larger commit/log load on this model is the reason to plan a refresh.", reference=PALO["cli_device_mgmt"]))
    if mem and mem.get("avail Mem") is not None and mem.get("total") and mem["avail Mem"] / mem["total"] < 0.1:
        out.append(finding("PAN-RTC-015", "high", "Platform health", "Management plane memory is nearly exhausted", obj="show system resources", detail=f"Only {mem['avail Mem'] / mem['total'] * 100:.0f}% of memory is available.", recommendation="Identify the process in 'show system resources' and open a TAC case before the OOM killer restarts services.", reference=PALO["cli_device_mgmt"]))
    cpu = res.get("cpu", {})
    if cpu and cpu.get("id") is not None and cpu["id"] < 15:
        out.append(finding("PAN-RTC-016", "medium", "Platform health", f"Management plane CPU is {100 - cpu['id']:.0f}% busy", obj="show system resources", detail="Idle time under 15% in a single sample.", recommendation="Sample again over time; commits, reports and log queries are the usual cause.", reference=PALO["cli_device_mgmt"]))
    for row in rt.get("processes", []):
        if row["state"].lower() != "running":
            out.append(finding("PAN-RTC-017", "high", "Platform health", f"Process {row['name']} is {row['state']}", obj=f"{row['slot']} {row['name']}", detail=f"show system software status lists {row['type'].lower()} {row['name']} as '{row['state']}'.", recommendation="Check 'show system software status' again and the system log; restart with 'debug software restart process <name>' only with TAC guidance.", reference=PALO["cli_device_mgmt"]))
    sess = rt.get("session", {})
    util = _number(sess.get("Session table utilization", ""))
    if util is not None and util >= 60:
        out.append(finding("PAN-RTC-018", "high" if util >= 80 else "medium", "Capacity", f"Session table is {util}% utilised", obj="show session info", detail=f"{sess.get('Number of allocated sessions', '?')} of {sess.get('Number of sessions supported', '?')} sessions in use.", recommendation="Review session timeouts and top talkers; accelerated aging starts at 80%.", reference=PALO["cli_device_mgmt"]))

    # --- interfaces --------------------------------------------------------------------------------------------------
    configured_down = [row for row in rt.get("interfaces", []) if row["kind"] == "hardware" and row["state"] == "down" and (row["addresses"] or row["zone"])]
    if configured_down:
        out.append(finding("PAN-RTC-019", "medium", "Interfaces", f"{len(configured_down)} interface(s) carry an address or zone but have no link", obj=", ".join(row["name"] for row in configured_down),
                           detail="; ".join(f"{row['name']} {'/'.join(row['addresses']) or 'no IP'} in zone {row['zone'] or '-'} - {'port disabled (power-down)' if row['reason'] == 'power-down' else 'no carrier (' + (row['reason'] or 'down') + ')'}" for row in configured_down) + ". Routes and policy that point at them are inactive; a port in 'power-down' was shut in the interface settings.",
                           recommendation="Confirm each is intentionally idle. If it is a standby uplink, check the cabling and the far-end port; if retired, remove the address, zone membership and routes so the configuration matches reality.", reference=PALO["cli_networking"]))
    mgmt = rt.get("management", {})
    if mgmt and mgmt.get("link") and not mgmt["link"].endswith("/up"):
        out.append(finding("PAN-RTC-020", "high", "Interfaces", "Management interface has no link", obj="show interface management", detail=f"Runtime link: {mgmt['link']}.", recommendation="Check the cable and switch port.", reference=PALO["cli_networking"]))
    errors = {k: int(mgmt[k]) for k in ("receive errors", "transmit errors", "receive packets dropped", "transmit packets dropped") if mgmt.get(k, "").isdigit() and int(mgmt[k])}
    if errors:
        out.append(finding("PAN-RTC-021", "low", "Interfaces", "Management interface counters show errors or drops", obj="show interface management", detail=", ".join(f"{k} {v}" for k, v in errors.items()) + ".", recommendation="Check duplex and cabling.", reference=PALO["cli_networking"]))

    # --- routing / neighbours ------------------------------------------------------------------------------------
    routes = rt.get("routes", [])
    defaults = [r for r in routes if r["destination"] in ("0.0.0.0/0", "::/0")]
    by_vr: dict[str, list[dict[str, Any]]] = {}
    for row in rt.get("interfaces", []):
        match = re.match(r"vr:(\S+)", row["forwarding"])
        if match and row["zone"] and row["kind"] == "hardware" and row["state"] == "up":
            by_vr.setdefault(match.group(1), []).append(row)
    for vr, members in by_vr.items():
        wan = [m for m in members if re.search(r"inet|wan|isp|internet", m["zone"], re.I)]
        vr_defaults = [r for r in defaults if r["vr"] == vr]
        if len(wan) >= 2 and len(vr_defaults) == 1:
            out.append(finding("PAN-RTC-022", "info", "Routing", f"Virtual router {vr} has {len(wan)} Internet-facing links up but one default route", obj=vr,
                               detail=f"Up: {', '.join(m['name'] + ' (' + m['zone'] + ')' for m in wan)}. The only installed default route is via {vr_defaults[0]['interface']} ({vr_defaults[0]['nexthop']}). Other uplinks carry traffic only if policy-based forwarding or a floating route selects them - not visible in a runtime capture.",
                               recommendation="Confirm the intended design (PBF rule, ECMP or floating default with path monitoring); capture 'show config running' to verify.", reference=PALO["path_monitor"]))
    incomplete = [r for r in rt.get("arp", {}).get("rows", []) if r["status"] == "i"]
    if incomplete:
        out.append(finding("PAN-RTC-023", "medium", "Neighbours", f"{len(incomplete)} unresolved ARP entries", obj=", ".join(r["ip"] for r in incomplete[:6]), detail="Incomplete entries are next hops or hosts that did not answer ARP.", recommendation="Check the far end and VLAN/zone assignment.", reference=PALO["cli_networking"]))

    # --- jobs ------------------------------------------------------------------------------------------------------------
    failed = [j for j in rt.get("jobs", []) if j["result"].upper() in ("FAIL", "FAILED") or j["status"].upper() == "FAIL"]
    if failed:
        out.append(finding("PAN-RTC-024", "medium", "Operations", f"{len(failed)} failed job(s) in the job history", obj=", ".join(f"{j['type']} #{j['id']}" for j in failed[:6]), detail="; ".join(f"{j['type']} {j['enqueued']} -> {j['result']}" for j in failed[:6]), recommendation="Open the job details (show jobs id <n>) and the system log.", reference=PALO["cli_device_mgmt"]))
    return out


# ------------------------------------------------------------------------------------------------------------------ sections
def sections(rt: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    info, now = rt.get("info", {}), rt.get("now")
    out += panos_runtime.section(info)
    if rt.get("licenses") is not None:
        rows = []
        for entry in rt["licenses"]:
            expires = _parse_date(entry.get("Expires", ""))
            expired = entry.get("Expired?", "").lower() == "yes" or (expires is not None and now is not None and expires < now)
            left = (expires - now).days if expires and now else None
            rows.append({"feature": entry.get("Feature", ""), "issued": entry.get("Issued", ""), "expires": entry.get("Expires", ""), "state": "expired" if expired else "active", "days": "" if left is None else left,
                         "_tones": {"state": "bad" if expired else "warn" if left is not None and left <= 60 else "ok"}})
        out.append(table_section("licenses", "Licences (request license info)", [("feature", "Feature"), ("issued", "Issued"), ("expires", "Expires"), ("state", "State", "status"), ("days", "Days left", "num")], rows, group="System",
                                 hint=f"Dated against the capture ({now.isoformat() if now else 'unknown date'}), not today. An expired licence keeps the installed signatures but stops all updates.", empty="No licences are installed.", facets=[{"key": "state", "label": "state"}]))
    content = _content_rows(info, now)
    if content:
        out.append(table_section("content_age", "Content versions and age", [("content", "Content"), ("version", "Version", "mono"), ("released", "Released"), ("age", "Age")], content, group="System",
                                 hint="Applications and Threats is normally weekly, Antivirus daily. Age is measured to the capture date."))
    res = rt.get("resources")
    if res:
        pairs = []
        if res.get("load"):
            pairs.append(("Load average (1/5/15 min)", " / ".join(f"{v:.2f}" for v in res["load"])))
        if res.get("cpu"):
            pairs.append(("CPU idle", f"{res['cpu'].get('id', 0):.1f}%", "warn" if res["cpu"].get("id", 100) < 15 else ""))
        if res.get("tasks"):
            pairs.append(("Tasks", f"{res['tasks']['total']} total, {res['tasks']['running']} running, {res['tasks']['zombie']} zombie"))
        mem, swap = res.get("memory"), res.get("swap")
        if mem and mem.get("total"):
            pairs.append(("Memory used / available", f"{mem.get('used', 0) / 1024 ** 3:.2f} GiB of {mem['total'] / 1024 ** 3:.2f} GiB; {mem.get('avail Mem', 0) / mem['total'] * 100:.0f}% available"))
        if swap and swap.get("total"):
            pct = swap.get("used", 0) / swap["total"] * 100
            pairs.append(("Swap used", f"{swap['used'] / 1024 ** 2:.0f} MiB of {swap['total'] / 1024 ** 2:.0f} MiB ({pct:.0f}%)", "warn" if pct >= 20 else ""))
        out.append(kv_section("resources", "Management plane resources", pairs, group="System", hint="From 'show system resources'. This is the management plane only; the data plane has its own counters ('show running resource-monitor')."))
        top = sorted(res.get("processes", []), key=lambda p: -p["mem"])[:10]
        out.append(table_section("top_processes", "Top management-plane processes by memory", [("command", "Process", "mono"), ("pid", "PID", "num"), ("mem", "% memory", "num"), ("cpu", "% CPU", "num"), ("res_mb", "Resident MiB", "num")],
                                 [dict(p, res_mb=round(p["res_kb"] / 1024)) for p in top], group="System"))
    if rt.get("disk"):
        out.append(table_section("disk", "Disk space", [("mount", "Mounted on", "mono"), ("filesystem", "Filesystem", "mono"), ("size", "Size"), ("used", "Used"), ("avail", "Free"), ("pct", "Use %", "num")],
                                 [dict(r, _tones={"pct": "bad" if r["pct"] >= 90 else "warn" if r["pct"] >= 80 else "ok"}) for r in rt["disk"]], group="System", hint="From 'show system disk-space'. Palo Alto's disk alarm is at 95%."))
    if rt.get("software"):
        info_sw = info.get("sw-version", "")
        out.append(table_section("software_images", "Software images known to the unit", [("version", "Version", "mono"), ("size", "Size"), ("released", "Released"), ("downloaded", "On disk", "status"), ("running", "Running", "status")],
                                 [dict(r, running="yes" if r["version"] == info_sw else "", downloaded="yes" if r["downloaded"] else "no", _tone="info" if r["version"] == info_sw else "") for r in rt["software"]], group="System", page_size=50,
                                 hint="From 'request system software info'. This is the unit's own catalogue: if the newest entry is years old, the unit has not been able to check for updates."))
    if rt.get("processes"):
        rows = [dict(r, _tone="bad" if r["state"].lower() != "running" else "") for r in rt["processes"]]
        counts = Counter(r["state"] for r in rt["processes"])
        out.append(table_section("services", f"Software processes ({', '.join(f'{n} {s}' for s, n in counts.items())})", [("slot", "Slot"), ("type", "Type"), ("name", "Name", "mono"), ("state", "State", "status"), ("pid", "PID", "num")], rows, group="System", page_size=60, facets=[{"key": "state", "label": "state"}]))
    if rt.get("jobs"):
        out.append(table_section("jobs", "Job history (show jobs all)", [("enqueued", "Enqueued"), ("id", "ID", "num"), ("type", "Type"), ("status", "Status", "status"), ("result", "Result", "status"), ("completed", "Completed")],
                                 [dict(j, _tones={"result": "ok" if j["result"].upper() == "OK" else "bad"}) for j in rt["jobs"]], group="System", page_size=50, facets=[{"key": "status", "label": "status"}, {"key": "result", "label": "result"}]))
    ifaces = rt.get("interfaces")
    if ifaces is not None:
        rows = []
        for r in ifaces:
            tone = "bad" if r["state"] == "down" and (r["addresses"] or r["zone"]) else "mute" if r["state"] == "down" else ""
            rows.append({"name": r["name"], "state": r["state"] or "-", "speed": "/".join(x for x in (r["speed"], r["duplex"]) if x), "reason": r["reason"], "zone": r["zone"], "vr": (r["forwarding"] or "").replace("vr:", ""), "addresses": r["addresses"], "mac": r["mac"],
                         "_tones": {"state": "ok" if r["state"] == "up" else "bad" if tone == "bad" else "mute" if r["state"] == "down" else ""}})
        out.append(table_section("interfaces_live", "Interfaces (show interface all)", [("name", "Interface", "mono"), ("state", "Link", "status"), ("speed", "Speed/duplex"), ("reason", "Reason"), ("zone", "Zone"), ("vr", "Virtual router"), ("addresses", "Addresses", "list"), ("mac", "MAC", "mono")],
                                 rows, group="Interfaces", page_size=100, hint="Link state is what the port reported at capture time. 'power-down' means the port was disabled in the interface settings; 'autoneg' means it is enabled but no carrier.", facets=[{"key": "state", "label": "link", "order": ["up", "down"]}]))
    mgmt = rt.get("management")
    if mgmt:
        out.append(kv_section("mgmt_interface", "Management interface", [(k.title(), v) for k, v in mgmt.items()], group="Interfaces"))
    routes = rt.get("routes")
    if routes is not None:
        vrs: dict[str, dict[str, Any]] = {}
        for r in routes:
            row = vrs.setdefault(r["vr"], {"vr": r["vr"], "id": r["vr_id"], "routes": 0, "static": 0, "connected": 0, "default": ""})
            row["routes"] += 1
            row["static"] += "S" in r["flags"].split()
            row["connected"] += "C" in r["flags"].split()
            if r["destination"] in ("0.0.0.0/0", "::/0"):
                row["default"] = f"{r['nexthop']} via {r['interface']}"
        out.append(table_section("virtual_routers", "Virtual routers", [("vr", "Virtual router", "mono"), ("id", "ID", "num"), ("routes", "Active routes", "num"), ("static", "Static", "num"), ("connected", "Connected", "num"), ("default", "Default route", "mono")],
                                 [dict(v, _tone="" if v["default"] else "mute") for v in vrs.values()], group="Routing"))
        out.append(table_section("routes_runtime", "Routing table (show routing route)", [("vr", "Virtual router", "mono"), ("destination", "Destination", "mono"), ("nexthop", "Next hop", "mono"), ("metric", "Metric", "num"), ("flags", "Flags"), ("interface", "Interface", "mono")],
                                 [dict(r, _tone="info" if r["destination"] in ("0.0.0.0/0", "::/0") else "") for r in routes], group="Routing", page_size=100, hint="Active routes only (flag A). S static, C connected, H host."))
    arp = rt.get("arp")
    if arp is not None:
        out.append(table_section("arp", f"ARP table ({arp['total']} entries)", [("interface", "Interface", "mono"), ("ip", "IP", "mono"), ("mac", "MAC", "mono"), ("status", "Status", "status"), ("ttl", "TTL", "num")],
                                 [dict(r, status={"c": "complete", "s": "static", "e": "expiring", "i": "incomplete"}.get(r["status"], r["status"]), _tones={"status": "bad" if r["status"] == "i" else "ok"}) for r in arp["rows"]], group="Live state", facets=[{"key": "status", "label": "status"}]))
    session = rt.get("session")
    if session:
        keys = ("Number of sessions supported", "Number of allocated sessions", "Number of active TCP sessions", "Number of active UDP sessions", "Number of active ICMP sessions", "Session table utilization", "Packet rate", "Throughput", "New connection establish rate", "Number of sessions created since bootup", "Hardware session offloading", "Session accelerated aging")
        out.append(kv_section("sessions", "Session table (show session info)", [(k, session[k]) for k in keys if k in session], group="Live state"))
    ha = rt.get("ha")
    if ha is not None:
        pairs = [("High availability", "enabled" if ha.get("enabled") else "not enabled", "" if ha.get("enabled") else "warn")] + [(k, v) for k, v in ha.get("pairs", [])]
        out.append(kv_section("ha_runtime", "High availability", pairs, group="Live state"))
    if rt.get("support"):
        out.append(kv_section("support_check", "Support check (request support check)", [("Result", rt["support"], "warn")], group="System"))
    return out


def _cards(rt: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    info, now = rt.get("info", {}), rt.get("now")
    cards = [card("Platform", info.get("model", "PAN-OS"), "info", f"PAN-OS {info.get('sw-version', '?')} · up {info.get('uptime', '?')}", "runtime_identity")]
    lic = rt.get("licenses")
    if lic is not None:
        expired = [e for e in lic if e.get("Expired?", "").lower() == "yes"]
        cards.append(card("Licences", f"{len(lic) - len(expired)}/{len(lic)} active" if lic else "none", "bad" if expired or not lic else "ok", f"{len(expired)} expired" if expired else "", "licenses"))
    ifaces = [r for r in rt.get("interfaces", []) if r["kind"] == "hardware" and r["name"].startswith(("ethernet", "ae"))]
    if ifaces:
        up = sum(r["state"] == "up" for r in ifaces)
        cards.append(card("Ports up", f"{up}/{len(ifaces)}", "info", "physical data ports", "interfaces_live"))
    util = _number(rt.get("session", {}).get("Session table utilization", ""))
    if util is not None:
        cards.append(card("Session table", f"{util}%", "bad" if util >= 80 else "warn" if util >= 60 else "ok", rt["session"].get("Packet rate", ""), "sessions"))
    root = next((r for r in rt.get("disk", []) if r["mount"] == "/"), None)
    if root:
        cards.append(card("Root disk", f"{root['pct']}%", "bad" if root["pct"] >= 90 else "warn" if root["pct"] >= 80 else "ok", f"{root['avail']} free", "disk"))
    ha = rt.get("ha")
    if ha is not None:
        cards.append(card("HA", "enabled" if ha.get("enabled") else "off", "ok" if ha.get("enabled") else "warn", "", "ha_runtime"))
    counts = severity_counts(findings)
    cards.append(card("High findings", counts["high"], "bad" if counts["high"] else "ok", "", "findings"))
    cards.append(card("Medium findings", counts["medium"], "warn" if counts["medium"] else "ok", f"{counts['low']} low · {counts['info']} info", "findings"))
    return cards


def _coverage(rt: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key, command in COMMANDS:
        if key == "ha_state" and "ha" in rt and "ha" in rt["lines"]:
            continue
        if key in rt["errors"]:
            rows.append({"command": command, "status": "rejected", "lines": rt["lines"].get(key, 0), "note": f"The device answered '{rt['errors'][key]}'.", "tone": "warn"})
        elif key in rt["lines"]:
            rows.append({"command": command, "status": "analyzed", "lines": rt["lines"][key], "note": "", "tone": "ok"})
        elif key in ("system_info", "license", "interfaces", "routes", "disk", "ha"):
            rows.append({"command": command, "status": "missing", "lines": 0, "note": "Not in this capture.", "tone": "warn"})
    known = [command for _, command in COMMANDS]
    for block in rt["capture"].blocks:
        if any(command_matches(block.norm, command) is not None for command in known):
            continue
        first = next((line.strip() for line in block.lines[:3] if line.strip()), "")
        if _ERROR_LINE.match(first):
            rows.append({"command": block.command, "status": "rejected", "lines": len(block.lines), "note": f"The device answered '{first}'.", "tone": "warn"})
        else:
            rows.append({"command": block.command, "status": "not analyzed", "lines": len(block.lines), "note": "Output kept in the capture; no analysis is written for this command yet.", "tone": "info"})
    rows.append({"command": "show config running", "status": "missing", "lines": 0, "note": "Add it to analyze security rules, NAT, VPN, profiles and administrators - a runtime capture cannot show policy.", "tone": "info"})
    rows.append({"command": "show running resource-monitor", "status": "missing", "lines": 0, "note": "Add it for data-plane CPU; 'show system resources' is the management plane only.", "tone": "info"})
    return rows


def analyze(content: str, filename: str = "", today: date | None = None) -> dict[str, Any]:
    rt = gather(content)
    if not rt.get("info"):
        raise ValueError("No 'show system info' output was found. Capture it together with the other show commands so the device can be identified and dated.")
    rt["now"] = rt.get("now") or today
    findings = sort_findings(evaluate(rt))
    info = rt["info"]
    hostname = rt.get("hostname") or filename.rsplit(".", 1)[0]
    result = new_result("firewall", hostname=hostname, vendor="Palo Alto Networks", platform=f"{info.get('model', 'PA')} · PAN-OS {info.get('sw-version', '')}".strip(" ·"), source_name=filename, title=hostname,
                        subtitle=f"{info.get('model', '')} · PAN-OS {info.get('sw-version', '')} · runtime capture (show commands)".strip(" ·"))
    result["sections"] = sections(rt)
    result["cards"] = _cards(rt, findings)
    result["info"] = info_rows([("Hostname", hostname), ("Model", info.get("model")), ("Serial number", info.get("serial")), ("PAN-OS", info.get("sw-version")), ("Uptime", info.get("uptime")), ("Management IP", info.get("ip-address")),
                                ("Captured", rt["now"].isoformat() if rt.get("now") else ""), ("Commands", f"{len(rt['capture'].blocks)}"), ("Source", "terminal log, replayed through a terminal model")])
    result["findings"] = findings
    result["coverage"] = _coverage(rt)
    notes = []
    if rt.get("ha", {}).get("enabled") or rt.get("arp", {}).get("rows") or rt.get("mac_entries"):
        notes.append("The HA, ARP and MAC tables were parsed from Palo Alto's documented output format but have not been validated against a capture where they are populated. Check them against the device.")
    notes.append("This is a runtime capture: it shows the state of the unit, not its policy. Findings about rules, NAT, VPN and profiles need 'show config running' or a configuration export.")
    result["warnings"] = notes
    result["capture"] = {"commands": len(rt["capture"].blocks), "lines": rt["capture"].raw_lines, "has_config": False}
    return result
