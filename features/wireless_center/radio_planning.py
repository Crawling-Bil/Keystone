"""Huawei WLC radio planning: per-AP and per-AP-group radio settings.

Huawei keeps radio planning in the `wlan` view:

    ap-group name SITE            ap-id 3 type-id 139 ap-mac d810-9f97-cfa0 ...
     radio 0                       radio 0
      eirp 120                      eirp 127
      calibrate auto-txpower-select disable
      radio-2g-profile NAME         channel 20mhz 6

A value on the AP overrides its AP group. EIRP is the fixed transmit power
and only applies when automatic power (calibrate auto-txpower-select) is
disabled; the same goes for a fixed channel and auto-channel-select.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

BANDS = {"0": "2.4 GHz", "1": "5 GHz", "2": "Radio 2"}
EIRP_REAL_MAX = 30            # no indoor radio transmits more; higher values act as "maximum"
PLAN_KEYS = ("eirp", "calibrate auto-txpower-select", "calibrate auto-channel-select", "channel ", "channel-monitor",
             "antenna-gain", "work-mode", "radio-2g-profile", "radio-5g-profile", "frequency", "radio disable", "radio enable")


def _mac(value: str) -> str:
    hexes = re.sub(r"[^0-9a-f]", "", (value or "").lower())
    return "-".join(hexes[i:i + 4] for i in (0, 4, 8)) if len(hexes) == 12 else (value or "")


def _is_plan(line: str) -> bool:
    return line.startswith(PLAN_KEYS)


def parse(content: str) -> dict[str, Any]:
    """APs and AP groups with their radio lines (VAP bindings left out)."""
    aps: list[dict[str, Any]] = []
    groups: dict[str, dict[str, list[str]]] = {}
    profiles: dict[str, dict[str, list[str]]] = defaultdict(dict)
    current = None            # ("ap", dict) | ("group", name) | ("profile", kind, name)
    radio = None
    for raw in content.replace("\r\n", "\n").splitlines():
        if not raw.strip() or raw.startswith("#"):
            current, radio = None, None
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent <= 1:
            radio = None
            m = re.match(r"ap-id\s+(\d+)(.*)$", line)
            if m:
                rest = m.group(2)
                mac = re.search(r"ap-mac\s+(\S+)", rest)
                sn = re.search(r"ap-sn\s+(\S+)", rest)
                ap = {"ap_id": m.group(1), "mac": _mac(mac.group(1)) if mac else "", "serial": sn.group(1) if sn else "",
                      "name": "", "group": "", "radios": {}}
                aps.append(ap)
                current = ("ap", ap)
                continue
            m = re.match(r"ap-group name\s+(.+)$", line)
            if m:
                groups[m.group(1)] = {}
                current = ("group", m.group(1))
                continue
            m = re.match(r"(radio-2g-profile|radio-5g-profile|rrm-profile|air-scan-profile) name\s+(.+)$", line)
            if m:
                profiles[m.group(1)][m.group(2)] = []
                current = ("profile", m.group(1), m.group(2))
                continue
            current = None
            continue
        if current is None:
            continue
        if current[0] == "profile":
            profiles[current[1]][current[2]].append(line)
            continue
        if indent == 2:
            m = re.match(r"radio\s+(\d+)$", line)
            if m:
                radio = m.group(1)
                target = current[1]["radios"] if current[0] == "ap" else groups[current[1]]
                target.setdefault(radio, [])
                continue
            radio = None
            if current[0] == "ap":
                if line.startswith("ap-name "):
                    current[1]["name"] = line[8:].strip()
                elif line.startswith("ap-group "):
                    current[1]["group"] = line[9:].strip()
            continue
        if radio is not None and _is_plan(line):
            target = current[1]["radios"] if current[0] == "ap" else groups[current[1]]
            target[radio].append(line)
    return {"aps": aps, "groups": groups, "profiles": {k: dict(v) for k, v in profiles.items()}}


def _value(lines: list[str], key: str) -> str | None:
    for line in lines:
        if line == key or line.startswith(key + " "):
            return line[len(key):].strip()
    return None


def _setting(ap_lines, group_lines, key):
    v = _value(ap_lines, key)
    if v is not None:
        return v, "AP"
    v = _value(group_lines, key)
    if v is not None:
        return v, "AP Group"
    return None, "Default"


def _site(name: str, group: str) -> str:
    return (name.split("-")[0] if name and "-" in name else "") or group or "-"


def plan(content: str) -> dict[str, Any]:
    parsed = parse(content)
    rows, findings = [], []
    ignored, over_max, fixed_channel_auto, monitor = [], [], [], []
    for ap in parsed["aps"]:
        group_radios = parsed["groups"].get(ap["group"], {})
        for radio in sorted(set(ap["radios"]) | set(group_radios)):
            a, g = ap["radios"].get(radio, []), group_radios.get(radio, [])
            eirp, eirp_src = _setting(a, g, "eirp")
            auto_power, power_src = _setting(a, g, "calibrate auto-txpower-select")
            auto_chan, _ = _setting(a, g, "calibrate auto-channel-select")
            channel, chan_src = _setting(a, g, "channel")
            gain, _ = _setting(a, g, "antenna-gain")
            mode, _ = _setting(a, g, "work-mode")
            disabled = "radio disable" in a or ("radio disable" in g and "radio enable" not in a)
            profile, _ = _setting(a, g, "radio-2g-profile" if radio == "0" else "radio-5g-profile")
            power_fixed = auto_power == "disable"
            chan_fixed = auto_chan == "disable"
            if not (eirp or auto_power or channel or auto_chan or gain or mode or profile or disabled):
                continue
            label = ap["name"] or f"ap-id {ap['ap_id']}"
            row = {
                "ap_id": ap["ap_id"], "ap": label, "mac": ap["mac"], "group": ap["group"], "site": _site(ap["name"], ap["group"]),
                "radio": radio, "band": BANDS.get(radio, f"Radio {radio}"),
                "power_mode": "Fixed" if power_fixed else "Auto",
                "eirp": eirp or "", "eirp_source": eirp_src if eirp else "",
                "channel_mode": "Fixed" if chan_fixed else "Auto",
                "channel": channel or "", "channel_source": chan_src if channel else "",
                "antenna_gain": gain or "", "work_mode": mode or "normal", "radio_profile": profile or "default",
                "status": "Disabled" if disabled else "Enabled",
                "set_on": "AP" if a else "AP Group",
                "note": "",
            }
            if power_fixed and not eirp and not disabled:
                row["note"] = "Automatic power off without EIRP: the radio keeps its last or default power"
            if eirp and not power_fixed:
                row["note"] = "EIRP ignored: automatic power is on"
                ignored.append(f"{label} radio {radio} (eirp {eirp})")
            elif eirp and eirp.isdigit() and int(eirp) > EIRP_REAL_MAX:
                row["note"] = "EIRP above what the radio can send: runs at maximum power"
                over_max.append(f"{label} radio {radio} (eirp {eirp})")
            if channel and not chan_fixed:
                row["note"] = (row["note"] + "; " if row["note"] else "") + "fixed channel overridden by auto channel"
                fixed_channel_auto.append(f"{label} radio {radio} ({channel})")
            if mode == "monitor":
                monitor.append(f"{label} radio {radio}")
            rows.append(row)

    if ignored:
        findings.append({"severity": "Warning", "title": f"{len(ignored)} radio with EIRP that does not apply",
                         "detail": "EIRP is set but calibrate auto-txpower-select is still on, so the controller keeps choosing the power. Add `calibrate auto-txpower-select disable` or remove the EIRP.",
                         "items": ignored})
    if over_max:
        findings.append({"severity": "Warning", "title": f"{len(over_max)} radio with EIRP above {EIRP_REAL_MAX} dBm",
                         "detail": "Huawei accepts EIRP up to 127, but the radio is capped by its hardware and the country limit, so these run at maximum power. Fixed maximum power on many neighbours raises co-channel interference; check if this was meant.",
                         "items": over_max})
    if fixed_channel_auto:
        findings.append({"severity": "Warning", "title": f"{len(fixed_channel_auto)} fixed channel overridden by auto channel",
                         "detail": "A channel is configured but auto-channel-select is not disabled, so calibration can move it.", "items": fixed_channel_auto})
    if monitor:
        findings.append({"severity": "Info", "title": f"{len(monitor)} radio in monitor mode", "detail": "These radios scan (WIDS) and serve no clients.", "items": monitor})
    off = [f"{r['ap']} radio {r['radio']}" for r in rows if r["status"] == "Disabled"]
    if off:
        findings.append({"severity": "Info", "title": f"{len(off)} radio disabled", "detail": "Disabled on the AP or through its AP group.", "items": off})
    has_channel_plan = any(r["channel_mode"] == "Fixed" for r in rows)
    if rows and not has_channel_plan:
        findings.append({"severity": "Info", "title": "Channels are not planned in the configuration",
                         "detail": "No AP or AP group fixes a channel: every radio takes its channel from calibration. Upload `display radio all` to see the channel each radio runs on now.", "items": []})

    by_site = defaultdict(lambda: {"radios": 0, "fixed": 0, "auto": 0, "eirp": Counter()})
    for r in rows:
        s = by_site[r["site"]]
        s["radios"] += 1
        s["fixed" if r["power_mode"] == "Fixed" else "auto"] += 1
        if r["eirp"]:
            s["eirp"][f"{r['band']} {r['eirp']}"] += 1
    sites = [{"site": k, "radios": v["radios"], "fixed_power": v["fixed"], "auto_power": v["auto"],
              "eirp": ", ".join(f"{e} ×{n}" for e, n in v["eirp"].most_common(6))} for k, v in sorted(by_site.items())]
    group_rows = [{"group": name, "radio": r, "band": BANDS.get(r, r), "settings": lines}
                  for name, radios in parsed["groups"].items() for r, lines in sorted(radios.items()) if lines]
    profile_rows = [{"kind": kind.replace("-", " "), "name": name, "settings": lines}
                    for kind, items in parsed["profiles"].items() for name, lines in items.items()]
    return {
        "rows": rows, "sites": sites, "groups": group_rows, "profiles": profile_rows, "findings": findings,
        "summary": {"aps_planned": len({r["mac"] or r["ap_id"] for r in rows if r["set_on"] == "AP"}),
                    "radios": len(rows), "fixed_power": sum(r["power_mode"] == "Fixed" for r in rows),
                    "fixed_channel": sum(r["channel_mode"] == "Fixed" for r in rows),
                    "aps_total": len(parsed["aps"])},
    }


# ----------------------------------------------------------------- source vs target (Config Delta)
def _ap_commands(ap_id: str, radio: str, source: list[str], target: list[str]) -> list[str]:
    body = []
    defaults = {"calibrate auto-txpower-select enable", "calibrate auto-channel-select enable"}
    for line in source:
        if line not in target and not (line in defaults and not any(t.startswith(line.rsplit(" ", 1)[0]) for t in target)):
            body.append(line)
    for line in target:
        if line in source:
            continue
        key = line.split()[0] if not line.startswith("calibrate ") else " ".join(line.split()[:2])
        if any(s.startswith(key) for s in source) or line in defaults:
            continue                       # replaced by the source value, or the default anyway
        if line.startswith("eirp"):
            body.append("undo eirp")
        elif line == "calibrate auto-txpower-select disable":
            body.append("calibrate auto-txpower-select enable")
        elif line == "calibrate auto-channel-select disable":
            body.append("calibrate auto-channel-select enable")
        else:
            body.append(f"# review: target has '{line}' that the source does not")
    if not body:
        return []
    return [f" ap-id {ap_id}", f"  radio {radio}", *(f"   {c}" for c in body), "   quit", "  quit"]


DEFAULT_LINES = {"calibrate auto-txpower-select enable", "calibrate auto-channel-select enable", "radio enable"}


def _effective(lines: list[str]) -> list[str]:
    return [line for line in lines if line not in DEFAULT_LINES]


def compare(source_content: str, target_content: str) -> dict[str, Any]:
    """Per-AP radio planning that differs between two controllers, matched
    by AP MAC (the AP ID can differ). Commands bring the target in line."""
    src, tgt = parse(source_content), parse(target_content)
    key = lambda ap: ap["mac"] or ap["serial"] or ap["name"]
    tmap = {key(ap): ap for ap in tgt["aps"]}
    rows, commands = [], []
    for ap in src["aps"]:
        other = tmap.get(key(ap))
        if not other:
            continue
        for radio in sorted(set(ap["radios"]) | set(other["radios"])):
            s, t = sorted(ap["radios"].get(radio, [])), sorted(other["radios"].get(radio, []))
            if _effective(s) == _effective(t):
                continue                   # only an explicit default differs
            rows.append({"ap": ap["name"] or other["name"], "mac": ap["mac"], "source_ap_id": ap["ap_id"], "target_ap_id": other["ap_id"],
                         "radio": radio, "band": BANDS.get(radio, radio), "source": s, "target": t,
                         "status": "Missing on Target" if not t else ("Extra on Target" if not s else "Different")})
            commands += _ap_commands(other["ap_id"], radio, s, t)
    group_rows = []
    for name, radios in src["groups"].items():
        for radio in sorted(set(radios) | set(tgt["groups"].get(name, {}))):
            s, t = sorted(radios.get(radio, [])), sorted(tgt["groups"].get(name, {}).get(radio, []))
            if _effective(s) != _effective(t) and name in tgt["groups"]:
                group_rows.append({"group": name, "radio": radio, "band": BANDS.get(radio, radio), "source": s, "target": t})
    script = ["# Radio planning: Source to Target (match by AP MAC, AP IDs are the Target's)", "wlan", *commands, " quit"] if commands else []
    return {"rows": rows, "groups": group_rows, "commands": "\n".join(script),
            "summary": {"aps": len({r["mac"] or r["ap"] for r in rows}), "radios": len(rows), "groups": len(group_rows)}}


def add_sheets(xlsx_path, planning: dict[str, Any]) -> None:
    """Append the radio planning sheets to an analysis workbook."""
    if not planning or not planning.get("rows"):
        return
    from openpyxl import load_workbook
    from openpyxl.styles import Font

    wb = load_workbook(xlsx_path)
    sheets = (
        ("Radio Planning", ["AP", "AP ID", "MAC", "AP Group", "Site", "Radio", "Band", "Status", "Power", "EIRP", "EIRP from",
                            "Channel mode", "Channel", "Antenna gain", "Work mode", "Radio profile", "Note"],
         [[r["ap"], r["ap_id"], r["mac"], r["group"], r["site"], r["radio"], r["band"], r.get("status", ""), r["power_mode"], r["eirp"],
           r["eirp_source"], r["channel_mode"], r["channel"], r["antenna_gain"], r["work_mode"], r["radio_profile"], r["note"]]
          for r in planning["rows"]]),
        ("Radio by Site", ["Site", "Radios", "Fixed power", "Auto power", "EIRP"],
         [[s["site"], s["radios"], s["fixed_power"], s["auto_power"], s["eirp"]] for s in planning["sites"]]),
        ("Radio Findings", ["Severity", "Finding", "Detail", "Affected"],
         [[f["severity"], f["title"], f["detail"], "\n".join(f["items"])] for f in planning["findings"]]),
    )
    for title, headers, rows in sheets:
        ws = wb.create_sheet(title)
        ws.append(headers)
        for cell in ws[1]:
            cell.font = Font(bold=True)
        for row in rows:
            ws.append(row)
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
    wb.save(xlsx_path)
