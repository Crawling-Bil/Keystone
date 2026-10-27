"""Tabs for device health, logs, NAT, the IPsec tunnel inventory and OSPF participation.

Same contract as :mod:`.sections`: every builder takes the :class:`~.context.Ctx` and
returns table / key-value sections; a group without content is hidden by
``sections.build_all``.  Credentials never appear: only the storage type and strength
of a key is shown, never the key, and the per-run reuse tokens stay inside the model.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..analyzer_core.result import kv_section, table_section
from ..analyzer_core.logtime import log_window
from .context import Ctx
from .netutil import human_bytes as _size


def _pct_tone(value: float | None, warn: float, bad: float) -> str:
    if value is None:
        return ""
    return "bad" if value >= bad else ("warn" if value >= warn else "ok")


def _yes(flag: Any) -> str:
    return "Yes" if flag else "No"


def _window(values: list[int], suffix: str = "") -> str:
    return " / ".join(f"{v:,}{suffix}" for v in values)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def health(ctx: Ctx) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    cpu = ctx.get("cpu")
    history = ctx.get("cpu_history")
    version = ctx.get("version") or {}
    pairs: list[tuple] = []
    if cpu and cpu.get("five_min") is not None:
        pairs.append(("Control-plane CPU (5 s / 1 min / 5 min)", f"{cpu['five_sec']}% / {cpu['one_min']}% / {cpu['five_min']}%", _pct_tone(cpu["five_min"], 70, 85)))
    if history:
        peaks = [f"{history[k]['peak']}%" for k in ("second", "minute", "hour") if history.get(k)]
        if peaks:
            pairs.append(("CPU peak (last 60 s / 60 min / 72 h)", " / ".join(peaks), _pct_tone((history.get("hour") or {}).get("peak"), 80, 95)))
    pools = ((ctx.get("memory_statistics") or {}).get("pools")) or ((ctx.get("process_memory") or {}).get("pools")) or []
    processor = next((p for p in pools if p["pool"] == "Processor"), None)
    if processor:
        text = f"{processor['used_pct']}% used ({_size(processor['used'])} of {_size(processor['total'])})"
        if processor.get("lowest_free_pct") is not None:
            text += f"; lowest free since reload {processor['lowest_free_pct']}%"
        pairs.append(("IOS Processor memory", text, _pct_tone(processor["used_pct"], 80, 90)))
    util = ctx.get("qfp_utilization")
    if util:
        pairs.append(("QFP packet-processing load (5 s / 1 min / 5 min / 60 min)", _window(util["processing"], "%"), _pct_tone(util["processing_peak"], 70, 85)))
        pairs.append(("QFP traffic, 5 min average", f"in {util['input_pps'][2]:,} pps · {util['input_bps'][2] / 1e6:,.1f} Mbps — out {util['output_pps'][2]:,} pps · {util['output_bps'][2] / 1e6:,.1f} Mbps"))
    qfp_mem = ctx.get("qfp_exmem")
    if qfp_mem:
        dram = next((m for m in qfp_mem["memories"] if m["type"] == "DRAM"), None)
        if dram:
            pairs.append(("QFP DRAM", f"{dram['used_pct']}% used ({_size(dram['used'])} of {_size(dram['total'])})", _pct_tone(dram["used_pct"], 80, 90)))
    if version.get("uptime"):
        pairs.append(("Uptime", version["uptime"]))
    if version.get("last_reload_reason"):
        pairs.append(("Last reload reason", version["last_reload_reason"]))
    if version.get("boot_mode"):
        pairs.append(("Boot mode", {"install": "install mode (packages.conf)", "bundle": "bundle mode (.bin image)"}.get(version["boot_mode"], version["boot_mode"])))
    if version.get("crypto_throughput_kbps"):
        pairs.append(("Crypto throughput level", f"{version['crypto_throughput_kbps'] // 1000} Mbps"))
    if pairs:
        sections.append(kv_section("health_summary", "Health summary", pairs, group="Health",
                                   hint="Tones use Keystone's heuristic thresholds (CPU/QFP 70% and 85%, memory 80% and 90%); they are not Cisco limits."))

    if cpu and cpu.get("processes"):
        rows = [{"pid": p["pid"], "process": p["process"], "five_sec": p["five_sec"], "one_min": p["one_min"], "five_min": p["five_min"], "runtime": p["runtime_ms"], "invoked": p["invoked"], "usecs": p["usecs"],
                 "_tones": {"five_min": _pct_tone(p["five_min"], 10, 30)}} for p in cpu["processes"][:15]]
        sections.append(table_section("cpu_processes", "Busiest IOS processes", [("pid", "PID", "id"), ("process", "Process"), ("five_sec", "5 s %", "num"), ("one_min", "1 min %", "num"), ("five_min", "5 min %", "num"),
                                                                              ("runtime", "Runtime (ms)", "num"), ("invoked", "Invoked", "num"), ("usecs", "µs / call", "num")], rows, group="Health"))
    if history:
        rows = [{"window": label, "peak": f"{history[key]['peak']}%", "average": f"{history[key]['mean_of_maxima']}%", "samples": history[key]["samples"]}
                for key, label in (("second", "last 60 seconds"), ("minute", "last 60 minutes"), ("hour", "last 72 hours")) if history.get(key)]
        sections.append(table_section("cpu_history", "CPU history", [("window", "Window"), ("peak", "Peak"), ("average", "Average of the maxima"), ("samples", "Samples", "num")], rows, group="Health"))

    resources = ctx.get("platform_resources") or []
    if resources:
        sections.append(table_section("platform_resources", "Platform resources (device thresholds)",
                                      [("scope", "Scope"), ("resource", "Resource"), ("usage", "Usage"), ("max", "Maximum"), ("warning", "Warning at"), ("critical", "Critical at"), ("state", "State", "status")],
                                      [dict(r, state={"H": "healthy", "W": "warning", "C": "critical"}.get(r["state"], r["state"]), _tones={"state": {"H": "ok", "W": "warn", "C": "bad"}.get(r["state"], "")}) for r in resources],
                                      group="Health", hint="'show platform resources': the platform's own thresholds, so a warning here is the device's judgement, not Keystone's.", facets=[{"key": "state", "label": "state"}]))
    control = ctx.get("control_processor")
    if control:
        cores = [{"slot": c["slot"], "core": c["cpu"], "user": c["user"], "system": c["system"], "idle": c["idle"], "busy": round(100 - c["idle"], 1), "_tones": {"busy": _pct_tone(100 - c["idle"], 70, 90)}} for c in control.get("cpu", [])]
        sections.append(table_section("control_cores", "Control-processor cores", [("slot", "Slot"), ("core", "Core", "id"), ("user", "User %", "num"), ("system", "System %", "num"), ("idle", "Idle %", "num"), ("busy", "Busy %", "num")], cores, group="Health"))
    if pools:
        rows = [{"pool": p["pool"], "total": _size(p["total"]), "used": _size(p["used"]), "free": _size(p["free"]), "used_pct": p["used_pct"],
                 "lowest": p.get("lowest_free_pct", ""), "note": "packet I/O buffers: always close to 100%, not a leak" if p["pool"] == "lsmpi_io" else "",
                 "_tones": {"used_pct": _pct_tone(p["used_pct"], 80, 90) if p["pool"] == "Processor" else ""}} for p in pools]
        sections.append(table_section("memory_pools", "IOS memory pools", [("pool", "Pool"), ("total", "Total"), ("used", "Used"), ("free", "Free"), ("used_pct", "Used %", "num"), ("lowest", "Lowest free % since reload", "num"), ("note", "Note", "wrap")],
                                      rows, group="Health"))
    holders = (ctx.get("process_memory") or {}).get("top") or []
    if holders:
        sections.append(table_section("memory_holders", "Largest memory holders", [("pid", "PID", "id"), ("process", "Process"), ("holding", "Holding (bytes)", "num"), ("allocated", "Allocated", "num"), ("freed", "Freed", "num")],
                                      holders[:12], group="Health", hint="Compare two captures taken hours apart: a leak is a holder that keeps growing."))
    if util:
        names = [("input_pps", "Input (pps)"), ("input_bps", "Input (bps)"), ("output_pps", "Output (pps)"), ("output_bps", "Output (bps)"), ("processing", "Processing load (%)"),
                 ("crypto_io_crypto", "Crypto engine load (%)"), ("crypto_io_rx", "Crypto/IO RX load (%)"), ("crypto_io_tx", "Crypto/IO TX load (%)"), ("crypto_io_idle", "Crypto/IO idle (%)")]
        rows = [dict(metric=label, **{f"w{i}": v for i, v in enumerate(util[key])}) for key, label in names if key in util]
        for row in rows:
            if row["metric"].startswith("Processing"):
                row["_tones"] = {f"w{i}": _pct_tone(row[f"w{i}"], 70, 85) for i in range(4)}
        sections.append(table_section("qfp_load", f"Forwarding plane (QFP) load — {util.get('engine', '')}", [("metric", "Metric"), ("w0", "5 s", "num"), ("w1", "1 min", "num"), ("w2", "5 min", "num"), ("w3", "60 min", "num")],
                                      rows, group="Health", hint="QFP is the forwarding ASIC of ASR1000, ISR4000 and Catalyst 8000: the control-plane CPU can be idle while it is saturated."))
    drops = ctx.get("qfp_drops")
    if drops:
        sections.append(table_section("qfp_drops", "Forwarding-plane drop counters", [("counter", "Counter"), ("packets", "Packets", "num"), ("octets", "Octets", "num")], drops["rows"][:25], group="Health",
                                      hint=f"Since {drops['cleared']}." if drops.get("cleared") else "",
                                      empty="No QFP drops."))
    if qfp_mem:
        sections.append(table_section("qfp_memory", "Forwarding-plane memory", [("type", "Memory"), ("qfp", "QFP", "id"), ("total", "Total"), ("used", "Used"), ("free", "Free"), ("used_pct", "Used %", "num"), ("lowest_free_pct", "Lowest free %", "num")],
                                      [dict(m, total=_size(m["total"]), used=_size(m["used"]), free=_size(m["free"]), _tones={"used_pct": _pct_tone(m["used_pct"], 80, 90)}) for m in qfp_mem["memories"]], group="Health"))

    env = ctx.get("environment") or {}
    slots = (ctx.get("platform_slots") or {}).get("slots", [])
    if slots:
        stack = bool((ctx.get("platform_slots") or {}).get("stack"))
        sections.append(table_section("chassis_slots", "Stack members" if stack else "Chassis slots", [("slot", "Switch" if stack else "Slot"), ("type", "Model" if stack else "Type"), ("state", "Role, state" if stack else "State", "status")]
                                      + ([("priority", "Priority"), ("ports", "Ports", "num"), ("hw", "Hardware"), ("sw", "Software")] if stack else [("uptime", "Uptime")]),
                                      [dict(s, _tones={"state": "bad" if any(w in s["state"].lower() for w in ("fail", "fault", "badinput")) else ("ok" if s["state"].lower().startswith("ok") or s["state"].lower().endswith("ready") else "warn")}) for s in slots], group="Health"))
    if env.get("sensors"):
        normal = {"normal", "ok", "good", "green", "online"}
        sections.append(table_section("environment", "Environment sensors", [("slot", "Slot"), ("sensor", "Sensor"), ("state", "State", "status"), ("value", "Reading", "num"), ("unit", "Unit")],
                                      [dict(s, _tones={"state": "ok" if s["state"].lower() in normal else "bad" if "crit" in s["state"].lower() else "warn"}) for s in env["sensors"]], group="Health",
                                      hint=("Alarm counters: " + ", ".join(f"{n} {k}" for k, n in env["alarms"].items())) if env.get("alarms") else "", facets=[{"key": "state", "label": "state"}]))
    red = ctx.get("redundancy_states")
    if red:
        history_data = ctx.get("redundancy_history") or {}
        sections.append(kv_section("redundancy", "Redundancy", [("Mode (configured / operational)", f"{red.get('configured_mode', '?')} / {red.get('operational_mode', '?')}"), ("This unit", red.get("my_state", "")),
                                                                 ("Peer", red.get("peer_state", "")), ("State", red.get("redundancy_state", "")), ("Switchovers in history", history_data.get("switchovers", ""))], group="Health"))

    fs = ctx.get("file_systems") or []
    if fs:
        sections.append(table_section("file_systems", "File systems", [("prefixes", "Name", "list"), ("type", "Type"), ("flags", "Flags"), ("size", "Size"), ("free", "Free"), ("free_pct", "Free %", "num")],
                                      [dict(f, size=_size(f["size"]), free=_size(f["free"]), _tones={"free_pct": "bad" if f["free_pct"] < 10 and f["type"] == "disk" and f.get("current") else ("warn" if f["free_pct"] < 20 and f["type"] == "disk" and f.get("current") else "")}) for f in fs if f.get("size")],
                                      group="Health"))
    flash = ctx.get("bootflash")
    if flash and flash.get("images"):
        import re
        running = (version.get("version") or "").lower()
        def key(text: str) -> tuple:
            return tuple(str(int(p)) if p.isdigit() else p for p in re.findall(r"\d+|[a-z]+", text.lower()))
        rows = []
        for image in flash["images"]:
            match = re.search(r"\.(\d+\.\d+\.\d+[a-z]?)\.SPA", image["path"], re.I)
            is_running = bool(match and running and key(match.group(1)) == key(running))
            rows.append({"file": image["path"].rsplit("/", 1)[-1], "release": match.group(1) if match else "", "size": _size(image["size"]), "date": image["date"],
                         "status": "running release" if is_running else "other release", "_tones": {"status": "ok" if is_running else "warn"}})
        sections.append(table_section("flash_images", "Software images on bootflash", [("file", "File", "mono"), ("release", "Release"), ("size", "Size"), ("date", "Date"), ("status", "Status", "status")], rows, group="Health",
                                      hint=("Packages of other releases: " + ", ".join(v for v in flash.get("package_versions", []) if key(v) != key(running)) if flash.get("package_versions") and running else ""), facets=[{"key": "status", "label": "status"}]))

    lic = ctx.get("license_all")
    smart_pairs = [(label, lic[k]) for k, label in (("smart_licensing", "Smart Licensing"), ("using_policy", "Using Policy"), ("transport", "Transport"), ("cslu_address", "CSLU address"),
                                                    ("policy", "Policy"), ("last_ack", "Last ACK received"), ("next_ack_deadline", "Next ACK deadline"), ("last_report_push", "Last report push"),
                                                    ("next_report_push", "Next report push"), ("agent", "Smart Agent")) if lic.get(k)] if lic else []
    if smart_pairs:
        sections.append(kv_section("licensing", "Smart Licensing", smart_pairs, group="Health"))
    store_rows = ctx.license_store()
    if store_rows:
        def store_tone(entry: dict[str, Any]) -> str:
            state = entry["state"].lower()
            if state.startswith("active, in use"):
                return "warn" if "eval" in entry["type"].lower() else "ok"
            return "mute"
        sections.append(table_section("license_store", "Licences (classic licensing)", [("store", "Store"), ("feature", "Feature", "mono"), ("type", "Type"), ("state", "State", "status"), ("eval_left", "Evaluation period left"),
                                                                                  ("count", "Count")], [dict(e, _tones={"state": store_tone(e)}) for e in store_rows], group="Health", page_size=100,
                                      facets=[{"key": "type", "label": "type"}, {"key": "store", "label": "store"}],
                                      hint=f"'{'show license all' if (lic or {}).get('store') else 'show license detail'}' on a router with classic (right-to-use) licensing. Cisco: an evaluation licence runs 60 days and then becomes a right-to-use licence; a feature whose EULA was never accepted stays 'Not in Use'."))
    credential = (ctx.get("license_status") or {}).get("device_credential")
    if credential:
        sections.append(kv_section("licensing_classic", "Licence device credential", [("Device credential verification", credential)], group="Health"))
    if version.get("license_table"):
        sections.append(table_section("license_table", "Licence levels (show version)", [("technology", "Technology"), ("type", "Type"), ("current", "Current"), ("next_reboot", "Next reboot")], version["license_table"], group="Health"))
    usage = ctx.get("license_usage")
    if usage and usage.get("licenses"):
        sections.append(table_section("license_usage", "Licences in use", [("name", "Licence"), ("tag", "Tag", "mono"), ("license_type", "Type"), ("count", "Count", "num"), ("status", "Status", "status"), ("export_status", "Export status"), ("enforcement_type", "Enforcement")],
                                      [dict(l, _tones={"status": "ok" if l.get("status") == "IN USE" else "mute"}) for l in usage["licenses"]], group="Health", facets=[{"key": "status", "label": "status"}]))
    return sections


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


def restart_history(ctx: Ctx) -> list[dict[str, Any]]:
    """Every restart, reload and crash indicator the capture can show, from three places."""
    version = ctx.get("version") or {}
    status = ctx.get("sdwan_status") or {}
    log = ctx.get("logging") or {}
    rows: list[dict[str, Any]] = []
    if version.get("restarted_at") or version.get("last_reload"):
        reason = version.get("last_reload_reason")
        detail = "; ".join(x for x in (f"returned to ROM by: {version['last_reload']}" if version.get("last_reload") else "", f"reload reason: {reason}" if reason else "", f"uptime {version['uptime']}" if version.get("uptime") else "") if x)
        rows.append({"when": version.get("restarted_at") or "", "source": "show version", "event": "Last restart", "detail": detail})
    if status.get("Last reboot") or status.get("CPU-reported reboot"):
        rows.append({"when": status.get("Current time", "") and f"as of {status['Current time']}", "source": "show sdwan system status", "event": "Last reboot: " + status.get("Last reboot", "n/a"),
                     "detail": "; ".join(x for x in (f"CPU-reported reboot: {status['CPU-reported reboot']}" if status.get("CPU-reported reboot") else "", f"system uptime {status['System uptime']}" if status.get("System uptime") else "") if x)})
    for item in log.get("restarts", []):
        rows.append({"when": item["time"], "source": "show logging", "event": item.get("kind", "restart"), "detail": item["message"]})
    for item in log.get("crashes", []):
        rows.append({"when": item["time"], "source": "show logging", "event": f"Fault indicator: {item['kind']}", "detail": f"{item['tag']}: {item['message']}", "_tones": {"event": "warn"}})
    return [table_section("restart_history", "Restart and crash history", [("when", "When"), ("source", "Source"), ("event", "Event"), ("detail", "Detail", "wrap")], rows, group="Health",
                          empty="No restart or crash indicator in this capture.",
                          hint="The log buffer is circular and starts empty after a reload, so restarts older than the buffer are only visible in 'show version' and 'show sdwan system status'. Core files and crashinfo are not read.")]


def logs(ctx: Ctx) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    counts = ctx.get("logging_count") or []
    if counts:
        rows = sorted(counts, key=lambda r: -r["occurrences"])
        sections.append(table_section("logging_count", "Message occurrence counts ('show logging count')",
                                      [("facility", "Facility", "mono"), ("mnemonic", "Message", "mono"), ("severity_name", "Severity"), ("occurrences", "Occurrences", "num"), ("last_time", "Last time")],
                                      rows, group="Logs", hint="Lifetime counters since they were last cleared — they can cover a longer, or shorter, window than the messages still held in the buffer below."))
    log = ctx.get("logging")
    if not log:
        return sections
    settings = log.get("settings", {})
    window = log_window(log["first"], log["last"])
    pairs: list[tuple] = [("Messages in the buffer", f"{log['message_count']:,}"), ("Window", f"{log['first']} → {log['last']}")]
    if window["text"]:
        pairs.append(("Duration", window["text"] + (f" ({window['assumed']})" if window["assumed"] else ""), "" if window["reliable"] else "warn"))
    if settings.get("buffer_bytes"):
        small = settings["buffer_bytes"] < 32_000
        pairs.append(("Buffer size", f"{settings['buffer_bytes']:,} bytes", "warn" if small else ""))
    for key, label in (("console", "Console"), ("monitor", "Monitor"), ("buffer", "Buffer"), ("trap", "Trap (syslog servers)")):
        item = settings.get(key)
        if item:
            pairs.append((f"{label} level", f"{item['level']} ({item['logged']:,} messages)", "warn" if key == "console" and item["level"] == "debugging" else ""))
    for host in settings.get("hosts", []):
        pairs.append((f"Syslog server {host['host']}", f"port {host['port']}, {host.get('link') or 'state unknown'}, {host['logged']:,} lines sent, {host['dropped']:,} dropped"))
    if not settings.get("hosts"):
        pairs.append(("Syslog servers", "none", "warn"))
    if log.get("shown_lines"):
        total = (settings.get("buffer") or {}).get("logged", 0)
        pairs.append(("Lines analyzed", f"last {log['shown_lines']:,} lines" + (f" of the {total:,} messages the buffer has logged" if total > log["shown_lines"] else ""), "warn" if total > log["shown_lines"] else ""))
    pairs.append(("Messages by severity", ", ".join(f"{k} {v:,}" for k, v in log["by_severity"].items())))
    sections.append(kv_section("log_summary", "Logging", pairs, group="Logs",
                               hint="Duration is the last time stamp minus the first. A clock that was set while the log was running (NTP after a reload) makes it longer than the period the messages really cover." if window["text"] else ""))

    flap_rows = []
    labels = {"interfaces": "Interface / tunnel", "tracks": "Tracked object", "ospf": "OSPF neighbour", "bgp": "BGP neighbour", "omp": "OMP peer (SD-WAN)"}
    for kind, table in log.get("flaps", {}).items():
        for name, row in table.items():
            flap_rows.append({"kind": labels[kind], "object": name, "down": row["down"], "up": row["up"], "first": row["first"], "last": row["last"],
                              "reasons": [f"{r} ×{n}" for r, n in row["reasons"].items()], "_tones": {"down": "bad" if row["down"] >= 3 else ("warn" if row["down"] else "")}})
    flap_rows.sort(key=lambda r: -r["down"])
    sections.append(table_section("log_flaps", "State changes seen in the log", [("kind", "Kind"), ("object", "Object", "mono"), ("down", "Down", "num"), ("up", "Up", "num"), ("first", "First"), ("last", "Last"), ("reasons", "Reasons", "list")],
                                  flap_rows, group="Logs", empty="No link, tunnel, OSPF, BGP or track state changes in the buffer.",
                                  hint="Time stamps have no year; they are in the order of the log."))
    sections.append(table_section("log_mnemonics", "Most frequent messages", [("count", "Count", "num"), ("severity", "Sev", "num"), ("facility", "Facility"), ("mnemonic", "Message"), ("first", "First"), ("last", "Last"), ("example", "Example", "wrap")],
                                  log["mnemonics"][:30], group="Logs", page_size=30))
    if log.get("config_changes"):
        sections.append(table_section("log_changes", "Configuration changes (%SYS-5-CONFIG_I)", [("time", "Time"), ("user", "User"), ("from", "From"), ("line", "Line", "mono"), ("source", "Source address", "mono")], log["config_changes"], group="Logs"))
    logins = log.get("logins", {})
    login_rows = [{"source": s, "count": n, "result": "success"} for s, n in logins.get("sources", {}).items()] + [
        {"source": f["source"], "count": f["count"], "result": f"failed as {f['user']}: {f['reason']}", "_tones": {"result": "bad"}} for f in log.get("login_failures", [])]
    sections.append(table_section("log_logins", "Logins in the log", [("source", "Source", "mono"), ("count", "Count", "num"), ("result", "Result", "status")], login_rows, group="Logs",
                                  empty="No %SEC_LOGIN messages in the buffer ('login on-success log' / 'login on-failure log' not configured).", facets=[{"key": "result", "label": "result"}]))
    model = ctx.models.get("ipsec") or {}
    peers = {p for t in model.get("tunnels", []) for p in t.get("peers", [])}
    ipsec_rows = []
    spi = log.get("invalid_spi") or {}
    for source, count in (spi.get("sources") or {}).items():
        known = source in peers
        ipsec_rows.append({"event": "ESP packet with unknown SPI", "address": source, "count": count, "peer": "configured peer" if known else "not a configured peer", "_tones": {"peer": "warn" if known else "mute"}})
    for peer, count in (log.get("ike_deletes") or {}).items():
        ipsec_rows.append({"event": "IKE SA cleared manually", "address": peer, "count": count, "peer": "configured peer" if peer in peers else "not a configured peer"})
    if ipsec_rows:
        sections.append(table_section("log_ipsec", "IPsec events in the log", [("event", "Event"), ("address", "Address", "mono"), ("count", "Count", "num"), ("peer", "Peer", "status")], ipsec_rows, group="Logs"))
    if log.get("license_bandwidth"):
        sections.append(table_section("log_bandwidth", "Licensed throughput events (%BW_LICENSE)", [("time", "Time"), ("level", "Level", "status"), ("limit", "Licensed limit"), ("periods", "Sampling periods", "num"), ("mnemonic", "Message")],
                                      [dict(e, _tones={"level": "bad" if e["level"] == "max" else "warn"}) for e in log["license_bandwidth"]], group="Logs"))
    return sections


# ---------------------------------------------------------------------------
# Neighbours, bundles and sessions (shared groups)
# ---------------------------------------------------------------------------


def neighbours(ctx: Ctx) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    detail, brief = ctx.get("cdp_detail"), ctx.get("cdp_neighbors")
    if detail:
        sections.append(table_section("cdp", "CDP neighbours", [("device", "Neighbour"), ("interface", "Local interface", "mono"), ("port", "Remote port", "mono"), ("address", "Management IP", "mono"),
                                                              ("platform", "Platform"), ("capabilities", "Capabilities"), ("native_vlan", "Native VLAN"), ("duplex", "Duplex")], detail, group="Interfaces", empty="No CDP neighbours."))
    elif brief:
        sections.append(table_section("cdp", "CDP neighbours", [("device", "Neighbour"), ("local", "Local interface", "mono"), ("port", "Remote port", "mono"), ("platform", "Platform"), ("capability", "Capability"),
                                                              ("hold", "Hold time", "num")], brief, group="Interfaces", empty="No CDP neighbours."))
    channels = ctx.get("etherchannel")
    if channels:
        sections.append(table_section("etherchannel", "Port-channels", [("group", "Group", "id"), ("port_channel", "Port-channel"), ("protocol", "Protocol"), ("ports", "Members", "list")],
                                      [dict(c, ports=[f"{p['port']}({p['flag']})" for p in c["ports"]]) for c in channels], group="Interfaces"))
    users = ctx.get("users")
    if users:
        sections.append(table_section("sessions", "Logged-in sessions", [("line", "Line", "mono"), ("user", "User"), ("location", "From", "mono"), ("idle", "Idle"), ("current", "This capture")],
                                      [dict(u, current=_yes(u["current"])) for u in users], group="Security"))
    return sections


# ---------------------------------------------------------------------------
# NAT
# ---------------------------------------------------------------------------


def nat(ctx: Ctx) -> list[dict[str, Any]]:
    model = ctx.models.get("nat")
    if not model:
        return []
    stats = model.get("stats") or {}
    sections: list[dict[str, Any]] = []
    # A 'show tech-support' or a lone 'show ip nat statistics' carries the live rules and pools but not the configuration:
    # show those instead of "0 / 0 / 0", which would read as "no NAT is configured".
    live_only = not (model["pools"] or model["dynamic"] or model["static"]) and bool(stats.get("mappings"))
    live_pools = list({m["pool"]["name"]: m["pool"] for m in stats.get("mappings", []) if m.get("pool")}.values()) if live_only else []
    if live_only:
        counts = (f"{len(live_pools)} / {len(stats['mappings'])} (read from 'show ip nat statistics'; the configuration was not captured, so overload and static entries are unknown)")
    else:
        counts = f"{len(model['pools'])} / {len(model['dynamic'])} ({sum(1 for d in model['dynamic'] if d['overload'])} with overload) / {len(model['static'])}"
    pairs: list[tuple] = [("Inside interfaces", model["inside"] or "none"), ("Outside interfaces", model["outside"] or "none"),
                          ("Pools / dynamic rules" if live_only else "Pools / dynamic rules / static entries", counts)]
    forwards = [s for s in model["static"] if s["proto"]]
    if forwards:
        pairs.append(("Static port-forwards", f"{len(forwards)} ({sum(1 for s in forwards if s.get('sensitive'))} on management or database ports)", "warn" if any(s.get("sensitive") for s in forwards) else ""))
    for key, value in model["settings"].items():
        pairs.append((key.replace("translation ", "").replace("-", " ").capitalize() if key.startswith("translation") else key, value))
    if stats:
        limit = stats.get("limit") or {}
        pairs.append(("Active translations", f"{stats.get('total', 0):,} ({stats.get('static', 0):,} static, {stats.get('dynamic', 0):,} dynamic, {stats.get('extended', 0):,} extended)"))
        if limit.get("max"):
            pct = round(100 * limit.get("used", 0) / limit["max"], 1)
            pairs.append(("Translation limit used", f"{limit.get('used', 0):,} of {limit['max']:,} ({pct}%), {limit.get('missed', 0):,} refused", _pct_tone(pct, 80, 95)))
        pairs.append(("Hits / misses", f"{stats.get('hits', 0):,} / {stats.get('misses', 0):,}; {stats.get('expired', 0):,} expired"))
        drops = stats.get("drops") or {}
        if any(drops.values()):
            pairs.append(("Drops", ", ".join(f"{k.replace('_', '-')} {v:,}" for k, v in drops.items() if v), "warn"))
    sections.append(kv_section("nat_summary", "NAT overview", pairs, group="NAT",
                               hint="Live values come from 'show ip nat statistics'; without it only the configuration is shown."))

    pool_rows = []
    for pool in live_pools:
        pct = pool.get("allocated_pct")
        misses = pool.get("misses") or 0
        pool_rows.append({"name": pool["name"], "range": f"{pool.get('start', '')} – {pool.get('end', '')}" if pool.get("start") != pool.get("end") else pool.get("start", ""), "size": pool.get("total", ""),
                          "mask": pool.get("netmask", ""), "used_by": [m["acl"] for m in stats["mappings"] if m.get("pool") and m["pool"]["name"] == pool["name"]], "overload": "", "allocated": pool.get("allocated", ""),
                          "pct": pct if pct is not None else "", "misses": misses, "translations": sum(m.get("refcount") or 0 for m in stats["mappings"] if m.get("pool") and m["pool"]["name"] == pool["name"]),
                          "_tones": {"pct": "bad" if misses else "", "misses": "bad" if misses else ""}})
    for pool in model["pools"]:
        pct = pool.get("allocated_pct")
        tone = "bad" if pool.get("misses") else ("warn" if pct is not None and pct >= 90 and not pool["overload"] and pool["used_by"] else "")
        pool_rows.append({"name": pool["name"], "range": f"{pool['start']} – {pool['end']}" if pool["start"] != pool["end"] else pool["start"], "size": pool["size"], "mask": pool["netmask"], "used_by": pool["used_by"] or ["unused"],
                          "overload": _yes(pool["overload"]) if pool["used_by"] else "", "allocated": pool["allocated"] if pool["allocated"] is not None else "", "pct": pct if pct is not None else "",
                          "misses": pool["misses"] if pool["misses"] is not None else "", "translations": pool["refcount"] if pool["refcount"] is not None else "",
                          "_tones": {"pct": tone, "misses": "bad" if pool.get("misses") else "", "used_by": "warn" if not pool["used_by"] else ""}})
    sections.append(table_section("nat_pools", "NAT pools", [("name", "Pool"), ("range", "Addresses", "mono"), ("size", "Size", "num"), ("mask", "Netmask", "mono"), ("used_by", "Used by (ACL)", "list"), ("overload", "Overload"),
                                                           ("allocated", "Allocated", "num"), ("pct", "Allocated %", "num"), ("misses", "Misses", "num"), ("translations", "Translations", "num")], pool_rows, group="NAT", empty="No 'ip nat pool'."))
    rule_rows = []
    for mapping in (stats["mappings"] if live_only else []):
        rule_rows.append({"direction": mapping.get("section") or "inside source", "match": f"{'route-map' if mapping['match'] == 'route-map' else 'access-list'} {mapping['acl']}", "target": f"{mapping['target_kind']} {mapping['target']}",
                          "overload": "", "vrf": mapping.get("vrf") or "global", "translations": mapping["refcount"] if mapping.get("refcount") is not None else "", "problem": "", "_tones": {}})
    for rule in model["dynamic"]:
        problem = "pool not defined" if rule.get("pool_defined") is False else ("ACL not defined" if rule.get("acl_undefined") else "")
        rule_rows.append({"direction": f"{rule['direction']} {rule['kind']}", "match": f"{rule['match']} {rule['acl']}", "target": f"{rule['target_kind']} {rule['target']}", "overload": _yes(rule["overload"]), "vrf": rule["vrf"] or "global",
                          "translations": rule["refcount"] if rule["refcount"] is not None else "", "problem": problem, "_tones": {"problem": "bad" if problem else ""}})
    sections.append(table_section("nat_rules", "Dynamic NAT rules", [("direction", "Direction"), ("match", "Source match"), ("target", "Translated to"), ("overload", "Overload"), ("vrf", "VRF"), ("translations", "Active translations", "num"),
                                                                    ("problem", "Problem", "status")], rule_rows, group="NAT", empty="No dynamic NAT rules.",
                                  hint="Active translations come from the 'Refcount' of 'show ip nat statistics' and are a snapshot: zero does not prove a rule is unused."))
    static_rows = []
    for entry in model["static"]:
        local = f"{entry['local']}:{entry['local_port']}" if entry["local_port"] else entry["local"]
        glob = f"{entry['global']}:{entry['global_port']}" if entry["global_port"] else entry["global"]
        public = _is_public(entry["global"])
        static_rows.append({"direction": entry["direction"], "protocol": entry["proto"] or "any", "local": local, "global": glob, "scope": "public" if public else ("private" if public is False else ""), "service": entry.get("sensitive") or "",
                            "flags": entry["flags"] + (["network"] if entry["network"] else []), "vrf": entry["vrf"] or "global",
                            "_tones": {"service": "warn" if entry.get("sensitive") else "", "global": "warn" if entry.get("translates_port") else ""}})
    sections.append(table_section("nat_static", "Static NAT entries", [("direction", "Direction"), ("protocol", "Protocol"), ("local", "Inside local", "mono"), ("global", "Inside global", "mono"), ("scope", "Global address"),
                                                                      ("service", "Sensitive service", "status"), ("flags", "Flags", "list"), ("vrf", "VRF")], static_rows, group="NAT",
                                  empty="Static entries are read from the running-config, which was not captured." if live_only else "No static NAT entries.",
                                  hint="A highlighted global port means the port number is changed by the translation."))
    if model["shared_addresses"]:
        sections.append(table_section("nat_shared", "Addresses shared by several pools", [("address", "Address", "mono"), ("pools", "Pools", "list")], model["shared_addresses"], group="NAT"))
    return sections


def _is_public(address: str) -> bool | None:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# VPN tunnel inventory
# ---------------------------------------------------------------------------


def vpn_inventory(ctx: Ctx) -> list[dict[str, Any]]:
    model = ctx.models.get("ipsec")
    if not model or not model.get("tunnels"):
        return []
    sections: list[dict[str, Any]] = []
    rows = []
    for t in model["tunnels"]:
        key = t.get("key") or {}
        live = t.get("live") or {}
        state = live.get("status") or ("" if not any(model["live"].values()) else "no session")
        rows.append({
            "name": t["name"], "kind": t["kind"], "peers": t["peers"], "ike": t["ike"], "auth": t["auth"], "key": f"{key.get('storage', '')}" if key else "",
            "transform": [f"{ts['name']}: {ts['cipher']} / {ts['integrity']}" for ts in t["transform_sets"]], "pfs": t["pfs"], "lifetime": t["lifetime"], "weak": t["weak"], "state": state,
            "_tones": {"key": {"weak": "bad"}.get(key.get("strength"), "") if key else "", "pfs": "bad" if t["pfs"] not in ("none", "") and any(g in t["pfs"] for g in ("group 1 ", "group 2 ", "group 5 ")) else ("warn" if t["pfs"] in ("none", "") else ""),
                       "weak": "bad" if t["weak"] else "", "state": "ok" if state == "UP-ACTIVE" else ("warn" if state else "")}})
    sections.append(table_section("vpn_tunnels", "IPsec tunnel inventory", [("name", "Tunnel"), ("kind", "Kind"), ("peers", "Peers", "list"), ("ike", "IKE"), ("auth", "Authentication"), ("key", "Key stored as", "status"),
                                                                           ("transform", "Transform set", "list"), ("weak", "Weak algorithms", "list"), ("pfs", "PFS"), ("lifetime", "Lifetime"),
                                                                           ("state", "Live state", "status")], rows, group="VPN & Crypto",
                                  hint=f"{len(model['tunnels'])} tunnel(s), {model['peer_count']} peer address(es). Pre-shared key values are never displayed.", facets=[{"key": "state", "label": "state"}]))
    # What each tunnel protects and where it is applied: a table of its own, because the selector lists are long and would squeeze the inventory.
    traffic = []
    for t in model["tunnels"]:
        selectors = list(t["proxy"])
        shown = selectors[:12] + ([f"… and {len(selectors) - 12} more"] if len(selectors) > 12 else [])
        traffic.append({"name": t["name"], "acl": t["acl"] or "", "applied_on": t["applied_on"], "proxy": shown})
    sections.append(table_section("vpn_traffic", "IPsec protected traffic", [("name", "Tunnel"), ("acl", "Crypto ACL"), ("applied_on", "Applied on", "list"), ("proxy", "Source → destination selectors", "list")], traffic,
                                  group="VPN & Crypto", hint="From the crypto ACL of each tunnel; each permit line is a pair of selectors that both ends must mirror."))
    offered = model.get("offered_ikev2") or []
    if offered:
        sections.append(table_section("ikev2_offered", "IKEv2 proposals offered", [("name", "Proposal"), ("policy", "Policy"), ("encryption", "Encryption", "list"), ("integrity", "Integrity", "list"), ("group", "DH group", "list"), ("assessment", "Assessment", "status")],
                                      [dict(o, assessment=", ".join(o["weak"]) or "acceptable", _tones={"assessment": "bad" if o["weak"] else "ok"}) for o in offered], group="VPN & Crypto",
                                      hint="Proposals reachable through an IKEv2 policy. The responder accepts the first one both sides support."))
    ikev2 = model.get("ikev2") or {}
    if ikev2.get("profiles"):
        sections.append(table_section("ikev2_profiles", "IKEv2 profiles", [("name", "Profile"), ("match_remote", "Matches remote", "list"), ("auth_local", "Local auth", "list"), ("auth_remote", "Remote auth", "list"), ("keyrings", "Keyring", "list"),
                                                                        ("lifetime", "Lifetime (s)"), ("dpd", "DPD")], [dict(p, dpd=p.get("dpd") or "not set") for p in ikev2["profiles"]], group="VPN & Crypto"))
    if model["reuse"]:
        sections.append(table_section("psk_reuse", "Pre-shared keys used for several peers", [("peers", "Peers", "list")], [{"peers": group} for group in model["reuse"]], group="VPN & Crypto",
                                      hint="Found by comparing salted hashes made for this analysis. The keys themselves are never read out or stored."))
    return sections


# ---------------------------------------------------------------------------
# OSPF participation
# ---------------------------------------------------------------------------


def ospf_participation(ctx: Ctx) -> list[dict[str, Any]]:
    model = ctx.models.get("ospf")
    if not model:
        return []
    sections: list[dict[str, Any]] = []
    state_label = {"running": "running", "empty": "no interface participates", "no_match": "no network statement matches", "all_passive": "all interfaces passive or shut"}
    sections.append(table_section("ospf_state", "OSPF process state (from configuration)", [("process", "Process"), ("vrf", "VRF"), ("state", "State", "status"), ("interfaces", "Participating interfaces", "num"), ("areas", "Areas", "list")],
                                  [{"process": p["process"], "vrf": p.get("vrf") or "global", "state": state_label[p["state"]], "interfaces": len(p["interfaces"]), "areas": p["areas"],
                                    "_tones": {"state": "ok" if p["state"] == "running" else "bad" if p["state"] == "all_passive" else "warn"}} for p in model["processes"]], group="OSPF / EIGRP",
                                  hint="An interface joins a process through a matching 'network … area' statement (most specific wins) or 'ip ospf <process> area <n>' on the interface, which takes precedence.", facets=[{"key": "state", "label": "state"}]))
    sections.append(table_section("ospf_participation", "Interfaces running OSPF (from configuration)", [("interface", "Interface", "mono"), ("description", "Description", "wrap"), ("ip", "Address", "mono"), ("process", "Process"), ("area", "Area"), ("how", "Enabled by"), ("passive", "Passive"),
                                                                                                         ("network_type", "Network type"), ("cost", "Cost"), ("auth", "Authentication"), ("bfd", "BFD"), ("state", "Live state", "status"), ("neighbors_listed", "Live neighbours", "list")],
                                  [dict(r, passive=_yes(r["passive"]), bfd=_yes(r["bfd"]), _tones={"passive": "warn" if r["passive"] else "", "state": "ok" if str(r["state"]).upper() in ("DR", "BDR", "DROTHER", "P2P", "P2MP") else ("warn" if r["state"] else "")}) for r in model["interfaces"]],
                                  group="OSPF / EIGRP", empty="No interface participates in OSPF.", facets=[{"key": "state", "label": "state"}]))
    return sections
