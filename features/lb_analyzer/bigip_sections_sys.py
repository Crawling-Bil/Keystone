"""Live tabs built from the system, network and traffic ``show`` output (see ``bigip_runtime_sys``): licence and modules, HA, ports, ARP, load, TLS, iRules."""

from __future__ import annotations

from datetime import date
from typing import Any

from ..analyzer_core.result import kv_section, table_section

GROUP = "Live state"
_AVAIL = {"available": "ok", "offline": "bad", "unavailable": "warn"}
_PORT = {"up": "ok", "down": "bad", "disabled": "mute", "uninit": "mute", "unpopulated": "mute", "fail": "bad", "miss": "warn"}
_HA = {"active": "ok", "standby": "ok"}
_LOAD_TONE = ((90, "bad"), (70, "warn"))


def sys_sections(runtime: dict[str, Any], today: date | None = None) -> list[dict[str, Any]]:
    today = today or date.today()
    out: list[dict[str, Any]] = []
    lic = runtime.get("license")
    if lic and (lic.get("platform") or lic.get("bundles")):
        pairs: list[tuple] = [("Platform", lic["platform"]), ("Appliance serial", lic["serial"]), ("Licensed version", lic["licensed_version"]), ("Licensed on", lic["licensed_on"]),
                              ("Service check date", lic["service_check"])]
        for bundle in lic["bundles"]:
            pairs.append(("Bundle", f"{bundle['name']} ({len(bundle['features'])} features)"))
        for item in lic["limited"]:
            days = (item["end_date"] - today).days if item["end_date"] else None
            tone = "bad" if days is not None and days < 0 else ("warn" if days is not None and days <= 90 else "ok")
            pairs.append((f"Time-limited: {item['name']}", f"{item['kind'].lower()}, ends {item['end_date'] or item['end']}", tone))
        out.append(kv_section("license_live", "Licence (live)", [p for p in pairs if p[1]], group=GROUP, hint="The registration key is not read, kept or shown."))
    provision = runtime.get("provision")
    if provision:
        rows = [dict(p, level="provisioned" if p["provisioned"] else "none", _tones={"level": "ok" if p["provisioned"] else "mute"}) for p in provision]
        out.append(table_section("provision_live", "Provisioned modules (live)", [("module", "Module", "mono"), ("level", "State", "status"), ("cpu", "CPU %", "num"), ("memory", "Memory (MB)", "num"),
                                                                             ("host_memory", "Host memory (MB)", "num"), ("disk", "Disk (MB)", "num")], rows, group=GROUP, page_size=40,
                                 facets=[{"key": "level", "label": "state"}]))
    devices = runtime.get("cm_devices")
    if devices:
        rows = [dict(d, _tones={"state": _HA.get(d["state"].lower(), "warn")}) for d in devices]
        out.append(table_section("cm_devices_live", "Device group members (live)", [("hostname", "Device", "mono"), ("state", "HA state", "status"), ("mgmt_ip", "Management IP", "mono"), ("configsync_ip", "Config-sync IP", "mono"),
                                                                                  ("mirror_ip", "Mirror IP", "mono"), ("failover_ip", "Failover addresses", "wrap"), ("load", "Load factor", "num")], rows, group=GROUP))
    links = (runtime.get("failover") or {}).get("connections")
    if links:
        rows = [dict(l, _tones={"status": "ok" if l["status"].lower() == "ok" else "bad"}) for l in links]
        out.append(table_section("failover_links_live", "Failover connections (live)", [("local", "Local address", "mono"), ("remote", "Peer", "mono"), ("status", "Status", "status"), ("transitions", "Transitions", "num"),
                                                                                       ("last", "Last packet"), ("packets", "Packets", "num")], rows, group=GROUP,
                                 hint="Transitions count how often the path changed state since the counters started: a high number on one path points at a flapping link."))
    groups = runtime.get("cm_groups")
    if groups:
        out.append(table_section("cm_groups_live", "Device group sync (live)", [("group", "Group", "mono"), ("member", "Member", "mono"), ("sync_type", "Last sync type"), ("since_sync", "Since last sync"),
                                                                              ("originator", "Config originator", "mono")], groups, group=GROUP))
    ha = runtime.get("ha_status")
    if ha:
        failed = [h for h in ha if h["failed"]]
        rows = [dict(h, fail="yes" if h["failed"] else "no", _tones={"fail": "bad" if h["failed"] else "ok"}) for h in sorted(ha, key=lambda h: (not h["failed"], h["feature"], h["key"]))]
        out.append(table_section("ha_status_live", "HA conditions (live)", [("feature", "Feature", "mono"), ("key", "Key", "mono"), ("action", "Action when it fails"), ("fail", "Triggered", "status")], rows, group=GROUP, page_size=80,
                                 hint=f"{len(ha)} conditions checked, {len(failed)} triggered.", facets=[{"key": "fail", "label": "triggered"}]))
    ports = (runtime.get("interfaces") or []) + [dict(t, trunk=t["trunk"] or t["name"]) for t in runtime.get("trunks") or []]
    if ports:
        rows = [dict(p, _tones={"status": _PORT.get(p["status"].lower(), "mute"), "errors": "bad" if p["errors_n"] else "", "drops": "warn" if p["drops_n"] else ""}) for p in ports]
        out.append(table_section("interfaces_live", "Interfaces and trunks (live)", [("name", "Port", "mono"), ("trunk", "Trunk", "mono"), ("status", "Status", "status"), ("media", "Media"), ("bits_in", "Bits in", "num"),
                                                                                  ("bits_out", "Bits out", "num"), ("pkts_in", "Packets in", "num"), ("pkts_out", "Packets out", "num"), ("drops", "Drops", "num"), ("errors", "Errors", "num")],
                                 rows, group=GROUP, page_size=60, hint="Counters are cumulative since the last reset.", facets=[{"key": "status", "label": "status"}]))
    lldp = runtime.get("lldp")
    if lldp:
        cols = [(key, key.replace("_", " ").title()) for key in lldp[0]]
        out.append(table_section("lldp_live", "LLDP neighbors (live)", cols, lldp, group=GROUP))
    arp = runtime.get("arp")
    if arp:
        rows = [dict(a, _tones={"status": "ok" if a["status"].lower() == "resolved" else "warn", "mac": "warn" if a["mac"] == "incomplete" else ""}) for a in arp]
        out.append(table_section("arp_live", "ARP table (live)", [("address", "Address", "mono"), ("mac", "MAC", "mono"), ("vlan", "VLAN", "mono"), ("expire", "Expires in (s)", "num"), ("status", "Status", "status")],
                                 rows, group=GROUP, page_size=100, facets=[{"key": "vlan", "label": "VLAN"}, {"key": "status", "label": "status"}]))
    perf = runtime.get("performance")
    if perf:
        rows = []
        for r in perf:
            tone = ""
            if r["unit"] == "%" and r["current_n"] is not None:
                tone = next((t for limit, t in _LOAD_TONE if r["current_n"] >= limit), "")
            rows.append(dict(r, name=f"{r['group']} / {r['metric']}", unit=r["unit"] or "-", _tones={"current": tone}))
        out.append(table_section("performance_live", "Performance (live)", [("group", "Group"), ("metric", "Metric", "mono"), ("unit", "Unit"), ("current", "Current", "num"), ("average", "Average", "num"), ("maximum", "Maximum", "num"),
                                                                            ("since", "Maximum since")], rows, group=GROUP, page_size=60, facets=[{"key": "group", "label": "group"}]))
    vaddr = runtime.get("virtual_addresses")
    if vaddr:
        rows = [dict(v, _tones={"availability": _AVAIL.get(v["availability"].lower(), "mute"), "state": "ok" if v["state"].lower() == "enabled" else "mute"}) for v in vaddr]
        out.append(table_section("virtual_addresses_live", "Virtual addresses (live)", [("address", "Address", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("connections", "Connections", "num"),
                                                                                       ("maximum", "Max connections", "num"), ("total", "Total", "num"), ("bits_in", "Bits in", "num"), ("bits_out", "Bits out", "num"), ("reason", "Reason", "wrap")],
                                 rows, group=GROUP, page_size=100, facets=[{"key": "availability", "label": "availability"}]))
    ssl = (runtime.get("client_ssl") or []) + (runtime.get("server_ssl") or [])
    if ssl:
        rows = []
        for p in ssl:
            rows.append(dict(p, side=p["kind"], versions=[f"{k.replace(' Protocol Version', '')}: {v}" for k, v in p["protocols"].items()] or ["-"],
                             _tones={"legacy": "bad" if p["legacy"] else ("ok" if p["total_n"] else "mute")}))
        rows.sort(key=lambda r: (-(r["total_n"] or 0), r["name"]))
        out.append(table_section("ssl_stats_live", "SSL profile statistics (live)", [("name", "Profile", "mono"), ("side", "Side"), ("virtual", "Virtual server", "mono"), ("total", "Native connections", "num"), ("open", "Open", "num"),
                                                                                  ("secure", "Secure handshakes", "num"), ("insecure_accepted", "Insecure handshakes accepted", "num"), ("legacy", "TLS 1.0/1.1/SSL handshakes", "num"),
                                                                                  ("versions", "Negotiated versions", "list")], rows, group=GROUP, page_size=60, facets=[{"key": "side", "label": "side"}],
                                 hint="A profile with a non-zero 'TLS 1.0/1.1/SSL' count still serves clients that negotiate a deprecated protocol (RFC 8996)."))
    rules = runtime.get("rules")
    if rules:
        used = sorted(rules, key=lambda r: (-r["total"], r["rule"]))
        rows = [dict(r, _tones={"failures": "bad" if r["failures"] else "", "aborts": "bad" if r["aborts"] else ""}) for r in used]
        out.append(table_section("rules_live", "iRule statistics (live)", [("rule", "iRule", "mono"), ("event", "Event", "mono"), ("priority", "Priority", "num"), ("total", "Executions", "num"), ("failures", "Failures", "num"),
                                                                         ("aborts", "Aborts", "num"), ("average", "Average CPU cycles", "num"), ("maximum", "Maximum CPU cycles", "num")], rows, group=GROUP, page_size=100,
                                 hint="Sorted by executions: the rules at the top are on the traffic path, the ones with 0 executions are candidates for clean-up."))
    return out
