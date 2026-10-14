"""Load Balancer Analyzer entry point (F5 BIG-IP / TMOS).

``analyze`` takes the text of a BIG-IP capture or export and returns a
``keystone.analysis/1`` result.  The input can be a prompted terminal capture
(``tmsh list ...`` plus ``show`` commands), the output of ``tmsh list`` /
``tmsh show running-config``, or ``bigip.conf`` / ``bigip_base.conf``.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from ..analyzer_core.findings import severity_counts
from ..analyzer_core.result import card, info_rows, kv_section, new_result, table_section
from . import bigip_extract, bigip_rules, bigip_runtime, bigip_sections
from .tmsh_tree import TmshTree, parse_tmsh

PLATFORMS: tuple[tuple[str, str], ...] = ()          # one vendor so far; the page hides the selector

# parsers written from the documented 'show' layouts but not yet run on a captured BIG-IP
UNVALIDATED = {"version": "show sys version", "sync": "show cm sync-status", "failover": "show cm failover-status", "virtuals": "show ltm virtual", "pools": "show ltm pool"}

_F5 = re.compile(r"^(#TMSH-VERSION:|ltm (?:virtual|pool|node|monitor|profile|rule|data-group|policy)\b|net (?:self|vlan|route|trunk)\b|sys (?:global-settings|httpd|sshd|snmp|ntp|provision)\b|cm (?:device|device-group|traffic-group)\b|auth (?:user|ldap|source)\b)", re.M)
_FORTI = re.compile(r"^(#config-version=FG|config (?:system global|firewall policy|system interface)\b)", re.M)
_CISCO_HUAWEI = re.compile(r"^(interface (?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Vlan|XGigabitEthernet|Eth-Trunk)|router (?:bgp|ospf|eigrp)|sysname |vlan batch|spanning-tree mode)", re.M)
_PANOS = re.compile(r"^(set (?:deviceconfig|rulebase|network|zone|vsys)\b|<config\b[^>]*version=)", re.M)


def _wrong_page_hint(text: str) -> str:
    if _FORTI.search(text) or _PANOS.search(text):
        return " This looks like a firewall configuration - open the Firewall Analyzer."
    if _CISCO_HUAWEI.search(text):
        return " This looks like a Cisco or Huawei switch/router configuration - open the Router Analyzer or Switch Analyzer."
    return ""


def looks_like_bigip(text: str) -> bool:
    return bool(_F5.search(text[:3_000_000]))


def analyze(content: str, filename: str = "", platform: str = "auto", today: date | None = None) -> dict[str, Any]:
    today = today or date.today()
    runtime = bigip_runtime.gather(content)
    text = runtime["config_text"] or content
    if not looks_like_bigip(text):
        raise ValueError(
            "No F5 BIG-IP configuration was recognised. The Load Balancer Analyzer reads the stanza format of bigip.conf / bigip_base.conf, 'tmsh list' and 'tmsh show running-config' "
            "(for example 'ltm virtual /Common/name { ... }')." + _wrong_page_hint(content)
        )
    tree = parse_tmsh(text)
    if not tree.root:
        raise ValueError("No 'ltm', 'net', 'sys' or 'cm' blocks were found in the capture.")
    data = bigip_extract.extract(tree)
    findings = bigip_rules.evaluate(tree, data, today, runtime)
    warnings: list[str] = list(tree.warnings)
    sections = bigip_sections.build_all(data, findings, warnings, today)
    sections += _runtime_sections(runtime)

    info = data["info"]
    hostname = info["hostname"] or runtime.get("hostname") or filename.rsplit(".", 1)[0]
    version = info["version"] or runtime.get("version", {}).get("version", "")
    platform_name = " · ".join(filter(None, ["BIG-IP", info["platform"] or info["platform_id"], f"TMOS {version}" if version else ""]))
    sync_groups = [g for g in data["device_groups"] if g["type"] == "sync-failover" and not g["system_group"]]
    result = new_result(
        "lb",
        hostname=hostname,
        vendor="F5",
        platform=platform_name,
        source_name=filename,
        title=hostname,
        subtitle=" · ".join(filter(None, [info["platform"], f"TMOS {version}" if version else "", f"{len(data['virtuals'])} virtual servers", f"HA {', '.join(g['short'] for g in sync_groups)}" if sync_groups else "standalone" if data["devices"] or data["device_groups"] else ""])),
    )
    result["sections"] = sections
    known = {s["id"] for s in sections} | {"findings", "overview", "coverage"}
    result["cards"] = [c if not c.get("section") or c["section"] in known else dict(c, section="") for c in _cards(data, findings, runtime, today)]
    result["info"] = _info(data, runtime, tree)
    result["findings"] = findings
    result["coverage"] = _coverage(data, tree, runtime)
    result["warnings"] = warnings + _notes(data, runtime)
    result["capture"] = {"commands": len(runtime["capture"].blocks) if "capture" in runtime else 0, "lines": tree.lines, "has_config": True}
    return result


# ------------------------------------------------------------------------ live state
def _runtime_sections(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pairs = []
    version = runtime.get("version")
    if version:
        pairs += [(k.title(), v) for k, v in version.items()]
    sync = runtime.get("sync")
    if sync and sync.get("status"):
        pairs.append(("Config sync", sync["status"], "ok" if sync["status"].lower() in ("in sync", "standalone") else "bad"))
        if sync.get("summary"):
            pairs.append(("Sync summary", sync["summary"]))
    fo = runtime.get("failover")
    if fo and fo.get("status"):
        pairs.append(("Failover", fo["status"], "ok" if fo["status"].lower() in ("active", "standby", "standalone") else "bad"))
        if fo.get("summary"):
            pairs.append(("Failover summary", fo["summary"]))
    if pairs:
        out.append(kv_section("status_live", "System status (live)", pairs, group="Live state"))
    vs = runtime.get("virtuals")
    if vs is not None:
        rows = [dict(v, _tones={"availability": {"available": "ok", "offline": "bad", "unavailable": "warn"}.get(v["availability"].lower(), "mute"), "state": "ok" if v["state"].lower() == "enabled" else "mute"}) for v in vs]
        out.append(table_section("virtuals_live", "Virtual servers (live)", [("name", "Virtual server", "mono"), ("destination", "Destination", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("connections", "Current connections", "num"), ("reason", "Reason", "wrap")],
                                 rows, group="Live state", empty="No virtual server status in the capture.", page_size=100))
    ps = runtime.get("pools")
    if ps is not None:
        rows = []
        for p in ps:
            tone = "ok"
            if p["total"] and p["available"] == 0:
                tone = "bad"
            elif p["total"] and p["available"] is not None and p["available"] < p["total"]:
                tone = "warn"
            rows.append(dict(p, members=f"{p['available']}/{p['total']}" if p["total"] is not None else "", _tones={"members": tone, "availability": {"available": "ok", "offline": "bad", "unavailable": "warn"}.get(p["availability"].lower(), "mute")}))
        out.append(table_section("pools_live", "Pools (live)", [("name", "Pool", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("members", "Available / total", "num"), ("reason", "Reason", "wrap")],
                                 rows, group="Live state", empty="No pool status in the capture.", page_size=100))
    return out


# ------------------------------------------------------------------------ overview
def _cards(data: dict[str, Any], findings: list[dict[str, Any]], runtime: dict[str, Any], today: date) -> list[dict[str, Any]]:
    cards = []
    info = data["info"]
    version = info["version"] or runtime.get("version", {}).get("version", "")
    cards.append(card("Platform", info["platform"] or "BIG-IP", "info", f"TMOS {version}" if version else "", "system"))
    vs = data["virtuals"]
    enabled = [v for v in vs if v["enabled"]]
    cards.append(card("Virtual servers", f"{len(enabled)}/{len(vs)}", "info", f"{sum(1 for v in enabled if v['public'])} public · {len(vs) - len(enabled)} disabled", "virtuals"))
    pools = data["pools"]
    ids = {f["id"] for f in findings}
    members = [m for p in pools for m in p["members"]]
    nomon_findings = [f for f in findings if f["id"] == "LB-POOL-001"]
    nomon = len(nomon_findings)
    nomon_tone = "bad" if any(f["severity"] == "high" for f in nomon_findings) else "warn"      # medium = only a node monitor protects it
    cards.append(card("Pools", len(pools), nomon_tone if nomon else "info", f"{nomon} without a service monitor" if nomon else f"{len(members)} members", "pools"))
    parked = sum(1 for m in members if m["disabled"] or m["forced_down"])
    if members:
        cards.append(card("Pool members", len(members), "warn" if parked else "info", f"{parked} disabled or forced down" if parked else "all enabled", "members"))
    ssl_profiles = [p for p in data["profiles"] if p["kind"] in ("client-ssl", "server-ssl")]
    if ssl_profiles:
        tone = "bad" if ids & {"LB-SSL-001", "LB-SSL-003"} else ("warn" if ids & {"LB-SSL-002", "LB-SSL-005", "LB-SSL-009"} else "ok")
        cards.append(card("SSL profiles", len(ssl_profiles), tone, f"{sum(1 for f in findings if f['id'] in ('LB-SSL-001', 'LB-SSL-002', 'LB-SSL-003'))} with legacy protocols or ciphers", "ssl_profiles"))
    dated = [c for c in data["certs"] if c["expires"] and not c["system"]]
    if dated:
        soonest = min(dated, key=lambda c: c["expires"])
        days = (soonest["expires"] - today).days
        cards.append(card("Certificates", len(dated), "bad" if days < 0 else "warn" if days <= 30 else "ok", f"{soonest['short']} {'expired' if days < 0 else 'expires'} {abs(days)} day(s) {'ago' if days < 0 else 'from now'}", "certificates"))
    groups = [g for g in data["device_groups"] if g["type"] == "sync-failover" and not g["system_group"]]
    if groups:
        cards.append(card("HA", f"{len(groups[0]['devices'])} units", "ok", f"{groups[0]['short']} · auto-sync {groups[0]['auto_sync']}", "device_groups"))
    elif data["devices"]:
        cards.append(card("HA", "standalone", "warn", "no sync-failover group", "devices"))
    sync = runtime.get("sync")
    if sync and sync.get("status"):
        cards.append(card("Config sync", sync["status"], "ok" if sync["status"].lower() in ("in sync", "standalone") else "bad", "live", "status_live"))
    exposed = ids & {"LB-MGT-001", "LB-MGT-002", "LB-MGT-004", "LB-MGT-012"}
    if exposed:
        cards.append(card("Management exposure", len(exposed), "bad", "GUI, SSH or self IP open", "hardening"))
    counts = severity_counts(findings)
    cards.append(card("High findings", counts["high"], "bad" if counts["high"] else "ok", "", "findings"))
    cards.append(card("Medium findings", counts["medium"], "warn" if counts["medium"] else "ok", f"{counts['low']} low · {counts['info']} info", "findings"))
    return cards


def _info(data: dict[str, Any], runtime: dict[str, Any], tree: TmshTree) -> list[dict[str, Any]]:
    info, sysd = data["info"], data["sys"]
    mods = [f"{m['module'].upper()} ({m['level']})" for m in sysd["provision"] if m["level"] != "none"]
    live = runtime.get("version", {})
    pairs = [
        ("Hostname", info["hostname"] or runtime.get("hostname")), ("Platform", info["platform"] or info["platform_id"]), ("TMOS version", info["version"] or live.get("version")), ("Build", live.get("build")), ("Failover state", info["failover_state"]),
        ("Management IP", ", ".join(sysd["management_ip"])), ("Provisioned", ", ".join(mods)), ("Partitions", ", ".join(bigip_extract.short(f) for f in sysd["folders"])),
        ("Devices in cluster", len(data["devices"]) or ""), ("Time zone", sysd["ntp"]["timezone"]), ("Capture", f"{tree.lines:,} lines"),
    ]
    return info_rows(pairs)


def _coverage(data: dict[str, Any], tree: TmshTree, runtime: dict[str, Any]) -> list[dict[str, Any]]:
    sysd = data["sys"]
    counts = f"{len(data['virtuals'])} virtual servers, {len(data['pools'])} pools, {len(data['nodes'])} nodes, {len(data['monitors'])} monitors, {len(data['profiles'])} profiles, {len(data['irules'])} iRules"
    rows = [{"command": "ltm (tmsh list ltm ... / bigip.conf)", "status": "analysed" if sysd["has_ltm"] else "missing", "lines": tree.lines, "note": counts if sysd["has_ltm"] else "No virtual servers, pools or nodes. Add bigip.conf, or run 'tmsh list ltm virtual', 'ltm pool', 'ltm node', 'ltm monitor', 'ltm profile', 'ltm rule'.", "tone": "ok" if sysd["has_ltm"] else "warn"},
            {"command": "net / sys / auth (bigip_base.conf)", "status": "analysed" if sysd["has_base"] else "missing", "lines": 0,
             "note": (f"{len(data['vlans'])} VLANs, {len(data['selfs'])} self IPs; management-plane rules were evaluated." if sysd["has_base"] else "Not in this export: management rules (GUI/SSH allow lists, SNMP, NTP, syslog, password policy, self IP port lockdown) were skipped. Add bigip_base.conf, or use 'tmsh list' for the whole configuration."),
             "tone": "ok" if sysd["has_base"] else "warn"},
            {"command": "sys file ssl-cert", "status": "analysed" if data["certs"] else "missing", "lines": 0, "note": f"{len(data['certs'])} certificate objects; expiry and key size were checked." if data["certs"] else "No certificate objects: expiry dates were not checked. Run 'tmsh list sys file ssl-cert'.", "tone": "ok" if data["certs"] else "warn"},
            {"command": "cm device / device-group / traffic-group", "status": "analysed" if data["devices"] or data["device_groups"] else "missing", "lines": 0,
             "note": f"{len(data['devices'])} device(s), {len(data['device_groups'])} device group(s)." if data["devices"] or data["device_groups"] else "No HA objects in the export; availability rules were skipped.", "tone": "ok" if data["devices"] or data["device_groups"] else "warn"}]
    keys = {"show sys version": "version", "show cm sync-status": "sync", "show cm failover-status": "failover", "show ltm virtual": "virtuals", "show ltm pool": "pools"}
    for command, purpose in bigip_runtime.COMMANDS:
        key = keys.get(command)
        if key and key in runtime:
            rows.append({"command": command, "status": "analysed", "lines": 0, "note": "Shown on the Live state tab.", "tone": "ok"})
        elif key:
            rows.append({"command": command, "status": "missing", "lines": 0, "note": "Not in this capture - would add: " + purpose, "tone": "warn"})
    rows.append({"command": "tmsh list / bigip.conf: default values", "status": "covered", "lines": 0,
                 "note": "'tmsh list' and bigip.conf print only values that differ from the default; findings that depend on a default quote the documented value. 'all-properties' prints every value (needed to see inherited SSL options).", "tone": "info"})
    return rows


def _notes(data: dict[str, Any], runtime: dict[str, Any]) -> list[str]:
    notes = ["The BIG-IP parser and rules are verified on synthetic configurations written from F5's documented TMSH syntax; they have not yet been run against a captured BIG-IP. Check the first real capture against the device."]
    used = [label for key, label in UNVALIDATED.items() if key in runtime]
    if used:
        notes.append("Live-state tables are parsed from the documented 'show' layout and not yet validated against a captured BIG-IP: " + ", ".join(used) + ".")
    if not data["sys"]["has_base"]:
        notes.append("bigip_base.conf (net, sys, auth, cm) is not part of this export, so management-plane rules were not evaluated.")
    return notes
