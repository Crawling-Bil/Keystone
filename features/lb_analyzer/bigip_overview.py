"""The overview of a BIG-IP result: summary cards, device information, the coverage table and the notes under the findings.

Pure presentation - everything is computed from the dictionaries ``service.analyze`` already built.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from ..analyzer_core.findings import severity_counts
from ..analyzer_core.result import card, info_rows
from . import bigip_extract, bigip_runtime
from .tmsh_tree import TmshTree

# parsers written from the documented 'show' layouts but not yet run on a captured BIG-IP
UNVALIDATED = {"version": "show sys version", "sync": "show cm sync-status", "failover": "show cm failover-status", "virtuals": "show ltm virtual", "pools": "show ltm pool", "pool_members": "show ltm pool members", "nodes": "show ltm node",
               "gtm_wideips": "show gtm wideip", "gtm_pools": "show gtm pool", "gtm_servers": "show gtm server", "gtm_datacenters": "show gtm datacenter", "gtm_iquery": "show gtm iquery", "gtm_listeners": "show gtm listener"}


def cards(data: dict[str, Any], findings: list[dict[str, Any]], runtime: dict[str, Any], today: date) -> list[dict[str, Any]]:
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
    extra = data["extra"]
    if extra["asm_policies"]:
        loose = [p for p in extra["asm_policies"] if not p["attached_to"]]
        cards.append(card("Advanced WAF policies", len(extra["asm_policies"]), "warn" if loose else "ok", f"{len(loose)} not attached to a virtual server" if loose else "all attached", "asm_policies"))
    ucs = data.get("ucs")
    if ucs:
        soon = [m for m in ucs["bundle"].license.get("timelimited", []) if m["end"]]
        if soon:
            first = min(soon, key=lambda m: m["end"])
            days = (first["end"] - today).days
            cards.append(card("License subscriptions", len(soon), "bad" if days < 0 else "warn" if days <= 90 else "ok", f"{first['module']} {'ended' if days < 0 else 'ends'} {first['end']}", "license_modules"))
    if ucs and ucs["history"]["count"]:
        hist = ucs["history"]
        parked = [f for f in findings if f["id"] in ("LB-CHG-001", "LB-CHG-002")]
        cards.append(card("Config saves (30 days)", hist["last_30_days"], "info", f"last save {(today - hist['last'].date()).days} days ago · {hist['count']} recorded", "change_log"))
        if parked:
            cards.append(card("Parked for 30+ days", len(parked), "warn", "members or virtual servers left disabled", "change_still_disabled"))
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


def info(data: dict[str, Any], runtime: dict[str, Any], tree: TmshTree) -> list[dict[str, Any]]:
    info, sysd = data["info"], data["sys"]
    mods = [f"{m['module'].upper()} ({m['level']})" for m in sysd["provision"] if m["level"] != "none"]
    live = runtime.get("version", {})
    pairs = [
        ("Hostname", info["hostname"] or runtime.get("hostname")), ("Platform", info["platform"] or info["platform_id"]), ("TMOS version", info["version"] or live.get("version")), ("Build", live.get("build")), ("Failover state", info["failover_state"]),
        ("Management IP", ", ".join(sysd["management_ip"])), ("Provisioned", ", ".join(mods)), ("Partitions", ", ".join(bigip_extract.short(f) for f in sysd["folders"])),
        ("Devices in cluster", len(data["devices"]) or ""), ("Time zone", sysd["ntp"]["timezone"]), ("Capture", f"{tree.lines:,} lines"),
    ]
    ucs = data.get("ucs")
    if ucs:
        bundle = ucs["bundle"]
        pairs += [("Source", "UCS archive"), ("Build", bundle.version.get("Build")), ("License", bundle.license.get("fields", {}).get("Usage") or bundle.license.get("fields", {}).get("Licensed version")),
                  ("Last configuration change", ucs["facts"]["last_config_change"].strftime("%Y-%m-%d %H:%M UTC") if ucs["facts"]["last_config_change"] else "")]
    return info_rows(pairs)


def coverage(data: dict[str, Any], tree: TmshTree, runtime: dict[str, Any]) -> list[dict[str, Any]]:
    sysd = data["sys"]
    counts = f"{len(data['virtuals'])} virtual servers, {len(data['pools'])} pools, {len(data['nodes'])} nodes, {len(data['monitors'])} monitors, {len(data['profiles'])} profiles, {len(data['irules'])} iRules"
    dns_only = not sysd["has_ltm"] and bool(data.get("gtm"))
    rows = [{"command": "ltm (tmsh list ltm ... / bigip.conf)", "status": "analyzed" if sysd["has_ltm"] else ("covered" if dns_only else "missing"), "lines": tree.lines, "note": counts if sysd["has_ltm"] else ("No LTM objects: this is a DNS-only unit; see the DNS (GTM) tab." if dns_only else "No virtual servers, pools or nodes. Add bigip.conf, or run 'tmsh list ltm virtual', 'ltm pool', 'ltm node', 'ltm monitor', 'ltm profile', 'ltm rule'."), "tone": "ok" if sysd["has_ltm"] else ("info" if dns_only else "warn")},
            {"command": "net / sys / auth (bigip_base.conf)", "status": "analyzed" if sysd["has_base"] else "missing", "lines": 0,
             "note": (f"{len(data['vlans'])} VLANs, {len(data['selfs'])} self IPs; management-plane rules were evaluated." if sysd["has_base"] else "Not in this export: management rules (GUI/SSH allow lists, SNMP, NTP, syslog, password policy, self IP port lockdown) were skipped. Add bigip_base.conf, or use 'tmsh list' for the whole configuration."),
             "tone": "ok" if sysd["has_base"] else "warn"},
            {"command": "sys file ssl-cert", "status": "analyzed" if data["certs"] else "missing", "lines": 0, "note": f"{len(data['certs'])} certificate objects; expiry and key size were checked." if data["certs"] else "No certificate objects: expiry dates were not checked. Run 'tmsh list sys file ssl-cert'.", "tone": "ok" if data["certs"] else "warn"},
            {"command": "cm device / device-group / traffic-group", "status": "analyzed" if data["devices"] or data["device_groups"] else "missing", "lines": 0,
             "note": f"{len(data['devices'])} device(s), {len(data['device_groups'])} device group(s)." if data["devices"] or data["device_groups"] else "No HA objects in the export; availability rules were skipped.", "tone": "ok" if data["devices"] or data["device_groups"] else "warn"}]
    keys = {"show sys version": "version", "show cm sync-status": "sync", "show cm failover-status": "failover", "show ltm virtual": "virtuals", "show ltm pool": "pools", "show ltm pool members": "pool_members", "show ltm node": "nodes",
            "show gtm wideip a detail": "gtm_wideips", "show gtm pool a detail": "gtm_pools", "show gtm server detail": "gtm_servers", "show gtm datacenter": "gtm_datacenters", "show gtm iquery": "gtm_iquery", "show gtm listener": "gtm_listeners"}
    dns_unit = bool(data.get("gtm")) or any(k.startswith("gtm_") for k in runtime)
    for command, purpose in bigip_runtime.COMMANDS + (bigip_runtime.GTM_COMMANDS if dns_unit else ()):
        key = keys.get(command)
        if key and key in runtime:
            rows.append({"command": command, "status": "analyzed", "lines": 0, "note": "Shown on the Live state tab.", "tone": "ok"})
        elif key:
            rows.append({"command": command, "status": "missing", "lines": 0, "note": "Not in this capture - would add: " + purpose, "tone": "warn"})
    ucs = data.get("ucs")
    if ucs:
        b = ucs["bundle"]
        rows.append({"command": "UCS archive (.ucs)", "status": "analyzed", "lines": 0, "note": f"{b.members:,} entries streamed; {len(b.files)} configuration files, {len(b.certs)} public certificates, the license, {len(b.db)} customised sys db values, {len(b.history)} saved-configuration patches, accounts and OS access rules were read. Private keys, the master key store, password files and shell histories were skipped.", "tone": "ok"})
    else:
        rows.append({"command": "UCS archive (.ucs)", "status": "missing", "lines": 0, "note": "Not uploaded: certificate validity beyond what bigip_base.conf states, license subscription dates, the last change / failover times and customised sys db values are only in the UCS.", "tone": "info"})
    rows.append({"command": "tmsh list / bigip.conf: default values", "status": "covered", "lines": 0,
                 "note": "'tmsh list' and bigip.conf print only values that differ from the default; findings that depend on a default quote the documented value. 'all-properties' prints every value (needed to see inherited SSL options).", "tone": "info"})
    return rows


def notes(data: dict[str, Any], runtime: dict[str, Any]) -> list[str]:
    notes = ["The configuration parser and rules were verified on synthetic configurations and on one captured BIG-IP UCS. ASM enforcement mode and signature settings are not in a UCS configuration file, so they are not assessed."]
    used = [label for key, label in UNVALIDATED.items() if key in runtime]
    if used:
        notes.append("Live-state tables are parsed from the documented 'show' layout and not yet validated against a captured BIG-IP: " + ", ".join(used) + ".")
    if not data["sys"]["has_base"]:
        notes.append("bigip_base.conf (net, sys, auth, cm) is not part of this export, so management-plane rules were not evaluated.")
    return notes
