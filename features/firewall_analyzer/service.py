"""Firewall Analyzer entry point.

``analyze`` takes the text of a firewall capture or export and returns a
``keystone.analysis/1`` result.  FortiGate is parsed natively (tree parser,
rules, runtime ``get`` output); Palo Alto PAN-OS and MikroTik RouterOS go
through Configuration Studio's parsers via :mod:`legacy`.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import date
from typing import Any

from ..analyzer_core.findings import severity_counts
from ..analyzer_core.result import card, info_rows, kv_section, new_result, table_section
from . import forti_extract, forti_rules, forti_runtime, forti_sections, legacy
from .forti_resolve import Resolver
from .forti_tree import parse_forti

PLATFORMS = (("auto", "Auto detect"), ("fortigate", "Fortinet FortiGate")) + ((("paloalto", "Palo Alto PAN-OS"), ("mikrotik", "MikroTik RouterOS")) if legacy.available() else ())

# parsers written from Fortinet's documented output format but not yet run on a captured FortiGate
UNVALIDATED = {
    "routes": "get router info routing-table all", "bgp": "get router info bgp summary", "ipsec": "get vpn ipsec tunnel summary", "ha": "get system ha status",
}

_FORTI = re.compile(r"^(#config-version=FG|config (?:system global|firewall policy|system interface|vpn ipsec phase1-interface|system admin)\b|config vdom\b)", re.M)
_PANOS = re.compile(r"^(set (?:deviceconfig|rulebase|network|zone|shared|vsys|device-group|template)\b|<config\b[^>]*version=|<entry name=\"localhost\.localdomain\")", re.M)
_MIKROTIK = re.compile(r"^(/(?:ip|interface|system|routing|user|queue|tool)\b|# .*by RouterOS)", re.M)
_CISCO_HINT = re.compile(r"^(interface (?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Vlan)|router (?:bgp|ospf|eigrp)|ip route \d|spanning-tree mode|switchport mode)", re.M)
_F5_HINT = re.compile(r"^(ltm (?:virtual|pool|node|monitor)\b|net self\b|sys global-settings\b|tmsh |cm device-group\b)", re.M)
_HUAWEI_HINT = re.compile(r"^(sysname |interface (?:GigabitEthernet|XGigabitEthernet|Eth-Trunk|Vlanif)|vlan batch)", re.M)


def detect_vendor(text: str) -> str:
    sample = text[:3_000_000]
    scores = {"fortigate": len(_FORTI.findall(sample)), "paloalto": len(_PANOS.findall(sample)), "mikrotik": len(_MIKROTIK.findall(sample))}
    best = max(scores, key=lambda key: scores[key])
    return best if scores[best] else ""


def _wrong_page_hint(text: str) -> str:
    if _F5_HINT.search(text):
        return " This looks like an F5 BIG-IP configuration - open the Load Balancer Analyzer."
    if _HUAWEI_HINT.search(text) or _CISCO_HINT.search(text):
        return " This looks like a Cisco or Huawei switch/router configuration - open the Router Analyzer or Switch Analyzer."
    return ""


def analyze(content: str, filename: str = "", platform: str = "auto", today: date | None = None) -> dict[str, Any]:
    vendor = platform if platform in ("fortigate", "paloalto", "mikrotik") else detect_vendor(content)
    if not vendor:
        raise ValueError(
            ("No FortiGate, Palo Alto or MikroTik configuration was recognised. The Firewall Analyzer reads a FortiOS 'show full-configuration' (config / edit / set / next / end), "
             "a PAN-OS 'set' or XML export, or a RouterOS '/export'." if legacy.available() else
             "No FortiGate configuration was recognised. The Firewall Analyzer reads a FortiOS 'show full-configuration' (config / edit / set / next / end).") + _wrong_page_hint(content)
        )
    if vendor == "fortigate":
        return _analyze_fortigate(content, filename, today)
    return legacy.analyze(content, filename, "Palo Alto" if vendor == "paloalto" else "Mikrotik")


# ------------------------------------------------------------------------ FortiGate
def _analyze_fortigate(content: str, filename: str, today: date | None) -> dict[str, Any]:
    tree = parse_forti(content)
    if not tree.root.children:
        raise ValueError("No 'config ... end' blocks were found. Paste the output of 'show full-configuration' (or 'show' for a short export)." + _wrong_page_hint(content))
    data = forti_extract.extract(tree)
    runtime = forti_runtime.gather(content)
    findings = forti_rules.evaluate(tree, data, today)
    warnings: list[str] = []
    sections = forti_sections.build_all(tree, data, findings, warnings)
    sections += _runtime_sections(runtime)
    res = Resolver(data)

    status = runtime.get("status", {})
    header = data["header"]
    hostname = data["global"].get("hostname") or status.get("Hostname") or runtime.get("hostname") or filename.rsplit(".", 1)[0]
    model = status.get("_model") or header.get("model") or "FortiGate"
    version = status.get("_version") or header.get("version", "")
    result = new_result(
        "firewall",
        hostname=hostname,
        vendor="Fortinet",
        platform=f"{model} · FortiOS {version}".strip(" ·"),
        source_name=filename,
        title=hostname,
        subtitle=" · ".join(filter(None, [model, f"FortiOS {version}" if version else "", "multi-VDOM" if data["multi_vdom"] else "single VDOM", f"HA {data['ha']['mode']}" if data["ha"] and data["ha"]["mode"] != "standalone" else ""])),
    )
    result["sections"] = sections
    known = {s["id"] for s in sections} | {"findings", "overview", "coverage"}
    result["cards"] = [c if not c.get("section") or c["section"] in known else dict(c, section="") for c in _cards(data, res, findings, runtime)]
    result["info"] = _info(data, runtime, tree)
    result["findings"] = findings
    result["coverage"] = _coverage(content, tree, runtime)
    result["warnings"] = warnings + _notes(runtime)
    result["capture"] = {"commands": len(runtime["capture"].blocks), "lines": tree.lines, "has_config": True}
    return result


def _runtime_sections(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    status = runtime.get("status")
    if status:
        pairs = [(k, status.get(k)) for k in ("Version", "Serial-Number", "Operation Mode", "Current virtual domain", "Max number of virtual domains", "Virtual domain configuration", "Current HA mode", "Branch point", "System time", "Last reboot reason", "License Status") if status.get(k)]
        out.append(kv_section("status_live", "System status (live)", pairs, group="Live state"))
    routes = runtime.get("routes")
    if routes is not None:
        out.append(table_section("routes_live", "Routing table (live)", [("vrf", "VRF"), ("protocol", "Protocol"), ("prefix", "Prefix", "mono"), ("next_hop", "Next hop", "mono"), ("interface", "Interface", "mono"), ("distance", "AD", "num"), ("metric", "Metric", "num")],
                                 [dict(r, _tone="info" if r["default"] else "") for r in routes], group="Live state", page_size=100))
    bgp = runtime.get("bgp")
    if bgp is not None:
        rows = [dict(n, _tones={"state": "ok" if n["state"] == "Established" else "bad"}) for n in bgp["neighbors"]]
        out.append(table_section("bgp_live", f"BGP sessions (live) · AS {bgp['local_as']}", [("ip", "Neighbor", "mono"), ("remote_as", "Remote AS", "mono"), ("state", "State", "status"), ("up_down", "Up/Down"), ("prefixes", "Prefixes received", "num")],
                                 rows, group="Live state", empty="No BGP neighbours."))
    ipsec = runtime.get("ipsec")
    if ipsec is not None:
        out.append(table_section("ipsec_live", "IPsec tunnels (live)", [("name", "Tunnel", "mono"), ("remote", "Remote", "mono"), ("selectors", "Selectors", "num"), ("up", "Up", "num"), ("state", "State", "status")],
                                 [dict(t, _tones={"state": {"up": "ok", "partial": "warn", "down": "bad"}[t["state"]]}) for t in ipsec], group="Live state", empty="No tunnels."))
    ha = runtime.get("ha")
    if ha and (ha.get("members") or len(ha) > 1):
        pairs = [(k, v) for k, v in ha.items() if k != "members" and v]
        pairs += [(m["role"], f"{m['host']} · {m['serial']} · index {m['index']}") for m in ha["members"]]
        out.append(kv_section("ha_live", "HA status (live)", pairs, group="Live state"))
    return out


def _cards(data: dict[str, Any], res: Resolver, findings: list[dict[str, Any]], runtime: dict[str, Any]) -> list[dict[str, Any]]:
    cards = []
    header = data["header"]
    status = runtime.get("status", {})
    cards.append(card("Platform", status.get("_model") or header.get("model") or "FortiGate", "info", f"FortiOS {status.get('_version') or header.get('version', '?')} build {status.get('_build') or header.get('build', '?')}", "global"))
    interfaces = [i for i in data["interfaces"] if i["type"] not in ("tunnel", "loopback")]
    wan = [i for i in interfaces if res.is_wan(i["name"])]
    exposed = [i for i in wan if {a.lower() for a in i["allowaccess"]} & {"https", "ssh", "http", "telnet", "snmp"}]
    cards.append(card("Interfaces", len(interfaces), "info", f"{len(wan)} internet-facing", "interfaces"))
    if exposed:
        cards.append(card("Management exposed", len(exposed), "bad", "on internet-facing interface(s)", "interfaces"))
    policies = data["policies"]
    enabled = [p for p in policies if p["status"] == "enable"]
    accept = [p for p in enabled if p["action"] == "accept"]
    cards.append(card("Policies", f"{len(enabled)}/{len(policies)}", "info", f"{len(accept)} accept · {len(policies) - len(enabled)} disabled", "policies"))
    tunnels = len(data["ipsec_p1"])
    ssl = bool(data["sslvpn"] and data["sslvpn"]["enabled"])
    live_tunnels = runtime.get("ipsec")
    if live_tunnels:
        up = sum(1 for t in live_tunnels if t["state"] == "up")
        cards.append(card("IPsec tunnels", f"{up}/{len(live_tunnels)}", "ok" if up == len(live_tunnels) else "bad", "up / total (live)", "ipsec_live"))
    elif tunnels or ssl:
        cards.append(card("VPN", f"{tunnels} IPsec" + (" + SSL" if ssl else ""), "info", "configured · state not captured", "ipsec_p1" if tunnels else "sslvpn"))
    bgp_live = runtime.get("bgp")
    if bgp_live and bgp_live["neighbors"]:
        est = sum(1 for n in bgp_live["neighbors"] if n["state"] == "Established")
        cards.append(card("BGP sessions", f"{est}/{len(bgp_live['neighbors'])}", "ok" if est == len(bgp_live["neighbors"]) else "bad", "established / total (live)", "bgp_live"))
    ha = data["ha"]
    if ha:
        cards.append(card("HA", ha["mode"], "ok" if ha["mode"] != "standalone" else "mute", f"group {ha['group_name']}" if ha["group_name"] else "", "ha"))
    counts = severity_counts(findings)
    cards.append(card("High findings", counts["high"], "bad" if counts["high"] else "ok", "", "findings"))
    cards.append(card("Medium findings", counts["medium"], "warn" if counts["medium"] else "ok", f"{counts['low']} low · {counts['info']} info", "findings"))
    return cards


def _info(data: dict[str, Any], runtime: dict[str, Any], tree: Any) -> list[dict[str, Any]]:
    h, g, status = data["header"], data["global"], runtime.get("status", {})
    modes = Counter(v["mode"] for v in data["vdoms"])
    pairs = [
        ("Hostname", g.get("hostname") or status.get("Hostname")), ("Model", status.get("_model") or h.get("model")), ("Serial number", status.get("Serial-Number")),
        ("FortiOS", f"{status.get('_version') or h.get('version', '')} build {status.get('_build') or h.get('build', '')}".strip()), ("Build date", h.get("built") and f"20{h['built'][:2]}-{h['built'][2:4]}-{h['built'][4:6]}"),
        ("Config header", h.get("config-version")), ("VDOMs", f"{len(data['vdoms'])} ({', '.join(f'{n} {m}' for m, n in modes.items())})" if data["multi_vdom"] else "single (root)"),
        ("Operation mode", status.get("Operation Mode")), ("HA", data["ha"].get("mode") if data["ha"] else ""), ("Time zone", g.get("timezone")), ("Administrators", len(data["admins"])),
        ("System time", status.get("System time")), ("Capture", f"{tree.lines:,} lines"),
    ]
    return info_rows(pairs)


def _coverage(content: str, tree: Any, runtime: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [{"command": "show full-configuration", "status": "analysed", "lines": tree.lines, "note": "Policies, objects, VPN, routing, admins, HA, logging, SNMP and system settings.", "tone": "ok"}]
    keys = {"get system status": "status", "get router info routing-table all": "routes", "get router info bgp summary": "bgp", "get vpn ipsec tunnel summary": "ipsec", "get system ha status": "ha"}
    for command, purpose in forti_runtime.COMMANDS:
        key = keys.get(command)
        if key and key in runtime:
            rows.append({"command": command, "status": "analysed", "lines": 0, "note": "Shown on the Live state tab.", "tone": "ok"})
        elif key or command == "get system performance status":
            rows.append({"command": command, "status": "missing", "lines": 0, "note": "Not in this capture - would add: " + purpose, "tone": "warn"})
    rows.append({"command": "show vs show full-configuration", "status": "covered", "lines": 0,
                 "note": "'show' prints only values that differ from the default; findings that depend on a default say so. 'show full-configuration' gives the complete picture.", "tone": "info"})
    return rows


def _notes(runtime: dict[str, Any]) -> list[str]:
    used = [label for key, label in UNVALIDATED.items() if key in runtime]
    if not used:
        return []
    return ["Parsed from Fortinet's documented output format but not yet validated against a captured FortiGate: " + ", ".join(used) + ". Check these tables against the device before relying on them."]
