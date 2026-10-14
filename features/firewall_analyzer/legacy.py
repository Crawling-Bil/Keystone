"""Palo Alto PAN-OS and MikroTik RouterOS through the shared parsers.

These two vendors are parsed by Configuration Studio's engine
(``features.switch_analyzer.firewall_service.analyze_firewall``); this module
reshapes its vendor-neutral dashboard dictionary into the
``keystone.analysis/1`` result used by every analyzer page, adds the
documentation links, and adds a few findings the old engine did not have.
FortiGate does not go through here - it has its own parser (``forti_*``).
"""

from __future__ import annotations

import re
from collections import Counter
from functools import lru_cache
from typing import Any

from ..analyzer_core.findings import dedupe_findings, finding, severity_counts, sort_findings
from ..analyzer_core.result import card, info_rows, kv_section, new_result, table_section
from .refs import MIKROTIK, PALO

ALLOW = {"allow", "accept", "permit"}
WAN_ZONE = re.compile(r"(wan|untrust|outside|internet|isp|public|external)", re.I)
CLEARTEXT_MGMT = {"telnet", "http", "snmp", "ftp"}
LEGACY_IDS = {
    "any-any-rule": ("FW-POL-001", "Policy"), "zone-without-policy": ("FW-POL-002", "Policy"), "nat-overlap": ("FW-NAT-001", "NAT"),
    "weak-ipsec": ("FW-VPN-001", "VPN"), "no-logging": ("FW-POL-003", "Policy"),
}


@lru_cache(maxsize=1)
def available() -> bool:
    """True when Configuration Studio's firewall parsers are part of this build.

    The Keystone GitHub edition has them; the standalone v1.9.2 edition does not, and then
    the Firewall Analyzer reads FortiGate only and says so on the page."""
    try:
        from features.switch_analyzer.firewall_service import analyze_firewall  # noqa: F401
    except Exception:
        return False
    return True


def _import_engine():
    if not available():
        raise ValueError(
            "Palo Alto and MikroTik parsing needs Configuration Studio's firewall parsers, which this build does not include. "
            "This edition of the Firewall Analyzer reads FortiGate configurations natively."
        )
    from features.switch_analyzer.firewall_service import analyze_firewall
    return analyze_firewall


def analyze(content: str, filename: str, vendor: str) -> dict[str, Any]:
    """``vendor`` is the Configuration Studio spelling: ``Palo Alto``, ``Mikrotik`` or ``Auto Detect``."""
    dashboard = _import_engine()(content, filename=filename or "firewall-config.txt", vendor=vendor)
    is_palo = str(dashboard.get("vendor", "")).strip().lower() == "palo alto"
    findings = _findings(dashboard, is_palo)
    result = new_result(
        "firewall",
        hostname=dashboard.get("hostname") or (filename or "").rsplit(".", 1)[0],
        vendor="Palo Alto Networks" if is_palo else "MikroTik",
        platform="PAN-OS" if is_palo else "RouterOS",
        source_name=filename,
        title=dashboard.get("hostname") or "Firewall",
        subtitle=("PAN-OS " + ("(Panorama template)" if dashboard.get("panorama_enabled") else "standalone") + f" · {dashboard.get('source_format', 'set')} export") if is_palo else "MikroTik RouterOS export",
    )
    sections = _sections(dashboard, is_palo)
    result["sections"] = sections
    result["findings"] = findings
    known = {section["id"] for section in sections} | {"findings", "overview", "coverage"}
    result["cards"] = [c if not c.get("section") or c["section"] in known else dict(c, section="") for c in _cards(dashboard, findings, is_palo)]
    result["info"] = _info(dashboard, is_palo)
    unhandled = dashboard.get("unhandled_commands") or []
    result["coverage"] = [
        {"command": "configuration export", "status": "analysed", "lines": len(content.splitlines()), "note": "Interfaces, zones, policies, NAT, routes, VPN, objects and system settings were read.", "tone": "ok"},
        {"command": "lines not interpreted", "status": "not parsed" if unhandled else "analysed", "lines": len(unhandled),
         "note": "See the 'Not interpreted' table on the System tab." if unhandled else "Nothing was skipped.", "tone": "warn" if unhandled else "ok"},
        {"command": "live state (show session, show vpn flow, BGP/OSPF neighbours)", "status": "missing", "lines": 0, "note": "A configuration export has no runtime state: tunnel up/down, session counts and routing adjacencies are not shown.", "tone": "warn"},
    ]
    result["warnings"] = ["This vendor is read from the configuration export only; runtime commands are not parsed yet."]
    return result


# --------------------------------------------------------------------------- findings
def _items(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _ports(service: str) -> set[int]:
    return {int(n) for n in re.findall(r"\d+", service or "") if int(n) < 65536}


def _findings(d: dict[str, Any], is_palo: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    doc_rule = PALO["security_rule"] if is_palo else MIKROTIK["filter"]
    refs = {
        "any-any-rule": doc_rule, "zone-without-policy": doc_rule, "nat-overlap": MIKROTIK["nat"] if not is_palo else PALO["security_rule"],
        "weak-ipsec": PALO["ike_crypto"] if is_palo else MIKROTIK["ipsec"], "no-logging": PALO["logging"],
    }
    recommendations = {
        "any-any-rule": "Name the source and destination networks and the application / service, and keep a logged deny at the end of the rulebase.",
        "zone-without-policy": "Add explicit rules for the zone and an explicit deny so the outcome does not depend on the implicit default.",
        "nat-overlap": "Give each translation a unique address/port pair or order the rules deliberately.",
        "weak-ipsec": "Use DH group 14 or higher (or ECP 19/20/21), AES-256 and SHA-256 or better.",
        "no-logging": "Enable log at session end on allow rules and forward logs to a collector.",
    }
    for legacy in d.get("findings", []):
        rule_id, category = LEGACY_IDS.get(legacy.get("category", ""), ("FW-GEN-001", "General"))
        out.append(finding(rule_id, legacy.get("severity", "info"), category, legacy.get("title", ""), obj=_object_of(legacy.get("title", "")), detail=legacy.get("detail", ""),
                           recommendation=recommendations.get(legacy.get("category", ""), ""), reference=refs.get(legacy.get("category", ""), "")))

    rules = [r for r in d.get("security_rules", []) if not r.get("disabled")]
    wan_zones = {z["name"] for z in d.get("zones", []) if WAN_ZONE.search(z["name"])}
    if is_palo:
        for rule in rules:
            if str(rule.get("action", "")).lower() not in ALLOW:
                continue
            if not rule.get("profile_setting"):
                inbound = any(zone in wan_zones for zone in _items(rule.get("from_zone")))
                out.append(finding("FW-POL-004", "medium" if inbound else "low", "Policy", "Allow rule has no security profile group", obj=f"rule {rule['name']}",
                                   detail=f"Rule '{rule['name']}' ({'/'.join(_items(rule.get('from_zone'))) or 'any'} → {'/'.join(_items(rule.get('to_zone'))) or 'any'}) allows traffic without attaching a profile group, so threat, URL and file inspection are not applied.",
                                   recommendation="Attach a security profile group (Antivirus, Anti-Spyware, Vulnerability Protection, URL Filtering, File Blocking, WildFire).", reference=PALO["security_rule"]))
            apps = [a.lower() for a in _items(rule.get("application"))]
            services = [s.lower() for s in _items(rule.get("service"))]
            if apps and "any" not in apps and "any" in services:
                out.append(finding("FW-POL-005", "medium", "Policy", "Application-based rule allows any service port", obj=f"rule {rule['name']}",
                                   detail=f"Rule '{rule['name']}' names applications but leaves the service as 'any', so those applications are permitted on every port.",
                                   recommendation="Set the service to application-default so each application is limited to its standard ports.", reference=PALO["app_default"]))
        profiles = {z["name"]: z.get("zone_protection_profile", "") for z in d.get("zones", []) if z.get("interfaces")}
        for zone, profile in profiles.items():
            if not profile:
                wan = zone in wan_zones
                out.append(finding("FW-ZPP-001", "medium" if wan else "info", "Zones", f"Zone '{zone}' has no zone protection profile", obj=f"zone {zone}",
                                   detail="Without a zone protection profile there is no flood, reconnaissance or packet-based attack protection at the zone edge." + (" This zone looks internet-facing." if wan else ""),
                                   recommendation="Create a zone protection profile (flood protection, reconnaissance protection, packet-based attack protection) and attach it to the zone.", reference=PALO["zone_protection"]))
        for profile in d.get("management_profiles", []):
            bad = sorted({s.lower() for s in profile.get("permitted_services", [])} & CLEARTEXT_MGMT)
            if bad:
                out.append(finding("FW-MGT-001", "high" if "telnet" in bad or "http" in bad else "medium", "Management", "Interface management profile permits a clear-text service", obj=f"management profile {profile['name']}",
                                   detail="Permitted: " + ", ".join(bad) + ". Interfaces that use this profile accept these protocols without encryption.", recommendation="Permit only HTTPS, SSH and ping, and restrict the permitted source addresses.", reference=PALO["mgmt_profile"]))
        for service in d.get("management_services", []):
            if service.get("field") in ("service-telnet", "service-http") and not service.get("disabled"):
                out.append(finding("FW-MGT-002", "high", "Management", f"Management-plane service {service['field']} is not disabled", obj=service["field"],
                                   detail="The device management interface accepts a clear-text protocol.", recommendation="Disable it under Device > Setup > Management > Management Interface Settings.", reference=PALO["mgmt_profile"]))
        for iface in d.get("interfaces", []):
            if iface.get("zone") in wan_zones and iface.get("management_profile"):
                profiles_by_name = {p["name"]: p for p in d.get("management_profiles", [])}
                perm = {s.lower() for s in profiles_by_name.get(iface["management_profile"], {}).get("permitted_services", [])}
                if perm & {"ssh", "https", "snmp", "telnet", "http"}:
                    out.append(finding("FW-MGT-003", "high", "Management", "Management services are allowed on an internet-facing interface", obj=f"interface {iface['name']}",
                                       detail=f"{iface['name']} (zone {iface['zone']}) uses management profile '{iface['management_profile']}' which permits {', '.join(sorted(perm & {'ssh', 'https', 'snmp', 'telnet', 'http'}))}.",
                                       recommendation="Move management to a dedicated interface and keep only ping on the untrusted interface.", reference=PALO["mgmt_profile"]))
    else:
        inputs = [r for r in d.get("security_rules", []) if r.get("chain") == "input"]
        for rule in inputs:
            if rule.get("disabled") or str(rule.get("action", "")).lower() != "accept":
                continue
            src = [s for s in _items(rule.get("source")) if s]
            ports = set().union(*[_ports(s) for s in _items(rule.get("service"))]) if rule.get("service") else set()
            risky = sorted(ports & {21, 23, 80, 8728, 8291, 22, 8729})
            if risky and not src:
                clear = [p for p in risky if p in (21, 23, 80, 8728)]
                out.append(finding("FW-MGT-004", "high" if clear else "medium", "Management", "Router management port is accepted from any source", obj=f"rule {rule['name']}",
                                   detail=f"The input chain accepts TCP {', '.join(map(str, risky))} without a source address or address-list" + (" (clear-text management protocol)." if clear else "."),
                                   recommendation="Limit the accepting rule to a management address-list, or disable the service under /ip service.", reference=MIKROTIK["securing"]))
        if not any(str(r.get("action", "")).lower() in ("drop", "reject") and r.get("chain") == "input" and not r.get("disabled") for r in d.get("security_rules", [])):
            out.append(finding("FW-MGT-005", "medium", "Management", "No drop rule in the input chain", obj="/ip firewall filter chain=input",
                               detail="RouterOS accepts everything in a chain that has no matching rule, so services on the router itself are open to every interface that reaches it.",
                               recommendation="End the input chain with a drop rule for traffic that is not from the LAN, after allowing established/related and the required services.", reference=MIKROTIK["securing"]))
    return sort_findings(dedupe_findings(out))


def _object_of(title: str) -> str:
    match = re.search(r"'([^']+)'", title)
    return match.group(1) if match else ""


# ------------------------------------------------------------------------- sections
def _yn(flag: Any) -> str:
    return "Yes" if flag else "No"


def _rule_tone(rule: dict[str, Any]) -> dict[str, str]:
    action = str(rule.get("action", "")).lower()
    return {"action": "ok" if action in ALLOW else "bad"}


def _sections(d: dict[str, Any], is_palo: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    iface_cols = [("name", "Interface", "mono"), ("type", "Type"), ("ip_address", "Address", "mono"), ("zone", "Zone"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")]
    if is_palo:
        iface_cols[4:4] = [("tag", "VLAN tag"), ("management_profile", "Management profile"), ("link_state", "Link")]
    out.append(table_section("interfaces", "Interfaces", iface_cols, [dict(i, disabled=_yn(i.get("disabled")), _tone="mute" if i.get("disabled") else "") for i in d.get("interfaces", [])], group="Interfaces"))
    out.append(table_section("zones", "Zones", [("name", "Zone", "mono"), ("interfaces", "Interfaces", "list")] + ([("zone_protection_profile", "Zone protection profile")] if is_palo else []),
                             [dict(z, _tones={"zone_protection_profile": "warn" if is_palo and not z.get("zone_protection_profile") and z.get("interfaces") else ""}) for z in d.get("zones", [])], group="Interfaces"))
    out.append(table_section("vlans", "VLANs", [("name", "Name", "mono"), ("vlan_id" if not is_palo else "tag", "VLAN ID"), ("parent_interface" if not is_palo else "vlan_interface", "Parent / interface"), ("interfaces", "Members", "list"), ("comment", "Comment", "wrap")],
                             [dict(v, vlan_id=v.get("vlan_id", ""), tag=v.get("tag", "")) for v in d.get("vlans", [])], group="Interfaces", empty="No VLANs."))
    out.append(table_section("static_routes", "Static routes", [("destination", "Destination", "mono"), ("nexthop", "Next hop", "mono"), ("metric", "Metric"), ("virtual_router", "Virtual router"), ("disabled", "Disabled")],
                             [dict(r, disabled=_yn(r.get("disabled"))) for r in d.get("static_routes", [])], group="Interfaces", empty="No static routes."))
    if is_palo:
        out.append(table_section("routing_protocols", "Virtual routers", [("virtual_router", "Virtual router", "mono"), ("routing_type", "Routing"), ("dynamic_protocols", "Dynamic protocols", "list"), ("static_route_count", "Static routes", "num"),
                                                                           ("bgp_as_number", "BGP AS"), ("bgp_router_id", "BGP router ID", "mono"), ("ospf_router_id", "OSPF router ID", "mono"), ("ospf_area_ids", "OSPF areas", "list")],
                                 d.get("routing_protocols", []), group="Interfaces", empty="No virtual routers."))
    # policies
    rule_cols = [("name", "Name"), ("chain", "Chain"), ("from_zone", "From", "list"), ("to_zone", "To", "list"), ("source", "Source", "list"), ("destination", "Destination", "list"), ("service", "Service", "list")]
    if is_palo:
        rule_cols += [("application", "Application", "list"), ("profile", "Profile group", "list"), ("category", "URL category", "list"), ("source_user", "Users", "list")]
    rule_cols += [("action", "Action", "status"), ("log", "Log"), ("disabled", "Disabled")]
    rows = []
    for index, r in enumerate(d.get("security_rules", []), start=1):
        tones = _rule_tone(r)
        any_all = all((not _items(r.get(k))) or [x.lower() for x in _items(r.get(k))] == ["any"] for k in ("source", "destination", "service")) and (not is_palo or [a.lower() for a in _items(r.get("application"))] in ([], ["any"]))
        if any_all and str(r.get("action", "")).lower() in ALLOW and not r.get("disabled"):
            tones.update({"source": "bad", "destination": "bad", "service": "bad"})
        if not r.get("log") and str(r.get("action", "")).lower() in ALLOW and is_palo:
            tones["log"] = "warn"
        rows.append(dict(r, profile=[f"{k}:{v}" for k, v in (r.get("profile_setting") or {}).items()] if is_palo else [], log=_yn(r.get("log")), disabled=_yn(r.get("disabled")), _tone="mute" if r.get("disabled") else "", _tones=tones))
    out.append(table_section("security_rules", "Security rules" if is_palo else "Firewall filter rules", rule_cols, rows, group="Policies", page_size=100,
                             hint="In evaluation order. Allow rules that match everything are shaded red."))
    out.append(table_section("address_objects", "Address objects and lists", [("name", "Name", "mono"), ("members", "Members", "list")], d.get("address_objects", []), group="Policies", empty="No address objects."))
    if is_palo:
        out.append(table_section("service_objects", "Service objects and groups", [("name", "Name", "mono"), ("members", "Members", "list")], d.get("service_objects", []), group="Policies", empty="No service objects."))
        out.append(table_section("application_groups", "Application groups", [("name", "Name", "mono"), ("members", "Members", "list")], d.get("application_groups", []), group="Policies", empty="No application groups."))
        out.append(table_section("security_profiles", "Security profiles", [("name", "Name", "mono"), ("type", "Type"), ("rule_count", "Rules", "num")], d.get("security_profiles", []), group="Policies", empty="No security profiles."))
        out.append(table_section("pbf_rules", "Policy-based forwarding", [("name", "Name", "mono"), ("from_zone", "From", "list"), ("source", "Source", "list"), ("destination", "Destination", "list"), ("egress_interface", "Egress"), ("nexthop", "Next hop", "mono"), ("disabled", "Disabled")],
                                 [dict(r, disabled=_yn(r.get("disabled"))) for r in d.get("pbf_rules", [])], group="Policies", empty="No PBF rules."))
    out.append(table_section("nat_rules", "NAT rules", [("name", "Name"), ("type", "Type"), ("from_zone", "From", "list"), ("to_zone", "To", "list"), ("source", "Source", "list"), ("destination", "Destination", "list"), ("service", "Service", "list"),
                                                      ("translated_address", "Translated address", "mono"), ("translated_port", "Port"), ("disabled", "Disabled")],
                             [dict(r, disabled=_yn(r.get("disabled")), _tone="mute" if r.get("disabled") else "") for r in d.get("nat_rules", [])], group="NAT", empty="No NAT rules."))
    out.append(table_section("ipsec_tunnels", "IPsec tunnels", [("name", "Name", "mono"), ("peer_address", "Peer", "mono"), ("dh_group", "DH group"), ("ike_encryption", "IKE encryption"), ("ike_hash", "IKE hash"), ("esp_encryption", "ESP encryption"),
                                                              ("esp_authentication", "ESP authentication"), ("proxy_id_local", "Local proxy ID", "mono"), ("proxy_id_remote", "Remote proxy ID", "mono"), ("disabled", "Disabled")],
                             [dict(t, disabled=_yn(t.get("disabled")), _tones={"dh_group": "bad" if str(t.get("dh_group", "")).lower() in {"group1", "group2", "group5", "modp768", "modp1024", "modp1536", "1", "2", "5"} else "",
                                                                                "ike_encryption": "bad" if str(t.get("ike_encryption", "")).lower() in {"des", "3des"} else "", "ike_hash": "warn" if str(t.get("ike_hash", "")).lower() == "md5" else ""}) for t in d.get("ipsec_tunnels", [])],
                             group="VPN", empty="No IPsec tunnels."))
    # system
    if is_palo:
        info = d.get("device_info", {})
        out.append(kv_section("device", "Device", [(k.replace("_", " ").title(), v) for k, v in info.items() if v], group="System"))
        out.append(table_section("administrators", "Administrators", [("username", "User", "mono"), ("role", "Role")], d.get("administrators", []), group="System", empty="No administrators in this export.", hint="Password hashes are not displayed."))
        out.append(table_section("management_profiles", "Interface management profiles", [("name", "Profile", "mono"), ("permitted_services", "Permitted services", "list")],
                                 [dict(p, _tones={"permitted_services": "bad" if {s.lower() for s in p.get("permitted_services", [])} & {"telnet", "http"} else ""}) for p in d.get("management_profiles", [])], group="System", empty="No management profiles."))
        out.append(table_section("zone_protection", "Zone protection profiles", [("name", "Profile", "mono"), ("protection_types", "Protections", "list")], d.get("zone_protection_profiles", []), group="System", empty="No zone protection profiles."))
        out.append(table_section("management_services", "Management interface services", [("field", "Setting", "mono"), ("disabled", "Disabled")], [dict(s, disabled=_yn(s.get("disabled"))) for s in d.get("management_services", [])], group="System"))
    dhcp = d.get("dhcp") or {}
    out.append(table_section("dhcp", "DHCP servers", [("name", "Name", "mono"), ("interface", "Interface"), ("address_pool", "Pool", "mono"), ("gateway", "Gateway", "mono"), ("dns_servers", "DNS", "list"), ("disabled", "Disabled")],
                             [dict(s, disabled=_yn(s.get("disabled"))) for s in dhcp.get("servers", [])], group="System", empty="No DHCP servers."))
    out.append(kv_section("time_dns", "DNS and NTP", [("DNS servers", ", ".join(d.get("dns_servers", [])) or "—"), ("NTP servers", ", ".join(d.get("ntp_servers", [])) or "—", "" if d.get("ntp_servers") else "warn")], group="System"))
    unhandled = d.get("unhandled_commands") or []
    out.append(table_section("unhandled", "Not interpreted", [("line", "Configuration line", "wrap")], [{"line": line} for line in unhandled[:300]], group="System", total=len(unhandled),
                             empty="Every line was understood.", hint="Lines the parser did not map to a table. Review them for features that are not analysed here."))
    live = {s["group"] for s in out if (s.get("rows") if s["kind"] == "table" else s.get("pairs"))}
    return [s for s in out if s["group"] in live or s["group"] in {"Interfaces", "Policies", "System"}]


def _cards(d: dict[str, Any], findings: list[dict[str, Any]], is_palo: bool) -> list[dict[str, Any]]:
    rules = d.get("security_rules", [])
    enabled = [r for r in rules if not r.get("disabled")]
    counts = severity_counts(findings)
    tunnels = d.get("ipsec_tunnels", [])
    cards = [card("Platform", "PAN-OS" if is_palo else "RouterOS", "info", "Palo Alto Networks" if is_palo else "MikroTik", "interfaces"),
             card("Interfaces", len(d.get("interfaces", [])), "info", f"{len(d.get('zones', []))} zone(s)", "interfaces"),
             card("Rules", f"{len(enabled)}/{len(rules)}", "info", "enabled / total", "security_rules"),
             card("NAT rules", len(d.get("nat_rules", [])), "info", "", "nat_rules"),
             card("IPsec tunnels", len(tunnels), "info", "configured · state not in an export", "ipsec_tunnels"),
             card("High findings", counts["high"], "bad" if counts["high"] else "ok", "", "findings"),
             card("Medium findings", counts["medium"], "warn" if counts["medium"] else "ok", f"{counts['low']} low · {counts['info']} info", "findings")]
    return cards


def _info(d: dict[str, Any], is_palo: bool) -> list[dict[str, Any]]:
    pairs: list[tuple[str, Any]] = [("Hostname", d.get("hostname")), ("Vendor", "Palo Alto Networks" if is_palo else "MikroTik")]
    if is_palo:
        info = d.get("device_info", {})
        pairs += [("Management IP", info.get("mgmt_ip")), ("Domain", info.get("domain")), ("Time zone", info.get("timezone")), ("Panorama", "template " + d.get("panorama_template_name", "") if d.get("panorama_enabled") else "standalone")]
    counts = Counter(str(r.get("action", "")).lower() for r in d.get("security_rules", []))
    pairs.append(("Rule actions", ", ".join(f"{k}: {v}" for k, v in counts.most_common())))
    return info_rows(pairs)
