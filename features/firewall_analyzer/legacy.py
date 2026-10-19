"""Palo Alto PAN-OS and MikroTik RouterOS through the shared parsers.

These two vendors are parsed by Configuration Studio's engine
(:mod:`.firewall_service`'s ``analyze_firewall``, which lives in this same
package -- it used to sit under ``switch_analyzer`` and got pulled in from
there for Switch Analyzer's own "you pasted a firewall config, not a switch
one" auto-redirect; that redirect still works, it now imports this module's
copy instead). This module reshapes its vendor-neutral dashboard dictionary
into the ``keystone.analysis/1`` result used by every analyzer page, adds the
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
from . import panos_routing, panos_rules, panos_runtime, panos_xml_extra, routeros, scope
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
        from .firewall_service import analyze_firewall  # noqa: F401
    except Exception:
        return False
    return True


def _import_engine():
    if not available():
        raise ValueError(
            "Palo Alto and MikroTik parsing needs Configuration Studio's firewall parsers, which this build does not include. "
            "This edition of the Firewall Analyzer reads FortiGate configurations natively."
        )
    from .firewall_service import analyze_firewall
    return analyze_firewall


def pan_cli_capture(content: str) -> Any:
    """``show config running`` (curly-brace view, usually with ``show system info``) converted to XML; ``None`` for anything else."""
    try:
        from features.configuration_studio.converter_engine.parsers.firewall import paloalto_curly
    except Exception:
        return None
    return paloalto_curly.convert(content) if paloalto_curly.looks_like_curly(content) else None


def analyze(content: str, filename: str, vendor: str) -> dict[str, Any]:
    """``vendor`` is the Configuration Studio spelling: ``Palo Alto``, ``Mikrotik`` or ``Auto Detect``."""
    capture = pan_cli_capture(content) if vendor != "Mikrotik" else None
    lines = len(content.splitlines())
    sysinfo: dict[str, str] = capture.system_info if capture else {}
    if capture:
        content = capture.xml                                          # every later step reads the XML form
        vendor = "Palo Alto"
    dashboard = _import_engine()(content, filename=filename or "firewall-config.txt", vendor=vendor)
    is_palo = str(dashboard.get("vendor", "")).strip().lower() == "palo alto"
    if is_palo:
        dashboard["runtime"] = sysinfo
        dashboard["source_format"] = "cli" if capture else dashboard.get("source_format", "set")
        panos_routing.annotate(dashboard, panos_runtime.advanced_routing(sysinfo))
    findings = _findings(dashboard, is_palo)
    result = new_result(
        "firewall",
        hostname=dashboard.get("hostname") or (filename or "").rsplit(".", 1)[0],
        vendor="Palo Alto Networks" if is_palo else "MikroTik",
        platform="PAN-OS" if is_palo else "RouterOS",
        source_name=filename,
        title=dashboard.get("hostname") or "Firewall",
        subtitle=("PAN-OS " + ("(Panorama-managed)" if dashboard.get("panorama_enabled") else "standalone") + (" · CLI capture (show config running)" if dashboard.get("source_format") == "cli" else f" · {dashboard.get('source_format', 'set')} export")) if is_palo else "MikroTik RouterOS export",
    )
    sections = _sections(dashboard, is_palo)
    extra_note = ""
    if is_palo:
        # The vendor-neutral model has no field for HA, certificates, TLS profiles, SNMP, permitted-IP, admins...
        # Read them from the raw XML (set-format exports return None here and are simply skipped).
        try:
            extra = panos_xml_extra.extract(content)
            if extra:
                known_ids = {s["id"] for s in sections}
                sections += [s for s in panos_xml_extra.sections(extra) if s["id"] not in known_ids]
                findings = sort_findings(dedupe_findings(findings + panos_xml_extra.evaluate(extra)))
                extra_note = "HA, certificates, SSL/TLS profiles, SNMP, permitted-IP list, administrators and authentication profiles were read from the XML."
        except Exception as exc:  # never let the extra pass break the main analysis
            result_warning = f"Extra PAN-OS details could not be read ({type(exc).__name__}: {exc})."
            dashboard.setdefault("warnings", []).append(result_warning)
    if is_palo:
        scope.apply(sections, "vsys", "vsys")
    result["sections"] = sections
    result["findings"] = findings
    known = {section["id"] for section in sections} | {"findings", "overview", "coverage"}
    result["cards"] = [c if not c.get("section") or c["section"] in known else dict(c, section="") for c in _cards(dashboard, findings, is_palo)]
    result["info"] = _info(dashboard, is_palo)
    unhandled = dashboard.get("unhandled_commands") or []
    result["coverage"] = [
        {"command": "show config running" if capture else "configuration export", "status": "analyzed", "lines": lines, "note": "Interfaces, zones, policies, NAT, routes, VPN, objects and system settings were read.", "tone": "ok"},
        *([{"command": "PAN-OS XML extras", "status": "analyzed", "lines": 0, "note": extra_note, "tone": "ok"}] if extra_note else []),
        {"command": "lines not interpreted", "status": "not parsed" if unhandled else "analyzed", "lines": len(unhandled),
         "note": "See the 'Not interpreted' table on the System tab." if unhandled else "Nothing was skipped.", "tone": "warn" if unhandled else "ok"},
        *([{"command": "show system info", "status": "analyzed", "lines": len(sysinfo), "note": "Model, serial, software, content versions and the advanced-routing flag were read.", "tone": "ok"}] if sysinfo else []),
        {"command": "live state (show session, show vpn flow, BGP/OSPF neighbours)", "status": "missing", "lines": 0, "note": "A configuration export has no runtime state: tunnel up/down, session counts and routing adjacencies are not shown.", "tone": "warn"},
    ]
    # dashboard["warnings"] carries parser-level notices from the underlying
    # PaloAltoNativeConfig/FirewallConfig models -- e.g. "this export has N
    # vsys, merged below" or "Panorama-managed, no local rulebase in this
    # file" -- that would otherwise never reach this page (analyze_firewall()
    # builds them, but nothing read dashboard["warnings"] until now).
    result["warnings"] = list(dashboard.get("warnings") or []) + [
        ("'show config running' and 'show system info' were read from the CLI capture; other runtime commands (show interface all, show routing route, show high-availability state, show vpn ike-sa) are not parsed here yet." if sysinfo else
         "This vendor is read from the configuration export only; runtime commands are not parsed yet.")
    ]
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

    if is_palo and not d.get("security_rules"):
        # a zone cannot be "without policy" when the file holds no policy at all; say that once instead
        out = [f for f in out if f["id"] != "FW-POL-002"]
        out.append(finding("FW-POL-006", "info", "Policy", "No security rules in this configuration", obj="security rulebase",
                           detail="The configuration holds no local security rule. Only the default rules apply: traffic inside a zone is allowed and traffic between zones is denied. "
                                  "This is normal for a freshly staged unit or a Panorama-managed firewall whose rules are pushed from a device group.",
                           recommendation="Push or create the rulebase before the unit goes into service, and review it again from a capture taken afterwards.", reference=PALO["security_rule"]))
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
        out += _group_gaps(d, rules, wan_zones)
        out += panos_rules.evaluate(d)
        out += panos_routing.evaluate(d, panos_runtime.advanced_routing(d.get("runtime") or {}))
        out += panos_runtime.evaluate(d, d.get("runtime") or {})
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
        if d.get("routeros"):
            out += routeros.evaluate(d["routeros"], d)
    return sort_findings(dedupe_findings(out))


CORE_PROFILES = ("virus", "spyware", "vulnerability")
INTERNET_PROFILES = CORE_PROFILES + ("url-filtering", "wildfire-analysis", "file-blocking")
PROFILE_NAMES = {"virus": "Antivirus", "spyware": "Anti-Spyware", "vulnerability": "Vulnerability Protection", "url-filtering": "URL Filtering", "wildfire-analysis": "WildFire Analysis", "file-blocking": "File Blocking", "data-filtering": "Data Filtering"}


def _group_gaps(d: dict[str, Any], rules: list[dict[str, Any]], wan_zones: set[str]) -> list[dict[str, Any]]:
    """A profile group attached to an allow rule is only as good as its members: report groups that miss the profiles the best-practice
    list expects (all six for rules that reach a WAN zone, the three threat profiles elsewhere)."""
    groups = {g["name"]: g for g in d.get("profile_groups", [])}
    if not groups:
        return []                                                       # Panorama pushes the groups: nothing to judge here
    used: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if str(rule.get("action", "")).lower() not in ALLOW:
            continue
        for name in (rule.get("profile_setting") or {}).get("group", []):
            wan = any(zone in wan_zones for zone in _items(rule.get("to_zone")))
            entry = used.setdefault(name, {"wan": False, "rules": []})
            entry["wan"] = entry["wan"] or wan
            entry["rules"].append(rule["name"])
    out = []
    for name, use in used.items():
        group = groups.get(name)
        if group is None:
            out.append(finding("FW-POL-008", "medium", "Policy", f"Profile group '{name}' is not defined", obj=f"profile group {name}",
                               detail=f"Rule(s) {', '.join(use['rules'][:6])} name the profile group '{name}', but no such group exists in this configuration, so the rule(s) apply no profiles.",
                               recommendation="Create the group (Objects > Security Profile Groups) or correct the rule.", reference=PALO["profile_group"]))
            continue
        needed = INTERNET_PROFILES if use["wan"] else CORE_PROFILES
        missing = [PROFILE_NAMES[t] for t in needed if not group["members"].get(t)]
        if missing:
            out.append(finding("FW-POL-007", "medium" if use["wan"] else "low", "Policy", f"Profile group '{name}' lacks {', '.join(missing)}", obj=f"profile group {name}",
                               detail=f"'{name}' is used by {', '.join(use['rules'][:6])}{' and more' if len(use['rules']) > 6 else ''}"
                                      f"{', which allow traffic to the Internet,' if use['wan'] else ''} but contains no {' / '.join(missing)} profile, so that inspection never runs for this traffic. It has: {', '.join(PROFILE_NAMES[k] for k in group['members']) or 'nothing'}.",
                               recommendation="Add the missing profiles to the group (the best-practice set is Antivirus, Anti-Spyware, Vulnerability Protection, URL Filtering, File Blocking and WildFire Analysis for Internet-bound rules).", reference=PALO["best_practice_profiles"]))
    return out


def _profile_label(rule: dict[str, Any], groups: dict[str, dict[str, Any]]) -> list[str]:
    out = []
    for kind, names in (rule.get("profile_setting") or {}).items():
        if kind == "group":
            for name in names:
                group = groups.get(name)
                out.append(f"group {name} ({', '.join(PROFILE_NAMES.get(k, k) for k in group['members'])})" if group else f"group {name}" + (" (not defined)" if groups else ""))
        else:
            out.append(f"{kind}: {', '.join(names)}")
    return out


def _object_of(title: str) -> str:
    match = re.search(r"'([^']+)'", title)
    return match.group(1) if match else ""


# ------------------------------------------------------------------------- sections
def _yn(flag: Any) -> str:
    return "Yes" if flag else "No"


def _rule_tone(rule: dict[str, Any]) -> dict[str, str]:
    action = str(rule.get("action", "")).lower()
    return {"action": "ok" if action in ALLOW else "bad"}


SCOPED_LISTS = ("zones", "interfaces", "security_rules", "nat_rules", "pbf_rules", "address_objects", "service_objects", "application_groups", "security_profiles", "profile_groups", "static_routes", "routing_protocols")


def vsys_names(d: dict[str, Any]) -> set[str]:
    """Every virtual system (and ``shared``) the export's objects were read from."""
    return {row["vsys"] for key in SCOPED_LISTS for row in d.get(key, []) if row.get("vsys")}


def _sections(d: dict[str, Any], is_palo: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    multi = is_palo and len(vsys_names(d)) > 1                                 # a vsys column that only ever says vsys1 is noise

    def scoped(columns: list[Any], at: int = 1) -> list[Any]:
        return columns[:at] + [("vsys", "vsys")] + columns[at:] if multi else columns

    iface_cols = [("name", "Interface", "mono"), ("type", "Type"), ("ip_address", "Address", "mono"), ("zone", "Zone"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")]
    if is_palo:
        iface_cols[4:4] = [("tag", "VLAN tag"), ("management_profile", "Management profile"), ("link_state", "Link")]
    else:
        iface_cols[3:3] = [("ip_addresses", "All addresses", "list"), ("disabled_ip_addresses", "Disabled addresses", "list"), ("speed", "Forced speed"), ("remote", "Remote end", "mono")]
    out.append(table_section("interfaces", "Interfaces", scoped(iface_cols), [dict(i, vsys=i.get("vsys") or "(none)", disabled=_yn(i.get("disabled")), _tone="mute" if i.get("disabled") else "", _tones={"disabled_ip_addresses": "warn" if i.get("disabled_ip_addresses") else ""}) for i in d.get("interfaces", [])], group="Interfaces",
                             hint="'(none)' = not imported into any virtual system (management, HA and unused ports)." if multi else "", facets=[{"key": "disabled", "label": "disabled", "order": ["No", "Yes"]}]))
    out.append(table_section("zones", "Zones", scoped([("name", "Zone", "mono"), ("interfaces", "Interfaces", "list")] + ([("zone_protection_profile", "Zone protection profile")] if is_palo else [])),
                             [dict(z, _tones={"zone_protection_profile": "warn" if is_palo and not z.get("zone_protection_profile") and z.get("interfaces") else ""}) for z in d.get("zones", [])], group="Interfaces"))
    out.append(table_section("vlans", "VLANs", [("name", "Name", "mono"), ("vlan_id" if not is_palo else "tag", "VLAN ID"), ("parent_interface" if not is_palo else "vlan_interface", "Parent / interface"), ("interfaces", "Members", "list"), ("comment", "Comment", "wrap")],
                             [dict(v, vlan_id=v.get("vlan_id", ""), tag=v.get("tag", "")) for v in d.get("vlans", [])], group="Interfaces", empty="No VLANs."))
    if is_palo:
        route_cols = [("name", "Route", "mono"), ("destination", "Destination", "mono"), ("nexthop", "Next hop", "mono"), ("interface", "Egress"), ("metric", "Metric"), ("detect", "Failure detection"),
                      ("virtual_router", "Router"), ("engine", "Engine"), ("active", "Active", "status")]
        route_rows = [dict(r, detect=" + ".join(x for x, on in (("path monitor", r.get("path_monitor")), ("BFD", r.get("bfd"))) if on) or "none", engine="advanced" if r.get("engine") == "logical-router" else "classic",
                           _tone="mute" if r.get("active") == "no" else "", _tones={"active": {"yes": "ok", "no": "mute", "unknown": "warn"}.get(r.get("active", ""), ""), "detect": "" if r.get("path_monitor") or r.get("bfd") or r.get("destination") != "0.0.0.0/0" else "warn"})
                      for r in d.get("static_routes", [])]
        out.append(table_section("static_routes", "Static routes", scoped(route_cols, 8), route_rows, group="Interfaces", empty="No static routes.",
                                 hint="Advanced Routing keeps its routes in logical routers; the old virtual-router section stays in the file but is not used ('Active: no'). With a bare XML export the active engine is 'unknown' when both exist - include 'show system info'."))
    else:
        out.append(table_section("static_routes", "Static routes", scoped([("destination", "Destination", "mono"), ("nexthop", "Next hop", "mono"), ("metric", "Distance"), ("routing_table", "Routing table"), ("route_type", "Type"), ("check_gateway", "Check gateway"), ("virtual_router", "Virtual router"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")], 4),
                                 [dict(r, disabled=_yn(r.get("disabled")), _tone="mute" if r.get("disabled") else "", _tones={"routing_table": "warn" if r.get("routing_table") not in ("", "main", None) else ""}) for r in d.get("static_routes", [])], group="Interfaces", empty="No static routes."))
    if is_palo:
        out.append(table_section("routing_protocols", "Virtual routers", scoped([("virtual_router", "Virtual router", "mono"), ("routing_type", "Routing"), ("dynamic_protocols", "Dynamic protocols", "list"), ("static_route_count", "Static routes", "num"),
                                                                           ("bgp_as_number", "BGP AS"), ("bgp_router_id", "BGP router ID", "mono"), ("ospf_router_id", "OSPF router ID", "mono"), ("ospf_area_ids", "OSPF areas", "list"), ("engine", "Engine"), ("active", "Active", "status")]),
                                 [dict(r, engine="advanced" if r.get("engine") == "logical-router" else "classic", _tones={"active": {"yes": "ok", "no": "mute", "unknown": "warn"}.get(r.get("active", ""), "")}) for r in d.get("routing_protocols", [])], group="Interfaces", empty="No virtual routers."))
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
        rows.append(dict(r, profile=_profile_label(r, {g["name"]: g for g in d.get("profile_groups", [])}) if is_palo else [], log=_yn(r.get("log")), disabled=_yn(r.get("disabled")), _tone="mute" if r.get("disabled") else "", _tones=tones))
    out.append(table_section("security_rules", "Security rules" if is_palo else "Firewall filter rules", scoped(rule_cols), rows, group="Policies", page_size=100,
                             hint="In evaluation order. Allow rules that match everything are shaded red.", facets=[{"key": "action", "label": "action"}]))
    out.append(table_section("address_objects", "Address objects and lists", scoped([("name", "Name", "mono"), ("members", "Members", "list")]), d.get("address_objects", []), group="Policies", empty="No address objects."))
    if is_palo:
        out.append(table_section("service_objects", "Service objects and groups", scoped([("name", "Name", "mono"), ("members", "Members", "list")]), d.get("service_objects", []), group="Policies", empty="No service objects."))
        out.append(table_section("application_groups", "Application groups", scoped([("name", "Name", "mono"), ("members", "Members", "list")]), d.get("application_groups", []), group="Policies", empty="No application groups."))
        group_rows = []
        for g in d.get("profile_groups", []):
            users = [r["name"] for r in d.get("security_rules", []) if g["name"] in (r.get("profile_setting") or {}).get("group", [])]
            group_rows.append(dict({"name": g["name"], "vsys": g.get("vsys", ""), "used_by": users or ["(unused)"]}, **{t: ", ".join(g["members"].get(t, [])) or "-" for t in ("virus", "spyware", "vulnerability", "url-filtering", "file-blocking", "wildfire-analysis")},
                                   _tones={t: "" if g["members"].get(t) else "warn" for t in ("virus", "spyware", "vulnerability")}))
        out.append(table_section("profile_groups", "Security profile groups", scoped([("name", "Group", "mono"), ("virus", "Antivirus"), ("spyware", "Anti-Spyware"), ("vulnerability", "Vulnerability"), ("url-filtering", "URL filtering"),
                                                                                  ("file-blocking", "File blocking"), ("wildfire-analysis", "WildFire"), ("used_by", "Used by rules", "list")]), group_rows, group="Policies", empty="No profile groups.",
                                 hint="A rule that names a group gets every profile in it; an empty cell means that inspection is not part of the group."))
        out.append(table_section("security_profiles", "Security profiles", scoped([("name", "Name", "mono"), ("type", "Type"), ("rule_count", "Rules", "num")]), d.get("security_profiles", []), group="Policies", empty="No security profiles."))
        out.append(table_section("pbf_rules", "Policy-based forwarding", scoped([("name", "Name", "mono"), ("from_zone", "From", "list"), ("source", "Source", "list"), ("destination", "Destination", "list"), ("egress_interface", "Egress"), ("nexthop", "Next hop", "mono"), ("disabled", "Disabled")]),
                                 [dict(r, disabled=_yn(r.get("disabled"))) for r in d.get("pbf_rules", [])], group="Policies", empty="No PBF rules."))
    out.append(table_section("nat_rules", "NAT rules", scoped([("name", "Name"), ("type", "Type"), ("from_zone", "From", "list"), ("to_zone", "To", "list"), ("source", "Source", "list"), ("destination", "Destination", "list"), ("service", "Service", "list"),
                                                      ("translated_address", "Translated address", "mono"), ("translated_port", "Port"), ("disabled", "Disabled")]),
                             [dict(r, disabled=_yn(r.get("disabled")), _tone="mute" if r.get("disabled") else "") for r in d.get("nat_rules", [])], group="NAT", empty="No NAT rules."))
    out.append(table_section("ipsec_tunnels", "IPsec tunnels", [("name", "Name", "mono"), ("peer_address", "Peer", "mono"), ("dh_group", "DH group"), ("ike_encryption", "IKE encryption"), ("ike_hash", "IKE hash"), ("esp_encryption", "ESP encryption"),
                                                              ("esp_authentication", "ESP authentication"), ("proxy_id_local", "Local proxy ID", "mono"), ("proxy_id_remote", "Remote proxy ID", "mono"), ("disabled", "Disabled")],
                             [dict(t, disabled=_yn(t.get("disabled")), _tone="mute" if t.get("disabled") else "", _tones={"dh_group": "bad" if str(t.get("dh_group", "")).lower() in {"group1", "group2", "group5", "modp768", "modp1024", "modp1536", "1", "2", "5"} else "",
                                                                                "ike_encryption": "bad" if str(t.get("ike_encryption", "")).lower() in {"des", "3des"} else "", "ike_hash": "warn" if str(t.get("ike_hash", "")).lower() == "md5" else ""}) for t in d.get("ipsec_tunnels", [])],
                             group="VPN", empty="No IPsec tunnels."))
    # system
    if is_palo:
        info = d.get("device_info", {})
        out.append(kv_section("device", "Device", [(k.replace("_", " ").title(), v) for k, v in info.items() if v], group="System"))
        out += panos_runtime.section(d.get("runtime") or {})
        out.append(table_section("administrators", "Administrators", [("username", "User", "mono"), ("role", "Role")], d.get("administrators", []), group="System", empty="No administrators in this export.", hint="Password hashes are not displayed."))
        out.append(table_section("management_profiles", "Interface management profiles", [("name", "Profile", "mono"), ("permitted_services", "Permitted services", "list")],
                                 [dict(p, _tones={"permitted_services": "bad" if {s.lower() for s in p.get("permitted_services", [])} & {"telnet", "http"} else ""}) for p in d.get("management_profiles", [])], group="System", empty="No management profiles."))
        out.append(table_section("zone_protection", "Zone protection profiles", [("name", "Profile", "mono"), ("protection_types", "Protections", "list")], d.get("zone_protection_profiles", []), group="System", empty="No zone protection profiles."))
        out.append(table_section("management_services", "Management interface services", [("field", "Setting", "mono"), ("disabled", "Disabled")], [dict(s, disabled=_yn(s.get("disabled"))) for s in d.get("management_services", [])], group="System"))
    dhcp = d.get("dhcp") or {}
    out.append(table_section("dhcp", "DHCP servers", [("name", "Name", "mono"), ("interface", "Interface"), ("address_pool", "Pool", "mono"), ("gateway", "Gateway", "mono"), ("dns_servers", "DNS", "list"), ("subnet_mask", "Mask", "mono"), ("lease_minutes", "Lease (min)"), ("reserved_count", "Reservations"), ("disabled", "Disabled")],
                             [dict(s, disabled=_yn(s.get("disabled")), _tone="mute" if s.get("disabled") else "") for s in dhcp.get("servers", [])], group="System", empty="No DHCP servers."))
    out.append(kv_section("time_dns", "DNS and NTP", [("DNS servers", ", ".join(d.get("dns_servers", [])) or "—"), ("NTP servers", ", ".join(d.get("ntp_servers", [])) or "—", "" if d.get("ntp_servers") else "warn")], group="System"))
    if not is_palo and d.get("routeros"):
        out += routeros.sections(d["routeros"])
    unhandled = d.get("unhandled_commands") or []
    if not is_palo:
        # The RouterOS parser appends a migration note ("... -- PAN-OS has no equivalent ...") for the converter; the analyzer shows the configuration line only.
        unhandled = [line.split(" -- ", 1)[0] for line in unhandled]
    out.append(table_section("unhandled", "Not interpreted", [("line", "Configuration line", "wrap")], [{"line": line} for line in unhandled[:300]], group="System", total=len(unhandled),
                             empty="Every line was understood.", hint="Lines the parser did not map to a table. Review them for features that are not analyzed here."))
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
        runtime = d.get("runtime") or {}
        pairs += [("Model", runtime.get("model")), ("Serial", runtime.get("serial")), ("PAN-OS version", runtime.get("sw-version")), ("Uptime", runtime.get("uptime")),
                  ("Management IP", info.get("mgmt_ip")), ("Domain", info.get("domain")), ("Time zone", info.get("timezone")),
                  ("Panorama", ("template " + d.get("panorama_template_name", "")) if d.get("panorama_template_name") else "server configured" if d.get("panorama_enabled") else "standalone")]
    ros = d.get("routeros") or {}
    if not is_palo and ros:
        header = ros.get("header", {})
        pairs += [("Model", header.get("model")), ("RouterOS version", header.get("routeros_version")), ("Serial", header.get("serial_number")),
                  ("Software ID", header.get("software_id")), ("Exported at", header.get("export_time"))]
    counts = Counter(str(r.get("action", "")).lower() for r in d.get("security_rules", []))
    pairs.append(("Rule actions", ", ".join(f"{k}: {v}" for k, v in counts.most_common())))
    return info_rows(pairs)
