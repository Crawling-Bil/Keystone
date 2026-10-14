"""Tabs for the security modules (Advanced WAF, DoS, logging, lists, APM, iApps, tunnels), the per-virtual-server protection view,
global settings and the configuration inventory.  Data comes from ``bigip_security`` via ``data["extra"]``.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from ..analyzer_core.result import table_section

SECURITY = "Security"
INVENTORY = "Inventory"


def security_sections(data: dict[str, Any], today: date) -> list[dict[str, Any]]:
    extra = data.get("extra")
    if not extra:
        return []
    out: list[dict[str, Any]] = []
    if extra["asm_policies"]:
        rows = []
        for p in extra["asm_policies"]:
            attached = p["attached_to"] or (["(LTM policy exists, no virtual server uses it)"] if p["orphan_ltm"] else ["(not attached)"])
            rows.append({"name": p["name"], "active": "yes" if p["active"] else "NO", "template": p["template"].replace("POLICY_TEMPLATE_", "") or "(custom)", "encoding": p["encoding"], "ltm": p["ltm_policies"], "attached": attached,
                         "_tones": {"active": "" if p["active"] else "bad", "attached": "" if p["attached_to"] else "warn"}})
        out.append(table_section("asm_policies", "Advanced WAF (ASM) policies", [("name", "Policy", "mono"), ("active", "Active"), ("template", "Template"), ("encoding", "Encoding"), ("ltm", "Attached through LTM policy", "list"), ("attached", "Virtual servers", "list")], rows,
                                 group=SECURITY, hint="A UCS lists the policy name, template and active flag only; enforcement mode, signature sets and learning state live in ASM's own database. Export the policy as XML (Security > Application Security > Policies > Export) to review blocking mode."))
    if extra["virtual_security"]:
        rows = []
        for r in extra["virtual_security"]:
            protected = bool(r["asm"] or r["dos"] or r["afm"])
            rows.append({"virtual": r["virtual"], "destination": r["destination"], "state": "enabled" if r["enabled"] else "disabled", "scope": "public" if r["public"] else "private", "asm": r["asm"] or ["-"], "dos": r["dos"] or ["-"],
                         "afm": r["afm"] or "-", "log": r["log"] or ["-"], "ip_intel": r["ip_intel"] or "-",
                         "_tones": {"asm": "" if r["asm"] else ("warn" if r["public"] and r["http"] and r["enabled"] and extra["asm_policies"] else "mute"), "scope": "warn" if r["public"] and not protected and r["enabled"] else "", "state": "ok" if r["enabled"] else "mute"}})
        out.append(table_section("virtual_protection", "Virtual server protection", [("virtual", "Virtual server", "mono"), ("destination", "Destination", "mono"), ("state", "State", "status"), ("scope", "Address"), ("asm", "ASM policy", "list"), ("dos", "DoS profile", "list"),
                                                                                       ("afm", "AFM policy", "mono"), ("log", "Security logging", "list"), ("ip_intel", "IP intelligence")], rows, group=SECURITY, page_size=100,
                                 hint="Which protections each virtual server actually has. 'public' means the destination is a routable (non-RFC 1918) address."))
    if extra["dos"]:
        out.append(table_section("dos_profiles", "DoS protection profiles", [("name", "Profile", "mono"), ("features", "Protections configured", "list"), ("used_by", "Used by", "list")],
                                 [dict(d, features=d["features"] or ["(none stated)"], used_by=d["used_by"] or ["(unused)"], _tones={"used_by": "" if d["used_by"] else "warn"}) for d in extra["dos"]], group=SECURITY))
    if extra["log_profiles"]:
        out.append(table_section("log_profiles", "Security logging profiles", [("name", "Profile", "mono"), ("kinds", "Logs", "list"), ("local", "Local storage"), ("remote", "Remote storage"), ("used_by", "Used by", "list")],
                                 [dict(item, kinds=item["kinds"] or ["-"], used_by=item["used_by"] or ["(unused)"]) for item in extra["log_profiles"]], group=SECURITY))
    if extra["lists"]:
        out.append(table_section("net_lists", "Address and port lists (network / AFM)", [("kind", "Kind"), ("name", "Name", "mono"), ("count", "Entries", "num"), ("members", "Members", "list")], extra["lists"], group=SECURITY))
    if extra["apm"]:
        out.append(table_section("apm_policies", "Access policies (APM)", [("name", "Access policy", "mono"), ("items", "Items", "num"), ("default_ending", "Default ending")], extra["apm"], group=SECURITY))
    if extra["apps"]:
        out.append(table_section("app_services", "Application services (iApps)", [("name", "Service", "mono"), ("template", "Template"), ("group", "Device group")], extra["apps"], group=SECURITY))
    if extra["tunnels"]:
        out.append(table_section("tunnels", "Tunnels", [("name", "Tunnel", "mono"), ("profile", "Profile"), ("local", "Local", "mono"), ("remote", "Remote", "mono"), ("mtu", "MTU")], extra["tunnels"], group=SECURITY))
    if extra["globals"]:
        out.append(table_section("global_settings", "Global settings", [("object", "Object", "mono"), ("settings", "Settings", "list")], extra["globals"], group=INVENTORY,
                                 hint="Single-instance objects that no other tab covers (software update, state mirroring, sFlow, spanning tree, daemon log levels ...), with their first settings. Values equal to the default are not printed by BIG-IP."))
    out.append(table_section("inventory", "Configuration inventory", [("type", "Object type", "mono"), ("count", "Objects", "num"), ("objects", "Objects (first names)", "list"), ("status", "Handling", "status")], extra["inventory"], group=INVENTORY, page_size=150,
                             hint="Every top-level object type in the configuration with its count and first names, so nothing is silently skipped. 'Counted only' types (for example the 2,500+ bot-defense signatures that ship with every BIG-IP) are not analysed."))
    return out
