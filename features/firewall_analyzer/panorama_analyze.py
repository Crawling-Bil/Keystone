"""Firewall Analyzer for a Panorama export: structure, policy, objects, templates and Panorama's own administration.

``analyze`` returns the same ``keystone.analysis/1`` result as every other analyzer.  The device group is the scope filter (like VDOM or vsys for a
firewall): every table that carries a ``dg`` column gets the shared filter row.  Credentials (admin password hashes, keys, SNMP communities) are
never read into a table or a finding.

References
* Panorama administration https://docs.paloaltonetworks.com/panorama/administration
* Device groups https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups
* Templates and stacks https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack
* Administrative access best practices https://docs.paloaltonetworks.com/best-practices/10-1/administrative-access-best-practices/administrative-access-best-practices/deploy-administrative-access-best-practices
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date
from typing import Any

from ..analyzer_core.findings import cap_per_rule, dedupe_findings, finding, severity_counts, sort_findings
from ..analyzer_core.result import card, info_rows, kv_section, new_result, table_section
from . import panorama_parse as pp
from . import panorama_rules, scope
from .panorama_effective import effective_objects, merged_template
from .panorama_parse import Panorama, Scope, entries, members, text
from .refs import PALO

REF_ADMIN = PALO["admin_access"]
REF_ROLES = "https://docs.paloaltonetworks.com/best-practices/10-1/best-practices-for-managing-firewalls-with-panorama/configuration-change-management/admin-roles-and-access-domains"
REF_STACK = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack"
REF_STACK_BP = "https://docs.paloaltonetworks.com/best-practices/10-1/best-practices-for-managing-firewalls-with-panorama/configuration-management/template-and-template-stack-management"
REF_DEVICE_GROUPS = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups"

_VALUE_TAGS = ("ip-netmask", "ip-range", "fqdn", "ip-wildcard")


def _short(values: list[str], limit: int = 5) -> str:
    return ", ".join(values[:limit]) + (f" (+{len(values) - limit})" if len(values) > limit else "")


def _object_value(elem) -> str:
    for tag in _VALUE_TAGS:
        value = text(elem, tag)
        if value:
            return f"{tag}:{value}"
    return ""


# ------------------------------------------------------------------------------------------------ object findings
def _references(pano: Panorama) -> dict[tuple[str, str], set[str]]:
    """(kind-group, name) -> scopes that mention it, from every rule and every group.  ``addr`` covers addresses and groups, ``svc`` services and groups."""
    refs: dict[tuple[str, str], set[str]] = defaultdict(set)
    for sc in [pano.shared] + list(pano.groups.values()):
        for rule in sc.all_rules():
            for tag in ("source", "destination"):
                for name in rule.f(tag):
                    refs[("addr", name)].add(sc.name)
            for name in rule.f("service"):
                refs[("svc", name)].add(sc.name)
            for name in rule.f("application"):
                refs[("app", name)].add(sc.name)
            for name in rule.f("tag") + rule.f("group-tag"):
                refs[("tag", name)].add(sc.name)
            for name in rule.f("category"):
                refs[("url", name)].add(sc.name)
            if rule.profile_group:
                refs[("pgroup", rule.profile_group)].add(sc.name)
            for names in rule.profiles.values():
                for name in names:
                    refs[("profile", name)].add(sc.name)
            if rule.log_setting:
                refs[("log", rule.log_setting)].add(sc.name)
            for tag in ("source-translation", "destination-translation"):
                node = rule.element.find(tag)
                if node is not None:
                    for el in node.iter():
                        if el.tag in ("translated-address", "member") and (el.text or "").strip():
                            refs[("addr", (el.text or "").strip())].add(sc.name)
        for kind in ("address-group", "service-group", "application-group"):
            for _, elem in sc.objects.get(kind, {}).items():
                target = {"address-group": "addr", "service-group": "svc", "application-group": "app"}[kind]
                for m in members(elem, "static") + members(elem, "members"):
                    refs[(target, m)].add(sc.name)
        for name, elem in sc.objects.get("address-group", {}).items():
            dyn = text(elem, "dynamic/filter")
            if dyn:
                for tag in pano_tags_in_filter(dyn):
                    refs[("tag", tag)].add(sc.name)
        for _, elem in sc.objects.get("profile-group", {}).items():
            for child in elem:
                for m in members(child):
                    refs[("profile", m)].add(sc.name)
    return refs


def pano_tags_in_filter(expr: str) -> list[str]:
    import re
    return [t for t in re.findall(r"'([^']+)'", expr)]


def _sees(pano: Panorama, owner: str, user: str) -> bool:
    """``user`` scope can see objects defined in ``owner`` (owner is user itself or one of its ancestors)."""
    return owner == "shared" or any(s.name == owner for s in pano.chain(user)) if user != "shared" else owner == "shared"


def object_findings(pano: Panorama) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    out: list[dict[str, Any]] = []
    unused_rows: list[dict[str, Any]] = []
    refs = _references(pano)
    kinds = (("address", "addr", "address object"), ("address-group", "addr", "address group"), ("service", "svc", "service"), ("service-group", "svc", "service group"),
             ("tag", "tag", "tag"), ("application-group", "app", "application group"), ("custom-url-category", "url", "custom URL category"),
             ("profile-group", "pgroup", "profile group"))
    for sc in [pano.shared] + list(pano.groups.values()):
        by_kind: Counter = Counter()
        for kind, ref_kind, word in kinds:
            for name in sc.objects.get(kind, {}):
                users = refs.get((ref_kind, name), set())
                if any(_sees(pano, sc.name, u) for u in users):
                    continue
                if kind == "tag" or kind == "profile-group" and False:
                    continue
                by_kind[word] += 1
                unused_rows.append({"dg": sc.name, "kind": word, "name": name, "value": _object_value(sc.objects[kind][name])})
        for word, n in by_kind.items():
            if n >= 5 or word in ("address group", "service group", "profile group"):
                out.append(finding("PANO-OBJ-002", "low", "Objects", f"{n} {word}(s) in '{sc.name}' are not referenced by any rule or group", obj=sc.name,
                                   detail=f"{n} {word}(s) defined in '{sc.name}' are not used by any rule or group of '{sc.name}' or of the device groups below it. "
                                          "Rules and objects on the firewalls themselves are not part of this export, so check the firewalls' local configuration before deleting.",
                                   recommendation="Review the Unused objects table, remove what is not needed, and use Panorama's 'Unused' filter before the commit to confirm.",
                                   reference=REF_DEVICE_GROUPS))
        dup: dict[str, list[str]] = defaultdict(list)
        for name, elem in sc.objects.get("address", {}).items():
            value = _object_value(elem)
            if value:
                dup[value].append(name)
        dups = {v: names for v, names in dup.items() if len(names) > 1}
        if dups:
            total = sum(len(n) for n in dups.values())
            out.append(finding("PANO-OBJ-003", "low", "Objects", f"{len(dups)} address value(s) in '{sc.name}' have more than one object", obj=sc.name,
                               detail=f"{total} address objects in '{sc.name}' share {len(dups)} value(s); for example {_short(next(iter(dups.values())), 3)}. Duplicates drift apart when only one of them is edited.",
                               recommendation="Keep one object per address and point the rules at it.", reference=REF_DEVICE_GROUPS))
        for name, elem in sc.objects.get("address-group", {}).items():
            static = members(elem, "static")
            if not static and not text(elem, "dynamic/filter"):
                out.append(finding("PANO-OBJ-004", "low", "Objects", "Address group is empty", obj=f"{name} [{sc.name}]", detail=f"Address group '{name}' in '{sc.name}' has no member.",
                                   recommendation="Delete it or add its members.", reference=REF_DEVICE_GROUPS))
        visible = {k: set() for k in ("address", "address-group", "region", "external-list")}
        for s in pano.chain(sc.name):
            for k in visible:
                visible[k].update(s.objects.get(k, {}))
        for name, elem in sc.objects.get("address-group", {}).items():
            gone = [m for m in members(elem, "static") if m not in visible["address"] and m not in visible["address-group"]]
            if gone:
                out.append(finding("PANO-OBJ-005", "medium", "Objects", "Address group has members that cannot be resolved", obj=f"{name} [{sc.name}]",
                                   detail=f"Address group '{name}' in '{sc.name}' lists {_short(gone)}, which is not defined in '{sc.name}', its parents or shared.",
                                   recommendation="Create the missing address objects at a level the group can see, or remove the members.", reference=REF_DEVICE_GROUPS))
    # the same name defined on more than one level
    for gname in pano.groups:
        _, hidden = effective_objects(pano, gname)
        diff: list[tuple[str, str, str, str]] = []
        same = 0
        for kind, name, upper, lower in hidden:
            if kind not in ("address", "service"):
                continue
            up = pano.shared if upper == "shared" else pano.groups[upper]
            lo = pano.groups[lower]
            if _object_value(up.objects[kind][name]) == _object_value(lo.objects[kind][name]) and kind == "address":
                same += 1
            elif kind == "address":
                diff.append((kind, name, upper, lower))
        if diff:
            out.append(finding("PANO-OBJ-006", "medium", "Objects", f"{len(diff)} address name(s) mean something different in '{gname}' than in shared", obj=gname,
                               detail=f"'{gname}' redefines {len(diff)} address object(s) that already exist in a higher level with a different value, for example {_short([d[1] for d in diff], 3)}. "
                                      "Rules written at the higher level resolve to the device group's value on its firewalls, so the same shared rule matches different networks per device group.",
                               recommendation="Use distinct names, or keep the object only at the level that owns it (Disable Override on the shared object stops accidental redefinition).",
                               reference=REF_DEVICE_GROUPS))
        if same >= 20:
            out.append(finding("PANO-OBJ-007", "low", "Objects", f"{same} address object(s) in '{gname}' repeat the shared definition", obj=gname,
                               detail=f"'{gname}' redefines {same} object(s) with the same name and the same value as a higher level.",
                               recommendation="Delete the redundant copies so changes are made once.", reference=REF_DEVICE_GROUPS))
    return out, unused_rows


# ------------------------------------------------------------------------------------------------ Panorama's own administration
def management_findings(pano: Panorama) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    root = pano.root
    if root is None:
        return out
    users = entries(root, "mgt-config/users")
    no_profile = [n for n, e in users.items() if e.find("authentication-profile") is None and e.find("phash") is not None]
    supers = [n for n, e in users.items() if e.find("permissions/role-based/superuser") is not None]
    if no_profile:
        out.append(finding("PANO-MGT-001", "medium", "Panorama administration", f"{len(no_profile)} local administrator(s) authenticate with a local password", obj="mgt-config/users",
                           detail=f"{len(no_profile)} of {len(users)} administrators have a password hash on Panorama and no authentication profile ({_short(no_profile, 6)}). "
                                  "Local accounts bypass the central directory, MFA and the offboarding process.",
                           recommendation="Move administrators to an authentication profile (RADIUS, TACACS+, SAML or LDAP) and keep one local break-glass account.", reference=REF_ADMIN))
    if len(supers) > 3:
        out.append(finding("PANO-MGT-002", "medium", "Panorama administration", f"{len(supers)} administrators have the superuser role", obj="mgt-config/users",
                           detail=f"Superusers: {_short(supers, 8)}. Superuser can push configuration to every managed firewall.",
                           recommendation="Give administrators a custom admin role limited to the device groups and templates they work on (access domains).", reference=REF_ROLES))
    pw = root.find("mgt-config/password-complexity")
    if pw is None:
        if users:
            out.append(finding("PANO-MGT-003", "medium", "Panorama administration", "No password complexity profile is configured", obj="mgt-config/password-complexity",
                               detail="Local administrator passwords are not subject to a complexity or expiry rule.", recommendation="Enable the password complexity settings and a password profile.",
                               reference=PALO["password_profiles"]))
    else:
        minimum = text(pw, "minimum-length")
        if text(pw, "enabled") != "yes" and pw.find("enabled") is not None:
            out.append(finding("PANO-MGT-004", "medium", "Panorama administration", "Password complexity is switched off", obj="mgt-config/password-complexity",
                               detail="The password-complexity block exists but 'enabled' is not yes.", recommendation="Enable minimum length, character classes and history.", reference=PALO["password_requirements"]))
        if minimum.isdigit() and int(minimum) < 12:
            out.append(finding("PANO-MGT-005", "low", "Panorama administration", f"Minimum password length is {minimum}", obj="mgt-config/password-complexity",
                               detail="A minimum below 12 characters allows short local passwords.", recommendation="Set the minimum length to at least 12 characters.", reference=PALO["password_requirements"]))
    return out


def template_findings(pano: Panorama) -> list[dict[str, Any]]:
    """Hardening of what a template stack pushes to the firewalls (management services, NTP, DNS, SNMP, interface management profiles)."""
    out: list[dict[str, Any]] = []
    for stack in pano.stacks.values():
        merged = merged_template(pano, stack.name)
        if merged is None:
            continue
        system = merged.find("deviceconfig/system")
        bad = []
        if system is not None:
            for tag, word in (("disable-telnet", "Telnet"), ("disable-http", "HTTP")):
                if text(system, f"service/{tag}") == "no":
                    bad.append(word)
            if system.find("snmp-setting/access-setting/version/v2c") is not None:
                bad.append("SNMP v2c")
        if bad:
            out.append(finding("PANO-TPL-001", "medium", "Template stack", f"Stack pushes clear-text management service(s): {', '.join(bad)}", obj=stack.name,
                               detail=f"Stack '{stack.name}' (templates {_short(stack.templates, 4)}) enables {', '.join(bad)} on {len(stack.devices)} firewall(s).",
                               recommendation="Disable them and use SSH, HTTPS and SNMPv3.", reference=REF_ADMIN))
        if system is not None:
            if not text(system, "ntp-servers/primary-ntp-server/ntp-server-address"):
                out.append(finding("PANO-TPL-002", "low", "Template stack", "Stack pushes no NTP server", obj=stack.name,
                                   detail=f"No primary NTP server is defined in stack '{stack.name}'; log timestamps and certificate checks depend on the clock.",
                                   recommendation="Configure two NTP servers in the template.", reference=REF_STACK_BP))
            if system.find("permitted-ip") is None:
                out.append(finding("PANO-TPL-003", "medium", "Template stack", "Stack does not restrict who may manage the firewalls", obj=stack.name,
                                   detail=f"Stack '{stack.name}' defines no permitted IP list, so the management interface accepts any source that reaches it.",
                                   recommendation="Set Permitted IP Addresses to the management networks.", reference=REF_ADMIN))
        profiles = entries(merged, "network/profiles/interface-management-profile")
        for name, prof in profiles.items():
            risky = [t for t in ("telnet", "http", "snmp", "http-ocsp") if text(prof, t) == "yes"]
            if risky and prof.find("permitted-ip") is None:
                out.append(finding("PANO-TPL-004", "medium", "Template stack", f"Interface management profile allows {', '.join(risky)} from anywhere", obj=f"{name} [{stack.name}]",
                                   detail=f"Profile '{name}' enables {', '.join(risky)} and has no permitted IP list.", recommendation="Remove the clear-text services or restrict the profile to management networks.",
                                   reference=PALO["mgmt_profile"]))
    return dedupe_findings(out)


# ------------------------------------------------------------------------------------------------ sections
def _rule_rows(pano: Panorama, kinds: tuple[str, ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sc in [pano.shared] + list(pano.groups.values()):
        for position in ("pre", "post", "default"):
            for kind in kinds:
                for rule in sc.rules.get((position, kind), []):
                    s = pp.rule_summary(rule)
                    rows.append({
                        "dg": sc.name, "position": position, "n": rule.index, "kind": kind, "name": rule.name, "from": _short(s["from"], 3), "to": _short(s["to"], 3),
                        "source": _short(s["source"], 3), "destination": _short(s["destination"], 3), "application": _short(s["application"], 3), "service": _short(s["service"], 3),
                        "action": rule.action, "state": "disabled" if rule.disabled else "enabled", "profile": rule.profile_group or ("profiles" if rule.profiles else ""),
                        "log": rule.log_setting or ("end" if s["log_end"] else "off"),
                        "target": ("not " if rule.target.negate else "") + (f"{len(rule.target.devices)} firewall(s)" if rule.target.devices else ("tags" if rule.target.tags else "")),
                        "description": s["description"][:140],
                        "_tone": "muted" if rule.disabled else "",
                    })
    return rows


def sections(pano: Panorama, unused: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rows = []
    for name, g in pano.groups.items():
        devices = list(g.devices)
        stacks = sorted({pano.devices[d].stack for d in devices if d in pano.devices and pano.devices[d].stack})
        rows.append({"dg": name, "parent": g.parent, "firewalls": len(devices), "stacks": _short(stacks, 3),
                     "security": g.rule_count("security"), "nat": g.rule_count("nat"), "other_rules": g.rule_count() - g.rule_count("security") - g.rule_count("nat"),
                     "targeted": sum(1 for r in g.all_rules() if r.target.restricted), "disabled": sum(1 for r in g.all_rules() if r.disabled),
                     "objects": sum(len(v) for v in g.objects.values()), "description": g.description})
    sh = pano.shared
    rows.insert(0, {"dg": "shared", "parent": "", "firewalls": len(pano.devices), "stacks": "", "security": sh.rule_count("security"), "nat": sh.rule_count("nat"),
                    "other_rules": sh.rule_count() - sh.rule_count("security") - sh.rule_count("nat"), "targeted": sum(1 for r in sh.all_rules() if r.target.restricted),
                    "disabled": sum(1 for r in sh.all_rules() if r.disabled), "objects": sum(len(v) for v in sh.objects.values()), "description": "inherited by every device group"})
    out.append(table_section("pano_groups", "Device groups", [("dg", "Device group", "mono"), ("parent", "Parent", "mono"), ("firewalls", "Firewalls", "num"), ("stacks", "Template stacks"),
                                                               ("security", "Security rules", "num"), ("nat", "NAT rules", "num"), ("other_rules", "Other rules", "num"),
                                                               ("targeted", "Targeted rules", "num"), ("disabled", "Disabled", "num"), ("objects", "Own objects", "num"), ("description", "Description")],
                             rows, group="Panorama", hint="shared is inherited by every device group; rules and objects of a device group are inherited by its children."))
    dev_rows = []
    for dev in pano.devices.values():
        g = pano.groups.get(dev.device_group)
        dev_rows.append({"dg": dev.device_group or "-", "serial": dev.serial, "stack": dev.stack or "-", "vsys": _short(g.devices.get(dev.serial, []), 3) if g else "",
                         "auto_push": dev.auto_push, "rules": sum(1 for r in (g.all_rules() if g else []) if r.target.applies(dev.serial, dev.tags)) + sh.rule_count(),
                         "_tone": "" if dev.device_group and dev.stack else "warn"})
    out.append(table_section("pano_devices", "Managed firewalls", [("dg", "Device group", "mono"), ("serial", "Serial number", "mono"), ("stack", "Template stack", "mono"), ("vsys", "vsys"),
                                                                     ("auto_push", "Auto push"), ("rules", "Rules received", "num")], dev_rows, group="Panorama",
                             hint="Rules received = shared rules plus the device group's rules whose target includes this firewall."))
    tpl_rows = []
    for name, tpl in pano.templates.items():
        e = tpl.device_entry()
        in_stacks = [s.name for s in pano.stacks.values() if name in s.templates]
        zones = sum(len(entries(v, "zone")) for v in (e.findall("vsys/entry") if e is not None else []))
        ifaces = 0
        if e is not None:
            for kind in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"):
                ifaces += len(entries(e, f"network/interface/{kind}"))
                for ent in entries(e, f"network/interface/{kind}").values():
                    ifaces += len(entries(ent, "layer3/units"))
        tpl_rows.append({"template": name, "stacks": _short(in_stacks, 3) or "-", "zones": zones, "interfaces": ifaces,
                         "routers": len(entries(e, "network/virtual-router")) if e is not None else 0, "ha": "yes" if e is not None and e.find("deviceconfig/high-availability/enabled") is not None
                         and text(e, "deviceconfig/high-availability/enabled") == "yes" else "", "variables": len(tpl.variables), "description": tpl.description,
                         "_tone": "muted" if not in_stacks else ""})
    out.append(table_section("pano_templates", "Templates", [("template", "Template", "mono"), ("stacks", "In stacks"), ("zones", "Zones", "num"), ("interfaces", "Interfaces", "num"),
                                                              ("routers", "Virtual routers", "num"), ("ha", "HA"), ("variables", "Variables", "num"), ("description", "Description")], tpl_rows,
                             group="Panorama"))
    stack_rows = [{"stack": s.name, "templates": " > ".join(s.templates), "firewalls": len(s.devices), "default_vsys": s.default_vsys, "variables": len(s.variables), "description": s.description}
                  for s in pano.stacks.values()]
    out.append(table_section("pano_stacks", "Template stacks", [("stack", "Stack", "mono"), ("templates", "Templates (first has priority)"), ("firewalls", "Firewalls", "num"),
                                                                  ("default_vsys", "Default vsys"), ("variables", "Variables", "num"), ("description", "Description")], stack_rows, group="Panorama",
                             hint="The first template in the list wins a conflict; settings made on the stack itself win over all of its templates."))
    sec_cols = [("dg", "Device group", "mono"), ("position", "Position"), ("n", "#", "num"), ("name", "Rule", "mono"), ("from", "From zone"), ("to", "To zone"), ("source", "Source"),
                ("destination", "Destination"), ("application", "Application"), ("service", "Service"), ("action", "Action"), ("state", "State"), ("profile", "Profile"), ("log", "Log"),
                ("target", "Target"), ("description", "Description")]
    out.append(table_section("pano_security", "Security rules", sec_cols, _rule_rows(pano, ("security",)), group="Policy", page_size=100,
                             hint="Rules in the order Panorama stores them: pre-rules are evaluated before the firewall's local rules, post-rules after."))
    other = _rule_rows(pano, ("nat", "pbf", "decryption", "application-override", "authentication", "dos", "qos", "tunnel-inspect", "sdwan", "default-security-rules"))
    out.append(table_section("pano_other_rules", "NAT and other rulebases", [("dg", "Device group", "mono"), ("kind", "Rulebase"), ("position", "Position"), ("n", "#", "num"),
                                                                              ("name", "Rule", "mono"), ("from", "From zone"), ("to", "To zone"), ("source", "Source"),
                                                                              ("destination", "Destination"), ("service", "Service / port"), ("action", "Action"), ("state", "State"),
                                                                              ("target", "Target"), ("description", "Description")], other, group="Policy", page_size=100))
    obj_rows = []
    for sc in [pano.shared] + list(pano.groups.values()):
        counts = {k: len(v) for k, v in sc.objects.items()}
        obj_rows.append({"dg": sc.name, "addresses": counts.get("address", 0), "address_groups": counts.get("address-group", 0), "services": counts.get("service", 0),
                         "service_groups": counts.get("service-group", 0), "tags": counts.get("tag", 0), "app_groups": counts.get("application-group", 0),
                         "profiles": sum(counts.get(k, 0) for k in pp.PROFILE_KINDS), "profile_groups": counts.get("profile-group", 0), "edl": counts.get("external-list", 0)})
    out.append(table_section("pano_objects", "Objects per scope", [("dg", "Scope", "mono"), ("addresses", "Addresses", "num"), ("address_groups", "Address groups", "num"), ("services", "Services", "num"),
                                                                    ("service_groups", "Service groups", "num"), ("tags", "Tags", "num"), ("app_groups", "Application groups", "num"),
                                                                    ("profiles", "Security profiles", "num"), ("profile_groups", "Profile groups", "num"), ("edl", "External lists", "num")],
                             obj_rows, group="Objects"))
    out.append(table_section("pano_unused", "Unused objects", [("dg", "Defined in", "mono"), ("kind", "Kind"), ("name", "Object", "mono"), ("value", "Value", "mono")], unused, group="Objects", page_size=100,
                             hint="Not referenced by any rule or group of the scope or of the device groups below it. Rules and objects on the firewalls themselves are not part of this export.",
                             empty="Every object is referenced."))
    root = pano.root
    admin_rows = []
    for name, e in entries(root, "mgt-config/users").items():
        role = "superuser" if e.find("permissions/role-based/superuser") is not None else (next((c.tag for c in e.find("permissions/role-based")), "custom") if e.find("permissions/role-based") is not None else "")
        admin_rows.append({"admin": name, "role": role, "auth": text(e, "authentication-profile") or ("local password" if e.find("phash") is not None else ""), "description": text(e, "description")[:120]})
    out.append(table_section("pano_admins", "Panorama administrators", [("admin", "Administrator", "mono"), ("role", "Role"), ("auth", "Authentication"), ("description", "Description")], admin_rows,
                             group="Panorama administration", hint="Password hashes and keys are never shown.", empty="No administrator is defined in this export."))
    return out


# ------------------------------------------------------------------------------------------------ entry point
def analyze(content: str, filename: str = "", today: date | None = None) -> dict[str, Any]:
    pano = pp.parse(content)
    findings: list[dict[str, Any]] = []
    notes: list[str] = []
    findings += panorama_rules.rule_findings(pano)
    findings += panorama_rules.disabled_findings(pano)
    findings += panorama_rules.object_visibility_findings(pano)
    findings += panorama_rules.target_findings(pano)
    findings += panorama_rules.hierarchy_findings(pano)
    shadow, shadow_notes = panorama_rules.shadow_findings(pano)
    findings += shadow
    notes += shadow_notes
    obj_findings, unused = object_findings(pano)
    findings += obj_findings
    findings += management_findings(pano)
    findings += template_findings(pano)
    findings = sort_findings(dedupe_findings(findings))
    sects = sections(pano, unused, findings)
    scope.apply(sects, "dg", "Device group")

    sec_rules = sum(sc.rule_count("security") for sc in [pano.shared] + list(pano.groups.values()))
    all_rules = sum(sc.rule_count() for sc in [pano.shared] + list(pano.groups.values()))
    nat_rules = sum(sc.rule_count("nat") for sc in [pano.shared] + list(pano.groups.values()))
    objects = sum(sum(len(v) for v in sc.objects.values()) for sc in [pano.shared] + list(pano.groups.values()))
    counts = severity_counts(findings)
    hostname = filename.rsplit(".", 1)[0] if filename else "Panorama"
    result = new_result("firewall", hostname=hostname, vendor="Palo Alto Networks", platform=f"Panorama · PAN-OS {pano.version}".strip(" ·"), source_name=filename, title=hostname,
                        subtitle=f"Panorama · {len(pano.groups)} device group(s), {len(pano.devices)} managed firewall(s), {len(pano.templates)} template(s), {sec_rules:,} security rules")
    result["sections"] = sects
    known = {s["id"] for s in sects} | {"findings", "overview", "coverage"}
    result["cards"] = [card("Device groups", len(pano.groups), section="pano_groups"), card("Managed firewalls", len(pano.devices), section="pano_devices"),
                       card("Templates", f"{len(pano.templates)} / {len(pano.stacks)} stacks", section="pano_templates"), card("Security rules", f"{sec_rules:,}", section="pano_security"),
                       card("Objects", f"{objects:,}", section="pano_objects"),
                       card("High findings", counts["high"], "bad" if counts["high"] else "ok"), card("Medium findings", counts["medium"], "warn" if counts["medium"] else "ok")]
    result["cards"] = [c if not c.get("section") or c["section"] in known else dict(c, section="") for c in result["cards"]]
    result["info"] = info_rows([("Type", "Panorama configuration export"), ("PAN-OS version", pano.version), ("Device groups", len(pano.groups)), ("Template stacks", len(pano.stacks)),
                                ("Managed firewalls", len(pano.devices)), ("Rules (all rulebases)", f"{all_rules:,}"), ("NAT rules", f"{nat_rules:,}"),
                                ("Device-group hierarchy", "read from the export" if pano.hierarchy_known else "not in the export (flat under shared)")])
    result["findings"] = findings
    result["coverage"] = [
        {"command": "shared / device-group objects", "status": "analyzed", "note": f"{objects:,} objects in {len(pano.groups) + 1} scope(s): references, duplicates, redefinitions, unused."},
        {"command": "pre / post rulebases", "status": "analyzed", "note": f"{all_rules:,} rules; security rules are checked in the order a firewall evaluates them."},
        {"command": "templates and template stacks", "status": "analyzed", "note": f"{len(pano.templates)} template(s), {len(pano.stacks)} stack(s): management services, NTP, interface management profiles."},
        {"command": "mgt-config users and password complexity", "status": "analyzed", "note": "Hashes and keys are never read into a table."},
        {"command": "rule hit counts, local firewall rules, template variables", "status": "not in this file", "note": "A Panorama export has no hit counts; local rules and per-firewall variable values live on the firewalls."},
    ]
    result["warnings"] = pano.warnings + notes
    result["panorama"] = {"groups": list(pano.groups), "devices": [{"serial": d.serial, "group": d.device_group, "stack": d.stack} for d in pano.devices.values()]}
    return result
