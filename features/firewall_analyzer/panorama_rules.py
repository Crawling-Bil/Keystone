"""Policy findings for a Panorama export: any-any, missing inspection, unseen objects, stale targets, shadowed and redundant rules.

Every check works on the rules of one scope (shared or one device group) in the position they were written (pre or post).  The shadow check
is different: it works on the *evaluation order* a firewall of the device group sees (shared pre, parent pre, own pre, own post, parent post,
shared post), because that is the order in which a later rule can be hidden by an earlier one that lives in another scope.

Rule ids (PANO-POL-xxx, PANO-OBJ-xxx, PANO-HIER-xxx) are this module's own; each finding cites a Palo Alto Networks page.

References
* Device group policies (pre, post, default rules) https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/device-groups/device-group-policies
* Manage the rule hierarchy https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups/manage-the-rule-hierarchy
* Push a policy rule to a subset of firewalls https://docs.paloaltonetworks.com/panorama/11-1/panorama-admin/manage-firewalls/manage-device-groups/push-a-policy-rule-to-a-subset-of-firewalls
* Security policy best practices https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any

from ..analyzer_core.findings import cap_per_rule, finding
from .panorama_effective import effective_rules
from .panorama_parse import Panorama, Rule, Scope, members, rule_summary

REF_RULEBASE = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups/manage-the-rule-hierarchy"
REF_DG_POLICY = "https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/device-groups/device-group-policies"
REF_TARGET = "https://docs.paloaltonetworks.com/panorama/11-1/panorama-admin/manage-firewalls/manage-device-groups/push-a-policy-rule-to-a-subset-of-firewalls"
REF_BEST = "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices"
REF_DEVICE_GROUPS = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups"
REF_PROFILE_GROUP = "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-profiles/create-a-security-profile-group"
REF_RULE_USAGE = "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/view-policy-rule-usage"

ANY = "any"
WAN_ZONE = re.compile(r"(wan|untrust|outside|internet|isp|public|external|inet)", re.I)
BUILTIN_SERVICES = {"service-http", "service-https", "application-default", "any"}
SHADOW_PAIR_BUDGET = 4_000_000                         # candidate pairs per device group before the shadow check gives up (and says so)


def _shown(values: list[str], limit: int = 4) -> str:
    return ", ".join(values[:limit]) + (f" (+{len(values) - limit})" if len(values) > limit else "")


def _label(rule: Rule) -> str:
    return f"{rule.name} [{rule.scope} {rule.position}]"


def _allows(rule: Rule) -> bool:
    return rule.kind == "security" and rule.action in ("allow", "") and not rule.disabled


# ------------------------------------------------------------------------------------------------ per-rule checks
def rule_findings(pano: Panorama) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    scopes = [pano.shared] + list(pano.groups.values())
    for scope in scopes:
        for rule in scope.all_rules():
            if rule.kind != "security" or not _allows(rule):
                continue
            s = rule_summary(rule)
            src_any = (not s["source"] or ANY in s["source"]) and not s["negate_source"]
            dst_any = (not s["destination"] or ANY in s["destination"]) and not s["negate_destination"]
            app_any = not s["application"] or ANY in s["application"]
            svc_any = not s["service"] or ANY in s["service"]
            wan_src = any(WAN_ZONE.search(z) for z in s["from"])
            if src_any and dst_any and app_any and svc_any:
                out.append(finding("PANO-POL-001", "high", "Policy", "Allow rule matches any source, destination, application and service", obj=_label(rule),
                                   detail=f"Rule '{rule.name}' in {rule.location} permits all traffic from {_shown(s['from']) or 'any'} to {_shown(s['to']) or 'any'}. Every firewall that receives this rule "
                                          "is open between those zones, and the rule sits above anything below it in the rule hierarchy.",
                                   recommendation="Replace it with rules that name the applications and the source and destination objects; use the Policy Optimizer to see which applications use it.",
                                   reference=REF_BEST))
                continue
            if app_any and not (s["profile_group"] or s["profiles"]):
                out.append(finding("PANO-POL-002", "high" if wan_src else "medium", "Policy", "Allow rule with application 'any' and no security profiles", obj=_label(rule),
                                   detail=f"Rule '{rule.name}' in {rule.location} allows every application (service {_shown(s['service']) or 'any'}) from {_shown(s['from']) or 'any'}"
                                          f"{' (an untrusted-looking zone)' if wan_src else ''} and does not attach a profile group, so no antivirus, vulnerability or URL inspection applies.",
                                   recommendation="Allow the applications the traffic needs (App-ID) with service 'application-default' and attach the profile group your standard uses.",
                                   reference=REF_BEST))
            elif app_any:
                out.append(finding("PANO-POL-003", "medium", "Policy", "Allow rule with application 'any'", obj=_label(rule),
                                   detail=f"Rule '{rule.name}' in {rule.location} allows every application on {_shown(s['service']) or 'any service'}.",
                                   recommendation="Name the applications; 'application-default' then restricts them to their standard ports.", reference=REF_BEST))
            elif not (s["profile_group"] or s["profiles"]):
                out.append(finding("PANO-POL-004", "high" if wan_src else "medium", "Policy", "Allow rule without security profiles", obj=_label(rule),
                                   detail=f"Rule '{rule.name}' in {rule.location} allows {_shown(s['application'])} but has neither a profile group nor individual profiles.",
                                   recommendation="Attach a security profile group so allowed traffic is also inspected for threats.", reference=REF_PROFILE_GROUP))
            if not s["log_end"] and not s["log_setting"]:
                out.append(finding("PANO-POL-005", "low", "Policy", "Allow rule does not log at session end", obj=_label(rule),
                                   detail=f"Rule '{rule.name}' in {rule.location} has log-at-session-end switched off and no log forwarding profile.",
                                   recommendation="Enable log at session end and a log forwarding profile so the traffic is recorded and forwarded.", reference=REF_BEST))
    return cap_per_rule(out, 25)


def disabled_findings(pano: Panorama) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for scope in [pano.shared] + list(pano.groups.values()):
        counts: dict[str, int] = defaultdict(int)
        for rule in scope.all_rules():
            if rule.disabled:
                counts[f"{rule.position} {rule.kind}"] += 1
        for key, n in counts.items():
            total = sum(len(r) for (pos, kind), r in scope.rules.items() if f"{pos} {kind}" == key)
            if n >= 10 or (total and n / total >= 0.25 and n >= 3):
                out.append(finding("PANO-POL-006", "low", "Policy hygiene", f"{n} of {total} {key} rules are disabled", obj=scope.name,
                                   detail=f"Device group '{scope.name}' keeps {n} disabled {key} rules. Disabled rules are still pushed, still committed and still read by every administrator.",
                                   recommendation="Review the disabled rules with their owners and delete the ones that are no longer needed (rule usage shows when a rule last matched).",
                                   reference=REF_RULE_USAGE))
    return out


# ------------------------------------------------------------------------------------------------ objects a rule needs
def _visible_names(pano: Panorama, scope: Scope) -> dict[str, set[str]]:
    seen: dict[str, set[str]] = defaultdict(set)
    for s in pano.chain(scope.name):
        for kind, items in s.objects.items():
            seen[kind].update(items)
    return seen


_LITERAL = re.compile(r"^[0-9a-fA-F:.]+(?:/[0-9]{1,3})?(?:-[0-9a-fA-F:.]+)?$")


def _is_literal(name: str) -> bool:
    if not _LITERAL.match(name):
        return False
    try:
        ipaddress.ip_network(name, strict=False)
        return True
    except ValueError:
        return "-" in name or "." in name or ":" in name


BUILTIN_EDL_PREFIX = "panw-"                           # predefined external dynamic lists (panw-highrisk-ip-list, panw-known-ip-list ...) exist on the firewall, not in the export


class _Names(set):
    """The address-like names a scope can resolve; the predefined ``panw-*`` lists always resolve."""

    def __contains__(self, item: object) -> bool:
        return isinstance(item, str) and (item.startswith(BUILTIN_EDL_PREFIX) or super().__contains__(item))


def _address_names(visible: dict[str, set[str]]) -> set[str]:
    return _Names(visible["address"] | visible["address-group"] | visible["external-list"] | visible["region"] | visible["dynamic-user-group"])


def object_visibility_findings(pano: Panorama) -> list[dict[str, Any]]:
    """A rule that names an object its own scope cannot see (defined only in a sibling device group, or not at all) does not commit."""
    out: list[dict[str, Any]] = []
    owners: dict[tuple[str, str], list[str]] = defaultdict(list)
    for scope in pano.groups.values():
        for kind, items in scope.objects.items():
            for name in items:
                owners[(kind, name)].append(scope.name)
    for scope in [pano.shared] + list(pano.groups.values()):
        visible = _visible_names(pano, scope)
        addr = _address_names(visible)
        for rule in scope.all_rules():
            if rule.kind not in ("security", "nat", "pbf", "decryption", "application-override", "qos", "authentication", "dos", "tunnel-inspect"):
                continue
            missing: list[tuple[str, str]] = []
            for tag in ("source", "destination"):
                for name in rule.f(tag):
                    if name != ANY and not _is_literal(name) and name not in addr:
                        missing.append((tag, name))
            for name in rule.f("service"):
                if name not in BUILTIN_SERVICES and name not in visible["service"] and name not in visible["service-group"] and rule.kind in ("security", "nat", "decryption"):
                    missing.append(("service", name))
            for name in rule.f("tag"):
                if name not in visible["tag"]:
                    missing.append(("tag", name))
            group = rule.profile_group
            if group and group not in visible["profile-group"]:
                missing.append(("profile group", group))
            if not missing:
                continue
            elsewhere = [m for m in missing if any(o != scope.name for o in owners.get(({"source": "address", "destination": "address"}.get(m[0], m[0]), m[1]), []))]
            kind_word = "is defined in another device group" if elsewhere else "is not defined in shared, this device group or its parents"
            out.append(finding("PANO-OBJ-001", "high" if elsewhere else "medium", "Objects", "Rule uses an object its device group cannot see", obj=_label(rule),
                               detail=f"Rule '{rule.name}' in {rule.location} refers to {_shown([f'{k} {n}' for k, n in missing])}, which {kind_word}. "
                                      "Panorama refuses to commit a device group with an unresolved reference, or the rule matches less than intended once the object is re-created locally.",
                               recommendation="Define the object in shared (or in the device group's own ancestors) so every device group that receives the rule resolves it, or move the rule to the device group that owns the object.",
                               reference=REF_DEVICE_GROUPS))
    return cap_per_rule(out, 25)


# ------------------------------------------------------------------------------------------------ targets
def target_findings(pano: Panorama) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for scope in [pano.shared] + list(pano.groups.values()):
        known = set(scope.devices) if scope.name != "shared" else set(pano.devices)
        stale: dict[str, int] = defaultdict(int)
        for rule in scope.all_rules():
            for serial in rule.target.devices:
                serial = serial.split("/")[0]
                if serial not in known and serial not in pano.devices:
                    stale[serial] += 1
        if stale:
            total = sum(stale.values())
            out.append(finding("PANO-HIER-001", "medium", "Panorama structure", f"{total} rule target(s) name firewalls that are not managed", obj=scope.name,
                               detail=f"Rules of '{scope.name}' are targeted at {len(stale)} serial number(s) that are not in this Panorama's managed devices or device groups. "
                                      "Such a rule is pushed to nobody, so the access it was written to give is not there.",
                               recommendation="Re-target the rules at the replacement firewall or remove the old serial numbers (Policies > Target).", reference=REF_TARGET))
    return out


def hierarchy_findings(pano: Panorama) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not pano.hierarchy_known and len(pano.groups) > 1:
        out.append(finding("PANO-HIER-002", "info", "Panorama structure", "The export does not carry the device-group hierarchy", obj="device groups",
                           detail="Every device group is read as a direct child of shared. Objects and pre/post rules that a device group inherits from a parent device group are not included in "
                                  "its effective view, so findings about shadowing and missing objects may be incomplete for nested groups.",
                           recommendation="Export the running configuration again from Panorama (Device > Setup > Operations > Export named configuration snapshot) so the hierarchy is included.",
                           reference="https://docs.paloaltonetworks.com/panorama/administration/administer-panorama/manage-panorama-and-firewall-configuration-backups/save-and-export-panorama-and-firewall-configurations"))
    for scope in pano.groups.values():
        if not scope.devices and not pano.children(scope.name):
            out.append(finding("PANO-HIER-003", "low", "Panorama structure", "Device group has no firewalls and no child device groups", obj=scope.name,
                               detail=f"Device group '{scope.name}' holds {scope.rule_count()} rule(s) and {sum(len(v) for v in scope.objects.values())} object(s) but nothing receives them.",
                               recommendation="Assign the firewalls or remove the device group.", reference=REF_DEVICE_GROUPS))
    for dev in pano.devices.values():
        if not dev.device_group:
            out.append(finding("PANO-HIER-004", "medium", "Panorama structure", "Managed firewall is in no device group", obj=dev.serial,
                               detail="The firewall is managed by this Panorama but belongs to no device group, so it receives no shared or device-group policy and objects.",
                               recommendation="Assign it to a device group.", reference=REF_DEVICE_GROUPS))
        if not dev.stack:
            out.append(finding("PANO-HIER-005", "medium", "Panorama structure", "Managed firewall is in no template stack", obj=dev.serial,
                               detail="The firewall receives no template: its interfaces, zones, routing and device settings are not managed from Panorama.",
                               recommendation="Add it to a template stack.", reference="https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack"))
    used = {name for stack in pano.stacks.values() for name in stack.templates}
    for name in pano.templates:
        if name not in used:
            out.append(finding("PANO-HIER-006", "low", "Panorama structure", "Template is not part of any template stack", obj=name,
                               detail=f"Template '{name}' is defined but no stack uses it, so no firewall receives its settings.",
                               recommendation="Add it to a stack or delete it.", reference="https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack"))
    for stack in pano.stacks.values():
        for name in stack.templates:
            if name not in pano.templates:
                out.append(finding("PANO-HIER-007", "high", "Panorama structure", "Template stack names a template that does not exist", obj=f"{stack.name} / {name}",
                                   detail=f"Stack '{stack.name}' lists template '{name}', which is not defined in this export.", recommendation="Remove it from the stack or restore the template.",
                                   reference="https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack"))
        if not stack.devices:
            out.append(finding("PANO-HIER-008", "low", "Panorama structure", "Template stack has no firewalls", obj=stack.name,
                               detail=f"Stack '{stack.name}' has no firewall assigned.", recommendation="Assign firewalls or delete the stack.",
                               reference="https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack"))
    return out


# ------------------------------------------------------------------------------------------------ shadowing
def _closure(names: list[str], groups: dict[str, list[str]], cache: dict[str, frozenset[str]]) -> frozenset[str]:
    out: set[str] = set()
    stack = list(names)
    while stack:
        n = stack.pop()
        if n in out:
            continue
        out.add(n)
        stack.extend(groups.get(n, []))
    return frozenset(out)


class _Compiled:
    __slots__ = ("rule", "frm", "to", "src", "dst", "app", "svc", "user", "cat", "devs", "negated", "skip", "order")

    def __init__(self, rule: Rule, order: int, groups: dict[str, list[str]], cache: dict[str, frozenset[str]]):
        s = rule_summary(rule)
        self.rule, self.order = rule, order

        def side(values: list[str], closure: bool = False) -> frozenset[str] | None:
            if not values or ANY in values:
                return None
            return _closure(values, groups, cache) if closure else frozenset(values)

        self.frm, self.to = side(s["from"]), side(s["to"])
        self.src, self.dst = side(s["source"], True), side(s["destination"], True)
        self.app, self.svc = side(s["application"]), side(s["service"])
        self.user, self.cat = side(s["source_user"]), side(s["category"])
        self.devs = frozenset(d.split("/")[0] for d in rule.target.devices) if (rule.target.devices and not rule.target.negate and not rule.target.tags) else None
        self.negated = s["negate_source"] or s["negate_destination"] or bool(rule.target.tags) or rule.target.negate
        self.skip = s["disabled"] or self.negated or bool(s["hip"]) or bool(s["schedule"]) or s["rule_type"] not in ("universal", "")


def _contains(a: frozenset[str] | None, b: frozenset[str] | None) -> bool:
    """Set ``a`` contains set ``b``; ``None`` is the universal set."""
    if a is None:
        return True
    if b is None:
        return False
    return b <= a


def _shadows(a: _Compiled, b: _Compiled) -> bool:
    if a.skip or b.skip:
        return False
    if a.devs is not None and (b.devs is None or not b.devs <= a.devs):     # a is pushed to fewer firewalls than b: it cannot hide b everywhere
        return False
    if not (_contains(a.frm, b.frm) and _contains(a.to, b.to) and _contains(a.src, b.src) and _contains(a.dst, b.dst)):
        return False
    if not (_contains(a.app, b.app) and _contains(a.user, b.user) and _contains(a.cat, b.cat)):
        return False
    if a.svc is None:
        return True
    if b.svc is None:
        return False
    return b.svc <= a.svc


def shadow_findings(pano: Panorama) -> tuple[list[dict[str, Any]], list[str]]:
    """Later security rules hidden by an earlier rule of the same evaluation order.  Each pair is reported once, however many device groups see it."""
    out: list[dict[str, Any]] = []
    notes: list[str] = []
    seen: dict[tuple[str, str, str, str, str, str], list[str]] = {}
    for gname in pano.groups:
        eff, _ = effective_rules(pano, gname)
        rules = eff.get("security", [])
        if len(rules) < 2:
            continue
        groups: dict[str, list[str]] = {}
        for scope in pano.chain(gname):
            for name, elem in scope.objects.get("address-group", {}).items():
                groups[name] = members(elem, "static")
        cache: dict[str, frozenset[str]] = {}
        compiled = [_Compiled(r, i, groups, cache) for i, r in enumerate(rules)]
        by_from: dict[str, list[int]] = defaultdict(list)
        any_from: list[int] = []
        for i, c in enumerate(compiled):
            if c.skip:
                continue
            if c.frm is None:
                any_from.append(i)
            else:
                for z in c.frm:
                    by_from[z].append(i)
        pairs = 0
        for j, b in enumerate(compiled):
            if b.skip:
                continue
            first = next(iter(b.frm)) if b.frm else None
            cands = any_from if first is None else sorted(set(by_from.get(first, [])) | set(any_from))
            for i in cands:
                if i >= j:
                    break
                pairs += 1
                a = compiled[i]
                if not _shadows(a, b):
                    continue
                key = (a.rule.scope, a.rule.position, a.rule.name, b.rule.scope, b.rule.position, b.rule.name)
                seen.setdefault(key, []).append(gname)
                break                                         # the first rule that hides it is the one to fix
            if pairs > SHADOW_PAIR_BUDGET:
                notes.append(f"The shadow check for device group '{gname}' stopped after {SHADOW_PAIR_BUDGET:,} candidate pairs; later rules of that group were not compared.")
                break
    index: dict[tuple[str, str, str], Rule] = {}
    for scope in [pano.shared] + list(pano.groups.values()):
        for rule in scope.rules.get(("pre", "security"), []) + scope.rules.get(("post", "security"), []):
            index[(rule.scope, rule.position, rule.name)] = rule
    for (a_scope, a_pos, a_name, b_scope, b_pos, b_name), gs in seen.items():
        a, b = index[(a_scope, a_pos, a_name)], index[(b_scope, b_pos, b_name)]
        same = (a.action or "allow") == (b.action or "allow")
        via = f" as seen by device group{'s' if len(gs) > 1 else ''} {_shown(gs, 3)}"
        if same:
            out.append(finding("PANO-POL-007", "low", "Policy hygiene", "Rule is redundant: an earlier rule already matches the same traffic with the same action", obj=_label(b),
                               detail=f"'{b.name}' [{b.scope} {b.position}] never decides a session: '{a.name}' [{a.scope} {a.position}] comes first, covers its zones, addresses, applications and services, "
                                      f"and has the same action ({a.action or 'allow'}){via}.",
                               recommendation="Delete the later rule, or narrow the earlier one if the later rule was meant to differ.", reference=REF_RULE_USAGE))
        else:
            out.append(finding("PANO-POL-008", "high" if (b.action in ("deny", "drop", "reset-client", "reset-server", "reset-both")) else "medium", "Policy",
                               "Rule is shadowed by an earlier rule with the opposite action", obj=_label(b),
                               detail=f"'{b.name}' [{b.scope} {b.position}] ({b.action or 'allow'}) can never match: '{a.name}' [{a.scope} {a.position}] ({a.action or 'allow'}) comes first and covers "
                                      f"everything it matches{via}.",
                               recommendation="Move the rule above the one that hides it (or reverse the pre/post position), or delete it if it is obsolete.", reference=REF_RULEBASE))
    return cap_per_rule(out, 25), notes
