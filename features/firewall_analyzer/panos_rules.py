"""Palo Alto rulebase checks that need the whole policy, not one rule.

Works on the vendor-neutral dashboard built by ``firewall_service`` (rows carry ``vsys``).  Every comparison is by
object *name* - groups and regions are not expanded - so a rule is reported as shadowed only when an earlier rule
names the same or a wider (``any``) value in every field.  That can miss a shadow hidden behind a group; it does
not invent one.

A Panorama-managed firewall often holds no rulebase at all (it is pushed from a device group): then there is nothing
to compare and these rules stay silent instead of calling every object "unused".

Reference: PAN-OS Administrator's Guide, View Policy Rule Usage
https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/view-policy-rule-usage
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..analyzer_core.findings import finding
from .refs import PALO

ALLOW = {"allow", "accept", "permit"}
MATCH_FIELDS = ("from_zone", "to_zone", "source", "destination", "application", "service", "category", "source_user")
SAMPLE = 12


def _set(value: Any) -> set[str]:
    items = value if isinstance(value, (list, tuple, set)) else ([value] if value else [])
    return {str(i).lower() for i in items if str(i).strip()}


def _covers(wider: set[str], narrower: set[str]) -> bool:
    return not wider or "any" in wider or (bool(narrower) and narrower <= wider)


def _where(row: dict[str, Any]) -> str:
    return f" in {row['vsys']}" if row.get("vsys") else ""


def _names(rows: list[dict[str, Any]], limit: int = SAMPLE) -> str:
    shown = [f"{r['name']}{_where(r)}" if r.get("vsys") else r["name"] for r in rows[:limit]]
    return ", ".join(shown) + (f" and {len(rows) - limit} more" if len(rows) > limit else "")


def evaluate(d: dict[str, Any]) -> list[dict[str, Any]]:
    rules = d.get("security_rules", [])
    if not rules:
        return []
    out: list[dict[str, Any]] = []
    out += _shadowed(rules)
    out += _disabled(rules)
    out += _app_any(d, rules)
    out += _unknown_zones(d, rules)
    out += _unused_objects(d, rules)
    return out


def _catch_all(rule: dict[str, Any]) -> bool:
    return all(not _set(rule.get(f)) or "any" in _set(rule.get(f)) for f in MATCH_FIELDS)


def _shadowed(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A later rule can never match when an earlier enabled rule of the same vsys already matches everything it would.

    When the earlier rule is a catch-all (any zone, address, application, service), one finding names it and every rule it
    kills instead of one finding per dead rule: the cause is a single rule, and the fix is one move."""
    out: list[dict[str, Any]] = []
    by_vsys: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in rules:
        by_vsys[rule.get("vsys", "")].append(rule)
    for vsys, group in by_vsys.items():
        killed: dict[int, list[dict[str, Any]]] = defaultdict(list)          # position of a catch-all rule -> the rules it shadows
        for index, rule in enumerate(group):
            if rule.get("disabled"):
                continue
            mine = {f: _set(rule.get(f)) for f in MATCH_FIELDS}
            for position, earlier in enumerate(group[:index]):
                if earlier.get("disabled") or not all(_covers(_set(earlier.get(f)), mine[f]) for f in MATCH_FIELDS):
                    continue
                same = str(earlier.get("action", "")).lower() == str(rule.get("action", "")).lower()
                if _catch_all(earlier):
                    killed[position].append(rule)
                    break
                out.append(finding("PAN-POL-001", "low" if same else "medium", "Policy", "Rule is shadowed by an earlier rule" if not same else "Rule is redundant: an earlier rule already does the same",
                                   obj=f"rule {rule['name']}{_where(rule)}",
                                   detail=f"Rule '{rule['name']}' can never match: '{earlier['name']}' above it covers the same zones, addresses, applications and services" +
                                          ("" if same else f", and its action is '{earlier.get('action')}' while this rule's is '{rule.get('action')}', so the intended outcome of this rule is never applied") + ".",
                                   recommendation="Move the more specific rule above the broader one, merge the two, or delete the dead rule. Check Monitor > Policy rule usage (hit count) before removing.",
                                   reference=PALO["rule_usage"]))
                break
        for position, dead in killed.items():
            boss = group[position]
            boss_action = str(boss.get("action", "")).lower()
            opposite = [r for r in dead if str(r.get("action", "")).lower() != boss_action]
            unprofiled = [r for r in dead if r not in opposite and r.get("profile_setting") and not boss.get("profile_setting")]
            parts = [f"Rule #{position + 1} '{boss['name']}' ({boss.get('action')}) matches every zone, address, application and service, so the {len(dead)} rule(s) below it can never match: {_names(dead)}."]
            if opposite:
                parts.append(f"{len(opposite)} of them have the opposite action ({_names(opposite)}): the {'deny' if boss_action in ALLOW else 'allow'} intent of those rules is not enforced, and everything is {boss.get('action')}ed by '{boss['name']}'.")
            if unprofiled:
                parts.append(f"'{boss['name']}' has no security profile group, so the profiles attached to {_names(unprofiled)} are never applied: that traffic is not inspected.")
            out.append(finding("PAN-POL-005", "high" if opposite else "medium", "Policy", f"A catch-all rule hides {len(dead)} rule(s) below it", obj=f"rule {boss['name']}{_where(boss)}", detail=" ".join(parts),
                               recommendation=f"Move '{boss['name']}' to the end of the rulebase (or delete it) and keep the specific rules above it. Check Monitor > Policy rule usage (hit counts) first: rules with zero hits below a catch-all confirm the problem.",
                               reference=PALO["rule_usage"]))
    return out


def _disabled(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    off = [r for r in rules if r.get("disabled")]
    if not off:
        return []
    return [finding("PAN-POL-002", "info", "Policy", f"{len(off)} disabled rule(s) left in the rulebase", obj=f"{len(off)} rule(s)",
                    detail="Disabled rules are not evaluated but still have to be read, reviewed and migrated: " + _names(off) + ".",
                    recommendation="Delete rules that are no longer needed (keep the configuration backup), or tag them with a ticket and an expiry date.", reference=PALO["rule_usage"])]


def _app_any(d: dict[str, Any], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wan = {z["name"].lower() for z in d.get("zones", []) if any(w in z["name"].lower() for w in ("wan", "untrust", "outside", "internet", "isp", "public", "external"))}
    out = []
    for rule in rules:
        if rule.get("disabled") or str(rule.get("action", "")).lower() not in ALLOW:
            continue
        apps, services = _set(rule.get("application")), _set(rule.get("service"))
        sources = _set(rule.get("source"))
        if ("any" in apps or not apps) and services and "any" not in services and _set(rule.get("from_zone")) & wan:
            out.append(finding("PAN-POL-003", "medium", "Policy", "Rule from an untrusted zone allows any application", obj=f"rule {rule['name']}{_where(rule)}",
                               detail=f"Rule '{rule['name']}' allows application 'any' on {', '.join(sorted(services))} from {', '.join(sorted(_set(rule.get('from_zone'))))}" + (" to any source" if not sources or "any" in sources else "") +
                                      ". Port-based rules let any application that can use those ports through, including tunnels and evasive applications.",
                               recommendation="Name the applications that must be reachable and set the service to application-default, so App-ID decides what is allowed.", reference=PALO["app_default"]))
    return out


def _unknown_zones(d: dict[str, Any], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    zones: dict[str, set[str]] = defaultdict(set)
    for zone in d.get("zones", []):
        zones[zone.get("vsys", "")].add(zone["name"].lower())
    if not zones:
        return []                                                       # zones come from a Panorama template: cannot judge
    out = []
    for rule in rules:
        known = zones.get(rule.get("vsys", ""))
        if known is None:
            continue
        missing = sorted({z for f in ("from_zone", "to_zone") for z in _set(rule.get(f))} - known - {"any"})
        if missing:
            out.append(finding("PAN-POL-004", "medium", "Policy", "Rule references a zone that is not defined", obj=f"rule {rule['name']}{_where(rule)}",
                               detail=f"Rule '{rule['name']}' uses zone(s) {', '.join(missing)}, which do not exist{(' in ' + rule['vsys']) if rule.get('vsys') else ''}. The rule can never match (or the zone is defined in a Panorama template that is not in this file).",
                               recommendation="Create the zone, correct the name, or remove the rule.", reference=PALO["security_rule"]))
    return out


def _unused_objects(d: dict[str, Any], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Address and service objects that no rule, NAT rule, PBF rule or group uses; ``shared`` objects are visible in every vsys."""
    used: set[tuple[str, str]] = set()

    def mark(vsys: str, values: Any) -> None:
        for value in _set(values):
            used.add((vsys, value))
            used.add(("*", value))

    for row in rules + d.get("nat_rules", []) + d.get("pbf_rules", []):
        v = row.get("vsys", "")
        for f in ("source", "destination", "service", "translated_address"):
            mark(v, row.get(f))
    for group in d.get("address_objects", []) + d.get("service_objects", []):
        if len(group.get("members") or []) and not any(":" in str(m) for m in group["members"]):
            mark(group.get("vsys", ""), group["members"])
    def is_used(obj: dict[str, Any]) -> bool:
        vsys, name = obj.get("vsys", ""), obj["name"].lower()
        return (vsys, name) in used or (vsys == "shared" and ("*", name) in used)

    out = []
    for key, label in (("address_objects", "address"), ("service_objects", "service")):
        unused = [o for o in d.get(key, []) if not is_used(o)]
        if len(unused) >= 3:
            out.append(finding("PAN-OBJ-001", "low", "Objects", f"{len(unused)} {label} object(s) are not used by any rule", obj=f"{len(unused)} {label} object(s)",
                               detail=f"No security, NAT or policy-based-forwarding rule and no group refers to these {label} objects: " + _names(unused) + ". Unused objects hide stale hosts and make reviews harder.",
                               recommendation="Confirm with the owners, then remove them. Objects used only by Panorama-pushed rules or by other devices' templates appear unused here.", reference=PALO["security_rule"]))
    return out
