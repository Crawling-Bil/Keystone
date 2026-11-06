"""Convert a Panorama export: pick one device group (and optionally one firewall of it), flatten it, and hand the result to the PAN-OS converters.

A Panorama configuration is not a firewall configuration, so the converters cannot read it directly.  ``scope_xml`` resolves what one device group
(or one firewall, ``"group:serial"``) receives - shared and parent objects, pre/post rules in evaluation order, the template stack's interfaces, zones and
routing - into the XML of an ordinary PAN-OS firewall (:mod:`features.firewall_analyzer.panorama_effective`).  That XML is what the FortiGate converter
reads, and it is also the output of the Panorama -> Palo Alto "flatten" conversion.

Scope syntax: ``Group`` (every rule of the device group, rule targets are kept in the report), ``Group:SERIAL`` (only the rules pushed to that firewall,
and its vsys), or empty when the export has exactly one device group.

References: https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups ,
https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from features.firewall_analyzer import panorama_effective as pe
from features.firewall_analyzer import panorama_parse as pp

from .report import Report

DOC_GROUPS = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups"
DOC_STACK = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack"
DOC_TARGET = "https://docs.paloaltonetworks.com/panorama/11-1/panorama-admin/manage-firewalls/manage-device-groups/push-a-policy-rule-to-a-subset-of-firewalls"


@dataclass
class Scoped:
    xml: str
    group: str
    serial: str
    stack: str
    rules: int
    skipped_by_target: int
    hidden_objects: int
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    masked: str = ""                      # the uploaded export with every credential removed: the only form of it that is shown on the page

    def info(self) -> dict:
        return {"group": self.group, "serial": self.serial, "stack": self.stack, "rules": self.rules, "skipped_by_target": self.skipped_by_target,
                "hidden_objects": self.hidden_objects, "notes": self.notes}


def is_panorama(text: str) -> bool:
    return pp.looks_like_panorama(text)


def scopes(text: str) -> list[dict]:
    """Device groups and their firewalls, for the page's picker."""
    pano = pp.parse(text)
    out = []
    for name, group in pano.groups.items():
        out.append({"group": name, "parent": group.parent, "rules": group.rule_count(),
                    "firewalls": [{"serial": serial, "stack": pano.devices[serial].stack if serial in pano.devices else ""} for serial in group.devices]})
    return out


def scope_xml(text: str, scope: str = "") -> Scoped:
    pano = pp.parse(text)
    group, _, serial = (scope or "").strip().partition(":")
    group, serial = group.strip(), serial.strip()
    names = list(pano.groups)
    if not group:
        if len(names) != 1:
            raise ValueError("This is a Panorama export with %d device groups (%s). Enter one of them in the 'VDOM / device group' field; add ':<serial number>' after the name "
                             "to keep only the rules pushed to that firewall." % (len(names), ", ".join(names[:12]) + (" ..." if len(names) > 12 else "")))
        group = names[0]
    if group not in pano.groups:
        match = [n for n in names if n.lower() == group.lower()]
        if not match:
            raise ValueError(f"Device group '{group}' is not in this Panorama export. Device groups: {', '.join(names[:12])}{' ...' if len(names) > 12 else ''}.")
        group = match[0]
    if serial and serial not in pano.groups[group].devices:
        raise ValueError(f"Firewall '{serial}' is not a member of device group '{group}'. Members: {', '.join(list(pano.groups[group].devices)[:8]) or 'none'}.")
    xml, eff = pe.build_standalone(pano, group, serial)
    if pano.root is not None:                                  # build_standalone copied what it needs, so the original tree can be cleaned for display
        pp.strip_secrets(pano.root)
        masked = ET.tostring(pano.root, encoding="unicode")
    else:
        masked = ""
    rules = sum(len(v) for k, v in eff.rules.items() if k in ("security",))
    return Scoped(xml=xml, group=group, serial=serial, stack=eff.stack, rules=rules, skipped_by_target=eff.skipped_by_target, hidden_objects=len(eff.hidden),
                  notes=list(eff.notes), warnings=list(pano.warnings), masked=masked)


def flatten_report(scoped: Scoped, text: str) -> Report:
    """What the flatten conversion resolved, as the same report the FortiGate conversion produces."""
    report = Report()
    pano = pp.parse(text)
    eff = pe.effective(pano, scoped.group, scoped.serial)
    report.count("policies", "read", sum(len(v) for v in eff.rules.values()) + eff.skipped_by_target)
    report.count("policies", "written", sum(len(v) for v in eff.rules.values()))
    report.count("objects", "read", sum(len(v) for v in eff.objects.values()))
    report.count("objects", "written", sum(len(v) for v in eff.objects.values()))
    if eff.skipped_by_target:
        report.add("policies", "rule target", scoped.serial or scoped.group, "approximated",
                   f"{eff.skipped_by_target} rule(s) are pushed to other firewalls only and were left out for firewall {scoped.serial}.", DOC_TARGET)
    elif not scoped.serial:
        targeted = sum(1 for rules in eff.rules.values() for r in rules if r.target.restricted)
        if targeted:
            report.add("policies", "rule target", scoped.group, "review",
                       f"{targeted} rule(s) are pushed to specific firewalls of the device group, not to all of them. All are included; add ':<serial>' to the scope to keep one firewall's rules only.",
                       DOC_TARGET)
    for kind, name, upper, lower in eff.hidden[:200]:
        report.add("objects", kind, name, "approximated", f"Defined in '{upper}' and again in '{lower}'; the definition in '{lower}' is used.", DOC_GROUPS)
    if len(eff.hidden) > 200:
        report.add("objects", "redefinitions", scoped.group, "approximated", f"{len(eff.hidden) - 200} more object name(s) are defined at two levels.", DOC_GROUPS)
    for note in eff.notes:
        report.add("interfaces", "template stack", eff.stack or scoped.group, "review", note, DOC_STACK)
    if not eff.stack:
        report.add("interfaces", "template stack", scoped.group, "review", "No template stack was found for this device group: interfaces, zones and routing are not part of the output.", DOC_STACK)
    report.add("interfaces", "credentials", scoped.group, "approximated",
               "Administrator password hashes, pre-shared keys, SNMP community strings and private keys are never copied from a Panorama export; set them again on the target.",
               "https://docs.paloaltonetworks.com/panorama/administration/configure-administrative-access-to-panorama")
    for warning in scoped.warnings:
        report.add("policies", "hierarchy", scoped.group, "review", warning, DOC_GROUPS)
    return report
