"""Palo Alto Panorama configuration export -> a typed model (scopes, device groups, templates, stacks, managed devices).

A Panorama running-config is not a firewall configuration: the firewall policy lives in *device groups* (``devices/entry/device-group``) that inherit
from ``shared`` and from their parent device group, and the network and device settings live in *templates* and *template stacks*
(``devices/entry/template`` and ``template-stack``).  A managed firewall (``mgt-config/devices``, serial number) belongs to one device group and one
template stack.  This module reads that structure and nothing else: the hierarchy resolution is in :mod:`.panorama_effective`, the findings in
:mod:`.panorama_analyze`.

What the model keeps
* every object kind that a rule can reference (address, address-group, service, service-group, tag, application group/filter, external list, region,
  schedule, custom URL category, security-profile objects and groups, log-forwarding profiles) per scope, as the raw XML element;
* every rulebase (security, NAT, PBF, decryption, application-override, authentication, DoS, QoS, tunnel-inspection, SD-WAN, default-security-rules) in
  ``pre`` and ``post`` position, rule by rule, in the order of the file, with the rule's *target* (the devices the rule is pushed to);
* the device-group hierarchy when the export carries it (``readonly/dg-meta-data`` or a ``parent-dg`` element), and otherwise a flat hierarchy under
  ``shared`` with a warning, because guessing a parent would silently change which objects and rules a firewall inherits.

Credentials (``phash``, ``password``, ``key``, ``pre-shared-key``, SNMP community strings ...) are never copied into a finding or a table; the helper
:func:`strip_secrets` removes them from any element that is re-serialised.

References
* Device groups https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups
* Device group policies (pre, post and default rules) https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/device-groups/device-group-policies
* Templates and template stacks https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack
* Push a policy rule to a subset of firewalls (rule target) https://docs.paloaltonetworks.com/panorama/11-1/panorama-admin/manage-firewalls/manage-device-groups/push-a-policy-rule-to-a-subset-of-firewalls
* Save and export Panorama and firewall configurations https://docs.paloaltonetworks.com/panorama/administration/administer-panorama/manage-panorama-and-firewall-configuration-backups/save-and-export-panorama-and-firewall-configurations
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Iterable

LOCAL = "localhost.localdomain"

# object kind -> path below a scope element (shared or device-group entry)
OBJECT_PATHS: dict[str, str] = {
    "address": "address", "address-group": "address-group", "service": "service", "service-group": "service-group", "tag": "tag",
    "application": "application", "application-group": "application-group", "application-filter": "application-filter",
    "external-list": "external-list", "region": "region", "schedule": "schedule", "dynamic-user-group": "dynamic-user-group",
    "custom-url-category": "profiles/custom-url-category", "virus": "profiles/virus", "spyware": "profiles/spyware", "vulnerability": "profiles/vulnerability",
    "url-filtering": "profiles/url-filtering", "file-blocking": "profiles/file-blocking", "wildfire-analysis": "profiles/wildfire-analysis",
    "data-filtering": "profiles/data-filtering", "dos-protection": "profiles/dos-protection", "decryption-profile": "profiles/decryption",
    "hip-object": "profiles/hip-objects", "hip-profile": "profiles/hip-profiles", "profile-group": "profile-group", "log-profile": "log-settings/profiles",
    "data-object": "profiles/data-objects", "authentication-object": "authentication-object", "device-object": "device-object",
}
PROFILE_KINDS = ("virus", "spyware", "vulnerability", "url-filtering", "file-blocking", "wildfire-analysis", "data-filtering")
RULE_KINDS = ("security", "nat", "pbf", "decryption", "application-override", "authentication", "dos", "qos", "tunnel-inspect", "sdwan", "network-packet-broker",
              "default-security-rules")

# leaf elements whose text is a credential; never re-serialised, never shown
SECRET_TAGS = frozenset({
    "phash", "password", "key", "pre-shared-key", "auth-password", "priv-password", "private-key", "secret", "passphrase", "snmp-community-string",
    "shared-secret", "bind-password", "api-key", "auth-key", "psk", "authkey", "privkey", "client-secret", "access-key", "secret-key",
})


def text(elem: ET.Element | None, path: str = ".", default: str = "") -> str:
    if elem is None:
        return default
    node = elem.find(path)
    return (node.text or "").strip() if node is not None and node.text else default


def members(elem: ET.Element | None, path: str = ".") -> list[str]:
    """``<x><member>a</member><member>b</member></x>`` -> ``["a", "b"]``; a bare ``<x>a</x>`` -> ``["a"]``."""
    if elem is None:
        return []
    node = elem if path == "." else elem.find(path)
    if node is None:
        return []
    out = [(m.text or "").strip() for m in node.findall("member") if (m.text or "").strip()]
    if not out and not len(node) and (node.text or "").strip():
        out = [(node.text or "").strip()]
    return out


def entries(elem: ET.Element | None, path: str = ".") -> dict[str, ET.Element]:
    """The ``<entry name=...>`` children (in file order) keyed by name."""
    node = elem if (elem is not None and path == ".") else (elem.find(path) if elem is not None else None)
    if node is None:
        return {}
    return {e.get("name", ""): e for e in node.findall("entry") if e.get("name")}


_SECRET_NAME = re.compile(r"(?:^|-)(?:password|passwd|secret|passphrase|psk|phash)(?:-|$)|private-key|pre-shared-key|api-key|auth-key|authentication-key|access-key|secret-key|encryption-key|"
                          r"snmp-community-string|shared-secret|(?:^|-)(?:auth|priv)pwd$")        # authpwd / privpwd: the SNMPv3 keys
_NOT_A_VALUE = re.compile(r"^(?:yes|no|\d{1,3}|enable|disable|enabled|disabled)$", re.I)       # password-history-count, password-change-on-first-login ...


def is_secret(parent: ET.Element, child: ET.Element) -> bool:
    """A leaf that holds a credential: named like one (``wmi-password``, ``bind-password``, ``pre-shared-key``) and not a setting about passwords, or an SNMP trap server's ``community``."""
    if len(child):
        return False
    value = (child.text or "").strip()
    if child.tag == "community":
        return parent.find("manager") is not None and bool(value)       # an SNMP trap receiver; a BGP community in a route map is not a credential
    if child.tag in SECRET_TAGS:
        return True
    return bool(_SECRET_NAME.search(child.tag)) and bool(value) and not _NOT_A_VALUE.match(value)


def strip_secrets(elem: ET.Element) -> int:
    """Remove credential leaves from ``elem`` in place; returns how many were removed."""
    removed = 0
    for parent in list(elem.iter()):
        for child in list(parent):
            if is_secret(parent, child):
                parent.remove(child)
                removed += 1
    return removed


@dataclass
class Target:
    """Where a rule is pushed: ``devices`` are serial numbers (with optional vsys), ``negate`` inverts the match, ``tags`` are device tags."""
    devices: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    negate: bool = False

    @property
    def restricted(self) -> bool:
        return bool(self.devices or self.tags or self.negate)

    def applies(self, serial: str, device_tags: Iterable[str] = ()) -> bool:
        if not (self.devices or self.tags):
            return True                                           # no device listed: the rule goes to every firewall of the device group
        hit = serial in self.devices or bool(set(self.tags) & set(device_tags))
        return (not hit) if self.negate else hit


@dataclass
class Rule:
    kind: str
    name: str
    position: str                      # "pre" | "post" | "default"
    scope: str                         # device-group name or "shared"
    index: int                         # 1-based position within (scope, position, kind)
    element: ET.Element
    target: Target = field(default_factory=Target)

    # -- common fields, read lazily from the element ------------------------------------------------
    def f(self, tag: str) -> list[str]:
        return members(self.element, tag)

    @property
    def disabled(self) -> bool:
        return text(self.element, "disabled") == "yes"

    @property
    def action(self) -> str:
        return text(self.element, "action") or ("allow" if self.kind == "security" else "")

    @property
    def description(self) -> str:
        return text(self.element, "description")

    @property
    def tags(self) -> list[str]:
        return self.f("tag")

    @property
    def log_end(self) -> bool:
        return text(self.element, "log-end") != "no"

    @property
    def log_setting(self) -> str:
        return text(self.element, "log-setting")

    @property
    def profile_group(self) -> str:
        return (members(self.element, "profile-setting/group") or [""])[0]

    @property
    def profiles(self) -> dict[str, list[str]]:
        node = self.element.find("profile-setting/profiles")
        return {child.tag: members(child) for child in node} if node is not None else {}

    @property
    def negate_source(self) -> bool:
        return text(self.element, "negate-source") == "yes"

    @property
    def negate_destination(self) -> bool:
        return text(self.element, "negate-destination") == "yes"

    @property
    def location(self) -> str:
        return f"{self.scope} {self.position}"


@dataclass
class Scope:
    """``shared`` or one device group."""
    name: str
    parent: str = ""                                   # "" for shared; "shared" for a top-level device group
    description: str = ""
    objects: dict[str, dict[str, ET.Element]] = field(default_factory=dict)
    rules: dict[tuple[str, str], list[Rule]] = field(default_factory=dict)      # (position, kind) -> rules in order
    devices: dict[str, list[str]] = field(default_factory=dict)                  # serial -> vsys names (device groups only)

    def all_rules(self) -> list[Rule]:
        return [rule for rules in self.rules.values() for rule in rules]

    def rule_count(self, kind: str | None = None) -> int:
        return sum(len(rules) for (position, k), rules in self.rules.items() if kind is None or k == kind)


@dataclass
class Template:
    name: str
    description: str = ""
    config: ET.Element | None = None                    # <config><devices><entry name=localhost.localdomain>...
    variables: dict[str, str] = field(default_factory=dict)

    def device_entry(self) -> ET.Element | None:
        return self.config.find(f"devices/entry") if self.config is not None else None


@dataclass
class Stack:
    name: str
    description: str = ""
    templates: list[str] = field(default_factory=list)          # first = highest priority
    devices: dict[str, list[str]] = field(default_factory=dict)
    default_vsys: str = ""
    config: ET.Element | None = None                    # settings made on the stack itself
    variables: dict[str, str] = field(default_factory=dict)
    device_variables: dict[str, dict[str, str]] = field(default_factory=dict)      # serial -> variable -> value set for that firewall


@dataclass
class ManagedDevice:
    serial: str
    device_group: str = ""
    stack: str = ""
    auto_push: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class Panorama:
    version: str = ""
    shared: Scope = field(default_factory=lambda: Scope("shared"))
    groups: dict[str, Scope] = field(default_factory=dict)
    templates: dict[str, Template] = field(default_factory=dict)
    stacks: dict[str, Stack] = field(default_factory=dict)
    devices: dict[str, ManagedDevice] = field(default_factory=dict)
    root: ET.Element | None = None
    hierarchy_known: bool = False
    warnings: list[str] = field(default_factory=list)

    def chain(self, group: str) -> list[Scope]:
        """``[shared, ancestor, ..., group]`` - the scopes whose objects and rules the group inherits, outermost first."""
        order: list[Scope] = []
        seen: set[str] = set()
        name = group
        while name and name != "shared" and name in self.groups and name not in seen:
            seen.add(name)
            order.append(self.groups[name])
            name = self.groups[name].parent
        return [self.shared] + list(reversed(order))

    def children(self, group: str) -> list[str]:
        return [g.name for g in self.groups.values() if g.parent == group]

    def depth(self, group: str) -> int:
        return len(self.chain(group)) - 1


_PANORAMA_HINT = re.compile(r"<(?:device-group|template-stack|template)\b")


def looks_like_panorama(content: str) -> bool:
    """A cheap test on the text, before any XML parsing: ``<config>`` with device groups, templates or stacks under ``devices/entry`` and no vsys of its own."""
    head = content[:400_000].lstrip("﻿ \t\r\n")
    if not head.startswith(("<?xml", "<config")):
        return False
    if "<config" not in head[:400]:
        return False
    return bool(_PANORAMA_HINT.search(content))


def is_panorama_root(root: ET.Element) -> bool:
    entry = root.find("devices/entry")
    if root.tag != "config" or entry is None:
        return False
    if entry.find("device-group") is not None or entry.find("template-stack") is not None or entry.find("template") is not None:
        return entry.find("vsys") is None
    return False


def _read_objects(scope_elem: ET.Element) -> dict[str, dict[str, ET.Element]]:
    out: dict[str, dict[str, ET.Element]] = {}
    for kind, path in OBJECT_PATHS.items():
        found = entries(scope_elem, path)
        if found:
            out[kind] = found
    return out


def _target(rule: ET.Element) -> Target:
    node = rule.find("target")
    if node is None:
        return Target()
    devices = []
    for entry in node.findall("devices/entry"):
        if entry.get("name"):
            devices.append(entry.get("name", ""))
    return Target(devices=devices, tags=members(node, "tags"), negate=text(node, "negate") == "yes")


def _read_rules(scope: Scope, scope_elem: ET.Element) -> None:
    for position, tag in (("pre", "pre-rulebase"), ("post", "post-rulebase")):
        base = scope_elem.find(tag)
        if base is None:
            continue
        for kind in RULE_KINDS:
            rule_nodes = base.findall(f"{kind}/rules/entry")
            if not rule_nodes:
                continue
            pos = "default" if kind == "default-security-rules" else position
            rules = [Rule(kind, node.get("name", ""), pos, scope.name, index, node, _target(node)) for index, node in enumerate(rule_nodes, 1) if node.get("name")]
            scope.rules[(pos, kind)] = rules


def _hierarchy(root: ET.Element) -> dict[str, str]:
    """device group -> parent, from the places PAN-OS writes it; ``{}`` when the export has none."""
    found: dict[str, str] = {}
    for path in ("readonly/dg-meta-data/dg-info/entry", "readonly/devices/entry/device-group/entry", "devices/entry/device-group/entry"):
        for entry in root.findall(path):
            parent = text(entry, "parent-dg")
            if entry.get("name") and parent:
                found[entry.get("name", "")] = parent
    return found


def _variables(elem: ET.Element) -> dict[str, str]:
    """``<variable><entry name="$x"><type><ip-netmask>10.0.0.1/24</ip-netmask>`` -> ``{"$x": "10.0.0.1/24"}`` (any variable type: the text of its first value)."""
    out: dict[str, str] = {}
    for v in elem.findall("variable/entry"):
        kind = v.find("type")
        value = ""
        if kind is not None:
            for child in kind:
                value = (child.text or "").strip() or text(child, "member")
                break
        if v.get("name"):
            out[v.get("name", "")] = value
    return out


def parse(content: str) -> Panorama:
    content = content.lstrip("﻿")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Not well-formed XML: {exc}") from exc
    if not is_panorama_root(root):
        raise ValueError("This XML is not a Panorama configuration: no device group, template or template stack was found below <devices><entry>.")
    pano = Panorama(version=root.get("version", ""), root=root)
    dev_entry = root.find("devices/entry")
    assert dev_entry is not None

    shared = root.find("shared")
    if shared is not None:
        pano.shared.objects = _read_objects(shared)
        _read_rules(pano.shared, shared)

    parents = _hierarchy(root)
    pano.hierarchy_known = bool(parents)
    for name, elem in entries(dev_entry, "device-group").items():
        scope = Scope(name, parent=parents.get(name, "shared"), description=text(elem, "description"))
        scope.objects = _read_objects(elem)
        _read_rules(scope, elem)
        for serial, dev in entries(elem, "devices").items():
            scope.devices[serial] = list(entries(dev, "vsys"))
        pano.groups[name] = scope
    for group in pano.groups.values():                         # a parent that does not exist is a dangling reference: flatten it
        if group.parent != "shared" and group.parent not in pano.groups:
            pano.warnings.append(f"Device group '{group.name}' names parent '{group.parent}', which is not defined in this export; it is treated as a child of shared.")
            group.parent = "shared"
    if not pano.hierarchy_known and len(pano.groups) > 1:
        pano.warnings.append("This export does not carry the device-group hierarchy, so every device group is treated as a direct child of shared. If a device group inherits from "
                             "another one, its objects and pre/post rules from the parent are not included below; export the configuration from Panorama "
                             "(Device > Setup > Operations > Export named configuration snapshot) to keep the hierarchy.")

    for name, elem in entries(dev_entry, "template").items():
        tpl = Template(name, text(elem, "description"), elem.find("config"))
        tpl.variables = _variables(elem)
        pano.templates[name] = tpl
    for name, elem in entries(dev_entry, "template-stack").items():
        stack = Stack(name, text(elem, "description"), members(elem, "templates"), default_vsys=text(elem, "settings/default-vsys"), config=elem.find("config"))
        stack.variables = _variables(elem)
        for serial, dev in entries(elem, "devices").items():
            stack.devices[serial] = [(v.text or "").strip() for v in dev.findall("vsys/member")]
            own = _variables(dev)
            if own:
                stack.device_variables[serial] = own
        pano.stacks[name] = stack

    for serial, elem in entries(root, "mgt-config/devices").items():
        pano.devices[serial] = ManagedDevice(serial, auto_push=text(elem, "auto-push"), tags=members(elem, "tags"))
    for group in pano.groups.values():
        for serial in group.devices:
            pano.devices.setdefault(serial, ManagedDevice(serial)).device_group = group.name
    for stack in pano.stacks.values():
        for serial in stack.devices:
            pano.devices.setdefault(serial, ManagedDevice(serial)).stack = stack.name
    return pano


def rule_summary(rule: Rule) -> dict[str, Any]:
    """The fields of one rule as plain lists, the way every table and finding reads them."""
    e = rule.element
    return {
        "from": rule.f("from"), "to": rule.f("to"), "source": rule.f("source"), "destination": rule.f("destination"), "application": rule.f("application"),
        "service": rule.f("service"), "category": rule.f("category"), "source_user": rule.f("source-user"), "action": rule.action, "disabled": rule.disabled,
        "log_end": rule.log_end, "log_start": text(e, "log-start") == "yes", "log_setting": rule.log_setting, "profile_group": rule.profile_group,
        "profiles": rule.profiles, "tags": rule.tags, "description": rule.description, "negate_source": rule.negate_source, "negate_destination": rule.negate_destination,
        "rule_type": text(e, "rule-type") or "universal", "schedule": text(e, "schedule"), "hip": rule.f("source-hip") + rule.f("destination-hip"),
    }
