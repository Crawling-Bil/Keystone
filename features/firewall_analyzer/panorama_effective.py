"""What a managed firewall actually receives from Panorama: inheritance, rule order, template stacks - and a standalone PAN-OS XML of it.

Inheritance (device groups)
    Objects are looked up from the device group upwards: a device group's own ``Web-Servers`` hides the ``Web-Servers`` of its parent and of ``shared``.
    PAN-OS honours ``disable-override`` on the higher-level object; that flag is reported by the analyzer, here the lower level simply wins as it does for
    a firewall that has no override restriction in play.  Rules are not overridden, they are *ordered*: ``shared`` pre-rules, then each ancestor's pre-rules
    down to the device group's own, then the firewall's local rules, then the device group's post-rules up through the ancestors to ``shared``, and last
    the default rules.  A rule whose *target* lists other firewalls is not pushed to this one.

Template stacks
    A stack lists templates in priority order; the first template wins a conflict.  Settings made on the stack itself win over all of its templates.  The
    merge below treats a named object (an interface, a zone, a virtual router, a profile) as a unit: the object of the higher-priority template replaces the
    one of the same name, while containers (network, interface, vsys, deviceconfig) are merged and a leaf or a member list is replaced by the higher-priority value.

:func:`build_standalone` writes the result as the XML of one ordinary firewall so the single-firewall analyzer, the converters and the Topology Builder
read a Panorama-managed firewall exactly as they read a local export.  Credentials are removed from everything that is copied.

References (the pages this module follows):
https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups/manage-the-rule-hierarchy (rule hierarchy and order),
https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack (stack priority) and
https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/override-a-template-setting/override-template-setting-using-template-stack-variables (variables).
"""

from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .panorama_parse import LOCAL, OBJECT_PATHS, RULE_KINDS, Panorama, Rule, strip_secrets

_NO_COPY_RULE_CHILD = ("target",)


@dataclass
class Effective:
    group: str
    serial: str = ""
    stack: str = ""
    vsys: str = "vsys1"
    objects: dict[str, dict[str, tuple[ET.Element, str]]] = field(default_factory=dict)     # kind -> name -> (element, scope it comes from)
    hidden: list[tuple[str, str, str, str]] = field(default_factory=list)                     # (kind, name, hidden scope, winning scope)
    rules: dict[str, list[Rule]] = field(default_factory=dict)                                # kind -> rules in evaluation order
    skipped_by_target: int = 0
    notes: list[str] = field(default_factory=list)


def effective_objects(pano: Panorama, group: str) -> tuple[dict[str, dict[str, tuple[ET.Element, str]]], list[tuple[str, str, str, str]]]:
    merged: dict[str, dict[str, tuple[ET.Element, str]]] = {}
    hidden: list[tuple[str, str, str, str]] = []
    for scope in pano.chain(group):                             # shared first, the device group last: later wins
        for kind, items in scope.objects.items():
            table = merged.setdefault(kind, {})
            for name, elem in items.items():
                if name in table:
                    hidden.append((kind, name, table[name][1], scope.name))
                table[name] = (elem, scope.name)
    return merged, hidden


def effective_rules(pano: Panorama, group: str, serial: str = "", serials: list[str] | None = None) -> tuple[dict[str, list[Rule]], int]:
    """Rules in the order the firewall evaluates them, per kind; ``serial`` drops the rules targeted at other firewalls (``""`` keeps every rule).

    ``serials`` is for a firewall whose own serial is not known (its export has none) but whose template stack is: a rule is kept when it is pushed to
    *any* firewall of that stack, so an HA pair is exact and a larger stack is never short of a rule."""
    chain = pano.chain(group)
    out: dict[str, list[Rule]] = {}
    skipped = 0
    candidates = [serial] if serial else list(serials or [])

    def pushed(rule: Rule) -> bool:
        if not candidates:
            return True
        return any(rule.target.applies(s, pano.devices[s].tags if s in pano.devices else []) for s in candidates)

    def take(rules: list[Rule], kind: str) -> None:
        nonlocal skipped
        for rule in rules:
            if not pushed(rule):
                skipped += 1
                continue
            out.setdefault(kind, []).append(rule)

    for kind in RULE_KINDS:
        if kind == "default-security-rules":
            continue
        for scope in chain:                                     # pre: outermost first
            take(scope.rules.get(("pre", kind), []), kind)
        for scope in reversed(chain):                           # post: innermost first
            take(scope.rules.get(("post", kind), []), kind)
    for scope in reversed(chain):                               # default-security-rules override: the innermost definition wins
        rules = scope.rules.get(("default", "default-security-rules"), [])
        if rules:
            take(rules, "default-security-rules")
            break
    return out, skipped


def stack_of(pano: Panorama, group: str, serial: str = "") -> str:
    """The template stack of a firewall; for a device group alone, the stack shared by most of its firewalls."""
    if serial and serial in pano.devices:
        return pano.devices[serial].stack
    counts: dict[str, int] = {}
    for dev_serial in pano.groups[group].devices if group in pano.groups else {}:
        device = pano.devices.get(dev_serial)
        if device and device.stack:
            counts[device.stack] = counts.get(device.stack, 0) + 1
    return max(counts, key=lambda s: counts[s]) if counts else ""


_MERGED_ENTRY_PARENTS = frozenset({"devices", "vsys"})          # these hold structural entries (the device, a virtual system): merged, not replaced


def _overlay(dst: ET.Element, src: ET.Element) -> None:
    """Merge ``src`` (the higher priority) into ``dst``.

    Containers are merged by name, leaves and member lists are replaced, and a named *object* (an interface, a zone, a virtual router, a profile) of the
    higher-priority template replaces the whole object of the same name: Panorama overrides an object as a unit, so the address list of ``ethernet1/2``
    in the first template does not add to the one in the second."""
    for child in src:
        if child.tag == "entry" and child.get("name") is not None:
            match = next((d for d in dst if d.tag == "entry" and d.get("name") == child.get("name")), None)
            if match is None:
                dst.append(copy.deepcopy(child))
            elif src.tag in _MERGED_ENTRY_PARENTS:
                _overlay(match, child)
            else:
                dst.remove(match)
                dst.append(copy.deepcopy(child))
            continue
        match = next((d for d in dst if d.tag == child.tag), None)
        has_entries = any(c.tag == "entry" for c in child)
        if match is None:
            dst.append(copy.deepcopy(child))
        elif len(child) and not any(c.tag == "member" for c in child) and (has_entries or len(match)):
            _overlay(match, child)
        else:
            dst.remove(match)
            dst.append(copy.deepcopy(child))


_LOCAL_LISTS = frozenset({"ip", "ipv6"})          # a local address list replaces the pushed one instead of adding to it


def overlay_local(dst: ET.Element, src: ET.Element) -> None:
    """Merge a firewall's *local* configuration (``src``) over what Panorama pushed (``dst``).

    Unlike :func:`_overlay` the entries are merged field by field: a local interface entry that only says ``aggregate-group`` keeps the addresses the template
    gave it.  Leaves and member lists of the local side win, and so does a local address list.  The pushed elements the export marks with ``ptpl`` stay marked."""
    for child in src:
        if child.tag == "entry" and child.get("name") is not None:
            match = next((d for d in dst if d.tag == "entry" and d.get("name") == child.get("name")), None)
            if match is None:
                dst.append(copy.deepcopy(child))
            else:
                match.attrib.update(child.attrib)
                overlay_local(match, child)
            continue
        match = next((d for d in dst if d.tag == child.tag), None)
        if match is None:
            dst.append(copy.deepcopy(child))
        elif not len(child) and not (child.text or "").strip() and len(match):
            continue                                          # an empty local container ("<zone/>") says nothing local: what Panorama pushed stays
        elif child.tag in _LOCAL_LISTS or any(c.tag == "member" for c in child) or not len(child):
            dst.remove(match)
            dst.append(copy.deepcopy(child))
        else:
            match.attrib.update(child.attrib)
            overlay_local(match, child)


def merge_device(pano: Panorama, stack_name: str, device_root: ET.Element, notes: list[str] | None = None) -> str | None:
    """The XML of one firewall as it really runs: the merged template stack with the firewall's own export on top, address names resolved from Shared.

    ``None`` when the stack is unknown.  Credentials of both sides are removed."""
    base = merged_template(pano, stack_name, notes)
    if base is None:
        return None
    local = device_root.find("devices/entry") if device_root.tag == "config" else device_root
    if local is not None:
        overlay_local(base, copy.deepcopy(local))
    resolve_address_names(base, _shared_addresses(pano), None)
    strip_secrets(base)
    config = ET.Element("config", {"version": pano.version or "11.2.0", "urldb": "paloalto"})
    devices = ET.SubElement(config, "devices")
    devices.append(base)
    for tag in ("mgt-config",):
        extra = device_root.find(tag)
        if extra is not None:
            node = copy.deepcopy(extra)
            strip_secrets(node)
            config.append(node)
    ET.indent(config)
    return '<?xml version="1.0"?>\n' + ET.tostring(config, encoding="unicode")


def _substitute(root: ET.Element, variables: dict[str, str]) -> int:
    """Replace ``$variable`` in entry names and text with its value; returns how many variables had no value (left as they are)."""
    unresolved = 0
    for node in root.iter():
        name = node.get("name")
        if name and name.startswith("$"):
            if variables.get(name):
                node.set("name", variables[name])
            else:
                unresolved += 1
        value = (node.text or "").strip()
        if value.startswith("$") and not len(node):
            if variables.get(value):
                node.text = variables[value]
            else:
                unresolved += 1
    return unresolved


_LITERAL = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]+)(/\d{1,3})?$")


def _shared_addresses(pano: Panorama) -> dict[str, str]:
    """``name -> ip-netmask`` of the objects in ``shared``: a template can only name objects of the Shared location, and its interface addresses often do."""
    out: dict[str, str] = {}
    for name, elem in pano.shared.objects.get("address", {}).items():
        value = (elem.findtext("ip-netmask") or "").strip()
        if value:
            out[name] = value
    return out


def resolve_address_names(root: ET.Element, addresses: dict[str, str], notes: list[str] | None = None, label: str = "") -> tuple[int, list[str]]:
    """Replace an address-object name used where PAN-OS wants an address (interface IP, static route destination or next hop, IKE peer / local address) by its value.

    An interface ``ip`` entry may name an address object (https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/configure-interfaces/layer-3-interfaces/configure-layer-3-interfaces);
    a template can use the objects of the Shared location.  Returns how many were replaced and the names that could not be (not in ``shared``, or not an IP netmask).
    The object's name stays on the element as ``src-object`` so a reader can still show it."""
    done = 0
    missing: list[str] = []

    def value_of(name: str, host: bool) -> str:
        value = addresses.get(name, "")
        if value and host and value.endswith("/32"):
            value = value[:-3]
        return value

    for entry in root.findall(".//network/interface//ip/entry"):
        name = entry.get("name", "")
        if not name or _LITERAL.match(name):
            continue
        value = value_of(name, False)
        if value:
            entry.set("src-object", name)
            entry.set("name", value)
            done += 1
        else:
            missing.append(name)
    for tag, host in (("destination", False), ("ip-address", True)):
        for node in root.findall(f".//routing-table//static-route/entry/{tag}") + root.findall(f".//routing-table//static-route/entry/nexthop/{tag}"):
            text = (node.text or "").strip()
            if not text or _LITERAL.match(text):
                continue
            value = value_of(text, host)
            if value:
                node.text = value
                done += 1
            else:
                missing.append(text)
    for tag in ("local-address/ip", "peer-address/ip"):
        for node in root.findall(f".//ike/gateway/entry/{tag}"):
            text = (node.text or "").strip()
            if not text or _LITERAL.match(text):
                continue
            value = value_of(text, True)
            if value:
                node.text = value
                done += 1
            else:
                missing.append(text)
    missing = list(dict.fromkeys(missing))
    if notes is not None:
        if done:
            notes.append(f"{done} address-object name(s) in {label or 'the template'} (interface addresses, routes, IKE peers) were replaced by the value of the Shared object of that name.")
        if missing:
            notes.append(f"{len(missing)} address name(s) in {label or 'the template'} are not objects of the Shared location, so their address is unknown: {', '.join(missing[:6])}{' ...' if len(missing) > 6 else ''}.")
    return done, missing


def merged_template(pano: Panorama, stack_name: str, notes: list[str] | None = None, serial: str = "") -> ET.Element | None:
    """The ``<entry name="localhost.localdomain">`` of the stack: its templates from the lowest priority up, then the stack's own settings."""
    stack = pano.stacks.get(stack_name)
    if stack is None:
        return None
    result = ET.Element("entry", {"name": LOCAL})
    for name in reversed(stack.templates):                     # members[0] is the highest priority, so it is applied last
        tpl = pano.templates.get(name)
        if tpl is None:
            if notes is not None:
                notes.append(f"Template stack '{stack_name}' lists template '{name}', which is not defined in this export.")
            continue
        entry = tpl.device_entry()
        if entry is not None:
            _overlay(result, entry)
    if stack.config is not None:
        own = stack.config.find("devices/entry")
        if own is not None:
            _overlay(result, own)
    variables: dict[str, str] = {}
    for name in reversed(stack.templates):                      # the same priority as the settings: the first template wins
        if name in pano.templates:
            variables.update({k: v for k, v in pano.templates[name].variables.items() if v})
    variables.update({k: v for k, v in stack.variables.items() if v})
    if serial:
        variables.update({k: v for k, v in stack.device_variables.get(serial, {}).items() if v})
    unresolved = _substitute(result, variables)
    resolve_address_names(result, _shared_addresses(pano), notes, f"template stack '{stack_name}'")
    if unresolved and notes is not None:
        notes.append(f"{unresolved} template variable reference(s) in stack '{stack_name}' have no value in the export and were left as $variable.")
    strip_secrets(result)
    return result


def effective(pano: Panorama, group: str, serial: str = "", stack: str = "", serials: list[str] | None = None) -> Effective:
    if group and group not in pano.groups:
        raise KeyError(group)
    eff = Effective(group=group, serial=serial, stack=stack or (stack_of(pano, group, serial) if group else ""))
    if group:
        eff.objects, eff.hidden = effective_objects(pano, group)
        eff.rules, eff.skipped_by_target = effective_rules(pano, group, serial, serials)
    stack = pano.stacks.get(eff.stack)
    dev_vsys = pano.groups[group].devices.get(serial, []) if serial and group else []
    eff.vsys = (dev_vsys[0] if dev_vsys else "") or (stack.default_vsys if stack else "") or "vsys1"
    return eff


def _append_rules(parent: ET.Element, rules: list[Rule]) -> None:
    for rule in rules:
        node = copy.deepcopy(rule.element)
        for tag in _NO_COPY_RULE_CHILD:
            for child in node.findall(tag):
                node.remove(child)
        node.set("loc", rule.location)
        parent.append(node)


def build_standalone(pano: Panorama, group: str, serial: str = "", *, stack: str = "", local: ET.Element | None = None,
                     serials: list[str] | None = None) -> tuple[str, Effective]:
    """The device group (and, with ``serial``, one firewall of it) as the XML of a standalone PAN-OS firewall, plus what was resolved to get there.

    ``stack`` names the template stack when it is known from elsewhere; ``local`` is the firewall's own export (``<config>`` or its device ``<entry>``), laid over
    the stack the way the firewall runs it (see :func:`overlay_local`); ``serials`` are the managed firewalls of the stack when this one's serial is not known.
    An empty ``group`` gives the stack and the local export without policy."""
    eff = effective(pano, group, serial, stack, serials)
    config = ET.Element("config", {"version": pano.version or "11.2.0", "urldb": "paloaltonetworks"})
    devices = ET.SubElement(config, "devices")
    entry = ET.SubElement(devices, "entry", {"name": LOCAL})
    tpl = merged_template(pano, eff.stack, eff.notes, serial) if eff.stack else None
    if tpl is not None and local is not None:
        local_entry = local.find("devices/entry") if local.tag == "config" else local
        if local_entry is not None:
            overlay_local(tpl, copy.deepcopy(local_entry))
            resolve_address_names(tpl, _shared_addresses(pano), None)      # the firewall's own VLAN interfaces name Shared objects too
            strip_secrets(tpl)
    elif tpl is None and local is not None:
        local_entry = local.find("devices/entry") if local.tag == "config" else local
        tpl = copy.deepcopy(local_entry) if local_entry is not None else None
        if tpl is not None:
            strip_secrets(tpl)
    tpl_vsys = None
    if tpl is not None:
        for child in tpl:
            if child.tag == "vsys":
                tpl_vsys = child
                continue
            entry.append(child)
    elif group:
        eff.notes.append(f"Device group '{group}' has no template stack with a firewall of it, so no interfaces, zones, routing or device settings were added.")
    vsys_root = ET.SubElement(entry, "vsys")
    vsys = ET.SubElement(vsys_root, "entry", {"name": eff.vsys})
    if tpl_vsys is not None:
        for v in tpl_vsys.findall("entry"):
            if v.get("name") == eff.vsys:
                for child in v:
                    vsys.append(child)                           # zone, user-id settings ...
            else:                                                 # another virtual system of the template: kept as one of its own (zones and settings only)
                vsys_root.append(v)
    paths = dict(OBJECT_PATHS)
    for kind, items in eff.objects.items():
        node = vsys
        parts = paths[kind].split("/")
        for part in parts:
            existing = node.find(part)
            node = existing if existing is not None else ET.SubElement(node, part)
        for name, (elem, scope_name) in items.items():
            copied = copy.deepcopy(elem)
            strip_secrets(copied)
            node.append(copied)
    base = vsys.find("rulebase")
    base = base if base is not None else ET.SubElement(vsys, "rulebase")
    for kind in RULE_KINDS:
        rules = eff.rules.get(kind)
        if not rules:
            continue
        holder = base.find(kind)
        holder = holder if holder is not None else ET.SubElement(base, kind)
        container = holder.find("rules")
        if container is None:
            _append_rules(ET.SubElement(holder, "rules"), rules)
        else:                                                   # the firewall has local rules of this kind: pre-rules, local rules, post-rules
            local_rules = list(container)
            for node in local_rules:
                container.remove(node)
            _append_rules(container, [r for r in rules if r.position == "pre"])
            for node in local_rules:
                container.append(node)
            _append_rules(container, [r for r in rules if r.position != "pre"])
    system = entry.find("deviceconfig/system")
    if system is None:
        dc = entry.find("deviceconfig")
        dc = dc if dc is not None else ET.SubElement(entry, "deviceconfig")
        system = ET.SubElement(dc, "system")
    if system.find("hostname") is None:
        ET.SubElement(system, "hostname").text = f"{group or eff.stack}"
    if local is not None and local.tag == "config":             # administrators, password rules, log / server / authentication profiles of the firewall itself
        for tag in ("mgt-config", "shared"):
            node = local.find(tag)
            if node is not None:
                copied = copy.deepcopy(node)
                strip_secrets(copied)
                config.append(copied)
    ET.indent(config)
    return '<?xml version="1.0"?>\n' + ET.tostring(config, encoding="unicode"), eff
