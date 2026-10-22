"""Guided firewall conversion: Mikrotik RouterOS -> Palo Alto PAN-OS.

The wizard does not convert anything itself. It keeps a ``state`` (target
model, deployment, interface/zone/VPN choices, acknowledged warnings),
turns it into the mapping PaloAltoFirewallTranslator already accepts,
runs the translator, and checks the result twice:

* source side (this module): every used source port has a target port,
  no two source ports share one, the roles (INET / LAN / ...) are shown so
  a swap such as LAN on port 1 -> port 2 is visible;
* target side (pan_validator): every reference in the generated PAN-OS
  lines resolves, plus the commit blockers visible without a firewall.

Each issue belongs to one step. Step N opens only when steps 1..N-1 have
no errors and their warnings are acknowledged, so a wrong port or zone is
fixed where it is made instead of surfacing three steps later as a broken
NAT or policy reference. Download is allowed only when every step passes.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any, Optional

from ..translators.firewall.paloalto import (
    PALOALTO_TARGET_MODELS,
    resolve_target_ethernet_port_count,
)
from . import pan_validator
from .pan_validator import ERROR, INFO, WARNING, Issue

STEPS = [
    {"key": "target", "label": "Target", "summary": "Model, standalone or Panorama."},
    {"key": "interfaces", "label": "Interfaces", "summary": "Source port, role and target port."},
    {"key": "zones", "label": "Zones", "summary": "Which zone each interface belongs to."},
    {"key": "routing", "label": "Routing", "summary": "Virtual router and static routes."},
    {"key": "objects", "label": "Objects", "summary": "Addresses, groups and services."},
    {"key": "nat", "label": "NAT", "summary": "Source and destination NAT rules."},
    {"key": "policy", "label": "Security policy", "summary": "Zones, objects and rule order."},
    {"key": "vpn", "label": "VPN", "summary": "IKE gateways, crypto profiles and tunnels."},
    {"key": "services", "label": "Services", "summary": "DHCP, DNS, management."},
    {"key": "review", "label": "Review & export", "summary": "Full output and download."},
]
STEP_KEYS = [step["key"] for step in STEPS]

ROLE_LABELS = {"inet": "INET", "lan": "LAN", "dmz": "DMZ", "mgmt": "MGMT", "transit": "Transit", "": "-"}
_TUNNEL_TYPES = {"eoip", "gre", "ipip", "l2tp-client", "pptp-client", "sstp-client", "ovpn-client",
                 "pppoe-client", "wireguard", "vrrp", "bonding"}
_PAN_PORT_RE = re.compile(r"^(?:ethernet\d+/\d+|ae\d+)$")
_PANORAMA_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_PREFIX_RE = re.compile(r"^set (?:template \S+ config devices localhost\.localdomain |device-group \S+ )?(.*)$")


# ------------------------------------------------------------------ source facts

def _is_private(address: str) -> Optional[bool]:
    try:
        return ipaddress.ip_interface(address).ip.is_private
    except ValueError:
        return None


def describe_source(config) -> dict:
    """Facts about each source interface the steps need: addresses, bridge
    membership, whether anything uses it, and a best-guess role."""
    bridges = {}
    for interface in config.interfaces:
        if interface.interface_type == "bridge":
            for port in interface.bridge_ports:
                bridges[port] = interface.name

    dhcp_clients = {b.interface for b in config.dhcp_client_bindings if not b.disabled}
    dhcp_servers = {b.interface for b in config.dhcp_servers if not getattr(b, "disabled", False)}
    masquerade_out = {r.out_interface for r in config.nat_rules
                      if not r.disabled and r.chain == "srcnat" and r.action in ("masquerade", "src-nat") and r.out_interface}
    referenced = set()
    for rule in list(config.nat_rules) + list(config.filter_rules):
        referenced.update(x for x in (rule.in_interface, rule.out_interface) if x)
    for clamp in config.mss_clamps:
        referenced.update(x for x in (clamp.in_interface, clamp.out_interface) if x)
    vlan_parents = {i.parent_interface for i in config.interfaces if i.interface_type == "vlan" and i.parent_interface}
    list_members = {m.interface for m in config.interface_list_members}

    default_gateways = []
    for route in config.static_routes:
        if route.disabled or route.dst_address not in ("0.0.0.0/0", ""):
            continue
        if getattr(route, "routing_mark", ""):
            continue
        try:
            default_gateways.append(ipaddress.ip_address(route.gateway.split("%")[0]))
        except ValueError:
            continue

    facts = {}
    for interface in config.interfaces:
        if interface.interface_type in _TUNNEL_TYPES:
            continue
        name = interface.name
        ips = list(interface.ip_addresses)
        bridge = bridges.get(name, "")
        role, reasons = "", []
        if name in dhcp_clients:
            role, reasons = "inet", reasons + ["DHCP client"]
        if name in masquerade_out:
            role, reasons = "inet", reasons + ["masquerade egress"]
        for address in ips:
            try:
                network = ipaddress.ip_interface(address).network
            except ValueError:
                continue
            if any(gw in network for gw in default_gateways):
                role, reasons = "inet", reasons + ["default route next hop"]
            elif not role and _is_private(address) is False:
                role, reasons = "inet", reasons + ["public address"]
        text = f"{name} {interface.comment}".lower()
        if not role and re.search(r"\b(wan|isp|inet|internet|uplink)\b", text):
            role, reasons = "inet", ["name/comment"]
        if not role:
            if "mgmt" in text or "manage" in text:
                role, reasons = "mgmt", ["name/comment"]
            elif "dmz" in text:
                role, reasons = "dmz", ["name/comment"]
            elif name in dhcp_servers or (bridge and bridge in dhcp_servers):
                role, reasons = "lan", ["DHCP server"]
            elif bridge:
                role, reasons = "lan", [f"member of {bridge}"]
            elif any(_is_private(a) for a in ips):
                role, reasons = "lan", ["private address"]
        used = bool(ips or bridge or name in referenced or name in dhcp_clients or name in dhcp_servers
                    or name in vlan_parents or name in list_members)
        facts[name] = {
            "name": name,
            "default_name": interface.default_name or "",
            "type": interface.interface_type or "",
            "comment": interface.comment or "",
            "addresses": ips,
            "dhcp_client": name in dhcp_clients,
            "bridge": bridge,
            "bridge_ports": list(interface.bridge_ports) if interface.interface_type == "bridge" else [],
            "disabled": bool(interface.disabled),
            "used": used and not interface.disabled,
            "role": role,
            "role_label": ROLE_LABELS.get(role, role.upper()),
            "role_reason": ", ".join(dict.fromkeys(reasons)),
            "physical": interface.interface_type not in ("bridge", "vlan"),
            "vlan_id": interface.vlan_id,
            "parent": interface.parent_interface or "",
            "parent_is_bridge": (interface.parent_interface or "") in {i.name for i in config.interfaces if i.interface_type == "bridge"},
        }
    return facts


# ------------------------------------------------------------------ state

def initial_state(config, translator, target_model: Optional[str] = None) -> dict:
    preview = translator.build_interface_mapping_preview(config)
    facts = describe_source(config)
    interfaces = {}
    for row in preview["interfaces"]:
        fact = facts.get(row["name"], {})
        kind = fact.get("type", "")
        if kind == "vlan":
            mode = "vlan" if fact.get("parent_is_bridge") else "subinterface"
            tag = fact.get("vlan_id") or ""
            unit = tag
        elif kind == "bridge":
            mode, tag, unit = "vlan", "", ""
        else:
            mode, tag, unit = "", "", ""
        interfaces[row["name"]] = {
            # An enabled port with nothing on it starts unmapped: converting it
            # would only add an empty layer3 interface and a zone.
            "pan_interface": (row.get("suggested_pan_interface") or "") if fact.get("used") or fact.get("bridge") else "",
            # A bridge member is a layer2 port: its zone is the bridge's.
            "zone": "" if fact.get("bridge") else (row.get("suggested_zone") or ""),
            "sdwan_link_type": "none",
            "role": fact.get("role", ""),
            # VLAN / bridge shape on PAN-OS (see _translate_vlan_interface /
            # _translate_bridge): mode, parent port for a sub-interface, tag, vlan.N unit.
            "mode": mode,
            "parent_port": "",
            "tag": tag,
            "unit": unit,
        }
    tunnels = {
        t["tunnel_name"]: {"zone": t.get("suggested_zone") or "", "tunnel_unit": t.get("suggested_unit") or 1}
        for t in preview["ipsec_tunnels"]
    }
    gateways = {}
    for peer in config.ipsec_peers:
        if not peer.disabled:
            gateways[translator.pan_name(peer.name)] = {"local_interface": ""}
    return {
        "target_model": target_model or "",
        "deployment": {
            "panorama": False,
            "template_name": preview.get("suggested_template_name", ""),
            "device_group_name": preview.get("suggested_device_group_name", ""),
        },
        "interfaces": interfaces,
        "ipsec_tunnels": tunnels,
        "ipsec_gateways": gateways,
        "sdwan": {"enabled": False, "zone": preview.get("suggested_sdwan_zone", "SDWAN")},
        "acknowledged": [],
    }


def merge_state(base: dict, incoming: Optional[dict]) -> dict:
    """Overlay a client-sent state on the stored one, keeping only known keys."""
    state = copy.deepcopy(base)
    if not isinstance(incoming, dict):
        return state
    if "target_model" in incoming:
        state["target_model"] = str(incoming.get("target_model") or "")
    for key in ("deployment", "sdwan"):
        if isinstance(incoming.get(key), dict):
            state[key].update({k: v for k, v in incoming[key].items() if k in state[key]})
    for key in ("interfaces", "ipsec_tunnels", "ipsec_gateways"):
        if isinstance(incoming.get(key), dict):
            for name, values in incoming[key].items():
                if name in state[key] and isinstance(values, dict):
                    state[key][name].update({k: v for k, v in values.items() if k in state[key][name]})
    if isinstance(incoming.get("acknowledged"), list):
        state["acknowledged"] = [str(x) for x in incoming["acknowledged"]][:2000]
    return state


def to_mapping(state: dict, translator, facts: Optional[dict] = None) -> dict:
    facts = facts or {}
    interfaces = {}
    for name, row in state["interfaces"].items():
        entry = {"sdwan_link_type": row.get("sdwan_link_type") or "none"}
        if str(row.get("pan_interface") or "").strip():
            entry["pan_interface"] = str(row["pan_interface"]).strip()
        for key in ("mode", "parent_port", "tag", "unit"):
            if str(row.get(key) or "").strip():
                entry[key] = str(row[key]).strip()
        fact = facts.get(name) or {}
        if fact.get("physical") and not entry.get("pan_interface"):
            interfaces[name] = {"skip": True}
            continue
        if fact.get("bridge"):
            interfaces[name] = entry  # zone follows the bridge (assign_zones)
            continue
        if str(row.get("zone") or "").strip():
            entry["zone"] = translator.pan_name(row["zone"])
        interfaces[name] = entry
    tunnels = {}
    for name, row in state["ipsec_tunnels"].items():
        zone = str(row.get("zone") or "").strip()
        if zone:
            text = str(row.get("tunnel_unit") or "").strip()
            unit = int(text) if text.isdigit() and 1 <= int(text) <= 9999 else 0
            if not unit:
                continue  # MAP-TUNNEL-UNIT blocks the VPN step; write no tunnel interface
            tunnels[name] = {"zone": zone, "tunnel_unit": unit}
    deployment = state["deployment"]
    return {
        "interfaces": interfaces,
        "ipsec_tunnels": tunnels,
        "ipsec_gateways": {
            name: {"local_interface": row.get("local_interface", "")} for name, row in state["ipsec_gateways"].items()
        },
        "sdwan": {"enabled": bool(state["sdwan"].get("enabled")), "zone": state["sdwan"].get("zone") or "SDWAN"},
        "panorama": {
            "enabled": bool(deployment.get("panorama")),
            "template_name": deployment.get("template_name") or "",
            "device_group_name": deployment.get("device_group_name") or "",
        },
    }


# ------------------------------------------------------------------ checks

def _source_issues(state: dict, facts: dict, port_count: Optional[int]) -> list:
    issues = []
    add = issues.append
    model = state.get("target_model") or ""

    if not model:
        add(Issue("TGT-NO-MODEL", WARNING, "target", "No target model selected, so ports cannot be checked against real hardware.",
                  "Pick the model you are deploying to.", ref="model"))
    elif port_count is None:
        add(Issue("TGT-UNKNOWN-MODEL", WARNING, "target", f"'{model}' is not in the hardware table; ports are not checked.",
                  "Pick a listed model or add it to PALOALTO_TARGET_MODELS.", ref="model"))
    deployment = state["deployment"]
    if deployment.get("panorama"):
        for key, label in (("template_name", "Template"), ("device_group_name", "Device group")):
            value = str(deployment.get(key) or "")
            if not _PANORAMA_NAME_RE.match(value):
                add(Issue("TGT-PANORAMA-NAME", ERROR, "target", f"{label} name '{value}' is not valid.",
                          "Use 1-63 letters, digits, '.', '_' or '-', starting with a letter or digit.", ref=key))

    owners: dict = {}
    for name, row in state["interfaces"].items():
        fact = facts.get(name, {})
        if not fact.get("physical", True):
            continue
        target = str(row.get("pan_interface") or "").strip()
        if not target:
            if fact.get("used") or fact.get("bridge"):
                add(Issue("MAP-UNMAPPED", ERROR, "interfaces",
                          f"{name} is in use ({fact.get('role_label', '-')}) but has no target port.",
                          "Pick the target port for it.", ref=name))
            continue
        if not _PAN_PORT_RE.match(target):
            add(Issue("MAP-NAME", ERROR, "interfaces", f"{name} -> '{target}' is not a PAN-OS port name.",
                      "Use ethernet<slot>/<port> (for example ethernet1/3) or aeN.", ref=name))
            continue
        owners.setdefault(target, []).append(name)
        slot_port = re.match(r"^ethernet(\d+)/(\d+)$", target)
        if port_count and slot_port and (slot_port.group(1) != "1" or int(slot_port.group(2)) > port_count):
            add(Issue("MAP-PORT-MISSING", ERROR, "interfaces",
                      f"{name} -> {target}, but {model} has only ethernet1/1 to ethernet1/{port_count}.",
                      "Pick a port that exists on the target.", ref=name))
    for target, names in owners.items():
        if len(names) > 1:
            add(Issue("MAP-DUP", ERROR, "interfaces", f"{', '.join(names)} are all mapped to {target}.",
                      "One source interface per target port; move the others.", ref=target))

    issues += _logical_issues(state, facts, owners)
    issues += _tunnel_issues(state)

    swaps = []
    for name, row in state["interfaces"].items():
        fact = facts.get(name, {})
        target = str(row.get("pan_interface") or "")
        default = fact.get("default_name") or name
        source_number = re.search(r"(\d+)$", default)
        target_number = re.search(r"/(\d+)$", target)
        if source_number and target_number and source_number.group(1) != target_number.group(1):
            swaps.append(f"{name} ({fact.get('role_label', '-')}) -> {target}")
    if swaps:
        add(Issue("MAP-RENUMBER", INFO, "interfaces", "Ports that change number: " + "; ".join(swaps) + ".",
                  "Recable these ports at cutover; every reference in the output already follows the new port.",
                  ref="renumber"))
    return issues


def _tunnel_issues(state: dict) -> list:
    """Each tunnel with a zone needs its own tunnel.N unit, 1-9999."""
    issues = []
    units: dict = {}
    for name, row in state["ipsec_tunnels"].items():
        if not str(row.get("zone") or "").strip():
            continue
        text = str(row.get("tunnel_unit") or "").strip()
        if not text.isdigit() or not 1 <= int(text) <= 9999:
            issues.append(Issue("MAP-TUNNEL-UNIT", ERROR, "vpn", f"Tunnel {name}: unit '{text}' is not 1-9999.",
                                "Use a whole number for tunnel.N.", ref=name))
            continue
        units.setdefault(int(text), []).append(name)
    for unit, names in units.items():
        if len(names) > 1:
            issues.append(Issue("MAP-TUNNEL-DUP", ERROR, "vpn", f"{', '.join(names)} all use tunnel.{unit}.",
                                "Give each tunnel its own unit.", ref=f"tunnel.{unit}"))
    return issues


def _logical_issues(state: dict, facts: dict, owners: dict) -> list:
    """VLAN and bridge choices: tag range, parent port, duplicate units and sub-interfaces."""
    issues = []
    add = issues.append
    mapped_ports = set(owners)
    units: dict = {}
    subifs: dict = {}
    for name, row in state["interfaces"].items():
        fact = facts.get(name, {})
        kind = fact.get("type")
        if kind not in ("vlan", "bridge"):
            continue
        mode = str(row.get("mode") or "")
        if kind == "bridge":
            ports = fact.get("bridge_ports") or []
            if mode == "routed" and len(ports) != 1:
                add(Issue("MAP-BRIDGE-ROUTED", ERROR, "interfaces",
                          f"Bridge {name} has {len(ports)} member ports; only a one-port bridge can be routed on the port.",
                          "Keep it as a VLAN interface (vlan.N).", ref=name))
            unit = str(row.get("unit") or "").strip()
            if mode != "routed" and unit:
                units.setdefault(unit, []).append(name)
            continue

        tag_text = str(row.get("tag") or "").strip()
        try:
            tag = int(tag_text)
        except ValueError:
            tag = 0
        if not 1 <= tag <= 4094:
            add(Issue("MAP-VLAN-TAG", ERROR, "interfaces", f"VLAN {name}: tag '{tag_text}' is not 1-4094.",
                      "Use the 802.1Q tag the switch side uses.", ref=name))
            continue
        if mode == "vlan":
            if not fact.get("parent_is_bridge"):
                add(Issue("MAP-VLAN-MODE", ERROR, "interfaces",
                          f"VLAN {name} sits on port {fact.get('parent')}, not on a bridge, so it cannot be a VLAN interface.",
                          "Use 'sub-interface'.", ref=name))
                continue
            unit = str(row.get("unit") or tag).strip()
            units.setdefault(unit, []).append(name)
        else:
            parent = str(row.get("parent_port") or "").strip()
            if not parent:
                if fact.get("parent_is_bridge"):
                    bridge = facts.get(fact.get("parent"), {})
                    ports = bridge.get("bridge_ports") or []
                    if len(ports) == 1:
                        parent = str((state["interfaces"].get(ports[0]) or {}).get("pan_interface") or "")
                    else:
                        add(Issue("MAP-VLAN-PARENT", ERROR, "interfaces",
                                  f"VLAN {name} is a sub-interface on bridge {fact.get('parent')}, which has "
                                  f"{len(ports)} ports; pick the trunk port.", "Choose the parent port.", ref=name))
                        continue
                else:
                    parent = str((state["interfaces"].get(fact.get("parent")) or {}).get("pan_interface") or "")
            if parent and parent not in mapped_ports:
                add(Issue("MAP-VLAN-PARENT", ERROR, "interfaces",
                          f"VLAN {name}: parent port {parent} is not mapped from any source port.",
                          "Pick a port that is in use on the target.", ref=name))
            if parent:
                subifs.setdefault(f"{parent}.{tag}", []).append(name)
    for unit, names in units.items():
        if len(names) > 1:
            add(Issue("MAP-VLAN-UNIT", ERROR, "interfaces", f"{', '.join(names)} all use vlan.{unit}.",
                      "Give each VLAN interface its own unit number.", ref=f"vlan.{unit}"))
    for subif, names in subifs.items():
        if len(names) > 1:
            add(Issue("MAP-VLAN-DUP", ERROR, "interfaces", f"{', '.join(names)} all become {subif}.",
                      "Two VLANs cannot share a tag on one port.", ref=subif))
    return issues


def _step_of_output_line(line: str) -> Optional[str]:
    text = line.strip()
    if not text.startswith("set "):
        return None
    match = _PREFIX_RE.match(text)
    rest = match.group(1) if match else text[4:]
    if rest.startswith("network interface tunnel") or rest.startswith(("network ike", "network tunnel")):
        return "vpn"
    if rest.startswith(("network interface", "network vlan")):
        if " dhcp-client" in rest:
            return "services"
        if "adjust-tcp-mss" in rest or "interface-management-profile" in rest:
            return "services"
        return "interfaces"
    if rest.startswith("zone "):
        return "zones"
    if rest.startswith("network virtual-router"):
        return "routing"
    if rest.startswith(("address", "service", "tag ")):
        return "objects"
    if rest.startswith(("rulebase nat", "pre-rulebase nat", "post-rulebase nat")):
        return "nat"
    if rest.startswith(("rulebase security", "pre-rulebase security", "post-rulebase security", "rulebase pbf", "pre-rulebase pbf")):
        return "policy"
    return "services"


_REVIEW_STEP_HINTS = [
    ("vpn", ("ike-gateway", "ipsec", "ike ", "l2tp", "pptp", "eoip", "gre tunnel", "globalprotect", "ppp ")),
    ("nat", ("nat rule",)),
    ("policy", ("filter rule", "security rule", "stateful helper")),
    ("routing", ("static route", "route rule", "policy-routing", "policy based forwarding", "mark-routing", "ospf", "bgp", "netwatch")),
    ("objects", ("address-list", "address list")),
    ("interfaces", ("interface ", "bridge ", "vlan", "speed/duplex", "bonding")),
]


def _step_of_review(text: str) -> str:
    lowered = text.lower()
    for step, hints in _REVIEW_STEP_HINTS:
        if any(h in lowered for h in hints):
            return step
    return "services"


# ------------------------------------------------------------------ evaluate

def evaluate(config, translator, state: dict) -> dict:
    facts = describe_source(config)
    port_count = resolve_target_ethernet_port_count(state.get("target_model") or None)
    mapping = to_mapping(state, translator, facts)
    output_lines = [str(line) for line in translator.translate(copy.deepcopy(config), mapping=mapping,
                                                             target_model=state.get("target_model") or None)]

    issues = _source_issues(state, facts, port_count)
    target_issues = pan_validator.validate(output_lines, port_count)
    # The source-side MAP-PORT-MISSING names the source interface; drop the
    # duplicate target-side one for the same port.
    mapped_missing = {str(state["interfaces"][i.ref].get("pan_interface")) for i in issues
                      if i.code == "MAP-PORT-MISSING" and i.ref in state["interfaces"]}
    issues += [i for i in target_issues if not (i.code == "IF-PORT-MISSING" and i.ref in mapped_missing)]

    acknowledged = set(state.get("acknowledged") or [])
    by_step = {key: [] for key in STEP_KEYS}
    for issue in issues:
        by_step.setdefault(issue.step, []).append(issue)

    lines_by_step = {key: [] for key in STEP_KEYS}
    notes_by_step = {key: [] for key in STEP_KEYS}
    for number, line in enumerate(output_lines, start=1):
        step = _step_of_output_line(line)
        if step:
            lines_by_step[step].append({"n": number, "text": line})
        elif line.startswith("# REVIEW: "):
            notes_by_step[_step_of_review(line)].append(line[len("# REVIEW: "):])

    steps = []
    open_so_far = True
    all_clear = True
    for spec in STEPS:
        key = spec["key"]
        step_issues = by_step.get(key, [])
        errors = [i for i in step_issues if i.severity == ERROR]
        warnings = [i for i in step_issues if i.severity == WARNING]
        pending = [i for i in warnings if i.key not in acknowledged]
        status = "error" if errors else ("warning" if pending else "ok")
        steps.append({
            **spec,
            "status": status,
            "reachable": open_so_far,
            "counts": {"error": len(errors), "warning": len(warnings), "pending": len(pending),
                       "info": len(step_issues) - len(errors) - len(warnings)},
            "issues": [dict(i.to_dict(), acknowledged=i.key in acknowledged) for i in
                       sorted(step_issues, key=lambda i: {ERROR: 0, WARNING: 1, INFO: 2}[i.severity])],
            "lines": lines_by_step[key],
            "notes": notes_by_step[key],
        })
        if status != "ok":
            open_so_far = False
            all_clear = False

    target_ports = (
        [f"ethernet1/{n}" for n in range(1, port_count + 1)] if port_count else []
    )
    index = pan_validator.build_index(output_lines)
    l3_targets = sorted((name for name, entry in index.interfaces.items()
                         if entry.mode == "layer3" and not name.startswith("tunnel.")), key=_port_sort_key)
    chosen = {str((row or {}).get("local_interface") or "") for row in state["ipsec_gateways"].values()}
    l3_targets += sorted(c for c in chosen if c and c not in l3_targets)
    return {
        "steps": steps,
        "ready": all_clear,
        "revision": state_revision(state),
        "output_text": "\n".join(output_lines).rstrip() + "\n",
        "output_lines": len(output_lines),
        "facts": facts,
        "state": state,
        "options": {
            "models": PALOALTO_TARGET_MODELS,
            "target_ports": target_ports,
            "port_count": port_count,
            "gateway_interfaces": l3_targets,
            "roles": ROLE_LABELS,
        },
        "gateways": _gateway_rows(config, translator, state),
        "tunnels": [{"name": name, **row} for name, row in state["ipsec_tunnels"].items()],
    }


def state_revision(state: dict) -> str:
    """Fingerprint of the choices an evaluation was made from. Export only
    accepts the revision the user last saw checked."""
    import hashlib, json
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _port_sort_key(name: str):
    numbers = [int(x) for x in re.findall(r"\d+", name)]
    return (name.split("/")[0].rstrip("0123456789"), numbers)


def _gateway_rows(config, translator, state):
    rows = []
    for peer in config.ipsec_peers:
        if peer.disabled:
            continue
        name = translator.pan_name(peer.name)
        rows.append({
            "name": name,
            "peer": peer.address or "dynamic",
            "source_local_address": peer.local_address or "",
            "local_interface": (state["ipsec_gateways"].get(name) or {}).get("local_interface", ""),
        })
    return rows
