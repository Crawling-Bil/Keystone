"""Readers for the families the shared analyzers do not model as a sizing asset: ArubaOS-Switch (AOS-S) and FortiSwitch.

* **AOS-S.**  The Switch Analyzer reads AOS-CX, Cisco and Huawei; an ArubaOS-Switch (2530, 2540, 2930F/M, 3810, 5400R) prints a different ``show tech`` layout.
  The reader takes what a sizing needs from the commands that capture always holds: ``show system`` (name, software, serial), the ``; JLxxxA Configuration Editor``
  header and ``module N type`` lines (the product number), ``show interfaces brief`` (port type and state), ``show power-over-ethernet brief`` (PoE budget),
  ``show vlans`` and ``show trunks``.  Reference: https://arubanetworking.hpe.com/techdocs/AOS-Switch/16.10/ (ArubaOS-Switch management and configuration guide).
* **FortiSwitch.**  The Firewall Analyzer already reads a FortiSwitch's own capture (``fsw_*`` sections); the Sizing Tool counts it as a switch, with its ports by speed,
  MCLAG pair and trunks.  Reference: https://docs.fortinet.com/product/fortiswitch/7.4.
"""

from __future__ import annotations

import re
from typing import Any

from .common import add_component, add_feature, add_licence, add_peak, info, kv, new_asset, rows, section, total
from .readers import role_for

_PROMPT = r"(?:\S*[#>]\s*)?"


def _block(text: str, command: str) -> str:
    """The output of one ``show`` command: from its own line to the next ``show`` line (a prompt in front of the command is allowed)."""
    start = re.search(rf"(?im)^{_PROMPT}{command}\s*$", text)
    if not start:
        return ""
    tail = text[start.end():]
    end = re.search(rf"(?im)^{_PROMPT}show\s+\S", tail)
    return tail[:end.start()] if end else tail


def _speed(port_type: str) -> str | None:
    """The speed bucket of an AOS-S port type column ("100/1000T", "1000SX", "10GbE-SFP+"); None for an empty SFP slot."""
    value = port_type.strip().upper()
    if not value:
        return None
    if re.search(r"100\s*G|100GBE|QSFP28", value):
        return "100G"
    if re.search(r"40\s*G|40GBE|QSFP", value):
        return "40G"
    if re.search(r"25\s*G|25GBE", value):
        return "25G"
    if re.search(r"10\s*G|10GBE|SFP\+", value):
        return "10G"
    if re.search(r"1000|GIG|\bSX\b|\bLX\b|\bLH\b|SFP", value):
        return "1G"
    if re.search(r"10/100(?!/1000)|100FX|100T", value):
        return "100M"
    return "other"


def read_aos_s(text: str, source: str = "") -> dict[str, Any]:
    system = _block(text, "show system")
    hostname = _first(r"System Name\s*:\s*(\S.*?)\s*$", system) or _first(r'(?m)^hostname\s+"?([^"\r\n]+?)"?\s*$', text)
    software = _first(r"Software revision\s*:\s*(\S+)", system or text)
    serial = _first(r"Serial Number\s*:\s*(\S+)", system or text)
    product = _first(r"(?m)^;\s*(J[LK]?\d{3,4}[A-Z]?)\s+Configuration Editor", text).upper()
    crash = re.search(r"(?m)^Product:\s+Aruba\s+(\S+)\s*\n\s*Name:\s+(.+?)\s*$", text)
    name = crash.group(2).strip() if crash else ""
    short = re.sub(r"\s+Switch(?:\s+Series)?$", "", re.sub(r"^Aruba\s+", "", name)) if name else ""
    stack = re.findall(r'(?im)^\s*stacking\s+member\s+(\d+)\s+type\s+"?(j[lk]?\d{3,4}[a-z]?)"?', text)
    modules = list(dict.fromkeys(re.findall(r"(?im)^\s*module\s+(\S+)\s+type\s+(j[lk]?\d{3,4}[a-z]?)\b", text)))      # "show tech" prints the config several times
    chassis_pid = product or (modules[0][1].upper() if len(modules) == 1 else (stack[0][1].upper() if stack else ""))
    model = short or chassis_pid
    role = role_for(hostname, model, "switch")
    asset = new_asset(hostname=hostname, vendor="Aruba", device_type="switch", role=role, model=model, serial=serial, os=f"ArubaOS-Switch {software}".strip() if software else "",
                      source=source, analyzer="Switch Analyzer (AOS-S reader)")
    members = len(stack) or 1
    asset["ha"] = f"Stack of {members}" if members > 1 else "Standalone"
    if re.search(r"(?m)^\s*(?:vsf|distributed-trunking|trunk\s+\S+\s+\S+\s+dt-lacp)\b", text, re.I):
        asset["ha"] += " + VSF / distributed trunking"

    # ports: the "show interfaces brief" table (type, enabled, status)
    ports: dict[str, int] = {}
    in_use: dict[str, int] = {}
    up = admin_down = physical = empty = 0
    transceivers: dict[str, int] = {}
    for line in _block(text, "show interfaces brief").splitlines():
        match = re.match(r"^\s+([A-Za-z]?\d+[/\d]*)\s+(.*?)\s*\|\s*(?:Yes|No)\s+(Yes|No)\s+(Up|Down)\b", line)
        if not match:
            continue
        port, port_type, enabled, status = match.groups()
        speed = _speed(port_type)
        physical += 1
        if speed is None:
            empty += 1
            continue
        ports[speed] = ports.get(speed, 0) + 1
        if status == "Up":
            up += 1
            in_use[f"Ports {speed}"] = in_use.get(f"Ports {speed}", 0) + 1
        if enabled == "No":
            admin_down += 1
        if re.search(r"SX|LX|LH|ZX|SFP|DAC|CX4|SR|LR", port_type.upper()):
            transceivers[port_type.strip()] = transceivers.get(port_type.strip(), 0) + 1
    cap = asset["capacity"]
    asset["in_use"] = in_use
    cap["Physical ports"] = physical
    cap["Ports in use (link up)"] = up
    for speed, count in sorted(ports.items()):
        cap[f"Ports {speed}"] = count
    if empty:
        cap["Ports (SFP slot, no transceiver)"] = empty
    cap["Ports disabled by configuration"] = admin_down
    poe = _block(text, "show power-over-ethernet brief")
    available = re.search(r"Available:\s*(\d+(?:\.\d+)?)\s*W\s+Used:\s*(\d+(?:\.\d+)?)\s*W", poe)
    poe_ports = sum(1 for line in poe.splitlines() if re.match(r"^\s+[A-Za-z]?\d+[/\d]*\s+(?:Yes|No)\s+\S+\s+", line))
    cap["PoE ports"] = poe_ports
    cap["PoE power (W)"] = float(available.group(1)) if available else 0
    cap["PoE power drawn (W)"] = float(available.group(2)) if available else 0
    vlans = [m for m in (re.match(r"^\s+(\d+)\s+(\S.*?)\s+\|", line) for line in _block(text, "show vlans").splitlines()) if m]
    cap["VLANs"] = len(vlans)
    trunk_lines = [line for line in _block(text, "show trunks").splitlines() if re.match(r"^\s+\S+\s+\|\s+\S", line) and not line.strip().startswith(("Port", "-"))]
    trunk_groups = {m.group(1) for m in (re.search(r"\|\s*(?:\S.*?)\s+(Trk\d+)\b", line) for line in trunk_lines) if m}
    cap["Trunk ports"] = len(trunk_lines)
    cap["Port-channels"] = len(trunk_groups)
    cap["Transceivers"] = sum(transceivers.values())
    cap["Stack members"] = members

    for _, pid in (stack or []):
        add_component(asset, "Chassis", pid.upper(), f"Aruba {short or pid.upper()}")
    if not stack and chassis_pid:
        add_component(asset, "Chassis", chassis_pid, name or f"Aruba {chassis_pid}")
    elif not stack and len(modules) > 1:
        add_component(asset, "Chassis", product or model, name or model)
    if not stack and len(modules) > 1:
        for _, pid in modules:
            add_component(asset, "Module", pid.upper(), f"Aruba module {pid.upper()}")
    if not asset["components"] and model:
        add_component(asset, "Chassis", model, model)
    for part, count in sorted(transceivers.items()):
        add_component(asset, "Transceiver", "", f"{part} port (SFP in service)", count)

    # features: counted from the running configuration
    config = _block(text, "show running-config") or text
    def count(pattern: str) -> int:
        return len(re.findall(pattern, config, re.I | re.M))
    add_feature(asset, "Layer 2", "VLANs", len(vlans))
    add_feature(asset, "Layer 2", "Trunk groups (LACP / static)", len(trunk_groups))
    add_feature(asset, "Layer 2", "Spanning tree", 1 if re.search(r"(?m)^\s*spanning-tree\b", config) else 0)
    add_feature(asset, "Layer 2", "Loop protection", 1 if re.search(r"(?m)^\s*loop-protect\b", config) else 0)
    add_feature(asset, "Layer 2", "IGMP snooping", 1 if re.search(r"(?m)^\s*(?:ip igmp|igmp)\b", config) else 0)
    add_feature(asset, "Layer 3", "Static routes", count(r"^ip route\s"))
    add_feature(asset, "Layer 3", "Routed VLAN interfaces (IP address)", count(r"^\s+ip address\s+\d"))
    add_feature(asset, "Layer 3", "OSPF", 1 if re.search(r"(?m)^router ospf", config, re.I) else 0)
    add_feature(asset, "Redundancy", "VRRP", count(r"^\s*vrrp vrid\s") or (1 if re.search(r"(?m)^router vrrp", config, re.I) else 0))
    add_feature(asset, "Services", "DHCP relay (helper addresses)", count(r"^\s*ip helper-address\s"))
    add_feature(asset, "Services", "DHCP snooping", 1 if re.search(r"(?m)^dhcp-snooping\b", config) else 0)
    add_feature(asset, "Services", "PoE", poe_ports)
    add_feature(asset, "Security", "802.1X / MAC authentication (port-access)", count(r"^aaa port-access\b"))
    add_feature(asset, "Security", "Port security", count(r"^port-security\b"))
    add_feature(asset, "Management", "SNMP", 1 if re.search(r"(?m)^snmp-server\b", config) else 0)
    add_feature(asset, "Management", "NTP", count(r"^ntp server\s"))
    add_feature(asset, "Management", "AAA (RADIUS / TACACS+)", count(r"^(?:radius-server|tacacs-server)\s"))

    # a "show tech" for an AOS-S switch holds no licence: the feature set is in the firmware, the support is in Aruba Central / the HPE contract
    add_licence(asset, "ArubaOS-Switch software", "no licence file", "", "Base features are part of the firmware; Aruba Central subscriptions and the support contract are held in HPE GreenLake / Aruba Central")
    asset["notes"].append("Aruba Central subscriptions and warranty are not in a switch capture: export them from Aruba Central / HPE GreenLake before the refresh.")
    if not chassis_pid:
        asset["notes"].append("The product number (JLxxxA) is not in the capture (add show system information / show modules).")
    if not physical:
        asset["notes"].append("No port table in the capture (add show interfaces brief, show vlans, show trunks): ports, VLANs and trunks are unknown.")
    if not available:
        asset["notes"].append("No show power-over-ethernet brief in the capture: the PoE budget is unknown.")
    if empty:
        asset["notes"].append(f"{empty} SFP slots show no transceiver; their speed is known only once an optic is inserted.")
    return asset


def _first(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.M)
    return match.group(1).strip() if match else ""


# ---------------------------------------------------------------------------------------------------------------- FortiSwitch

_FSW_SPEED = re.compile(r"(\d+(?:\.\d+)?)\s*([GM])", re.I)


def read_fortiswitch(result: dict[str, Any], source: str = "") -> dict[str, Any]:
    meta = info(result)
    ident = kv(result, "fsw_identity")
    hostname = result.get("hostname") or meta.get("Hostname", "")
    model = meta.get("Model") or ident.get("Model", "")
    serial = meta.get("Serial number") or ident.get("Serial number", "")
    os_ = meta.get("FortiSwitchOS") or ident.get("FortiSwitchOS", "")
    role = role_for(hostname, model, "access")
    asset = new_asset(hostname=hostname, vendor="Fortinet", device_type="switch", role=role if role in ("core", "aggregation", "access", "switch") else "access", model=model,
                      serial=serial, os=f"FortiSwitchOS {os_}".strip() if os_ else "", source=source, analyzer="Firewall Analyzer (FortiSwitch reader)")
    mclag = rows(result, "fsw_mclag")
    peer = meta.get("MCLAG peer", "")
    asset["ha"] = "MCLAG pair" if (peer or mclag) else "Standalone"
    speeds: dict[str, int] = {}
    physical = up = 0
    for row in rows(result, "fsw_ports"):
        name = str(row.get("name", "")).lower()
        if not re.match(r"^(?:port\d+|[a-z]+\d+/\d+|[a-z]+\d+)$", name) or name in ("internal", "mgmt") or name.startswith(("internal", "mgmt")):
            continue
        physical += 1
        is_up = str(row.get("link", "")).lower() == "up"
        if is_up:
            up += 1
        match = _FSW_SPEED.search(str(row.get("speed", "")))
        label = "1G"
        if match:
            value = float(match.group(1))
            label = f"{int(value)}G" if match.group(2).upper() == "G" else "100M"
            if label == "0G":
                label = "100M"
        speeds[label] = speeds.get(label, 0) + 1
        if is_up:
            asset["in_use"][f"Ports {label}"] = asset["in_use"].get(f"Ports {label}", 0) + 1
    cap = asset["capacity"]
    cap["Physical ports"] = physical
    cap["Ports in use (link up)"] = up
    for label, count in sorted(speeds.items()):
        cap[f"Ports {label}"] = count
    cap["VLANs"] = len(rows(result, "fsw_vlans"))
    trunks = rows(result, "fsw_trunks")
    cap["Port-channels"] = len({str(r.get("name", "")) for r in trunks})
    cap["Trunk ports"] = sum(len(re.findall(r"port\w+", str(r.get("ports", "")))) for r in {str(r.get("name", "")): r for r in trunks}.values())
    add_component(asset, "Chassis", model, f"Fortinet FortiSwitch {re.sub(r'^FortiSwitch-?', '', model, flags=re.I)}".strip())
    health = kv(result, "fsw_health")
    for label in health:
        if label.startswith("PSU"):
            add_component(asset, "Power supply", "", "Power supply (hot-swap, per model datasheet)")
        elif label.startswith("Fan"):
            add_component(asset, "Fan", "", "Fan tray")
    add_feature(asset, "Layer 2", "VLANs", cap["VLANs"])
    add_feature(asset, "Layer 2", "Trunks (LACP)", cap["Port-channels"])
    add_feature(asset, "Layer 2", "Spanning tree instances", total(result, "fsw_stp"))
    add_feature(asset, "Redundancy", "MCLAG", 1 if (peer or mclag) else 0)
    add_licence(asset, "FortiSwitch support / FortiCare", "not in capture", "", "Warranty, FortiCare and FortiSwitch Cloud entitlements are held in FortiCare; a switch capture does not print them")
    asset["notes"].append("PoE budget and transceiver parts are not in this capture: take them from the model datasheet (https://docs.fortinet.com/product/fortiswitch) or the FortiGate that manages the switch.")
    asset["notes"].append("Managed switches are also listed in their FortiGate: the FortiLink port and the managed-switch table there carry the same device (count it once).")
    return asset


# ------------------------------------------------------------------------------------------------------------------ Huawei AC runtime tables

_PORT_ROW = re.compile(r"^(?P<name>(?:XG|40G|100G|25G|10G|G|)(?:igabit)?(?:Ethernet|E)\d+/\d+/\d+)\s+(?P<phy>\*?down|up)\b", re.M)
_HW_SPEED = (("XGigabitEthernet", "Ports 10G"), ("10GE", "Ports 10G"), ("25GE", "Ports 25G"), ("40GE", "Ports 40G"), ("100GE", "Ports 100G"), ("GigabitEthernet", "Ports 1G"))


def huawei_ac_extras(asset: dict[str, Any], result: dict[str, Any], text: str) -> None:
    """Numbers a replacement controller needs that the wireless analyzer's configuration view does not hold: access-point states, radios and clients at capture time,
    controller ports, power modules, and how many access points each switch carries (their PoE load)."""
    cap, in_use = asset["capacity"], asset["in_use"]
    counts = result.get("status_counts") or {}
    cap["Access points fault"], cap["Access points idle"] = counts.get("fault", 0), counts.get("idle", 0)
    runtime = (result.get("radio_runtime") or {}).get("summary") or {}
    if runtime.get("radios"):
        cap["Radios"], cap["Radios on"] = runtime["radios"], runtime["radios_on"]
        add_peak(asset, "Associated clients (at capture time)", runtime["clients"], "clients", "capture", "one moment, not a peak")
        add_peak(asset, "Busiest radio channel utilisation (%)", runtime["max_utilisation"] or 0, "%", "capture", "one moment, not a peak")
        add_peak(asset, "Most clients on one access point", runtime["max_clients_per_ap"], "clients", "capture", "one moment, not a peak")
        standards = ", ".join(f"{k} x{v}" for k, v in sorted((runtime.get("standards") or {}).items(), key=lambda kv: -kv[1]))
        asset["notes"].append(f"Radios by standard at capture time: {standards}. Clients and utilisation are one moment: repeat display radio all in the busiest hour before sizing.")
    else:
        asset["notes"].append("No display radio all in the capture: radios, clients and channel utilisation are unknown.")
    if (counts.get("fault", 0) or counts.get("idle", 0)):
        asset["notes"].append(f"{counts.get('fault', 0)} access points in fault and {counts.get('idle', 0)} idle at capture time: they are counted as configured, not as joined.")
    power = sum(1 for ap in result.get("data", {}).get("aps", []) if "P" in str(ap.get("extra_info", "")).upper().split())
    if power:
        asset["notes"].append(f"{power} access points report insufficient PoE power (P flag in display ap all): check the switch ports and budget they sit on.")
    uplinks = ((result.get("ap_uplinks") or {}).get("per_switch")) or []
    if uplinks:
        cap["Switches carrying access points"] = len(uplinks)
        cap["Access points with a known switch port"] = sum(u["aps"] for u in uplinks)
        top = ", ".join(f"{u['switch']} {u['aps']}" for u in uplinks[:6])
        asset["notes"].append(f"Access points per switch (controller LLDP view; PoE ports the switches must carry): {top}.")
    # controller ports: one row per interface even when the log holds the table several times
    seen: dict[str, str] = {}
    for match in _PORT_ROW.finditer(text or ""):
        seen[match.group("name")] = match.group("phy")
    for name, phy in seen.items():
        label = next((lab for prefix, lab in _HW_SPEED if name.startswith(prefix)), "")
        if not label:
            continue
        cap[label] = cap.get(label, 0) + 1
        if phy == "up":
            in_use[label] = in_use.get(label, 0) + 1
    if seen:
        cap["Physical ports"] = sum(v for k, v in cap.items() if k.startswith("Ports "))
        cap["Ports in use (link up)"] = sum(in_use.values())
    # power modules from "display device": the slot table lists them without a part number
    blocks = re.findall(r"(?is)display device\s*\n(.*?)(?=\n<|\Z)", text or "")
    if blocks:
        modules = len(re.findall(r"(?im)^-?\s+\d+\s+POWER\s+Present", blocks[-1]))
        if modules:
            add_component(asset, "Power supply", "", "Power module (part number is not in the capture: add display elabel)", modules)
