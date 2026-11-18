"""One reader per analyzer family: the analyzer's own result in, one asset record out (see ``common``).

Nothing is parsed again here.  A reader picks fields the analyzer already produced; what a capture did not hold is written into ``notes`` so the
architect knows what to collect before the design is final, never guessed.
"""

from __future__ import annotations

import re
from typing import Any

from features.switch_analyzer.sizing import _device_sizing_row

from . import licence_extra
from .classify import role_of
from .common import (add_component, add_feature, add_licence, add_peak, card, feature_catalog, first, info, kv, licence_rows,
                     new_asset, port_speed_label, rows, section, si_number, total)

# ---------------------------------------------------------------------------------------------------------------- switch (Cisco, Huawei, Aruba)

_PART_CATEGORY = {"Chassis": "Chassis", "Stack member": "Chassis", "Stack": "Stack", "Stack cable": "Stack", "Stack module": "Stack",
                  "Power supply": "Power supply", "Fan": "Fan", "Module": "Module", "Transceiver": "Transceiver"}


def read_switch(result: dict[str, Any], source: str = "", text: str = "") -> dict[str, Any]:
    sizing = _device_sizing_row(result)
    hostname = result.get("hostname") or ""
    model = sizing["model"] or ""
    role = role_for(hostname, model, "switch")
    asset = new_asset(hostname=hostname, vendor=result.get("vendor", ""), device_type="switch", role=role, model=model, serial=sizing["serial_number"],
                      os=sizing["os_version"], source=source, analyzer="Switch Analyzer")
    stack = (result.get("inventory") or {}).get("stack") or {}
    members = int(stack.get("member_count") or 1)
    vpc = result.get("vpc_mlag") or {}
    ha = []
    if members > 1:
        ha.append(f"Stack of {members}")
    if sizing["vpc_mlag_configured"]:
        ha.append("vPC / MLAG / VSX pair")
    if text and "stackwise-virtual" in text.lower():
        try:
            from features.topology import stackwise
            domain = (stackwise.read(text) or {}).get("domain")
            if domain:
                ha.append(f"StackWise Virtual (domain {domain})")
        except Exception:
            pass
    asset["ha"] = " + ".join(ha) or "Standalone"

    cap = asset["capacity"]
    cap["Physical ports"] = sizing["physical_port_count"]
    cap["Ports in use (link up)"] = sizing["physical_ports_up"]
    sizing["port_type_counts"] = resolve_port_speeds(result, text, sizing["port_type_counts"])
    for label, count in sorted(sizing["port_type_counts"].items()):
        key = "Ports (speed not in name)" if "speed not in name" in label else "Ports (other)" if label == "Other" else f"Ports {label}"
        cap[key] = cap.get(key, 0) + count
    asset["in_use"] = in_use_by_speed(result, text)
    cap["PoE ports"] = sizing["poe_port_count"]
    cap["PoE power (W)"] = sizing["poe_total_watts"]
    cap["Transceivers"] = sizing["transceiver_count"]
    cap["Trunk ports"] = sizing["trunk_port_count"]
    cap["Port-channels"] = sizing["port_channel_count"]
    cap["VLANs"] = sizing["vlan_count"]
    cap["Routed interfaces"] = len([i for i in (result.get("l3") or {}).get("interfaces", [])])
    cap["Static routes"] = sizing["static_route_count"]
    cap["Stack members"] = members

    seen_xcvr = False
    for part in result.get("parts") or []:
        if part.get("kind") == "Stack":
            continue                                   # the stack summary entry repeats the PID of its members
        category = _PART_CATEGORY.get(part.get("kind", ""), "Other")
        seen_xcvr = seen_xcvr or category == "Transceiver"
        add_component(asset, category, part.get("pid", ""), _part_text(part))
    if not asset["components"] and model:
        add_component(asset, "Chassis", model, model)
    if not seen_xcvr:
        for xcvr in result.get("transceivers") or []:
            if xcvr.get("present", True):
                add_component(asset, "Transceiver", (xcvr.get("vendor_part_number") or "").strip(), xcvr.get("type", ""))

    licence = (result.get("health") or {}).get("licence") or {}
    detail = licence.get("detail") or {}
    ends = {t.get("license"): t.get("end") for t in detail.get("terms") or []}
    seen = set()
    for ent in detail.get("entitlements") or []:
        name = ent.get("description") or ent.get("name") or ent.get("tag") or ""
        seen.add(ent.get("tag") or name)
        add_licence(asset, name, ent.get("status") or ent.get("license_type", ""), ends.get(ent.get("name"), "") or ends.get(ent.get("tag"), ""),
                    "; ".join(x for x in (ent.get("tag", ""), ent.get("license_type", "")) if x))
    for row in licence.get("licenses") or []:
        if row.get("tag") in seen:
            continue
        add_licence(asset, row.get("license", ""), row.get("status", ""), "", row.get("tag", ""))
    for row in detail.get("rtu") or detail.get("stores") or []:
        add_licence(asset, row.get("feature", ""), row.get("license_type", "") or row.get("state", ""), row.get("eval_left", ""), row.get("store", ""))
    if detail.get("mode") or detail.get("registration"):
        asset["notes"].append("Licensing: " + ", ".join(x for x in (detail.get("mode"), detail.get("registration"), detail.get("authorization")) if x))
    if text:
        licence_extra.apply(asset, text)
    if not asset["licences"]:
        asset["notes"].append(_NO_SWITCH_LICENCE.get(asset["vendor"], _NO_SWITCH_LICENCE["Cisco"]))

    # features switched on, with the number of objects behind each
    routing = result.get("routing_protocols") or {}
    l3 = result.get("l3") or {}
    add_feature(asset, "Layer 2", "VLANs", sizing["vlan_count"])
    add_feature(asset, "Layer 2", "Port-channels / LACP", sizing["port_channel_count"])
    st = result.get("spanning_tree") or {}
    if st.get("protocol") or st.get("enabled"):
        add_feature(asset, "Layer 2", f"Spanning tree ({st.get('protocol') or 'enabled'})", 1)
    add_feature(asset, "Layer 2", "Trunk ports", sizing["trunk_port_count"])
    add_feature(asset, "Redundancy", "vPC / MLAG / VSX", 1 if sizing["vpc_mlag_configured"] else 0)
    add_feature(asset, "Redundancy", "Stack", 1 if members > 1 else 0)
    add_feature(asset, "Redundancy", "HSRP / VRRP interfaces", max(sizing["hsrp_vrrp_svi_count"], int((result.get("fhrp") or {}).get("config_hsrp") or 0)))
    add_feature(asset, "Layer 3", "Routed interfaces / SVIs", len(l3.get("interfaces") or []))
    add_feature(asset, "Layer 3", "Static routes", sizing["static_route_count"])
    add_feature(asset, "Layer 3", "OSPF", 1 if routing.get("ospf") else 0)
    add_feature(asset, "Layer 3", "EIGRP", 1 if routing.get("eigrp") else 0)
    add_feature(asset, "Layer 3", "Other routing protocols (BGP, IS-IS, RIP)", len(l3.get("other_protocols") or []))
    add_feature(asset, "Layer 3", "Policy-based routing", len((result.get("pbr") or {}).get("pbr_policies") or []))
    add_feature(asset, "Layer 3", "ACLs", len((l3.get("acls") or {}).get("definitions") or []))
    dhcp = result.get("dhcp") or {}
    add_feature(asset, "Services", "DHCP server pools", len(dhcp.get("pools") or []))
    add_feature(asset, "Services", "DHCP relay (helper addresses)", len(dhcp.get("helper_addresses") or []))
    add_feature(asset, "Services", "DHCP snooping", 1 if (dhcp.get("snooping") or {}).get("enabled") else 0)
    add_feature(asset, "Services", "PoE", sizing["poe_port_count"])
    add_feature(asset, "Management", "SNMP", 1 if (result.get("snmp") or {}).get("enabled") else 0)
    add_feature(asset, "Management", "NTP", 1 if (result.get("ntp") or {}).get("peers") or (result.get("ntp") or {}).get("status") else 0)
    add_feature(asset, "Management", "AAA", 1 if result.get("aaa_commands") else 0)
    if not sizing["transceiver_count"] and not result.get("transceivers"):
        asset["notes"].append("No transceiver output in the capture (add show interface transceiver / display transceiver).")
    if sizing["physical_ports_unknown"]:
        asset["notes"].append(f"{sizing['physical_ports_unknown']} ports have no live state (add show interfaces status).")
    for label in sizing["port_type_counts"]:
        if "speed not in name" in label:
            asset["notes"].append("Port speed is not in the port names of this platform; check the model datasheet or add show interface status.")
            break
    return asset


# NX-OS "show interface status": Port Name Status Vlan Duplex Speed Type -- the Type column ("10g", "40g", "1000", "10Gbase-SR") is what the port can do
_NXOS_STATUS_ROW = re.compile(r"(?m)^(Eth\S+|Ethernet\S+)\s+.*?\b(?:full|half|auto)\s+(?:a-)?\S+\s+(\S+)\s*$")


_NXOS_DESCRIPTION_ROW = re.compile(r"(?m)^(Eth\S+)\s+eth\s+(\S+)(?:\s|$)")


def _type_bucket(raw: str) -> str | None:
    value = raw.strip().lower()
    for pattern, label in ((r"(?<![0-9x])100g", "100G"), (r"(?<![0-9x])40g", "40G"), (r"(?<![0-9x])25g", "25G"), (r"(?<![0-9x])10g", "10G"),
                           (r"^(?:1000|1g|1000base|sfp-1g|glc-)", "1G")):                # QSFP-100G-SR4, QSFP-H40G-CU, SFP-H10GB-CU, 10Gbase-SR; a 4x10G breakout names no one speed
        if re.search(pattern, value):
            return label
    return None


def _speed_map(result: dict[str, Any], text: str) -> dict[str, str]:
    """``{port key: speed bucket}`` from the capture's own tables: the status Type column, the transceiver, the description table (in that order of trust)."""
    by_port: dict[str, str] = {}
    for match in _NXOS_STATUS_ROW.finditer(text or ""):
        bucket = _type_bucket(match.group(2))
        if bucket:
            by_port[_port_key(match.group(1))] = bucket
    for xcvr in result.get("transceivers") or []:
        bucket = _type_bucket(str(xcvr.get("type", ""))) or _type_bucket(str(xcvr.get("pid", "")))
        if bucket and xcvr.get("interface"):
            by_port.setdefault(_port_key(xcvr["interface"]), bucket)
    for match in _NXOS_DESCRIPTION_ROW.finditer(text or ""):            # "show interface description": Port Type Speed Description (the speed the port is set to)
        bucket = _type_bucket(match.group(2))
        if bucket:
            by_port.setdefault(_port_key(match.group(1)), bucket)
    return by_port


def resolve_port_speeds(result: dict[str, Any], text: str, counts: dict[str, int]) -> dict[str, int]:
    """Ports whose name carries no speed (NX-OS ``Ethernet1/1``) get the speed their own ``show interface status`` Type column or their transceiver names.
    What cannot be resolved stays in the explicit "speed not in name" bucket, so a gap is counted and flagged, never guessed."""
    if not any("speed not in name" in label for label in counts):
        return counts
    by_port = _speed_map(result, text)
    if not by_port:
        return counts
    out = {label: count for label, count in counts.items() if "speed not in name" not in label}
    for iface in result.get("interfaces") or []:
        label = port_speed_label(str(iface.get("name", "")))
        if not label or "speed not in name" not in label:
            continue
        key = by_port.get(_port_key(iface["name"])) or label
        out[key] = out.get(key, 0) + 1
    return out


def in_use_by_speed(result: dict[str, Any], text: str) -> dict[str, int]:
    """Ports with a link per speed bucket (the keys of the capacity table), so a replacement can be sized on the ports in use and not on the ports that exist."""
    by_port = _speed_map(result, text)
    out: dict[str, int] = {}
    for iface in result.get("interfaces") or []:
        label = port_speed_label(str(iface.get("name", "")))
        if label is None:
            continue
        if "speed not in name" in label:
            label = by_port.get(_port_key(iface["name"])) or label
        if str(iface.get("status", "")).lower() == "up":
            key = "Ports (speed not in name)" if "speed not in name" in label else "Ports (other)" if label == "Other" else f"Ports {label}"
            out[key] = out.get(key, 0) + 1
    return out


def _port_key(name: str) -> str:
    return re.sub(r"^ethernet", "eth", str(name).strip().lower())


_MEMBER_PREFIX = re.compile(r"^(?:switch|slot|member)\s*\d+\s*-\s*", re.I)


def _part_text(part: dict[str, Any]) -> str:
    """What a part is, without the member or slot it sits in (so two power supplies of one model are one line of the bill of materials)."""
    text = _MEMBER_PREFIX.sub("", str(part.get("description") or "").strip())
    kind = part.get("kind", "")
    if part.get("pid"):
        if kind in ("Power supply", "Fan"):
            text = re.sub(r"\s+[A-D0-9]$", "", text)             # "Power Supply B" -> "Power Supply"
        elif kind in ("Stack cable", "Stack module"):
            text = re.sub(r"\s*\d+/\d+$", "", text)           # "StackPort1/1" -> "StackPort"
    return text


_NO_SWITCH_LICENCE = {
    "Cisco": "No licence output in the capture (add show license summary and show license usage).",
    "Huawei": "No licence output in the capture (add display license).",
    "Aruba": "Aruba licences (Aruba Central subscriptions, CX feature licences) are not in a switch capture: export them from Aruba Central / HPE GreenLake.",
}


def role_for(hostname: str, model: str, fallback: str) -> str:
    return role_of(hostname, model, fallback)


# ---------------------------------------------------------------------------------------------------------------- router (Cisco IOS / IOS-XE / SD-WAN)

ROUTER_FEATURES = (
    ("bgp_neighbors", "Routing", "BGP neighbours"), ("ospf_processes", "Routing", "OSPF processes"), ("eigrp_processes", "Routing", "EIGRP processes"),
    ("vrfs", "Routing", "VRFs"), ("static_routes", "Routing", "Static routes"), ("route_maps", "Routing", "Route-maps"), ("fhrp", "Routing", "HSRP / VRRP groups"),
    ("ip_sla", "Routing", "IP SLA probes"), ("tracks", "Routing", "Tracked objects"),
    ("vpn_tunnels", "VPN", "IPsec tunnels"), ("crypto_maps", "VPN", "Crypto maps"), ("ikev2_profiles", "VPN", "IKEv2 profiles"), ("gdoi_config", "VPN", "GETVPN (GDOI)"),
    ("nat_rules", "NAT", "NAT rules"), ("nat_static", "NAT", "Static NAT"), ("nat_pools", "NAT", "NAT pools"),
    ("zones", "Security", "Zone-based firewall zones"), ("acl_summary", "Security", "Access lists"),
    ("policy_maps", "QoS", "QoS policy-maps"), ("class_maps", "QoS", "QoS class-maps"), ("netflow", "Visibility", "NetFlow / flow export"),
    ("sdwan_control", "SD-WAN", "Control connections"), ("sdwan_tunnels", "SD-WAN", "Data tunnels"), ("sdwan_aar_rules", "SD-WAN", "AAR / SLA rules"),
    ("sdwan_policy_lists", "SD-WAN", "Policy lists"), ("dhcp", "Services", "DHCP pools"), ("eem", "Services", "EEM applets"),
    ("snmp_communities", "Management", "SNMP communities"), ("snmp_groups", "Management", "SNMPv3 groups / traps"), ("aaa_servers", "Management", "AAA servers"),
    ("ntp_associations", "Management", "NTP associations"), ("evc", "Layer 2", "Ethernet service instances (EVC)"), ("etherchannel", "Layer 2", "EtherChannels"),
)


_LOGICAL = (("loopback", "loopbacks"), ("lo", "loopbacks"), ("tunnel", "tunnels"), ("tu", "tunnels"), ("port-channel", "port-channels"), ("po", "port-channels"), ("vlan", "SVIs"),
            ("bdi", "BDIs"), ("vl", "SVIs"), ("nve", "NVEs"), ("virtual-template", "virtual templates"), ("virtual-access", "virtual access"))


def _logical_kind(name: str) -> str:
    """``Loopback0`` -> loopbacks, ``Tunnel10`` -> tunnels ...; "" for a name that is none of them (a port speed or a name the tool does not know)."""
    match = re.match(r"^([A-Za-z\-]+?)\s*\d", name.strip())
    word = (match.group(1) if match else name.strip()).lower()
    for prefix, kind in _LOGICAL:
        if word == prefix:
            return kind
    return ""


def read_router(result: dict[str, Any], source: str = "") -> dict[str, Any]:
    meta = info(result)
    hostname = result.get("hostname") or meta.get("Hostname", "")
    model = meta.get("Model", "")
    asset = new_asset(hostname=hostname, vendor="Cisco", device_type="router", role="router", model=model, serial=meta.get("Serial number", ""),
                      os=meta.get("Software", ""), source=source, analyzer="Router Analyzer")
    if "sdwan" in (meta.get("Platform family", "") + " " + str(result.get("platform", ""))).lower() or total(result, "sdwan_control") or total(result, "sdwan_tunnels"):
        asset["ha"] = "SD-WAN edge"
    asset["ha"] = asset["ha"] or ("HSRP / VRRP" if total(result, "fhrp") else "Standalone")
    cap = asset["capacity"]
    speeds: dict[str, int] = {}
    physical = logical = 0
    kinds: dict[str, int] = {}
    for row in rows(result, "interfaces"):
        name = str(row.get("name", ""))
        label = port_speed_label(name)
        if label is None:                                      # no port speed in the name: a loopback, tunnel, port-channel or SVI is logical, anything else is not counted
            kind = _logical_kind(name)
            if kind:
                logical += 1
                kinds[kind] = kinds.get(kind, 0) + 1
            continue
        if label == "Other":                                   # NVI, Sdwan-system-intf, Dialer: logical, no port to buy
            logical += 1
            continue
        physical += 1
        speeds[label] = speeds.get(label, 0) + 1
    cap["Physical interfaces"] = physical
    cap["Logical interfaces (loopback, tunnel, BDI)"] = logical
    for kind, count in sorted(kinds.items()):
        cap[f"Logical: {kind}"] = count
    for label, count in sorted(speeds.items()):
        cap[f"Interfaces {label}"] = count
    routes_card = re.sub(r"[^\d]", "", str(card(result, "Routes") or ""))                  # "not captured" is text, not zero
    cap["Routes"] = total(result, "routes") or int(routes_card or 0)
    cap["BGP sessions"] = total(result, "bgp_neighbors")
    cap["VRFs"] = total(result, "vrfs")
    cap["IPsec tunnels"] = total(result, "vpn_tunnels")
    cap["NAT rules"] = total(result, "nat_rules") + total(result, "nat_static")
    for row in rows(result, "inventory"):
        name = (row.get("name") or "").lower()
        category = "Chassis" if "chassis" in name else "Power supply" if "power" in name or "psu" in name else "Fan" if "fan" in name else "Transceiver" if re.match(r"^(gi|te|fo|hu|twe|fa)", name) else "Module"
        pid = (row.get("pid") or "").strip()
        add_component(asset, category, "" if pid.upper() in ("N/A", "NA", "UNKNOWN") else pid, row.get("description", "") or row.get("name", ""))
    if not asset["components"] and model:
        add_component(asset, "Chassis", model, model)
    for row in rows(result, "license_table"):                     # technology packages: name, package in use, type (Permanent, RightToUse, Smart License)
        tech = (row.get("technology") or "").split()
        package = (row.get("current") or "").strip()
        if tech and package.lower() != "none":
            add_licence(asset, f"{tech[0]} technology package", row.get("type", ""), "", f"in use: {package}" + (f"; next reload: {row['next_reboot']}" if row.get("next_reboot") else ""))
    licence_rows(asset, result, ("license_usage", "licensing", "licensing_classic", "license_store"))
    meta_level = meta.get("License level") or meta.get("Licence level") or ""
    if meta_level and not asset["licences"]:
        add_licence(asset, f"Technology package: {meta_level}")
    if not asset["licences"]:
        asset["notes"].append("No licence output in the capture (add show license summary / show license all; classic IOS: show license).")
    feature_catalog(asset, result, ROUTER_FEATURES)
    if not rows(result, "inventory"):
        asset["notes"].append("No show inventory in the capture: modules, power supplies and optics are not listed.")
    return asset


# ---------------------------------------------------------------------------------------------------------------- firewall (Palo Alto, FortiGate)

FIREWALL_FEATURES = (
    ("policies", "Policy", "Firewall policies"), ("security_rules", "Policy", "Security rules"), ("nat_rules", "Policy", "NAT rules"), ("central_snat", "Policy", "Central SNAT"),
    ("vips", "Policy", "Virtual IPs (port forwards)"), ("vipgrps", "Policy", "VIP groups"), ("policy_routes", "Policy", "Policy routes"), ("pbf_rules", "Policy", "Policy-based forwarding"),
    ("proxy_policies", "Policy", "Explicit proxy policies"), ("shaping_policies", "Policy", "Traffic-shaping policies"), ("local_in", "Policy", "Local-in policies"),
    ("security_profiles", "Inspection", "Security profiles"), ("profile_groups", "Inspection", "Security profile groups"), ("profiles", "Inspection", "Security profiles defined"),
    ("urlfilters", "Inspection", "URL / web filters"), ("tls_profiles", "Inspection", "SSL / TLS inspection profiles"), ("dos", "Inspection", "DoS policies"),
    ("zone_protection", "Inspection", "Zone protection profiles"), ("botnet", "Inspection", "Botnet / reputation"), ("application_groups", "Inspection", "Application groups"),
    ("ipsec_tunnels", "VPN", "IPsec tunnels"), ("ipsec_p1", "VPN", "IPsec phase 1"), ("ike_gateways", "VPN", "IKE gateways"), ("sslvpn", "VPN", "SSL-VPN"), ("sslvpn_portals", "VPN", "SSL-VPN portals"),
    ("globalprotect", "VPN", "GlobalProtect"),
    ("sdwan_members", "SD-WAN", "SD-WAN members"), ("sdwan_rules", "SD-WAN", "SD-WAN rules"),
    ("bgp_neighbors", "Routing", "BGP neighbours"), ("ospf_areas", "Routing", "OSPF areas"), ("ospf_process", "Routing", "OSPF process"), ("static_routes", "Routing", "Static routes"),
    ("virtual_routers", "Routing", "Virtual routers"), ("routing_protocols", "Routing", "Dynamic routing"),
    ("vdoms", "Virtualisation", "VDOMs"), ("vsys_list", "Virtualisation", "Virtual systems"), ("vlans", "Layer 2", "VLAN sub-interfaces"), ("zones", "Layer 2", "Security zones"),
    ("ha", "Redundancy", "High availability"),
    ("auth_servers", "Identity", "Authentication servers"), ("user_groups", "Identity", "User groups"), ("local_users", "Identity", "Local users"), ("auth_profiles", "Identity", "Authentication profiles"),
    ("dhcp", "Services", "DHCP servers"), ("ippools", "Services", "IP pools"), ("traffic_shapers", "Services", "Traffic shapers"), ("qos_profiles", "Services", "QoS profiles"),
    ("log_forwarding", "Management", "Log forwarding"), ("snmp", "Management", "SNMP"), ("certificates", "Management", "Certificates"), ("fctems", "Management", "FortiClient EMS"),
    ("pano_devices", "Management", "Managed by Panorama"),
)
_FW_LICENCE_IDS = ("licenses", "support_check")


def _fw_os(result: dict[str, Any]) -> str:
    parts = [p.strip() for p in str(result.get("platform", "")).split("·")]
    return parts[-1] if len(parts) > 1 and parts[-1] != parts[0] else ""


def read_firewall(result: dict[str, Any], source: str = "", text: str = "") -> dict[str, Any]:
    meta = info(result)
    vendor = "Palo Alto" if str(result.get("vendor", "")).lower().startswith("palo") else "Fortinet" if str(result.get("vendor", "")).lower().startswith("forti") else result.get("vendor", "")
    model = meta.get("Model") or str(result.get("platform", "")).split("·")[0].strip()
    live = kv(result, "runtime_identity") or kv(result, "status_live")
    if vendor == "Palo Alto":
        model = live.get("Model") or ("" if model.strip().upper() in ("PAN-OS", "") else model)
    hostname = result.get("hostname") or meta.get("Hostname", "")
    router_os = vendor not in ("Palo Alto", "Fortinet")                  # MikroTik RouterOS boxes (RB, CCR) are routers that also filter
    asset = new_asset(hostname=hostname, vendor=vendor, device_type="router" if router_os else "firewall", role="router" if router_os else "firewall", model=model,
                      serial=meta.get("Serial number") or meta.get("Serial") or live.get("Serial") or live.get("Serial-Number", ""),
                      os=meta.get("FortiOS") or (f"PAN-OS {meta['PAN-OS version']}" if meta.get("PAN-OS version") else "") or (f"PAN-OS {live['PAN-OS version']}" if live.get("PAN-OS version") else "") or _fw_os(result), source=source, analyzer="Firewall Analyzer")
    ha = str(card(result, "HA") or "").strip()
    pan_ha = kv(result, "ha")
    if not ha and pan_ha.get("Enabled", "").lower() == "yes":
        mode = pan_ha.get("Mode", "").strip()
        ha = f"HA {mode}" if mode and mode not in ("—", "-") else "HA pair (mode not in the capture)"
    ha = {"a-p": "HA active-passive (a-p)", "a-a": "HA active-active (a-a)"}.get(ha.lower(), ha)
    asset["ha"] = ha if ha and ha.lower() not in ("standalone", "none", "-", "—") else ("Panorama-managed" if total(result, "pano_devices") else "Standalone")
    cap = asset["capacity"]
    ifaces = rows(result, "interfaces")
    cap["Interfaces"] = len(ifaces)
    cap["Physical interfaces"] = sum(1 for r in ifaces if str(r.get("type", "")).lower() in ("physical", "ethernet", "ethernet (physical)", "")) if ifaces else 0
    cap["Firewall policies"] = total(result, "policies") + total(result, "security_rules")
    cap["NAT rules / VIPs"] = total(result, "nat_rules") + total(result, "vips")
    cap["Address objects"] = total(result, "addresses") + total(result, "address_objects")
    cap["VPN tunnels"] = total(result, "ipsec_tunnels") + total(result, "ipsec_p1")
    cap["Zones"] = total(result, "zones")
    cap["Static routes"] = total(result, "static_routes")
    vd = rows(result, "vdoms")
    cap["VDOMs / vsys"] = max(len(vd), total(result, "vsys_list"), 1 if asset["model"] else 0)
    if asset["model"]:
        add_component(asset, "Chassis", asset["model"], f"{vendor} {asset['model']}".strip())
        if vendor == "Fortinet" and re.fullmatch(r"FG\d[A-Z]\d[A-Z]", asset["model"]):
            asset["notes"].append(f"{asset['model']} is the model code of the configuration header, not the sales model: add get system status for the model to put on the bill of materials.")
    elif not router_os:
        hint = re.search(r"PA-?\s?(\d{3,4})", hostname or "", re.I) or re.search(r"(?:^|[-_])(\d{3,4})$", hostname or "")
        asset["notes"].append("The model is not in the capture (" + ("add show system info" if vendor == "Palo Alto" else "add get system status") + ")."
                              + (f" The hostname hints at PA-{hint.group(1)}: confirm before it goes on the bill of materials." if hint and vendor == "Palo Alto" else ""))
    if not asset["serial"] and not router_os:
        asset["notes"].append("The serial number is not in the capture (" + ("show system info" if vendor == "Palo Alto" else "get system status") + "): it is needed to match the support contract.")
    for warning in result.get("warnings") or []:               # what the analyzer says the file does not hold (Panorama-managed, no policy, several virtual systems)
        warning = str(warning).strip()
        if warning and "runtime commands are not parsed yet" not in warning:
            asset["notes"].append(warning[:400])
    licence_rows(asset, result, _FW_LICENCE_IDS)
    if text:
        licence_extra.apply(asset, text)
    if not asset["licences"] and vendor == "Fortinet" and live.get("License Status"):
        add_licence(asset, "FortiGate licence", live["License Status"], "", "State printed by get system status; the FortiGuard services and their expiry dates are held in FortiCare")
    if not asset["licences"]:
        asset["notes"].append("No licence output in the capture (" + ("add request license info" if vendor == "Palo Alto" else "add get system status / diagnose test update info; FortiGuard entitlements come from FortiCare" if vendor == "Fortinet"
                                                                  else "RouterOS: /system license print shows the licence level") + ").")
    feature_catalog(asset, result, FIREWALL_FEATURES)
    if text and not router_os:
        from .fwprofile import read_inspection
        asset["inspection"] = read_inspection(text, vendor)       # which rules inspect, carry threat profiles or decrypt: the throughput figure to size on (fwprofile.py)
    asset["notes"].append("Throughput, session counts and inspection load are not in a configuration: collect peak figures from monitoring before choosing the replacement.")
    return asset


# ---------------------------------------------------------------------------------------------------------------- load balancer (F5 BIG-IP)

LB_FEATURES = (
    ("virtuals", "Traffic", "Virtual servers"), ("virtual_addresses", "Traffic", "Virtual addresses"), ("pools", "Traffic", "Pools"), ("members", "Traffic", "Pool members"), ("nodes", "Traffic", "Nodes"),
    ("monitors", "Traffic", "Health monitors"), ("snat", "Traffic", "SNAT pools / translations"), ("persistence", "Traffic", "Persistence profiles"), ("irules", "Traffic", "iRules"),
    ("policies", "Traffic", "Local traffic policies"), ("http_profiles", "Profiles", "HTTP profiles"), ("ssl_profiles", "Profiles", "Client / server SSL profiles"),
    ("certificates", "Profiles", "Certificates"), ("data_groups", "Profiles", "Data groups"),
    ("asm_policies", "Security", "ASM / Advanced WAF policies"), ("dos_profiles", "Security", "DoS profiles"), ("apm_policies", "Security", "APM access policies"),
    ("gtm_wideips", "DNS", "GTM wide IPs"), ("gtm_pools", "DNS", "GTM pools"), ("gtm_servers", "DNS", "GTM servers"), ("gtm_datacenters", "DNS", "GTM data centers"),
    ("dns_zones", "DNS", "DNS zones"), ("vlans", "Network", "VLANs"), ("selfs", "Network", "Self IPs"), ("trunks", "Network", "Trunks"), ("route_domains", "Network", "Route domains"),
    ("routes", "Network", "Static routes"), ("tunnels", "Network", "Tunnels"), ("vcmp_guests", "Virtualisation", "vCMP guests"), ("app_services", "Virtualisation", "iApp services"),
    ("device_groups", "Redundancy", "Device groups"), ("traffic_groups", "Redundancy", "Traffic groups"), ("devices", "Redundancy", "Cluster devices"),
    ("remote_auth", "Management", "Remote authentication"), ("snmp", "Management", "SNMP"),
)


def read_lb(result: dict[str, Any], source: str = "", text: str = "") -> dict[str, Any]:
    meta = info(result)
    live = kv(result, "license_live")
    platform = str(result.get("platform", ""))
    model = meta.get("Platform") or (platform.split("·")[1].strip() if "·" in platform else platform)
    if model.strip().upper().startswith("TMOS") or model.strip().upper() in ("BIG-IP", ""):
        model = ""                                         # the software line is not a model: a show-only capture has no hardware table
    asset = new_asset(hostname=result.get("hostname", ""), vendor="F5", device_type="load_balancer", role="loadbalancer", model=model,
                      serial=live.get("Appliance serial") or meta.get("Serial number", ""), os=f"TMOS {meta['TMOS version']}" if meta.get("TMOS version") else "",
                      source=source, analyzer="Load Balancer Analyzer")
    devices = int(meta.get("Devices in cluster") or 1)
    asset["ha"] = f"HA cluster of {devices}" if devices > 1 else str(card(result, "HA") or "Standalone").capitalize()
    cap = asset["capacity"]
    def seen(config_id: str, live_id: str) -> int:
        """A show-only capture holds the live table, a configuration holds the config table; the larger of the two is what the unit carries."""
        return max(total(result, config_id), total(result, live_id))
    cap["Virtual servers"] = seen("virtuals", "virtuals_live")
    cap["Pools"] = seen("pools", "pools_live")
    cap["Pool members"] = seen("members", "pool_members_live")
    cap["Nodes"] = seen("nodes", "nodes_live")
    cap["Physical interfaces"] = total(result, "interfaces_live")
    cap["GTM pools"] = seen("gtm_pools", "gtm_pools_live")
    cap["GTM servers"] = seen("gtm_servers", "gtm_servers_live")
    cap["Self IPs"] = total(result, "selfs")
    cap["VLANs"] = total(result, "vlans")
    cap["Trunks"] = total(result, "trunks")
    cap["iRules"] = total(result, "irules")
    cap["Wide IPs"] = seen("gtm_wideips", "gtm_wideips_live")
    cap["vCMP guests"] = total(result, "vcmp_guests")
    cap["SSL profiles"] = total(result, "ssl_profiles")
    if asset["model"]:
        add_component(asset, "Chassis", asset["model"], (asset["model"] if asset["model"].upper().startswith("BIG-IP") else f"F5 BIG-IP {asset['model']}").strip())
    else:
        bundle = live.get("Bundle", "")
        code = live.get("Platform", "")
        asset["notes"].append("The hardware model is not in the capture (add tmsh show sys hardware)."
                              + (f" The licence names the bundle '{bundle}'" + (f" and platform code {code}" if code else "") + ": confirm the appliance before it goes on the bill of materials." if bundle or code else ""))
    _lb_peaks(asset, result)
    for row in rows(result, "provision") + rows(result, "provision_live"):
        module, level = first(row, "module", "name"), first(row, "level")
        if module and level.lower() not in ("none", ""):
            add_feature(asset, "Provisioned modules", f"{module.upper()} ({level})", 1)
            add_licence(asset, f"{module.upper()} module", "provisioned", "", level)
    licence_rows(asset, result, ("license_modules",))
    for item in (licence_extra.f5_licences(text) if text else []):
        add_licence(asset, item["name"], item["state"], item["expires"], item["detail"])
    if not any(l["name"] == "BIG-IP licence" for l in asset["licences"]):
        facts = [f"{label.lower()} {value}" for label in ("Licensed version", "Licensed on", "Service check date", "Platform")
                 for value in [next((str(p.get("value", "")) for p in (section(result, "license_live").get("pairs") or []) if p.get("label") == label), "")] if value]
        if facts:
            add_licence(asset, "BIG-IP licence", "installed", "", "; ".join(facts))
    for row in rows(result, "license_info"):
        add_licence(asset, first(row, "name", "feature", "module"), first(row, "status", "kind", "type"), first(row, "end", "expires", "end_date"), first(row, "start", "description"))
    if not asset["licences"]:
        asset["notes"].append("No licence output in the capture (add tmsh show sys license and list sys provision).")
    feature_catalog(asset, result, LB_FEATURES)
    if not asset["peaks"]:
        asset["notes"].append("Throughput, concurrent connections and SSL transactions per second are not in the capture: add tmsh show sys performance all-stats (or enter the peaks from monitoring) before sizing the replacement.")
    return asset


# (performance_live group, metric) -> (label, unit, scale)
_LB_PEAKS = (
    (("Throughput", "Service"), "Peak throughput (Mbit/s)", "Mbit/s", 1e-6), (("System CPU Usage", "Utilization"), "Peak CPU (%)", "%", 1),
    (("Active Connections", "Connections"), "Peak concurrent connections", "connections", 1), (("Total New Connections", "Client Connections"), "Peak new client connections/s", "/s", 1),
    (("HTTP Requests", "HTTP Requests"), "Peak HTTP requests/s", "/s", 1), (("SSL Transactions", "SSL TPS"), "Peak SSL transactions/s", "/s", 1),
    (("Memory Used", "TMM Memory Used"), "Peak TMM memory (%)", "%", 1),
)


def _lb_peaks(asset: dict[str, Any], result: dict[str, Any]) -> None:
    """tmsh show sys performance all-stats prints current, average and maximum since a time; the maximum is the peak the replacement must carry."""
    perf = rows(result, "performance_live")
    for (group, metric), label, unit, scale in _LB_PEAKS:
        row = next((r for r in perf if r.get("group") == group and r.get("metric") == metric), None)
        value = si_number(row.get("maximum")) if row else None
        if value is not None:
            add_peak(asset, label, round(value * scale, 2), unit, "capture", f"since {row.get('since', '')}".strip())


# ---------------------------------------------------------------------------------------------------------------- wireless controller (Cisco C9800, Huawei AC) and its access points

def read_wireless(result: dict[str, Any], source: str = "", text: str = "") -> list[dict[str, Any]]:
    """The controller, then one access-point record per AP model (the replacement is bought by model, not by name)."""
    data = result.get("data") or {}
    vendor = data.get("vendor") or ("Cisco" if result.get("cisco") else "Huawei")
    wlc = data.get("wlc") or {}
    serials = wlc.get("serials") or ([wlc.get("esn")] if wlc.get("esn") else [])
    hostname = wlc.get("hostname", "")
    aps = data.get("aps") or []
    asset = new_asset(hostname=hostname, vendor=vendor, device_type="wlc", role="wlc", model=wlc.get("model", ""), serial="; ".join(s for s in serials if s),
                      os=wlc.get("software_version", ""), source=source, analyzer="Wireless Analyzer")
    asset["ha"] = (wlc.get("ha_mode") or "").strip() or "Standalone"
    cap = asset["capacity"]
    cap["Access points (configured)"] = len(aps)
    joined = sum(1 for ap in aps if str(ap.get("status") or ap.get("join_status") or ap.get("state") or "").lower() in ("joined", "normal", "registered", "run"))
    cap["Access points joined"] = joined
    cap["Licensed AP capacity"] = _to_int(wlc.get("max_aps"))
    cap["Client capacity"] = _to_int(wlc.get("max_clients"))
    ssids = {str(s.get("ssid", "")).strip() for s in result.get("wlan_relationships") or [] if str(s.get("ssid", "")).strip()}
    cap["SSIDs"] = len(ssids) or int((result.get("cards") or {}).get("unique_ssids") or (result.get("cards") or {}).get("wlans") or 0)
    cap["AP groups / site tags"] = len(data.get("ap_groups") or []) or int((result.get("cards") or {}).get("site_tags") or 0)
    add_component(asset, "Chassis", asset["model"], f"{vendor} wireless controller {asset['model']}".strip())
    if text and vendor == "Cisco":
        _wlc_inventory(asset, text)
    if text and vendor == "Huawei":
        from .readers_extra import huawei_ac_extras
        huawei_ac_extras(asset, result, text)
    licenses = wlc.get("licenses") or []
    for lic in licenses:
        if isinstance(lic, dict):
            add_licence(asset, first(lic, "name", "license", "feature"), first(lic, "status", "state", "type"), first(lic, "expires", "end"), ("count " + str(lic["count"])) if lic.get("count") not in (None, "") else first(lic, "description"))
        else:
            add_licence(asset, str(lic))
    if text:
        licence_extra.apply(asset, text)
        if vendor == "Huawei" and not cap["Licensed AP capacity"]:
            for item in asset["licences"]:
                found = re.search(r"value (\d+)", item["detail"]) if re.search(r"manageable AP|AP number|number of AP", item["detail"], re.I) else None
                if found:
                    cap["Licensed AP capacity"] = int(found.group(1))
                    break
    if not asset["licences"]:
        asset["notes"].append("No licence output in the capture (Cisco: show license summary; Huawei: display license).")
    cards = result.get("cards") or {}
    for key, group, name in (("wlans", "WLAN", "WLANs"), ("vap_profiles", "WLAN", "VAP profiles"), ("policy_profiles", "WLAN", "Policy profiles"), ("policy_tags", "WLAN", "Policy tags"),
                             ("site_tags", "WLAN", "Site tags"), ("ap_groups", "WLAN", "AP groups"), ("local_users", "Management", "Local users")):
        value = cards.get(key)
        if isinstance(value, int):
            add_feature(asset, group, name, value)
    if wlc.get("mobility_group"):
        add_feature(asset, "WLAN", "Mobility group", 1)
    out = [asset]
    by_model: dict[str, list[dict[str, Any]]] = {}
    for ap in aps:
        by_model.setdefault(str(ap.get("model") or ap.get("type_id") or "Unknown model").strip() or "Unknown model", []).append(ap)
    for model, group in sorted(by_model.items(), key=lambda item: (-len(item[1]), item[0])):
        ap_asset = new_asset(hostname=f"{hostname or 'WLC'} · {model}", vendor=vendor, device_type="access_point", role="ap", model=model, os=_most_common(group, "version"),
                             source=source, analyzer="Wireless Analyzer", site=asset["site"])
        ap_asset["capacity"]["Access points"] = len(group)
        ap_asset["capacity"]["Joined"] = sum(1 for ap in group if str(ap.get("status") or ap.get("join_status") or ap.get("state") or "").lower() in ("joined", "normal", "registered", "run"))
        versions = len({str(ap.get("version")) for ap in group if ap.get("version")})
        if versions:
            ap_asset["capacity"]["Software versions in use"] = versions
        else:
            ap_asset["notes"].append("AP software versions are not in the capture (Huawei: display ap version; Cisco: show ap image).")
        add_component(ap_asset, "Access point", model, f"{vendor} access point {model}", len(group))
        ap_asset["ha"] = "Controller-managed"
        ap_asset["notes"].append("Wi-Fi standard, radios, PoE class and mounting come from the model datasheet; confirm coverage with a site survey before the refresh.")
        out.append(ap_asset)
    return out


_INVENTORY_BLOCK = re.compile(r'(?im)^NAME:\s*"([^"]*)"\s*,\s*DESCR:\s*"([^"]*)"\s*\n\s*PID:\s*(\S*)')


def _wlc_inventory(asset: dict[str, Any], text: str) -> None:
    """A controller appliance's power supplies, fans and optics from ``show inventory``: the chassis alone is not what the replacement quote needs."""
    seen: set[tuple[str, str]] = set()
    for name, descr, pid in _INVENTORY_BLOCK.findall(text):
        pid = pid.strip().strip(",")
        if not pid or pid.upper() in ("N/A", "UNKNOWN") or pid == asset["model"] or (name, pid) in seen:
            continue
        seen.add((name, pid))
        label = f"{name} {descr}".lower()
        category = "Power supply" if "power supply" in label else "Fan" if re.search(r"\bfan\b", label) else "Transceiver" if re.search(r"sfp|transceiver|qsfp", label) else ""
        if category:
            add_component(asset, category, pid, descr or name)


def _to_int(value: Any) -> int:
    match = re.search(r"\d[\d,]*", str(value or ""))
    return int(match.group(0).replace(",", "")) if match else 0


def _most_common(group: list[dict[str, Any]], key: str) -> str:
    counts: dict[str, int] = {}
    for item in group:
        if item.get(key):
            counts[str(item[key])] = counts.get(str(item[key]), 0) + 1
    return max(counts, key=counts.get) if counts else ""
