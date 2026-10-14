"""Two-device comparison for the Switch Analyzer — the "old Cisco/Aruba
vs. new Huawei draft/implemented config" parity check the migration
project needs for sizing/assessment sign-off.

Deliberately NOT a per-interface diff: interface names don't carry
across vendors (Cisco "GigabitEthernet1/0/1" vs Huawei "GE0/0/1" are the
same physical port under a completely different name), so pretending to
match them 1:1 would either require the migration_inventory.csv port
mapping (a separate, bigger feature) or produce a lot of false
"missing" rows for ports that migrated correctly under a new name. What
carries across a migration reliably is the STUFF, not the labels — VLAN
IDs, route destinations, DNS servers — so this is a set comparison on
those, plus straightforward numeric side-by-sides (interface/VLAN/route/
neighbor/PoE counts) for everything else.
"""
from __future__ import annotations

import re
from typing import Any

from . import fhrp_live, ospf_db, vpc_live
from .l3 import ifkey
from .live_state import interface_key


def _normalize_mac(mac: Any) -> str:
    """Twelve lower-case hex digits, whatever separator the vendor uses."""
    digits = "".join(ch for ch in str(mac or "").lower() if ch in "0123456789abcdef")
    return digits if len(digits) == 12 else ""


def _set_diff(a_values: set, b_values: set) -> dict[str, list]:
    return {
        "only_a": sorted(a_values - b_values, key=str),
        "only_b": sorted(b_values - a_values, key=str),
        "both": sorted(a_values & b_values, key=str),
    }


def _l3_ip_by_key(result: dict[str, Any]) -> dict[str, str]:
    """Interface key -> real (non-virtual) IP address, from this device's own
    Layer-3 interface list -- used to show each HSRP/VRRP pair's real subnet
    address next to its virtual IP in the FHRP pair-check table.

    Keyed with live_state.interface_key, the same canonicalisation
    fhrp_live.py uses for its groups, and deliberately NOT l3.ifkey: the two
    disagree on a few prefixes (plain "GigabitEthernet" canonicalises to
    "ge" here but to "gi" in l3.ifkey), so a lookup built with ifkey would
    silently miss every physical-GigabitEthernet HSRP/VRRP group while
    still working for the common SVI case."""
    return {
        interface_key(item.get("name", "")): item["address"]
        for item in (result.get("l3") or {}).get("interfaces", [])
        if "/" in str(item.get("address", ""))
    }


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _ips_from_commands(commands: list[str] | None) -> set[str]:
    """Server/host IPv4 addresses embedded in a raw config-command list: Cisco's
    ``ntp server 1.2.3.4 ...`` / ``logging server 1.2.3.4 ...``, Huawei's
    ``ntp-service unicast-server 1.2.3.4`` and the rest. Pulled out by shape
    rather than per-vendor keyword syntax — the same reasoning this module
    already uses everywhere else: diff the STUFF (the address), not the exact
    command text, which never matches across vendors anyway."""
    found: set[str] = set()
    for line in commands or []:
        found.update(_IPV4.findall(line))
    return found


def compare(result_a: dict[str, Any], result_b: dict[str, Any]) -> dict[str, Any]:
    vlan_ids_a = {str(v.get("vlan_id")) for v in result_a.get("vlans", []) if v.get("vlan_id") is not None}
    vlan_ids_b = {str(v.get("vlan_id")) for v in result_b.get("vlans", []) if v.get("vlan_id") is not None}

    routes_a = {r.get("destination") for r in result_a.get("routes", []) if r.get("destination")}
    routes_b = {r.get("destination") for r in result_b.get("routes", []) if r.get("destination")}

    dns_a = set(result_a.get("dns", {}).get("servers", []))
    dns_b = set(result_b.get("dns", {}).get("servers", []))

    # Management/AAA server parity: did the new device get every NTP / syslog / TACACS+ / RADIUS
    # server the old one had? A missed one is invisible day-to-day (the device still boots and
    # passes traffic) and only shows up later as a clock that drifted, a login event nobody
    # logged, or an admin suddenly only able to log in with the local fallback account.
    ntp_a, ntp_b = _ips_from_commands(result_a.get("ntp_commands")), _ips_from_commands(result_b.get("ntp_commands"))
    syslog_a, syslog_b = _ips_from_commands(result_a.get("logging_commands")), _ips_from_commands(result_b.get("logging_commands"))
    tacacs_a, tacacs_b = _ips_from_commands(result_a.get("tacacs_commands")), _ips_from_commands(result_b.get("tacacs_commands"))
    radius_a, radius_b = _ips_from_commands(result_a.get("radius_commands")), _ips_from_commands(result_b.get("radius_commands"))
    snmp_hosts_a = set((result_a.get("snmp") or {}).get("summary", {}).get("hosts", []) or [])
    snmp_hosts_b = set((result_b.get("snmp") or {}).get("summary", {}).get("hosts", []) or [])

    # CDP/LLDP neighbour identity: for a physical swap (old device out, new device in), the same
    # upstream/downstream neighbours showing up on both sides is the cheapest cabling confirmation
    # there is; one that only shows up on the old device is a link nobody re-terminated yet.
    neighbors_a = {row.get("neighbor_id") for row in result_a.get("neighbors", []) if row.get("neighbor_id")}
    neighbors_b = {row.get("neighbor_id") for row in result_b.get("neighbors", []) if row.get("neighbor_id")}

    # Hosts survive a migration even though port names do not, so MAC
    # addresses and ARP (IP, MAC) pairs are compared as sets. MACs are
    # normalised first: "0011.2233.4455" (Cisco), "0011-2233-4455" (Huawei)
    # and "001122-334455" (Aruba) are the same address.
    # The switch's own CPU / supervisor entries exist on every box by design and
    # are left out of the host comparison (see live_state.is_system_mac).
    macs_a = {_normalize_mac(r.get("mac_address")) for r in result_a.get("mac_table", []) if not r.get("system")} - {""}
    macs_b = {_normalize_mac(r.get("mac_address")) for r in result_b.get("mac_table", []) if not r.get("system")} - {""}
    arp_a = {
        (r.get("ip_address"), _normalize_mac(r.get("mac_address")))
        for r in result_a.get("arp_table", [])
        if r.get("ip_address") and r.get("mac_address")
    }
    arp_b = {
        (r.get("ip_address"), _normalize_mac(r.get("mac_address")))
        for r in result_b.get("arp_table", [])
        if r.get("ip_address") and r.get("mac_address")
    }

    def device_summary(result: dict) -> dict:
        os_version = result.get("os_version") or {}
        inventory = result.get("inventory") or {}
        stack = inventory.get("stack") or {}
        cards = result.get("cards") or {}
        pbr = result.get("pbr") or {}
        serial_info = result.get("serials") or {}
        vpc_mlag = result.get("vpc_mlag") or {}
        vpc_source = vpc_mlag.get("source") or "none"
        vpc_summary = vpc_mlag.get("summary") or {}
        vpc_detail = ""
        if vpc_live.is_configured(vpc_summary):
            bits = [f"domain {vpc_summary['domain_id']}" if vpc_summary.get("domain_id") else "", str(vpc_summary.get("role") or "")]
            vpc_detail = " ".join(part for part in bits if part)
        return {
            "hostname": result.get("hostname", ""),
            "vendor": result.get("vendor", ""),
            "model": os_version.get("model", ""),
            # The switch's own serial (one line per member in a stack, see
            # serials.py). Never a neighbor's or a transceiver's.
            "serial_number": serial_info.get("display", ""),
            "os_version": os_version.get("os_version", ""),
            "stack_mode": stack.get("mode", ""),
            # Single Device already surfaces this (renderResult's KV
            # list auto-labels any key it's given); Compare Devices'
            # side-by-side table uses its own hardcoded field list
            # (switch_analyzer.js renderCompareResult / excel_exporter.
            # export_comparison) and had simply never been given this
            # key, so a stacked device's member count silently
            # disappeared the moment it was put next to another device.
            "stack_member_count": stack.get("member_count", ""),
            "total_interfaces": cards.get("total_interfaces", 0),
            "interfaces_up": cards.get("interfaces_up", 0),
            "interfaces_down": cards.get("interfaces_down", 0),
            "interfaces_admin_down": cards.get("interfaces_admin_down", 0),
            "interfaces_unknown": cards.get("interfaces_unknown", 0),
            "arp_entries": cards.get("arp_entries", 0),
            "mac_entries": cards.get("mac_entries", 0),
            "total_vlans": cards.get("total_vlans", 0),
            "total_routes": cards.get("total_routes", 0),
            "neighbor_count": cards.get("neighbor_count", 0),
            "port_channel_count": cards.get("port_channel_count", 0),
            "transceiver_count": cards.get("transceiver_count", 0),
            "poe_port_count": cards.get("poe_port_count", 0),
            # vPC (Cisco) / M-LAG (Huawei): whether this device has one
            # configured at all, and whether that came from the device's own
            # live state ("show vpc" / runtime_parser.parse_vpc_mlag, refined
            # by nxos_extras.refine_vpc on NX-OS) or only from reading the
            # config with no live status to confirm it
            # (service._apply_vpc_mlag_config_fallback). The full per-device
            # summary/members detail is already shown further down the
            # Compare Devices page (vPC / M-LAG side-by-side tables); this is
            # just the quick side-by-side flag the way has_custom_routing is.
            "vpc_mlag_configured": vpc_source != "none",
            "vpc_mlag_source": vpc_source,
            "vpc_mlag_detail": vpc_detail,
            # PBR / SLA-Track / NQA -- whether this device has custom
            # routing behavior beyond a plain static/dynamic routing
            # table (see features/switch_analyzer/service.py's
            # _build_pbr_summary). A quick side-by-side flag; the full
            # per-vendor detail is in the top-level "pbr" key below.
            "has_custom_routing": bool(pbr.get("has_custom_routing")),
        }

    return {
        "device_a": device_summary(result_a),
        "device_b": device_summary(result_b),
        "vlans": _set_diff(vlan_ids_a, vlan_ids_b),
        "routes": _set_diff(routes_a, routes_b),
        "dns_servers": _set_diff(dns_a, dns_b),
        "ntp_servers": _set_diff(ntp_a, ntp_b),
        "syslog_servers": _set_diff(syslog_a, syslog_b),
        "tacacs_servers": _set_diff(tacacs_a, tacacs_b),
        "radius_servers": _set_diff(radius_a, radius_b),
        "snmp_trap_hosts": _set_diff(snmp_hosts_a, snmp_hosts_b),
        "neighbors": _set_diff(neighbors_a, neighbors_b),
        "mac_addresses": _set_diff(macs_a, macs_b),
        "arp_hosts": {
            key: [f"{ip} = {mac}" for ip, mac in values]
            for key, values in _set_diff(arp_a, arp_b).items()
        },
        # PBR/SLA-Track/NQA full detail, side by side rather than
        # set-diffed -- these are named, vendor-specific objects
        # (Cisco route-map/IP SLA vs. Huawei traffic-policy/NQA) with
        # no cross-vendor identity to diff against, the same reason
        # this module already documents for skipping a per-interface
        # diff above. A reviewer compares the two panels visually
        # instead, same as routing_protocols already works.
        "pbr": {
            "a": result_a.get("pbr") or {},
            "b": result_b.get("pbr") or {},
        },
        # Layer 3: gateways, default / static routes, OSPF, ACLs, DHCP snooping.
        "l3": l3_compare(result_a, result_b),
        # The two peers of an HSRP pair, group by group (needs `show hsrp` of both devices)
        "ospf_live": ospf_db.pair_check(result_a.get("ospf_live") or {}, result_b.get("ospf_live") or {}),
        "fhrp": fhrp_live.pair_check(
            (result_a.get("fhrp") or {}).get("groups") or [], (result_b.get("fhrp") or {}).get("groups") or [],
            ip_a=_l3_ip_by_key(result_a), ip_b=_l3_ip_by_key(result_b),
        ),
        # Spanning-tree parity: protocol, which root bridges each side can see, and any VLAN
        # where the two disagree about (or both claim) the root.
        "spanning_tree": stp_compare(result_a, result_b),
        # The two peers of a vPC / M-LAG pair: domain, role split, consistency checks, per-bundle state.
        "vpc_mlag": vpc_live.pair_check(result_a.get("vpc_mlag") or {}, result_b.get("vpc_mlag") or {}),
    }


# --------------------------------------------------------------------------
# Spanning tree
# --------------------------------------------------------------------------


def stp_compare(result_a: dict[str, Any], result_b: dict[str, Any]) -> dict[str, Any]:
    """Spanning-tree parity: same protocol, the same root bridges visible from both sides, and no
    VLAN where the two devices disagree about who the root is, or both claim the role themselves.

    A split or duplicate root is the classic symptom of an L2 topology that is not actually one
    connected tree — easy for a migration to cause by moving one uplink but not the other, or by
    standing up the new switch's trunk before its STP priority/region is configured to match."""
    a, b = result_a.get("spanning_tree") or {}, result_b.get("spanning_tree") or {}
    empty_counts = {"a_instances": 0, "b_instances": 0, "a_blocking": 0, "b_blocking": 0, "a_broken": 0, "b_broken": 0}
    if not a.get("captured") and not b.get("captured"):
        return {"captured": False, "findings": [], "protocol": {}, "root_bridges": {"only_a": [], "only_b": [], "both": []},
                "duplicate_root": [], "root_mismatch": [], "broken_ports": {"only_a": [], "only_b": [], "both": []}, "counts": empty_counts}

    findings: list[dict[str, str]] = []

    def note(level: str, code: str, text: str) -> None:
        findings.append({"level": level, "code": code, "text": text})

    proto_a, proto_b = (a.get("protocol") or "").lower(), (b.get("protocol") or "").lower()
    protocol = {"a": proto_a or "—", "b": proto_b or "—", "same": bool(proto_a) and bool(proto_b) and proto_a == proto_b}
    if proto_a and proto_b and proto_a != proto_b:
        note("warning", "stp_protocol_differs",
             f"Spanning-tree protocol differs: {proto_a.upper()} on Device A vs {proto_b.upper()} on Device B — mixing PVST+ with MST/RSTP across one "
             "topology needs the boundary handled deliberately (MST region config, PVST simulation on the MST side) or ports go into an inconsistent state.")
    elif bool(a.get("enabled")) != bool(b.get("enabled")) and (a.get("captured") and b.get("captured")):
        note("warning", "stp_enabled_differs", f"Spanning tree is {'enabled' if a.get('enabled') else 'disabled'} on Device A but "
             f"{'enabled' if b.get('enabled') else 'disabled'} on Device B.")

    def vlan_num(name: str) -> str:
        text = str(name or "")
        return text[4:].lstrip("0") or "0" if text.upper().startswith("VLAN") and text[4:].isdigit() else text

    root_a = {i.get("root_address") for i in a.get("instances", []) if i.get("root_address")}
    root_b = {i.get("root_address") for i in b.get("instances", []) if i.get("root_address")}
    root_bridges = _set_diff(root_a, root_b)
    if a.get("instances") and b.get("instances") and (root_bridges["only_a"] or root_bridges["only_b"]):
        note("info", "stp_root_visibility_differs",
             "The two devices do not see the same set of root bridges. For a pair meant to be adjacent on one Layer-2 segment, that means one of them "
             "is missing spanning-tree information the other has — usually a trunk or STP domain boundary between them; for two otherwise-unrelated "
             f"devices this is simply each one's own, separate network and not a finding on its own: only seen by A: {', '.join(root_bridges['only_a']) or 'none'}; "
             f"only seen by B: {', '.join(root_bridges['only_b']) or 'none'}.")

    root_for_a = {vlan_num(v) for v in a.get("root_for", [])}
    root_for_b = {vlan_num(v) for v in b.get("root_for", [])}
    duplicate_root = sorted(root_for_a & root_for_b, key=lambda v: int(v) if v.isdigit() else -1)
    for vlan in duplicate_root:
        note("warning", "stp_duplicate_root",
             f"VLAN {vlan}: both Device A and Device B report themselves as the STP root. If the two are meant to be adjacent on one Layer-2 segment "
             "(a pair, or an old device and its replacement in the same spot), they are not forming one spanning tree for this VLAN; if they are "
             "unrelated devices that simply happen to reuse the same VLAN number in their own separate network, this is expected and not a problem.")

    a_by_vlan = {i["vlan"]: i for i in a.get("instances", []) if i.get("vlan") is not None}
    b_by_vlan = {i["vlan"]: i for i in b.get("instances", []) if i.get("vlan") is not None}
    root_mismatch = [
        {"vlan": vlan, "a_root": a_by_vlan[vlan]["root_address"], "b_root": b_by_vlan[vlan]["root_address"]}
        for vlan in sorted(set(a_by_vlan) & set(b_by_vlan))
        if a_by_vlan[vlan].get("root_address") and b_by_vlan[vlan].get("root_address")
        and a_by_vlan[vlan]["root_address"] != b_by_vlan[vlan]["root_address"]
    ]
    for row in root_mismatch[:20]:
        note("warning", "stp_root_mismatch",
             f"VLAN {row['vlan']}: Device A sees the root bridge as {row['a_root']}, Device B sees {row['b_root']}. Only a real disagreement if the two "
             f"devices are meant to share VLAN {row['vlan']} on one Layer-2 segment — two unrelated devices with their own separate VLAN {row['vlan']} "
             "will naturally show different roots.")
    if len(root_mismatch) > 20:
        note("warning", "stp_root_mismatch_more",
             f"...and {len(root_mismatch) - 20} more VLAN(s) where Device A and Device B disagree about the root bridge (see the Spanning Tree compare table for the full list).")

    def broken_id(port: dict[str, Any]) -> str:
        return f"{port.get('instance', '')} {port.get('interface', '')}".strip()

    broken_a = {broken_id(p) for p in (a.get("broken") or [])}
    broken_b = {broken_id(p) for p in (b.get("broken") or [])}
    broken_ports = _set_diff(broken_a, broken_b)
    for side, ports in (("A", broken_a), ("B", broken_b)):
        if ports:
            shown = ", ".join(sorted(ports)[:6]) + ("…" if len(ports) > 6 else "")
            note("warning", "stp_inconsistent_port", f"Device {side} has {len(ports)} port(s) in an STP-inconsistent state: {shown}.")

    return {
        "captured": True, "findings": findings, "protocol": protocol, "root_bridges": root_bridges,
        "duplicate_root": duplicate_root, "root_mismatch": root_mismatch, "broken_ports": broken_ports,
        "counts": {
            "a_instances": len(a.get("instances", [])), "b_instances": len(b.get("instances", [])),
            "a_blocking": a.get("blocking", 0) or 0, "b_blocking": b.get("blocking", 0) or 0,
            "a_broken": len(a.get("broken", []) or []), "b_broken": len(b.get("broken", []) or []),
        },
    }


# --------------------------------------------------------------------------
# Layer 3
# --------------------------------------------------------------------------


def _vlan_numbers(items: list[Any]) -> set[int]:
    """VLAN ids from the forms the DHCP-snooping lists use: "53", "10,20",
    "700-701", "1 to 4094", "10 20 30"."""
    found: set[int] = set()
    for item in items or []:
        text = str(item).strip().lower()
        for low, high in re.findall(r"(\d+)\s*(?:to|-)\s*(\d+)", text):
            low_i, high_i = int(low), int(high)
            if 0 < low_i <= high_i <= 4094:
                found.update(range(low_i, high_i + 1))
        rest = re.sub(r"(\d+)\s*(?:to|-)\s*(\d+)", " ", text)
        found.update(int(token) for token in re.findall(r"\d+", rest) if 0 < int(token) <= 4094)
    return found


def _compress(numbers: set[int]) -> str:
    out: list[str] = []
    ordered = sorted(numbers)
    index = 0
    while index < len(ordered):
        end = index
        while end + 1 < len(ordered) and ordered[end + 1] == ordered[end] + 1:
            end += 1
        out.append(str(ordered[index]) if end == index else f"{ordered[index]}-{ordered[end]}")
        index = end + 1
    return ", ".join(out)


def _l3_side(result: dict[str, Any]) -> dict[str, Any]:
    return result.get("l3") or {
        "interfaces": [], "default_routes": [], "static_routes": [], "routing_table": {},
        "ospf": {"configured": False, "processes": [], "interfaces": [], "findings": []},
        "acls": {"definitions": [], "bindings": []}, "findings": [],
    }


def _iface_cell(item: dict[str, Any] | None) -> dict[str, Any]:
    if not item:
        return {"name": "", "address": "", "secondary": [], "helpers": [], "acl": "", "virtual_ip": "", "ospf_area": "", "status": "", "shutdown": False}
    acls = [name for name in (item.get("acl_in"), item.get("acl_out")) if name]
    acls += [f"{pol['policy']} ({pol['direction']})" for pol in item.get("traffic_policies", [])]
    acls += [f"{flt['acl']} ({flt['direction']})" for flt in item.get("traffic_filters", [])]
    return {
        "name": item.get("name", ""), "address": item.get("address", ""), "secondary": list(item.get("secondary") or []),
        "helpers": list(item.get("helpers") or []), "acl": ", ".join(acls), "virtual_ip": item.get("virtual_ip", ""),
        "ospf_area": item.get("ospf_area", ""), "status": item.get("status", ""), "shutdown": bool(item.get("shutdown")),
    }


def _compare_l3_interfaces(a_rows: list[dict[str, Any]], b_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per Layer-3 interface. SVIs, loopbacks and port-channels carry the
    same key on both vendors (Vlan53 = Vlanif53, Eth-Trunk1 = Port-channel1);
    anything left over is matched on its IP address, because a gateway address
    that moved to another interface is exactly what a migration check must show."""
    a_by = {item["key"]: item for item in a_rows}
    b_by = {item["key"]: item for item in b_rows}
    rows: list[dict[str, Any]] = []
    used_a: set[str] = set()
    used_b: set[str] = set()

    def add(key_a: str | None, key_b: str | None, status: str) -> None:
        item_a, item_b = a_by.get(key_a or ""), b_by.get(key_b or "")
        base = item_a or item_b
        rows.append({
            "label": base["name"] if base else "", "kind": base["kind"] if base else "", "status": status,
            "a": _iface_cell(item_a), "b": _iface_cell(item_b),
            "sort": (0 if base and base["kind"] == "SVI" else 1, base.get("vlan_id") or 0 if base else 0, base["key"] if base else ""),
        })

    for key in a_by:
        if key in b_by:
            used_a.add(key)
            used_b.add(key)
            a_item, b_item = a_by[key], b_by[key]
            same_ip = a_item["address"] == b_item["address"] and sorted(a_item["secondary"]) == sorted(b_item["secondary"])
            add(key, key, "same" if same_ip else "changed")
    left_a = [item for item in a_rows if item["key"] not in used_a]
    left_b = [item for item in b_rows if item["key"] not in used_b]
    for item_a in list(left_a):
        if not item_a["ip"]:
            continue
        match = next((item for item in left_b if item["address"] == item_a["address"]), None)
        if match is not None:
            used_a.add(item_a["key"])
            used_b.add(match["key"])
            left_a.remove(item_a)
            left_b.remove(match)
            add(item_a["key"], match["key"], "moved")
    for item in left_a:
        add(item["key"], None, "only a")
    for item in left_b:
        add(None, item["key"], "only b")
    rows.sort(key=lambda row: row["sort"])
    for row in rows:
        row.pop("sort")
    return rows


def _compare_static_routes(a_routes: list[dict[str, Any]], b_routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def group(routes: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
        out: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for route in routes:
            out.setdefault((route["vrf"], route["cidr"]), []).append(route)
        return out

    ga, gb = group(a_routes), group(b_routes)
    rows = []
    for key in sorted(set(ga) | set(gb), key=lambda k: (k[0], k[1] != "0.0.0.0/0", k[1])):
        ra, rb = ga.get(key, []), gb.get(key, [])
        hops_a = sorted({r["next_hop"] or r["interface"] for r in ra})
        hops_b = sorted({r["next_hop"] or r["interface"] for r in rb})
        dist_a = sorted({str(r["distance"]) for r in ra if r["distance"] is not None})
        dist_b = sorted({str(r["distance"]) for r in rb if r["distance"] is not None})
        if ra and rb:
            status = "same" if hops_a == hops_b else "changed"
        else:
            status = "only a" if ra else "only b"
        rows.append({
            "vrf": key[0], "cidr": key[1], "status": status,
            "a_next_hop": ", ".join(hops_a), "b_next_hop": ", ".join(hops_b),
            "a_distance": ", ".join(dist_a), "b_distance": ", ".join(dist_b),
            "a_description": "; ".join(sorted({r["description"] for r in ra if r["description"]})),
            "b_description": "; ".join(sorted({r["description"] for r in rb if r["description"]})),
        })
    return rows


def _ospf_side(l3_data: dict[str, Any]) -> dict[str, Any]:
    ospf = l3_data["ospf"]
    running = bool(ospf["interfaces"])
    if not ospf["configured"]:
        state = "Not configured"
    elif running:
        state = "Running"
    else:
        state = "Configured, not running"
    process = ospf["processes"][0] if ospf["processes"] else {}
    networks = sorted({net["cidr"] + f" area {net['area']}" for proc in ospf["processes"] for net in proc["networks"]})
    return {
        "state": state, "running": running, "configured": ospf["configured"],
        "process": ", ".join(proc["id"] or "(default)" for proc in ospf["processes"]),
        "router_id": ", ".join(proc["router_id"] for proc in ospf["processes"] if proc["router_id"]),
        "areas": sorted({area for proc in ospf["processes"] for area in proc.get("areas", [])}),
        "networks": networks,
        "interfaces": sorted(f"{row['interface']} (area {row['area']}{', passive' if row['passive'] else ''})" for row in ospf["interfaces"]),
        "interface_keys": {ifkey(row["interface"]): row["area"] for row in ospf["interfaces"]},
        "redistribute": sorted({item for proc in ospf["processes"] for item in proc["redistribute"]}),
        "passive_default": any(proc["passive_default"] for proc in ospf["processes"]),
        "has_process_detail": bool(process),
    }


def _compare_acls(a_acls: dict[str, Any], b_acls: dict[str, Any]) -> list[dict[str, Any]]:
    def view(acls: dict[str, Any]) -> dict[str, dict[str, Any]]:
        applied: dict[str, list[str]] = {}
        for binding in acls.get("bindings", []):
            if binding["acl"]:
                applied.setdefault(binding["acl"], []).append(f"{binding['target']} {binding['direction']}")
        out = {}
        for item in acls.get("definitions", []):
            out[item["name"]] = {
                "rules": item["rules"], "applied": sorted(set(applied.get(item["name"], []))), "system": item["system"],
                "referenced_by": item.get("referenced_by", []), "kind": item.get("kind", ""),
            }
        return out

    va, vb = view(a_acls), view(b_acls)
    rows = []
    for name in sorted(set(va) | set(vb), key=str.lower):
        ia, ib = va.get(name), vb.get(name)
        if ia and ib:
            status = "same" if ia["rules"] == ib["rules"] and bool(ia["applied"]) == bool(ib["applied"]) else "changed"
        else:
            status = "only a" if ia else "only b"
        rows.append({
            "name": name, "status": status, "system": bool((ia or ib)["system"]),
            "a_rules": ia["rules"] if ia else "", "b_rules": ib["rules"] if ib else "",
            "a_applied": ", ".join(ia["applied"]) if ia else "", "b_applied": ", ".join(ib["applied"]) if ib else "",
            "a_referenced": "; ".join(ia["referenced_by"]) if ia else "", "b_referenced": "; ".join(ib["referenced_by"]) if ib else "",
        })
    return rows


def l3_compare(result_a: dict[str, Any], result_b: dict[str, Any]) -> dict[str, Any]:
    a, b = _l3_side(result_a), _l3_side(result_b)
    findings: list[dict[str, str]] = []

    def note(level: str, code: str, text: str) -> None:
        findings.append({"level": level, "code": code, "text": text})

    # ---- gateways / Layer-3 interfaces
    interfaces = _compare_l3_interfaces(a["interfaces"], b["interfaces"])
    for row in interfaces:
        label = row["label"]
        if row["status"] == "changed":
            note("warning", "l3_address_changed",
                 f"{label}: address changed from {row['a']['address'] or 'none'} (Device A) to {row['b']['address'] or 'none'} (Device B).")
        elif row["status"] == "moved":
            note("warning", "l3_address_moved",
                 f"{row['a']['address']} is on {row['a']['name']} on Device A but on {row['b']['name']} on Device B.")
        elif row["status"] == "only a" and not row["a"]["shutdown"] and "/" in row["a"]["address"]:
            note("warning", "l3_interface_missing_b",
                 f"{label} ({row['a']['address']}) exists only on Device A: hosts in that subnet have no gateway on Device B.")
        elif row["status"] == "only b" and "/" in row["b"]["address"]:
            note("info", "l3_interface_only_b", f"{label} ({row['b']['address']}) exists only on Device B.")
        if row["status"] in {"same", "changed", "moved"}:
            ha, hb = sorted(row["a"]["helpers"]), sorted(row["b"]["helpers"])
            if ha != hb:
                note("warning", "dhcp_helper_differs",
                     f"{label}: DHCP relay servers differ — Device A {', '.join(ha) or 'none'}; Device B {', '.join(hb) or 'none'}.")
            # HSRP/VRRP virtual IP configured on this gateway interface
            # (l3.py's own "virtual_ip" field, read straight off the
            # interface's hsrp/vrrp sub-commands -- the live Active/Standby
            # role check is the separate FHRP pair-check table below, which
            # needs `show hsrp`/`display vrrp`; this is config-only and
            # works even without it).
            va, vb = row["a"]["virtual_ip"], row["b"]["virtual_ip"]
            if va and vb and va != vb:
                note("warning", "l3_fhrp_virtual_ip_differs",
                     f"{label}: HSRP/VRRP virtual IP differs — Device A {va}, Device B {vb}.")
            elif va and not vb:
                note("info", "l3_fhrp_virtual_ip_only_a", f"{label}: HSRP/VRRP virtual IP {va} is configured on Device A only.")
            elif vb and not va:
                note("info", "l3_fhrp_virtual_ip_only_b", f"{label}: HSRP/VRRP virtual IP {vb} is configured on Device B only.")

    # ---- default route
    def default_view(side: dict[str, Any]) -> dict[str, Any]:
        hops = sorted({row["next_hop"] for row in side["default_routes"] if row["next_hop"]})
        return {"next_hops": hops, "via": ", ".join(sorted({row["via"] for row in side["default_routes"]}))}

    da, db = default_view(a), default_view(b)
    if da["next_hops"] and db["next_hops"]:
        default_status = "same" if da["next_hops"] == db["next_hops"] else "changed"
    elif da["next_hops"]:
        default_status = "only a"
    elif db["next_hops"]:
        default_status = "only b"
    else:
        default_status = "none"
    if default_status == "changed":
        note("warning", "default_route_changed",
             f"Default route next hop changed from {', '.join(da['next_hops'])} (Device A) to {', '.join(db['next_hops'])} (Device B).")
    elif default_status == "only a":
        note("warning", "default_route_missing_b", f"Device A has a default route via {', '.join(da['next_hops'])}; Device B has none.")
    elif default_status == "only b":
        note("info", "default_route_only_b", f"Device B has a default route via {', '.join(db['next_hops'])}; Device A has none.")

    # ---- static routes (default route is its own block above; keep it in the table too)
    statics = _compare_static_routes(a["static_routes"], b["static_routes"])
    for row in statics:
        if row["cidr"] == "0.0.0.0/0":
            continue
        if row["status"] == "changed":
            note("warning", "static_route_changed",
                 f"Static route {row['cidr']}: next hop {row['a_next_hop']} (Device A) vs {row['b_next_hop']} (Device B).")
        elif row["status"] == "only a":
            note("warning", "static_route_missing_b", f"Static route {row['cidr']} via {row['a_next_hop']} exists only on Device A.")
        elif row["status"] == "only b":
            note("info", "static_route_only_b", f"Static route {row['cidr']} via {row['b_next_hop']} exists only on Device B.")

    # ---- OSPF
    oa, ob = _ospf_side(a), _ospf_side(b)
    if oa["running"] and not ob["configured"]:
        note("warning", "ospf_missing_b",
             "OSPF is running on Device A but Device B has no OSPF process: routes learned by OSPF disappear unless static routes replace them.")
    elif oa["running"] and not ob["running"]:
        note("warning", "ospf_not_running_b", "OSPF is running on Device A, but Device B's OSPF process has no interface that runs it.")
    elif oa["running"] and ob["running"]:
        areas_a = {ifk: area for ifk, area in oa["interface_keys"].items()}
        areas_b = {ifk: area for ifk, area in ob["interface_keys"].items()}
        for ifk in sorted(set(areas_a) & set(areas_b)):
            if areas_a[ifk] != areas_b[ifk]:
                note("warning", "ospf_area_differs", f"{ifk}: OSPF area {areas_a[ifk]} on Device A vs area {areas_b[ifk]} on Device B.")
        for ifk in sorted(set(areas_a) - set(areas_b)):
            note("warning", "ospf_interface_missing_b", f"{ifk} runs OSPF (area {areas_a[ifk]}) on Device A but not on Device B.")
    elif oa["configured"] and not oa["running"] and not ob["configured"]:
        note("info", "ospf_inactive_a",
             "Device A has an OSPF process that no interface runs, so it carries no routes; Device B having none behaves the same.")
    elif ob["running"] and not oa["running"]:
        note("info", "ospf_only_b", "OSPF runs on Device B but not on Device A.")

    # ---- ACLs
    acls = _compare_acls(a["acls"], b["acls"])
    for row in acls:
        if row["system"]:
            continue
        if row["status"] == "only a":
            note("warning", "acl_missing_b", f"ACL {row['name']} ({row['a_rules']} rules) exists only on Device A.")
        elif row["status"] == "only b":
            note("info", "acl_only_b", f"ACL {row['name']} ({row['b_rules']} rules) exists only on Device B.")
        elif row["status"] == "changed":
            note("info", "acl_changed", f"ACL {row['name']}: {row['a_rules']} rules on Device A, {row['b_rules']} on Device B; check the rule text.")

    # ---- DHCP snooping
    sa = (result_a.get("dhcp") or {}).get("snooping") or {}
    sb = (result_b.get("dhcp") or {}).get("snooping") or {}
    vlans_a, vlans_b = _vlan_numbers(sa.get("vlans", [])), _vlan_numbers(sb.get("vlans", []))
    snooping = {
        "a_enabled": bool(sa.get("enabled")), "b_enabled": bool(sb.get("enabled")),
        "a_vlans": _compress(vlans_a), "b_vlans": _compress(vlans_b),
        "only_a": _compress(vlans_a - vlans_b), "only_b": _compress(vlans_b - vlans_a),
        "a_trusted": list(sa.get("trusted_interfaces", [])), "b_trusted": list(sb.get("trusted_interfaces", [])),
    }
    if snooping["a_enabled"] and not snooping["b_enabled"]:
        note("warning", "dhcp_snooping_missing_b", "DHCP snooping is enabled on Device A but not on Device B.")
    elif snooping["a_enabled"] and snooping["b_enabled"] and vlans_a and vlans_b and vlans_a != vlans_b:
        note("info", "dhcp_snooping_vlans_differ",
             f"DHCP snooping VLANs differ: only on Device A: {snooping['only_a'] or 'none'}; only on Device B: {snooping['only_b'] or 'none'}.")

    # ---- routing behaviour that changes with the platform
    if any(item["code"] == "ip_routing_off" for item in a["findings"]):
        b_active = {item["network"] for item in b["interfaces"] if item["kind"] == "SVI" and item["ip"] and not item["shutdown"]}
        if len(b_active) >= 2:
            note("info", "inter_vlan_routing_new",
                 "Device A does not route between its VLAN interfaces (no `ip routing`); Device B has several active Vlanif interfaces and "
                 "does route between them, so inter-VLAN traffic that used to leave through the upstream gateway is now routed on the switch.")

    # Keep one finding per (code, text); level order warning, info.
    seen: set[tuple[str, str]] = set()
    ordered: list[dict[str, str]] = []
    for item in sorted(findings, key=lambda f: 0 if f["level"] == "warning" else 1):
        key = (item["code"], item["text"])
        if key not in seen:
            seen.add(key)
            ordered.append(item)

    return {
        "findings": ordered,
        "interfaces": interfaces,
        "default_route": {"status": default_status, "a": da, "b": db},
        "static_routes": statics,
        "ospf": {"a": {k: v for k, v in oa.items() if k != "interface_keys"}, "b": {k: v for k, v in ob.items() if k != "interface_keys"}},
        "acls": acls,
        "dhcp_snooping": snooping,
        "device_findings": {"a": a["findings"], "b": b["findings"]},
    }
