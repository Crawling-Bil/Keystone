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

from typing import Any


def _set_diff(a_values: set, b_values: set) -> dict[str, list]:
    return {
        "only_a": sorted(a_values - b_values, key=str),
        "only_b": sorted(b_values - a_values, key=str),
        "both": sorted(a_values & b_values, key=str),
    }


def compare(result_a: dict[str, Any], result_b: dict[str, Any]) -> dict[str, Any]:
    vlan_ids_a = {str(v.get("vlan_id")) for v in result_a.get("vlans", []) if v.get("vlan_id") is not None}
    vlan_ids_b = {str(v.get("vlan_id")) for v in result_b.get("vlans", []) if v.get("vlan_id") is not None}

    routes_a = {r.get("destination") for r in result_a.get("routes", []) if r.get("destination")}
    routes_b = {r.get("destination") for r in result_b.get("routes", []) if r.get("destination")}

    dns_a = set(result_a.get("dns", {}).get("servers", []))
    dns_b = set(result_b.get("dns", {}).get("servers", []))

    def device_summary(result: dict) -> dict:
        os_version = result.get("os_version") or {}
        inventory = result.get("inventory") or {}
        stack = inventory.get("stack") or {}
        cards = result.get("cards") or {}
        pbr = result.get("pbr") or {}
        return {
            "hostname": result.get("hostname", ""),
            "vendor": result.get("vendor", ""),
            "model": os_version.get("model", ""),
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
            "total_vlans": cards.get("total_vlans", 0),
            "total_routes": cards.get("total_routes", 0),
            "neighbor_count": cards.get("neighbor_count", 0),
            "port_channel_count": cards.get("port_channel_count", 0),
            "transceiver_count": cards.get("transceiver_count", 0),
            "poe_port_count": cards.get("poe_port_count", 0),
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
    }
