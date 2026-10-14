"""Which port-channel / Eth-Trunk / LAG each physical port belongs to.

The Interfaces tab shows a "Port-channel" column so a reader sees at once that Ethernet1/45 is a member of
Po1 without opening the Port-Channel tab. The membership is read from three places, in this order of
trust:

1. The live bundle table (``show etherchannel summary`` / ``show port-channel summary`` / ``display eth-trunk``
   / ArubaOS-CX ``show lag``), already parsed into ``port_channels`` with one flag per member.
2. The live LACP table (``show lacp neighbor`` on NX-OS and IOS): a port that has an LACP partner in group N.
3. The configuration: ``channel-group N mode ...`` (Cisco), ``eth-trunk N`` (Huawei), ``lag N`` (ArubaOS-CX).

A bundle that is configured but missing from the live table (a capture without ``show port-channel
summary``) still gets a row in the Port-Channel tab, built from 2 and 3, and says where it came from.
"""
from __future__ import annotations

import re
from typing import Any

from . import live_state

_TRAILING_ID = re.compile(r"(\d+)\s*$")


def _bundle_id(name: str) -> str:
    match = _TRAILING_ID.search(name or "")
    return str(int(match.group(1))) if match else ""


def short_name(name: str) -> str:
    """port-channel101 -> Po101 (Cisco's own short form); Eth-Trunk1 and lag1 are printed as they are."""
    return re.sub(r"^(?:port-channel|portchannel)(?=\d)", "Po", (name or "").strip(), flags=re.IGNORECASE)


def _is_bundle(name: str) -> bool:
    return live_state.interface_key(name).startswith("po") and bool(_bundle_id(name))


def _member_names(pc: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``[(port, flag, meaning)]`` of one live bundle row."""
    states = pc.get("member_states") or []
    if states:
        return [(str(item.get("port", "")), str(item.get("flag", "")), str(item.get("meaning", ""))) for item in states if item.get("port")]
    return [(port, "", "") for port in re.split(r"[,\s]+", str(pc.get("members") or "")) if port and port != "-"]


def _lacp_state(row: dict[str, Any]) -> tuple[str, str]:
    """(flag, meaning) of one ``show lacp neighbor`` row: collecting and distributing = bundled."""
    if row.get("healthy"):
        return "P", "bundled, LACP partner collecting and distributing"
    bits = str(row.get("state_bits") or "").strip()
    return "", f"LACP partner state: {bits}" if bits else "LACP partner not collecting and distributing"


def default_prefix(vendor: str, aoscx: bool = False) -> str:
    """What the platform calls a bundle when the capture has no interface of that name: Eth-Trunk (Huawei), lag (ArubaOS-CX), Trk (ArubaOS-Switch), Po."""
    if aoscx:
        return "lag"
    return {"huawei": "Eth-Trunk", "aruba": "Trk"}.get((vendor or "").lower(), "Po")


def build(interfaces: list[dict[str, Any]], port_channels: list[dict[str, Any]], lacp_rows: list[dict[str, Any]] | None,
          config_interfaces: list[Any] | None, prefix: str = "Po") -> dict[str, Any]:
    """Adds ``bundle`` / ``bundle_id`` / ``bundle_mode`` / ``bundle_state`` to every member port in ``interfaces`` and
    ``bundle_members`` to every bundle interface, appends a Port-Channel row for a bundle the live table did not list.
    Returns ``{"members": {interface_key: entry}, "bundles": {id: label}, "added": n}``."""
    members: dict[str, dict[str, Any]] = {}

    def remember(port: str, bundle_id: str, *, mode: str = "", flag: str = "", meaning: str = "", source: str) -> None:
        if not port or not bundle_id:
            return
        key = live_state.interface_key(port)
        entry = members.setdefault(key, {"port": port, "id": bundle_id, "mode": "", "flag": "", "meaning": "", "sources": []})
        if entry["id"] != bundle_id:
            return                      # two sources disagree: keep the first (the live table is read first)
        if mode and (not entry["mode"] or entry["mode"] == "LACP"):
            entry["mode"] = mode           # Cisco's own word (active / passive / static) beats the generic "LACP" a partner table implies
        entry["flag"] = entry["flag"] or flag
        entry["meaning"] = entry["meaning"] or meaning
        if source not in entry["sources"]:
            entry["sources"].append(source)

    live_ids: set[str] = set()
    for pc in port_channels:
        bundle_id = _bundle_id(str(pc.get("name", "")))
        if not bundle_id:
            continue
        live_ids.add(bundle_id)
        for port, flag, meaning in _member_names(pc):
            remember(port, bundle_id, flag=flag, meaning=meaning, source="bundle table")
    for row in lacp_rows or []:
        group = str(row.get("group") or "").strip()
        if group.isdigit() and row.get("port"):
            flag, meaning = _lacp_state(row)
            remember(str(row["port"]), str(int(group)), mode="LACP", flag=flag, meaning=meaning, source="show lacp neighbor")
    for item in config_interfaces or []:
        group = getattr(item, "channel_group", None)
        if group is None:
            continue
        mode = getattr(item, "lacp_mode", "") or ""
        # Huawei keeps the LACP line of the interface here ("lacp timeout fast"), not a mode: only Cisco's words are modes
        remember(item.name, str(int(group)), mode=mode if mode in ("active", "passive", "static") else "", source="configuration")

    for entry in members.values():
        if not entry["meaning"] and entry["sources"] == ["configuration"]:
            # a port the configuration puts in the bundle but no live table lists: with the LACP table captured, that is a finding in itself
            entry["meaning"] = "configured as a member, not listed in show lacp neighbor" if lacp_rows else "configured as a member (no live bundle table in this capture)"

    by_key = {live_state.interface_key(item["name"]): item for item in interfaces}
    for key, entry in members.items():
        if key in by_key:
            entry["port"] = by_key[key]["name"]     # one spelling per port: the Interfaces tab's ("Ethernet1/1", not "Eth1/1")
    labels: dict[str, str] = {}
    for bundle_id in {entry["id"] for entry in members.values()}:
        bundle_if = by_key.get(f"po{bundle_id}")
        labels[bundle_id] = short_name(bundle_if["name"]) if bundle_if else f"{prefix}{bundle_id}"
    for pc in port_channels:
        bundle_id = _bundle_id(str(pc.get("name", "")))
        if bundle_id:
            labels[bundle_id] = short_name(str(pc["name"]))

    per_bundle: dict[str, list[dict[str, Any]]] = {}
    for key, entry in members.items():
        item = by_key.get(key)
        state = entry["meaning"] or ("" if not entry["flag"] else entry["flag"])
        entry["state"] = state
        entry["label"] = labels[entry["id"]]
        if item is not None:
            item["bundle"] = labels[entry["id"]]
            item["bundle_id"] = entry["id"]
            item["bundle_mode"] = entry["mode"]
            item["bundle_state"] = state
        per_bundle.setdefault(entry["id"], []).append(entry)
    for bundle_id, entries in per_bundle.items():
        bundle_if = by_key.get(f"po{bundle_id}")
        if bundle_if is not None:
            bundle_if["bundle_members"] = [{"port": e["port"], "state": e["state"], "mode": e["mode"]} for e in sorted(entries, key=lambda e: e["port"])]

    added = 0
    for bundle_id in sorted(per_bundle, key=int):
        if bundle_id in live_ids:
            continue
        entries = sorted(per_bundle[bundle_id], key=lambda e: e["port"])
        bundle_if = by_key.get(f"po{bundle_id}") or {}
        lacp = any("show lacp neighbor" in e["sources"] or e["mode"] in ("active", "passive", "LACP") for e in entries)
        protocol = "LACP" if lacp else "static" if any(e["mode"] == "static" for e in entries) else ""
        port_channels.append({
            "name": labels[bundle_id], "protocol": protocol, "status": bundle_if.get("status", ""), "members": ", ".join(e["port"] for e in entries),
            "member_states": [{"port": e["port"], "flag": e["flag"], "meaning": e["meaning"]} for e in entries],
            "description": bundle_if.get("description", ""), "mode": bundle_if.get("mode", ""), "vlan": bundle_if.get("vlan", ""),
            "allowed_vlans": bundle_if.get("allowed_vlans", ""), "ip_address": bundle_if.get("ip_address", ""),
            "source": "configuration and show lacp neighbor (this capture has no bundle summary)",
        })
        added += 1
    return {"members": members, "bundles": labels, "added": added}
