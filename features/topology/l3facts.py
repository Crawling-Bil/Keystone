"""The layer-3 facts of one device that the L3 views need and the switch reader does not give: routes by next hop, routing
neighbors, SD-WAN overlay sessions, tunnels and interface state.

They come from the Router Analyzer's reader (``router_analyzer.context.gather``), which understands the same captures
(``show ip route``, ``show ip ospf neighbor``, ``show ip bgp summary``, ``show sdwan bfd sessions`` ...).  Interface addresses and
prefix lengths stay with the switch reader (``Device.l3``): both readers see the same configuration.

Routes are aggregated while reading: one row per (VRF, protocol, next hop, egress interface) with a count and the first prefixes,
so a router with a full BGP table does not put a hundred thousand rows into the diagram state.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from .names import canon_port

MAX_PREFIXES = 3000          # prefixes kept per next hop (the path trace needs them; the tables show the first 200)
_LOCAL = {"connected", "local", "c", "l"}


def _state(brief: dict[str, Any] | None, cfg: dict[str, Any] | None) -> str:
    if cfg and cfg.get("shutdown"):
        return "admin down"
    if brief:
        status, protocol = str(brief.get("status", "")), str(brief.get("protocol", ""))
        if status.startswith("administratively"):
            return "admin down"
        if status and protocol:
            return f"{status}/{protocol}"
    return ""


def _routes(ctx: Any) -> list[dict[str, Any]]:
    groups: OrderedDict[tuple[str, str, str, str], dict[str, Any]] = OrderedDict()
    for route in ctx.routes or []:
        protocol = str(route.get("protocol", "")).lower()
        if protocol in _LOCAL:
            continue
        for hop in route.get("next_hops") or []:
            via = str(hop.get("via", ""))
            if not via:
                continue
            key = (str(route.get("vrf", "")) or "global", protocol, via, canon_port(str(hop.get("interface", ""))))
            entry = groups.setdefault(key, {"vrf": key[0], "protocol": protocol, "next_hop": via, "interface": key[3], "count": 0, "prefixes": [], "default": False})
            entry["count"] += 1
            prefix = str(route.get("prefix", ""))
            if prefix == "0.0.0.0/0":
                entry["default"] = True
            if len(entry["prefixes"]) < MAX_PREFIXES:
                entry["prefixes"].append(prefix)
    return list(groups.values())


def _neighbors(ctx: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in ctx.get("ospf_neighbors") or []:
        out.append({"protocol": "ospf", "address": row.get("address", ""), "id": row.get("neighbor_id", ""), "interface": canon_port(str(row.get("interface", ""))), "state": f"{row.get('state', '')}", "vrf": row.get("vrf", "")})
    for row in ctx.get("eigrp_neighbors") or []:
        out.append({"protocol": "eigrp", "address": row.get("address", ""), "id": "", "interface": canon_port(str(row.get("interface", ""))), "state": "up", "vrf": row.get("vrf", "")})
    for row in ctx.get("bgp_neighbors") or []:
        out.append({"protocol": "bgp", "address": row.get("neighbor", ""), "id": "", "interface": "", "state": str(row.get("state", "")), "vrf": row.get("vrf", ""), "remote_as": str(row.get("remote_as", ""))})
    return out


def _overlay(ctx: Any) -> list[dict[str, Any]]:
    return [{"system_ip": row.get("system_ip", ""), "site_id": row.get("site_id", ""), "state": str(row.get("state", "")), "local_color": row.get("source_color", ""), "remote_color": row.get("remote_color", ""),
             "local_ip": row.get("source_ip", ""), "remote_ip": row.get("dst_public_ip", ""), "encap": row.get("encap", "")} for row in ctx.get("sdwan_bfd") or []]


def _tunnels(ctx: Any) -> list[dict[str, Any]]:
    out = []
    for rec in ctx.interfaces or []:
        cfg = rec.get("config") or {}
        tunnel = cfg.get("tunnel") or {}
        if tunnel:
            out.append({"name": canon_port(str(rec.get("name", ""))), "source": str(tunnel.get("source", "")), "destination": str(tunnel.get("destination", "")), "mode": str(tunnel.get("mode", "")),
                        "vrf": str(cfg.get("vrf", "")), "description": str(cfg.get("description", "")), "ip": str(cfg.get("ip_address", ""))})
    return out


def _interfaces(ctx: Any) -> list[dict[str, Any]]:
    """Routed interfaces in the shape of ``Device.l3`` (used when the switch reader could not read the capture at all)."""
    rows = []
    for rec in ctx.interfaces or []:
        cfg = rec.get("config") or {}
        address = str(cfg.get("ip_address", ""))
        if "/" not in address:
            continue
        ip, plen = address.split("/", 1)
        name = canon_port(str(rec.get("name", "")))
        low = name.lower()
        kind = "Loopback" if low.startswith(("lo",)) else "SVI" if low.startswith("vlan") else "Tunnel" if cfg.get("tunnel") or low.startswith("tu") else "Routed"
        rows.append({"name": name, "ip": ip, "prefix_len": int(plen) if plen.isdigit() else None, "vrf": str(cfg.get("vrf", "")), "kind": kind, "shutdown": bool(cfg.get("shutdown")),
                     "description": str(cfg.get("description", "")), "status": _state(rec.get("brief"), cfg), "secondary": [str(x) for x in (cfg.get("ip_secondary") or [])][:4]})
    return [r for r in rows if r["prefix_len"] is not None]


def read(text: str, name: str = "") -> dict[str, Any]:
    """Facts of one capture; ``{}`` when the Router Analyzer's reader finds nothing it can use."""
    from ..router_analyzer import context as ctxmod       # imported here: the reader is large and only L3 views need it
    try:
        ctx = ctxmod.gather(text, name)
    except ValueError:                                     # not a Cisco capture the reader understands
        return {}
    if not ctx.used_blocks:
        return {}
    system = (ctx.sdwan_cfg or {}).get("system", {}) if ctx.sdwan_cfg else {}
    state = {canon_port(str(rec.get("name", ""))): _state(rec.get("brief"), rec.get("config")) for rec in ctx.interfaces or []}
    colours = {canon_port(str(t.get("interface", ""))): str(t.get("color", "")) for t in ((ctx.sdwan_cfg or {}).get("tunnel_interfaces", []) if ctx.sdwan_cfg else [])}
    dialect = getattr(ctx, "dialect", {}) or {}
    facts = {"hostname": str(ctx.hostname or ""), "model": str(dialect.get("model") or ""), "release": str(dialect.get("release") or ""), "interfaces": _interfaces(ctx), "routes": _routes(ctx), "neighbors": _neighbors(ctx), "overlay": _overlay(ctx), "tunnels": _tunnels(ctx), "state": {k: v for k, v in state.items() if v},
             "wan_colour": {k: v for k, v in colours.items() if v}, "system_ip": str(system.get("system-ip", "")), "site_id": str(system.get("site-id", "")),
             "gateway": [], "arp": [{"ip_address": r.get("address", ""), "mac_address": r.get("mac", ""), "interface": canon_port(str(r.get("interface", ""))), "vrf": r.get("vrf", "")} for r in ctx.arp or []]}
    return facts


def device_from_facts(facts: dict[str, Any], source: str) -> Any:
    """A router the switch reader could not use (a show-only SD-WAN or WAN-router capture without neighbors): built from the Router Analyzer's reading."""
    from .extract import Device
    from .names import short_host
    fqdn = str(facts.get("hostname") or "").strip()
    rows = facts.get("interfaces") or []
    ips = {r["ip"] for r in rows if str(r.get("kind", "")).lower() != "tunnel"}
    loop = next((r["ip"] for r in rows if str(r.get("kind", "")).lower() == "loopback"), "")
    device = Device(key="", hostname=short_host(fqdn) or short_host(source.rsplit(".", 1)[0]), fqdn=fqdn, source=source, vendor="Cisco", model=str(facts.get("model") or ""),
                    os_version=str(facts.get("release") or ""), mgmt_ip=loop or (sorted(ips)[0] if ips else ""), ips=ips, arp_table=[dict(r) for r in facts.get("arp") or []], role_hint="router")
    device.l3 = rows
    device.l3facts = facts
    device.coverage = {"routes": bool(facts.get("routes")), "neighbors": bool(facts.get("neighbors")), "overlay": bool(facts.get("overlay"))}
    return device
