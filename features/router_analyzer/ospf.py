"""OSPF on a Cisco router: which interfaces actually run it, and what is wrong.

``router ospf`` on its own does nothing.  An interface joins a process in one
of two ways (Cisco IOS XE IP Routing: OSPF Configuration Guide):

* a ``network <address> <wildcard> area <n>`` statement in the process whose
  address/wildcard covers the interface's primary address (the most specific
  statement wins), or
* ``ip ospf <process> area <n>`` on the interface itself, which takes
  precedence over any network statement.

A process with neither form forms no neighbour and advertises nothing, which
is exactly what the captured PRJ-WAN-RTR-01 router has (an empty
``router ospf 1``).  An interface listed by ``passive-interface`` — or all of
them under ``passive-interface default`` unless ``no passive-interface`` names
them — advertises its prefix but sends no Hellos, so no adjacency forms.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .ifnames import canon
from .netutil import is_ipv4

_SOURCES = {"connected", "static", "bgp", "ospf", "eigrp", "rip", "isis", "mobile", "odr", "lisp", "nhrp", "vrf"}


def parse_redistribute(text: str) -> dict[str, Any]:
    """``connected route-map X`` / ``bgp 65000 metric 20 subnets`` → structured."""
    tokens = text.split()
    out: dict[str, Any] = {"text": text, "source": tokens[0] if tokens else "", "id": "", "subnets": False, "route_map": "", "metric": "", "metric_type": "", "tag": "", "vrf": "", "nssa_only": False}
    i = 1
    if out["source"] in ("bgp", "ospf", "eigrp", "isis", "rip", "lisp", "nhrp") and i < len(tokens) and tokens[i] not in ("metric", "metric-type", "subnets", "route-map", "tag", "vrf", "nssa-only", "match"):
        out["id"] = tokens[i]
        i += 1
    while i < len(tokens):
        token = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if token == "subnets":
            out["subnets"] = True
        elif token == "nssa-only":
            out["nssa_only"] = True
        elif token in ("route-map", "metric", "metric-type", "tag", "vrf"):
            out[token.replace("-", "_")] = nxt
            i += 1
        elif token == "match":
            i += 1
            while i < len(tokens) and tokens[i] not in ("metric", "metric-type", "subnets", "route-map", "tag", "vrf"):
                i += 1
            continue
        i += 1
    return out


def _wildcard_matches(ip: str, network: str, wildcard: str) -> bool:
    try:
        ip_i = int(ipaddress.IPv4Address(ip))
        net_i = int(ipaddress.IPv4Address(network))
        wild_i = int(ipaddress.IPv4Address(wildcard))
    except ValueError:
        return False
    mask = ~wild_i & 0xFFFFFFFF
    return (ip_i & mask) == (net_i & mask)


def _specificity(wildcard: str) -> int:
    try:
        return bin(int(ipaddress.IPv4Address(wildcard))).count("1")   # fewer wildcard bits = more specific
    except ValueError:
        return 32


def _cidr(network: str, wildcard: str) -> str:
    try:
        wild_i = int(ipaddress.IPv4Address(wildcard))
        if wild_i & (wild_i + 1):
            return f"{network} {wildcard}"
        return str(ipaddress.IPv4Network(f"{network}/{32 - wild_i.bit_length()}", strict=False))
    except ValueError:
        return f"{network} {wildcard}"


def _same(a: str, b: str) -> bool:
    return canon(a).lower() == canon(b).lower()


def build(cfg: dict[str, Any] | None, live: dict[str, Any] | None = None) -> dict[str, Any]:
    """Process / interface model.  ``live`` may carry ``ospf_neighbors`` and ``ospf_interfaces``."""
    if not cfg or not cfg.get("ospf"):
        return {}
    live = live or {}
    interfaces = cfg.get("interfaces", [])
    address_of = {canon(i["name"]).lower(): (i.get("ip_address") or "").split("/")[0] for i in interfaces}
    processes: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    neighbors = live.get("ospf_neighbors") or []
    live_ifaces = {canon(r.get("interface", "")).lower(): r for r in live.get("ospf_interfaces") or []}

    for proc in cfg["ospf"]:
        mine: list[dict[str, Any]] = []
        passive = {canon(p).lower() for p in proc.get("passive", [])}
        active = {canon(p).lower() for p in proc.get("active_exceptions", [])}
        for network in proc["networks"]:
            network["cidr"] = _cidr(network.get("address", ""), network.get("wildcard", ""))
            network["matched"] = []
        for iface in interfaces:
            ip = (iface.get("ip_address") or "").split("/")[0]
            if not ip and iface.get("ip_unnumbered"):
                ip = address_of.get(canon(iface["ip_unnumbered"]).lower(), "")
            enable = iface.get("ospf_enable") or {}
            how = area = ""
            if enable and enable.get("process") == proc["process"]:
                how, area = "interface command", enable["area"]
            elif not enable and ip and (iface.get("vrf") or "") == (proc.get("vrf") or ""):
                # the primary address first; a network statement that covers only a secondary address also enables the interface
                candidates = [ip] + [str(a).split("/")[0] for a in iface.get("ip_secondary") or [] if a]
                best: tuple[int, dict[str, Any]] | None = None
                for candidate in candidates:
                    for network in proc["networks"]:
                        if network.get("address") and _wildcard_matches(candidate, network["address"], network["wildcard"]):
                            score = _specificity(network["wildcard"])
                            if best is None or score < best[0]:
                                best = (score, network)
                    if best is not None:
                        break
                if best is not None:
                    how, area = "network statement", best[1]["area"]
                    if iface["name"] not in best[1]["matched"]:
                        best[1]["matched"].append(iface["name"])
            if not how:
                continue
            key = canon(iface["name"]).lower()
            is_passive = key in passive or (proc.get("passive_default") and key not in active)
            live_row = live_ifaces.get(key, {})
            nbr = [n for n in neighbors if canon(n.get("interface", "")).lower() == key]
            ospf = iface.get("ospf") or {}
            row = {
                "process": proc["process"], "vrf": proc.get("vrf") or "", "interface": iface["name"], "description": iface.get("description") or "",
                "ip": iface.get("ip_address") or (f"unnumbered ({iface['ip_unnumbered']})" if iface.get("ip_unnumbered") else ""),
                "area": area, "how": how, "passive": bool(is_passive), "shutdown": bool(iface.get("shutdown")), "network_type": ospf.get("network", ""), "cost": ospf.get("cost", ""),
                "hello": ospf.get("hello-interval", ""), "dead": ospf.get("dead-interval", ""), "auth": ospf.get("authentication") or ("md5 key" if ospf.get("message-digest-key") else ""),
                "bfd": bool(ospf.get("bfd")) or bool(proc.get("bfd")),
                "state": live_row.get("state", ""), "neighbors_live": live_row.get("neighbors", ""), "neighbors_listed": [f"{n.get('neighbor_id', '')} {n.get('state', '')}" for n in nbr],
            }
            mine.append(row)
        # state of the process
        if not mine and not proc["networks"]:
            state = "empty"
        elif not mine:
            state = "no_match"
        elif all(r["passive"] or r["shutdown"] for r in mine):
            state = "all_passive"
        else:
            state = "running"
        for network in proc["networks"]:
            pass
        processes.append(dict(proc, interfaces=mine, state=state, areas=sorted({r["area"] for r in mine} | {n["area"] for n in proc["networks"]})))
        rows.extend(mine)

    # live adjacencies that no configured interface explains (config and capture from different moments)
    explained = {canon(r["interface"]).lower() for r in rows}
    stray = [n for n in neighbors if canon(n.get("interface", "")).lower() not in explained]
    return {"processes": processes, "interfaces": rows, "stray_neighbors": stray,
            "up": sum(1 for n in neighbors if str(n.get("state", "")).upper().startswith("FULL")), "neighbors": len(neighbors)}
