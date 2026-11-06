"""Per-interface MTU and OSPF parameters of one capture, for the checks that compare the two ends of a link (``paramfindings``).

The Switch Analyzer already says which interfaces run OSPF (``l3["ospf"]["interfaces"]``: area, passive, network type, cost, from the ``router ospf``
network statements or the interface commands).  What it does not keep is what the two neighbors must agree on: the hello and dead timers, and the MTU.
This module reads those from the ``interface`` blocks of the configuration in the capture, with the command names of each vendor:

=============================  =========================  ============================  ==============================
                               Cisco IOS XE / NX-OS       Aruba AOS-CX                  Huawei VRP
=============================  =========================  ============================  ==============================
MTU of the interface           ``mtu 9000``               ``mtu 9198``                  ``mtu 1500``
MTU of the IP packets          ``ip mtu 1500``            ``ip mtu 1500``               (the interface MTU)
OSPF hello / dead interval     ``ip ospf hello-interval`` ``ip ospf hello-interval``    ``ospf timer hello 10``
                               ``ip ospf dead-interval``  ``ip ospf dead-interval``     ``ospf timer dead 40``
OSPF network type              ``ip ospf network ...``    ``ip ospf network ...``       ``ospf network-type p2p``
OSPF area on the interface     ``ip ospf 1 area 0``       ``ip ospf 1 area 0.0.0.0``    ``ospf enable 1 area 0.0.0.0``
=============================  =========================  ============================  ==============================

A value that is not written is the default of the platform: hello 10 s and dead 40 s on broadcast and point-to-point networks (30 s and 120 s on
non-broadcast and point-to-multipoint), a dead interval of four hello intervals when only the hello interval is set (Cisco, NX-OS and AOS-CX; Huawei keeps 40 s),
and an MTU of 1500 bytes on a routed interface.  A device with a global jumbo setting (``system mtu``, ``system jumbomtu``, ``jumboframe enable``) has an
MTU that the interface does not show, so its routed ports are left out of the MTU comparison instead of being guessed.

Nothing else is kept: no address, no description, no password or key (``ip ospf message-digest-key`` and the like are not read).

References:

* IETF RFC 2328 section 10.5 (Hello packets: the hello interval, dead interval, network mask and area ID must be equal) and 10.6 (Database Description:
  an MTU larger than the receiver's interface keeps the adjacency in ExStart): https://datatracker.ietf.org/doc/html/rfc2328#section-10.5
* Cisco, OSPF Neighbor Relationship Troubleshooting: https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/12151-trouble-main.html
* Cisco, Troubleshoot OSPF Neighbors Stuck in Exstart/Exchange State: https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13684-12.html
* Aruba AOS-CX IP Routing Guide: https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/ip_routing_cx_10.13/index.html
"""

from __future__ import annotations

import re
from typing import Any

from .names import canon_port

MAX_INTERFACES = 4000
DEFAULT_MTU = 1500

_INTERFACE = re.compile(r"^interface\s+(\S.*?)\s*$")
_MTU = re.compile(r"^mtu\s+(\d{3,5})$")
_IP_MTU = re.compile(r"^ip mtu\s+(\d{3,5})$")
_HELLO = re.compile(r"^(?:ip ospf hello-interval|ospf timer hello)\s+(\d{1,5})$")
_DEAD = re.compile(r"^(?:ip ospf dead-interval|ospf timer dead)\s+(\d{1,6})$")
_NETWORK = re.compile(r"^(?:ip ospf network|ospf network-type)\s+(.+)$")
_AREA = re.compile(r"^(?:ip ospf|ip router ospf|ospf enable)\s+(?:\S+\s+)?area\s+(\S+)$")
_CHANNEL = re.compile(r"^channel-group\s+\d+\s+mode\s+(\S+)")
_IGNORE = re.compile(r"^(?:ip ospf|ospf)\s+mtu-ignore$")
_GLOBAL_MTU = re.compile(r"^(?:system mtu|system jumbomtu|system jumbo mtu|jumboframe enable)\b")

_NETWORK_TYPES = {"point-to-point": "point-to-point", "p2p": "point-to-point", "broadcast": "broadcast", "non-broadcast": "non-broadcast", "nbma": "non-broadcast",
                  "point-to-multipoint": "point-to-multipoint", "p2mp": "point-to-multipoint", "loopback": "loopback"}
_SLOW = ("non-broadcast", "point-to-multipoint")          # types whose default hello interval is 30 s


def area_id(text: Any) -> str:
    """OSPF area as dotted decimal: ``0`` and ``0.0.0.0`` are the same area."""
    value = str(text or "").strip()
    if value.isdigit() and int(value) < 2 ** 32:
        number = int(value)
        return ".".join(str((number >> shift) & 255) for shift in (24, 16, 8, 0))
    return value


def network_type(text: Any) -> str:
    low = " ".join(str(text or "").lower().split())
    for word, kind in _NETWORK_TYPES.items():
        if low == word or low.startswith(word + " "):
            return kind
    return low


def blocks(text: str) -> list[tuple[str, list[str]]]:
    """``(interface name, child lines)`` for every ``interface`` block of the configuration (Cisco, NX-OS, AOS-CX and Huawei write the children indented)."""
    found: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for raw in str(text).replace("\r", "").split("\n"):
        if raw[:1] in (" ", "\t"):
            if current is not None and raw.strip():
                current[1].append(raw.strip())
            continue
        current = None
        match = _INTERFACE.match(raw)
        if match:
            current = (match.group(1), [])
            found.append(current)
            if len(found) >= MAX_INTERFACES:
                break
    return found


def _ospf_rows(result: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """The interfaces that run OSPF and are not passive or shut down, by canonical name (the Switch Analyzer's reading)."""
    rows = (((result or {}).get("l3") or {}).get("ospf") or {}).get("interfaces") or []
    return {canon_port(str(row.get("interface", ""))): row for row in rows if row.get("interface") and not row.get("passive") and not row.get("shutdown")}


def read(text: str, result: dict[str, Any] | None = None, vendor: str = "") -> dict[str, Any]:
    """``{"global_mtu": bool, "ports": {canonical port: {...}}}``; a port holds only what the capture said (``mtu``, ``ip_mtu``) plus ``ip`` when it has an
    address and ``ospf`` (area, hello, dead, network, mtu_ignore) when OSPF runs on it."""
    ospf_rows = _ospf_rows(result)
    addressed = {canon_port(str(row.get("name", ""))) for row in (((result or {}).get("l3") or {}).get("interfaces") or []) if row.get("ip") and not row.get("shutdown")}
    ports: dict[str, dict[str, Any]] = {}
    for name, children in blocks(text):
        port = canon_port(name)
        record = ports.setdefault(port, {})
        explicit: dict[str, Any] = {}
        for line in children:
            low = line.lower()
            for pattern, key in ((_MTU, "mtu"), (_IP_MTU, "ip_mtu"), (_HELLO, "hello"), (_DEAD, "dead")):
                found = pattern.match(low)
                if found:
                    (record if key in ("mtu", "ip_mtu") else explicit)[key] = int(found.group(1))
            found = _CHANNEL.match(low)
            if found:
                record["channel_mode"] = found.group(1)
            found = _NETWORK.match(low)
            if found:
                explicit["network"] = network_type(found.group(1))
            found = _AREA.match(low)
            if found:
                explicit["area"] = area_id(found.group(1))
            if _IGNORE.match(low):
                explicit["mtu_ignore"] = True
        if explicit:
            record["_ospf"] = {**record.get("_ospf", {}), **explicit}
    huawei = "huawei" in vendor.lower()
    for port, record in list(ports.items()):
        explicit = record.pop("_ospf", {})
        row = ospf_rows.get(port)
        if port in addressed:
            record["ip"] = True
        if row is not None or explicit.get("area"):
            kind = explicit.get("network") or network_type(row.get("network_type") if row else "") or "broadcast"
            slow = kind in _SLOW
            hello = explicit.get("hello") or (30 if slow else 10)
            if "dead" in explicit:
                dead = explicit["dead"]
            elif huawei and not slow:
                dead = 40                                          # Huawei does not derive the dead interval from the hello interval
            else:
                dead = 120 if slow and "hello" not in explicit else 4 * hello
            record["ospf"] = {"area": area_id(row.get("area") if row else "") or explicit.get("area", ""), "hello": hello, "dead": dead, "network": kind,
                              "mtu_ignore": bool(explicit.get("mtu_ignore")), "assumed": False}
        if not record:
            del ports[port]
    for port, row in ospf_rows.items():                       # OSPF on an interface the configuration text does not show (a show-only capture): defaults
        if port not in ports:
            kind = network_type(row.get("network_type")) or "broadcast"
            hello = 30 if kind in _SLOW else 10
            ports[port] = {"ospf": {"area": area_id(row.get("area")), "hello": hello, "dead": 4 * hello, "network": kind, "mtu_ignore": False, "assumed": True}, "ip": True}
    global_mtu = any(_GLOBAL_MTU.match(line.strip().lower()) for line in str(text).replace("\r", "").split("\n") if line[:1] not in (" ", "\t"))
    return {"global_mtu": global_mtu, "ports": ports}
