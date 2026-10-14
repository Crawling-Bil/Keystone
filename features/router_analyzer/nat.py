"""NAT on a Cisco router: configuration model, live statistics and the join.

Three inputs are combined:

* the ``ip nat ...`` lines and the ``ip nat inside|outside`` interface
  commands of the running-config (what is *meant* to happen),
* ``show ip nat statistics`` (what is happening: translations, hits and
  misses, pool utilisation, the platform limit and its drop counters), and
* the ACLs that select the traffic (an undefined or empty ACL means the
  rule never matches).

``show ip nat statistics`` output used to write the parser came from an
ISR/ASR-class IOS-XE 17.x router with 57,747 active translations; the older
IOS layout (``Total translations`` / ``Dynamic mappings`` without the
``nat-limit`` block) is accepted as well.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .config_tree import ConfigTree, Node

# TCP/UDP ports whose exposure through a static translation deserves a second look.
SENSITIVE_PORTS = {
    "20": "FTP data", "21": "FTP", "22": "SSH", "23": "Telnet", "69": "TFTP", "135": "MS-RPC", "137": "NetBIOS", "138": "NetBIOS", "139": "NetBIOS", "161": "SNMP",
    "445": "SMB", "512": "rexec", "513": "rlogin", "514": "rsh/syslog", "1433": "Microsoft SQL Server", "1521": "Oracle listener", "2049": "NFS", "3306": "MySQL",
    "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC", "5985": "WinRM", "5986": "WinRM", "6379": "Redis", "9200": "Elasticsearch", "27017": "MongoDB",
}


def _ip(value: str) -> int | None:
    try:
        return int(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def _addr(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_TIMEOUTS = ("timeout", "tcp-timeout", "udp-timeout", "dns-timeout", "icmp-timeout", "finrst-timeout", "syn-timeout", "port-timeout", "pptp-timeout", "arp-ping-timeout")


def _pool(node: Node) -> dict[str, Any] | None:
    # ip nat pool NAME START END {netmask M | prefix-length N} [add-route] [type match-host|rotary] [accounting X]
    parts = node.text.split()
    if len(parts) < 7 or parts[0:3] != ["ip", "nat", "pool"]:
        return None
    start, end = parts[4], parts[5]
    low, high = _ip(start), _ip(end)
    size = (high - low + 1) if low is not None and high is not None and high >= low else 0
    mask = prefix = ""
    rest = parts[6:]
    if rest and rest[0] == "netmask" and len(rest) > 1:
        mask = rest[1]
        value = _ip(mask)
        prefix = str(bin(value).count("1")) if value is not None else ""
    elif rest and rest[0] == "prefix-length" and len(rest) > 1:
        prefix = rest[1]
    tail = " ".join(rest[2:])
    return {"name": parts[3], "start": start, "end": end, "size": size, "netmask": mask, "prefix": prefix, "add_route": "add-route" in tail,
            "type": "rotary" if "rotary" in tail else ("match-host" if "match-host" in tail else "generic")}


def _dynamic(node: Node) -> dict[str, Any] | None:
    # ip nat inside|outside source|destination list ACL | route-map RM  pool P | interface I [vrf V] [overload] [add-route]
    parts = node.text.split()
    if len(parts) < 7 or parts[2] not in ("inside", "outside") or parts[3] not in ("source", "destination"):
        return None
    if parts[4] not in ("list", "route-map"):
        return None
    out = {"direction": parts[2], "kind": parts[3], "match": parts[4], "acl": parts[5], "target": "", "target_kind": "", "overload": "overload" in parts, "vrf": "", "text": node.text}
    if "vrf" in parts and parts.index("vrf") + 1 < len(parts):
        out["vrf"] = parts[parts.index("vrf") + 1]
    for keyword in ("pool", "interface"):
        if keyword in parts and parts.index(keyword) + 1 < len(parts):
            out["target_kind"] = keyword
            out["target"] = parts[parts.index(keyword) + 1]
            break
    return out


_PROTO = ("tcp", "udp", "esp", "gre", "icmp", "ah", "sctp")


def _static(node: Node) -> dict[str, Any] | None:
    # ip nat inside source static [tcp|udp] LOCAL [lport] GLOBAL|interface IF [gport] [flags...]
    # ip nat inside source static network LOCAL GLOBAL MASK [flags]
    # ip nat outside source static [tcp|udp] GLOBAL [gport] LOCAL [lport] [flags]
    parts = node.text.split()
    if len(parts) < 6 or parts[2] not in ("inside", "outside") or parts[3] != "source" or parts[4] != "static":
        return None
    direction = parts[2]
    tokens = parts[5:]
    out: dict[str, Any] = {"direction": direction, "proto": "", "local": "", "local_port": "", "global": "", "global_port": "", "mask": "", "network": False,
                           "flags": [], "vrf": "", "text": node.text}
    if tokens and tokens[0] == "network":
        out["network"] = True
        tokens = tokens[1:]
        if len(tokens) >= 3:
            first, second, out["mask"] = tokens[0], tokens[1], tokens[2]
            out["local"], out["global"] = (first, second) if direction == "inside" else (second, first)
            out["flags"] = tokens[3:]
        return out
    if tokens and tokens[0] in _PROTO:
        out["proto"] = tokens.pop(0)
    has_ports = out["proto"] in ("tcp", "udp", "sctp")
    first = tokens.pop(0) if tokens else ""
    first_port = tokens.pop(0) if has_ports and tokens else ""
    if tokens and tokens[0] == "interface":
        second = "interface " + (tokens[1] if len(tokens) > 1 else "")
        tokens = tokens[2:]
    else:
        second = tokens.pop(0) if tokens else ""
    second_port = tokens.pop(0) if has_ports and tokens and tokens[0].isdigit() else ""
    if direction == "inside":
        out["local"], out["local_port"], out["global"], out["global_port"] = first, first_port, second, second_port
    else:
        out["global"], out["global_port"], out["local"], out["local_port"] = first, first_port, second, second_port
    flags = []
    skip = 0
    for index, token in enumerate(tokens):
        if skip:
            skip -= 1
            continue
        if token == "vrf" and index + 1 < len(tokens):
            out["vrf"] = tokens[index + 1]
            skip = 1
        elif token in ("redundancy", "mapping-id", "route-map") and index + 1 < len(tokens):
            flags.append(f"{token} {tokens[index + 1]}")
            skip = 1
        else:
            flags.append(token)
    out["flags"] = flags
    out["translates_port"] = bool(has_ports and out["local_port"] and out["global_port"] and out["local_port"] != out["global_port"])
    return out


def extract(tree: ConfigTree) -> dict[str, Any]:
    """Structured NAT configuration from the parsed running-config."""
    pools: list[dict[str, Any]] = []
    dynamic: list[dict[str, Any]] = []
    static: list[dict[str, Any]] = []
    settings: dict[str, str] = {}
    routes: list[str] = []
    other: list[str] = []
    for node in tree.top("ip nat"):
        parts = node.text.split()
        if len(parts) < 3:
            continue
        if parts[2] == "pool":
            item = _pool(node)
            if item:
                pools.append(item)
        elif parts[2] in ("inside", "outside") and len(parts) > 4 and parts[3] == "source" and parts[4] == "static":
            item = _static(node)
            if item:
                static.append(item)
        elif parts[2] in ("inside", "outside") and len(parts) > 3 and parts[3] in ("source", "destination"):
            item = _dynamic(node)
            if item:
                dynamic.append(item)
            else:
                other.append(node.text)
        elif parts[2] == "translation":
            if len(parts) > 3 and parts[3] in _TIMEOUTS:
                settings[f"translation {parts[3]}"] = " ".join(parts[4:])
            elif len(parts) > 3 and parts[3] == "max-entries":
                key = "translation max-entries " + (parts[4] if len(parts) > 5 and not parts[4].isdigit() else "global")
                settings[key] = parts[-1]
            else:
                settings["translation " + " ".join(parts[3:5])] = " ".join(parts[5:])
        elif parts[2] == "route":
            routes.append(" ".join(parts[3:]))
        elif parts[2] == "log":
            settings["log " + " ".join(parts[3:])] = "enabled"
        else:
            other.append(node.text)
    return {"pools": pools, "dynamic": dynamic, "static": static, "settings": settings, "routes": routes, "other": other}


# ---------------------------------------------------------------------------
# Live: show ip nat statistics
# ---------------------------------------------------------------------------

_TOTAL = re.compile(r"Total(?: active)? translations:\s*(\d+)(?:\s*\((\d+) static,\s*(\d+) dynamic[;,]\s*(\d+) extended\))?", re.I)
_MAPPING = re.compile(r"^\[Id:\s*(\d+)\]\s+(access-list|route-map)\s+(\S+)\s+(pool|interface)\s+(\S+)(?:\s+(?:vrf\s+(\S+)\s+)?refcount\s+(\d+))?", re.I)
_POOL = re.compile(r"^\s*pool\s+(\S+):\s*(?:id\s+(\d+),\s*)?netmask\s+(\S+)", re.I)
_START = re.compile(r"^\s*start\s+(\S+)\s+end\s+(\S+)", re.I)
_POOL_STATS = re.compile(r"^\s*type\s+(\w+),\s*total addresses\s+(\d+),\s*allocated\s+(\d+)\s*\((\d+)%\),\s*misses\s+(\d+)", re.I)


def _number(text: str) -> int:
    return int(text.replace(",", ""))


def parse_nat_statistics(lines: list[str]) -> dict[str, Any]:
    """``show ip nat statistics`` → totals, interfaces, hits/misses, mappings with pool detail, platform limit."""
    text = "\n".join(lines)
    if not _TOTAL.search(text) and "Dynamic mappings" not in text and "nat-limit" not in text:
        return {}
    out: dict[str, Any] = {"mappings": [], "inside_interfaces": [], "outside_interfaces": []}
    match = _TOTAL.search(text)
    if match:
        out["total"] = int(match.group(1))
        if match.group(2) is not None:
            out["static"], out["dynamic"], out["extended"] = int(match.group(2)), int(match.group(3)), int(match.group(4))
    match = re.search(r"Peak translations:\s*(\d+)(?:,\s*occurred\s+(\S+)\s+ago)?", text)
    if match:
        out["peak"] = int(match.group(1))
        out["peak_ago"] = match.group(2) or ""
    match = re.search(r"Hits:\s*(\d+)\s+Misses:\s*(\d+)", text)
    if match:
        out["hits"], out["misses"] = int(match.group(1)), int(match.group(2))
    match = re.search(r"CEF Translated packets:\s*(\d+),\s*CEF Punted packets:\s*(\d+)", text)
    if match:
        out["cef_translated"], out["cef_punted"] = int(match.group(1)), int(match.group(2))
    match = re.search(r"Expired translations:\s*(\d+)", text)
    if match:
        out["expired"] = int(match.group(1))
    match = re.search(r"Queued Packets:\s*(\d+)", text)
    if match:
        out["queued"] = int(match.group(1))

    # interface lists: "Outside interfaces:" then one or more indented, comma-separated lines
    for key, label in (("outside_interfaces", "Outside interfaces:"), ("inside_interfaces", "Inside interfaces:")):
        names: list[str] = []
        capture = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(label):
                capture = True
                rest = stripped[len(label):].strip()
                names += [n.strip() for n in rest.split(",") if n.strip()]
                continue
            if capture:
                if not line.startswith((" ", "\t")) or not stripped:
                    capture = False
                    continue
                names += [n.strip() for n in stripped.split(",") if n.strip()]
        out[key] = names

    current: dict[str, Any] | None = None
    section = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("-- "):
            section = stripped[3:].strip().lower()   # "inside source", "outside source"…
            continue
        match = _MAPPING.match(stripped)
        if match:
            current = {"id": int(match.group(1)), "section": section, "match": "route-map" if match.group(2).lower() == "route-map" else "list", "acl": match.group(3),
                       "target_kind": match.group(4).lower(), "target": match.group(5), "vrf": match.group(6) or "", "refcount": int(match.group(7)) if match.group(7) else None, "pool": None}
            out["mappings"].append(current)
            continue
        if current is not None:
            match = _POOL.match(line)
            if match:
                current["pool"] = {"name": match.group(1), "id": int(match.group(2)) if match.group(2) else None, "netmask": match.group(3)}
                continue
            match = _START.match(line)
            if match and current.get("pool") is not None:
                current["pool"]["start"], current["pool"]["end"] = match.group(1), match.group(2)
                continue
            match = _POOL_STATS.match(line)
            if match and current.get("pool") is not None:
                current["pool"].update({"type": match.group(1), "total": int(match.group(2)), "allocated": int(match.group(3)), "allocated_pct": int(match.group(4)), "misses": int(match.group(5))})
                continue

    # platform limit and the drop counters printed after "nat-limit statistics:"
    limit = re.search(r"max entry:\s*max allowed\s+(\d+),\s*used\s+(\d+),\s*missed\s+(\d+)", text)
    if limit:
        out["limit"] = {"max": int(limit.group(1)), "used": int(limit.group(2)), "missed": int(limit.group(3))}
    drops: dict[str, int] = {}
    for key, pattern in (("in_to_out", r"In-to-out drops:\s*(\d+)"), ("out_to_in", r"Out-to-in drops:\s*(\d+)"), ("pool", r"Pool stats drop:\s*(\d+)"), ("mapping", r"Mapping stats drop:\s*(\d+)"),
                         ("port_block", r"Port block alloc fail:\s*(\d+)"), ("ip_alias", r"IP alias add fail:\s*(\d+)"), ("limit_entry", r"Limit entry add fail:\s*(\d+)")):
        found = re.search(pattern, text)
        if found:
            drops[key] = int(found.group(1))
    if drops:
        out["drops"] = drops
    return out


# ---------------------------------------------------------------------------
# The joined model
# ---------------------------------------------------------------------------


def build(cfg: dict[str, Any] | None, stats: dict[str, Any] | None, undefined_acls: set[str] | None = None) -> dict[str, Any]:
    """Join configuration and live statistics into the structure the tab, the
    cards and the rules read.  Returns ``{}`` when the device has no NAT at all."""
    config = (cfg or {}).get("nat") or {}
    pools = [dict(p) for p in config.get("pools", [])]
    dynamic = [dict(d) for d in config.get("dynamic", [])]
    static = [dict(s) for s in config.get("static", [])]
    interfaces = (cfg or {}).get("interfaces", []) if cfg else []
    inside = [i["name"] for i in interfaces if i.get("nat") == "inside"]
    outside = [i["name"] for i in interfaces if i.get("nat") == "outside"]
    if stats:
        inside = inside or list(stats.get("inside_interfaces", []))
        outside = outside or list(stats.get("outside_interfaces", []))
    if not (pools or dynamic or static or inside or outside or stats):
        return {}

    live_pools: dict[str, dict[str, Any]] = {}
    live_mappings: dict[tuple[str, str], dict[str, Any]] = {}
    for mapping in (stats or {}).get("mappings", []):
        pool = mapping.get("pool")
        if pool:
            live_pools[pool["name"]] = pool
        live_mappings[(mapping["acl"], mapping["target"])] = mapping

    pool_by_name = {p["name"]: p for p in pools}
    users: dict[str, list[str]] = {}
    for rule in dynamic:
        live = live_mappings.get((rule["acl"], rule["target"]))
        rule["refcount"] = live.get("refcount") if live else None
        rule["live"] = live is not None
        if rule["target_kind"] == "pool":
            users.setdefault(rule["target"], []).append(rule["acl"])
            rule["pool_defined"] = rule["target"] in pool_by_name
        rule["acl_undefined"] = rule["match"] == "list" and bool(undefined_acls) and rule["acl"] in undefined_acls

    for pool in pools:
        live = live_pools.get(pool["name"])
        pool["used_by"] = users.get(pool["name"], [])
        pool["live"] = live
        pool["allocated"] = live.get("allocated") if live else None
        pool["allocated_pct"] = live.get("allocated_pct") if live else None
        pool["misses"] = live.get("misses") if live else None
        pool["overload"] = any(r["overload"] for r in dynamic if r["target"] == pool["name"] and r["target_kind"] == "pool")
        pool["refcount"] = sum(r.get("refcount") or 0 for r in dynamic if r["target"] == pool["name"] and r["target_kind"] == "pool") if stats else None

    # pools that overlap in address space
    owners: dict[int, list[str]] = {}
    for pool in pools:
        low, high = _ip(pool["start"]), _ip(pool["end"])
        if low is None or high is None or high < low or high - low > 70000:
            continue
        for value in range(low, high + 1):
            owners.setdefault(value, []).append(pool["name"])
    shared = [{"address": _addr(value), "pools": names} for value, names in sorted(owners.items()) if len(names) > 1]

    # static entries: duplicate global side, port-changing entries, sensitive ports
    seen: dict[tuple, list[dict[str, Any]]] = {}
    for entry in static:
        entry["sensitive"] = SENSITIVE_PORTS.get(entry.get("global_port", "") or entry.get("local_port", "")) if entry.get("proto") == "tcp" else None
        key = (entry["direction"], entry["proto"], entry["global"], entry["global_port"], entry["vrf"])
        seen.setdefault(key, []).append(entry)
    conflicts = [group for group in seen.values() if len({(e["local"], e["local_port"]) for e in group}) > 1]
    duplicates = [group for group in seen.values() if len(group) > 1 and len({(e["local"], e["local_port"]) for e in group}) == 1]

    summary: dict[str, Any] = {"pools": len(pools), "dynamic": len(dynamic), "static": len(static), "inside": inside, "outside": outside,
                               "overload_rules": sum(1 for r in dynamic if r["overload"]), "settings": config.get("settings", {})}
    return {
        "pools": pools, "dynamic": dynamic, "static": static, "shared_addresses": shared, "static_conflicts": conflicts, "static_duplicates": duplicates,
        "inside": inside, "outside": outside, "settings": config.get("settings", {}), "routes": config.get("routes", []), "stats": stats or {}, "summary": summary,
        "live_mappings_unmatched": [m for key, m in live_mappings.items() if not any((d["acl"], d["target"]) == key for d in dynamic)] if dynamic else [],
    }


def digits_transposed(a: str, b: str) -> bool:
    """True when two port numbers are made of the same digits in a different order (5535 / 5355)."""
    return a != b and len(a) == len(b) and sorted(a) == sorted(b)
