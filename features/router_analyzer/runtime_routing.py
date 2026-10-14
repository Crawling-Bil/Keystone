"""Routing-table, BGP and neighbour-table parsers (IOS / IOS-XE)."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .ifnames import canon
from .netutil import is_ipv4

# --------------------------------------------------------------------------
# show ip route [vrf X]
# --------------------------------------------------------------------------

PROTOCOLS = {
    "L": "Local", "C": "Connected", "S": "Static", "R": "RIP", "M": "Mobile", "B": "BGP", "D": "EIGRP", "O": "OSPF",
    "i": "IS-IS", "o": "ODR", "P": "Static (downloaded)", "H": "NHRP", "l": "LISP", "m": "OMP", "n": "NAT", "G": "NHRP", "g": "NHRP",
    "a": "Application", "U": "Static (per-user)", "N": "NAT",
}
SUBTYPES = {
    "IA": "inter-area", "N1": "NSSA ext 1", "N2": "NSSA ext 2", "E1": "ext 1", "E2": "ext 2", "EX": "external",
    "L1": "level-1", "L2": "level-2", "ia": "inter-area", "su": "summary", "i": "NAT inside", "o": "NAT outside", "d": "NAT DIA",
    "Ni": "NAT inside", "No": "NAT outside", "Nd": "NAT DIA",
}
_ROUTE_HEAD = re.compile(r"^(?P<head>\S.*?)\s+(?P<net>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<len>\d+))?(?P<rest>\s.*)?$")
_HEAD_OK = re.compile(r"^[A-Za-z*+%&!]{1,3}(?:\s?[A-Za-z]{1,2}\d?)?[*+%&!]*$")
_PARENT = re.compile(r"^\s+(?P<net>\d{1,3}(?:\.\d{1,3}){3})/(?P<len>\d+) is (?:(?P<var>variably) )?subnetted, (?P<n>\d+) subnets?(?:, (?P<masks>\d+) masks?)?")
_VIA = re.compile(r"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<nh>\S+?)(?:,\s*(?P<age>\d[\w:]*))?(?:,\s*(?P<if>\S+))?\s*$")
_VIA_CONT = re.compile(r"^\s+\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<nh>\S+?)(?:,\s*(?P<age>\d[\w:]*))?(?:,\s*(?P<if>\S+))?\s*$")
_CONNECTED = re.compile(r"is directly connected,\s*(?:(?P<age>\d[\w:]*),\s*)?(?P<if>\S+)")
_SUMMARY = re.compile(r"is a summary,\s*(?P<age>\d[\w:]*),\s*(?P<if>\S+)")


def _decode_head(head: str) -> tuple[str, str, str, bool]:
    """(protocol name, subtype, raw code, candidate-default?)"""
    raw = head.strip()
    candidate = "*" in raw
    cleaned = re.sub(r"[*+%&!]", " ", raw)
    tokens = cleaned.split()
    if not tokens:
        return "", "", raw, candidate
    main = tokens[0]
    sub = tokens[1] if len(tokens) > 1 else ""
    # glued forms such as "O*E2" -> tokens O, E2 after cleaning; "EX" alone means EIGRP external
    if main == "EX":
        main, sub = "D", "EX"
    proto = PROTOCOLS.get(main, PROTOCOLS.get(main[:1], main))
    if main in ("IA",):
        proto, sub = "OSPF", "IA"
    if main in ("E1", "E2", "N1", "N2"):
        proto, sub = "OSPF", main
    if main in ("L1", "L2", "ia", "su"):
        proto, sub = "IS-IS", main
    if main in ("Ni", "No", "Nd"):
        proto, sub = "NAT", main
    return proto, SUBTYPES.get(sub, sub), raw, candidate


def parse_ip_route(lines: list[str], vrf: str = "") -> dict[str, Any]:
    routes: list[dict[str, Any]] = []
    gateway = ""
    table_vrf = vrf
    parent_len: int | None = None
    last: dict[str, Any] | None = None
    for line in lines:
        if not line.strip():
            continue
        m = re.match(r"^Routing Table:\s*(\S+)", line)
        if m:
            table_vrf = m.group(1)
            continue
        if line.startswith("Gateway of last resort"):
            m = re.match(r"Gateway of last resort is (\S+)", line)
            if m and m.group(1) != "not":
                gateway = m.group(1)
            continue
        if line.startswith("Codes:") or re.match(r"^\s{4,}\S.* - .*", line) and "via" not in line and "[" not in line:
            continue
        parent = _PARENT.match(line)
        if parent:
            # "is subnetted": children carry no mask, use the parent's length;
            # "is variably subnetted": children print their own /len.
            parent_len = None if parent.group("var") else int(parent.group("len"))
            last = None
            continue
        cont = _VIA_CONT.match(line)
        if cont and last is not None:
            last["next_hops"].append({"via": cont.group("nh"), "interface": canon(cont.group("if") or ""), "age": cont.group("age") or "", "ad": int(cont.group("ad")), "metric": int(cont.group("metric"))})
            continue
        head = _ROUTE_HEAD.match(line)
        if not head or not _HEAD_OK.match(head.group("head").strip()):
            continue
        proto, subtype, raw_code, candidate = _decode_head(head.group("head"))
        length = int(head.group("len")) if head.group("len") else (parent_len if parent_len is not None else 32)
        prefix = f"{head.group('net')}/{length}"
        rest = head.group("rest") or ""
        route = {
            "vrf": table_vrf or "global", "prefix": prefix, "length": length, "protocol": proto, "subtype": subtype, "code": raw_code,
            "candidate_default": candidate, "ad": None, "metric": None, "next_hops": [], "connected_interface": "",
        }
        conn = _CONNECTED.search(rest)
        summ = _SUMMARY.search(rest)
        via = _VIA.search(rest)
        if conn:
            route["connected_interface"] = canon(conn.group("if"))
            route["next_hops"].append({"via": "directly connected", "interface": canon(conn.group("if")), "age": conn.group("age") or "", "ad": 0, "metric": 0})
        elif summ:
            route["next_hops"].append({"via": "summary", "interface": canon(summ.group("if")), "age": summ.group("age"), "ad": None, "metric": None})
        elif via:
            route["ad"] = int(via.group("ad"))
            route["metric"] = int(via.group("metric"))
            route["next_hops"].append({"via": via.group("nh"), "interface": canon(via.group("if") or ""), "age": via.group("age") or "", "ad": route["ad"], "metric": route["metric"]})
        routes.append(route)
        last = route
    return {"vrf": table_vrf or "global", "gateway_of_last_resort": gateway, "routes": routes}


def summarise_routes(tables: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate one or more parsed route tables."""
    per_vrf: dict[str, Counter] = {}
    next_hops: Counter = Counter()
    by_if: Counter = Counter()
    ecmp = 0
    defaults = []
    total = 0
    for table in tables:
        for route in table["routes"]:
            total += 1
            per_vrf.setdefault(route["vrf"], Counter())[route["protocol"]] += 1
            if len(route["next_hops"]) > 1:
                ecmp += 1
            for hop in route["next_hops"]:
                if hop["via"] not in ("directly connected", "summary"):
                    next_hops[(route["vrf"], hop["via"])] += 1
                if hop["interface"]:
                    by_if[(route["vrf"], hop["interface"])] += 1
            if route["prefix"] == "0.0.0.0/0":
                defaults.append(route)
    return {"total": total, "per_vrf": {k: dict(v) for k, v in per_vrf.items()}, "ecmp": ecmp, "next_hops": next_hops.most_common(), "by_interface": by_if.most_common(), "defaults": defaults,
            "gateways": {table["vrf"]: table["gateway_of_last_resort"] for table in tables}}


# --------------------------------------------------------------------------
# show ip route summary / show ipv6 route summary
# --------------------------------------------------------------------------

_SOURCE_ROW = re.compile(r"^(?P<source>[A-Za-z][\w-]*(?: \d+)?)\s+(?P<nums>\d+(?:\s+\d+)*)\s*$")


def _route_summary(lines: list[str], columns: list[str], ipv6: bool) -> dict[str, Any]:
    out: dict[str, Any] = {"vrf": "", "table_name": "", "max_paths": None, "entries": None, "rows": [], "total": None, "prefix_lengths": []}
    last: dict[str, Any] | None = None
    in_prefixes = False
    for line in lines:
        text = line.strip()
        if not text:
            continue
        m = re.match(r"^IP(?:v6)? routing table name is ([^\s(]+)", text, re.I)
        if m:
            name = m.group(1)
            out["table_name"] = name
            out["vrf"] = "" if name.lower() in ("default", "global") else name
            entries = re.search(r"-\s*(\d+) entr", text)
            if entries:
                out["entries"] = int(entries.group(1))
            continue
        m = re.match(r"^IP(?:v6)? routing table (?:default )?maximum-paths is (\d+)", text, re.I)
        if m:
            out["max_paths"] = int(m.group(1))
            continue
        if re.match(r"^Route Source\b", text, re.I):
            in_prefixes = False
            continue
        if re.match(r"^Number of prefixes:", text, re.I):
            in_prefixes = True
            continue
        if in_prefixes:
            for length, count in re.findall(r"/(\d+):\s*(\d+)", text):
                out["prefix_lengths"].append({"length": int(length), "count": int(count)})
            continue
        m = _SOURCE_ROW.match(text)
        if m and not line.startswith(" "):
            nums = [int(n) for n in m.group("nums").split()]
            source = m.group("source")
            row: dict[str, Any] = {"source": source, "detail": ""}
            if source.lower() == "total":
                row.update(dict(zip(columns, nums)))
                out["total"] = row
                last = None
                continue
            if source.lower() == "internal" and len(nums) == 2:  # internal: networks and memory only
                row.update({columns[0]: nums[0], "memory": nums[1]})
            elif len(nums) == len(columns):
                row.update(dict(zip(columns, nums)))
            else:
                continue
            out["rows"].append(row)
            last = row
            continue
        if line.startswith(" ") and last is not None and re.search(r"\w+(?:-\w+)*:\s*\d+", text):
            last["detail"] = (last["detail"] + "  " + re.sub(r"\s{2,}", " ", text)).strip()
    if not out["rows"] and out["total"] is None:
        return {}
    return out


def parse_route_summary(lines: list[str]) -> dict[str, Any]:
    """``show ip route [vrf X] summary`` (IOS / IOS-XE): routes per source, with memory."""
    result = _route_summary(lines, ["networks", "subnets", "replicates", "overhead", "memory"], False)
    if result:
        for row in result["rows"] + ([result["total"]] if result["total"] else []):
            row["routes"] = (row.get("networks") or 0) + (row.get("subnets") or 0)
    return result


def parse_ipv6_route_summary(lines: list[str]) -> dict[str, Any]:
    """``show ipv6 route summary`` (IOS-XE): routes per source, with memory and the prefix-length spread."""
    result = _route_summary(lines, ["networks", "overhead", "memory"], True)
    if result:
        for row in result["rows"] + ([result["total"]] if result["total"] else []):
            row["routes"] = row.get("networks") or 0
    return result


# --------------------------------------------------------------------------
# show ip bgp
# --------------------------------------------------------------------------


def parse_bgp_table(lines: list[str]) -> dict[str, Any]:
    """Parse ``show ip bgp`` (IOS 12.4 and IOS-XE layouts).

    Column offsets come from the header line.  Three row shapes exist:
    a full row, an *alternate path* row (network column blank, inherits the
    previous network) and a *wrapped* row where a long prefix fills the
    Network column so the next hop starts on the following line.
    """
    info: dict[str, Any] = {"table_version": "", "router_id": "", "paths": []}
    offsets: dict[str, int] | None = None
    last_net = ""
    pending: tuple[str, str] | None = None  # (status, network) waiting for the next-hop line
    status_re = re.compile(r"^[ *sdhrSmbfxaci>]{1,5}$")
    for line in lines:
        m = re.match(r"^BGP table version is (\d+), local router ID is (\S+)", line)
        if m:
            info["table_version"], info["router_id"] = m.group(1), m.group(2)
            continue
        if "Network" in line and "Next Hop" in line and "Path" in line:
            offsets = {
                "net": line.index("Network"), "nh": line.index("Next Hop"),
                "metric_end": line.index("Metric") + 6, "locprf_end": line.index("LocPrf") + 6,
                "weight_end": line.index("Weight") + 6, "path": line.index("Path"),
            }
            continue
        if offsets is None or not line.strip():
            continue
        status = line[:offsets["net"]]
        if not status_re.match(status):
            continue  # legend / continuation text, not a path row
        tokens = [(m.group(), m.start(), m.end()) for m in re.finditer(r"\S+", line[offsets["net"]:])]
        tokens = [(text, start + offsets["net"], end + offsets["net"]) for text, start, end in tokens]
        if not tokens:
            continue
        if pending is not None and not status.strip():
            status_text, network = pending
            pending = None
            row = _bgp_row(status_text, network, tokens, offsets)
            if row:
                info["paths"].append(row)
                last_net = network
            continue
        pending = None
        network = ""
        if tokens[0][1] < offsets["nh"] - 1:
            network = tokens[0][0]
            tokens = tokens[1:]
            if not tokens:
                pending = (status.strip(), network)
                continue
        else:
            network = last_net
        row = _bgp_row(status.strip(), network, tokens, offsets)
        if row:
            info["paths"].append(row)
            last_net = network
    return info


def _bgp_row(status: str, network: str, tokens: list[tuple[str, int, int]], offsets: dict[str, int]) -> dict[str, Any] | None:
    if not tokens or not network:
        return None
    next_hop = tokens[0][0]
    metric = locprf = weight = ""
    path_tokens: list[str] = []
    for text, _start, end in tokens[1:]:
        if path_tokens:
            path_tokens.append(text)
        elif end <= offsets["metric_end"] + 1 and text.isdigit() and not metric:
            metric = text
        elif end <= offsets["locprf_end"] + 1 and text.isdigit() and not locprf:
            locprf = text
        elif end <= offsets["weight_end"] + 1 and text.isdigit() and not weight:
            weight = text
        else:
            path_tokens.append(text)
    origin = ""
    if path_tokens and path_tokens[-1] in ("i", "e", "?"):
        origin = path_tokens.pop()
    as_path = [t for t in path_tokens if re.match(r"^[\d.{},()]+$", t)]
    flags = status.replace(" ", "")
    return {
        "network": network, "next_hop": next_hop, "metric": metric, "locprf": locprf, "weight": weight, "as_path": as_path, "origin": origin,
        "status": flags, "valid": "*" in flags, "best": ">" in flags, "internal": flags.endswith("i"), "rib_failure": "r" in flags,
        "suppressed": "s" in flags, "stale": "S" in flags, "multipath": "m" in flags, "backup": "b" in flags,
    }


def summarise_bgp_table(table: dict[str, Any]) -> dict[str, Any]:
    paths = table["paths"]
    prefixes = {p["network"] for p in paths}
    best = [p for p in paths if p["best"]]
    first_as: Counter = Counter()
    by_next_hop: Counter = Counter()
    prepended = 0
    longest = 0
    local = 0
    for p in best:
        by_next_hop[p["next_hop"]] += 1
        if p["as_path"]:
            first_as[p["as_path"][0]] += 1
            longest = max(longest, len(p["as_path"]))
            if any(a == b for a, b in zip(p["as_path"], p["as_path"][1:])):
                prepended += 1
        else:
            local += 1
    return {
        "paths": len(paths), "prefixes": len(prefixes), "best": len(best),
        "rib_failures": sum(1 for p in paths if p["rib_failure"]),
        "suppressed": sum(1 for p in paths if p["suppressed"]),
        "stale": sum(1 for p in paths if p["stale"]),
        "locally_originated": local, "prepended": prepended, "longest_as_path": longest,
        "by_neighbor_as": first_as.most_common(), "by_next_hop": by_next_hop.most_common(),
        "multi_path_prefixes": len(paths) - len(prefixes),
    }


# --------------------------------------------------------------------------
# show ip bgp neighbors
# --------------------------------------------------------------------------


def parse_bgp_neighbors(lines: list[str]) -> list[dict[str, Any]]:
    neighbors: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in lines:
        m = re.match(r"^BGP neighbor is (\S+?),\s+(?:vrf (\S+),\s+)?remote AS (\S+?),\s*(external|internal) link", line)
        if m:
            cur = {
                "neighbor": m.group(1), "vrf": m.group(2) or "", "remote_as": m.group(3), "link": m.group(4), "state": "", "uptime": "", "admin_shutdown": False,
                "description": "", "router_id": "", "hold_time": "", "keepalive": "", "prefixes_sent": None, "prefixes_received": None, "last_reset": "",
                "established": None, "dropped": None, "route_map_in": "", "route_map_out": "", "filter_list_in": "", "filter_list_out": "", "prefix_list_in": "", "prefix_list_out": "",
                "max_prefix": "", "peer_group": "", "multihop": "", "updates_in": None, "updates_out": None, "notifications_in": None, "notifications_out": None,
                "graceful_restart": "", "soft_reconfig": False, "bfd": "", "ttl_security": False, "tcp_mss": "", "families": [],
            }
            neighbors.append(cur)
            continue
        if cur is None:
            continue
        text = line.strip()
        if text.startswith("Description:"):
            cur["description"] = text[len("Description:"):].strip()
        elif text.startswith("Administratively shut down"):
            cur["admin_shutdown"] = True
        elif text.startswith("BGP version"):
            m = re.search(r"remote router ID (\S+)", text)
            if m:
                cur["router_id"] = m.group(1)
        elif text.startswith("BGP state ="):
            m = re.match(r"BGP state = ([^,]+)(?:, up for (\S+))?", text)
            if m:
                cur["state"] = m.group(1).strip()
                cur["uptime"] = m.group(2) or ""
        elif text.startswith("Last read"):
            m = re.search(r"hold time is (\d+), keepalive interval is (\d+)", text)
            if m:
                cur["hold_time"], cur["keepalive"] = m.group(1), m.group(2)
        elif text.startswith("Member of peer-group"):
            m = re.match(r"Member of peer-group (\S+)", text)
            if m:
                cur["peer_group"] = m.group(1)
        elif text.startswith("Last reset"):
            cur["last_reset"] = text[len("Last reset"):].strip()
        elif text.startswith("Connections established"):
            m = re.match(r"Connections established (\d+); dropped (\d+)", text)
            if m:
                cur["established"], cur["dropped"] = int(m.group(1)), int(m.group(2))
        elif text.startswith("For address family:"):
            cur["families"].append(text.replace("For address family:", "").strip())
        elif text.startswith("Route map for incoming"):
            cur["route_map_in"] = text.split()[-1]
        elif text.startswith("Route map for outgoing"):
            cur["route_map_out"] = text.split()[-1]
        elif re.match(r"(Incoming|Outgoing) update AS path filter list", text):
            key = "filter_list_in" if text.startswith("Incoming") else "filter_list_out"
            cur[key] = text.split()[-1]
        elif re.match(r"(Incoming|Outgoing) update prefix filter list", text):
            key = "prefix_list_in" if text.startswith("Incoming") else "prefix_list_out"
            cur[key] = text.split()[-1]
        elif text.startswith("Prefixes Current:"):
            nums = re.findall(r"\d+", text.replace("Prefixes Current:", ""))
            if len(nums) >= 2 and cur["prefixes_sent"] is None:
                cur["prefixes_sent"], cur["prefixes_received"] = int(nums[0]), int(nums[1])
        elif text.startswith("Updates:"):
            nums = re.findall(r"\d+", text)
            if len(nums) >= 2:
                cur["updates_out"], cur["updates_in"] = int(nums[0]), int(nums[1])
        elif text.startswith("Notifications:"):
            nums = re.findall(r"\d+", text)
            if len(nums) >= 2:
                cur["notifications_out"], cur["notifications_in"] = int(nums[0]), int(nums[1])
        elif text.startswith("Maximum prefixes allowed") or text.startswith("Maximum prefix"):
            m = re.search(r"(\d+)", text)
            cur["max_prefix"] = m.group(1) if m else ""
        elif text.startswith("External BGP neighbor may be up to"):
            m = re.search(r"up to (\d+) hops", text)
            cur["multihop"] = m.group(1) if m else ""
        elif text.startswith("Graceful-Restart is"):
            cur["graceful_restart"] = text.replace("Graceful-Restart is", "").strip()
        elif text.startswith("Inbound soft reconfiguration allowed"):
            cur["soft_reconfig"] = True
        elif text.startswith("fall-over") or "BFD" in text and "neighbor" in text.lower():
            cur["bfd"] = text
        elif text.startswith("Transport(tcp) path-mtu"):
            pass
        elif "TTL" in text and "security" in text.lower():
            cur["ttl_security"] = True
    return neighbors


def parse_bgp_summary(lines: list[str]) -> dict[str, Any]:
    info: dict[str, Any] = {"router_id": "", "local_as": "", "neighbors": []}
    header = None
    for line in lines:
        m = re.match(r"^BGP router identifier (\S+), local AS number (\d+)", line)
        if m:
            info["router_id"], info["local_as"] = m.group(1), m.group(2)
            continue
        if line.startswith("Neighbor"):
            header = True
            continue
        if not header or not line.strip():
            continue
        parts = line.split()
        if is_ipv4(parts[0]) and len(parts) >= 9:
            info["neighbors"].append({
                "neighbor": parts[0], "version": parts[1], "remote_as": parts[2], "msg_rcvd": parts[3], "msg_sent": parts[4], "up_down": parts[8], "state_or_prefixes": " ".join(parts[9:]),
            })
        elif len(parts) == 1 and is_ipv4(parts[0]):
            pass
    return info


# --------------------------------------------------------------------------
# Neighbour tables for IGPs / FHRP / ARP-like
# --------------------------------------------------------------------------


def parse_ospf_neighbors(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        m = re.match(r"^(\S+)\s+(\d+)\s+(\S+?)(?:/(\S+))?\s+(\d+:\d+:\d+|-)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s*$", line)
        if m:
            rows.append({"neighbor_id": m.group(1), "priority": m.group(2), "state": m.group(3), "role": m.group(4) or "", "dead_time": m.group(5), "address": m.group(6), "interface": canon(m.group(7))})
    return rows


def parse_ospf_interface_brief(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        m = re.match(r"^(\S+)\s+(\d+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s*$", line)
        if m:
            rows.append({"interface": canon(m.group(1)), "process": m.group(2), "area": m.group(3), "address": m.group(4), "cost": m.group(5), "state": m.group(6), "neighbors": m.group(7)})
    return rows


def parse_eigrp_neighbors(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        m = re.match(r"^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)
        if m:
            rows.append({"handle": m.group(1), "address": m.group(2), "interface": canon(m.group(3)), "hold": m.group(4), "uptime": m.group(5), "srtt": m.group(6), "rto": m.group(7), "queue": m.group(8), "seq": m.group(9)})
    return rows


def parse_standby_brief(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        m = re.match(r"^(\S+)\s+(\d+)\s+(\d+)\s+(P?)\s*(Active|Standby|Init|Listen|Speak|Learn)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", line)
        if m:
            rows.append({"interface": canon(m.group(1)), "group": m.group(2), "priority": m.group(3), "preempt": "Yes" if m.group(4) else "No", "state": m.group(5), "active": m.group(6), "standby": m.group(7), "virtual_ip": m.group(8)})
    return rows


def parse_vrrp_brief(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        m = re.match(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(Y|N)?\s*(Y|N)?\s*(Master|Backup|Init)\s+(\S+)\s+(\S+)\s*$", line)
        if m:
            rows.append({"interface": canon(m.group(1)), "group": m.group(2), "priority": m.group(3), "state": m.group(7), "master": m.group(8), "virtual_ip": m.group(9)})
    return rows


def parse_ntp_status(lines: list[str]) -> dict[str, Any]:
    text = "\n".join(lines)
    info: dict[str, Any] = {"raw": text.strip()}
    m = re.search(r"Clock is (synchronized|unsynchronized)", text)
    if m:
        info["synchronized"] = m.group(1) == "synchronized"
    m = re.search(r"stratum (\d+)", text)
    if m:
        info["stratum"] = int(m.group(1))
    m = re.search(r"reference is (\S+)", text)
    if m:
        info["reference"] = m.group(1)
    return info


# --------------------------------------------------------------------------
# show ntp associations
# --------------------------------------------------------------------------

# Leading sync-state marker, Cisco's own legend: "* sys.peer, # selected, + candidate,
# - outlyer, x falseticker, ~ configured". A blank marker (a lone space) means none of
# those — the peer is configured but NTP currently has nothing to say about it, which in
# practice means it has never been successfully polled.
_NTP_MARKER = {"*": "sys.peer", "#": "selected", "+": "candidate", "-": "outlyer", "x": "falseticker", " ": "none"}

# marker (1 char) + optional '~' (configured, vs. discovered by broadcast/manycast) + address,
# with no space between them — then the usual whitespace-separated numeric columns.
_NTP_ASSOC_ROW = re.compile(
    r"^(?P<marker>[*#+\-x ])(?P<configured>~)?(?P<address>\S+)\s+(?P<refclock>\S+)\s+(?P<stratum>\d+)\s+"
    r"(?P<when>\S+)\s+(?P<poll>\d+)\s+(?P<reach>\d+)\s+(?P<delay>[\d.]+)\s+(?P<offset>-?[\d.]+)\s+(?P<disp>\S+)\s*$"
)


def parse_ntp_associations(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        m = _NTP_ASSOC_ROW.match(line)
        if not m:
            continue
        reach = m.group("reach")
        rows.append({
            "address": m.group("address"), "configured": bool(m.group("configured")),
            "state": _NTP_MARKER.get(m.group("marker"), "none"), "ref_clock": m.group("refclock"),
            "stratum": int(m.group("stratum")), "when": m.group("when"), "poll": int(m.group("poll")),
            "reach": reach, "reachable": reach != "0", "delay_ms": float(m.group("delay")),
            "offset_ms": float(m.group("offset")), "disp": m.group("disp"),
        })
    return rows


# --------------------------------------------------------------------------
# show ip sla statistics
# --------------------------------------------------------------------------

_SLA_OP_ID = re.compile(r"^(?:Round Trip Time \()?IPSLA operation id:\s*(\d+)\)?", re.I)
_SLA_FIELDS = (
    ("rtt_ms", re.compile(r"Latest RTT:\s*(\d+)\s*milliseconds", re.I)),
    ("rtt_raw", re.compile(r"Latest RTT:\s*(.+?)\s*$", re.I)),
    ("start_time", re.compile(r"Latest operation start time:\s*(.+?)\s*$", re.I)),
    ("return_code", re.compile(r"Latest operation return code:\s*(.+?)\s*$", re.I)),
    ("successes", re.compile(r"Number of successes:\s*(\d+)", re.I)),
    ("failures", re.compile(r"Number of failures:\s*(\d+)", re.I)),
    ("ttl", re.compile(r"Operation time to live:\s*(.+?)\s*$", re.I)),
)


def parse_ip_sla_statistics(lines: list[str]) -> list[dict[str, Any]]:
    """One row per ``IPSLA operation id: N`` block. ``successes``/``failures`` are the
    device's own lifetime counters for that probe — a probe with 0 successes and any
    failures has never once completed since the last clear, whatever routing or tracking
    depends on it."""
    ops: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines:
        text = line.strip()
        m = _SLA_OP_ID.match(text)
        if m:
            current = {"id": m.group(1), "rtt_ms": None, "rtt_raw": "", "start_time": "", "return_code": "", "successes": 0, "failures": 0, "ttl": ""}
            ops.append(current)
            continue
        if current is None:
            continue
        for key, pattern in _SLA_FIELDS:
            m = pattern.match(text)
            if not m:
                continue
            value = m.group(1)
            current[key] = int(value) if key in ("successes", "failures") else value
    return ops
