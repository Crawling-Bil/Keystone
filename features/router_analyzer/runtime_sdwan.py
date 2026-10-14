"""Parsers for the Cisco Catalyst SD-WAN overlay commands of an IOS-XE router in controller mode.

Formats were read from real captures of two cEdge routers (``show sdwan omp peers``, ``omp tlocs``,
``omp routes``, ``control local-properties``, ``app-route stats``, ``policy from-vsmart``); the points
that are easy to get wrong are recorded next to the code that handles them.

Only the ``show sdwan ...`` spelling is read.  The vEdge spelling (``show omp peers``) has a slightly
different column set on older releases and has not been seen in a capture, so it is left alone.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_PEER_TYPES = ("vsmart", "vbond", "vmanage", "vedge")


def is_ip(text: str) -> bool:
    """IPv4 or IPv6 address (the overlay tables print both)."""
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _int(text: str) -> int | None:
    return int(text) if re.fullmatch(r"-?\d+", text or "") else None


# --------------------------------------------------------------------------
# show sdwan omp peers
# --------------------------------------------------------------------------


def parse_omp_peers(lines: list[str]) -> list[dict[str, Any]]:
    """One row per OMP session: TENANT, PEER, TYPE, DOMAIN, OVERLAY, SITE, [REGION], STATE, UPTIME, R/I/S.

    R/I/S is routes received / installed / sent.  The REGION ID column is absent on releases before
    multi-region fabric, so the identifier columns are read between TYPE and STATE by count.
    """
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) < 9 or not parts[0].isdigit() or not is_ip(parts[1]) or parts[2] not in _PEER_TYPES:
            continue
        ris = re.fullmatch(r"(\d+)/(\d+)/(\d+)", parts[-1])
        if not ris:
            continue
        ids = parts[3:-3]
        if len(ids) not in (3, 4):
            continue
        rows.append({
            "tenant": parts[0], "peer": parts[1], "type": parts[2], "domain_id": ids[0], "overlay_id": ids[1], "site_id": ids[2],
            "region_id": ids[3] if len(ids) == 4 else "", "state": parts[-3], "uptime": parts[-2],
            "received": int(ris.group(1)), "installed": int(ris.group(2)), "sent": int(ris.group(3)),
        })
    return rows


# --------------------------------------------------------------------------
# show sdwan omp tlocs
# --------------------------------------------------------------------------

_TLOC_HEAD = re.compile(r"^tloc entries for\s+(\S+)\s*$")
_KEYVAL = re.compile(r"^([a-z][a-z0-9-]*)\s+(\S.*?)\s*$")
_TLOC_KEEP = {
    "peer": "peer", "status": "status", "bfd-status": "bfd_status", "site-id": "site_id", "preference": "preference", "weight": "weight", "carrier": "carrier", "restrict": "restrict",
    "public-ip": "public_ip", "public-port": "public_port", "private-ip": "private_ip", "private-port": "private_port", "encap-encrypt": "encrypt", "encap-auth": "auth",
    "stale": "stale", "loss-reason": "loss_reason", "region-id": "region_id", "attribute-type": "attribute_type", "overlay-id": "overlay_id", "domain-id": "domain_id",
}


def parse_omp_tlocs(lines: list[str]) -> list[dict[str, Any]]:
    """``show sdwan omp tlocs``: one row per TLOC and direction (RECEIVED FROM / ADVERTISED TO).

    A block opens with ``tloc entries for <system-ip>`` followed by the color and the encapsulation on
    their own lines.  Attributes appear twice for public/private address (IPv4, then IPv6); the first
    occurrence is kept.
    """
    entries: list[dict[str, Any]] = []
    tloc: dict[str, str] | None = None
    entry: dict[str, Any] | None = None
    for raw in lines:
        text = raw.strip()
        if not text or text.startswith("---"):
            continue
        head = _TLOC_HEAD.match(text)
        if head:
            tloc, entry = {"tloc_ip": head.group(1), "color": "", "encap": ""}, None
            continue
        if tloc is None:
            continue
        if entry is None and not tloc["color"] and re.fullmatch(r"[A-Za-z][\w-]*", text):
            tloc["color"] = text
            continue
        if entry is None and tloc["color"] and not tloc["encap"] and text.lower() in ("ipsec", "gre"):
            tloc["encap"] = text.lower()
            continue
        if text in ("RECEIVED FROM:", "ADVERTISED TO:"):
            entry = {"tloc_ip": tloc["tloc_ip"], "color": tloc["color"], "encap": tloc["encap"], "direction": "received" if text.startswith("RECEIVED") else "advertised"}
            entries.append(entry)
            continue
        if entry is None:
            continue
        pair = _KEYVAL.match(text)
        if pair and pair.group(1) in _TLOC_KEEP:
            entry.setdefault(_TLOC_KEEP[pair.group(1)], pair.group(2))
    return entries


# --------------------------------------------------------------------------
# show sdwan omp routes
# --------------------------------------------------------------------------

_STATUS_TOKEN = re.compile(r"^[A-Za-z]+(?:-[A-Za-z]+)?(?:,[A-Za-z]+(?:-[A-Za-z]+)?)*$")
_LEGEND_LINE = re.compile(r"^(C|I|Red|Rej|L|R|S|Ext|Inv|Stg|IA|U|BR-R|TGW-R)\s+->\s+(.+?)\s*$")


def _split_route_row(parts: list[str], first: bool) -> tuple[str, str, str, list[str]] | None:
    """Return (tenant, vpn, prefix, path-columns) for a row that carries a prefix, or ("", "", "", path-columns) for a continuation."""
    if first:
        if len(parts) < 12 or not parts[0].isdigit() or not parts[1].isdigit() or "/" not in parts[2]:
            return None
        tenant, vpn, prefix, rest = parts[0], parts[1], parts[2], parts[3:]
    else:
        tenant = vpn = prefix = ""
        rest = parts
    # FROM PEER, PATH ID, LABEL, STATUS, ATTRIBUTE TYPE, TLOC IP, COLOR, ENCAP, PREFERENCE, ...
    if len(rest) < 8 or not is_ip(rest[0]) or not rest[1].isdigit() or not _STATUS_TOKEN.match(rest[3]) or not is_ip(rest[5]):
        return None
    return tenant, vpn, prefix, rest


def parse_omp_routes(lines: list[str]) -> dict[str, Any]:
    """``show sdwan omp routes``: counts by status and color, plus one record per prefix.

    A prefix is printed once; its further paths follow on rows that start with the peer address.  A
    long PATH ID wraps its last digits onto a line of their own (a number alone under the PATH ID
    column); those lines are not rows and are skipped.  Status codes are decoded with the legend the
    device prints.  A path counts as usable when it is resolved (``R``) and not invalid (``Inv``).
    """
    legend: dict[str, str] = {}
    prefixes: dict[tuple[str, str], dict[str, Any]] = {}
    by_status: dict[str, int] = {}
    by_color: dict[str, dict[str, int]] = {}
    unresolved_tlocs: dict[str, set[str]] = {}
    peers: dict[str, int] = {}
    current: dict[str, Any] | None = None
    paths = 0
    for line in lines:
        if not line.strip():
            continue
        leg = _LEGEND_LINE.match(line)
        if leg:
            legend[leg.group(1)] = leg.group(2)
            continue
        parts = line.split()
        if re.fullmatch(r"\s+\d+\s*", line):
            continue  # wrapped PATH ID digits
        first = not line[0].isspace()
        row = _split_route_row(parts, first)
        if row is None:
            continue
        tenant, vpn, prefix, rest = row
        if first:
            key = (vpn, prefix)
            current = prefixes.get(key)
            if current is None:
                current = {"vpn": vpn, "prefix": prefix, "paths": 0, "usable": 0, "chosen": 0, "installed": 0, "colors": {}, "tlocs": [], "best_color": "", "best_tloc": "", "statuses": {}}
                prefixes[key] = current
        if current is None:
            continue
        status, color, tloc_ip = rest[3], rest[6], rest[5]
        flags = set(status.split(","))
        usable = "R" in flags and "Inv" not in flags
        paths += 1
        current["paths"] += 1
        current["usable"] += 1 if usable else 0
        if "C" in flags:
            current["chosen"] += 1
            if not current["best_color"]:
                current["best_color"], current["best_tloc"] = color, tloc_ip
        if "I" in flags:
            current["installed"] += 1
        current["statuses"][status] = current["statuses"].get(status, 0) + 1
        current["colors"][color] = current["colors"].get(color, 0) + 1
        if tloc_ip not in current["tlocs"] and len(current["tlocs"]) < 4:
            current["tlocs"].append(tloc_ip)
        by_status[status] = by_status.get(status, 0) + 1
        slot = by_color.setdefault(color, {"paths": 0, "usable": 0, "unresolved": 0})
        slot["paths"] += 1
        slot["usable" if usable else "unresolved"] += 1
        if not usable:
            unresolved_tlocs.setdefault(color, set()).add(tloc_ip)
        peers[rest[0]] = peers.get(rest[0], 0) + 1
    if not paths:
        return {}
    for color, slot in by_color.items():
        slot["unresolved_tlocs"] = len(unresolved_tlocs.get(color, ()))
    vpns: dict[str, dict[str, int]] = {}
    for record in prefixes.values():
        slot = vpns.setdefault(record["vpn"], {"prefixes": 0, "paths": 0, "unusable_prefixes": 0})
        slot["prefixes"] += 1
        slot["paths"] += record["paths"]
        slot["unusable_prefixes"] += 1 if not record["usable"] else 0
    return {
        "legend": legend, "paths": paths, "prefix_count": len(prefixes), "by_status": by_status, "by_color": by_color, "vpns": vpns, "peers": peers,
        "prefixes": list(prefixes.values()), "unusable_prefixes": sum(1 for r in prefixes.values() if not r["usable"]),
        "installed_paths": sum(r["installed"] for r in prefixes.values()),
    }


# --------------------------------------------------------------------------
# show sdwan control local-properties
# --------------------------------------------------------------------------

_VSVM = re.compile(r"^\d+/\d+$")


def parse_control_local_properties(lines: list[str]) -> dict[str, Any]:
    """Device identity and certificate block, then one row per WAN interface.

    The interface table is fixed-width but its address columns vary in length, so a row is read as
    tokens and anchored on the VS/VM column (``2/0``): everything before it is addresses and ports,
    everything after it is color, state and the counters.
    """
    properties: dict[str, str] = {}
    interfaces: list[dict[str, str]] = []
    for line in lines:
        if not line.strip():
            continue
        if line[0].islower():
            pair = re.match(r"^([a-z][\w/-]*)\s+(\S.*?)\s*$", line)
            if pair:
                properties[pair.group(1)] = pair.group(2)
            continue
        parts = line.split()
        if len(parts) < 14 or not line[0].isupper():
            continue
        anchor = next((i for i in range(4, min(len(parts), 9)) if _VSVM.match(parts[i])), None)
        if anchor is None:
            continue
        # The color cell can be printed in two pieces with spaces between them ("cus" + "tom2" for custom2,
        # "pri" + "vate2" for private2); the STATE word that follows ends it, so the pieces are joined.
        state_at = next((i for i in range(anchor + 2, len(parts)) if parts[i] in ("up", "down", "init")), None)
        if state_at is None or state_at + 6 >= len(parts):
            continue
        after = parts[state_at:]
        interfaces.append({
            "interface": parts[0], "public_ip": parts[1], "public_port": parts[2], "private_ip": parts[3], "private_ipv6": parts[4] if anchor - 1 > 4 else "", "private_port": parts[anchor - 1],
            "vs_vm": parts[anchor], "color": "".join(parts[anchor + 1:state_at]), "state": after[0], "max_control": after[1], "restrict_control_stun": after[2], "lr_lb": after[3], "last_connection": after[4],
            "spi_remaining": after[5], "nat_type": after[6] if len(after) > 6 else "", "vm_con_prf": after[7] if len(after) > 7 else "", "reg_ids": " ".join(after[8:]),
        })
    if not properties and not interfaces:
        return {}
    return {"properties": properties, "interfaces": interfaces}


# --------------------------------------------------------------------------
# show sdwan app-route stats
# --------------------------------------------------------------------------

_AR_HEAD = re.compile(r"^app-route statistics\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s*$")
_AR_TUNNEL_KEYS = {
    "remote-system-ip": "remote_system_ip", "local-color": "local_color", "remote-color": "remote_color", "sla-class-index": "sla_class_index",
    "fallback-sla-class-index": "fallback_sla_class_index", "app-probe-class-list": "app_probe_class_list",
}
_AR_MEANS = {"mean-loss": "mean_loss", "mean-latency": "mean_latency", "mean-jitter": "mean_jitter"}
_AR_INTERVAL_KEYS = {"total-packets": "total_packets", "loss": "loss", "average-latency": "latency", "average-jitter": "jitter", "tx-data-pkts": "tx", "rx-data-pkts": "rx"}


def parse_app_route_stats(lines: list[str]) -> list[dict[str, Any]]:
    """One record per tunnel (source, destination, protocol, ports) with the device-computed means and the per-interval samples.

    ``mean-loss`` is a percentage, ``mean-latency`` and ``mean-jitter`` are milliseconds, as computed
    by the device over the interval window (Cisco: "Understand BFD Protocol Relationship with
    App-Aware Routing").
    """
    tunnels: list[dict[str, Any]] = []
    tunnel: dict[str, Any] | None = None
    interval: dict[str, Any] | None = None
    for raw in lines:
        head = _AR_HEAD.match(raw.strip())
        if head:
            tunnel = {"src_ip": head.group(1), "dst_ip": head.group(2), "protocol": head.group(3), "src_port": head.group(4), "dst_port": head.group(5), "intervals": []}
            tunnels.append(tunnel)
            interval = None
            continue
        if tunnel is None:
            continue
        pair = re.match(r"^\s*([a-z][\w-]*)\s+(\S.*?)\s*$", raw)
        if not pair:
            continue
        key, value = pair.group(1), pair.group(2)
        if key == "interval" and value.isdigit():
            interval = {"index": int(value)}
            tunnel["intervals"].append(interval)
        elif interval is not None and key in _AR_INTERVAL_KEYS:
            interval[_AR_INTERVAL_KEYS[key]] = _int(value)
        elif key in _AR_MEANS:
            tunnel[_AR_MEANS[key]] = _int(value)
            interval = None
        elif key in _AR_TUNNEL_KEYS:
            tunnel[_AR_TUNNEL_KEYS[key]] = value
            interval = None
    return [t for t in tunnels if t.get("remote_system_ip") or t["intervals"]]


# --------------------------------------------------------------------------
# show sdwan policy from-vsmart
# --------------------------------------------------------------------------


def _tree(lines: list[str]) -> list[dict[str, Any]]:
    """Indentation tree of the lines of one ``from-vsmart`` block."""
    root: dict[str, Any] = {"indent": -1, "text": "", "children": []}
    stack = [root]
    for line in lines:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        node = {"indent": indent, "text": line.strip(), "children": []}
        while stack[-1]["indent"] >= indent:
            stack.pop()
        stack[-1]["children"].append(node)
        stack.append(node)
    return root["children"]


def _split_key(text: str) -> tuple[str, str]:
    parts = text.split(None, 1)
    return parts[0], (parts[1].strip() if len(parts) > 1 else "")


def parse_policy_from_vsmart(lines: list[str]) -> dict[str, Any]:
    """``show sdwan policy from-vsmart``: SLA classes, application-aware (app-route) policies and the lists they use.

    The device prints each policy object under a ``from-vsmart`` line, children indented below it.
    Anything that is not an SLA class, an app-route policy or a list (data policy, cflowd, ...) is
    kept only as a heading with its line count so the Coverage tab can say it was seen.
    """
    blocks: list[tuple[str, list[str]]] = []
    for line in lines:
        if line.startswith("from-vsmart"):
            blocks.append((line.strip(), []))
        elif blocks and line.startswith(" "):
            blocks[-1][1].append(line)
    if not blocks:
        return {}
    sla_classes: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []
    lists: list[dict[str, Any]] = []
    other: list[dict[str, Any]] = []
    for heading, body in blocks:
        words = heading.split()
        kind = words[1] if len(words) > 1 else ""
        if kind == "sla-class" and len(words) >= 3:
            values = {k: _int(v) for k, v in (_split_key(n["text"]) for n in _tree(body))}
            sla_classes.append({"name": words[2], "loss": values.get("loss"), "latency": values.get("latency"), "jitter": values.get("jitter")})
        elif kind == "app-route-policy" and len(words) >= 3:
            policies.append({"name": words[2], "vpn_lists": [_parse_vpn_list(node) for node in _tree(body) if node["text"].startswith("vpn-list")]})
        elif kind == "lists" and len(words) >= 4:
            entries = []
            for node in _tree(body):
                key, value = _split_key(node["text"])
                entries.append(f"{key} {value}".strip() if key != "ip-prefix" else value)
            lists.append({"kind": words[2], "name": words[3], "entries": entries})
        else:
            other.append({"heading": heading, "lines": len(body)})
    return {"sla_classes": sla_classes, "policies": policies, "lists": lists, "other": other}


def _parse_vpn_list(node: dict[str, Any]) -> dict[str, Any]:
    sequences = []
    for seq in node["children"]:
        if not seq["text"].startswith("sequence"):
            continue
        match: dict[str, str] = {}
        action: dict[str, Any] = {"sla_class": "", "strict": False, "preferred_colors": [], "backup_color": "", "other": []}
        for part in seq["children"]:
            if part["text"] == "match":
                for item in part["children"]:
                    key, value = _split_key(item["text"])
                    match[key] = value
            elif part["text"] == "action":
                for item in part["children"]:
                    key, value = _split_key(item["text"])
                    if key == "sla-class":
                        sub, rest = _split_key(value)
                        if sub == "strict":
                            action["strict"] = True
                        elif sub == "preferred-color":
                            action["preferred_colors"] = rest.split()
                        elif sub:
                            action["sla_class"] = sub
                    elif key == "no" and value == "sla-class strict":
                        action["strict"] = False
                    elif key == "backup-sla-preferred-color":
                        action["backup_color"] = value
                    else:
                        action["other"].append(item["text"])
        sequences.append({"sequence": seq["text"].split()[-1], "match": match, "action": action})
    return {"name": node["text"].split(None, 1)[1] if " " in node["text"] else "", "sequences": sequences}
