"""``show`` output that complements the BIG-IP configuration.

These parsers follow the output layout documented for ``show sys version``,
``show cm sync-status``, ``show cm failover-status``, ``show ltm virtual``,
``show ltm pool`` and, for BIG-IP DNS, ``show gtm wideip / pool / server /
datacenter / iquery / listener``.  They have not been run against a captured BIG-IP yet, so
the service lists whichever of them produced data in the result's warnings.
Everything is optional: the analysis works from the configuration alone.
"""

from __future__ import annotations

import re
from typing import Any

from ..analyzer_core import capture as cap

COMMANDS = (
    ("show sys version", "TMOS version, build and edition."),
    ("show sys hardware", "Platform, chassis and blade serial numbers (parsed as raw text only)."),
    ("show cm sync-status", "Configuration-sync state of the device group."),
    ("show cm failover-status", "Failover state of this unit (active / standby / offline)."),
    ("show ltm virtual", "Availability, state and reason of every virtual server, plus connection counters."),
    ("show ltm pool", "Availability and available / total members for every pool."),
    ("show ltm pool members", "Availability, state, reason and monitor status of every pool member (feeds the Visualization tab)."),
    ("show ltm node", "Availability, state and reason of every node (feeds the Visualization tab)."),
)

GTM_COMMANDS = (
    ("show gtm wideip a detail", "Availability, state and reason of every wide IP (also aaaa, cname, mx, srv, naptr), with request and load-balancing counters (feeds the DNS part of the Visualization tab)."),
    ("show gtm pool a detail", "Availability, state and reason of every GTM pool and of its members (also aaaa, cname, mx, srv, naptr)."),
    ("show gtm server detail", "Availability and state of every GTM server and of its virtual servers, with the data center it belongs to."),
    ("show gtm datacenter", "Availability and state of every data center."),
    ("show gtm iquery", "iQuery connection state to every BIG-IP in the sync group: connected, backlogged, reconnects."),
    ("show gtm listener", "Statistics of the DNS listeners."),
)

_KV = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 /_\-\.\(\)]*?)\s*(?::\s+|\s{2,})(?P<value>\S.*?)\s*$")
_SECTION = re.compile(r"^(?:Ltm::Virtual Server|Ltm::Pool|Ltm::Pool Member|Sys::Version|CM::Sync-Status|CM::Failover-Status):?\s*(?P<name>.*)$")


def _pairs(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        match = _KV.match(line)
        if match:
            out.setdefault(match["key"].strip(), match["value"].strip())
    return out


def _sections(text: str, header: str) -> list[tuple[str, list[str]]]:
    """Split ``show ltm virtual``-style output at each ``<header>: <name>`` line."""
    out: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in text.splitlines():
        if line.startswith(header):
            if current:
                out.append(current)
            current = (line[len(header):].lstrip(": ").strip(), [])
        elif line.startswith(("Ltm::", "Sys::", "CM::")):                 # another object kind starts (a pool member inside a pool listing): the previous object ends here
            if current:
                out.append(current)
            current = None
        elif current is not None and not set(line.strip()) <= {"-"}:
            current[1].append(line)
    if current:
        out.append(current)
    return out


def parse_version(text: str) -> dict[str, str]:
    pairs = _pairs(text.splitlines())
    return {key.lower(): value for key, value in pairs.items() if key in ("Product", "Version", "Build", "Edition", "Date")}


def parse_sync_status(text: str) -> dict[str, str]:
    pairs = _pairs(text.splitlines())
    return {"status": pairs.get("Status", ""), "summary": pairs.get("Summary", ""), "color": pairs.get("Color", ""), "mode": pairs.get("Mode", "")}


def parse_failover_status(text: str) -> dict[str, str]:
    pairs = _pairs(text.splitlines())
    return {"status": pairs.get("Status", ""), "summary": pairs.get("Summary", ""), "color": pairs.get("Color", ""), "details": pairs.get("Details", "")}


def _int(text: str) -> int | None:
    match = re.search(r"\d+", text or "")
    return int(match[0]) if match else None


def parse_virtuals(text: str) -> list[dict[str, Any]]:
    out = []
    for name, lines in _sections(text, "Ltm::Virtual Server"):
        pairs = _pairs(lines)
        out.append({
            "name": name, "availability": pairs.get("Availability", ""), "state": pairs.get("State", ""), "reason": pairs.get("Reason", ""), "destination": pairs.get("Destination", ""),
            "connections": _int(pairs.get("Current Connections", "")), "pva": pairs.get("PVA Acceleration", ""),
        })
    return out


def parse_pools(text: str) -> list[dict[str, Any]]:
    out = []
    for name, lines in _sections(text, "Ltm::Pool:"):
        pairs = _pairs(lines)
        out.append({
            "name": name, "availability": pairs.get("Availability", ""), "state": pairs.get("State", ""), "reason": pairs.get("Reason", ""),
            "active": _int(pairs.get("Current Active Members", "")), "available": _int(pairs.get("Available Members", "")), "total": _int(pairs.get("Total Members", "")),
            "minimum_active": _int(pairs.get("Minimum Active Members", "")),
        })
    return [p for p in out if p["name"]]


_MEMBER_HEAD = re.compile(r"^Ltm::Pool Member:\s*(?P<rest>.+?)\s*$")
_NODE_HEAD = re.compile(r"^Ltm::Node:\s*(?P<rest>.+?)\s*$")
_POOL_HEAD = re.compile(r"^Ltm::Pool:\s*(?P<name>\S.*?)\s*$")


def _clean_name(token: str) -> str:
    return re.sub(r"\(.*?\)", "", token).strip().strip(",")


def _split_member_head(rest: str, pool_context: str) -> tuple[str, str]:
    """``Ltm::Pool Member:`` headers differ between releases ('10.1.1.1:80', '10.1.1.1:80 in pool_web', 'pool_web 10.1.1.1:80'): return (pool, member)."""
    tokens = rest.replace(",", " ").split()
    if "in" in tokens and tokens.index("in") + 1 < len(tokens):
        at = tokens.index("in")
        member = " ".join(tokens[:at])
        pool = " ".join(t for t in tokens[at + 1:] if t.lower() != "pool")
        return _clean_name(pool) or pool_context, _clean_name(member)
    endpoints = [t for t in tokens if re.search(r"[:.]\d+$", t) or ":" in t]
    if endpoints:
        member = endpoints[-1]
        others = [_clean_name(t) for t in tokens if t != member and t.lower() != "pool"]
        others = [t for t in others if t]                                    # '(10.1.1.9)' is the member's address, not a pool
        return others[0] if others else pool_context, _clean_name(member)
    return pool_context, _clean_name(tokens[-1]) if tokens else ""


def _status_record(lines: list[str]) -> dict[str, Any]:
    pairs = _pairs(lines)
    return {
        "availability": pairs.get("Availability", ""), "state": pairs.get("State", ""), "reason": pairs.get("Reason", ""),
        "monitor_status": pairs.get("Monitor Status", ""), "monitor": pairs.get("Monitor", ""),
        "connections": _int(pairs.get("Current Connections", "")),
    }


def parse_pool_members(text: str) -> list[dict[str, Any]]:
    """Members from ``show ltm pool members`` (also ``show ltm pool <name> members``): the Status block under each 'Ltm::Pool Member:' header."""
    out: list[dict[str, Any]] = []
    pool = ""
    current: dict[str, Any] | None = None
    buffer: list[str] = []

    def flush() -> None:
        nonlocal current, buffer
        if current is not None:
            current.update(_status_record(buffer))
            out.append(current)
        current, buffer = None, []

    for line in text.splitlines():
        head = _MEMBER_HEAD.match(line)
        pool_head = _POOL_HEAD.match(line)
        if head:
            flush()
            member_pool, member = _split_member_head(head["rest"], pool)
            if member:
                current = {"pool": member_pool, "member": member}
        elif pool_head:
            flush()
            pool = _clean_name(pool_head["name"])
        elif current is not None and not set(line.strip()) <= {"-"}:
            buffer.append(line)
    flush()
    return out


def parse_nodes(text: str) -> list[dict[str, Any]]:
    """Nodes from ``show ltm node``: 'Ltm::Node: 10.1.1.1' or 'Ltm::Node: web01 (10.1.1.1)'."""
    out: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    buffer: list[str] = []

    def flush() -> None:
        nonlocal current, buffer
        if current is not None:
            current.update(_status_record(buffer))
            out.append(current)
        current, buffer = None, []

    for line in text.splitlines():
        head = _NODE_HEAD.match(line)
        if head:
            flush()
            rest = head["rest"]
            inner = re.search(r"\(([^)]+)\)", rest)
            current = {"name": _clean_name(rest) or rest, "address": inner[1].strip() if inner else _clean_name(rest)}
        elif current is not None and not set(line.strip()) <= {"-"}:
            buffer.append(line)
    flush()
    return out


# ---------------------------------------------------------------- BIG-IP DNS (GTM)
_GTM_HEAD = re.compile(r"^Gtm::(?P<kind>[A-Za-z][A-Za-z0-9 \-]*?):\s*(?P<name>.*?)\s*$")
_GTM_KINDS = {"wideip": "wideip", "pool": "pool", "poolmember": "member", "member": "member", "server": "server", "virtualserver": "virtual", "datacenter": "datacenter", "iquery": "iquery", "listener": "listener", "link": "link"}
_RECORD_TYPES = {"a", "aaaa", "cname", "mx", "naptr", "srv"}
_PARENT_OF = {"member": "pool", "pool": "wideip", "virtual": "server"}


def _gtm_kind(label: str) -> str:
    key = re.sub(r"[^a-z0-9]", "", label.lower())
    return _GTM_KINDS.get(key, key)


def _gtm_name(kind: str, rest: str, pool_context: str) -> tuple[str, str, str]:
    """(name, record type, pool) from the text after ``Gtm::<Kind>:``; member headers may carry the pool ('x in pool_a', 'pool_a x')."""
    tokens = rest.replace(",", " ").split()
    rtype = ""
    if len(tokens) >= 2 and tokens[0].lower() in _RECORD_TYPES and kind in ("wideip", "pool"):
        rtype, tokens = tokens[0].lower(), tokens[1:]
    if kind == "member":
        pool, member = _split_member_head(" ".join(tokens), pool_context)
        return member, rtype, pool
    return _clean_name(" ".join(tokens)) or " ".join(tokens), rtype, ""


def _gtm_sections(lines: list[str]) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """Group the lines of one object by their (unindented) heading; indented ``key : value`` lines belong to the heading above.

    Returns (sections, flat): ``sections['status']['availability']`` and a first-wins flat view of every pair.
    """
    sections: dict[str, dict[str, str]] = {}
    flat: dict[str, str] = {}
    current = ""
    for line in lines:
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", "=", " "}:
            continue
        match = _KV.match(line)
        if line[:1] not in (" ", "\t") and not match:
            current = stripped.lower()
            continue
        if match:
            key, value = match["key"].strip().lower(), match["value"].strip()
            sections.setdefault(current if line[:1] in (" ", "\t") else "", {}).setdefault(key, value)
            flat.setdefault(key, value)
    return sections, flat


def _pick(sections: dict[str, dict[str, str]], flat: dict[str, str], section: str, *keys: str) -> str:
    for key in keys:
        value = sections.get(section, {}).get(key)
        if value:
            return value
    for key in keys:
        if flat.get(key):
            return flat[key]
    return ""


def parse_gtm(text: str) -> list[dict[str, Any]]:
    """Objects of one ``show gtm ...`` output: wide IPs, pools, pool members, servers, virtual servers, data centers, iQuery peers, listeners.

    Every record has ``kind``, ``name``, ``parent`` (the wide IP of a pool, the pool of a member, the server of a virtual server),
    ``type`` (record type), ``availability`` / ``state`` / ``reason`` and ``stats`` (the request and decision counters).
    The layout follows the documented 'Gtm::<Object>: <name>' / 'Status' blocks of ``show gtm``; it has not been checked on a device.
    """
    records: list[dict[str, Any]] = []
    last: dict[str, str] = {}
    current: dict[str, Any] | None = None
    buffer: list[str] = []

    def flush() -> None:
        nonlocal current, buffer
        if current is not None:
            sections, flat = _gtm_sections(buffer)
            current["availability"] = _pick(sections, flat, "status", "availability")
            current["state"] = _pick(sections, flat, "status", "state")
            current["reason"] = _pick(sections, flat, "status", "reason")
            stats: dict[str, str] = {}
            for heading, label in (("requests", "requests"), ("load balancing decisions", "decisions")):
                for key, value in sections.get(heading, {}).items():
                    stats[f"{label} {key}"] = value
            current["stats"] = stats
            current["fields"] = {k: v for k, v in flat.items() if k not in ("availability", "state", "reason")}
            if current["kind"] == "iquery":
                current["address"] = current["address"] or _pick(sections, flat, "", "ip address", "address", "peer")
                current["iquery_state"] = _pick(sections, flat, "", "iquery state", "state", "status")
                current["server"] = _pick(sections, flat, "", "server")
                current["datacenter"] = _pick(sections, flat, "", "data center", "datacenter")
            records.append(current)
        current, buffer = None, []

    for line in text.splitlines():
        head = _GTM_HEAD.match(line)
        if head:
            flush()
            kind = _gtm_kind(head["kind"])
            name, rtype, pool = _gtm_name(kind, head["name"], last.get("pool", ""))
            if not name:
                continue
            parent = pool if kind == "member" else last.get(_PARENT_OF.get(kind, ""), "")
            if kind in ("wideip", "server", "datacenter", "iquery"):
                last = {}                                   # a new top-level object ends the previous one's children
            last[kind] = name
            current = {"kind": kind, "name": name, "type": rtype, "parent": parent, "address": name if re.match(r"^\d+\.\d+\.\d+\.\d+$|^[0-9a-f:]+:[0-9a-f:]+$", name, re.I) else ""}
        elif line.startswith(("Ltm::", "Sys::", "CM::")):
            flush()
        elif current is not None:
            buffer.append(line)
    flush()
    return records


def merge_gtm(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The same object shown by several commands (a pool inside a wide IP and in ``show gtm pool``): keep the record that knows most."""
    best: dict[tuple[str, str, str], dict[str, Any]] = {}
    for rec in records:
        key = (rec["kind"], rec["name"].lower(), rec["parent"].lower())
        old = best.get(key)
        if old is None or (bool(rec["availability"]), len(rec["stats"]), len(rec["fields"])) > (bool(old["availability"]), len(old["stats"]), len(old["fields"])):
            best[key] = rec
    return list(best.values())


CONFIG_COMMANDS = ("list ...", "tmsh list ...", "show running-config ...", "tmsh show running-config ...", "cat bigip.conf", "cat bigip_base.conf", "cat /config/bigip.conf", "cat /config/bigip_base.conf")


def _is_config_block(block: cap.Block) -> bool:
    norm = re.sub(r"^tmsh\s+", "", block.norm).strip()
    if "|" in norm:                                                  # a filtered view is a fragment, not the configuration
        return False
    if norm.startswith(("list ", "show running-config", "cat ")) and not block.error:
        return not norm.startswith("cat ") or "bigip" in norm
    return norm in ("list", "show running-config")


def gather(content: str) -> dict[str, Any]:
    """Split a prompted capture; returns the configuration text and the parsed ``show`` output."""
    capture = cap.split_capture(content, [cap.F5_PROMPT])
    data: dict[str, Any] = {"capture": capture, "hostname": capture.hostname(), "config_text": ""}
    if not capture.blocks:
        data["config_text"] = content
        return data

    def block_text(*templates: str) -> str:
        found = capture.first(*[t for t in templates] + ["tmsh " + t for t in templates])
        return found.text if found else ""

    data["config_text"] = "\n".join(b.text for b in capture.blocks if _is_config_block(b))
    version = block_text("show sys version")
    if version:
        data["version"] = parse_version(version)
    sync = block_text("show cm sync-status")
    if sync:
        data["sync"] = parse_sync_status(sync)
    failover = block_text("show cm failover-status")
    if failover:
        data["failover"] = parse_failover_status(failover)
    virtuals = block_text("show ltm virtual", "show ltm virtual all-properties")
    if virtuals:
        data["virtuals"] = parse_virtuals(virtuals)
    pools = block_text("show ltm pool", "show ltm pool members")
    if pools:
        data["pools"] = parse_pools(pools)
    members = block_text("show ltm pool members", "show ltm pool <name> members")
    if members:
        parsed = parse_pool_members(members)
        if parsed:
            data["pool_members"] = parsed
    nodes = block_text("show ltm node", "show ltm node all")
    if nodes:
        parsed_nodes = parse_nodes(nodes)
        if parsed_nodes:
            data["nodes"] = parsed_nodes
    gtm_blocks = capture.find(*[t for template in ("show gtm wideip ...", "show gtm pool ...", "show gtm server ...", "show gtm datacenter ...", "show gtm iquery ...", "show gtm listener ...", "show gtm link ...") for t in (template, "tmsh " + template)])
    if gtm_blocks:
        records = merge_gtm([rec for block in gtm_blocks for rec in parse_gtm(block.text)])
        for kind, key in (("wideip", "gtm_wideips"), ("pool", "gtm_pools"), ("member", "gtm_members"), ("server", "gtm_servers"), ("virtual", "gtm_virtuals"), ("datacenter", "gtm_datacenters"), ("iquery", "gtm_iquery"), ("listener", "gtm_listeners")):
            found = [rec for rec in records if rec["kind"] == kind]
            if found:
                data[key] = found
    return data
