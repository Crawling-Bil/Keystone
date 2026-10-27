"""BIG-IP DNS (GTM) objects: data centers, servers, pools, wide IPs, listeners and topology records.

Read from the ``gtm`` stanzas of ``bigip_gtm.conf`` / a ``tmsh list gtm`` capture.  Typed objects carry the record type before
the name (``gtm wideip a /Common/www.example.com``, ``gtm pool a /Common/pool_www``); ``tree.named`` handles one trailing name
token only, so this module matches the prefix itself.

Written from the documented TMSH syntax (clouddocs.f5.com, gtm_* pages) and checked against the saved ``bigip_gtm.conf`` of two
BIG-IP DNS units (TMOS 17.1).  The live ``show gtm`` output (``bigip_runtime``) was checked against captures of a BIG-IP DNS pair (TMOS 17.1.3).
"""

from __future__ import annotations

from typing import Any

from .bigip_extract import canon, short
from .netutil import parse_destination
from .tmsh_tree import TmshTree, TNode

DEFAULT_LB = "round-robin"
BIGIP_PRODUCTS = {"bigip", "redundant-bigip"}


def _name(node: TNode) -> str:
    return canon(node.tokens[-1]) if node.tokens else ""


def _type(node: TNode, base: int) -> str:
    """Record type word (a, aaaa, cname, mx, naptr, srv) when present: ``gtm pool a /Common/x`` has 4 tokens, ``gtm pool /Common/x`` 3."""
    return node.tokens[base] if len(node.tokens) > base + 1 else ""


def _flag_off(node: TNode) -> bool:
    return node.has("disabled")


def _addresses(node: TNode) -> list[str]:
    found: list[str] = []
    for item in node.walk():
        if item.key == "addresses":
            found += [t for t in item.names() if t not in found]
    return found


def _datacenters(tree: TmshTree) -> list[dict[str, Any]]:
    return [{"name": _name(n), "disabled": _flag_off(n), "location": n.val("location"), "servers": []} for n in tree.all_with_prefix("gtm", "datacenter") if len(n.tokens) == 3]


def _servers(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for n in tree.all_with_prefix("gtm", "server"):
        if len(n.tokens) != 3:
            continue
        vs = n.child("virtual-servers")
        vs_items = [c for c in vs.children if c.tokens] if vs is not None else []
        detail = []
        for c in vs_items:
            dest = c.val("destination")
            ip, port, _ = parse_destination(dest) if dest else ("", 0, "")
            detail.append({"name": canon(c.tokens[0]), "raw": c.tokens[0], "destination": ip, "port": port, "disabled": c.has("disabled")})
        dev = n.child("devices")
        out.append({"name": _name(n), "datacenter": canon(n.val("datacenter")), "product": n.val("product"), "monitor": n.val("monitor"), "addresses": _addresses(n),
                    "devices": [c.tokens[0] for c in (dev.children if dev is not None else []) if c.tokens],
                    "discovery": n.val("virtual-server-discovery"), "prober": n.val("prober-preference"),
                    "virtual_servers": [c.tokens[0] for c in vs_items], "vs_detail": detail, "vs_monitored": any(c.has("monitor") for c in vs_items), "disabled": _flag_off(n)})
    return out


def _pools(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for n in tree.all_with_prefix("gtm", "pool"):
        if len(n.tokens) not in (3, 4):
            continue
        members = []
        box = n.child("members")
        for m in (box.children if box is not None else []):
            if not m.tokens:
                continue
            server, _, vs = m.tokens[0].partition(":")
            members.append({"name": m.tokens[0], "server": canon(server), "virtual_server": vs, "disabled": m.has("disabled")})
        out.append({"name": _name(n), "type": _type(n, 2), "mode": n.val("load-balancing-mode") or DEFAULT_LB, "alternate": n.val("alternate-mode"), "fallback": n.val("fallback-mode"),
                    "monitor": n.val("monitor"), "verify": n.val("verify-member-availability").lower() != "disabled", "members": members, "disabled": _flag_off(n), "wideips": []})
    return out


def _wideips(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for n in tree.all_with_prefix("gtm", "wideip"):
        if len(n.tokens) not in (3, 4):
            continue
        rtype = _type(n, 2) or "a"
        refs = [(rtype, canon(p)) for p in n.names("pools")] + [("cname", canon(p)) for p in n.names("pools-cname")]
        last = n.val("last-resort-pool").split()
        out.append({"name": _name(n), "type": rtype, "mode": n.val("pool-lb-mode") or DEFAULT_LB, "pool_refs": refs,
                    "last_resort": (last[0], canon(last[-1])) if len(last) >= 2 else None, "aliases": n.names("aliases"), "persistence": n.val("persistence") == "enabled", "disabled": _flag_off(n)})
    return out


def _listeners(tree: TmshTree) -> list[dict[str, Any]]:
    return [{"name": _name(n), "address": n.val("address"), "port": n.val("port") or "53", "protocol": n.val("ip-protocol") or "udp", "disabled": _flag_off(n)}
            for n in tree.all_with_prefix("gtm", "listener") if len(n.tokens) == 3]


def _global_settings(tree: TmshTree) -> dict[str, dict[str, str]]:
    """``gtm global-settings <group>`` -> ``{group: {option: value}}``; ``tmsh list`` prints only the values that differ from the default."""
    out: dict[str, dict[str, str]] = {}
    for n in tree.all_with_prefix("gtm", "global-settings"):
        if len(n.tokens) != 3:
            continue
        options = {}
        for c in n.children:
            if c.tokens:
                options[c.key] = " ".join(c.names()) if c.block else " ".join(c.tokens[1:])
        out[n.tokens[2]] = options
    return out


def _topology_records(tree: TmshTree) -> list[dict[str, Any]]:
    """``gtm topology ldns: <spec> server: <spec> { score N }``: one record per stanza (an older ``records { }`` wrapper is read as well)."""
    out: list[dict[str, Any]] = []

    def one(tokens: list[str], node: TNode) -> None:
        if "ldns:" not in tokens or "server:" not in tokens:
            return
        a, b = tokens.index("ldns:"), tokens.index("server:")
        if a > b:
            return
        out.append({"ldns": " ".join(tokens[a + 1:b]), "server": " ".join(tokens[b + 1:]),
                    "score": node.val("score") or "1", "order": node.val("order"), "description": node.val("description")})

    for n in tree.all_with_prefix("gtm", "topology"):
        one(n.tokens[2:], n)
        for wrapper in n.kids("records"):
            for rec in wrapper.children:
                one(rec.tokens, rec)
    return out


def _region_records(tree: TmshTree) -> list[dict[str, Any]]:
    """``gtm region <name> { region-members { <type> <value> { } ... } }``; a member can be negated with ``not``."""
    out: list[dict[str, Any]] = []
    for n in tree.all_with_prefix("gtm", "region"):
        if len(n.tokens) != 3:
            continue
        members = n.child("region-members")
        out.append({"name": canon(n.tokens[2]), "members": [" ".join(m.tokens) for m in (members.children if members is not None else []) if m.tokens],
                    "description": n.val("description")})
    return out


def extract(tree: TmshTree) -> dict[str, Any] | None:
    """``None`` when the capture holds no GTM object at all (the normal case for an LTM-only unit, which still prints ``gtm global-settings`` stanzas)."""
    if not tree.has_prefix("gtm"):
        return None
    dcs, servers, pools, wideips = _datacenters(tree), _servers(tree), _pools(tree), _wideips(tree)
    listeners = _listeners(tree)
    if not (dcs or servers or pools or wideips or listeners or tree.has_prefix("gtm", "topology") or tree.has_prefix("gtm", "region")):
        return None        # an LTM-only unit still carries 'gtm global-settings metrics' stanzas: no DNS tabs for that
    by_pool = {(p["type"] or "a", p["name"]): p for p in pools}
    for w in wideips:
        for ref in w["pool_refs"] + ([w["last_resort"]] if w["last_resort"] else []):
            pool = by_pool.get(ref)
            if pool is not None and w["name"] not in pool["wideips"]:
                pool["wideips"].append(w["name"])
    by_dc = {d["name"]: d for d in dcs}
    for s in servers:
        if s["datacenter"] in by_dc:
            by_dc[s["datacenter"]]["servers"].append(short(s["name"]))
    return {"datacenters": dcs, "servers": servers, "pools": pools, "wideips": wideips, "listeners": listeners,
            "settings": _global_settings(tree), "topology": len(tree.all_with_prefix("gtm", "topology")), "regions": len(tree.all_with_prefix("gtm", "region")),
            "topology_records": _topology_records(tree), "region_records": _region_records(tree),
            "dns_virtuals": _dns_virtuals(tree)}


def _dns_virtuals(tree: TmshTree) -> list[str]:
    """LTM virtual servers with a DNS profile: they can also answer GTM queries (``enable-gtm``), so a missing ``gtm listener`` is not an error."""
    return [short(n.tokens[-1]) for n in tree.named("ltm", "virtual") if any("dns" in p.lower() for p in n.names("profiles"))]


def ltm_matches(gtm: dict[str, Any], virtuals: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """GTM server virtual server -> the LTM virtual server of THIS configuration that listens on the same address and port.

    A DNS unit that also runs LTM carries both halves, so the match shows which application a wide IP member really reaches.  A GTM
    virtual server for a remote LTM, or one behind NAT, has no match here; that is normal and never a finding by itself.
    Key: ``(server name, GTM virtual server name)``.
    """
    index: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for v in virtuals:
        index.setdefault((v.get("destination", ""), v.get("port", 0)), []).append(v)
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for s in gtm["servers"]:
        for d in s["vs_detail"]:
            hits = index.get((d["destination"], d["port"])) or []
            if hits:
                out[(s["name"], d["name"])] = hits[0]
    return out
