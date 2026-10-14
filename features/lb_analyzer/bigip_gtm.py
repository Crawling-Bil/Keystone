"""BIG-IP DNS (GTM) objects: data centers, servers, pools, wide IPs, listeners and topology records.

Read from the ``gtm`` stanzas of ``bigip_gtm.conf`` / a ``tmsh list gtm`` capture.  Typed objects carry the record type before
the name (``gtm wideip a /Common/www.example.com``, ``gtm pool a /Common/pool_www``); ``tree.named`` handles one trailing name
token only, so this module matches the prefix itself.

Written from the documented TMSH syntax (clouddocs.f5.com, gtm_* pages).  Not yet checked against a configuration captured from
a DNS/GTM device - ``bigip_sections_gtm`` says so on the tab.
"""

from __future__ import annotations

from typing import Any

from .bigip_extract import canon, short
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
        out.append({"name": _name(n), "datacenter": canon(n.val("datacenter")), "product": n.val("product"), "monitor": n.val("monitor"), "addresses": _addresses(n),
                    "virtual_servers": [c.tokens[0] for c in vs_items], "vs_monitored": any(c.has("monitor") for c in vs_items), "disabled": _flag_off(n)})
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


def extract(tree: TmshTree) -> dict[str, Any] | None:
    """``None`` when the capture holds no GTM object at all (the normal case for an LTM-only unit)."""
    if not tree.has_prefix("gtm"):
        return None
    dcs, servers, pools, wideips = _datacenters(tree), _servers(tree), _pools(tree), _wideips(tree)
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
    return {"datacenters": dcs, "servers": servers, "pools": pools, "wideips": wideips, "listeners": _listeners(tree),
            "topology": len(tree.all_with_prefix("gtm", "topology")), "regions": len(tree.all_with_prefix("gtm", "region")),
            "dns_virtuals": _dns_virtuals(tree)}


def _dns_virtuals(tree: TmshTree) -> list[str]:
    """LTM virtual servers with a DNS profile: they can also answer GTM queries (``enable-gtm``), so a missing ``gtm listener`` is not an error."""
    return [short(n.tokens[-1]) for n in tree.named("ltm", "virtual") if any("dns" in p.lower() for p in n.names("profiles"))]
