"""Findings for BIG-IP DNS (GTM) objects.  Silent when the capture holds no ``gtm`` stanza (``data["gtm"]`` is ``None``).

Everything compares names exactly as written; a pool member ``/Common/server:vs`` is split at the colon.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .bigip_context import LCtx, listing
from .refs import F5

TOPOLOGY_MODES = {"topology"}


def gtm_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    g = ctx.data.get("gtm")
    if not g:
        return []
    out: list[dict[str, Any]] = []
    pools = {(p["type"] or "a", p["name"]): p for p in g["pools"]}
    servers = {s["name"]: s for s in g["servers"]}
    dcs = {d["name"] for d in g["datacenters"]}

    for w in g["wideips"]:
        if w["disabled"]:
            continue
        if not w["pool_refs"]:
            out.append(finding("LB-GTM-001", "medium", "DNS (GTM)", "Wide IP has no pool", obj=f"gtm wideip {w['type']} {w['name']}",
                               detail=f"{w['name']} lists no pool, so it has nothing to answer with; clients get an empty or failing response.",
                               recommendation="Add at least one pool, or delete the wide IP.", reference=F5["gtm_wideip"]))
        for ref in w["pool_refs"]:
            if ref not in pools:
                out.append(finding("LB-GTM-002", "medium", "DNS (GTM)", "Wide IP refers to a pool that is not defined", obj=f"gtm wideip {w['type']} {w['name']}",
                                   detail=f"{w['name']} lists {ref[0]} pool {ref[1]}, which is not in this capture (partial export, other partition or a deleted pool).",
                                   recommendation="Export all partitions, or create/remove the reference.", reference=F5["gtm_wideip"]))
        if w["mode"] in TOPOLOGY_MODES and len(w["pool_refs"]) > 1 and not g["topology"]:
            out.append(finding("LB-GTM-005", "medium", "DNS (GTM)", "Topology load balancing without topology records", obj=f"gtm wideip {w['type']} {w['name']}",
                               detail=f"{w['name']} picks among its {len(w['pool_refs'])} pools by topology, but the capture has no 'gtm topology' record, so no pool can score better than another.",
                               recommendation="Add topology records (or a region list) or choose another pool-lb-mode.", reference=F5["gtm_topology"]))

    for p in g["pools"]:
        if p["disabled"]:
            continue
        label = f"gtm pool {p['type']} {p['name']}".replace("  ", " ")
        if not p["members"]:
            out.append(finding("LB-GTM-003", "medium", "DNS (GTM)", "GTM pool has no members", obj=label,
                               detail=f"{p['name']} has no member, so it can never be selected" + (f"; wide IP(s) {listing(p['wideips'])} depend on it." if p["wideips"] else "."),
                               recommendation="Add members (server:virtual-server) or delete the pool.", reference=F5["gtm_pool"]))
        for m in p["members"]:
            server = servers.get(m["server"])
            if m["server"] and server is None:
                out.append(finding("LB-GTM-004", "medium", "DNS (GTM)", "Pool member refers to an unknown GTM server", obj=label,
                                   detail=f"Member {m['name']} names server {m['server']}, which is not defined with 'gtm server'.", recommendation="Create the server object or remove the member.", reference=F5["gtm_server"]))
            elif server is not None and m["virtual_server"] and m["virtual_server"] not in server["virtual_servers"] and server["virtual_servers"]:
                out.append(finding("LB-GTM-004", "medium", "DNS (GTM)", "Pool member refers to an unknown virtual server", obj=label,
                                   detail=f"Member {m['name']}: server {server['name']} has no virtual server '{m['virtual_server']}'.", recommendation="Correct the member name or add the virtual server (or run discovery).", reference=F5["gtm_server"]))
        if p["mode"] in TOPOLOGY_MODES and not g["topology"]:
            out.append(finding("LB-GTM-005", "medium", "DNS (GTM)", "Topology load balancing without topology records", obj=label,
                               detail=f"{p['name']} uses 'topology' as its preferred method but the capture has no 'gtm topology' record.", recommendation="Add topology records or change load-balancing-mode.", reference=F5["gtm_topology"]))
        if not p["verify"]:
            out.append(finding("LB-GTM-006", "low", "DNS (GTM)", "Pool does not verify member availability", obj=label,
                               detail=f"verify-member-availability is disabled on {p['name']}: members are returned even when the local virtual server or pool behind them is down (documented default: enabled).",
                               recommendation="Leave it enabled unless the member is health-checked some other way.", reference=F5["gtm_pool"]))
        if not p["wideips"] and p["members"]:
            out.append(finding("LB-GTM-008", "info", "DNS (GTM)", "GTM pool is not used by any wide IP", obj=label, detail=f"No wide IP lists {p['name']} as a pool or last-resort pool.",
                               recommendation="Attach it or delete it.", reference=F5["gtm_pool"]))

    for s in g["servers"]:
        if s["datacenter"] and s["datacenter"] not in dcs:
            out.append(finding("LB-GTM-009", "medium", "DNS (GTM)", "GTM server refers to an unknown data center", obj=f"gtm server {s['name']}",
                               detail=f"{s['name']} is placed in {s['datacenter']}, which is not defined with 'gtm datacenter'.", recommendation="Create the data center or correct the name.", reference=F5["gtm_datacenter"]))
        if not s["disabled"] and s["product"] and s["product"] not in {"bigip", "redundant-bigip"} and not s["monitor"] and not s["vs_monitored"]:
            out.append(finding("LB-GTM-007", "low", "DNS (GTM)", "Third-party GTM server has no health monitor", obj=f"gtm server {s['name']}",
                               detail=f"{s['name']} is a '{s['product']}' server, which does not report its state over iQuery, and neither the server nor its virtual servers have a monitor: it is always treated as up.",
                               recommendation="Assign a monitor (for example gateway_icmp, tcp or http) to the server or to its virtual servers.", reference=F5["gtm_server"]))

    used_dcs = {s["datacenter"] for s in g["servers"]}
    empty = [d["name"] for d in g["datacenters"] if d["name"] not in used_dcs]
    if empty:
        out.append(finding("LB-GTM-010", "info", "DNS (GTM)", f"{len(empty)} data center(s) hold no server", obj=listing(empty), detail="No 'gtm server' is placed in these data centers.",
                           recommendation="Remove leftovers or add the servers.", reference=F5["gtm_datacenter"]))
    if g["wideips"] and not g["listeners"] and not g["dns_virtuals"]:
        out.append(finding("LB-GTM-011", "medium", "DNS (GTM)", "Wide IPs exist but nothing listens for DNS queries", obj=f"{len(g['wideips'])} wide IP(s)",
                           detail="There is no 'gtm listener' and no LTM virtual server with a DNS profile, so the unit cannot receive queries for the wide IPs (a listener can also exist in another partition or in a part of the configuration that was not exported).",
                           recommendation="Create a listener on the DNS address, or enable GTM on a DNS-profile virtual server.", reference=F5["gtm_listener"]))
    return out


# ===================================================================== live state ('show gtm ...')
def gtm_runtime_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    """Findings from live ``show gtm`` output: iQuery peers that are not connected, wide IPs and servers that are offline.  Silent without that output."""
    rt = ctx.runtime
    out: list[dict[str, Any]] = []
    for peer in rt.get("gtm_iquery", []):
        shown = (peer.get("iquery_state") or "").strip().lower()
        if shown and shown != "connected":
            who = peer.get("server") or peer["name"]
            out.append(finding("LB-GTM-020", "high", "DNS (GTM)", f"iQuery to {who} is {shown}", obj=f"gtm iquery {peer['name']}",
                               detail=f"The iQuery connection from this DNS device to {who} ({peer['name']}) is '{shown}'. Without it the unit cannot learn that peer's virtual server health, so wide IP answers can point at dead members or drop them wrongly.",
                               recommendation="Check that TCP 4353 is reachable both ways, that the device certificates were exchanged ('bigip_add' on the DNS device) and that the peer's self IP is reachable.", reference=F5["dns_iquery_troubleshooting"]))
    for w in rt.get("gtm_wideips", []):
        if w["state"].lower() == "enabled" and w["availability"].lower() in ("offline", "unavailable"):
            out.append(finding("LB-GTM-021", "high" if w["availability"].lower() == "offline" else "medium", "DNS (GTM)", f"Wide IP is {w['availability'].lower()}", obj=f"gtm wideip {w['name']}",
                               detail=f"{w['name']}: {w['reason'] or w['availability']}. Queries for it get no usable answer (or only the fallback / last-resort answer).",
                               recommendation="Open its pools and members ('show gtm pool a detail'), then the server and virtual server monitors behind them.", reference=F5["gtm_wideip"]))
    for server in rt.get("gtm_servers", []):
        if server["state"].lower() == "enabled" and server["availability"].lower() in ("offline", "unavailable"):
            out.append(finding("LB-GTM-022", "medium", "DNS (GTM)", f"GTM server is {server['availability'].lower()}", obj=f"gtm server {server['name']}",
                               detail=f"{server['name']}: {server['reason'] or server['availability']}. Every pool member on it is treated as down.",
                               recommendation="Check the server monitor, iQuery and the network path to it.", reference=F5["gtm_server"]))
    return out
